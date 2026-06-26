# Honeytoken & Decoy Seeding — Architecture Overview

> Status: Design | Target: v0.2.0 | Last updated: 2026-06-25

## 1. Goals

Turn passive honeypots into active detection surfaces. When an attacker reads a fake AWS credential file, exfiltrates a canary SSH key, or probes a planted `.env` endpoint, we know it's real, not a scanner.

**Design principles:**
- Honeytokens are **high-confidence, low-noise** alerts. Every trigger means a human looked at something they shouldn't have.
- Tokens are seeded **declaratively** via the Decoy CRD's `spec.filesystem.honeytokens` field (already in the schema) and the existing `HoneyToken` CRD (reserved stub).
- File-read monitoring must work across **all access vectors**: shell commands, SFTP, SCP.
- The NATS stream (`HONEYTOKEN_EVENTS` on `cicdecoy.honeytoken.>`) and SIEM formatter (`CICD-6001`) already exist. We wire into them.

---

## 2. Architecture Overview

```
                                    Operator
                                   reconciler.py
                                       |
                          reads spec.filesystem.honeytokens
                                       |
                                       v
                        +-----------------------------+
                        |  Decoy Pod (SSH or HTTP)    |
                        |                             |
                        |  +-----------------------+  |
                        |  | HoneytokenRegistry    |  |
                        |  | (in-memory set of     |  |
                        |  |  monitored paths +    |  |
                        |  |  token metadata)      |  |
                        |  +-----------+-----------+  |
                        |              |              |
                        |   seeds files into          |
                        |              |              |
                        |  +-----------v-----------+  |
                        |  | VirtualFilesystem     |  |  <-- base layer (immutable)
                        |  |(profile + honeytokens)|  |
                        |  +-----------+-----------+  |
                        |              |              |
                        |  +-----------v-----------+  |
                        |  | SessionFilesystem     |  |  <-- COW overlay (per-connection)
                        |  | (read_file checks     |  |
                        |  |  registry on access)  |  |
                        |  +-----------+-----------+  |
                        |              |              |
                        |   on access: emit event     |
                        |              |              |
                        |  +-----------v-----------+  |
                        |  | EventEmitter          |  |
                        |  +----------|------------+  |
                        +-------------|---------------+
                                      |
                     NATS publish to two subjects:
                     1. cicdecoy.decoy.events.{name}.honeytoken.accessed
                     2. cicdecoy.honeytoken.triggered.{token_name}
                                      |
                        +-------------v--------------+
                        |       NATS JetStream       |
                        | DECOY_EVENTS stream        |
                        | HONEYTOKEN_EVENTS stream   |
                        +-------|----------|---------+
                                |          |
                   +------------v--+  +----v-----------------+
                   | CTI Pipeline  |  | Future: HT Alerter   |
                   | (enrichment,  |  | (dedicated consumer  |
                   |  DB storage,  |  |  for instant alerts) |
                   |  republish)   |  +----------------------+
                   +-------+-------+
                           |
              enriched to cicdecoy.enriched.events.*
                           |
              +------------v-------------+
              |   Dashboard / SIEM       |
              |   (honeytoken page,      |
              |    trigger history,      |
              |    placement map)        |
              +--------------------------+
```

---

## 3. Data Model

### 3.1 Honeytoken Definition (via Decoy CRD)

The Decoy CRD already has `spec.filesystem.honeytokens` (lines 168-181 of the CRD YAML). Each entry:

```yaml
spec:
  filesystem:
    honeytokens:
      - path: /home/admin/.aws/credentials
        tokenRef: ""           # optional: reference to HoneyToken CR
        content: |             # inline content (used if tokenRef is empty)
          [default]
          aws_access_key_id = AKIAIOSFODNN7EXAMPLE
          aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
          region = us-east-1

      - path: /home/admin/.ssh/id_rsa
        content: |
          -----BEGIN OPENSSH PRIVATE KEY-----
          b3BlbnNzaC1rZXktdjEAAAAABG5vbmU... (canary key)
          -----END OPENSSH PRIVATE KEY-----

      - path: /opt/app/.env
        content: |
          DATABASE_URL=postgresql://admin:Pr0d_s3cret@db-prod-03.internal:5432/app
          FAKE_STR1P3_SECRET_KEY==EXAMPLE_KEY_DO_NOT_USE
          JWT_SECRET=super-secret-jwt-key-do-not-share
```

### 3.2 Honeytoken Registry (runtime, in-memory)

```python
@dataclass
class HoneytokenEntry:
    path: str                    # absolute path in the virtual filesystem
    token_name: str              # derived from path or explicit name
    token_type: str              # aws-key, ssh-key, env-var, database-cred, file, etc.
    content_hash: str            # SHA-256 of content (for dedup / attribution)
    alert_on_access: bool        # default True
    metadata: dict               # arbitrary KV (decoy_name, namespace, placement_time)
```

The `HoneytokenRegistry` is a dict keyed by normalized path. It is:
- Populated at server startup from the `HONEYTOKEN_MANIFEST` env var (JSON, set by the operator)
- Consulted on every `read_file()` call to determine if a trigger event should fire

### 3.3 Event Schema

```json
{
  "event_id": "uuid",
  "timestamp": "2026-06-25T12:00:00Z",
  "version": "1.0",
  "source": { "decoy": "ssh-prod-01", "tier": 2 },
  "session_id": "abc123",
  "event_type": "honeytoken.accessed",
  "data": {
    "token_name": "aws-prod-admin-canary",
    "token_type": "aws-key",
    "access_type": "file_read",
    "access_vector": "shell",
    "accessed_path": "/home/admin/.aws/credentials",
    "command": "cat /home/admin/.aws/credentials",
    "content_hash": "sha256:abcdef...",
    "client_ip": "10.42.0.5",
    "username": "admin"
  }
}
```

The `access_vector` field distinguishes how the file was accessed:
| Vector | Source |
|--------|--------|
| `shell` | Command router processed a file-reading command (`cat`, `head`, `less`, `grep`, etc.) |
| `sftp` | SFTP `open()` or `stat()` on the honeytoken path |
| `scp` | SCP download request (`scp -f`) targeting the honeytoken path |
| `http` | HTTP GET on a honeytoken endpoint (HTTP decoy only) |

---

## 4. Component Design

### 4.1 Operator Changes (`reconciler.py`)

**What changes:** When reconciling a Decoy CR that has `spec.filesystem.honeytokens`, the operator serializes the honeytoken manifest as a JSON env var on the decoy container.

```python
# In _build_decoy_deployment(), after existing env vars:
honeytokens = spec.get("filesystem", {}).get("honeytokens", [])
if honeytokens:
    manifest = []
    for ht in honeytokens:
        manifest.append({
            "path": ht["path"],
            "content": ht.get("content", ""),
            "token_name": ht.get("tokenRef") or _derive_token_name(ht["path"]),
            "token_type": _infer_token_type(ht["path"], ht.get("content", "")),
            "alert_on_access": ht.get("alertOnAccess", True),
        })
    env.append({
        "name": "HONEYTOKEN_MANIFEST",
        "value": json.dumps(manifest),
    })
```

Type inference (`_infer_token_type`) uses path and content heuristics:
| Path/Content Pattern | Inferred Type |
|---------------------|---------------|
| `.aws/credentials`, `AKIA` prefix | `aws-key` |
| `id_rsa`, `id_ed25519`, `BEGIN.*PRIVATE KEY` | `ssh-key` |
| `.env`, `DATABASE_URL=`, `SECRET_KEY=` | `env-var` |
| `.kube/config`, `kubeconfig` | `kubeconfig` |
| `password`, `credential`, `.pgpass` | `database-cred` |
| `token`, `api_key`, `bearer` | `api-token` |
| fallback | `file` |

### 4.2 SSH Decoy Changes

#### 4.2.1 HoneytokenRegistry (`ssh-decoy/honeytoken_registry.py` — new file)

```python
class HoneytokenRegistry:
    """Tracks honeytoken file paths and emits trigger events on access."""

    def __init__(self, emitter: EventEmitter):
        self._entries: dict[str, HoneytokenEntry] = {}
        self._emitter = emitter
        self._triggered: dict[str, set[str]] = {}  # path -> set of session_ids (dedup)

    def load_from_env(self):
        """Load honeytoken manifest from HONEYTOKEN_MANIFEST env var."""
        raw = os.environ.get("HONEYTOKEN_MANIFEST", "")
        if not raw:
            return
        for item in json.loads(raw):
            entry = HoneytokenEntry(...)
            self._entries[posixpath.normpath(item["path"])] = entry

    def seed_into_filesystem(self, fs: VirtualFilesystem):
        """Add honeytoken files to the base filesystem."""
        for path, entry in self._entries.items():
            fs.add_file(path, entry.content, owner="root", permissions=0o644)

    def is_honeytoken(self, path: str) -> bool:
        return posixpath.normpath(path) in self._entries

    async def on_access(self, path: str, session_id: str, access_vector: str,
                        client_ip: str, username: str, command: str = ""):
        """Called when a monitored path is accessed. Emits trigger event."""
        path = posixpath.normpath(path)
        entry = self._entries.get(path)
        if not entry or not entry.alert_on_access:
            return

        # Dedup: only fire once per session per path
        seen = self._triggered.setdefault(path, set())
        if session_id in seen:
            return
        seen.add(session_id)

        await self._emitter.emit("honeytoken.accessed", session_id, {
            "token_name": entry.token_name,
            "token_type": entry.token_type,
            "access_type": "file_read",
            "access_vector": access_vector,
            "accessed_path": path,
            "command": command,
            "content_hash": entry.content_hash,
            "client_ip": client_ip,
            "username": username,
        })

        # Also publish to the dedicated honeytoken subject
        await self._emitter.emit_to_subject(
            f"cicdecoy.honeytoken.triggered.{entry.token_name}",
            session_id, { ... same data ... }
        )
```

#### 4.2.2 Filesystem Instrumentation

**`SessionFilesystem.read_file()` — add access hook:**

```python
def read_file(self, path: str) -> str | None:
    # ... existing tombstone/overlay/base logic ...
    content = ...
    if content is not None and self._access_callback:
        self._access_callback(path)  # fires honeytoken check
    return content
```

The callback is set during server startup:

```python
# In DecoySSHServer.__init__():
def on_file_access(path):
    asyncio.ensure_future(
        honeytoken_registry.on_access(path, self._session_id, "shell", ...)
    )
self._fs.set_access_callback(on_file_access)
```

**SFTP instrumentation** — already emits `sftp.open` events. Add a honeytoken check in `DecoySFTPServer.open()`:

```python
async def open(self, path, pflags, attrs):
    # ... existing logic ...
    if self._registry.is_honeytoken(path):
        await self._registry.on_access(path, session_id, "sftp", ...)
```

**SCP instrumentation** — add check in `_handle_scp()` for download requests (`scp -f`).

#### 4.2.3 EventEmitter Addition

Add `emit_to_subject()` method for publishing to arbitrary NATS subjects (the honeytoken stream uses `cicdecoy.honeytoken.triggered.*`, not the decoy events subject):

```python
async def emit_to_subject(self, subject: str, session_id: str, data: dict):
    """Publish to a specific NATS subject (for honeytoken triggers)."""
    event = self._build_event("honeytoken.accessed", session_id, data)
    if self._connected and self.nc:
        await self.nc.publish(subject, json.dumps(event, default=str).encode())
```

### 4.3 HTTP Decoy Changes

The HTTP decoy serves honeytoken files as **route endpoints** (not static files). This is better; each route has its own telemetry.

#### New: `routes/honeytokens.py`

```python
# Configurable honeytoken endpoints served by the HTTP decoy.
# Loaded from HONEYTOKEN_MANIFEST env var (same format as SSH decoy).

from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse

router = APIRouter()

def register_honeytoken_routes(router, registry, emitter):
    """Dynamically register routes for each honeytoken path."""
    for entry in registry.entries():
        _register_one(router, entry, emitter)

def _register_one(router, entry, emitter):
    @router.get(entry.path)
    async def serve_honeytoken(request: Request):
        await emitter.emit("honeytoken.accessed", ...)
        return PlainTextResponse(entry.content)
```

#### Existing routes to upgrade:

| Current Route | Current Response | Upgrade |
|--------------|-----------------|---------|
| `/.env` | 403 Forbidden | Serve realistic `.env` content with canary credentials |
| `/config.php`, `/wp-config.php` | 403 Forbidden | Serve realistic PHP config with DB credentials |
| `/backup.sql`, `/dump.sql` | 403 Forbidden | Serve small SQL dump with fake user table |
| `/robots.txt` | Disallow list | Add hidden honeytoken paths as Disallow entries |

The upgrade is **opt-in** via the Decoy CR's honeytoken config. Default behavior stays as-is (403).

### 4.4 CTI Pipeline Changes

**1. Add `HONEYTOKEN_EVENTS` to `_ensure_streams()`:**

```python
StreamConfig(name="HONEYTOKEN_EVENTS", subjects=["cicdecoy.honeytoken.>"],
             max_age=720 * 3600, max_bytes=134217728),  # 128 MB
```

**2. Honeytoken events via existing pipeline:**

Honeytoken events published to `cicdecoy.decoy.events.*.honeytoken.accessed` flow through the existing `DECOY_EVENTS` stream and CTI pipeline. They are stored in `decoy_events` with `event_type = 'honeytoken.accessed'`, enriched with MITRE ATT&CK technique `T1552.001` (Credentials In Files), and severity `critical`.

The duplicate publish to `cicdecoy.honeytoken.triggered.*` goes to the `HONEYTOKEN_EVENTS` stream for a future dedicated alerter consumer (out of scope for v0.2.0, alerts go through the existing `AlertForwarder`).

**3. Enrichment additions** (`cti/enrichment.py`):

```python
# Honeytoken access is always critical and maps to T1552.001
if event_type == "honeytoken.accessed":
    result["severity"] = "critical"
    result["mitre_techniques"].append({
        "id": "T1552.001",
        "name": "Credentials In Files",
        "tactic": "Credential Access",
    })
    # Additional techniques based on token_type:
    if token_type == "ssh-key":
        result["mitre_techniques"].append({"id": "T1552.004", ...})  # Private Keys
    elif token_type == "kubeconfig":
        result["mitre_techniques"].append({"id": "T1552.001", ...})
```

**4. Engage mapping** — already exists in `cti/engage_mapper.py` (`HONEYTOKEN_MAPPING`). The `EngageEnricher` already increments `honeytokens_triggered` in the session outcome.

### 4.5 Dashboard Changes

**New API endpoint:**

```python
@app.get("/api/honeytokens", dependencies=[Depends(require_api_key)])
async def get_honeytokens(limit: int = 50, offset: int = 0):
    """List honeytoken trigger events with aggregation."""
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT
                raw_data->>'token_name' AS token_name,
                raw_data->>'token_type' AS token_type,
                raw_data->>'accessed_path' AS path,
                decoy_name,
                COUNT(*) AS trigger_count,
                MAX(timestamp) AS last_triggered,
                array_agg(DISTINCT source_ip::text) AS source_ips
            FROM decoy_events
            WHERE event_type = 'honeytoken.accessed'
            GROUP BY token_name, token_type, path, decoy_name
            ORDER BY last_triggered DESC
            LIMIT $1 OFFSET $2
        """, limit, offset)
    return {"honeytokens": [dict(r) for r in rows], ...}
```

**New frontend page** (`src/pages/Honeytokens.jsx`):
- Table: token name, type, decoy, trigger count, last triggered, source IPs
- Detail drill-down: full trigger timeline for a specific token
- Placement map: which decoys have which tokens (from stats/config)

**New API client function** (`src/api/client.js`):
```javascript
export const fetchHoneytokens = (limit = 50) => get(`/api/honeytokens?limit=${limit}`);
```

### 4.6 CLI Changes

The CLI already has `cicdecoy intel honeytokens` (read-only). For v0.2.0, no additional CLI work is required, the existing subcommand queries `decoy_events WHERE event_type = 'honeytoken.triggered'` and will pick up the new events automatically.

Future (v0.3.0): top-level `cicdecoy honeytokens` command group with `place`, `rotate`, `status`.

---

## 5. Implementation Phases

### Phase 1: Core Plumbing (SSH Decoy)

| Task | Files | Effort |
|------|-------|--------|
| Create `HoneytokenRegistry` class | `ssh-decoy/honeytoken_registry.py` (new) | M |
| Add `HONEYTOKEN_MANIFEST` env var parsing at startup | `ssh-decoy/server.py` (main) | S |
| Seed honeytoken files into `VirtualFilesystem` at boot | `ssh-decoy/server.py` (main), `filesystem.py` | S |
| Add read-access callback to `SessionFilesystem.read_file()` | `ssh-decoy/cow_filesystem.py` | S |
| Wire callback to honeytoken check in `DecoySSHServer` | `ssh-decoy/server.py` | S |
| Add honeytoken check to SFTP `open()` | `ssh-decoy/server.py` (DecoySFTPServer) | S |
| Add honeytoken check to SCP download handler | `ssh-decoy/server.py` (_handle_scp) | S |
| Add `emit_to_subject()` to EventEmitter | `ssh-decoy/server.py` | S |
| Unit tests for HoneytokenRegistry | `tests/ssh-decoy/test_honeytoken_registry.py` (new) | M |

### Phase 2: Operator + Decoy CRD Integration

| Task | Files | Effort |
|------|-------|--------|
| Parse `spec.filesystem.honeytokens` in reconciler | `platform/operator/reconciler.py` | S |
| Serialize manifest to `HONEYTOKEN_MANIFEST` env var | `platform/operator/reconciler.py` | S |
| Add `_infer_token_type()` helper | `platform/operator/reconciler.py` | S |
| Add example honeytokens to test-decoy fixture | `tests/e2e/fixtures/test-decoy.yaml` | S |
| Unit tests for operator honeytoken handling | `tests/operator/test_reconciler.py` | M |

### Phase 3: CTI Pipeline + Enrichment

| Task | Files | Effort |
|------|-------|--------|
| Add `HONEYTOKEN_EVENTS` to `_ensure_streams()` | `cti/pipeline.py` | S |
| Add honeytoken-specific enrichment rules | `cti/enrichment.py` | S |
| Verify Engage mapping triggers on honeytoken events | `cti/engage_mapper.py` (already exists) | S |
| Verify SIEM forwarder routes honeytoken events | `siem-forwarder/formatter/formatter.go` (already exists) | S |

### Phase 4: HTTP Decoy Honeytokens

| Task | Files | Effort |
|------|-------|--------|
| Create `routes/honeytokens.py` with dynamic route registration | `http-decoy/routes/honeytokens.py` (new) | M |
| Upgrade `/.env` route to serve canary content (opt-in) | `http-decoy/routes/admin.py` | S |
| Add `HONEYTOKEN_MANIFEST` parsing to HTTP decoy config | `http-decoy/config.py` | S |
| Add honeytoken access event emission | `http-decoy/telemetry.py` | S |

### Phase 5: Dashboard + Observability

| Task | Files | Effort |
|------|-------|--------|
| Add `/api/honeytokens` endpoint | `dashboard/main.py` | M |
| Add `fetchHoneytokens()` to API client | `dashboard/src/api/client.js` | S |
| Create `Honeytokens.jsx` page | `dashboard/src/pages/Honeytokens.jsx` (new) | M |
| Register route and nav link | `dashboard/src/App.jsx`, `src/components/Header.jsx` | S |
| Add Prometheus `honeytoken_triggers_total` counter | `ssh-decoy/metrics.py`, `http-decoy/metrics.py` | S |

### Phase 6: E2E Verification

| Task | Files | Effort |
|------|-------|--------|
| Add honeytoken to e2e test-decoy fixture | `tests/e2e/fixtures/test-decoy.yaml` | S |
| Extend `run_smoke.sh` to access honeytoken and verify event | `tests/e2e/run_smoke.sh` | M |
| Add docker-compose integration test for honeytoken flow | `.github/workflows/integration.yaml` | M |

---

## 6. Example: End-to-End Flow

1. **User defines** a Decoy CR with honeytokens:

   ```yaml
   spec:
     filesystem:
       honeytokens:
         - path: /home/admin/.aws/credentials
           content: |
             [default]
             aws_access_key_id = AKIAIOSFODNN7EXAMPLE
             aws_secret_access_key = wJalrXUtnFEMI/K7MDENG
   ```

2. **Operator** reconciles: serializes the manifest as `HONEYTOKEN_MANIFEST` env var on the decoy pod.

3. **SSH decoy starts**: parses `HONEYTOKEN_MANIFEST`, seeds `/home/admin/.aws/credentials` into the `VirtualFilesystem`, registers the path in `HoneytokenRegistry`.

4. **Attacker connects** via SSH, runs `cat /home/admin/.aws/credentials`.

5. **CommandRouter** processes the `cat` command, calls `SessionFilesystem.read_file("/home/admin/.aws/credentials")`.

6. **read_file()** returns the content and fires the access callback.

7. **HoneytokenRegistry.on_access()** matches the path, emits:
   - `honeytoken.accessed` event to `cicdecoy.decoy.events.ssh-prod-01.honeytoken.accessed`
   - Duplicate to `cicdecoy.honeytoken.triggered.aws-prod-admin-canary`

8. **CTI Pipeline** receives the event, enriches with `T1552.001` (Credentials In Files), severity `critical`, stores in TimescaleDB.

9. **Dashboard** shows the trigger in the Honeytokens page. **AlertForwarder** sends a critical alert to configured channels (Slack/PagerDuty).

10. **SIEM Forwarder** exports the event with signature `CICD-6001` and severity 9.

---

## 7. Security Considerations

- **Content in env vars:** The `HONEYTOKEN_MANIFEST` env var contains fake credential content. This is intentional — the content IS the deception. The env var is not a real secret; it's bait. However, it should not appear in Kubernetes `describe` output unnecessarily. Consider using a ConfigMap or Secret for the manifest in a future iteration.
- **Dedup:** The registry deduplicates triggers per (path, session_id) to prevent alert fatigue from repeated `cat` commands in the same session.
- **Rate limiting:** A global rate limit on honeytoken trigger events prevents an attacker who discovers the monitoring from flooding the alert pipeline. Cap at 100 triggers per minute per decoy.
- **Content uniqueness:** For attribution, each deployment's honeytoken content should include a unique identifier (e.g., a UUID embedded in a comment or unused field) so that if the credential appears in the wild, it can be traced back to the specific decoy and session.
