# Dashboard Authentication

The CI/CDecoy dashboard gates all `/api/*` routes and the live SSE event
stream behind a shared API key. This is a single team-wide secret (not
multi-user); OIDC can layer on later.

## How It Works

| Component | Mechanism |
|-----------|-----------|
| REST calls (`/api/*`) | `X-API-Key` header |
| SSE (`/api/events/stream`) | `?api_key=<key>` query param (browser `EventSource` cannot set headers) |
| Healthcheck (`/healthz`) | **Public** -- Kubernetes liveness/readiness probes |
| Prometheus (`/metrics`) | **Public** -- scrape target |
| Static assets (`/`, `/assets/*`) | **Public** -- the React SPA and login modal must load before the key is entered |

Unauthorized requests receive `401 Unauthorized` with a `WWW-Authenticate: ApiKey` header. Key comparison uses `secrets.compare_digest` (constant-time).

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DASHBOARD_API_KEY` | In production | _(empty)_ | The shared API key. When blank in dev, an ephemeral key is generated and logged to stdout. |
| `DASHBOARD_REQUIRE_AUTH` | No | `false` | Force auth requirement even outside Kubernetes. |
| `DASHBOARD_DEV_MODE` | No | _(auto)_ | Not explicitly checked; dev mode is inferred when `KUBERNETES_SERVICE_HOST` is absent and `DASHBOARD_REQUIRE_AUTH` is not `true`. |

## Local Development

```bash
# Option 1: Let the backend generate an ephemeral key (check container logs)
docker compose up

# Option 2: Set an explicit key
echo 'DASHBOARD_API_KEY=my-dev-key-here' >> .env
docker compose up
```

The ephemeral key is printed at startup in a banner:

```
========================================================================
[auth] WARNING  No API key set; generated ephemeral key: <base64-key>
[auth]          Set DASHBOARD_API_KEY for production or persistent dev use.
========================================================================
```

Copy the key and paste it into the dashboard login modal.

## Kubernetes / Helm

Add to your `values.yaml`:

```yaml
dashboard:
  auth:
    # Option A: Reference an existing Secret (recommended for production)
    existingSecret: "my-dashboard-secret"   # must contain key "api-key"

    # Option B: Set the key directly (NOT recommended -- stored in plain text)
    apiKey: ""

    # Option C: Leave both blank -- the chart generates a random 32-char key
    # in a Secret named "<release>-dashboard-auth" on first install and
    # preserves it across upgrades.

    required: true   # Default. The backend refuses to start without a key.
```

The generated Secret can be read with:

```bash
kubectl get secret <release>-dashboard-auth -o jsonpath='{.data.api-key}' | base64 -d
```

## Frontend Behavior

1. On load, the React SPA checks `localStorage` for `cicdecoy_api_key`.
2. If missing, a full-screen modal prompts for the key.
3. On submit, the key is stored in `localStorage` and used for all subsequent
   `fetch()` calls (via `X-API-Key` header) and the SSE connection (via
   `?api_key=` query param).
4. On any `401` response, the stored key is cleared and the modal re-appears.
5. The header "Sign out" button manually clears the key and re-prompts.
