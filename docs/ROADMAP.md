# CI/CDecoy Roadmap

> Last updated: 2026-06-26 | Current version: 0.1.0

This document describes the planned development trajectory for CI/CDecoy. It is organized into versioned milestones with clear goals, scope, and priorities. Items marked with a checkbox indicate completion status.

For the current state of the project, see [CHANGELOG.md](../CHANGELOG.md).

---

## v0.2.0 — Operational Readiness

**Goal:** Make CI/CDecoy usable for real SOC teams by wiring alerts to where operators actually look, activating the honeytoken subsystem, and hardening CI/CD.

**Target:** Q3 2026

### Alerting & Notifications

The NATS alert stream (`cicdecoy.alert.>`) produces high-quality alerts today (kill chain, C2 detection, dangerous progressions, high behavioral score). They just don't go anywhere operators will see them.

- [x] **Slack integration** — Block Kit formatted alerts to configurable Slack channels via incoming webhooks. Includes severity, source IP, decoy name, MITRE technique, and command.
- [x] **Microsoft Teams integration** — MessageCard formatting for Teams channels.
- [ ] **Email alerts** — SMTP-based delivery for critical/high severity events. Configurable recipients and throttling.
- [x] **PagerDuty integration** — Events API v2 triggers for critical alerts with severity mapping.
- [ ] **Generic webhook** — POST alert JSON to any URL, enabling custom integrations (SOAR, ticketing, Lambda/Cloud Functions).
- [ ] **Alert routing rules** — configure which alert types go to which channels (e.g., C2 -> PagerDuty, credential stuffing -> Slack).

### Honeytokens — Type 1 (Access Detection)

Self-contained, zero-external-dependency honeytoken system. See [honeytoken-architecture.md](design/honeytoken-architecture.md) and [honeytoken-types-adr.md](design/honeytoken-types-adr.md).

- [x] **Shared HoneytokenRegistry** — decoy-agnostic registry in `lib/` loaded from `HONEYTOKEN_MANIFEST` env var. Handles type inference, filesystem seeding, access dedup, and event emission.
- [x] **SSH decoy integration** — `read_file()` access callback on the COW filesystem. Fires `honeytoken.accessed` events on shell, SFTP, and SCP access vectors.
- [x] **HTTP decoy integration** — `/.env`, `/config.php`, `/wp-config.php`, `/backup.sql` routes serve canary content when honeytokens are configured.
- [x] **Operator support** — parses `spec.filesystem.honeytokens` from Decoy CRD, serializes as `HONEYTOKEN_MANIFEST` env var with inferred token type.
- [x] **CTI enrichment** — honeytoken events get severity=critical, MITRE T1552.001 (Credentials In Files), T1552.004 (Private Keys) for SSH keys.
- [x] **Cross-decoy credential correlation** — CTI pipeline detects when credentials planted as honeytokens in one decoy are used to authenticate on another decoy.
- [x] **Dashboard honeytoken page** — trigger history, per-token drill-down with event fetching. Backend aggregation + detail endpoints, React frontend with stat cards, token table, and detail panel.
- [x] **Environment variable honeytokens** — inject canary credentials as env vars visible to attackers who run `env` or `printenv`. Monitored via `_check_env_honeytoken_access` in SSH decoy.
- [ ] **CLI honeytoken commands** — `cicdecoy honeytoken place`, `cicdecoy honeytoken list`, `cicdecoy honeytoken triggers`.

### Threat Intelligence Feeds

IP reputation and known-bad indicators transform honeypot data from "someone connected" to "a known Cobalt Strike operator connected."

- [ ] **GreyNoise integration** — enrich source IPs with GreyNoise RIOT/NOISE classification. Distinguish scanners from targeted attacks.
- [ ] **abuse.ch integration** — check IPs and hashes against abuse.ch threat feeds (URLhaus, ThreatFox, Feodo Tracker).
- [ ] **AlienVault OTX integration** — pull IOC context (related campaigns, threat actors, malware families).
- [ ] **Shodan integration** — reverse-lookup attacker IPs for exposed services, OS fingerprints, and hosting provider.
- [ ] **Feed caching layer** — local cache with TTL to avoid rate limits and reduce latency. Configurable per-feed.
- [ ] **Cross-session IOC correlation** — detect the same tool, credential, or IP across multiple sessions. Surface repeat visitors and campaign patterns.

### SIEM Export Maturity

- [ ] **Splunk HEC retry & batching** — configurable batch size, exponential backoff on 5xx failures, dead-letter queue for undeliverable events.
- [ ] **Elastic Data Streams** — native Elasticsearch data stream support with ILM policy templates and index template management.
- [ ] **LEEF format completion** — finish the declared-but-incomplete LEEF formatter in the SIEM forwarder.
- [ ] **ECS format completion** — finish the declared-but-incomplete Elastic Common Schema formatter.
- [ ] **Microsoft Sentinel** — direct integration via Azure Monitor Data Collector API.
- [ ] **Datadog** — native Datadog log integration.
- [ ] **Event filtering** — configurable filters so operators can forward only specific event types or severity levels.
- [ ] **SIEM circuit breaker** — exponential backoff and circuit breaker pattern for failing SIEM endpoints.
- [ ] **Webhook request signing** — HMAC-SHA256 signatures for webhook output sink.

### SSH Decoy — Fidelity Improvements (Small)

These are quick wins that reduce the risk of an attacker detecting the honeypot.

- [ ] **Expand command coverage to 300+ responses** — attackers running `lsblk`, `df -h`, `free -m`, `ss -tlnp`, `journalctl`, `timedatectl`, `ip route` get empty output, which is an immediate fingerprint. (#1)
- [ ] **Increase MITRE enrichment coverage to 85%+** — currently 77% (41/53 relevant Linux techniques). Add T1048 (Exfiltration), T1071 (Application Layer Protocol), T1027 (Obfuscated Files), T1059.004 (Unix Shell), T1547.006 (Kernel Modules). (#5)
- [x] **Add /dev/null, /dev/zero, /dev/urandom, /dev/random** — attackers commonly reference these; now populated in virtual filesystem.
- [ ] **Add /proc/self directory** — with cmdline, environ, maps stubs. Every containerized attacker expects this.
- [ ] **Add missing SSH environment variables** — SSH_CLIENT, SSH_CONNECTION, SSH_TTY, HISTFILE, HISTSIZE, EDITOR, COLUMNS, LINES.
- [ ] **Improve sudo realism** — support `sudo -i` (interactive root shell), `sudo -u user` (user switching), and respect a simulated sudoers timeout.
- [x] **Add /etc/sudoers stub** — realistic Ubuntu sudoers with 0440 permissions.
- [ ] **Brace expansion** — `echo {1..5}` should expand to `1 2 3 4 5`, not output the literal string.
- [x] **Glob pattern matching** — `ls *.txt` matches files in the virtual filesystem via fnmatch.
- [x] **Add `time` command** — wraps command execution with real/user/sys timing output.
- [x] **Add `seq` command** — sequence generation with 3 forms (end, start end, start step end), 10K safety cap.
- [x] **Add `diff` command** — basic unified diff between two files.

### HTTP Decoy — Small Improvements

- [ ] **Add security headers** — X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Content-Security-Policy on all responses.
- [ ] **Add X-Powered-By spoofing** — configurable per portal (e.g., PHP/7.4.33 for WordPress, Express for Node apps).
- [x] **Add 500 Internal Server Error page** — nginx-style HTML 500 page with global exception handler.
- [ ] **CORS preflight responses** — return proper Access-Control-Allow-* headers on OPTIONS requests.
- [ ] **Wire HTTP enrichment into pipeline** — HTTP request classifier exists but isn't integrated with the CTI pipeline event flow.

### Dashboard — Analyst Workflow

- [ ] **Filter healthcheck noise** — Docker/Kubernetes healthcheck connections from 127.0.0.1 pollute top attacker IPs, session counts, and the live event feed. Add query-level filtering. (#11)
- [ ] **Session triage workflow** — add triage status to sessions (new/in-progress/reviewed) so analysts can track review progress. Filter buttons on the Sessions page. (#9)
- [ ] **Session duration histogram** — distribution of session durations to measure how convincing decoys are. Bucket by tier and decoy type. The `duration_seconds` field already exists. (#7)
- [ ] **Kill chain timeline visualization** — horizontal bar chart showing attack phases in chronological order for sessions with 3+ tactics. Color-coded by tactic. (#6)
- [ ] **Geo visualization for source IPs** — the `geo` JSONB field exists and `/api/geo` returns data. Need a frontend map or country-frequency table. (#8)

### Testing & Quality

- [x] **Go test coverage** — unit tests for CLI (48 tests), SIEM forwarder (33 tests), and adapter framework (50 tests).
- [x] **React component tests** — Vitest with React Testing Library for dashboard components (48 tests across 11 components).
- [x] **Honeytoken test suite** — 64 tests covering registry, enrichment, credential correlation, HTTP routes, and operator integration.
- [x] **E2E Kubernetes smoke test** — k3d cluster, Helm install, operator reconciliation, SSH probe, event pipeline verification.
- [x] **Docker Compose integration test** — full stack smoke test with SSH connection, pipeline, and dashboard health check.
- [x] **Contract tests** — 15 tests verifying NATS message schemas between producers (decoys) and consumers (pipeline, dashboard, forwarder).
- [x] **Fuzz testing** — 30 tests fuzzing SSH command router and HTTP request classifier with malformed inputs.

### Supply Chain Security

- [x] **Chainguard base images** — all Python and Go services use zero-CVE Chainguard images.
- [x] **Trivy container scanning** — all 8 container images scanned for CVEs in CI.
- [x] **CodeQL SAST** — static analysis for Go and Python in every PR.
- [x] **Gitleaks secret scanning** — pre-commit and CI checks for leaked secrets.
- [x] **pip-audit** — dependency vulnerability scanning for all Python services.
- [x] **golangci-lint** — comprehensive Go linting (errcheck, staticcheck, gosec, gocritic, revive, misspell).
- [x] **Prettier** — frontend code formatting with CI enforcement.
- [x] **SBOM generation** — Syft SBOM generation in release workflow for all container images.
- [x] **Cosign artifact signing** — Sigstore cosign keyless signing with GitHub OIDC in release workflow.
- [x] **OpenSSF Scorecard** — automated supply chain security posture assessment via scorecard.yaml workflow.

---

## v0.3.0 — Protocol Expansion & Adaptive Deception

**Goal:** Expand beyond SSH and HTTP to cover the protocols attackers encounter most in enterprise and cloud environments. Introduce adaptive deception orchestration and external honeytoken monitoring.

**Target:** Q4 2026

### Honeytokens — Type 2 (Usage Detection)

Detect when exfiltrated credentials are used on real external systems. See [honeytoken-types-adr.md](design/honeytoken-types-adr.md).

- [ ] **`externalMonitor` CRD field** — add to `HoneyToken` CRD spec for configuring external monitoring providers.
- [ ] **Webhook receiver** — `/api/webhook/canarytoken` on CTI pipeline with HMAC-SHA256 validation.
- [ ] **Self-hosted Canarytokens integration** — factory API client for token creation, webhook delivery to CI/CDecoy.
- [ ] **AWS CloudTrail integration** — EventBridge rule template for zero-permission IAM canary credentials.
- [ ] **GCP Audit Log integration** — service account key honeytokens with Cloud Logging alerts.
- [ ] **DNS callback tokens** — embed unique FQDNs in config files, detect DNS resolution from external networks.
- [ ] **Per-session unique tokens** — template engine for `{{session_id}}`, `{{timestamp}}`, `{{client_ip}}` placeholders in token content.
- [ ] **Token rotation** — automatic credential rotation on schedule or post-trigger.
- [ ] **Correlation engine** — match external trigger to original placement, session, and attacker.

### Dolos — Forgery Engine (Powers Tier 3)

*In Greek mythology, Dolos was Prometheus's apprentice. When Prometheus sculpted Aletheia (Truth) from clay, Dolos attempted to forge an identical copy. He ran out of clay for the feet, but the duplicate was otherwise so perfect it was nearly indistinguishable from the original — and that copy became Pseudologos, Falsehood.*

Dolos is CI/CDecoy's content generation engine. It is the difference between Tier 2 and Tier 3. **Tier 3 is not a different runtime** — it is a Tier 2 decoy whose filesystem has been pre-populated by Dolos with hundreds of realistic, internally-consistent artifacts at deploy time. The attacker never talks to an LLM. They explore the same scripted Tier 2 shell, but the environment looks lived-in because Dolos filled it.

**Why this is better than real-time LLM responses:**
- No latency fingerprint — every command responds at Tier 2 speed (instant)
- No prompt injection surface — the LLM is not in the session path
- Consistency — the filesystem is pre-generated and self-referencing, the LLM can't contradict itself across commands
- Testable — operators can inspect, version, and diff what Dolos generated before deploying
- Deterministic — same seed produces same filesystem, reproducible for forensics

**What Dolos generates at deploy time:**

- [ ] **Patterns of life** — realistic `.bash_history` with plausible command sequences (package installs, git operations, Docker builds, SSH sessions to internal hosts). Cron job output in `/var/log/`. Systemd service files. Recent `apt` install logs. `pip freeze` output matching the decoy's persona.
- [ ] **Home directory artifacts** — code projects with git history, `README.md` files, `Makefile`, `docker-compose.yaml`, `.gitconfig`, `.vimrc`, `.ssh/config`, `Downloads/` with plausible filenames, `.local/share/` app data.
- [ ] **Credential artifacts** — realistic AWS credentials, SSH key pairs, database connection strings, API tokens, kubeconfig files. Valid structure and formatting, but zero-permission or non-functional. Each is a tracked honeytoken.
- [ ] **Application state** — log files that look recent, database dumps with realistic schemas, config files with internal hostnames, `.env` files with plausible service URLs.
- [ ] **Profile-driven content** — Dolos reads the decoy's identity profile (company name, domain, OS, users) and generates content that matches the persona. A "fintech startup" decoy gets Stripe keys and PostgreSQL dumps; a "government contractor" gets PIV certificates and LDAP configs.
- [ ] **Breadcrumb weaving** — automatically plant cross-references between decoys. SSH decoy's `.bash_history` contains `ssh deploy@{http-decoy-hostname}`. HTTP decoy's `/config.json` contains database credentials for the MySQL decoy. Each breadcrumb is a tracked honeytoken.
- [ ] **Unique-per-deployment generation** — every `helm install` produces a fresh set of fake credentials, hostnames, and file contents. No two deployments share the same canary material, enabling precise attribution when credentials appear in the wild.
- [ ] **Validation engine** — verify that generated content passes format checks (AWS key structure, valid JSON/YAML, syntactically correct SQL) without being usable on real services.

**Dolos implementation:**

- [ ] **Dolos CLI / init container** — runs at deploy time (Helm hook or init container). Reads the decoy profile, calls the inference gateway, writes the generated filesystem to a ConfigMap or PVC that the decoy pod mounts.
- [ ] **LLM backend** — uses the existing inference gateway (Ollama, local models). No API keys required. The LLM generates content offline — before the decoy accepts connections.
- [ ] **Template library** — pre-built prompt templates for each content type (bash_history, git repo, Docker project, etc.). Operators can add custom templates.
- [ ] **Content cache** — cache generated content per profile so re-deploys don't re-generate unless the profile changes. Store in PVC or ConfigMap.
- [ ] **Guardrail filter** — scan generated content for patterns that reveal the deception (mentions of "honeypot", "decoy", "cicdecoy", model-specific phrases). Strip before deployment.

### HTTP Tier 3 (Dolos-Generated Content)

HTTP Tier 3 follows the same principle: Dolos pre-generates content at deploy time, and the Tier 2 route handlers serve it. The protocol layer (status codes, headers, redirects, auth flows) remains scripted. Only the *content* is richer.

- [ ] **Pre-generated page content** — Dolos generates realistic blog posts, user directories, file listings, and search result pages. Stored as static HTML/JSON files, served by existing Tier 2 routes.
- [ ] **Fake data seeding** — Dolos generates plausible API response datasets (user lists, config objects, database records). The Tier 2 API routes serve from these pre-generated datasets instead of hardcoded stubs.
- [ ] **Consistent internal linking** — generated pages reference each other (blog post links to author profile, API pagination works across pre-generated pages).
- [ ] **Response filtering** — extend the guardrail filter to catch infrastructure leakage in generated HTTP content.

### MySQL / PostgreSQL Decoy

- [ ] **Wire protocol implementation** — handle MySQL/PostgreSQL client handshake, authentication, and query execution.
- [ ] **SQL parser subset** — parse SELECT, INSERT, UPDATE, DELETE, SHOW, DESCRIBE. Return plausible result sets from a seeded fake schema.
- [ ] **Credential capture** — log authentication attempts with username, password, and client fingerprint.
- [ ] **Query classification** — map SQL queries to MITRE techniques (T1005 Data from Local System, T1552 Unsecured Credentials).
- [ ] **Configurable schemas** — define fake databases, tables, and seed data via profile JSON.

### Kubernetes API Decoy

- [ ] **REST API emulation** — serve a subset of the Kubernetes API (pods, secrets, configmaps, deployments, namespaces, RBAC).
- [ ] **Fake cluster state** — return plausible pod lists, secret metadata, and RBAC policies.
- [ ] **kubectl capture** — identify and log kubectl client interactions, API versions, and auth tokens.
- [ ] **Cloud metadata decoy** — emulate cloud instance metadata endpoints (169.254.169.254) for SSRF and credential harvesting detection.
- [ ] **MITRE mapping** — T1552.007 (Container API), T1613 (Container and Resource Discovery).

### SMB / File Share Decoy

- [ ] **SMB2/3 protocol handling** — share listing, directory browsing, file download.
- [ ] **Honeytoken files** — seed shares with canary documents (fake credentials, financial data, PII).
- [ ] **Access logging** — capture file enumeration patterns, download attempts, and lateral movement indicators.

### SSH Decoy: Major Fidelity Features

These are larger efforts that significantly improve deception quality for skilled attackers.

- [x] **SFTP subsystem** — asyncssh SFTPServer backed by per-session virtual filesystem. Full stat/scandir/read/write/mkdir/rmdir/remove/rename with telemetry.
- [x] **SCP protocol** — SCP binary protocol handler for upload and download. Files captured in virtual FS with telemetry. 10 MB cap.
- [x] **SSH port forwarding** — accepts local (-L), remote (-R), and dynamic (-D) forwarding requests. Logs tunnel endpoints but black-holes traffic (no actual forwarding).
- [ ] **SSH agent forwarding** — accept agent forwarding requests. Log forwarded key fingerprints.
- [ ] **Script execution** — `bash script.sh`, `python script.py`, `chmod +x && ./script` should attempt to parse and execute commands within the script content. Even basic line-by-line execution would be a major improvement.
- [ ] **Symlink support** — `ln -s` should create symlinks in the virtual filesystem. `ls -l` should show symlink indicators. Currently silently ignored.
- [x] **Shell control flow** — `if/then/fi`, `for/do/done`, `while` loop support for one-liners. Iteration capped at 100. Supports `seq` expansion.
- [ ] **Input redirection** — support `< file` (read from file) and `2>` (stderr redirect). Currently only `>` and `>>` work.
- [ ] **Here-documents** — `cat << EOF ... EOF` should work. Common in attacker scripts.
- [ ] **Arithmetic expansion** — `$((2+2))` should evaluate to `4`.

### CTI Pipeline — Enrichment Expansion

- [ ] **Container/Kubernetes attack patterns** — detect etcd abuse, kubelet exploitation, Docker socket abuse, CDK tool usage.
- [ ] **Additional tool signatures** — Mythic C2, PoshC2, SAMRDump, procdump, container escape tools (cdk, deepce).
- [ ] **Behavioral heuristics** — detect command chaining patterns (recon -> privesc -> exfil sequences) beyond individual technique classification.
- [ ] **Cloud service discovery** — detect `aws s3 ls`, `gcloud compute instances list`, `az vm list` and similar cloud enumeration.

### Hydra — Adaptive Deception Orchestration

Hydra is a closed-loop adaptive orchestrator that consumes CTI pipeline intelligence and dynamically adapts the deception infrastructure. See [hydra-adaptive-orchestration-spec.md](specifications/hydra-adaptive-orchestration-spec.md) for the full specification and [hydra-adr.md](design/hydra-adr.md) for engineering decision rationale.

- [ ] **HydraStrategy CRD** — new custom resource defining adaptive response policies with trigger conditions, actions, and safety constraints.
- [ ] **Decision engine** — asyncio service consuming `cicdecoy.alert.session.>`, evaluating strategies, dispatching actions.
- [ ] **Dynamic decoy deployment** — create Decoy CRs from DecoyTemplates in response to attacker classification (scanner -> advanced_threat).
- [ ] **Runtime breadcrumb injection** — NATS control messages inject files (`.ssh/known_hosts`, `.aws/credentials`, `.bash_history`) into running decoys based on attacker behavior.
- [ ] **Contextual honeytoken placement** — generate canary credentials (AWS keys, kubeconfigs, SSH keys) tailored to observed attacker interests, tracked via HoneyToken CRs.
- [ ] **Tier escalation** — automatically promote decoys from Tier 1->2->3 when high-value attackers are detected (patches Decoy CR, operator reconciles).
- [ ] **Human approval gate** — high-risk strategies queue for operator approval before execution.
- [ ] **TTL reaper** — auto-retire dynamic decoys after configurable duration to prevent resource sprawl.
- [ ] **Safety constraints** — per-strategy cooldowns, global resource caps, circuit breaker, audit trail in TimescaleDB.
- [ ] **Default strategies** — 5 example HydraStrategy manifests: scanner-breadcrumb, operator-escalate, advanced-threat-engage, c2-detected-expand, kill-chain-alert.

### Validation & Documentation

- [ ] **Deploy on VPS and collect real attacker data** — deploy CI/CDecoy on a public VPS to collect real-world attacker telemetry. This is the credibility artifact — nothing substitutes for real data from real adversaries. (#19)
- [ ] **Extract Deception as Code spec** — publish the DaC concept as a standalone specification document, independent of the CI/CDecoy implementation. Publishable, citable, and referenceable by other projects. (#17)
- [ ] **Inference gateway as Dolos backend** — the existing inference gateway becomes Dolos's LLM backend. Extract into a standalone service with prompt engine, response filter, and template cache. Runs at deploy time, not session time. (#25)

---

## v0.4.0 — Intelligence Maturity

**Goal:** Transform raw honeypot data into actionable, shareable threat intelligence with advanced analytics and visualization. Begin community engagement with real data and published reports.

**Target:** Q1 2027

### STIX / TAXII

- [ ] **STIX 2.1 full bundle export** — generate complete STIX bundles with Indicators, Observed Data, Attack Patterns, Threat Actors, and Relationships. Currently only basic indicator conversion exists.
- [ ] **TAXII 2.1 server** — serve collections of STIX objects for automated intel sharing with ISACs, partners, and other platforms.
- [ ] **Automated bundle generation** — produce STIX bundles on session close, triggered by alert thresholds, or on a schedule.

### Attacker Fingerprinting & Attribution

- [ ] **Tool fingerprint library** — expanded signature database beyond the current 48 tools. Add Mythic, PoshC2, container-specific tools.
- [ ] **Cross-session actor clustering** — identify repeat attackers across sessions using behavioral patterns, tool overlap, credential reuse, and timing.
- [ ] **Infrastructure reuse detection** — flag shared C2 infrastructure, staging servers, and proxy chains across campaigns.
- [ ] **TTP profile generation** — produce per-actor profiles summarizing observed techniques, tools, and objectives.
- [ ] **Keystroke timing analysis** — distinguish human operators from automated C2 frameworks based on inter-keystroke intervals.

### Advanced Analytics

- [ ] **Behavioral anomaly detection** — identify sessions that deviate significantly from observed baselines (unsupervised clustering).
- [ ] **Engagement effectiveness scoring** — measure which decoy configurations generate the most intelligence per session. Compare tiers, profiles, and portal types.
- [ ] **Dwell time analysis** — track how long attackers engage before abandoning or escalating. Correlate with decoy fidelity tier.
- [ ] **Campaign timeline reconstruction** — link related sessions into multi-day campaign views based on shared IOCs, timing, and behavioral similarity.
- [ ] **Campaign-level Engage reporting** — aggregate MITRE Engage activity/approach/goal mappings across sessions into campaign-level summaries. "Our DMZ deception campaign across 3 SSH and 2 HTTP decoys engaged 47 unique attackers, captured 12 novel credential sets, and mapped to 8 Engage activities." (#29)

### MITRE Caldera Integration — Detection Validation

- [ ] **Caldera operation correlation** — ingest Caldera operation results and correlate with CTI pipeline detections. "Caldera executed T1003.008 against decoy-db-03 — did the pipeline detect it?" Identifies blind spots in the enrichment engine.
- [ ] **Detection coverage report** — for each technique in a Caldera adversary profile, report whether the CTI pipeline detected it, at what severity, and with what latency. Produces a gap analysis matrix.
- [ ] **Caldera plugin or API adapter** — lightweight integration that pushes Caldera operation metadata to a NATS subject for correlation by the CTI pipeline.

### Dashboard Enhancements — Visualization

- [ ] **Attack graph visualization** — D3.js/Vis.js node-link diagram showing attacker movement across decoys, techniques used at each hop, and temporal progression.
- [ ] **Geographic attack map** — world map with attack origin heatmap overlay. Currently geo data is returned by API but not visualized on a map.
- [ ] **Session replay annotations** — overlay MITRE technique markers, tool signature badges, and kill chain phase transitions on the terminal replay timeline.
- [ ] **Trend analysis** — 7/14/30-day views for technique frequency, tool prevalence, attacker IP churn, and engagement metrics.
- [ ] **Technique co-occurrence matrix** — which techniques co-occur in the same session. Reveals attacker playbooks.
- [ ] **MITRE ATT&CK coverage matrix** — visualize which techniques the current decoy fleet can detect vs. total ATT&CK surface.
- [ ] **Comparative analytics** — "which decoys are most engaging?" view comparing session duration, command count, and intelligence yield across configurations.

### Dashboard Enhancements — Export & Reporting

- [ ] **CSV export** — download session lists, events, IOCs, and technique frequencies as CSV.
- [ ] **JSON export** — full session data export for external analysis tools.
- [ ] **PDF intelligence reports** — generate formatted briefing documents with executive summary, technique breakdown, IOC table, and session highlights.
- [ ] **Session replay export** — download terminal sessions as .cast (asciinema format) for sharing and archival.
- [ ] **Scheduled reports** — automated daily/weekly/monthly intelligence summaries delivered via email or webhook.

### CLI Completions

- [ ] **Implement CLI DB client methods** — ExportIntel, GenerateReport, analytics queries. Currently ~70% stubbed.
- [ ] **intel export command** — complete the `cicdecoy intel export --format stix|csv|json` implementation.
- [ ] **intel report command** — complete the `cicdecoy intel report --format md|html|pdf` implementation.
- [ ] **intel mitre heatmap format** — complete the `--format heatmap` terminal visualization.

### Community & Adoption

- [ ] **Community outreach** — share the Deception as Code concept and working demo. Twitter/X thread, MITRE Engage Slack, DEF CON/BSides submission, blog series. (#20)
- [ ] **Engage MITRE network** — with real VPS telemetry, a published threat intelligence report, and a working CALDERA plugin, reach out to MITRE contacts. Time for ATT&CKcon planning cycles. (#31)
- [ ] **CALDERA plugin prototype** — CALDERA ability to deploy CI/CDecoy decoys, detect attacker techniques, and produce gap analysis reports. Key credibility play for MITRE engagement. (#26)
- [ ] **First published threat intelligence report** — produce a report from real VPS attacker data showing campaign tracking, ATT&CK mapping, and intelligence findings.

---

## v0.5.0 — Enterprise Operations

**Goal:** Production-harden the platform for enterprise environments with fleet management, multi-cloud deployment, and operational tooling.

**Target:** Q2-Q3 2027

### Fleet & Lifecycle Management

- [ ] **Auto-credential rotation** — scheduled rotation of decoy identities (hostnames, credentials, SSH keys, banners) to prevent attacker targeting. Configurable via CRD annotations. CLI `rotate` command currently stubbed.
- [ ] **Implement CLI K8s client stubs** — RotateDecoy, RotateAllDecoys, ScaleFleet, FleetDetail, ListFleets, ListProfiles, GetProfile, RunFidelityTests, WaitForDecoys. Currently ~50% stubbed.
- [ ] **Fleet scaling** — `cicdecoy fleet scale <name> --replicas 20` with intelligent distribution across nodes/zones.
- [ ] **Health monitoring & auto-recovery** — detect degraded decoys (crash loops, resource exhaustion) and automatically restart or replace them.
- [ ] **Canary deployment** — deploy new decoy configurations to a subset of the fleet before rolling out globally.
- [ ] **Pod Disruption Budgets** — ensure minimum decoy availability during cluster maintenance.
- [ ] **HPA for inference/dashboard** — autoscaling based on request volume or event throughput.

### Operator Improvements

- [ ] **Validating webhook** — reject invalid Decoy specs at admission time (e.g., Tier 3 without Dolos-generated content, invalid port ranges).
- [ ] **Mutating webhook** — inject defaults (resource limits, security context, labels) into Decoy specs.
- [ ] **Kubernetes events** — emit events on reconciliation success/failure for audit trail and debugging.
- [ ] **NetworkPolicy creation** — CRD supports `spec.network.allowEgressCIDRs` but operator doesn't create matching NetworkPolicies. Implement this.
- [ ] **Session migration** — when decoy spec changes, gracefully drain active sessions before rolling out new pods.
- [ ] **DecoyFleet reconciliation** — operator should reconcile DecoyFleet CRDs into N Decoy instances with distribution rules.
- [ ] **DecoyTemplate reconciliation** — operator should reconcile DecoyTemplate CRDs, allowing parameterized decoy creation.
- [ ] **DecoyProfile CRD** — define and reconcile DecoyProfile as a first-class CRD (currently referenced but not defined).
- [ ] **Status conditions** — richer status reporting with conditions for each sub-resource (deployment ready, service created, credentials provisioned).
- [ ] **HoneyToken CRD reconciliation** — operator support for the HoneyToken CRD (currently a reserved stub).

### Decoy Management Dashboard

- [ ] **Deploy decoys from dashboard** — full decoy lifecycle management without CLI or kubectl. The dashboard becomes the primary control plane for non-GitOps workflows:
  - Deployment wizard — guided form: select decoy type (SSH/HTTP/MySQL/K8s API) -> configure identity (hostname, OS, banner) -> set authentication (credentials, mode) -> place honeytokens (pick from templates or custom) -> select namespace -> deploy. Live validation against CRD schema.
  - Fleet table with actions — start, stop, restart, scale, rotate credentials, destroy. Bulk operations on selected decoys.
  - Real-time deployment status — watch pod rollout progress, see readiness probes pass, live log streaming from new decoys.
  - Honeytoken management — place, rotate, and monitor honeytokens across decoys from a unified view. Drag-and-drop token placement onto a decoy fleet map.
  - One-click templates — pre-built decoy configurations ("DMZ SSH honeypot", "Internal web app", "Cloud credential trap") that deploy with a single click.
  - YAML escape hatch — switch to raw YAML editor for advanced configuration. Schema validation and diff preview before apply.
- [ ] **Fleet overview** — visual map of deployed decoys with status, last activity, and intelligence yield.
- [ ] **Configuration editor** — browser-based YAML editor with schema validation and autocompletion for decoy manifests.
- [ ] **Profile builder** — interactive UI to assemble OS personality profiles (hostname, packages, users, filesystem).
- [ ] **Alert management** — search/filter past alerts, acknowledge, annotate, mark as false positive.
- [ ] **Custom alerting rules** — define thresholds in the UI (e.g., "alert if >10 commands in <60s from same IP").

### Multi-Cloud & Infrastructure

- [ ] **Terraform modules** — deploy CI/CDecoy to AWS EKS, GCP GKE, and Azure AKS with a single `terraform apply`. Include VPC, IAM, and storage configuration.
- [ ] **Ansible playbooks** — bare-metal and VM deployment for non-Kubernetes environments.
- [ ] **Cloud VPC integration** — automated VPC peering and route injection to place decoys on production subnets without manual network configuration.
- [ ] **Cloud firewall coordination** — automated IP blocking via AWS Security Groups, Azure NSGs, or GCP firewall rules on critical alerts.
- [ ] **Air-gapped deployment guide** — offline image bundles, private registry mirroring, and disconnected installation documentation.

### Operational Tooling

- [x] **Backup & restore** — automated TimescaleDB backups via Helm CronJob with pg_dump, gzip compression, retention-based pruning, and configurable PVC storage.
- [ ] **Database migrations** — schema migration framework for upgrades (currently manual SQL).
- [ ] **Log retention policies** — configurable archival to S3/GCS/Azure Blob with lifecycle rules. NATS streams currently hardcoded to 72h.
- [ ] **Grafana dashboard templates** — pre-built dashboards for decoy health, event rates, alert volumes, pipeline latency, and SIEM forwarder throughput. Prometheus metrics are scraped but no dashboards exist.
- [ ] **Cost estimation** — resource calculator for planning fleet deployments (CPU, memory, storage, inference GPU per decoy count and tier).
- [ ] **Distributed tracing** — OpenTelemetry integration for request correlation across services (decoy -> NATS -> pipeline -> dashboard).

### Multi-Tenancy & Access Control

- [x] **Dashboard API-key authentication** — all API endpoints gated with `X-API-Key` header or `?api_key=` query param. Auto-generated keys on first deploy.
- [ ] **Multi-user RBAC** — replace single shared API key with per-user authentication, role-based views (admin, analyst, read-only).
- [ ] **OIDC/SAML integration** — SSO via Okta, Azure AD, or other identity providers.
- [ ] **Audit logging** — who accessed what data, when. Required for compliance.
- [ ] **API key rotation** — scheduled key rotation with grace period for active sessions.
- [ ] **Namespace isolation** — separate decoy fleets, dashboards, and RBAC per team/tenant.

### CLI Enhancements

- [ ] **TUI mode** — interactive terminal UI (bubbletea/lipgloss) with:
  - Fleet overview panel — live decoy status, health indicators, interaction counts, sortable/filterable table.
  - Session watcher — real-time streaming of active sessions with command preview. Select a session to drill into full terminal replay.
  - Decoy deployment wizard — step-through flow for creating Decoy CRs: select type -> configure identity -> set credentials -> choose honeytokens -> deploy. YAML preview before apply.
  - Honeytoken dashboard — trigger feed, placement map, credential correlation alerts.
  - Event firehose — scrolling live feed of all NATS events with severity coloring and ATT&CK technique badges.
  - Keyboard-driven — vim-style navigation, `/` search, `q` quit, `?` help, tab switching between panels.
- [ ] **Shell completion** — Bash, Zsh, Fish, and PowerShell autocompletion generation (Cobra built-in, just needs wiring).
- [ ] **Profile management** — `cicdecoy profile create/edit/list/show` for managing OS personality profiles.
- [ ] **Fidelity testing** — `cicdecoy validate --fidelity` to probe deployed decoys and score their realism. Currently prints "not yet implemented."
- [ ] **Caldera-driven fidelity testing** — run Caldera adversary profiles against deployed decoys to automatically score realism. For each ability executed, measure whether the decoy responded convincingly or revealed itself as a honeypot. Feed results into a per-decoy fidelity score.
- [ ] **Progress bars** — visual progress indicators for long-running operations (deploy, rotate, export).
- [ ] **Proper K8s client** — replace subprocess kubectl wrapper with native Kubernetes Go client library for reliability and performance.

---

## v1.0.0 — Production GA

**Goal:** Stable, documented, and battle-tested release suitable for production security operations.

**Target:** Q4 2027 - Q1 2028

### Stability & Compatibility

- [ ] **CRD versioning** — migrate from v1alpha1 to v1 with conversion webhooks for backwards compatibility.
- [ ] **Helm upgrade path** — tested upgrade from every minor version with pre-upgrade backup hooks and CRD migration.
- [ ] **API stability guarantee** — versioned REST API with deprecation policy for dashboard endpoints.
- [ ] **Performance benchmarks** — documented throughput (events/sec), latency (enrichment pipeline p50/p99), and resource consumption per decoy type and tier.
- [ ] **Materialized views** — pre-aggregated stats for faster dashboard loads on large datasets.
- [ ] **Query cursor pagination** — replace offset-based pagination with cursor-based for consistent performance at scale.

### Integration Ecosystem

- [ ] **SOAR connectors** — Splunk SOAR, Palo Alto XSOAR, and Tines playbook templates for automated investigation and response.
- [ ] **NDR integration** — bidirectional integration with Zeek and Suricata for network-level correlation.
- [ ] **Identity provider integration** — Okta/Azure AD for honeytoken credential generation that mimics real org credential patterns.
- [ ] **Automated response** — on critical alerts: block attacker IP via cloud firewalls, create JIRA/ServiceNow ticket, isolate host via EDR API.
- [ ] **Adapter completions** — production-ready Cowrie, Dionaea, and T-Pot adapters with full test coverage and checkpoint management.
- [ ] **T-Pot adapter HTTP layer** — complete the Elasticsearch polling implementation (currently ~10%).
- [ ] **Adapter checkpointing** — resume-from-position on restart so adapters don't reprocess or lose events.

### SSH Decoy — Advanced Fidelity

- [ ] **Interactive editor simulation** — `vi`/`vim`/`nano` should present a basic editor interface (even if non-functional). Currently returns empty string.
- [ ] **Python/Node REPL** — `python3` and `node` should show an interactive prompt. Log entered expressions.
- [ ] **Docker/kubectl stubs** — `docker ps`, `docker images`, `kubectl get pods` should return profile-driven realistic output instead of generic stubs.
- [ ] **Package manager simulation** — `apt install <pkg>` should simulate downloading and installing. `pip install` should show progress.
- [ ] **Process accounting** — `ps aux` CPU/memory percentages should vary realistically over time, not always show 0.0%.
- [ ] **Network interface realism** — MAC addresses, TX/RX byte counters should be plausible and session-consistent.
- [ ] **Multiple concurrent channels** — support parallel SSH channels (interactive shell + SFTP + port forward) in one connection.
- [ ] **Tab completion for created files** — files created during session should appear in tab completion. Currently hardcoded at boot.

### Research & Training

- [ ] **CTF mode** — pre-built challenge scenarios with scoring, time limits, and leaderboards.
- [ ] **Red team training scenarios** — guided exercises for security teams to practice detection and response using CI/CDecoy.
- [ ] **Caldera + CI/CDecoy purple team lab** — turnkey purple team environment where Caldera runs adversary emulation campaigns against a CI/CDecoy decoy fleet, and analysts train on detecting and responding to the activity through the dashboard. Pre-built adversary profiles tuned for deception environments. Includes scoring: how many techniques did the analyst identify via the dashboard vs. how many Caldera actually executed?
- [ ] **Academic dataset export** — anonymized session data export in standard formats for security research.
- [ ] **A/B testing framework** — deploy two decoy configurations and compare engagement metrics, intelligence yield, and attacker behavior.
- [ ] **Fidelity scoring system** — automated scoring of how convincing a decoy is, based on response accuracy, timing realism, and protocol completeness.

### Additional Protocol Decoys

- [ ] **RDP** — Remote Desktop Protocol emulation for Windows-focused environments.
- [ ] **FTP/SFTP** — file listing, upload capture, credential harvesting.
- [ ] **DNS** — zone transfer responses, DNS tunnel detection, query logging.
- [ ] **SMTP** — mail relay emulation for spam/phishing campaign detection.
- [ ] **Redis / Memcached** — in-memory datastore emulation for cloud environments.
- [ ] **Telnet** — legacy protocol emulation for OT/IoT environments.

### Dashboard — Polish

- [ ] **Light mode / theme toggle** — currently dark-only. Some SOC environments prefer light mode.
- [ ] **Accessibility audit** — WCAG AA compliance (focus indicators, ARIA labels, color contrast, screen reader support).
- [ ] **Mobile optimization** — responsive design exists but isn't optimized for tablet/phone use.
- [ ] **Custom query builder** — SQL/DSL interface for ad-hoc data exploration.
- [ ] **Bulk actions** — export multiple sessions, annotate/tag sessions, mark as false positive.
- [ ] **Campaign tracking** — group related sessions by shared IOCs, timing, or behavioral similarity.
- [ ] **Response compression** — gzip API responses for bandwidth-constrained environments.

---

## Beyond v1.0

Ideas under consideration for future development. These are not committed and may change based on community feedback and adoption patterns.

### Platform Evolution

- **Managed CI/CDecoy (SaaS)** — hosted deployment option for teams that don't want to run Kubernetes.
- **Decoy marketplace** — community-contributed profiles, response databases, and protocol plugins with vetting and quality scoring.
- **Deception mesh** — coordinated multi-decoy scenarios where decoys reference each other (e.g., SSH decoy's `/etc/hosts` points to MySQL decoy, `.env` files contain credentials for another decoy's login portal). Dolos handles the cross-referencing automatically.
- **Multi-cluster federation** — cross-cluster decoy placement with centralized dashboard and intelligence aggregation.

### Intelligence

- **ML-driven adaptive placement** — automatically recommend decoy placement based on network topology, traffic patterns, and threat intelligence.
- **YARA integration** — scan uploaded files and command payloads against YARA rules for malware classification.
- **Behavioral graph database** — Neo4j/Dgraph for relationship-rich queries across sessions, actors, techniques, and infrastructure.

### Emerging Threats

- **Supply chain deception** — fake package registries (npm, PyPI), container registries, and artifact repositories as honeypots.
- **AI-powered reconnaissance detection** — detect when attackers use LLMs or automated tools to probe decoy filesystems for inconsistencies or honeypot indicators.
- **IoT/OT protocol decoys** — Modbus, BACnet, DNP3, MQTT for industrial control system environments.

### Operational

- **Active defense integration** — coordinate with endpoint agents to deploy decoys dynamically in response to detected threats.
- **Deception effectiveness metrics** — quantify the security value of deception deployments (MTTD improvement, false positive reduction, technique coverage delta).
- **Cost/benefit analysis** — automated ROI calculation based on intelligence generated vs. infrastructure cost.

---

## Current Implementation Status

For transparency, here is the completion status of each major component as of v0.2.0-dev:

| Component | Completion | Key Strengths | Key Gaps |
|-----------|-----------|---------------|----------|
| **SSH Decoy** | 92% | 60+ commands, pipes, awk, COW filesystem, SCP/SFTP, port forwarding, for/while/if, globs, honeytokens, 3 tiers | No symlinks, no script execution, no here-documents |
| **HTTP Decoy** | 80% | 10 login portals, attack detection, tool fingerprinting, honeytoken file serving | No Dolos-generated content (Tier 3), no WebSocket, no OAuth flows |
| **CTI Pipeline** | 92% | 70+ MITRE techniques, 48 tools, kill chain detection, Engage, honeytoken enrichment, credential correlation | No threat feeds, no YARA |
| **Session Analyzer** | 95% | Behavioral scoring, classification, dangerous progressions | No ML/anomaly detection |
| **Dashboard Backend** | 85% | 13 API endpoints, SSE, session replay, geo data, API-key auth | No export, no custom queries, no decoy management |
| **Dashboard Frontend** | 80% | 4 pages, 11 components, real-time SSE, terminal replay | No attack graph, no geo map, no honeytoken page yet |
| **Operator** | 75% | Reconciles Decoy -> Deployment+Service+Secret, honeytoken manifest | No webhooks, no events, no NetworkPolicy, no Fleet/Template |
| **CLI** | 65% | deploy, destroy, sessions, intel, validate, logs | rotate/fleet/profile stubbed, K8s client ~40% implemented |
| **SIEM Forwarder** | 80% | JSON, CEF, syslog, Splunk HEC, Elasticsearch, webhook | LEEF/ECS incomplete, no dead-letter, no circuit breaker |
| **Adapters** | 40% | Cowrie draft, Dionaea draft, T-Pot stub, common schema | No checkpoint, no backfill, T-Pot ~10% complete |
| **Helm Chart** | 80% | Full deployment, CRDs, auto-generated secrets, GHCR defaults | No webhooks, no HPA, Network Policy disabled |
| **Infrastructure** | 95% | docker-compose zero-config, 5 CI workflows, E2E k3d, CodeQL, Trivy, golangci-lint, Prettier, Chainguard images | No Terraform/Ansible, no SBOM/cosign |
| **Honeytoken System** | 70% | Shared registry, SSH+HTTP detection, operator integration, CTI enrichment, credential correlation, 64 tests | No dashboard page, no Type 2, no Dolos |
| **Testing** | 85% | ~1,100 tests (885 Python, 131 Go, 48 Frontend, 64 honeytoken), 60% coverage threshold | No contract tests, no fuzz testing |

---

## Contributing to the Roadmap

We welcome community input on roadmap priorities. If you have a use case that isn't covered, or you'd like to contribute to a planned feature:

1. **Discuss first** — open a [GitHub Discussion](https://github.com/csquare-d/CICDecoy/discussions) describing your use case and proposed approach.
2. **Check the issues** — each roadmap item will have a corresponding GitHub issue tagged with `roadmap` for tracking.
3. **Start small** — even partial implementations, prototypes, and design docs are valuable contributions.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for development setup and contribution guidelines.
