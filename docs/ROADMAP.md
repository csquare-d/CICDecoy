# CI/CDecoy Roadmap

> Last updated: 2026-04-19 | Current version: 0.1.0

This document describes the planned development trajectory for CI/CDecoy. It is organized into versioned milestones with clear goals, scope, and priorities. Items marked with a checkbox indicate completion status.

For the current state of the project, see [CHANGELOG.md](../CHANGELOG.md).

---

## v0.2.0 — Operational Readiness

**Goal:** Make CI/CDecoy usable for real SOC teams by wiring alerts to where operators actually look, integrating threat intelligence feeds, and activating the honeytoken subsystem.

**Target:** Q2 2026

### Alerting & Notifications

The NATS alert stream (`cicdecoy.alert.>`) produces high-quality alerts today (kill chain, C2 detection, dangerous progressions, high behavioral score). They just don't go anywhere operators will see them.

- [x] **Slack integration** — Block Kit formatted alerts to configurable Slack channels via incoming webhooks. Includes severity, source IP, decoy name, MITRE technique, and command.
- [x] **Microsoft Teams integration** — MessageCard formatting for Teams channels.
- [ ] **Email alerts** — SMTP-based delivery for critical/high severity events. Configurable recipients and throttling.
- [x] **PagerDuty integration** — Events API v2 triggers for critical alerts with severity mapping.
- [ ] **Generic webhook** — POST alert JSON to any URL, enabling custom integrations (SOAR, ticketing, Lambda/Cloud Functions).
- [ ] **Alert routing rules** — configure which alert types go to which channels (e.g., C2 → PagerDuty, credential stuffing → Slack).

### Threat Intelligence Feeds

IP reputation and known-bad indicators transform honeypot data from "someone connected" to "a known Cobalt Strike operator connected."

- [ ] **GreyNoise integration** — enrich source IPs with GreyNoise RIOT/NOISE classification. Distinguish scanners from targeted attacks.
- [ ] **abuse.ch integration** — check IPs and hashes against abuse.ch threat feeds (URLhaus, ThreatFox, Feodo Tracker).
- [ ] **AlienVault OTX integration** — pull IOC context (related campaigns, threat actors, malware families).
- [ ] **Shodan integration** — reverse-lookup attacker IPs for exposed services, OS fingerprints, and hosting provider.
- [ ] **Feed caching layer** — local cache with TTL to avoid rate limits and reduce latency. Configurable per-feed.
- [ ] **Cross-session IOC correlation** — detect the same tool, credential, or IP across multiple sessions. Surface repeat visitors and campaign patterns.

### Honeytokens

The `HoneyToken` CRD is fully defined. Runtime placement and trigger detection will bring it to life.

- [ ] **File-based honeytokens** — seed canary files (fake AWS credentials, database dumps, SSH keys, `.env` files) into decoy filesystems during pod startup.
- [ ] **Environment variable honeytokens** — inject canary credentials as env vars visible to attackers who run `env` or `printenv`.
- [ ] **Trigger detection** — monitor for honeytoken access (file read, env var expansion, credential use) and emit high-confidence alerts to `cicdecoy.honeytoken.>`.
- [ ] **Dashboard honeytoken view** — display honeytoken status, trigger history, and placement map.
- [ ] **CLI honeytoken commands** — `cicdecoy honeytoken place`, `cicdecoy honeytoken list`, `cicdecoy honeytoken triggers`.

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

- [ ] **Add /dev/null, /dev/zero, /dev/urandom, /dev/random** — attackers commonly reference these; currently return "No such file."
- [ ] **Add /proc/self directory** — with cmdline, environ, maps stubs. Every containerized attacker expects this.
- [ ] **Add missing SSH environment variables** — SSH_CLIENT, SSH_CONNECTION, SSH_TTY, HISTFILE, HISTSIZE, EDITOR, COLUMNS, LINES.
- [ ] **Improve sudo realism** — support `sudo -i` (interactive root shell), `sudo -u user` (user switching), and respect a simulated sudoers timeout.
- [ ] **Add /etc/sudoers stub** — attackers frequently `cat /etc/sudoers` to check privilege escalation.
- [ ] **Brace expansion** — `echo {1..5}` should expand to `1 2 3 4 5`, not output the literal string.
- [x] **Glob pattern matching** — `ls *.txt` matches files in the virtual filesystem via fnmatch.
- [ ] **Add `time` command** — wraps command execution with real/user/sys timing output.
- [ ] **Add `seq` command** — sequence generation, commonly used in scripts.
- [ ] **Add `diff` command** — file comparison stub.

### HTTP Decoy — Small Improvements

- [ ] **Add security headers** — X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Content-Security-Policy on all responses.
- [ ] **Add X-Powered-By spoofing** — configurable per portal (e.g., PHP/7.4.33 for WordPress, Express for Node apps).
- [x] **Add 500 Internal Server Error page** — nginx-style HTML 500 page with global exception handler.
- [ ] **CORS preflight responses** — return proper Access-Control-Allow-* headers on OPTIONS requests.

### Testing & Quality

- [ ] **Go test coverage** — unit tests for CLI commands (~3,260 LOC), SIEM forwarder consumers (~1,600 LOC), and adapter framework (~1,347 LOC). Currently zero test coverage.
- [ ] **React component tests** — Jest/React Testing Library for dashboard components (21 components untested).
- [ ] **Contract tests** — verify NATS message schemas between producers (decoys) and consumers (pipeline, dashboard, forwarder).

---

## v0.3.0 — Protocol Expansion

**Goal:** Expand beyond SSH and HTTP to cover the protocols attackers encounter most in enterprise and cloud environments.

**Target:** Q3 2026

### HTTP/HTTPS Tier 3 (Dynamic Content Generation)

HTTP Tier 3 uses the LLM as a **content generator** feeding into the existing Tier 2 route handlers. The protocol layer (status codes, headers, redirects, auth flows, session mechanics) remains scripted — HTTP is too structurally rigid for full LLM improvisation. The LLM generates realistic *content* that makes static pages and API responses look like a live application.

- [ ] **Dynamic page content** — LLM generates realistic blog posts, user directories, file listings, search results, and error pages based on the decoy's profile and the request context.
- [ ] **Fake data generation** — produce plausible API responses with realistic PII, database records, config files, and `.env` contents when attackers probe data endpoints.
- [ ] **Stateful web sessions** — maintain conversation context across multiple HTTP requests within a session to keep generated content consistent.
- [ ] **Form response generation** — process POST submissions and generate plausible response content (success pages, error messages, redirect targets).
- [ ] **API endpoint enrichment** — enrich REST API responses (CRUD operations, pagination, search) with LLM-generated realistic JSON data instead of static stubs.
- [ ] **Response filtering** — extend the inference response filter to catch infrastructure leakage in HTTP responses.
- [ ] **Prompt injection detection** — detect and log LLM-targeted attacks in HTTP request bodies.

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

### SSH Decoy — Major Fidelity Features

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
- [ ] **Behavioral heuristics** — detect command chaining patterns (recon → privesc → exfil sequences) beyond individual technique classification.
- [ ] **Cloud service discovery** — detect `aws s3 ls`, `gcloud compute instances list`, `az vm list` and similar cloud enumeration.

---

## v0.4.0 — Intelligence Maturity

**Goal:** Transform raw honeypot data into actionable, shareable threat intelligence with advanced analytics and visualization.

**Target:** Q4 2026

### STIX / TAXII

- [ ] **STIX 2.1 full bundle export** — generate complete STIX bundles with Indicators, Observed Data, Attack Patterns, Threat Actors, and Relationships. Currently only basic indicator conversion exists.
- [ ] **TAXII 2.1 server** — serve collections of STIX objects for automated intel sharing with ISACs, partners, and other platforms.
- [ ] **Automated bundle generation** — produce STIX bundles on session close, triggered by alert thresholds, or on a schedule.

### Attacker Fingerprinting & Attribution

- [ ] **Tool fingerprint library** — expanded signature database beyond the current 38 tools. Add Mythic, PoshC2, container-specific tools.
- [ ] **Cross-session actor clustering** — identify repeat attackers across sessions using behavioral patterns, tool overlap, credential reuse, and timing.
- [ ] **Infrastructure reuse detection** — flag shared C2 infrastructure, staging servers, and proxy chains across campaigns.
- [ ] **TTP profile generation** — produce per-actor profiles summarizing observed techniques, tools, and objectives.
- [ ] **Keystroke timing analysis** — distinguish human operators from automated C2 frameworks based on inter-keystroke intervals.

### Advanced Analytics

- [ ] **Behavioral anomaly detection** — identify sessions that deviate significantly from observed baselines (unsupervised clustering).
- [ ] **Engagement effectiveness scoring** — measure which decoy configurations generate the most intelligence per session. Compare tiers, profiles, and portal types.
- [ ] **Dwell time analysis** — track how long attackers engage before abandoning or escalating. Correlate with decoy fidelity tier.
- [ ] **Campaign timeline reconstruction** — link related sessions into multi-day campaign views based on shared IOCs, timing, and behavioral similarity.

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

---

## v0.5.0 — Enterprise Operations

**Goal:** Production-harden the platform for enterprise environments with fleet management, multi-cloud deployment, and operational tooling.

**Target:** Q1–Q2 2027

### Fleet & Lifecycle Management

- [ ] **Auto-credential rotation** — scheduled rotation of decoy identities (hostnames, credentials, SSH keys, banners) to prevent attacker targeting. Configurable via CRD annotations. CLI `rotate` command currently stubbed.
- [ ] **Implement CLI K8s client stubs** — RotateDecoy, RotateAllDecoys, ScaleFleet, FleetDetail, ListFleets, ListProfiles, GetProfile, RunFidelityTests, WaitForDecoys. Currently ~50% stubbed.
- [ ] **Fleet scaling** — `cicdecoy fleet scale <name> --replicas 20` with intelligent distribution across nodes/zones.
- [ ] **Health monitoring & auto-recovery** — detect degraded decoys (crash loops, resource exhaustion) and automatically restart or replace them.
- [ ] **Canary deployment** — deploy new decoy configurations to a subset of the fleet before rolling out globally.
- [ ] **Pod Disruption Budgets** — ensure minimum decoy availability during cluster maintenance.
- [ ] **HPA for inference/dashboard** — autoscaling based on request volume or event throughput.

### Operator Improvements

- [ ] **Validating webhook** — reject invalid Decoy specs at admission time (e.g., Tier 3 without inference endpoint, invalid port ranges).
- [ ] **Mutating webhook** — inject defaults (resource limits, security context, labels) into Decoy specs.
- [ ] **Kubernetes events** — emit events on reconciliation success/failure for audit trail and debugging.
- [ ] **NetworkPolicy creation** — CRD supports `spec.network.allowEgressCIDRs` but operator doesn't create matching NetworkPolicies. Implement this.
- [ ] **Session migration** — when decoy spec changes, gracefully drain active sessions before rolling out new pods.
- [ ] **DecoyFleet reconciliation** — operator should reconcile DecoyFleet CRDs into N Decoy instances with distribution rules.
- [ ] **DecoyTemplate reconciliation** — operator should reconcile DecoyTemplate CRDs, allowing parameterized decoy creation.
- [ ] **DecoyProfile CRD** — define and reconcile DecoyProfile as a first-class CRD (currently referenced but not defined).
- [ ] **Status conditions** — richer status reporting with conditions for each sub-resource (deployment ready, service created, credentials provisioned).

### Decoy Management Dashboard

- [ ] **Deploy/destroy/rotate from UI** — full decoy lifecycle management without CLI. Currently the DecoyFleet page is read-only.
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
- [ ] **Distributed tracing** — OpenTelemetry integration for request correlation across services (decoy → NATS → pipeline → dashboard).

### Multi-Tenancy & Access Control

- [ ] **Multi-user RBAC** — replace single shared API key with per-user authentication, role-based views (admin, analyst, read-only).
- [ ] **OIDC/SAML integration** — SSO via Okta, Azure AD, or other identity providers.
- [ ] **Audit logging** — who accessed what data, when. Required for compliance.
- [ ] **API key rotation** — scheduled key rotation with grace period for active sessions.
- [ ] **Namespace isolation** — separate decoy fleets, dashboards, and RBAC per team/tenant.

### CLI Enhancements

- [ ] **TUI mode** — interactive terminal UI (bubbletea/lipgloss) for fleet browsing, session watching, and decoy configuration.
- [ ] **Shell completion** — Bash, Zsh, Fish, and PowerShell autocompletion generation (Cobra built-in, just needs wiring).
- [ ] **Profile management** — `cicdecoy profile create/edit/list/show` for managing OS personality profiles.
- [ ] **Fidelity testing** — `cicdecoy validate --fidelity` to probe deployed decoys and score their realism. Currently prints "not yet implemented."
- [ ] **Caldera-driven fidelity testing** — run Caldera adversary profiles against deployed decoys to automatically score realism. For each ability executed, measure whether the decoy responded convincingly or revealed itself as a honeypot. Feed results into a per-decoy fidelity score.
- [ ] **Progress bars** — visual progress indicators for long-running operations (deploy, rotate, export).
- [ ] **Proper K8s client** — replace subprocess kubectl wrapper with native Kubernetes Go client library for reliability and performance.

---

## v1.0.0 — Production GA

**Goal:** Stable, documented, and battle-tested release suitable for production security operations.

**Target:** Q3–Q4 2027

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
- **Deception mesh** — coordinated multi-decoy scenarios where decoys reference each other (e.g., SSH decoy's `/etc/hosts` points to MySQL decoy, `.env` files contain credentials for another decoy's login portal).
- **Multi-cluster federation** — cross-cluster decoy placement with centralized dashboard and intelligence aggregation.

### Intelligence

- **ML-driven adaptive placement** — automatically recommend decoy placement based on network topology, traffic patterns, and threat intelligence.
- **YARA integration** — scan uploaded files and command payloads against YARA rules for malware classification.
- **Behavioral graph database** — Neo4j/Dgraph for relationship-rich queries across sessions, actors, techniques, and infrastructure.

### Emerging Threats

- **Supply chain deception** — fake package registries (npm, PyPI), container registries, and artifact repositories as honeypots.
- **AI/LLM attack detection** — detect prompt injection, jailbreak attempts, and AI-powered reconnaissance against Tier 3 decoys.
- **IoT/OT protocol decoys** — Modbus, BACnet, DNP3, MQTT for industrial control system environments.

### Operational

- **Active defense integration** — coordinate with endpoint agents to deploy decoys dynamically in response to detected threats.
- **Deception effectiveness metrics** — quantify the security value of deception deployments (MTTD improvement, false positive reduction, technique coverage delta).
- **Cost/benefit analysis** — automated ROI calculation based on intelligence generated vs. infrastructure cost.

---

## Current Implementation Status

For transparency, here is the completion status of each major component as of v0.1.0:

| Component | Completion | Key Strengths | Key Gaps |
|-----------|-----------|---------------|----------|
| **SSH Decoy** | 90% | 60+ commands, pipes, awk, COW filesystem, SCP/SFTP, port forwarding, for/while/if, globs, 3 tiers | No symlinks, no script execution, no here-documents |
| **HTTP Decoy** | 75% | 10 login portals, attack detection, tool fingerprinting | No Tier 3 content generation, no WebSocket, no OAuth flows, no file upload |
| **CTI Pipeline** | 90% | 70+ MITRE techniques, 38 tools, kill chain detection, Engage | No threat feeds, no cross-session correlation, no YARA |
| **Session Analyzer** | 95% | Behavioral scoring, classification, dangerous progressions | No ML/anomaly detection |
| **Dashboard Backend** | 85% | 13 API endpoints, SSE, session replay, geo data | No export, no custom queries, no decoy management |
| **Dashboard Frontend** | 80% | 4 pages, 11 components, real-time SSE, terminal replay | No attack graph, no geo map, no export, read-only fleet |
| **Operator** | 70% | Reconciles Decoy → Deployment+Service+Secret | No webhooks, no events, no NetworkPolicy, no Fleet/Template |
| **CLI** | 65% | deploy, destroy, sessions, intel, validate, logs | rotate/fleet/profile stubbed, K8s client ~40% implemented |
| **SIEM Forwarder** | 80% | JSON, CEF, syslog, Splunk HEC, Elasticsearch, webhook | LEEF/ECS incomplete, no dead-letter, no circuit breaker |
| **Adapters** | 40% | Cowrie draft, Dionaea draft, T-Pot stub, common schema | No checkpoint, no backfill, T-Pot ~10% complete |
| **Helm Chart** | 75% | Full deployment, CRDs, auto-generated secrets | No webhooks, no HPA/PDB, no Network Policy templates |
| **Infrastructure** | 90% | docker-compose zero-config, 5 CI workflows, Makefile | No Terraform/Ansible, no air-gap guide |

---

## Contributing to the Roadmap

We welcome community input on roadmap priorities. If you have a use case that isn't covered, or you'd like to contribute to a planned feature:

1. **Discuss first** — open a [GitHub Discussion](https://github.com/csquare-d/CICDecoy/discussions) describing your use case and proposed approach.
2. **Check the issues** — each roadmap item will have a corresponding GitHub issue tagged with `roadmap` for tracking.
3. **Start small** — even partial implementations, prototypes, and design docs are valuable contributions.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for development setup and contribution guidelines.
