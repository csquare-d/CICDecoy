# Threat Hunt Playbooks

Five tactical playbooks for deploying CI/CDecoy decoys to detect specific adversary behaviors. Each playbook includes deployment manifests, detection criteria, MITRE ATT&CK mappings, and tuning guidance.

These playbooks assume CI/CDecoy is installed per the [Getting Started](../getting-started.md) guide and the CTI pipeline is forwarding events to your SIEM.

---

## Playbook 1: Detect Credential Stuffing

### Objective

Detect automated credential attacks — brute force, password spraying, and credential stuffing — by deploying SSH beacons on common authentication ports across multiple subnets. Any authentication attempt against a decoy is suspicious; high-volume attempts from a single source confirm automated tooling.

### MITRE ATT&CK

| Technique | ID | Tactic |
|---|---|---|
| Brute Force | T1110 | Credential Access |
| Brute Force: Password Spraying | T1110.003 | Credential Access |
| Brute Force: Credential Stuffing | T1110.004 | Credential Access |
| Valid Accounts | T1078 | Defense Evasion, Persistence |

### Network Placement

```
              Corporate Network
    ┌──────────────────────────────────────┐
    │                                      │
    │   ┌─────────┐    ┌─────────┐         │
    │   │ Subnet A│    │ Subnet B│         │
    │   │ 10.1.0/24    │ 10.2.0/24         │
    │   │         │    │         │         │
    │   │ [DECOY] │    │ [DECOY] │         │
    │   │ :22     │    │ :22     │         │
    │   │ [DECOY] │    │ [DECOY] │         │
    │   │ :2222   │    │ :8022   │         │
    │   └─────────┘    └─────────┘         │
    │                                      │
    │   ┌─────────┐    ┌──────────────┐    │
    │   │ Subnet C│    │ DMZ          │    │
    │   │ 10.3.0/24    │ 172.16.0/24  │    │
    │   │         │    │              │    │
    │   │ [DECOY] │    │ [HTTP DECOY] │    │
    │   │ :22     │    │ :443 (SSO)   │    │
    │   └─────────┘    └──────────────┘    │
    └──────────────────────────────────────┘
```

Place Tier 1 SSH beacons on ports 22, 2222, and 8022 across subnets that contain real SSH servers. The decoys blend in with legitimate infrastructure. Add one Tier 2 HTTP decoy presenting a corporate SSO login page to catch credential reuse from web-based attacks.

### Deployment Manifests

**Tier 1 SSH beacons (deploy one per subnet, adjust port and name):**

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: Decoy
metadata:
  name: ssh-credstuff-subnet-a-01
  namespace: decoys-production
  labels:
    cicdecoy.io/tier: "1"
    cicdecoy.io/zone: "internal"
    cicdecoy.io/campaign: "credential-stuffing-hunt"
spec:
  service:
    type: ssh
    port: 22
  fidelity:
    tier: 1
  identity:
    hostname: "mail-relay-02"
    os:
      family: linux
      distro: "Ubuntu 22.04.3 LTS"
    fingerprint:
      sshBanner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
  authentication:
    mode: closed
    logAllAttempts: true
  telemetry:
    sessionCapture:
      fullTranscript: true
    exporter:
      type: nats
      endpoint: "nats://cicdecoy-nats.cicdecoy-system:4222"
      subject: "cicdecoy.decoy.events.credstuff"
  engage:
    activity: EAC0001
    goal: EG0004
    hypothesis: "Automated tools performing credential attacks will hit decoy SSH services."
  resources:
    requests:
      cpu: "50m"
      memory: "32Mi"
    limits:
      cpu: "100m"
      memory: "64Mi"
```

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: Decoy
metadata:
  name: ssh-credstuff-subnet-a-02
  namespace: decoys-production
  labels:
    cicdecoy.io/tier: "1"
    cicdecoy.io/zone: "internal"
    cicdecoy.io/campaign: "credential-stuffing-hunt"
spec:
  service:
    type: ssh
    port: 2222
  fidelity:
    tier: 1
  identity:
    hostname: "vpn-gateway-01"
    os:
      family: linux
    fingerprint:
      sshBanner: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
  authentication:
    mode: closed
    logAllAttempts: true
  telemetry:
    sessionCapture:
      fullTranscript: true
    exporter:
      type: nats
      endpoint: "nats://cicdecoy-nats.cicdecoy-system:4222"
      subject: "cicdecoy.decoy.events.credstuff"
  engage:
    activity: EAC0001
    goal: EG0004
    hypothesis: "Credential attacks targeting alternate SSH ports indicate tool-based scanning."
  resources:
    requests:
      cpu: "50m"
      memory: "32Mi"
    limits:
      cpu: "100m"
      memory: "64Mi"
```

**Tier 2 HTTP SSO decoy (catches credential reuse on web):**

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: Decoy
metadata:
  name: http-sso-credstuff
  namespace: decoys-production
  labels:
    cicdecoy.io/tier: "2"
    cicdecoy.io/zone: "dmz"
    cicdecoy.io/campaign: "credential-stuffing-hunt"
spec:
  service:
    type: https
    port: 443
  fidelity:
    tier: 2
    scriptedResponses: "corporate-sso"
  identity:
    hostname: "sso-legacy.corp.internal"
    os:
      family: linux
      distro: "Ubuntu 22.04 LTS"
  authentication:
    mode: selective
    allowCredentials:
      - username: svc-backup
        password: "Backup2024!"
      - username: admin
        password: "P@ssw0rd2024"
    captureAll: true
  telemetry:
    sessionCapture:
      fullTranscript: true
    exporter:
      type: nats
      endpoint: "nats://cicdecoy-nats.cicdecoy-system:4222"
      subject: "cicdecoy.decoy.events.credstuff"
  engage:
    activity: EAC0001
    goal: EG0004
    hypothesis: "Attackers reusing credentials from SSH brute force will try the same pairs on web login portals."
```

### Detection Criteria

| Signal | Confidence | Threshold |
|---|---|---|
| Single failed auth attempt against any decoy | Low | 1 event |
| 5+ failed auth attempts from same source IP within 10 minutes | High | Automated tool confirmed |
| Same username:password pair attempted across 2+ decoys | Critical | Credential stuffing confirmed |
| Same source IP hits SSH decoy then HTTP SSO decoy | Critical | Cross-protocol credential reuse |
| Auth attempts using known leaked credential lists | High | Correlate with breach databases |

**SIEM query (Splunk):**

```spl
index=cicdecoy sourcetype="cicdecoy:event" event_type=auth.failure
| stats count dc(decoy_name) as decoys_targeted values(username) as usernames
  by src_ip
| where count > 5 OR decoys_targeted > 1
| sort -count
```

### Response Actions

1. **Immediate (automated):** Block source IP at the network edge for external IPs. For internal IPs, isolate the source host pending investigation.
2. **Triage:** Determine if the source is an internal host (compromised endpoint) or external scanner. Check if the same credentials were attempted against real systems.
3. **Hunt:** Search SIEM for the source IP across all log sources in the past 7 days. Look for successful authentications on real systems using the same credentials.
4. **Remediate:** If leaked credentials match real accounts, force password resets. If an internal host is compromised, initiate IR.

### Tuning Guidance

- **Vulnerability scanners:** Exclude IPs of authorized vulnerability scanners by adding them to a decoy-level allowlist or filtering in the SIEM query. Do not whitelist in the decoy itself — you still want the telemetry; just suppress the alert.
- **Network monitoring tools:** Tools like Nagios or Zabbix doing port checks will trigger Tier 1 beacons. Filter by user-agent or connection pattern (single SYN, no auth attempt).
- **Threshold adjustment:** Start with 5 failed attempts in 10 minutes. Lower to 3 if your environment has minimal background noise. In noisy DMZ segments, raise to 10.
- **Port scan noise:** Tier 1 beacons on port 22 in the DMZ will catch internet-wide scanners (Shodan, Censys). These are low-value. Filter by GeoIP or ASN if you only care about targeted attacks.

---

## Playbook 2: Catch Lateral Movement

### Objective

Detect attackers pivoting through the network after initial compromise by placing SSH decoys at common lateral movement destinations. Because no legitimate user or service ever connects to a decoy, any connection is a confirmed indicator of compromise.

### MITRE ATT&CK

| Technique | ID | Tactic |
|---|---|---|
| Remote Services: SSH | T1021.004 | Lateral Movement |
| Valid Accounts | T1078 | Defense Evasion, Lateral Movement |
| Remote Services | T1021 | Lateral Movement |
| Internal Proxy | T1090.001 | Command and Control |

### Network Placement

```
    Attacker's initial foothold
              │
              ▼
    ┌─────────────────┐
    │ Compromised     │
    │ Workstation     │
    │ 10.1.5.42       │
    └────────┬────────┘
             │  Lateral movement attempts
             │
     ┌───────┼────────────────────────────┐
     │       │                            │
     ▼       ▼                            ▼
┌─────────┐ ┌──────────┐          ┌──────────────┐
│ [DECOY] │ │ [DECOY]  │          │ [DECOY]      │
│ jump-   │ │ dev-db-  │          │ build-       │
│ staging │ │ 03       │          │ server-04    │
│ -01     │ │          │          │              │
│ :22     │ │ :22      │          │ :22          │
│ Tier 2  │ │ Tier 2   │          │ Tier 2       │
└─────────┘ └──────────┘          └──────────────┘
  Jump box     Database             CI runner
  segment      segment              segment
```

Place decoys on subnets adjacent to high-value targets. Name them to match real infrastructure naming conventions. An attacker who compromised a workstation and is scanning for the next hop will find these before (or alongside) real targets.

### Deployment Manifests

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: Decoy
metadata:
  name: ssh-lateral-jumpbox
  namespace: decoys-production
  labels:
    cicdecoy.io/tier: "2"
    cicdecoy.io/zone: "management"
    cicdecoy.io/campaign: "lateral-movement-hunt"
spec:
  service:
    type: ssh
    port: 22
  fidelity:
    tier: 2
    scripted:
      responseSet: "openssh-8.9"
      customResponses:
        - match: "uname -a"
          response: "Linux jump-staging-01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux"
        - match: "cat /etc/hostname"
          response: "jump-staging-01"
        - match: "w"
          response: |
            13:42:01 up 112 days,  4:18,  0 users,  load average: 0.00, 0.01, 0.05
            USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
        - match: "last"
          response: |
            mgarcia  pts/0    10.1.4.22        Mon14    00:23m  0.04s  0.04s -bash
            schen    pts/1    10.1.4.35        Fri09    3days   0.02s  0.02s -bash
            wtmp begins Tue Oct  3 09:15:22 2023
  identity:
    hostname: "jump-staging-01"
    os:
      family: linux
      distro: "Ubuntu 22.04.3 LTS"
    fingerprint:
      sshBanner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
  authentication:
    mode: selective
    allowCredentials:
      - username: svc-deploy
        password: "St@ging_2024"
      - username: mgarcia
        password: "Welcome1!"
    captureAll: true
  telemetry:
    sessionCapture:
      fullTranscript: true
      keystrokeTimings: true
    exporter:
      type: nats
      endpoint: "nats://cicdecoy-nats.cicdecoy-system:4222"
      subject: "cicdecoy.decoy.events.lateral"
  engage:
    activity: EAC0001
    goal: EG0001
    hypothesis: "Attackers who compromise a workstation will attempt SSH to jump boxes and staging infrastructure."
```

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: Decoy
metadata:
  name: ssh-lateral-devdb
  namespace: decoys-production
  labels:
    cicdecoy.io/tier: "2"
    cicdecoy.io/zone: "database"
    cicdecoy.io/campaign: "lateral-movement-hunt"
spec:
  service:
    type: ssh
    port: 22
  fidelity:
    tier: 2
    scripted:
      responseSet: "openssh-8.9"
      customResponses:
        - match: "uname -a"
          response: "Linux dev-db-03 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux"
        - match: "cat /etc/hostname"
          response: "dev-db-03"
        - match: "systemctl status postgresql"
          response: |
            ● postgresql.service - PostgreSQL RDBMS
                 Loaded: loaded (/lib/systemd/system/postgresql.service; enabled)
                 Active: active (exited) since Mon 2024-01-08 03:15:22 UTC; 2 weeks ago
        - match: "psql --version"
          response: "psql (PostgreSQL) 15.4 (Ubuntu 15.4-2.pgdg22.04+1)"
  identity:
    hostname: "dev-db-03"
    os:
      family: linux
      distro: "Ubuntu 22.04.3 LTS"
    fingerprint:
      sshBanner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
  authentication:
    mode: selective
    allowCredentials:
      - username: postgres
        password: "pgAdmin_2024"
      - username: dbadmin
        password: "D3v_db_pass!"
    captureAll: true
  telemetry:
    sessionCapture:
      fullTranscript: true
      keystrokeTimings: true
    exporter:
      type: nats
      endpoint: "nats://cicdecoy-nats.cicdecoy-system:4222"
      subject: "cicdecoy.decoy.events.lateral"
  engage:
    activity: EAC0001
    goal: EG0001
    hypothesis: "Attackers performing lateral movement will target database servers for data access."
```

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: Decoy
metadata:
  name: ssh-lateral-buildserver
  namespace: decoys-production
  labels:
    cicdecoy.io/tier: "2"
    cicdecoy.io/zone: "cicd"
    cicdecoy.io/campaign: "lateral-movement-hunt"
spec:
  service:
    type: ssh
    port: 22
  fidelity:
    tier: 2
    scripted:
      responseSet: "openssh-8.9"
      customResponses:
        - match: "uname -a"
          response: "Linux build-server-04 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux"
        - match: "cat /etc/hostname"
          response: "build-server-04"
        - match: "docker ps"
          response: |
            CONTAINER ID   IMAGE                    STATUS          NAMES
            a3f2b1c9d8e7   jenkins/jenkins:2.426     Up 14 days     jenkins
            b4e3c2d1f0a9   registry:2               Up 14 days     registry
        - match: "cat /etc/environment"
          response: |
            PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            JENKINS_HOME="/var/lib/jenkins"
            DOCKER_HOST="unix:///var/run/docker.sock"
  identity:
    hostname: "build-server-04"
    os:
      family: linux
      distro: "Ubuntu 22.04.3 LTS"
    fingerprint:
      sshBanner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
  authentication:
    mode: selective
    allowCredentials:
      - username: jenkins
        password: "J3nkins_bld!"
      - username: deploy
        password: "Deploy2024#"
    captureAll: true
  telemetry:
    sessionCapture:
      fullTranscript: true
      keystrokeTimings: true
    exporter:
      type: nats
      endpoint: "nats://cicdecoy-nats.cicdecoy-system:4222"
      subject: "cicdecoy.decoy.events.lateral"
  engage:
    activity: EAC0001
    goal: EG0001
    hypothesis: "Attackers performing lateral movement will target build infrastructure for supply chain access."
```

### Detection Criteria

| Signal | Confidence | Threshold |
|---|---|---|
| Any TCP connection to a lateral-movement decoy from an internal IP | High | 1 event — no legitimate user connects to decoys |
| Successful authentication on any lateral-movement decoy | Critical | Confirmed compromise; attacker has working credentials |
| Connection from internal IP outside business hours (22:00-06:00) | Critical | After-hours lateral movement strongly indicates adversary |
| Same source IP connects to multiple decoys within 1 hour | Critical | Active network pivoting in progress |
| SSH connection followed by command execution | Critical | Attacker has shell access and is operating interactively |

**Key insight:** Unlike perimeter beacons that catch scanners, lateral movement decoys produce near-zero false positives. Real users never have a reason to connect. Any connection from an internal IP is an incident.

**SIEM query (Splunk):**

```spl
index=cicdecoy sourcetype="cicdecoy:event" campaign="lateral-movement-hunt"
  src_ip IN (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
| eval hour=strftime(_time, "%H")
| eval after_hours=if(hour>=22 OR hour<6, "yes", "no")
| table _time src_ip decoy_name event_type username after_hours
| sort _time
```

### Response Actions

1. **Immediate:** Trigger a SOAR playbook to isolate the source IP's host from the network. This is a confirmed compromise — do not wait for analyst review.
2. **Identify the foothold:** The source IP is not the initial compromise point; it is a pivot host. Search for how that host was compromised: prior auth events, malware alerts, phishing timeline.
3. **Scope the breach:** Query all firewall, proxy, and authentication logs for the source IP and any credentials the attacker used. Determine what real systems they accessed before hitting the decoy.
4. **Credential reset:** Force reset any credentials the attacker attempted (whether they succeeded on the decoy or not). The fact that they tried `postgres:pgAdmin_2024` means they may have found similar credentials on real systems.
5. **Hunt forward:** Search for the attacker's TTPs on other internal hosts. Check for SSH key drops, reverse shells, or persistence mechanisms.

### Tuning Guidance

- **Zero tolerance policy:** Do not tune down sensitivity on lateral movement decoys. Every internal connection is an alert. If you are getting false positives, something in your environment is misconfigured (e.g., a monitoring tool probing all IPs on a subnet).
- **Exclude infrastructure IPs:** If network monitoring tools do health checks on all IPs in a VLAN, add their source IPs to a SIEM-level suppression rule. Do not disable logging in the decoy.
- **DNS registration:** For maximum effectiveness, register decoy hostnames in internal DNS so they appear in `nslookup` and `dig` results. Attackers who enumerate DNS will find them.
- **Hostname realism:** Match your organization's naming convention exactly. If your real DB servers are `prod-pg-01`, `prod-pg-02`, name the decoy `dev-db-03` — plausible but not a collision.

---

## Playbook 3: Expose Reconnaissance Activity

### Objective

Detect network scanning and service enumeration by deploying Tier 1 beacons on ports that represent high-value services. Attackers performing reconnaissance will probe these ports during discovery. The beacons act as tripwires that fire on first contact.

### MITRE ATT&CK

| Technique | ID | Tactic |
|---|---|---|
| Network Service Discovery | T1046 | Discovery |
| Network Sniffing | T1040 | Credential Access, Discovery |
| System Network Configuration Discovery | T1016 | Discovery |
| Remote System Discovery | T1018 | Discovery |

### Network Placement

```
    Internal Network — High-Value Segment
    ┌──────────────────────────────────────────────────┐
    │                                                  │
    │   Real Servers          Decoy Beacons            │
    │   ┌──────────┐          ┌───────────────┐        │
    │   │ prod-db  │          │ [DECOY] :3306 │ MySQL  │
    │   │ (pg:5432)│          │ [DECOY] :5432 │ PgSQL  │
    │   └──────────┘          │ [DECOY] :6379 │ Redis  │
    │                         │ [DECOY] :8443 │ Admin  │
    │   ┌──────────┐          │ [DECOY] :9200 │ Elastic│
    │   │ prod-app │          │ [DECOY] :27017│ Mongo  │
    │   │ (http)   │          └───────────────┘        │
    │   └──────────┘                                   │
    │                                                  │
    └──────────────────────────────────────────────────┘
```

Scatter beacons across ports that attackers specifically look for during service enumeration. These ports indicate databases, caches, and admin interfaces — high-value targets that attract reconnaissance.

### Deployment Manifests

**Fleet deployment — multiple beacons from a single manifest:**

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: DecoyTemplate
metadata:
  name: recon-beacon
  namespace: decoys-production
spec:
  description: "Tier 1 beacon for reconnaissance detection"
  template:
    spec:
      fidelity:
        tier: 1
      identity:
        hostname: "{{ .hostname }}"
        os:
          family: linux
      authentication:
        mode: closed
        captureAll: true
      telemetry:
        sessionCapture:
          fullTranscript: true
        exporter:
          type: nats
          endpoint: "nats://cicdecoy-nats.cicdecoy-system:4222"
          subject: "cicdecoy.decoy.events.recon"
      engage:
        activity: EAC0001
        goal: EG0002
        hypothesis: "Attackers performing reconnaissance will probe common service ports."
  parameters:
    - name: hostname
      required: true
      description: "Decoy hostname"
---
apiVersion: cicdecoy.io/v1alpha1
kind: DecoyFleet
metadata:
  name: recon-detection-fleet
  namespace: decoys-production
spec:
  count: 6
  templateRef: "recon-beacon"
  namingPattern: "recon-{{ .Zone }}-{{ .Index }}"
  zones: ["data-tier", "app-tier"]
  parameterOverrides:
    hostname: "srv-{{ .Zone }}-{{ .Index }}"
```

**Individual beacons for specific ports (when you want fine-grained control):**

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: Decoy
metadata:
  name: recon-mysql-beacon
  namespace: decoys-production
  labels:
    cicdecoy.io/tier: "1"
    cicdecoy.io/zone: "data-tier"
    cicdecoy.io/campaign: "recon-detection"
spec:
  service:
    type: mysql
    port: 3306
    banner: "5.7.42-0ubuntu0.22.04.1"
  fidelity:
    tier: 1
  identity:
    hostname: "analytics-db-01"
    os:
      family: linux
  authentication:
    mode: closed
    captureAll: true
  telemetry:
    sessionCapture:
      fullTranscript: true
    exporter:
      type: nats
      endpoint: "nats://cicdecoy-nats.cicdecoy-system:4222"
      subject: "cicdecoy.decoy.events.recon"
  engage:
    activity: EAC0001
    goal: EG0002
    hypothesis: "Reconnaissance tools scanning for MySQL will hit this beacon."
  resources:
    requests:
      cpu: "25m"
      memory: "16Mi"
    limits:
      cpu: "50m"
      memory: "32Mi"
```

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: Decoy
metadata:
  name: recon-redis-beacon
  namespace: decoys-production
  labels:
    cicdecoy.io/tier: "1"
    cicdecoy.io/zone: "data-tier"
    cicdecoy.io/campaign: "recon-detection"
spec:
  service:
    type: redis
    port: 6379
    banner: "Redis 7.2.3"
  fidelity:
    tier: 1
  identity:
    hostname: "cache-node-02"
    os:
      family: linux
  authentication:
    mode: closed
    captureAll: true
  telemetry:
    sessionCapture:
      fullTranscript: true
    exporter:
      type: nats
      endpoint: "nats://cicdecoy-nats.cicdecoy-system:4222"
      subject: "cicdecoy.decoy.events.recon"
  engage:
    activity: EAC0001
    goal: EG0002
    hypothesis: "Attackers scanning for unprotected Redis instances will hit this beacon."
  resources:
    requests:
      cpu: "25m"
      memory: "16Mi"
    limits:
      cpu: "50m"
      memory: "32Mi"
```

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: Decoy
metadata:
  name: recon-admin-beacon
  namespace: decoys-production
  labels:
    cicdecoy.io/tier: "1"
    cicdecoy.io/zone: "app-tier"
    cicdecoy.io/campaign: "recon-detection"
spec:
  service:
    type: https
    port: 8443
    banner: "Apache/2.4.57"
  fidelity:
    tier: 1
  identity:
    hostname: "admin-panel-01"
    os:
      family: linux
  authentication:
    mode: closed
    captureAll: true
  telemetry:
    sessionCapture:
      fullTranscript: true
    exporter:
      type: nats
      endpoint: "nats://cicdecoy-nats.cicdecoy-system:4222"
      subject: "cicdecoy.decoy.events.recon"
  engage:
    activity: EAC0001
    goal: EG0002
    hypothesis: "Reconnaissance targeting admin panels will probe 8443."
  resources:
    requests:
      cpu: "25m"
      memory: "16Mi"
    limits:
      cpu: "50m"
      memory: "32Mi"
```

### Detection Criteria

| Signal | Confidence | Threshold |
|---|---|---|
| Single port connection to one beacon | Low | Possible scan, possible accident |
| Connections to 3+ different beacon ports from same source within 5 minutes | High | Port scan confirmed |
| Banner grab (TCP connect, read banner, disconnect immediately) | Medium | Service enumeration |
| SYN scan pattern (half-open connections across multiple beacons) | High | nmap-style scanning |
| Connection to beacon port followed by no authentication attempt | Medium | Automated discovery, not exploitation |
| Internal IP scanning multiple beacon ports | Critical | Internal reconnaissance — compromised host |

**SIEM query (Splunk):**

```spl
index=cicdecoy sourcetype="cicdecoy:event" campaign="recon-detection"
| bin _time span=5m
| stats count dc(decoy_name) as ports_scanned values(service_port) as ports
  by src_ip _time
| where ports_scanned >= 3
| table _time src_ip ports_scanned ports
| sort -ports_scanned
```

### Response Actions

1. **Assess scope:** Determine how many decoy ports the scanner hit and over what time window. Slow scans (one port per hour) indicate a stealthier adversary.
2. **Correlate with firewall logs:** Check if the same source IP also scanned real hosts. The decoy gives you the early warning; the firewall logs show the full picture.
3. **For external IPs:** Add to threat intelligence watchlist. Block if the scan is aggressive. Monitor for follow-up exploitation attempts against real services on the same ports.
4. **For internal IPs:** This is a compromised host performing internal discovery. Escalate immediately. An insider or attacker with a foothold is mapping your network.
5. **Update firewall rules:** If certain ports should not be externally accessible at all, use the reconnaissance data to validate firewall segmentation.

### Tuning Guidance

- **Internet-facing beacons are noisy.** Expect thousands of hits from Shodan, Censys, ZoomEye, and mass-scanning botnets. These are useful for threat intelligence but will overwhelm your alert queue. Filter known scanner ASNs for alerting purposes; still store the events for intel.
- **Internal beacons are high-signal.** Any internal IP hitting a recon beacon should generate an alert. If internal vulnerability scanners (Nessus, Qualys) trigger beacons, suppress those specific source IPs in the SIEM.
- **Reduce beacon resource usage.** Tier 1 beacons are cheap. Run them at 16-32 MB memory. The goal is quantity and coverage, not interaction depth.
- **Rotate ports periodically.** If you suspect an attacker has identified your decoy ports, rotate the fleet to a new set of ports. The DecoyFleet rotation feature handles this automatically.

---

## Playbook 4: Identify Data Exfiltration Attempts

### Objective

Detect attackers searching for and attempting to extract sensitive data by deploying Tier 3 adaptive SSH decoys seeded with realistic honeytokens — fake AWS credentials, database connection strings, API keys, and configuration files. When an attacker accesses or exfiltrates these files, you get a high-confidence alert with full behavioral context.

### MITRE ATT&CK

| Technique | ID | Tactic |
|---|---|---|
| Data from Local System | T1005 | Collection |
| Unsecured Credentials: Credentials in Files | T1552.001 | Credential Access |
| Unsecured Credentials: Private Keys | T1552.004 | Credential Access |
| Archive Collected Data | T1560 | Collection |
| Exfiltration Over C2 Channel | T1041 | Exfiltration |
| Account Discovery | T1087 | Discovery |

### Network Placement

```
    ┌───────────────────────────────────────────┐
    │   Data-Rich Segment                       │
    │                                           │
    │   ┌───────────────────────────────────┐   │
    │   │  [DECOY] — Tier 3 Adaptive        │   │
    │   │  backup-admin-01                  │   │
    │   │                                   │   │
    │   │  Seeded files:                    │   │
    │   │  ~/.aws/credentials  [CANARY]     │   │
    │   │  ~/db-backups/prod-dump.sql.gz    │   │
    │   │  /etc/app/database.yml [CANARY]   │   │
    │   │  ~/.ssh/id_rsa (fake private key) │   │
    │   │  ~/scripts/deploy-prod.sh         │   │
    │   └───────────────────────────────────┘   │
    │                                           │
    │   ┌───────────────────────────────────┐   │
    │   │  [DECOY] — Tier 3 Adaptive        │   │
    │   │  data-warehouse-02                │   │
    │   │                                   │   │
    │   │  Seeded files:                    │   │
    │   │  /opt/etl/config.env  [CANARY]    │   │
    │   │  ~/exports/customer-data.csv      │   │
    │   │  /var/lib/pgsql/recovery.conf     │   │
    │   └───────────────────────────────────┘   │
    └───────────────────────────────────────────┘
```

### Deployment Manifests

**Honeytoken definitions (deploy these first):**

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: HoneyToken
metadata:
  name: aws-canary-exfil-01
  namespace: decoys-production
spec:
  type: aws-key
  value: |
    [default]
    aws_access_key_id = AKIAIOSFODNN7CANARY1
    aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bCanaryKeyExfil01
    region = us-east-1
  placement:
    - target: ssh-exfil-backup
      path: /home/backupadm/.aws/credentials
  alertOnAccess: true
---
apiVersion: cicdecoy.io/v1alpha1
kind: HoneyToken
metadata:
  name: db-conn-canary-01
  namespace: decoys-production
spec:
  type: database-cred
  value: |
    production:
      adapter: postgresql
      host: prod-pg-primary.corp.internal
      port: 5432
      database: customers_prod
      username: app_readwrite
      password: "Pr0d_DB_s3cret!2024"
  placement:
    - target: ssh-exfil-backup
      path: /etc/app/database.yml
  alertOnAccess: true
---
apiVersion: cicdecoy.io/v1alpha1
kind: HoneyToken
metadata:
  name: api-key-canary-01
  namespace: decoys-production
spec:
  type: api-token
  value: |
    STRIPE_SECRET_KEY=sk_live_canary_4eC39HqLyjWDarjtT1zdp7dc
    DATADOG_API_KEY=canary_a1b2c3d4e5f6g7h8i9j0k1l2m3
    SLACK_BOT_TOKEN=xoxb-canary-1234567890-abcdefghijklmno
  placement:
    - target: ssh-exfil-datawarehouse
      path: /opt/etl/config.env
  alertOnAccess: true
```

**Tier 3 adaptive decoy with seeded filesystem:**

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: Decoy
metadata:
  name: ssh-exfil-backup
  namespace: decoys-production
  labels:
    cicdecoy.io/tier: "3"
    cicdecoy.io/zone: "data-tier"
    cicdecoy.io/campaign: "exfil-detection"
spec:
  service:
    type: ssh
    port: 22
  fidelity:
    tier: 3
    adaptive:
      profileRef: "backup-admin-server"
      inferenceConfig:
        maxSessionTokens: 8192
        temperature: 0.3
      fastPath:
        enabled: true
        commands:
          - { match: "^ls", source: filesystem }
          - { match: "^pwd$", source: state }
          - { match: "^whoami$", source: state }
          - { match: "^id$", source: state }
          - { match: "^cat /etc/(passwd|hostname|os-release)", source: profile }
      guardrails:
        preventRealCommands: true
        filterPatterns:
          - "(?i)honeypot"
          - "(?i)decoy"
          - "(?i)cicdecoy"
          - "(?i)I('m| am) an AI"
          - "(?i)language model"
        maxResponseLines: 500
  identity:
    hostname: "backup-admin-01"
    os:
      family: linux
      distro: "Ubuntu 22.04.3 LTS"
    fingerprint:
      sshBanner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
  authentication:
    mode: selective
    allowCredentials:
      - username: backupadm
        password: "Bkup_2024!admin"
      - username: root
        password: "toor"
    captureAll: true
  filesystem:
    base: "ubuntu-22.04-server"
    honeytokens:
      - path: /home/backupadm/.aws/credentials
        tokenRef: aws-canary-exfil-01
      - path: /etc/app/database.yml
        tokenRef: db-conn-canary-01
      - path: /home/backupadm/.ssh/id_rsa
        content: |
          -----BEGIN OPENSSH PRIVATE KEY-----
          b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
          NhAAAAAwEAAQAAAIEA1FakeKeyForDecoyPurposes2Nzaaaaaa0BAAAIEA1FakeKeyForD
          ecoyPurposes2Nzaaaaaa0BAAAIEA1FakeKeyForDecoyPurposes2Nzaaaaaa0BAAAIEA1
          -----END OPENSSH PRIVATE KEY-----
      - path: /home/backupadm/db-backups/prod-dump-2024-01-15.sql.gz
        content: "[binary placeholder - LLM will describe as a gzipped SQL dump]"
      - path: /home/backupadm/scripts/deploy-prod.sh
        content: |
          #!/bin/bash
          # Deploy to production -- run as root
          export DB_HOST=prod-pg-primary.corp.internal
          export DB_PASS="Pr0d_DB_s3cret!2024"
          rsync -avz /opt/app/ prod-app-01:/opt/app/
          ssh prod-app-01 "systemctl restart app-service"
  telemetry:
    sessionCapture:
      fullTranscript: true
      keystrokeTimings: true
      fileUploads: true
    exporter:
      type: nats
      endpoint: "nats://cicdecoy-nats.cicdecoy-system:4222"
      subject: "cicdecoy.decoy.events.exfil"
  engage:
    activity: EAC0001
    goal: EG0001
    hypothesis: "Attackers who gain shell access will search for credentials, keys, and data to exfiltrate."
    collection_requirements:
      - "Commands used to locate sensitive files (find, grep, locate)"
      - "Methods used to read credential files"
      - "Exfiltration methods attempted (scp, curl, wget, base64 encoding)"
```

**Decoy profile for the backup admin server:**

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: DecoyProfile
metadata:
  name: backup-admin-server
  namespace: cicdecoy-system
spec:
  description: "Backup administration server with access to production data"
  os:
    family: linux
    distro: "Ubuntu 22.04.3 LTS"
    kernel: "5.15.0-91-generic"
  packages:
    - { name: "openssh-server", version: "8.9p1" }
    - { name: "postgresql-client-15", version: "15.4" }
    - { name: "awscli", version: "2.15.4" }
    - { name: "rsync", version: "3.2.7" }
    - { name: "rclone", version: "1.65.0" }
  users:
    - username: backupadm
      uid: 1000
      shell: /bin/bash
      home: /home/backupadm
  filesystem:
    extraPaths:
      - /home/backupadm/db-backups/
      - /home/backupadm/scripts/
      - /home/backupadm/.aws/
      - /opt/app/
      - /var/log/backup/
```

### Detection Criteria

| Signal | Confidence | Threshold |
|---|---|---|
| Any file read on a honeytoken file (cat, less, head, vi) | Critical | Attacker is harvesting credentials |
| `find` or `grep` commands searching for keys, passwords, credentials | High | Credential hunting behavior |
| `cat ~/.aws/credentials` or `cat ~/.ssh/id_rsa` | Critical | Direct credential theft |
| Attacker runs `scp`, `curl`, `wget`, or base64-encodes file contents | Critical | Active exfiltration attempt |
| Attacker runs `tar` or `zip` on directories containing honeytokens | Critical | Staging data for bulk exfiltration |
| AWS API calls using canary access key ID | Critical | Exfiltrated credential was used (requires AWS CloudTrail + canary key registration) |

**SIEM query (Splunk):**

```spl
index=cicdecoy sourcetype="cicdecoy:event" campaign="exfil-detection"
  event_type=command.exec
  (command="*cat*credentials*" OR command="*cat*id_rsa*" OR
   command="*find*password*" OR command="*grep*key*" OR
   command="*scp*" OR command="*curl*" OR command="*base64*" OR
   command="*tar*" OR command="*zip*")
| table _time src_ip session_id command decoy_name
| sort _time
```

**Honeytoken trigger query:**

```spl
index=cicdecoy sourcetype="cicdecoy:event" event_type="honeytoken.access"
| table _time src_ip token_name token_type file_path session_id
| sort _time
```

### Response Actions

1. **Immediate:** Any honeytoken access is a confirmed compromise. Isolate the attacker's source host. The session transcript tells you exactly what they found and what they tried to steal.
2. **Check canary triggers:** If the attacker read AWS canary credentials, check CloudTrail for API calls using the canary access key. If triggered, the attacker has exfiltrated credentials and is using them outside your network.
3. **Damage assessment:** Review the full session transcript. What commands did the attacker run before finding the honeytokens? What else did they look for? This tells you what data they value and what they may have already taken from real systems.
4. **Rotate real credentials:** If the decoy's fake credentials resemble real credential patterns in your organization, rotate the real ones. The attacker now knows your credential naming conventions.
5. **Feed false intelligence:** If operational goals allow, leave the session open and monitor what the attacker does with the fake credentials. This generates additional TTPs and may reveal their infrastructure.

### Tuning Guidance

- **Honeytoken placement must be realistic.** Put `~/.aws/credentials` in a home directory that has other AWS-related files (`.aws/config`, CLI history referencing S3 buckets). An isolated credentials file with nothing else looks planted.
- **Make file timestamps plausible.** The deploy script should have a modification date from weeks ago, not from the moment the decoy was deployed. Profiles with filesystem overlays can set `mtime` values.
- **Avoid overly valuable data.** If your fake database dump filename is `customer-pii-all-records-2024.sql.gz`, a sophisticated attacker may suspect deception. Use mundane names like `prod-dump-2024-01-15.sql.gz`.
- **Canary key registration.** For AWS canary keys to trigger on use, register them with AWS (or a canary token provider like Thinkst Canary). Without external trigger detection, you only know the attacker read the file, not that they used the key.

---

## Playbook 5: Detect C2 Communication

### Objective

Identify command-and-control frameworks (Cobalt Strike, Metasploit, Sliver, Brute Ratel) interacting with decoys by deploying Tier 3 adaptive SSH decoys that engage attackers in extended sessions. The CTI pipeline's behavioral scoring, tool identification, and session analysis detect C2 signatures even when the attacker uses encrypted or obfuscated channels.

### MITRE ATT&CK

| Technique | ID | Tactic |
|---|---|---|
| Command and Scripting Interpreter: Unix Shell | T1059.004 | Execution |
| Remote Access Software | T1219 | Command and Control |
| Ingress Tool Transfer | T1105 | Command and Control |
| Automated Collection | T1119 | Collection |
| Scheduled Task/Job: Cron | T1053.003 | Execution, Persistence |

### Network Placement

```
    ┌──────────────────────────────────────────────┐
    │   Segments Where C2 Implants Phone Home      │
    │                                              │
    │   ┌──────────────┐   ┌──────────────┐        │
    │   │ [DECOY]      │   │ [DECOY]      │        │
    │   │ web-proxy-05 │   │ mgmt-srv-02  │        │
    │   │ Tier 3 SSH   │   │ Tier 3 SSH   │        │
    │   │              │   │              │        │
    │   │ Long session │   │ Long session │        │
    │   │ engagement   │   │ engagement   │        │
    │   │              │   │              │        │
    │   │ Behavioral   │   │ Behavioral   │        │
    │   │ scoring      │   │ scoring      │        │
    │   └──────┬───────┘   └──────┬───────┘        │
    │          │                  │                 │
    │          └──────┬───────────┘                 │
    │                 ▼                             │
    │   ┌──────────────────────────────┐            │
    │   │ CTI Pipeline                 │            │
    │   │ - Tool identification        │            │
    │   │ - Behavioral scoring         │            │
    │   │ - Kill chain reconstruction  │            │
    │   │ - Beaconing interval detect  │            │
    │   └──────────────────────────────┘            │
    └──────────────────────────────────────────────┘
```

Place Tier 3 decoys on segments where you expect attackers with persistent access to operate: management VLANs, server segments, and network zones adjacent to internet egress points. The decoys need to sustain interactive sessions long enough for behavioral analysis to identify C2 tooling.

### Deployment Manifests

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: Decoy
metadata:
  name: ssh-c2-detect-webproxy
  namespace: decoys-production
  labels:
    cicdecoy.io/tier: "3"
    cicdecoy.io/zone: "management"
    cicdecoy.io/campaign: "c2-detection"
spec:
  service:
    type: ssh
    port: 22
  fidelity:
    tier: 3
    adaptive:
      profileRef: "web-proxy-server"
      inferenceConfig:
        maxSessionTokens: 16384
        temperature: 0.3
      fastPath:
        enabled: true
        commands:
          - { match: "^ls", source: filesystem }
          - { match: "^pwd$", source: state }
          - { match: "^whoami$", source: state }
          - { match: "^id$", source: state }
          - { match: "^hostname$", source: state }
          - { match: "^date$", source: dynamic }
          - { match: "^uptime$", source: profile }
          - { match: "^cat /etc/(passwd|hostname|os-release|hosts|issue)", source: profile }
          - { match: "^ps", source: profile }
          - { match: "^netstat", source: profile }
          - { match: "^ss ", source: profile }
          - { match: "^ifconfig", source: profile }
          - { match: "^ip a", source: profile }
      guardrails:
        preventRealCommands: true
        filterPatterns:
          - "(?i)honeypot"
          - "(?i)decoy"
          - "(?i)cicdecoy"
          - "(?i)I('m| am) an AI"
          - "(?i)language model"
          - "(?i)simulated"
        maxResponseLines: 500
        disallowedPaths:
          - "/opt/cicdecoy"
          - "/var/log/decoy"
  identity:
    hostname: "web-proxy-05"
    os:
      family: linux
      distro: "Ubuntu 22.04.3 LTS"
    fingerprint:
      sshBanner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
  authentication:
    mode: realistic
    allowCredentials:
      - username: sysadmin
        password: "Pr0xy_adm1n!"
      - username: root
        password: "R00t_2024!"
    captureAll: true
  filesystem:
    base: "ubuntu-22.04-server"
    honeytokens:
      - path: /etc/squid/squid.conf
        content: |
          # Squid proxy configuration
          http_port 3128
          acl localnet src 10.0.0.0/8
          http_access allow localnet
      - path: /var/log/squid/access.log
        content: "[LLM will generate realistic proxy log entries]"
      - path: /home/sysadmin/.bash_history
        content: |
          systemctl status squid
          tail -f /var/log/squid/access.log
          sudo apt update
          sudo apt upgrade -y
          vim /etc/squid/squid.conf
          squid -k reconfigure
          df -h
          free -m
          last
  telemetry:
    sessionCapture:
      fullTranscript: true
      keystrokeTimings: true
      fileUploads: true
    exporter:
      type: nats
      endpoint: "nats://cicdecoy-nats.cicdecoy-system:4222"
      subject: "cicdecoy.decoy.events.c2"
  engage:
    activity: EAC0001
    goal: EG0001
    hypothesis: "C2 frameworks operating in the management VLAN will attempt SSH access to pivot hosts."
    collection_requirements:
      - "Tool signatures and framework identification"
      - "Command timing patterns indicating automation"
      - "Staging behaviors and persistence mechanisms attempted"
      - "Network reconnaissance commands revealing attacker objectives"
```

**Profile for the web proxy server:**

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: DecoyProfile
metadata:
  name: web-proxy-server
  namespace: cicdecoy-system
spec:
  description: "Squid proxy server in the management VLAN"
  os:
    family: linux
    distro: "Ubuntu 22.04.3 LTS"
    kernel: "5.15.0-91-generic"
  packages:
    - { name: "openssh-server", version: "8.9p1" }
    - { name: "squid", version: "5.7-0ubuntu0.22.04.1" }
    - { name: "net-tools", version: "1.60+git20181103" }
    - { name: "curl", version: "7.81.0" }
    - { name: "vim", version: "8.2.3995" }
    - { name: "htop", version: "3.0.5" }
  users:
    - username: sysadmin
      uid: 1000
      shell: /bin/bash
      home: /home/sysadmin
    - username: squid
      uid: 13
      shell: /usr/sbin/nologin
      home: /var/spool/squid
  filesystem:
    extraPaths:
      - /etc/squid/
      - /var/log/squid/
      - /var/spool/squid/
```

**Second Tier 3 decoy for cross-correlation:**

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: Decoy
metadata:
  name: ssh-c2-detect-mgmt
  namespace: decoys-production
  labels:
    cicdecoy.io/tier: "3"
    cicdecoy.io/zone: "management"
    cicdecoy.io/campaign: "c2-detection"
spec:
  service:
    type: ssh
    port: 22
  fidelity:
    tier: 3
    adaptive:
      profileRef: "mgmt-server"
      inferenceConfig:
        maxSessionTokens: 16384
        temperature: 0.3
      fastPath:
        enabled: true
        commands:
          - { match: "^ls", source: filesystem }
          - { match: "^pwd$", source: state }
          - { match: "^whoami$", source: state }
          - { match: "^id$", source: state }
          - { match: "^hostname$", source: state }
          - { match: "^date$", source: dynamic }
          - { match: "^uptime$", source: profile }
          - { match: "^cat /etc/(passwd|hostname|os-release)", source: profile }
          - { match: "^ps", source: profile }
          - { match: "^netstat", source: profile }
      guardrails:
        preventRealCommands: true
        filterPatterns:
          - "(?i)honeypot"
          - "(?i)decoy"
          - "(?i)cicdecoy"
          - "(?i)I('m| am) an AI"
          - "(?i)language model"
          - "(?i)simulated"
        maxResponseLines: 500
  identity:
    hostname: "mgmt-srv-02"
    os:
      family: linux
      distro: "Ubuntu 22.04.3 LTS"
    fingerprint:
      sshBanner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
  authentication:
    mode: realistic
    allowCredentials:
      - username: admin
        password: "Mgmt_2024!"
      - username: ansible
        password: "Ans1ble_key!"
    captureAll: true
  filesystem:
    base: "ubuntu-22.04-server"
    honeytokens:
      - path: /home/admin/.bash_history
        content: |
          ansible-playbook -i inventory/prod site.yml
          ssh prod-app-01 "systemctl status nginx"
          kubectl get pods -n production
          scp admin@prod-db-01:/tmp/backup.tar.gz .
          vim /etc/ansible/hosts
      - path: /etc/ansible/hosts
        content: |
          [webservers]
          prod-app-01 ansible_host=10.2.1.10
          prod-app-02 ansible_host=10.2.1.11

          [databases]
          prod-db-01 ansible_host=10.3.1.10
          prod-db-02 ansible_host=10.3.1.11

          [monitoring]
          grafana-01 ansible_host=10.4.1.10
  telemetry:
    sessionCapture:
      fullTranscript: true
      keystrokeTimings: true
      fileUploads: true
    exporter:
      type: nats
      endpoint: "nats://cicdecoy-nats.cicdecoy-system:4222"
      subject: "cicdecoy.decoy.events.c2"
  engage:
    activity: EAC0001
    goal: EG0001
    hypothesis: "C2 operators will target management servers to expand access to production infrastructure."
    collection_requirements:
      - "Automated vs. manual command patterns"
      - "Persistence mechanisms attempted"
      - "Lateral movement targets from command history"
```

### Detection Criteria

| Signal | Confidence | How CI/CDecoy Detects It |
|---|---|---|
| Cobalt Strike `beacon` command patterns (sleep, checkin, execute-assembly) | Critical | Tool identification in CTI enrichment pipeline |
| Metasploit `meterpreter` commands (sysinfo, getuid, hashdump) | Critical | Pattern matching against known framework command sets |
| Command timing with regular intervals (e.g., exactly every 60s) | High | Keystroke timing analysis detects beaconing patterns |
| Batch command execution (multiple commands pasted with no human typing delay) | High | Keystroke timing — pasted commands arrive in <5ms vs. human typing at 50-200ms per character |
| `wget`/`curl` downloading binaries from external IPs | Critical | Command content analysis + URL extraction |
| `chmod +x` followed by execution of downloaded file | Critical | Kill chain reconstruction: staging -> execution |
| Persistence attempts: crontab edits, systemd services, `.bashrc` modifications | Critical | MITRE ATT&CK mapping flags T1053/T1546 |
| Network enumeration: `ifconfig`, `ip a`, `arp -a`, `netstat -tlnp` in rapid succession | High | Behavioral scoring: discovery phase of kill chain |
| Same source IP connects to multiple C2 campaign decoys | Critical | Cross-decoy correlation in session analyzer |

**SIEM query — tool signature detection (Splunk):**

```spl
index=cicdecoy sourcetype="cicdecoy:event" campaign="c2-detection"
  event_type=command.exec
| eval is_c2_signature=case(
    match(command, "(?i)(beacon|sleep\s+\d+|execute-assembly|jump\s+psexec)"), "cobalt_strike",
    match(command, "(?i)(sysinfo|getuid|hashdump|getsystem|migrate\s+\d+)"), "metasploit",
    match(command, "(?i)(implant|generate|armory|cursed)"), "sliver",
    match(command, "(?i)(badger|brute.*ratel)"), "brute_ratel",
    1=1, null()
  )
| where isnotnull(is_c2_signature)
| table _time src_ip session_id is_c2_signature command
```

**SIEM query — beaconing interval detection (Splunk):**

```spl
index=cicdecoy sourcetype="cicdecoy:event" campaign="c2-detection"
  event_type=command.exec
| sort session_id _time
| streamstats current=f last(_time) as prev_time by session_id
| eval interval=_time-prev_time
| stats stdev(interval) as interval_stdev avg(interval) as interval_avg
  count by session_id src_ip
| where interval_stdev < 5 AND interval_avg > 10 AND count > 5
| eval pattern="Regular interval beaconing: avg=" . round(interval_avg,1) . "s, stdev=" . round(interval_stdev,2) . "s"
| table session_id src_ip interval_avg interval_stdev count pattern
```

**SIEM query — automated vs. human typing (Splunk):**

```spl
index=cicdecoy sourcetype="cicdecoy:event" campaign="c2-detection"
  event_type=command.exec keystroke_timing_ms=*
| eval is_pasted=if(keystroke_timing_ms < 5, 1, 0)
| stats count sum(is_pasted) as pasted_commands by session_id src_ip
| eval paste_ratio=round(pasted_commands/count*100, 1)
| where paste_ratio > 80 AND count > 3
| eval assessment="Automated tool: " . paste_ratio . "% commands pasted (" . pasted_commands . "/" . count . ")"
| table session_id src_ip paste_ratio pasted_commands count assessment
```

### Response Actions

1. **Immediate:** A confirmed C2 framework interacting with a decoy means an attacker has persistent access to your network. Escalate to incident response. Do not simply block the IP — the attacker has other implants.
2. **Identify the C2 infrastructure:** Extract external IPs, domains, and URLs from the session transcript. These are C2 server addresses. Block them at the perimeter and add them to your threat intelligence platform.
3. **Determine implant scope:** The source IP connecting to the decoy hosts a C2 implant. Search for the same implant signatures (process names, network connections, file hashes) across all endpoints using your EDR.
4. **Analyze session behavior:** The full session transcript shows you what the attacker was looking for. Were they after credentials? Configuration files? Network maps? This reveals their objectives and helps you protect those assets.
5. **Preserve evidence:** Export the full session via `cicdecoy sessions export <session-id> --format stix` for incident documentation and potential law enforcement referral.
6. **Do not tip off the attacker.** If possible, keep the decoy session alive while you scope the breach on real infrastructure. The longer the attacker engages with the decoy, the more intelligence you collect — and the more time you have to contain the real compromise.

### Tuning Guidance

- **Increase maxSessionTokens for C2 hunts.** C2 operators may run long sessions with many commands. Set `maxSessionTokens: 16384` or higher to keep the LLM context coherent throughout the session.
- **Keystroke timing is the strongest C2 signal.** Humans type at 30-80 WPM with variable inter-key delays. C2 frameworks paste commands with near-zero delay. A session where >80% of commands have <5ms inter-keystroke timing is almost certainly automated.
- **Beaconing detection requires patience.** Regular-interval check-ins only become detectable after 5+ interactions. Do not alert on the first few commands — wait for the pattern to emerge.
- **Tool signature updates.** The CTI enrichment pipeline's tool identification rules need periodic updates as C2 frameworks evolve. Add new signatures based on threat intelligence reports and red team debriefs.
- **Red team coordination.** If your organization runs red team exercises, coordinate with them to avoid burning your deception posture. Give red teams decoy locations only if testing deception detection is in scope. Otherwise, they should avoid decoys so real attacker interactions remain distinguishable.
- **Session replay for analysis.** Use `cicdecoy sessions replay <session-id> --speed 1` to watch C2 sessions in real time. The pacing and command selection reveal whether the operator is using a GUI-based C2 (click-to-run, slow and deliberate) or a CLI-based framework (fast, scripted).

---

## Cross-Playbook Deployment

These five playbooks can run simultaneously. Use campaign labels to organize alerts and filter SIEM queries.

### Combined fleet view

```bash
# See all campaign decoys
cicdecoy status decoys --label cicdecoy.io/campaign

# Watch all campaigns in real time
cicdecoy sessions watch --annotated

# Filter by campaign
cicdecoy sessions list --live --label cicdecoy.io/campaign=lateral-movement-hunt

# Weekly intelligence report across all campaigns
cicdecoy intel report --period weekly --format md -o weekly-hunt-report.md
```

### Alert priority matrix

| Campaign | Any Connection | Auth Attempt | Auth Success | Command Execution |
|---|---|---|---|---|
| credential-stuffing-hunt | Low | Medium | High | N/A (Tier 1) |
| lateral-movement-hunt | High | Critical | Critical | Critical |
| recon-detection | Low | Medium | N/A (closed auth) | N/A (Tier 1) |
| exfil-detection | High | Critical | Critical | Critical (especially file access) |
| c2-detection | High | Critical | Critical | Critical (tool signatures) |

### Resource budget

| Campaign | Decoy Count | Tier Mix | Estimated Resources |
|---|---|---|---|
| credential-stuffing-hunt | 6-10 | 5 T1 + 1 T2 | ~300 MB RAM, ~400m CPU |
| lateral-movement-hunt | 3-5 | All T2 | ~500 MB RAM, ~500m CPU |
| recon-detection | 6-12 | All T1 | ~200 MB RAM, ~300m CPU |
| exfil-detection | 2-3 | All T3 | ~1 GB RAM, ~2 CPU (plus shared inference) |
| c2-detection | 2-3 | All T3 | ~1 GB RAM, ~2 CPU (plus shared inference) |
| **Total** | **19-33** | | **~3 GB RAM, ~5 CPU + inference** |
