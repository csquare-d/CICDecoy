# Profile Authoring Guide

Profiles define the personality of a CI/CDecoy decoy -- the operating system it claims to run, the software it has installed, the users who log in, the files on disk, and the narrative that ties it all together. This guide covers the profile format, how profiles drive decoy behavior, and how to create your own.

## 1. What Is a Decoy Profile?

A profile is a JSON file that describes a complete system identity: OS version, kernel, installed packages, running services, user accounts, environment variables, filesystem artifacts, and a free-text narrative. The decoy engine uses the profile at two levels:

- **Tier 2 (Scripted):** The profile's `static_responses` and `filesystem_extras` fields populate the high-fidelity scripted engine with canned responses for commands like `docker ps`, `df -h`, and `free -h`. The virtual filesystem is seeded from `filesystem_extras` so that `cat`, `head`, `grep`, and `find` work against realistic file content.

- **Tier 3 (Adaptive):** The inference service's prompt engine reads the profile and injects `system`, `users`, `software`, `environment`, and `narrative` into the LLM system prompt. The LLM then generates terminal output consistent with the described machine. A good narrative is the difference between a generic Linux box and a convincing production server.

**Why profiles matter:** A decoy with a thin or inconsistent identity gets fingerprinted quickly. A decoy whose `uname -a` says Ubuntu but whose `yum` works, or whose `.bash_history` is empty, signals deception. Profiles let you build a coherent, layered identity that keeps attackers engaged longer and generates better intelligence.

## 2. Profile Structure

Profiles are JSON files stored in `decoys/profiles/`. At runtime they are mounted into containers at `/etc/cicdecoy/profiles/` (see `docker-compose.yaml` and the Helm chart).

### Required Fields

The inference service's prompt engine requires two top-level keys:

| Field | Type | Description |
|-------|------|-------------|
| `system` | object | OS identity, kernel, hostname, uptime, timezone |
| `users` | array | User accounts on the system |

If either is missing, the profile is skipped during loading.

### Full Schema

```json
{
  "description": "One-line summary of what this profile simulates",

  "system": {
    "os":        "Ubuntu 22.04.3 LTS",
    "kernel":    "5.15.0-91-generic",
    "hostname":  "dev-ws-03",
    "uptime":    "67 days, 3:14",
    "timezone":  "America/New_York",
    "locale":    "en_US.UTF-8"
  },

  "users": [
    {
      "name":      "admin",
      "fullName":  "Alex Chen",
      "groups":    ["sudo", "docker", "developers"],
      "shell":     "/bin/bash",
      "lastLogin": "2024-01-18 09:32:01",
      "uid":       1000,
      "home":      "/home/admin"
    }
  ],

  "software": {
    "packages": [
      {"name": "openssh-server", "version": "8.9p1"},
      {"name": "docker-ce",      "version": "24.0.7"}
    ],
    "services": [
      {"name": "sshd",   "status": "active", "port": 22},
      {"name": "docker", "status": "active"}
    ]
  },

  "environment": {
    "variables": {
      "NODE_ENV": "production",
      "PATH":     "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    },
    "crontab": [
      "0 3 * * * /home/deploy/scripts/backup.sh >> /var/log/backup.log 2>&1"
    ]
  },

  "narrative": "Free-text description of the machine's role, users, and history.",

  "filesystem_extras": {
    "/path/to/file": "file content as a string"
  },

  "static_responses": {
    "command string": "output string"
  }
}
```

### Field Reference

**`system`** -- Populates the SYSTEM IDENTITY block of the LLM prompt and drives `uname`, `hostname`, `hostnamectl`, and `lsb_release` responses.

| Key | Required | Default | Notes |
|-----|----------|---------|-------|
| `os` | no | `"Ubuntu 22.04 LTS"` | Full OS name as shown by `lsb_release -d` |
| `kernel` | no | `"5.15.0-generic"` | Kernel version for `uname -r` |
| `hostname` | no | from Decoy manifest | Overridden at deploy time by the Decoy CR's `identity.hostname` |
| `uptime` | no | `"30 days"` | Human-readable uptime |
| `timezone` | no | `"UTC"` | IANA timezone |
| `locale` | no | -- | System locale string |

**`users`** -- Each entry becomes a line in the USER ACCOUNTS block of the LLM prompt. The scripted engine also uses `uid` and `home` for session state.

| Key | Required | Notes |
|-----|----------|-------|
| `name` | yes | Login username |
| `fullName` | no | GECOS / display name |
| `groups` | no | Array of group names |
| `shell` | no | Default: `/bin/bash` |
| `lastLogin` | no | Timestamp string |
| `uid` | no | Numeric UID |
| `home` | no | Home directory path |

**`software.packages`** -- Each entry has `name` (required) and `version` (optional). These populate the INSTALLED SOFTWARE prompt block.

**`software.services`** -- Each entry has `name` (required), `status` (optional, default `"active"`), and `port` (optional). These populate the RUNNING SERVICES prompt block.

**`environment.variables`** -- Key-value pairs injected into the LLM prompt's ENVIRONMENT section. Also available for identity substitution in scripted responses.

**`environment.crontab`** -- Array of crontab entry strings, included in the ENVIRONMENT prompt block.

**`narrative`** -- Free-text paragraph injected into the SYSTEM NARRATIVE prompt block. This is the most important field for Tier 3 quality. See the dedicated section below.

**`filesystem_extras`** -- A map of absolute paths to file contents. These are loaded into the virtual filesystem so that `cat`, `head`, `tail`, `grep`, `find`, `stat`, `wc`, `strings`, and `xxd` all work against them. Use this for `.bash_history`, config files, scripts, and breadcrumb files.

**`static_responses`** -- A map of exact command strings to output strings. These bypass all other resolution and return the output directly. Use for commands whose output is hard to generate dynamically, like `free -h`, `df -h`, and `docker ps`.

### Identity Substitution Tokens

Both `static_responses` and the response database support placeholder tokens that are replaced at runtime with session-specific values:

| Token | Replaced With |
|-------|---------------|
| `{{HOSTNAME}}` | Current decoy hostname |
| `{{USERNAME}}` | Logged-in username |
| `{{UID}}` | Logged-in user's UID |
| `{{HOME}}` | User's home directory |
| `{{CWD}}` | Current working directory |
| `{{SHELL}}` | User's shell (default `/bin/bash`) |

Example in `static_responses`:

```json
"static_responses": {
  "uptime": " 09:14:22 up 67 days,  3:14,  1 user,  load average: 0.12, 0.08, 0.03"
}
```

Example in a response database file using tokens:

```json
"cat /etc/hostname": {
  "output": "{{HOSTNAME}}",
  "exit_code": 0
}
```

## 3. Built-In Profiles

The project ships with one profile in `decoys/profiles/`:

### `dev-workstation.json`

Simulates a mid-level developer's Ubuntu 22.04 workstation. The machine runs a Node.js internal dashboard on port 3000, has Docker installed with running containers (nginx, postgres, redis), and is used by "Alex Chen" on the platform team. Includes:

- Two users: `admin` (developer) and `deploy` (service account)
- Node.js 18, Python 3.10, Docker CE 24, Git, vim, tmux
- Running services: sshd, Docker, cron, node-app on port 3000
- Filesystem extras: `.bash_history`, `.gitconfig`, app config with database credentials, backup scripts, `/etc/hosts` with internal hostnames
- Static responses for `uptime`, `free -h`, `df -h`, `docker ps`, `docker images`

A companion response database at `decoys/responses/dev-workstation.json` provides ~50 scripted responses for system inspection commands (`lsb_release`, `hostnamectl`, `systemctl status`, `pip list`, `lsblk`, etc.).

## 4. Creating a Custom Profile

This walkthrough creates a profile for an Ubuntu 22.04 database server -- the kind of machine an attacker would expect to find behind a bastion host on a production subnet.

### Step 1: Define the System Identity

Start with the basics. Pick an OS, kernel version, and hostname that match your target environment. If your real database servers are named `db-prod-NN`, use that pattern.

```json
{
  "description": "Production MySQL database server",

  "system": {
    "os": "Ubuntu 22.04.4 LTS",
    "kernel": "5.15.0-105-generic",
    "hostname": "db-prod-07",
    "uptime": "142 days, 8:37",
    "timezone": "America/Chicago",
    "locale": "en_US.UTF-8"
  }
}
```

### Step 2: Add User Accounts

Include the users an attacker would expect on a database server: root, the default OS user, a database service account, and a deployment user.

```json
  "users": [
    {
      "name": "root",
      "fullName": "root",
      "groups": ["root"],
      "shell": "/bin/bash",
      "lastLogin": "2024-03-10 02:15:00",
      "uid": 0,
      "home": "/root"
    },
    {
      "name": "ubuntu",
      "fullName": "Ubuntu",
      "groups": ["sudo", "adm", "docker"],
      "shell": "/bin/bash",
      "lastLogin": "2024-03-12 09:45:22",
      "uid": 1000,
      "home": "/home/ubuntu"
    },
    {
      "name": "mysql",
      "fullName": "MySQL Server",
      "groups": ["mysql"],
      "shell": "/bin/false",
      "uid": 27,
      "home": "/var/lib/mysql"
    },
    {
      "name": "deploy",
      "fullName": "Deploy Bot",
      "groups": ["docker", "deploy"],
      "shell": "/bin/bash",
      "lastLogin": "2024-03-11 03:00:01",
      "uid": 1001,
      "home": "/home/deploy"
    }
  ]
```

### Step 3: List Software and Services

Include everything an attacker would check with `which`, `dpkg -l`, `systemctl`, or `--version` flags.

```json
  "software": {
    "packages": [
      {"name": "openssh-server",     "version": "8.9p1"},
      {"name": "mysql-server",       "version": "8.0.36"},
      {"name": "python3",            "version": "3.10.12"},
      {"name": "docker-ce",          "version": "25.0.3"},
      {"name": "git",                "version": "2.34.1"},
      {"name": "vim",                "version": "8.2.4919"},
      {"name": "curl",               "version": "7.81.0"},
      {"name": "net-tools",          "version": "1.60"},
      {"name": "percona-toolkit",    "version": "3.5.7"},
      {"name": "mytop",              "version": "1.9.1"},
      {"name": "prometheus-node-exporter", "version": "1.7.0"}
    ],
    "services": [
      {"name": "sshd",                      "status": "active", "port": 22},
      {"name": "mysql",                     "status": "active", "port": 3306},
      {"name": "prometheus-node-exporter",  "status": "active", "port": 9100},
      {"name": "cron",                      "status": "active"},
      {"name": "docker",                    "status": "active"}
    ]
  }
```

### Step 4: Set Up the Environment

Include environment variables and crontab entries consistent with the machine's role.

```json
  "environment": {
    "variables": {
      "MYSQL_HOME": "/etc/mysql",
      "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      "LANG": "en_US.UTF-8"
    },
    "crontab": [
      "0 2 * * * /opt/backups/mysql-backup.sh >> /var/log/mysql-backup.log 2>&1",
      "30 3 * * 0 /opt/backups/full-backup.sh >> /var/log/full-backup.log 2>&1",
      "*/5 * * * * /usr/local/bin/healthcheck.sh"
    ]
  }
```

### Step 5: Write the Narrative

This is the most important field for Tier 3 decoys. Write it as if you are briefing someone who needs to impersonate this machine. Cover: who uses it, what it does, what connects to it, what it connects to, any recent history or quirks.

```json
  "narrative": "This is a production MySQL 8.0 database server managed by the database team. It hosts the primary application database (app_production) and a reporting replica database (app_reporting). The server is accessed by two people: Jordan Park (DBA, logs in as ubuntu) for maintenance, and the deploy user for automated schema migrations via Ansible. The machine sits on the 10.10.5.0/24 database subnet and accepts MySQL connections from application servers on 10.10.3.0/24. Percona Toolkit is installed for query analysis and pt-online-schema-change operations. Daily backups run at 2 AM via mysqldump to /opt/backups/ and are rsynced to backup-nas.corp.internal. The server has 32GB RAM with innodb_buffer_pool_size set to 24G. Jordan has been meaning to upgrade to MySQL 8.0.37 but the quarterly release freeze has delayed it. There is a known slow query on the orders table that Jordan has been investigating -- notes are in /home/ubuntu/slow-query-notes.txt. Docker is installed but only used for running Percona PMM client containers for monitoring."
```

### Step 6: Seed the Filesystem

Add files that make the machine feel lived-in. Focus on files attackers typically inspect: shell history, config files, credentials, scripts, and logs.

```json
  "filesystem_extras": {
    "/home/ubuntu/.bash_history": "mysql -u root -p\nshow databases;\nselect count(*) from app_production.orders;\npt-query-digest /var/log/mysql/slow-query.log\ndocker ps\ndf -h\nfree -h\nssh deploy@app-server-01.corp.internal\ntail -f /var/log/mysql/error.log\nsudo systemctl restart mysql\ncat /opt/backups/mysql-backup.sh\nless /home/ubuntu/slow-query-notes.txt\nmysqldump --single-transaction app_production > /tmp/app_prod_dump.sql\nvim /etc/mysql/mysql.conf.d/mysqld.cnf",
    "/home/ubuntu/.ssh/known_hosts": "app-server-01.corp.internal,10.10.3.10 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK...\napp-server-02.corp.internal,10.10.3.11 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBL...\nbackup-nas.corp.internal,10.10.8.5 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBM...",
    "/home/ubuntu/slow-query-notes.txt": "2024-03-08: orders table full scan on status column\nTried adding index on (status, created_at) but rollback due to lock wait\nWill retry during next maintenance window (Sunday 3am)\npt-online-schema-change might work -- need to test on staging first\nJordan",
    "/etc/mysql/mysql.conf.d/mysqld.cnf": "[mysqld]\npid-file        = /var/run/mysqld/mysqld.pid\nsocket          = /var/run/mysqld/mysqld.sock\ndatadir         = /var/lib/mysql\nlog-error       = /var/log/mysql/error.log\nbind-address    = 0.0.0.0\nport            = 3306\nmax_connections = 500\ninnodb_buffer_pool_size = 24G\ninnodb_log_file_size = 1G\nslow_query_log  = 1\nslow_query_log_file = /var/log/mysql/slow-query.log\nlong_query_time = 2\nserver-id       = 7\nlog-bin         = /var/log/mysql/mysql-bin",
    "/opt/backups/mysql-backup.sh": "#!/bin/bash\n# Daily MySQL backup\nset -euo pipefail\nDATE=$(date +%Y%m%d-%H%M%S)\nBACKUP_DIR=/opt/backups/daily\nmkdir -p $BACKUP_DIR\nmysqldump --single-transaction --routines --triggers \\\n  -u backup -p'bkp_s3cure_2024!' \\\n  app_production | gzip > $BACKUP_DIR/app_production-$DATE.sql.gz\nfind $BACKUP_DIR -name '*.sql.gz' -mtime +7 -delete\nrsync -az $BACKUP_DIR/ backup-nas.corp.internal:/db-backups/db-prod-07/\necho \"$(date): Backup completed successfully\" >> /var/log/mysql-backup.log",
    "/etc/hosts": "127.0.0.1\tlocalhost\n127.0.1.1\tdb-prod-07\n\n# Database cluster\n10.10.5.10\tdb-prod-07\n10.10.5.11\tdb-prod-08\n10.10.5.12\tdb-replica-01\n\n# Application servers\n10.10.3.10\tapp-server-01.corp.internal\n10.10.3.11\tapp-server-02.corp.internal\n10.10.3.12\tapp-server-03.corp.internal\n\n# Infrastructure\n10.10.8.5\tbackup-nas.corp.internal\n10.10.1.5\tbastion.corp.internal\n10.10.1.10\tmonitoring.corp.internal",
    "/opt/app/.env": "# Database credentials -- DO NOT COMMIT\nDB_HOST=localhost\nDB_PORT=3306\nDB_NAME=app_production\nDB_USER=app_svc\nDB_PASSWORD=pr0d_mysql_2024!#\nDB_REPLICA_HOST=db-replica-01\nREDIS_URL=redis://cache-prod-01.corp.internal:6379/0\nSECRET_KEY=a8f2e91b4c3d5e6f7890abcdef123456"
  }
```

### Step 7: Add Static Responses

For commands with complex output that the scripted engine or LLM might get wrong, provide exact responses.

```json
  "static_responses": {
    "uptime": " 10:37:12 up 142 days,  8:37,  1 user,  load average: 0.45, 0.38, 0.31",
    "free -h": "               total        used        free      shared  buff/cache   available\nMem:            31Gi        26Gi       1.2Gi       142Mi       4.1Gi       4.5Gi\nSwap:          4.0Gi       512Mi       3.5Gi",
    "df -h": "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda2        50G   18G   30G  38% /\ntmpfs            16G     0   16G   0% /dev/shm\n/dev/sdb1       500G  312G  163G  66% /var/lib/mysql\n/dev/sdc1       200G   78G  113G  41% /opt/backups\ntmpfs           3.2G  1.5M  3.2G   1% /run",
    "docker ps": "CONTAINER ID   IMAGE                    STATUS         PORTS     NAMES\ne7f8a9b0c1d2   percona/pmm-client:2.41  Up 30 days               pmm-client"
  }
```

### Complete Profile

Save the file as `decoys/profiles/db-server.json`. The complete profile is the combination of all the sections above in a single JSON object.

## 5. Profile Design Tips

### Match Your Target Environment

If you are deploying decoys in an AWS VPC, use hostnames like `ip-10-10-5-42` or `db-prod-07.us-east-1.compute.internal`. If your org uses CentOS, do not profile an Ubuntu system. Mirror real naming conventions, IP ranges, and architecture patterns.

### Add Realistic Artifacts

Empty home directories and blank histories are red flags. Seed these files:

- **`.bash_history`** -- 10-20 commands consistent with the user's role. A DBA should have `mysql`, `pt-query-digest`, `mysqldump`. A developer should have `git`, `npm`, `docker`.
- **`.ssh/known_hosts`** -- Include hostnames and IPs of other systems this machine would connect to. Attackers use these for lateral movement targeting.
- **`.gitconfig`** -- Name, email, and aliases consistent with the user identity.
- **Crontab entries** -- Scheduled backups, health checks, log rotation.
- **Config files** -- Application configs, database configs, systemd unit overrides.

### Include Breadcrumbs

Breadcrumbs are artifacts that entice attackers to go deeper. They generate high-value intelligence when accessed:

- **`.env` files** with database passwords, API keys, and internal URLs
- **Backup scripts** with hardcoded credentials and target hostnames
- **`/etc/hosts`** entries revealing internal network topology
- **`.ssh/config`** with shortcuts to other internal hosts
- **AWS credentials** in `~/.aws/credentials` (use HoneyToken CRs for tracking)
- **Kubeconfig** files in `~/.kube/config`

Every breadcrumb is a potential honeytoken. Pair them with `HoneyToken` CRs to get alerts when attackers use the credentials.

### Avoid Tells

Common mistakes that reveal a decoy:

- **Inconsistent versions.** If `python3 --version` says 3.10 but `pip --version` references Python 3.8, a careful attacker will notice.
- **Missing packages.** If Docker is in the services list but `which docker` returns "not found", credibility is blown.
- **Default/placeholder data.** Hostnames like `changeme`, `test-server`, or `honeypot-01` are obvious. Usernames like `user1` and passwords like `password123` are fine for login captures but should not appear in internal config files.
- **Wrong OS output format.** CentOS uses `yum` and `/etc/redhat-release`. Ubuntu uses `apt` and `/etc/lsb-release`. Do not mix them.
- **Missing uptime drift.** If `uptime` always returns the same value across multiple sessions, an attacker may notice. The narrative's uptime value feeds the LLM -- the LLM can adjust it, but `static_responses` are fixed.

### Consider These Details

- **Timezone and locale.** Set `system.timezone` to match the organization's geography. A server with UTC timestamps but an `America/New_York` timezone in `/etc/timezone` is inconsistent.
- **Uptime.** Long uptimes (60+ days) suggest a stable production server. Short uptimes (< 1 day) suggest recent maintenance or a fresh deployment.
- **Load averages.** A database server should show moderate load (0.3-0.8). A nearly-idle box (0.00, 0.01, 0.00) is suspicious for production infrastructure.
- **Disk usage.** A database server with 1% disk usage on `/var/lib/mysql` does not look real. Use 40-70% for production databases.

## 6. Testing Your Profile

### Local Testing with docker-compose

The fastest way to test a profile is with the local development stack.

**1. Place your profile file:**

```bash
cp my-profile.json decoys/profiles/
```

**2. Start the Tier 2 stack (no LLM, no API keys):**

```bash
docker compose up --build
```

**3. Connect and test:**

```bash
ssh admin@localhost -p 2222
# password: admin123
```

**4. For Tier 3 testing with LLM responses:**

```bash
docker compose --profile tier3 up --build
ssh admin@localhost -p 2223
# password: admin123
```

The first Tier 3 start downloads the Ollama model (~2GB). Subsequent starts are instant.

### What to Check

Run through this checklist inside the SSH session:

**Identity consistency:**
```bash
uname -a               # Should match system.kernel
hostname               # Should match system.hostname
cat /etc/os-release    # Should match system.os
lsb_release -a         # Should match system.os
hostnamectl             # All fields consistent
```

**User accounts:**
```bash
whoami                 # Current user
id                     # UID, groups match profile
w                      # Who is logged in
last -5                # Recent login history
```

**Installed software:**
```bash
python3 --version      # Matches software.packages
node --version         # If listed
docker --version       # If listed
git --version          # If listed
which mysql            # Should exist if MySQL is in packages
```

**Filesystem content:**
```bash
cat ~/.bash_history    # Should contain role-appropriate commands
cat /etc/hosts         # Should list internal hosts
ls /opt/backups/       # Should have expected structure
cat /opt/app/.env      # Breadcrumbs should be present
```

**Services and network:**
```bash
systemctl status mysql    # If MySQL is in services
docker ps                 # Should match static_responses
df -h                     # Should match static_responses
free -h                   # Should match static_responses
ss -tlnp                  # Should show expected ports
```

**Process list:**
```bash
ps aux                    # Should include expected services
```

### Debug Tips

- Watch the container logs (`docker compose logs -f ssh-decoy`) while interacting. The router logs which tier handled each command and whether it was an exact match, fuzzy match, template, or LLM response.
- If a command returns unexpected output, check whether it is covered by `static_responses`, the response database, the hifi engine's templates, or if it fell through to the LLM.
- For Tier 3, check the inference service logs (`docker compose logs -f inference`) to see the prompts being generated and the LLM's raw output.

## 7. Example Profiles

### Example 1: Ubuntu Dev Workstation

A junior developer's workstation with Node.js, Python, and Docker. This is the built-in `dev-workstation` profile, included here for reference.

```json
{
  "description": "Mid-level developer's Ubuntu workstation",

  "system": {
    "os": "Ubuntu 22.04.3 LTS",
    "kernel": "5.15.0-91-generic",
    "hostname": "dev-ws-03",
    "uptime": "67 days, 3:14",
    "timezone": "America/New_York",
    "locale": "en_US.UTF-8"
  },

  "users": [
    {
      "name": "admin",
      "fullName": "Alex Chen",
      "groups": ["sudo", "docker", "developers"],
      "shell": "/bin/bash",
      "lastLogin": "2024-01-18 09:32:01",
      "uid": 1000,
      "home": "/home/admin"
    },
    {
      "name": "deploy",
      "fullName": "Deploy Service",
      "groups": ["docker"],
      "shell": "/bin/bash",
      "lastLogin": "2024-01-17 03:00:00",
      "uid": 1001,
      "home": "/home/deploy"
    }
  ],

  "software": {
    "packages": [
      {"name": "openssh-server", "version": "8.9p1"},
      {"name": "docker-ce",      "version": "24.0.7"},
      {"name": "nodejs",         "version": "18.19.0"},
      {"name": "python3",        "version": "3.10.12"},
      {"name": "git",            "version": "2.34.1"},
      {"name": "vim",            "version": "8.2.4919"},
      {"name": "tmux",           "version": "3.2a"},
      {"name": "curl",           "version": "7.81.0"},
      {"name": "jq",             "version": "1.6"}
    ],
    "services": [
      {"name": "sshd",     "status": "active", "port": 22},
      {"name": "docker",   "status": "active"},
      {"name": "cron",     "status": "active"},
      {"name": "node-app", "status": "active", "port": 3000}
    ]
  },

  "environment": {
    "variables": {
      "NODE_ENV": "production",
      "DOCKER_HOST": "unix:///var/run/docker.sock"
    },
    "crontab": [
      "0 3 * * * /home/deploy/scripts/backup.sh >> /var/log/backup.log 2>&1",
      "*/5 * * * * /opt/app/healthcheck.sh"
    ]
  },

  "narrative": "This is a developer workstation used by Alex Chen, a mid-level engineer on the platform team. The machine runs a Node.js application that serves an internal dashboard on port 3000. Alex uses Docker for local development and testing. There are project repos in /home/admin/projects/ including a main web application. The deploy user runs automated backups and health checks via cron. Python 3.10 is installed for utility scripts. The machine has been running stably for about 67 days since the last system update. There is a .env file in /opt/app/ with database credentials, and deployment scripts in /home/deploy/scripts/.",

  "filesystem_extras": {
    "/home/admin/.bash_history": "docker ps\ngit log --oneline -10\nnpm run build\ncurl -s http://localhost:3000/health\nvim /opt/app/config.json\nhtop\ndf -h\nssh deploy@build-server.internal\ntmux attach\ngit pull origin main",
    "/home/admin/.gitconfig": "[user]\n    name = Alex Chen\n    email = achen@corp.internal\n[core]\n    editor = vim\n[alias]\n    st = status\n    co = checkout\n    br = branch",
    "/opt/app/config.json": "{\n  \"port\": 3000,\n  \"database\": {\n    \"host\": \"db-prod.corp.internal\",\n    \"port\": 5432,\n    \"name\": \"app_production\",\n    \"user\": \"app_svc\",\n    \"password\": \"Pr0d_DB_s3cret!\"\n  },\n  \"redis\": {\n    \"host\": \"redis-prod.corp.internal\",\n    \"port\": 6379\n  },\n  \"logLevel\": \"info\"\n}",
    "/opt/app/package.json": "{\n  \"name\": \"internal-dashboard\",\n  \"version\": \"2.4.1\",\n  \"scripts\": {\n    \"start\": \"node server.js\",\n    \"build\": \"webpack --mode production\",\n    \"test\": \"jest\"\n  }\n}",
    "/home/deploy/scripts/backup.sh": "#!/bin/bash\nDATE=$(date +%Y%m%d)\npg_dump -h db-prod.corp.internal -U app_svc app_production | gzip > /var/backups/db-$DATE.sql.gz\nfind /var/backups -name '*.sql.gz' -mtime +7 -delete\necho \"Backup completed: $DATE\"",
    "/etc/hosts": "127.0.0.1\tlocalhost\n127.0.1.1\tdev-ws-03\n\n# Internal hosts\n10.0.1.10\tdb-prod.corp.internal\n10.0.1.20\tredis-prod.corp.internal\n10.0.2.5\tbuild-server.internal\n10.0.2.10\tgitlab.corp.internal"
  },

  "static_responses": {
    "uptime": " 09:14:22 up 67 days,  3:14,  1 user,  load average: 0.12, 0.08, 0.03",
    "free -h": "               total        used        free      shared  buff/cache   available\nMem:           15Gi       4.2Gi       6.8Gi       312Mi       4.5Gi        10Gi\nSwap:          2.0Gi          0B       2.0Gi",
    "df -h": "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        80G   34G   42G  45% /\ntmpfs           7.8G     0  7.8G   0% /dev/shm\n/dev/sda2       200G   67G  123G  36% /opt\ntmpfs           1.6G  1.2M  1.6G   1% /run",
    "docker ps": "CONTAINER ID   IMAGE                         STATUS          PORTS                    NAMES\na1b2c3d4e5f6   internal-dashboard:2.4.1      Up 12 days      0.0.0.0:3000->3000/tcp   app\nf6e5d4c3b2a1   redis:7-alpine                Up 12 days      6379/tcp                 app-redis"
  }
}
```

### Example 2: CentOS/RHEL Database Server

A production MySQL server on RHEL 8, typical of enterprise environments.

```json
{
  "description": "RHEL 8 production MySQL database server",

  "system": {
    "os": "Red Hat Enterprise Linux 8.9 (Ootpa)",
    "kernel": "4.18.0-513.11.1.el8_9.x86_64",
    "hostname": "db-prod-07",
    "uptime": "203 days, 14:22",
    "timezone": "America/Chicago",
    "locale": "en_US.UTF-8"
  },

  "users": [
    {
      "name": "root",
      "fullName": "root",
      "groups": ["root"],
      "shell": "/bin/bash",
      "uid": 0,
      "home": "/root",
      "lastLogin": "2024-02-28 22:10:00"
    },
    {
      "name": "jpark",
      "fullName": "Jordan Park",
      "groups": ["wheel", "dba", "docker"],
      "shell": "/bin/bash",
      "uid": 1000,
      "home": "/home/jpark",
      "lastLogin": "2024-03-12 09:15:44"
    },
    {
      "name": "mysql",
      "fullName": "MySQL Server",
      "groups": ["mysql"],
      "shell": "/sbin/nologin",
      "uid": 27,
      "home": "/var/lib/mysql"
    },
    {
      "name": "deploy",
      "fullName": "Ansible Deploy",
      "groups": ["deploy", "docker"],
      "shell": "/bin/bash",
      "uid": 1001,
      "home": "/home/deploy",
      "lastLogin": "2024-03-12 03:00:01"
    }
  ],

  "software": {
    "packages": [
      {"name": "openssh-server",            "version": "8.0p1-19.el8"},
      {"name": "mysql-community-server",    "version": "8.0.36"},
      {"name": "mysql-community-client",    "version": "8.0.36"},
      {"name": "python38",                  "version": "3.8.17"},
      {"name": "docker-ce",                 "version": "25.0.3"},
      {"name": "git",                       "version": "2.39.3"},
      {"name": "vim-enhanced",              "version": "8.0.1763"},
      {"name": "percona-toolkit",           "version": "3.5.7"},
      {"name": "node_exporter",             "version": "1.7.0"},
      {"name": "ansible",                   "version": "2.14.14"},
      {"name": "rsync",                     "version": "3.1.3"}
    ],
    "services": [
      {"name": "sshd",          "status": "active", "port": 22},
      {"name": "mysqld",        "status": "active", "port": 3306},
      {"name": "node_exporter", "status": "active", "port": 9100},
      {"name": "crond",         "status": "active"},
      {"name": "docker",        "status": "active"},
      {"name": "firewalld",     "status": "active"}
    ]
  },

  "environment": {
    "variables": {
      "MYSQL_HOME": "/etc/my.cnf.d",
      "ANSIBLE_INVENTORY": "/etc/ansible/hosts",
      "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    },
    "crontab": [
      "0 2 * * * /opt/dba/scripts/mysql-backup.sh >> /var/log/mysql-backup.log 2>&1",
      "0 4 * * 0 /opt/dba/scripts/full-backup.sh >> /var/log/full-backup.log 2>&1",
      "*/5 * * * * /usr/local/bin/mysql-healthcheck.sh",
      "0 6 * * 1 /opt/dba/scripts/analyze-slow-queries.sh"
    ]
  },

  "narrative": "This is a production MySQL 8.0 database server in the Chicago data center, managed by Jordan Park (DBA, username jpark). It hosts the primary transactional database for the e-commerce platform (ecommerce_prod, ~180GB) and a smaller analytics database (analytics_staging, ~40GB). The server has 64GB RAM with innodb_buffer_pool_size at 48G. Jordan connects from the bastion host (bastion-chi.corp.internal) and uses Percona Toolkit for query analysis. Automated schema migrations are run by the deploy user via Ansible playbooks from the CI/CD server (ci-runner-01.corp.internal). Backups run nightly via mysqldump and are rsynced to the NAS at backup-nas-chi.corp.internal. The server was last patched 203 days ago -- there is an open JIRA ticket (DBA-1847) to schedule the RHEL 8.10 upgrade during the next maintenance window. Docker is installed for running the Percona PMM monitoring agent. Firewalld is active and only allows SSH from the bastion subnet (10.10.1.0/24) and MySQL from the application subnet (10.10.3.0/24).",

  "filesystem_extras": {
    "/home/jpark/.bash_history": "mysql -u root -p\nshow processlist;\nSELECT table_name, data_length/1024/1024 AS size_mb FROM information_schema.tables WHERE table_schema='ecommerce_prod' ORDER BY data_length DESC LIMIT 20;\npt-query-digest /var/log/mysql/slow-query.log --since '2024-03-11'\nsudo systemctl status mysqld\ndf -h\nfree -h\ndocker logs pmm-client --tail 50\nssh deploy@ci-runner-01.corp.internal\nsudo tail -100 /var/log/mysql/error.log\nsudo firewall-cmd --list-all\ncat /opt/dba/scripts/mysql-backup.sh\nansible-playbook -i /etc/ansible/hosts /opt/dba/playbooks/check-replication.yml",
    "/home/jpark/.ssh/config": "Host bastion\n    HostName bastion-chi.corp.internal\n    User jpark\n\nHost app-*\n    ProxyJump bastion\n    User deploy\n\nHost ci-runner\n    HostName ci-runner-01.corp.internal\n    User jpark",
    "/home/jpark/.ssh/known_hosts": "bastion-chi.corp.internal,10.10.1.5 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTY...\nci-runner-01.corp.internal,10.10.2.20 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTY...\nbackup-nas-chi.corp.internal,10.10.8.10 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTY...",
    "/etc/my.cnf.d/server.cnf": "[mysqld]\ndatadir=/var/lib/mysql\nsocket=/var/lib/mysql/mysql.sock\nlog-error=/var/log/mysql/error.log\npid-file=/var/run/mysqld/mysqld.pid\nport=3306\nbind-address=0.0.0.0\nmax_connections=1000\ninnodb_buffer_pool_size=48G\ninnodb_buffer_pool_instances=8\ninnodb_log_file_size=2G\ninnodb_flush_log_at_trx_commit=1\nslow_query_log=1\nslow_query_log_file=/var/log/mysql/slow-query.log\nlong_query_time=1\nserver-id=7\nlog-bin=/var/log/mysql/mysql-bin\ngtid_mode=ON\nenforce_gtid_consistency=ON",
    "/opt/dba/scripts/mysql-backup.sh": "#!/bin/bash\nset -euo pipefail\nDATE=$(date +%Y%m%d-%H%M%S)\nBACKUP_DIR=/opt/backups/mysql/daily\nmkdir -p $BACKUP_DIR\nfor DB in ecommerce_prod analytics_staging; do\n  mysqldump --single-transaction --routines --triggers --events \\\n    -u backup -p'Bkp_S3cure_Pr0d!' \\\n    $DB | gzip > $BACKUP_DIR/${DB}-${DATE}.sql.gz\ndone\nfind $BACKUP_DIR -name '*.sql.gz' -mtime +7 -delete\nrsync -az $BACKUP_DIR/ backup-nas-chi.corp.internal:/db-backups/db-prod-07/daily/\necho \"$(date): Backup completed\" >> /var/log/mysql-backup.log",
    "/etc/hosts": "127.0.0.1   localhost localhost.localdomain\n::1         localhost localhost.localdomain\n10.10.5.10  db-prod-07\n10.10.5.11  db-prod-08\n10.10.5.15  db-replica-01\n10.10.5.16  db-replica-02\n10.10.1.5   bastion-chi.corp.internal\n10.10.2.20  ci-runner-01.corp.internal\n10.10.3.10  app-server-01.corp.internal\n10.10.3.11  app-server-02.corp.internal\n10.10.3.12  app-server-03.corp.internal\n10.10.8.10  backup-nas-chi.corp.internal\n10.10.1.10  monitoring.corp.internal",
    "/etc/redhat-release": "Red Hat Enterprise Linux release 8.9 (Ootpa)",
    "/home/deploy/.my.cnf": "[client]\nuser=deploy_svc\npassword=d3pl0y_Pr0d_2024!\nhost=localhost"
  },

  "static_responses": {
    "uptime": " 09:15:44 up 203 days, 14:22,  1 user,  load average: 0.52, 0.41, 0.38",
    "free -h": "              total        used        free      shared  buff/cache   available\nMem:           62Gi        51Gi       1.8Gi       245Mi       9.4Gi        10Gi\nSwap:         8.0Gi       1.2Gi       6.8Gi",
    "df -h": "Filesystem           Size  Used Avail Use% Mounted on\n/dev/sda2             50G   22G   26G  46% /\ndevtmpfs              32G     0   32G   0% /dev\ntmpfs                 32G     0   32G   0% /dev/shm\n/dev/sdb1            500G  312G  163G  66% /var/lib/mysql\n/dev/sdc1            200G   89G  102G  47% /opt/backups\ntmpfs                6.3G  1.8M  6.3G   1% /run",
    "docker ps": "CONTAINER ID   IMAGE                    STATUS         PORTS     NAMES\ne7f8a9b0c1d2   percona/pmm-client:2.41  Up 45 days               pmm-client",
    "cat /etc/redhat-release": "Red Hat Enterprise Linux release 8.9 (Ootpa)"
  }
}
```

### Example 3: AWS EC2 Jump Box

A bastion/jump host in an AWS VPC, used by operations engineers to access internal infrastructure.

```json
{
  "description": "AWS EC2 bastion host / jump box",

  "system": {
    "os": "Amazon Linux 2023",
    "kernel": "6.1.77-99.164.amzn2023.x86_64",
    "hostname": "bastion-prod-use1",
    "uptime": "34 days, 7:51",
    "timezone": "UTC",
    "locale": "en_US.UTF-8"
  },

  "users": [
    {
      "name": "ec2-user",
      "fullName": "EC2 Default User",
      "groups": ["wheel", "docker", "adm"],
      "shell": "/bin/bash",
      "uid": 1000,
      "home": "/home/ec2-user",
      "lastLogin": "2024-03-12 14:22:10"
    },
    {
      "name": "ssm-user",
      "fullName": "SSM Session Manager",
      "groups": [],
      "shell": "/bin/bash",
      "uid": 1001,
      "home": "/home/ssm-user",
      "lastLogin": "2024-03-11 18:05:33"
    },
    {
      "name": "ops-mwilson",
      "fullName": "Morgan Wilson",
      "groups": ["wheel", "ops"],
      "shell": "/bin/bash",
      "uid": 1100,
      "home": "/home/ops-mwilson",
      "lastLogin": "2024-03-12 10:15:00"
    }
  ],

  "software": {
    "packages": [
      {"name": "openssh-server",   "version": "8.7p1"},
      {"name": "aws-cli",          "version": "2.15.17"},
      {"name": "python3",          "version": "3.11.6"},
      {"name": "docker",           "version": "24.0.5"},
      {"name": "git",              "version": "2.40.1"},
      {"name": "tmux",             "version": "3.3a"},
      {"name": "jq",               "version": "1.7"},
      {"name": "kubectl",          "version": "1.28.4"},
      {"name": "helm",             "version": "3.14.0"},
      {"name": "session-manager-plugin", "version": "1.2.553.0"},
      {"name": "amazon-ssm-agent",      "version": "3.2.2222.0"}
    ],
    "services": [
      {"name": "sshd",         "status": "active", "port": 22},
      {"name": "amazon-ssm-agent", "status": "active"},
      {"name": "docker",       "status": "active"},
      {"name": "crond",        "status": "active"},
      {"name": "chronyd",      "status": "active"}
    ]
  },

  "environment": {
    "variables": {
      "AWS_DEFAULT_REGION": "us-east-1",
      "AWS_PROFILE": "prod",
      "KUBECONFIG": "/home/ec2-user/.kube/config",
      "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/aws-cli/v2/current/bin"
    },
    "crontab": [
      "0 */6 * * * /usr/local/bin/rotate-ssh-keys.sh",
      "*/10 * * * * /usr/local/bin/session-audit.sh >> /var/log/session-audit.log 2>&1"
    ]
  },

  "narrative": "This is the primary bastion host (jump box) for the production AWS environment in us-east-1. Operations engineers SSH into this machine to access internal resources: RDS databases, EKS clusters, and EC2 instances on private subnets. The machine is an m5.large instance behind an NLB in the public subnet (10.0.1.0/24). It has security group rules allowing SSH (port 22) from the corporate VPN CIDR (203.0.113.0/24) only. Morgan Wilson (SRE lead, username ops-mwilson) uses this box daily to manage the production EKS cluster via kubectl and to tunnel to RDS instances. The ec2-user account has AWS CLI configured with a prod profile that assumes an IAM role for read-only access to production resources. SSM Session Manager is installed as an alternative access path. There are SSH tunneling scripts in /usr/local/bin/ for connecting to the RDS PostgreSQL instances (db-prod-1.cluster-xyz.us-east-1.rds.amazonaws.com). Docker is installed for running one-off administrative containers. SSH keys are rotated every 6 hours by a cron job.",

  "filesystem_extras": {
    "/home/ec2-user/.bash_history": "aws sts get-caller-identity\nkubectl get pods -n production\nkubectl logs -f deploy/api-server -n production --tail=100\naws rds describe-db-instances --query 'DBInstances[*].[DBInstanceIdentifier,Endpoint.Address]' --output table\nssh -L 5432:db-prod-1.cluster-xyz.us-east-1.rds.amazonaws.com:5432 localhost\naws ec2 describe-instances --filters 'Name=tag:Environment,Values=production' --query 'Reservations[*].Instances[*].[InstanceId,PrivateIpAddress,Tags[?Key==`Name`].Value|[0]]' --output table\nhelm list -A\ndocker run --rm -it postgres:16 psql -h localhost -U app_ro -d ecommerce\ntmux attach -t ops\naws s3 ls s3://acme-prod-artifacts/\nkubectl get nodes",
    "/home/ec2-user/.aws/credentials": "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n\n[prod]\nrole_arn = arn:aws:iam::123456789012:role/ProductionReadOnly\nsource_profile = default\nregion = us-east-1",
    "/home/ec2-user/.aws/config": "[default]\nregion = us-east-1\noutput = json\n\n[profile prod]\nrole_arn = arn:aws:iam::123456789012:role/ProductionReadOnly\nsource_profile = default\nregion = us-east-1\noutput = json\n\n[profile staging]\nrole_arn = arn:aws:iam::123456789012:role/StagingAdmin\nsource_profile = default\nregion = us-east-1",
    "/home/ec2-user/.kube/config": "apiVersion: v1\nclusters:\n- cluster:\n    certificate-authority-data: LS0tLS1CRUdJTi...(truncated)\n    server: https://ABC123DEF456.gr7.us-east-1.eks.amazonaws.com\n  name: arn:aws:eks:us-east-1:123456789012:cluster/prod-cluster\ncontexts:\n- context:\n    cluster: arn:aws:eks:us-east-1:123456789012:cluster/prod-cluster\n    namespace: production\n    user: arn:aws:eks:us-east-1:123456789012:cluster/prod-cluster\n  name: prod\ncurrent-context: prod\nkind: Config\npreferences: {}\nusers:\n- name: arn:aws:eks:us-east-1:123456789012:cluster/prod-cluster\n  user:\n    exec:\n      apiVersion: client.authentication.k8s.io/v1beta1\n      command: aws\n      args:\n        - eks\n        - get-token\n        - --cluster-name\n        - prod-cluster\n        - --region\n        - us-east-1",
    "/home/ec2-user/.ssh/config": "Host db-tunnel\n    HostName 10.0.4.10\n    User ec2-user\n    LocalForward 5432 db-prod-1.cluster-xyz.us-east-1.rds.amazonaws.com:5432\n    LocalForward 5433 db-prod-2.cluster-xyz.us-east-1.rds.amazonaws.com:5432\n\nHost app-*\n    User ec2-user\n    StrictHostKeyChecking no\n    IdentityFile ~/.ssh/ops-prod.pem\n\nHost *.internal\n    User ec2-user\n    ProxyCommand aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters portNumber=%p",
    "/home/ops-mwilson/.bash_history": "kubectl get pods -n production -o wide\nkubectl describe pod api-server-7d8f9c6b5d-xk2p4 -n production\nkubectl rollout restart deploy/api-server -n production\naws logs tail /ecs/prod-api --since 1h --follow\nhelm upgrade api-server ./charts/api-server -n production -f values-prod.yaml\nssh -L 5432:db-prod-1.cluster-xyz.us-east-1.rds.amazonaws.com:5432 db-tunnel\naws ec2 describe-security-groups --group-ids sg-0123456789abcdef0\ncurl -s http://10.0.3.50:8080/health | jq .\ntmux new -s deploy",
    "/etc/hosts": "127.0.0.1   localhost localhost.localdomain\n::1         localhost localhost.localdomain\n\n# Managed by EC2\n10.0.1.42   bastion-prod-use1",
    "/usr/local/bin/rotate-ssh-keys.sh": "#!/bin/bash\n# Rotate SSH authorized_keys from Parameter Store\naws ssm get-parameter --name /ops/ssh-authorized-keys \\\n  --with-decryption --query 'Parameter.Value' \\\n  --output text > /home/ec2-user/.ssh/authorized_keys\nchmod 600 /home/ec2-user/.ssh/authorized_keys\nchown ec2-user:ec2-user /home/ec2-user/.ssh/authorized_keys\nlogger \"SSH keys rotated from Parameter Store\""
  },

  "static_responses": {
    "uptime": " 14:22:10 up 34 days,  7:51,  2 users,  load average: 0.08, 0.05, 0.02",
    "free -h": "               total        used        free      shared  buff/cache   available\nMem:           7.7Gi       1.2Gi       4.1Gi        12Mi       2.4Gi       6.2Gi\nSwap:            0B          0B          0B",
    "df -h": "Filesystem      Size  Used Avail Use% Mounted on\n/dev/xvda1       30G  8.2G   22G  28% /\ndevtmpfs        3.9G     0  3.9G   0% /dev\ntmpfs           3.9G     0  3.9G   0% /dev/shm\ntmpfs           3.9G  456K  3.9G   1% /run",
    "docker ps": "CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS    PORTS     NAMES",
    "curl -s http://169.254.169.254/latest/meta-data/instance-id": "i-0a1b2c3d4e5f67890",
    "curl -s http://169.254.169.254/latest/meta-data/instance-type": "m5.large",
    "curl -s http://169.254.169.254/latest/meta-data/local-ipv4": "10.0.1.42",
    "curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone": "us-east-1a",
    "aws sts get-caller-identity": "{\n    \"UserId\": \"AIDAIOSFODNN7EXAMPLE\",\n    \"Account\": \"123456789012\",\n    \"Arn\": \"arn:aws:iam::123456789012:user/ops-bastion\"\n}"
  }
}
```

## Connecting Profiles to Decoy Manifests

Profiles are referenced from Decoy custom resources via `spec.identity.profileRef`:

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: Decoy
metadata:
  name: db-prod-07
  labels:
    cicdecoy.io/tier: "3"
    cicdecoy.io/zone: "database"
spec:
  service:
    type: ssh
    port: 22
  fidelity:
    tier: 3
    adaptive:
      model: "llama3.2:3b"
  identity:
    hostname: db-prod-07
    profileRef: "db-server"        # matches decoys/profiles/db-server.json
  authentication:
    mode: selective
    allowCredentials:
      - username: jpark
        password: "W1nt3r2024!"
    captureAll: true
```

For fleet deployments, profiles can be assigned from a pool:

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: DecoyFleet
metadata:
  name: database-subnet
spec:
  count: 5
  templateRef: "ssh-server"
  zones: ["database"]
  parameterOverrides:
    profiles:
      pool: ["db-server", "db-replica", "db-staging"]
```

## Response Database Files

Profiles work together with response database files (`decoys/responses/*.json`). While `static_responses` in the profile handle a handful of commands, response databases provide the bulk of scripted output (50+ commands). They are loaded by the high-fidelity engine and support the same `{{HOSTNAME}}`, `{{USERNAME}}`, etc. substitution tokens.

Response database format:

```json
{
  "meta": {
    "profile": "db-server",
    "os": "RHEL 8.9",
    "captured": "2024-03-12T10:00:00Z"
  },
  "responses": {
    "command string": {
      "output": "exact output",
      "exit_code": 0
    }
  }
}
```

The `meta` block is informational. Only the `responses` map is used at runtime. You can capture responses from a real system to build the database, then pair it with a profile for Tier 3 coverage.
