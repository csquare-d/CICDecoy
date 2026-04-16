# Security Policy

CI/CDecoy is a deception and honeypot framework. By design, it exposes fake services, simulated vulnerabilities, and intentional credentials to attract, divert, and/or study adversaries. This makes vulnerability reporting more nuanced than in typical software projects. Please read this document carefully before submitting a report.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x (pre-release) | Yes |

As a pre-release project, security fixes are applied to the latest development branch only.

## What Counts as a Vulnerability

Because CI/CDecoy intentionally mimics vulnerable systems, the line between "feature" and "bug" requires careful distinction.

### In Scope (report these)

- **Container escape** -- an attacker interacting with a decoy gains access to the underlying host or other containers
- **Real credential or secret exposure** -- the framework leaks actual operator credentials, API keys, database DSNs, or infrastructure details (not the intentional honeypot credentials defined in decoy manifests)
- **Response filter bypass** -- an attacker can cause a Tier 3 (LLM-backed) decoy to reveal that it is a honeypot, expose internal service names (e.g., `inference-gateway`, `/opt/cicdecoy`), or leak NATS/database connection strings
- **Operator interface bypass** -- unauthorized access to the dashboard, CTI pipeline, operator API, or any control-plane component
- **Host filesystem access** -- the virtual filesystem abstraction is broken and real host paths are readable or writable from within a decoy session
- **Cross-session data leakage** -- one attacker session can read data (commands, filesystem mutations, environment) from another session
- **Privilege escalation in the control plane** -- gaining elevated access to Kubernetes resources, NATS streams, or TimescaleDB beyond what the component's service account permits
- **Dependency vulnerabilities** -- known CVEs in project dependencies that are reachable and exploitable in CI/CDecoy's usage

### Out of Scope (do not report these)

- **Intentional honeypot credentials** -- passwords like `admin123` or `W3lcome2024!` in decoy manifests and example configurations are deliberate lures, not vulnerabilities
- **Simulated vulnerable services** -- decoys are designed to appear exploitable; successfully "exploiting" a decoy is the intended behavior
- **Fake data exposure** -- honeytoken files, canary AWS keys, fake database dumps, and seeded data within decoys exist to be found
- **Bandit/SAST warnings on honeypot code** -- static analysis findings related to intentional credential handling (ruff S105/S106 suppressions) are expected

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, use one of the following methods:

1. **GitHub Security Advisories (preferred)** -- navigate to the repository's Security tab and select "Report a vulnerability" to open a private advisory draft.
2. **Email** -- send details to **hello@cicdecoy.systems**. Use the subject line `[SECURITY] Brief description`. If you need to share sensitive details, request a PGP key in your initial email.

### What to Include

- Affected component (e.g., ssh-decoy, inference gateway, CTI pipeline, operator)
- Description of the vulnerability and its impact
- Steps to reproduce, including any relevant configuration
- Whether you believe this is exploitable in a default deployment

## Response Timeline

| Stage | Target |
|-------|--------|
| Acknowledgment of report | 48 hours |
| Initial triage and severity assessment | 5 business days |
| Fix development and testing | Depends on severity |
| Public disclosure (coordinated with reporter) | 90 days maximum |

We will keep you informed of progress throughout the process.

## Recognition

We credit all confirmed vulnerability reporters in the release notes and CHANGELOG (unless you prefer to remain anonymous). Let us know your preferred name and any affiliation when you submit your report.

## Questions

If you are unsure whether something qualifies as a vulnerability in a honeypot context, feel free to reach out via email at hello@cicdecoy.systems or open a regular GitHub issue tagged `question`. We are happy to clarify scope before you invest time in a full report.
