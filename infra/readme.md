# 🛡️ Honeypot SOC Lab v2

**A multi-sensor deception network with a full detection-as-code pipeline, built entirely on Azure's free tier and deployed via GitHub Actions.**

No manual clicks in the portal. Every VM, network rule, data pipeline, detection, and dashboard in this lab is defined in Bicep and deployed automatically on push to `main`.

---

## Overview

This project stands up three internet-facing honeypots inside an isolated Azure environment, streams everything they see into Microsoft Sentinel, and turns that raw telemetry into scheduled detections and a live dashboard — all through infrastructure-as-code.

Within hours of going live, the lab was already logging real, unsolicited attack traffic from the open internet: SSH credential-stuffing attempts, RDP scans, and automated vulnerability scanners probing for PHPUnit RCE exploits and exposed `.env` files.

```
                    ┌──────────────────────────────┐
  Public Internet ──▶  Windows Decoy (RDP + Sysmon) │──┐
                    └──────────────────────────────┘  │
                    ┌──────────────────────────────┐  │      ┌───────────────────────┐
  Public Internet ──▶  Linux Decoy (Cowrie SSH)     │──┼─────▶  Log Analytics         │
                    └──────────────────────────────┘  │      │  Workspace             │
                    ┌──────────────────────────────┐  │      └───────────┬───────────┘
  Public Internet ──▶  Web App Decoy (Flask)        │──┘                  │
                    └──────────────────────────────┘                     ▼
                                                              ┌───────────────────────┐
                                                              │  Microsoft Sentinel    │
                                                              │  • Scheduled alerts    │
                                                              │  • Workbook dashboard  │
                                                              │  • SOAR playbook       │
                                                              └───────────────────────┘
```

## Decoys

| Decoy | Exposed Service | Capture Method | What It Logs |
|---|---|---|---|
| **Windows Server** | RDP (3389) | Sysmon + Windows Security Event Log | Process creation, network connections, file writes, DNS queries, logon attempts (4624/4625/4688) |
| **Linux (Cowrie)** | SSH (22) | [Cowrie](https://github.com/cowrie/cowrie) medium-interaction honeypot | Full session recording, credentials tried, commands executed, files dropped |
| **Web App (Flask)** | HTTP (80) | Custom fake endpoints with honeytokens | Requests to `/wp-login.php`, `/.env`, `/admin`, and any unmatched path, including submitted form data |

Each decoy runs in its own isolated subnet with an NSG that allows only its own service inbound and denies all outbound traffic to the internet by default — a compromised decoy can't be used to attack anything else.

## Data Pipeline

Every decoy ships its logs into a shared **Log Analytics workspace** via the **Azure Monitor Agent**:

- Windows Security and Sysmon events flow through a native **Data Collection Rule** (`windows-dcr.bicep`) using built-in `SecurityEvent` and `Event` tables.
- Cowrie and the web app decoy write structured JSON to disk, which is tailed by AMA and ingested into dedicated **custom log tables** (`Cowrie_CL`, `WebDecoy_CL`) via their own DCRs.

## Detections

Three scheduled analytics rules run continuously against the ingested data:

| Rule | Logic | Window |
|---|---|---|
| **Cowrie SSH Brute Force** | ≥6 failed logins from one IP | 24 hours (catches both rapid and slow/evasive attackers) |
| **Windows RDP Brute Force** | ≥5 failed logins (Event 4625) from one IP | 5 minutes |
| **Web Decoy Path Scanning** | ≥3 honeytoken paths probed by one IP | 10 minutes |

Detections were tuned against real attacker behavior observed in the lab — the Cowrie rule's 24-hour window exists because live traffic showed at least one bot deliberately spacing login attempts roughly an hour apart to evade tighter rate-limit detection.

## Dashboard & Automation

- **Sentinel Workbook** — visual summary of incidents by severity, incidents over time, top attacking IPs across all three decoys, and a MITRE ATT&CK tactics breakdown.
- **IR Playbook** — automated response workflow triggered on incident creation.

## Tech Stack

- **Infrastructure as Code:** Bicep
- **CI/CD:** GitHub Actions (`azure/arm-deploy`)
- **Compute:** Azure VMs (Windows Server, Ubuntu)
- **Detection & SIEM:** Microsoft Sentinel, Log Analytics
- **Honeypot software:** [Cowrie](https://github.com/cowrie/cowrie), [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) ([SwiftOnSecurity config](https://github.com/SwiftOnSecurity/sysmon-config)), Flask

## Repository Structure

```
infra/
├── main.bicep                          # Entry point — subscription-scope deployment
├── resources.bicep                     # Core orchestration — networking, workspace, Sentinel, all decoys
├── windows-decoy.bicep                 # Windows VM + Sysmon install + AMA
├── windows-dcr.bicep                   # Data Collection Rule: Security + Sysmon events
├── install-sysmon.ps1                  # Sysmon installation script (run via Custom Script Extension)
├── linux-ssh-decoy.bicep               # Linux VM + Cowrie + AMA
├── cowrie-dcr.bicep / cowrie-table.bicep
├── cloud-init-cowrie.yaml              # Cowrie installation & configuration
├── web-app-decoy.bicep                 # Web decoy VM + Flask app + AMA
├── web-decoy-network.bicep             # Isolated VNet/NSG for the web decoy
├── webdecoy-dcr.bicep / webdecoy-table.bicep
├── cloud-init-webdecoy.yaml            # Flask decoy app + systemd service
├── analytics-rule-*.bicep              # Scheduled detection rules
├── sentinel-workbook.bicep             # Dashboard definition
└── ir-playbook.bicep                   # Automated incident response
```

## Deployment

Every push to `main` under `infra/**` triggers `.github/workflows/deploy-infra.yml`, which:

1. Authenticates to Azure
2. Generates a parameters file from GitHub Secrets (admin credentials, SSH key)
3. Deploys `main.bicep` at subscription scope via `azure/arm-deploy`

Required secrets: `AZURE_CREDENTIALS`, `AZURE_SUBSCRIPTION_ID`, `VM_ADMIN_PASSWORD`, `VM_SSH_PUBLIC_KEY`.

## Findings

Live traffic captured during operation includes:

- Credential-stuffing attempts against SSH from multiple international source IPs
- RDP network scans from unsolicited sources
- Automated exploitation attempts targeting PHPUnit's `eval-stdin.php` remote code execution vector
- Path traversal probes (`cgi-bin/../../../bin/sh`)
- Reconnaissance for exposed `.env` files, WordPress admin panels, and Docker sockets (`/containers/json`)

## Security Notes

- All decoys are intentionally exposed to the public internet — this is the point.
- Outbound traffic is denied by default at the NSG level to prevent lateral movement or use as an attack platform.
- Credentials are never committed to source; all secrets are injected at deploy time via GitHub Actions.
- This lab is for research, learning, and demonstration purposes only.

---

*Built as a hands-on exercise in detection engineering, infrastructure-as-code, and SOC tooling.*
