# Honeypot-SOC_Lab.V2

A fully infrastructure-as-code Azure honeypot and SOC detection lab, built to practice real-world security operations: decoy systems attract real internet attackers, and a Microsoft Sentinel-backed pipeline detects, enriches, and responds to that activity — end to end, with nothing deployed by hand in the Azure portal.

## Overview

This project stands up three decoy systems exposed to the public internet, feeds their activity into Microsoft Sentinel, and layers native analytics rules, threat intelligence enrichment, and automated incident response on top. Every component — networking, compute, logging, detections, dashboards, and automation — is defined in Bicep and deployed via GitHub Actions on every push to `main`.

**Decoys:**
- **Windows RDP decoy** — exposes ports 3389/445, Sysmon-instrumented, logs Security and Sysmon events (process creation, network connections, file creation)
- **Linux SSH decoy** — runs Cowrie, a medium-interaction SSH honeypot that logs brute-force attempts, shell interaction, and captured payloads
- **Web app decoy** — mimics common vulnerable paths (`/wp-login.php`, `.env`, `/admin`) using honeytokens to catch reconnaissance and scanning

**Detection & response pipeline:**
- Native Microsoft Sentinel analytics rules (not legacy Azure Monitor alerts) for brute-force and scanning detection, each mapped to MITRE ATT&CK tactics and techniques
- Pipeline health monitoring — dedicated rules that alert if a decoy stops sending logs, independent of attack-detection logic
- Microsoft Threat Intelligence connector cross-referencing attacker IPs against known indicators
- A Sentinel workbook dashboard with a MITRE technique heat map, attack geometry map, and top-attacker breakdowns
- An automated SOAR playbook (Logic Apps, managed-identity authenticated) that enriches and comments on every new incident
- A library of KQL hunting queries for manual threat hunting across all three decoys

## Repository structure

```
├── infra/                  # Bicep IaC — networking, VMs, DCRs, Sentinel, analytics rules, playbook
├── detections/              # Detection logic documentation and YAML definitions
├── Hunting_queries/          # KQL queries for proactive threat hunting
├── scripts/                # Remediation and recovery scripts for decoy VMs
└── .github/workflows/        # CI/CD pipeline — deploys infra/ on every push to main
```

Each subfolder has its own README with further detail.

## Architecture

All decoys sit in an isolated VNet with no peering. The NSG allows only the specific inbound ports each decoy needs (3389, 445, 22, 80) and denies all outbound internet traffic by default — decoys can talk to Azure Monitor, Azure AD, Storage, and ARM, but nothing else, so a compromised decoy can't be used to attack other systems. Logs flow through Data Collection Rules into a capped Log Analytics workspace (1 GB/day), which feeds Microsoft Sentinel.

## Deployment

Deployment is fully automated via GitHub Actions — pushing to `main` with changes under `infra/` triggers the pipeline.

### Required GitHub secrets

| Secret | Description |
|---|---|
| `AZURE_CREDENTIALS` | Service principal credentials for OIDC login |
| `AZURE_SUBSCRIPTION_ID` | Target Azure subscription |
| `VM_ADMIN_PASSWORD` | Windows decoy admin password |
| `VM_SSH_PUBLIC_KEY` | SSH public key for the Linux decoy |
| `ALERT_EMAIL` | Email address for detection and incident notifications |

### Manual post-deployment step

Sentinel's playbook automation requires the Logic App's managed identity to hold the **Microsoft Sentinel Responder** role. This is a one-time, deliberate manual step rather than something the CI/CD pipeline does itself — granting role-assignment privileges to a pipeline identity is a broader privilege grant than this project wants, so a human performs it once after first deploy:

```bash
az role assignment create \
  --assignee-object-id <playbook-managed-identity-principal-id> \
  --assignee-principal-type ServicePrincipal \
  --role "Microsoft Sentinel Responder" \
  -g rg-honeypot-soc-lab
```

## Detection coverage

| Detection | MITRE Technique | Trigger |
|---|---|---|
| Cowrie SSH brute force | T1110 (Credential Access) | 6+ failed logins / 24h |
| Windows RDP brute force | T1110 (Credential Access) | 5+ failed logins (4625) / 5min |
| Web decoy path scanning | T1595 (Reconnaissance) | 3+ honeytoken path probes / 10min |
| Cowrie / WebDecoy pipeline silence | — | No data received in 30+ min |

## Lessons learned

This project includes a documented incident (`INCIDENT_2026-09-21_provisioning_failures.md`) from a real 3-day silent outage where the web decoy crash-looped with no alert generated — the pipeline health rules above were added directly in response.

## Status

- ✅ Decoy infrastructure, logging pipeline, and Sentinel onboarding
- ✅ Native analytics rules with MITRE mapping and entity correlation
- ✅ Sentinel workbook (MITRE heat map, geo map, top attackers)
- ✅ Threat intelligence enrichment
- ✅ SOAR playbook for incident notification


## Author

Oludemi Joshua — Cloud Security Analyst | Blue Team | Cybersecurity Analyst | SOC Analyst |Security Automation|

> Building HEX WATCH, an AI-powered SOC platform > HEX WATCH is an ongoing project and is being developed incrementally as I expand my skills in security engineering and software development.

---
