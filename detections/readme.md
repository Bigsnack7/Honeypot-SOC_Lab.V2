# Detections

Human-readable, version-controlled documentation of every Microsoft Sentinel analytics rule in this lab — one YAML file per detection, describing its purpose, trigger logic, and MITRE ATT&CK mapping. These files are **not** consumed by the deployment pipeline directly; the actual live rules are defined as `Microsoft.SecurityInsights/alertRules` resources in `/infra/resources.bicep`. This folder exists so a reader can understand every detection's logic without wading through Bicep syntax, and so detection design changes show up clearly in `git diff`.

## ⚠️ Deployment status — seven rules are documented but not yet live

| File | Rule name | Deployed in `resources.bicep`? |
|---|---|---|
| `cowrie-ssh-bruteforce.yaml` | Cowrie SSH Brute Force Detected | ✅ `cowrieBruteForceRule` |
| `cowrie-command-execution.yaml` | Cowrie Command Execution After Login | ❌ **Not deployed** — documented only |
| `cowrie-pipeline-silent.yaml` | Cowrie Honeypot - No Data Received | ✅ `cowriePipelineSilentRule` |
| `cowrie-post-exploit-sequences.yaml` | Cowrie Honeypot - Post-Exploit Command Sequence Detected | ❌ **Not deployed** — documented only |
| `webdecoy-path-scanning.yaml` | Web Decoy Sensitive Path Scanning Detected | ✅ `webDecoyScanningRule` |
| `webdecoy-pipeline-silent.yaml` | Web Decoy Honeypot - No Data Received | ✅ `webDecoyPipelineSilentRule` |
| `windows-rdp-bruteforce.yaml` | Windows RDP Brute Force Detected | ✅ `windowsBruteForceRule` |
| `windows-process-creation.yaml` | Windows Suspicious Process Creation | ❌ **Not deployed** — documented only |
| `windows-persistence-attempts.yaml` | Windows Honeypot - Persistence Attempt Detected | ❌ **Not deployed** — documented only |
| `windows-discovery-commands.yaml` | Windows Honeypot - Discovery Commands Detected | ❌ **Not deployed** — documented only |
| `event-log-clearing.yaml` | Windows Honeypot - Event Log Clearing Detected | ❌ **Not deployed** — documented only |
| `powershell-suspicious-commands.yaml` | Windows Honeypot - Suspicious PowerShell Activity | ❌ **Not deployed** — documented only |

**Five newly documented rules** (`cowrie-post-exploit-sequences.yaml`, `windows-persistence-attempts.yaml`, `windows-discovery-commands.yaml`, `event-log-clearing.yaml`, `powershell-suspicious-commands.yaml`) describe well-designed detections adapted from the corresponding hunting queries, but — like the two pre-existing gaps — no matching resource exists in `resources.bicep` yet. To close this gap for any of them, add a `Microsoft.SecurityInsights/alertRules` resource following the same pattern as the five already-deployed rules (`scope: law`, `kind: 'Scheduled'`, matching `tactics`/`techniques`/`entityMappings` from the YAML below, and a `name` generated via `guid('<slug>')` per the naming convention).

**Schema note on the four Windows-based new rules:** `windows-persistence-attempts.yaml`, `windows-discovery-commands.yaml`, and `powershell-suspicious-commands.yaml` rely on Sysmon Event ID 13/1 field positions and PowerShell script block logging (Event ID 4104) that have not yet been verified against a live raw event from this lab's `install-sysmon.ps1` config. Verify field indices and confirm script block logging is enabled before deploying these to Bicep — see the matching `.kql` files in `/Hunting_queries` for the same caveat.

## All detections

| File | Detects | Tactic / Technique | Trigger condition |
|---|---|---|---|
| `cowrie-ssh-bruteforce.yaml` | Repeated failed SSH logins against the Cowrie honeypot | Credential Access / T1110 | 6+ failed logins from one IP within 24 hours |
| `cowrie-command-execution.yaml` | An attacker successfully logging in and running shell commands | Execution / T1059 | Any `cowrie.command.input` event, grouped by source IP |
| `cowrie-pipeline-silent.yaml` | The Cowrie logging pipeline itself going dark | Impact | No `Cowrie_CL` events in the last 30 minutes |
| `cowrie-post-exploit-sequences.yaml` | Post-exploit command patterns on the Cowrie shell — download-and-execute chains, permission changes, firewall/log tampering, cron persistence, credential file access | Execution, Persistence, Defense Evasion, Credential Access / T1105, T1222, T1562.004, T1070, T1053.003, T1552 | Any matching command pattern in `Cowrie_CL` |
| `webdecoy-path-scanning.yaml` | Scanning/probing of honeytoken paths (`/wp-login.php`, `/.env`, `/admin`) | Reconnaissance / T1595 | 3+ distinct honeytoken paths probed by one IP within 10 minutes |
| `webdecoy-pipeline-silent.yaml` | The web decoy logging pipeline going dark | Impact | No `WebDecoy_CL` events in the last 30 minutes |
| `windows-rdp-bruteforce.yaml` | Repeated failed RDP logins against the Windows honeypot | Credential Access / T1110 | 5+ failed logons (Event 4625) from one IP within 5 minutes |
| `windows-process-creation.yaml` | Known attacker/living-off-the-land tools launched on the Windows honeypot | Execution / T1059 | Process creation (Event 4688) matching a known tool list (`powershell.exe`, `certutil.exe`, `bitsadmin.exe`, `mshta.exe`, `wmic.exe`, `cmd.exe`) |
| `windows-persistence-attempts.yaml` | New scheduled tasks, registry Run/RunOnce key writes, or new service installation on the Windows honeypot | Persistence / T1053.005, T1547.001, T1543.003 | Any matching Event 4698, Sysmon Event 13, or Event 4697 |
| `windows-discovery-commands.yaml` | "Just landed" recon commands (whoami, systeminfo, ipconfig, net user, nltest, etc.) | Discovery / T1087, T1082, T1016, T1482 | Any matching Sysmon Event 1 process launch |
| `event-log-clearing.yaml` | Attempts to clear Windows event logs via native audit events or `wevtutil`/`Clear-EventLog` command-line usage | Defense Evasion / T1070.001 | Any Event 1102/104, or matching command line |
| `powershell-suspicious-commands.yaml` | Encoded commands, download cradles, AMSI bypass strings, execution-policy bypass in PowerShell | Execution, Defense Evasion / T1059.001, T1027, T1105, T1562.001 | Any matching PowerShell script block (Event 4104) or Sysmon-captured command line |

## Why two rules exist as "pipeline silent" detections

`cowrie-pipeline-silent.yaml` and `webdecoy-pipeline-silent.yaml` don't detect attacker behavior — they detect the *absence* of expected telemetry. Both were added after a real incident (documented in `INCIDENT_2026-09-21_provisioning_failures.md`) where a decoy's service crash-looped following a redeploy, but Azure's VM heartbeat stayed healthy the entire time, so no alert fired for three days. A honeypot that silently stops logging is functionally useless — these two rules exist specifically to catch that failure mode going forward.

There is currently no equivalent "pipeline silent" rule for the Windows honeypot's Sysmon/Security event stream — worth considering as a future addition given the precedent above.

## Relationship to `/Hunting_queries`

Detections here alert automatically on a fixed threshold; `windows-process-creation.yaml` specifically only flags a fixed list of known tool names via native Event 4688. The `windows-process-creation.kql` hunting query in `/Hunting_queries` covers similar ground but more broadly — it also correlates Sysmon Event ID 1 telemetry and flags suspicious *parent/child* process relationships rather than just a static tool list, for open-ended investigation rather than automatic alerting.

The five newly added rules each have a corresponding hunting query of the same base filename in `/Hunting_queries/Hunting_queries` (e.g. `windows-persistence-attempts.kql` ↔ `windows-persistence-attempts.yaml`). They were drafted together and share identical KQL logic — the hunting query version is for ad hoc investigation, the YAML version is the same logic packaged as a documented (but not yet deployed) scheduled rule.

## Naming convention

Each rule's `name` field in Bicep is generated via `guid('<slug>')`, where `<slug>` matches the YAML filename's base name (e.g. `cowrie-bruteforce-rule` for `cowrie-ssh-bruteforce.yaml`). Keep new detections consistent with this pattern so the YAML documentation and the deployed resource stay traceable to each other.

**Note for the five newly added YAML files:** each currently carries a manually generated placeholder GUID in its `id:` field rather than one derived via `guid('<slug>')`. Replace these with the Bicep-generated GUID at deployment time, and double-check none collide with existing rule IDs before committing.
