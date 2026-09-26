# Detections

Human-readable, version-controlled documentation of every Microsoft Sentinel analytics rule in this lab — one YAML file per detection, describing its purpose, trigger logic, and MITRE ATT&CK mapping. These files are **not** consumed by the deployment pipeline directly; the actual live rules are defined as `Microsoft.SecurityInsights/alertRules` resources in `/infra/resources.bicep`. This folder exists so a reader can understand every detection's logic without wading through Bicep syntax, and so detection design changes show up clearly in `git diff`.

## ⚠️ Deployment status — two rules are documented but not yet live

| File | Rule name | Deployed in `resources.bicep`? |
|---|---|---|
| `cowrie-ssh-bruteforce.yaml` | Cowrie SSH Brute Force Detected | ✅ `cowrieBruteForceRule` |
| `cowrie-command-execution.yaml` | Cowrie Command Execution After Login | ❌ **Not deployed** — documented only |
| `cowrie-pipeline-silent.yaml` | Cowrie Honeypot - No Data Received | ✅ `cowriePipelineSilentRule` |
| `webdecoy-path-scanning.yaml` | Web Decoy Sensitive Path Scanning Detected | ✅ `webDecoyScanningRule` |
| `webdecoy-pipeline-silent.yaml` | Web Decoy Honeypot - No Data Received | ✅ `webDecoyPipelineSilentRule` |
| `windows-rdp-bruteforce.yaml` | Windows RDP Brute Force Detected | ✅ `windowsBruteForceRule` |
| `windows-process-creation.yaml` | Windows Suspicious Process Creation | ❌ **Not deployed** — documented only |

**`cowrie-command-execution.yaml`** and **`windows-process-creation.yaml`** describe real, well-designed detections, but no matching resource exists in `resources.bicep` — they don't currently fire in the live environment. To close this gap, add each as a `Microsoft.SecurityInsights/alertRules` resource in `resources.bicep`, following the same pattern as the five already-deployed rules (`scope: law`, `kind: 'Scheduled'`, matching `tactics`/`techniques`/`entityMappings` from the YAML below).

## All detections

| File | Detects | Tactic / Technique | Trigger condition |
|---|---|---|---|
| `cowrie-ssh-bruteforce.yaml` | Repeated failed SSH logins against the Cowrie honeypot | Credential Access / T1110 | 6+ failed logins from one IP within 24 hours |
| `cowrie-command-execution.yaml` | An attacker successfully logging in and running shell commands | Execution / T1059 | Any `cowrie.command.input` event, grouped by source IP |
| `cowrie-pipeline-silent.yaml` | The Cowrie logging pipeline itself going dark | Impact | No `Cowrie_CL` events in the last 30 minutes |
| `webdecoy-path-scanning.yaml` | Scanning/probing of honeytoken paths (`/wp-login.php`, `/.env`, `/admin`) | Reconnaissance / T1595 | 3+ distinct honeytoken paths probed by one IP within 10 minutes |
| `webdecoy-pipeline-silent.yaml` | The web decoy logging pipeline going dark | Impact | No `WebDecoy_CL` events in the last 30 minutes |
| `windows-rdp-bruteforce.yaml` | Repeated failed RDP logins against the Windows honeypot | Credential Access / T1110 | 5+ failed logons (Event 4625) from one IP within 5 minutes |
| `windows-process-creation.yaml` | Known attacker/living-off-the-land tools launched on the Windows honeypot | Execution / T1059 | Process creation (Event 4688) matching a known tool list (`powershell.exe`, `certutil.exe`, `bitsadmin.exe`, `mshta.exe`, `wmic.exe`, `cmd.exe`) |

## Why two rules exist as "pipeline silent" detections

`cowrie-pipeline-silent.yaml` and `webdecoy-pipeline-silent.yaml` don't detect attacker behavior — they detect the *absence* of expected telemetry. Both were added after a real incident (documented in `INCIDENT_2026-09-21_provisioning_failures.md`) where a decoy's service crash-looped following a redeploy, but Azure's VM heartbeat stayed healthy the entire time, so no alert fired for three days. A honeypot that silently stops logging is functionally useless — these two rules exist specifically to catch that failure mode going forward.

## Relationship to `/Hunting_queries`

Detections here alert automatically on a fixed threshold; `windows-process-creation.yaml` specifically only flags a fixed list of known tool names via native Event 4688. The `windows-process-creation.kql` hunting query in `/Hunting_queries` covers similar ground but more broadly — it also correlates Sysmon Event ID 1 telemetry and flags suspicious *parent/child* process relationships rather than just a static tool list, for open-ended investigation rather than automatic alerting.

## Naming convention

Each rule's `name` field in Bicep is generated via `guid('<slug>')`, where `<slug>` matches the YAML filename's base name (e.g. `cowrie-bruteforce-rule` for `cowrie-ssh-bruteforce.yaml`). Keep new detections consistent with this pattern so the YAML documentation and the deployed resource stay traceable to each other.
