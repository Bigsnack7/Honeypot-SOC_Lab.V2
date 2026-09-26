# Hunting Queries

KQL queries for manual threat hunting against the honeypot telemetry in `law-honeypot-soc`. These are separate from the scheduled analytics rules in `/detections` — analytics rules alert automatically on a fixed condition; the queries here are for open-ended investigation, run ad hoc from the Sentinel **Logs** or **Hunting** blade when following up on an incident or looking for patterns the automated rules don't yet cover.

## Queries

| Query | Data source(s) | Purpose |
|---|---|---|
| `cowrie-file-downloads.kql` | `Cowrie_CL` | Lists every file download attempt against the SSH honeypot — source IP, URL, and SHA1 hash of the payload. Use to pivot on a specific hash across threat intel or sandbox lookups. |
| `cowrie-successful-logins-and-commands.kql` | `Cowrie_CL` | Reconstructs a session's full activity timeline — every successful login and command an attacker ran, ordered by session and time. The primary query for "what did they actually do once they got in." |
| `cowrie-top-credentials.kql` | `Cowrie_CL` | Ranks the 25 most-attempted username/password pairs across both failed and successful logins. Useful for spotting default-credential lists and common brute-force wordlists in circulation. |
| `top-attacker-ips.kql` | `Cowrie_CL`, `WebDecoy_CL`, `SecurityEvent`, `ThreatIntelligenceIndicator` | Aggregates source IPs across all three decoys into one ranked list, cross-referenced against the last 7 days of threat intelligence indicators. Surfaces IPs already flagged by known threat feeds first. This is the closest thing to a single "who's attacking us right now" view. |
| `web-honeytoken-hits.kql` | `WebDecoy_CL` | Counts hits per honeytoken path (`/wp-login.php`, `/.env`, `/admin`, etc.) and how many distinct source IPs probed each one. Shows which lure is getting the most attention. |
| `windows-rdp-logon-types.kql` | `SecurityEvent` | Hourly breakdown of successful and failed Windows logons (Event ID 4624/4625) by logon type. Useful for spotting a shift from failed attempts to a successful logon on the RDP decoy. |
| `windows-process-creation.kql` | `SecurityEvent`, `Event` (Sysmon) | Correlates native Windows process creation (Event ID 4688) with Sysmon process creation (Event ID 1) into one lineage view, flagging process/parent combinations commonly seen in living-off-the-land execution (e.g. a script host spawning `cmd.exe` or `powershell.exe`). The query to run after an RDP logon succeeds, to see what the attacker actually executed. |

## Usage

1. Open **Microsoft Sentinel** → your workspace (`law-honeypot-soc`) → **Logs** (or **Hunting** for the built-in hunting-query experience).
2. Paste the query and run it. All queries default to Sentinel's standard time range picker unless a query hardcodes its own lookback (`top-attacker-ips.kql` fixes a 7-day window for its threat intel join).
3. Most queries `parse_json(RawData)` before projecting fields — this matches the custom table schema written by the Cowrie/WebDecoy Data Collection Rules. If you add a new field to the Cowrie or WebDecoy log format, extend the `parse_json` block accordingly rather than querying `RawData` directly.

## Schema notes

- **`Cowrie_CL`** and **`WebDecoy_CL`** both store their payload as a JSON blob in `RawData`; every query here starts by parsing it out into typed columns (`src_ip`, `eventid`, `username`, `password`, `path`, etc.).
- **`SecurityEvent`** is the native Windows Security auditing table via Azure Monitor Agent (logon events, native process creation) — no custom parsing needed.
- **`Event`** is where Sysmon telemetry lands (`Source == "Microsoft-Windows-Sysmon"`), as raw XML in the `EventData` column. Unlike `SecurityEvent`, this requires `parse_xml()` and pulling fields out by index position — see the note on `windows-process-creation.kql` below.
- **`ThreatIntelligenceIndicator`** only returns rows once a TI data connector is actively feeding indicators into the workspace. If this table is empty, `top-attacker-ips.kql` will still run correctly — every `IsKnownThreat` value will simply resolve to `false`.

## Extending this folder

New queries should follow the existing naming convention (`<source>-<what-it-shows>.kql`) and get a one-line entry added to the table above. `windows-process-creation.kql` covers process-creation lineage (Event ID 4688 / Sysmon Event ID 1); natural next additions in the same spirit are Sysmon network-connection events (Event ID 3) and file-creation events (Event ID 11), which aren't yet covered by any query or analytics rule here.

**A note on `windows-process-creation.kql` specifically:** the Sysmon half of that query parses raw XML (`EventData.DataItem.EventData.Data[n]`) by fixed index position, which matches a default Sysmon configuration. If `install-sysmon.ps1` or the Sysmon config XML changes which fields are logged, or their order, those index positions will need re-verifying against a sample raw event — this is the one piece of this folder that's config-dependent rather than portable as-is.
