# Scripts

Operational remediation scripts for recovering decoy VMs when first-boot provisioning fails. These are not part of the automated deploy path — they're run manually, over SSH, when a decoy comes up in a broken state.

## Background: why these exist

Both decoy VMs install their runtime dependencies (Python venv, Cowrie, Flask) via `pip` during first boot. The NSG denies all outbound internet traffic by default (`allowProvisioningEgress: false` in `main.bicep`) as a containment control, since a compromised decoy should not be able to reach out to the internet. If a VM is provisioned — or rebuilt — while that parameter is `false`, the first-boot `pip install` step fails silently, and the affected service crash-loops with no clear error beyond "exit 203/EXEC" (systemd's code for "the binary I was told to run doesn't exist").

These scripts are the recovery path for that failure mode.

## Scripts

| Script | Target | What it does |
|---|---|---|
| `fix-cowrie.sh` | `vm-linux-decoy` | Rebuilds the Cowrie Python venv from scratch, reinstalls Cowrie, re-applies the port-22 listener config, and fixes the AMA log-read permission issue (`syslog` user needs group access to traverse `/home/cowrie`). Starts Cowrie manually at the end rather than via systemd. |
| `cowrie-service.sh` | `vm-linux-decoy` | Installs the systemd unit for Cowrie (`Restart=always`, starts on boot) so it survives reboots and crashes going forward. Run this once, after `fix-cowrie.sh` has confirmed Cowrie starts correctly by hand. |
| `fix-webdecoy.sh` | `vm-web-decoy` | Rebuilds the web decoy's Python venv and reinstalls Flask, fixes the same class of AMA log-permission issue, then re-enables the existing `webdecoy.service` systemd unit (which cloud-init already creates — this script only repairs what's missing underneath it). |

## Prerequisites before running any of these

1. **Outbound egress must be temporarily allowed.** Set `allowProvisioningEgress: true` in your Bicep parameters and redeploy the NSG *before* SSHing in to run a fix script — these scripts run `apt-get install` and `pip install`, both of which need outbound 80/443. Redeploy with `false` again once the fix is confirmed working.
2. SSH access to the affected VM's public IP (see the Bicep outputs for `vm-linux-decoy` / `vm-web-decoy` public IP addresses).
3. Run each script as `root` (or with `sudo`) — they call `apt-get`, write to `/etc/systemd/system/`, and modify user group membership.

## Usage

```bash
# Cowrie recovery
scp fix-cowrie.sh azureuser@<linux-decoy-ip>:~
ssh azureuser@<linux-decoy-ip> "sudo bash fix-cowrie.sh"

# Once Cowrie starts successfully by hand, install the systemd unit
scp cowrie-service.sh azureuser@<linux-decoy-ip>:~
ssh azureuser@<linux-decoy-ip> "sudo bash cowrie-service.sh"

# Web decoy recovery
scp fix-webdecoy.sh azureuser@<web-decoy-ip>:~
ssh azureuser@<web-decoy-ip> "sudo bash fix-webdecoy.sh"
```

Each script ends with a status check (`systemctl status` plus a `ss -tlnp` port check) so you can confirm the service is actually listening before moving on.

## Known inconsistency worth fixing

`fix-webdecoy.sh` repairs an *existing* `webdecoy.service` unit — the web decoy's cloud-init already defines it. `cowrie-service.sh`, by contrast, has to create Cowrie's systemd unit from scratch, implying `cloud-init-cowrie.yaml` never set one up in the first place. The cleaner long-term fix is to move Cowrie's systemd unit definition into `cloud-init-cowrie.yaml` itself, matching the web decoy's pattern — that would remove the need to ever run `cowrie-service.sh` manually after a fresh deploy, leaving these scripts purely as break-glass recovery tools rather than a required step in the happy path.
