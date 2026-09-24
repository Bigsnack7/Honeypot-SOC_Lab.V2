#!/bin/bash
# Repairs a broken web decoy install (missing venv/Flask) on vm-web-decoy.
# Root cause: same as Cowrie — first-boot pip install blocked by NSG.
# webdecoy.service was crash-looping with exit 203/EXEC because the venv
# referenced in ExecStart never existed. Requires outbound 80/443 reachable.
set -ex
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y -o Acquire::Retries=5 python3-venv python3-pip authbind

mkdir -p /etc/authbind/byport
touch /etc/authbind/byport/80
chown webdecoy:webdecoy /etc/authbind/byport/80
chmod 770 /etc/authbind/byport/80

su - webdecoy -c "python3 -m venv /home/webdecoy/venv"
su - webdecoy -c "/home/webdecoy/venv/bin/pip install --upgrade pip && \
  /home/webdecoy/venv/bin/pip install flask"

# Fixes log-permission issue: same class of bug as Cowrie.
usermod -aG webdecoy syslog
systemctl restart azuremonitoragent

systemctl daemon-reload
systemctl reset-failed webdecoy
systemctl enable --now webdecoy
sleep 5
systemctl status webdecoy --no-pager | head -12
ss -tlnp | grep ':80'
