#!/bin/bash
# Installs a systemd unit for Cowrie so it survives reboots and crashes.
# Run this once after fix-cowrie.sh has confirmed Cowrie starts manually.
set -ex

su - cowrie -c "cd /home/cowrie/my-honeypot && source cowrie-env/bin/activate && cowrie stop" || true

cat > /etc/systemd/system/cowrie.service <<'UNIT'
[Unit]
Description=Cowrie SSH honeypot
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
User=cowrie
Group=cowrie
WorkingDirectory=/home/cowrie/my-honeypot
Environment=PATH=/home/cowrie/my-honeypot/cowrie-env/bin:/usr/local/bin:/usr/bin:/bin
PIDFile=/home/cowrie/my-honeypot/var/run/cowrie.pid
ExecStartPre=/bin/rm -f /home/cowrie/my-honeypot/var/run/cowrie.pid
ExecStart=/usr/bin/authbind --deep /home/cowrie/my-honeypot/cowrie-env/bin/cowrie start
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now cowrie
sleep 5
systemctl status cowrie --no-pager | head -12
ss -tlnp | grep -E ':22 |:2222 '
