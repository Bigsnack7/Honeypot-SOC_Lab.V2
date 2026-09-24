#!/bin/bash
# Repairs a broken Cowrie install (broken/missing venv) on vm-linux-decoy.
# Root cause: first-boot pip install failed due to NSG blocking outbound
# traffic. Requires outbound 80/443 to be reachable before running.
set -ex
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y -o Acquire::Retries=5 python3-pip python3-venv \
  libssl-dev libffi-dev build-essential libpython3-dev python3-minimal authbind

rm -rf /home/cowrie/my-honeypot/cowrie-env
su - cowrie -c "cd /home/cowrie/my-honeypot && python3 -m venv cowrie-env"
su - cowrie -c "cd /home/cowrie/my-honeypot && source cowrie-env/bin/activate && \
  pip install --upgrade pip && pip install cowrie"
su - cowrie -c "cd /home/cowrie/my-honeypot && source cowrie-env/bin/activate && cowrie init"

sed -i 's/^listen_endpoints = tcp:2222.*/listen_endpoints = tcp:22:interface=0.0.0.0/' \
  /home/cowrie/my-honeypot/etc/cowrie.cfg

# Fixes log-permission issue: Azure Monitor Agent runs as `syslog` and needs
# to traverse /home/cowrie (750) to reach the log file.
usermod -aG cowrie syslog
systemctl restart azuremonitoragent

su - cowrie -c "cd /home/cowrie/my-honeypot && source cowrie-env/bin/activate && authbind --deep cowrie start"
