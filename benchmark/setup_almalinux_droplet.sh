#!/usr/bin/env bash
# Bootstrap a fresh AlmaLinux 8 droplet for scoring: install oscap + scap-security-guide
# + python3 via dnf, confirm the ssg-almalinux8-ds.xml datastream is present.
#
# Usage: ./setup_almalinux_droplet.sh <droplet_ip>
set -euo pipefail

IP="${1:?usage: setup_almalinux_droplet.sh <droplet_ip>}"
KEY=~/.ssh/id_ed25519

echo "[$IP] confirming OS..."
ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -i "$KEY" "root@$IP" \
  "grep PRETTY_NAME /etc/os-release"

echo "[$IP] installing openscap-scanner, scap-security-guide, python3..."
ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -i "$KEY" "root@$IP" '
dnf install -y openscap-scanner scap-security-guide python3 -q
oscap --version | head -1
python3 --version
ls /usr/share/xml/scap/ssg/content/ | grep -i almalinux
'

echo ""
echo "[$IP] ready."
