#!/usr/bin/env bash
# Bootstrap a fresh Ubuntu 24.04 droplet for scoring: install oscap, extract the
# ssg-ubuntu2404-ds.xml datastream. Skips security.ubuntu.com in apt sources --
# that upstream has been observed to hang/crawl (~18.6 kB/s) from DigitalOcean
# droplets in this project, even though the main archive mirror is fast. We don't
# need security patches for a throwaway scoring VM, so dropping it avoids the stall
# instead of waiting it out.
#
# Usage: ./setup_droplet.sh <droplet_ip>
set -euo pipefail

IP="${1:?usage: setup_droplet.sh <droplet_ip>}"
KEY=~/.ssh/id_ed25519
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARBALL="/tmp/scap-security-guide-0.1.81.tar.gz"

if [ ! -f "$TARBALL" ]; then
  echo "Local tarball cache not found at $TARBALL -- downloading from GitHub release..."
  curl -sL -o "$TARBALL" \
    https://github.com/ComplianceAsCode/content/releases/download/v0.1.81/scap-security-guide-0.1.81.tar.gz
fi

echo "[$IP] confirming OS + copying tarball..."
ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -i "$KEY" "root@$IP" \
  "grep PRETTY_NAME /etc/os-release"
scp -o StrictHostKeyChecking=no -i "$KEY" "$TARBALL" "root@$IP:/root/"

echo "[$IP] disabling security.ubuntu.com (slow upstream, not needed for scoring) + installing oscap..."
ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -i "$KEY" "root@$IP" '
python3 -c "
with open(\"/etc/apt/sources.list.d/ubuntu.sources\") as f:
    content = f.read()
blocks = content.split(\"\n\n\")
kept = [b for b in blocks if \"security.ubuntu.com\" not in b]
with open(\"/etc/apt/sources.list.d/ubuntu.sources\", \"w\") as f:
    f.write(\"\n\n\".join(kept))
"
apt-get update -qq
apt-get install -y -qq openscap-scanner
oscap --version | head -1
'

echo "[$IP] extracting ssg-ubuntu2404-ds.xml..."
ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -i "$KEY" "root@$IP" '
cd /root
tar -xzf scap-security-guide-0.1.81.tar.gz scap-security-guide-0.1.81/ssg-ubuntu2404-ds.xml
mv scap-security-guide-0.1.81/ssg-ubuntu2404-ds.xml /root/ssg-ubuntu2404-ds.xml
rmdir scap-security-guide-0.1.81 2>/dev/null || true
oscap info /root/ssg-ubuntu2404-ds.xml | grep -A1 "Id: xccdf_org.ssgproject.content_profile_stig"
'

echo ""
echo "[$IP] ready. Next: ubuntu2404/score_on_droplet.sh run <model> $IP"
