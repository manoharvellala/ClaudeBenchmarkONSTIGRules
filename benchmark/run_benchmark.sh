#!/bin/bash
# Full end-to-end scoring on the droplet — no manual steps, including reboot rules.
#
#   1. score all NON-reboot rules           (phase normal)
#   2. apply all REBOOT-rule scripts          (phase apply -> mark pending)
#   3. install a one-shot service that runs   (phase rescan) automatically on next boot
#   4. reboot once
#   --> after the box comes back, the service finalizes the pending rules and disables itself.
#
# Everything is logged to /root/benchmark.log throughout (survives the reboot), and
# results are written incrementally to /root/results.jsonl (never lost).
#
# Usage (on the droplet, as root):
#   ./run_benchmark.sh predictions_opus.jsonl
#
set -u
PRED="${1:-predictions_opus.jsonl}"
DS="/usr/share/xml/scap/ssg/content/ssg-almalinux8-ds.xml"
OUT="/root/results.jsonl"
LOG="/root/benchmark.log"
PY="/usr/bin/python3.11"
cd /root

# Guard: never proceed (and never reboot) if there are no predictions to score.
if [ ! -s "$PRED" ]; then
    echo "ERROR: predictions file '$PRED' is missing or empty — run inference first. Aborting (no reboot)." | tee -a "$LOG"
    exit 1
fi

echo "================ $(date) START (predictions=$PRED) ================" | tee -a "$LOG"

echo "---- $(date) PHASE 1: non-reboot rules ----" | tee -a "$LOG"
$PY score_remediations.py --predictions "$PRED" --dataset dataset.jsonl \
    --datastream "$DS" --phase normal --no-prescan --out "$OUT" 2>&1 | tee -a "$LOG"

echo "---- $(date) PHASE 2: apply reboot-required scripts (marked pending) ----" | tee -a "$LOG"
$PY score_remediations.py --predictions "$PRED" --dataset dataset.jsonl \
    --datastream "$DS" --phase apply --no-prescan --out "$OUT" 2>&1 | tee -a "$LOG"

# count how many are pending; if none, skip the reboot entirely
# (grep | wc -l is robust: grep's exit code is irrelevant when piped, wc gives a clean integer)
PENDING=$(grep -F '"post_scan": "pending_reboot"' "$OUT" 2>/dev/null | wc -l | tr -d ' ')
if [ "$PENDING" -eq 0 ]; then
    echo "---- $(date) no reboot-required rules pending; done. ----" | tee -a "$LOG"
    $PY score_remediations.py --datastream "$DS" --phase rescan --out "$OUT" 2>&1 | tee -a "$LOG"
    exit 0
fi

echo "---- $(date) installing post-reboot auto-rescan service ($PENDING pending) ----" | tee -a "$LOG"
cat > /etc/systemd/system/stig-rescan.service <<EOF
[Unit]
Description=STIG benchmark post-reboot rescan
After=multi-user.target

[Service]
Type=oneshot
WorkingDirectory=/root
ExecStart=$PY /root/score_remediations.py --datastream $DS --phase rescan --out $OUT
ExecStartPost=/bin/systemctl disable stig-rescan.service
StandardOutput=append:$LOG
StandardError=append:$LOG

[Install]
WantedBy=multi-user.target
EOF
systemctl enable stig-rescan.service

echo "---- $(date) REBOOTING; rescan runs automatically on boot. Check $LOG and $OUT afterward. ----" | tee -a "$LOG"
sync
sleep 3
reboot
