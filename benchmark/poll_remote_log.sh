#!/usr/bin/env bash
# Continuously mirror a remote score_remediations.py log + results file to local disk,
# so that if the droplet crashes mid-run (the recurring failure mode in this project --
# a remediation script corrupts something and the box becomes unreachable), we still
# have the most recent successful snapshot to compute a final score from, instead of
# losing everything.
#
# Uses SSH connection multiplexing (ControlMaster) so repeated polls reuse one already-
# authenticated connection instead of paying a full SSH handshake every poll -- this is
# what makes a ~1s poll interval actually feasible instead of wasteful/rate-limit-prone.
#
# Usage: ./poll_remote_log.sh <ip> <remote_log> <remote_results> <local_dir> [interval_s]
set -uo pipefail

IP="${1:?ip}"
REMOTE_LOG="${2:?remote log path}"
REMOTE_RESULTS="${3:?remote results path}"
LOCAL_DIR="${4:?local dir}"
INTERVAL="${5:-1}"
KEY=~/.ssh/id_ed25519
CTRL="/tmp/ssh_ctrl_$$_$(basename "$IP")"

mkdir -p "$LOCAL_DIR"
LOCAL_LOG="$LOCAL_DIR/$(basename "$REMOTE_LOG")"
LOCAL_RESULTS="$LOCAL_DIR/$(basename "$REMOTE_RESULTS")"
STATUS_FILE="$LOCAL_DIR/poll_status.txt"

SSH_OPTS=(-o StrictHostKeyChecking=no -o ConnectTimeout=8
          -o ControlMaster=auto -o ControlPath="$CTRL" -o ControlPersist=60s
          -i "$KEY")

cleanup() { ssh "${SSH_OPTS[@]}" -O exit "root@$IP" 2>/dev/null; }
trap cleanup EXIT

echo "$(date -u +%FT%TZ) polling started" > "$STATUS_FILE"

fails=0
while true; do
  out=$(ssh "${SSH_OPTS[@]}" "root@$IP" "cat '$REMOTE_LOG' 2>/dev/null" 2>/dev/null)
  rc=$?
  if [ $rc -eq 0 ] && [ -n "$out" ]; then
    printf '%s' "$out" > "$LOCAL_LOG.tmp" && mv "$LOCAL_LOG.tmp" "$LOCAL_LOG"
    ssh "${SSH_OPTS[@]}" "root@$IP" "cat '$REMOTE_RESULTS' 2>/dev/null" 2>/dev/null \
      > "$LOCAL_RESULTS.tmp" && mv "$LOCAL_RESULTS.tmp" "$LOCAL_RESULTS"
    fails=0
    echo "$(date -u +%FT%TZ) OK ($(wc -l < "$LOCAL_RESULTS" 2>/dev/null | tr -d ' ') results rows)" >> "$STATUS_FILE"
    if grep -q "SCORE" "$LOCAL_LOG" 2>/dev/null; then
      echo "$(date -u +%FT%TZ) job finished (SCORE marker seen) -- stopping poller" >> "$STATUS_FILE"
      break
    fi
  else
    fails=$((fails+1))
    echo "$(date -u +%FT%TZ) POLL FAILED (attempt $fails) -- last good snapshot preserved" >> "$STATUS_FILE"
    if [ $fails -ge 10 ]; then
      echo "$(date -u +%FT%TZ) $fails consecutive failures -- droplet likely down. Stopping poller." >> "$STATUS_FILE"
      break
    fi
  fi
  sleep "$INTERVAL"
done
