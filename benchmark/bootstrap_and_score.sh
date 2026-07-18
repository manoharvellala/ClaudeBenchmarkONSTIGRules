#!/usr/bin/env bash
# One-shot scoring bootstrap for a fresh AlmaLinux/RHEL-8 droplet.
#
# Drop this file (plus score_remediations.py, compute_scores.py, dataset.jsonl, and one or
# more predictions_<model>.jsonl) into the same directory on a brand-new droplet, then run:
#
#   bash bootstrap_and_score.sh
#
# and it does everything: installs OpenSCAP + SCAP Security Guide if not already present,
# then scores every predictions_*.jsonl file it finds in this directory, one at a time.
#
# Designed to be interrupted and re-run: it re-checks the install state, and per-model
# scoring is skipped once that model's results file already has as many rows as its
# predictions file (score_remediations.py itself is also resumable mid-model — see its
# own `done` tracking).
#
# WHY THE FLAGS BELOW (--no-prescan --skip-hazardous --reverse):
#   --no-prescan     trusts the dataset's recorded initial_state instead of re-scanning
#                     the rule before running the script — halves oscap invocations.
#   --skip-hazardous excludes crypto-policy/FIPS/SSH-cipher/GRUB rules, which can sever
#                     SSH/console access if a model's remediation script is wrong. Does
#                     NOT guarantee safety though — see the postmortem note below.
#   --reverse        processes rules from the end of the list backward. On its own this
#                     buys nothing; it's meant to pair with a forward run of the SAME
#                     predictions file on a second host, so a landmine rule that kills one
#                     box doesn't block the other from covering its half. Kept on here as
#                     a mild mitigation (if this box dies partway, at least the un-run
#                     portion is the opposite end from previous droplets' runs) even
#                     without a formal pair.
#
# POSTMORTEM (2026-07-17, the first 3-droplet CodeLlama-34B scoring run): all 3 droplets
# lost external SSH access mid-run despite --skip-hazardous — two via sshd crashing
# outright (connection refused), one via a remediation script breaking pubkey auth
# specifically (permission denied). The score_remediations.py process itself kept running
# fine in both cases (it only needs local access), so results were still complete on disk —
# just unreachable over the network until retrieved via the cloud provider's web console.
# --skip-hazardous covers the KNOWN dangerous categories, not every possible way a model's
# generated script can misconfigure sshd/PAM/firewall. Assume this can happen again:
#     1. Pair this script with a sync process pulling results_*.jsonl off the droplet on a
#        short interval (see benchmark/compute_ci.py's companion sync scripts / ci_runs/
#        for the pattern used) so results are never solely on a box you might lose access to.
#     2. If SSH does drop, the cloud provider's web/serial console still works (it doesn't
#        go through sshd) — `cat results_<model>.jsonl` there and paste it manually.
#        benchmark/compute_ci.py accepts either the raw .jsonl or a captured
#        score_remediations.py text log, so a console paste is not a dead end.
#
# These are $6/mo, 1 vCPU / 1GB RAM droplets — plenty for OpenSCAP + short remediation
# scripts, but don't expect headroom for much else running concurrently.

set -uo pipefail
cd "$(dirname "$0")"

DS=/usr/share/xml/scap/ssg/content/ssg-almalinux8-ds.xml

echo "=== [$(date -u +%H:%M:%S)] Checking OpenSCAP / SCAP Security Guide install ==="
if ! command -v oscap >/dev/null 2>&1 || [ ! -f "$DS" ]; then
  echo "Installing openscap-scanner, scap-security-guide, python3 ..."
  dnf install -y -q openscap-scanner scap-security-guide python3
else
  echo "Already installed: $(oscap -V | head -1)"
fi

if [ ! -f "$DS" ]; then
  echo "ERROR: datastream not found at $DS after install attempt. Aborting." >&2
  exit 1
fi

mkdir -p logs

for PRED in predictions_*.jsonl; do
  [ -e "$PRED" ] || { echo "No predictions_*.jsonl files found in $(pwd) — nothing to score."; break; }

  MODEL="${PRED#predictions_}"
  MODEL="${MODEL%.jsonl}"
  OUT="results_${MODEL}.jsonl"

  EXPECTED=$(wc -l < "$PRED")
  DONE=0
  [ -f "$OUT" ] && DONE=$(wc -l < "$OUT")
  if [ "$DONE" -ge "$EXPECTED" ] && [ "$EXPECTED" -gt 0 ]; then
    echo "=== [$(date -u +%H:%M:%S)] $MODEL already scored ($DONE/$EXPECTED) — skipping ==="
    continue
  fi

  echo "=== [$(date -u +%H:%M:%S)] Scoring $MODEL ($DONE/$EXPECTED done so far) ==="
  python3 score_remediations.py \
    --predictions "$PRED" \
    --dataset dataset.jsonl \
    --datastream "$DS" \
    --phase normal --no-prescan --skip-hazardous --reverse \
    --out "$OUT" \
    > "logs/score_${MODEL}.log" 2>&1

  N=$(wc -l < "$OUT" 2>/dev/null || echo 0)
  PASS=$(python3 -c "import json;print(sum(1 for l in open('$OUT') if json.loads(l).get('passed') is True))" 2>/dev/null || echo "?")
  echo "  done: $N/$EXPECTED scored, $PASS passed"
done

echo "=== SCORING PASS COMPLETE [$(date -u +%H:%M:%S)] ==="
echo "Run 'python3 compute_scores.py results_<model>.jsonl' for the bucket breakdown of any one file."
