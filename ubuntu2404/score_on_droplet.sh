#!/usr/bin/env bash
# One-shot Ubuntu-24.04 scoring pipeline for a single model's predictions.
#
# "run" mode:  filters <model>'s Ubuntu predictions down to the 88 rule_ids that have a
#              real Ubuntu STIG equivalent, copies everything needed to the droplet, and
#              launches apply_then_scan.py there in the background (run all scripts first,
#              single oscap sweep after -- see benchmark/apply_then_scan.py for why).
# "pull" mode: copies the finished results + log back and files them into
#              ubuntu2404/<model>/, matching the layout used for every other model.
#
# Usage:
#   ./score_on_droplet.sh run  <model> [droplet_ip]
#   ./score_on_droplet.sh pull <model> [droplet_ip]
#
# <model> must match an existing ubuntu2404/<model>/predictions_<model>_ubuntu2404.jsonl
set -euo pipefail

MODE="${1:?usage: score_on_droplet.sh run|pull <model> [droplet_ip]}"
MODEL="${2:?usage: score_on_droplet.sh run|pull <model> [droplet_ip]}"
IP="${3:-134.199.159.208}"
KEY=~/.ssh/id_ed25519

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UBUNTU_DIR="$REPO_ROOT/ubuntu2404"
MODEL_DIR="$UBUNTU_DIR/$MODEL"
PRED_FILE="$MODEL_DIR/predictions_${MODEL}_ubuntu2404.jsonl"
SCORABLE_FILE="$MODEL_DIR/predictions_${MODEL}_ubuntu2404_scorable.jsonl"
ALLOWLIST="$UBUNTU_DIR/ubuntu_scorable_rule_ids.json"
REMOTE_PRED="predictions_${MODEL}_ubuntu2404_scorable.jsonl"
REMOTE_OUT="results_${MODEL}_ubuntu2404.jsonl"
REMOTE_LOG="apply_then_scan_${MODEL}.log"

ssh_cmd() { ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -i "$KEY" "root@$IP" "$1"; }

if [ "$MODE" = "run" ]; then
  [ -f "$PRED_FILE" ] || { echo "Not found: $PRED_FILE" >&2; exit 1; }

  echo "[$MODEL] filtering predictions down to the 88 Ubuntu-scorable rule_ids..."
  python3 -c "
import json
allow = set(json.load(open('$ALLOWLIST')))
preds = [json.loads(l) for l in open('$PRED_FILE')]
filtered = [p for p in preds if p['rule_id'] in allow]
print(f'  {len(preds)} total -> {len(filtered)} scorable')
with open('$SCORABLE_FILE', 'w') as f:
    for p in filtered:
        f.write(json.dumps(p) + '\n')
"

  echo "[$MODEL] copying to $IP..."
  scp -o StrictHostKeyChecking=no -i "$KEY" \
    "$SCORABLE_FILE" "$UBUNTU_DIR/dataset_ubuntu2404.jsonl" \
    "$REPO_ROOT/benchmark/apply_then_scan.py" "$REPO_ROOT/benchmark/score_remediations.py" \
    "root@$IP:/root/"

  echo "[$MODEL] launching apply_then_scan.py on $IP (background)..."
  ssh_cmd "cd /root && nohup python3 apply_then_scan.py \
    --predictions $REMOTE_PRED --dataset dataset_ubuntu2404.jsonl \
    --datastream /root/ssg-ubuntu2404-ds.xml --skip-hazardous \
    --out $REMOTE_OUT > $REMOTE_LOG 2>&1 & disown; echo launched"

  echo ""
  echo "Watch live:  ssh root@$IP 'tail -f $REMOTE_LOG'"
  echo "Check done:  ssh root@$IP 'grep \"Results ->\" $REMOTE_LOG'"
  echo "Then pull:   $0 pull $MODEL $IP"

elif [ "$MODE" = "pull" ]; then
  mkdir -p "$MODEL_DIR/logs"
  scp -o StrictHostKeyChecking=no -i "$KEY" \
    "root@$IP:/root/$REMOTE_OUT" "root@$IP:/root/$REMOTE_LOG" "$MODEL_DIR/"
  mv "$MODEL_DIR/$REMOTE_LOG" "$MODEL_DIR/logs/$REMOTE_LOG"
  n=$(wc -l < "$MODEL_DIR/$REMOTE_OUT" | tr -d ' ')
  p=$(python3 -c "import json; print(sum(1 for l in open('$MODEL_DIR/$REMOTE_OUT') if json.loads(l).get('passed')))")
  echo "[$MODEL] pulled: $p/$n passed -> $MODEL_DIR/$REMOTE_OUT"

else
  echo "unknown mode: $MODE (expected run|pull)" >&2
  exit 1
fi
