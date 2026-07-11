#!/usr/bin/env bash
# One-shot: serve GLM-Z1-32B via vLLM, wait for it, run all 215 prompts.
# Run from the glm/ directory on the RunPod A100 box.
#
# Usage:
#   bash run_all.sh                                    # uses GLM-Z1-32B-0414
#   bash run_all.sh THUDM/GLM-Z1-9B-0414              # smaller variant
#   HF_HOME=/root/hf bash run_all.sh                  # override cache dir
set -euo pipefail
cd "$(dirname "$0")"

MODEL="${1:-THUDM/GLM-Z1-32B-0414}"
SAFE="$(echo "$MODEL" | tr '/:-' '___' | tr '[:upper:]' '[:lower:]')"
OUT="${2:-predictions_${SAFE}.jsonl}"

pip install -q openai

echo "=== Launching vLLM server for $MODEL (logs -> vllm.log) ==="
export HF_HOME="${HF_HOME:-/root/hf}"
nohup bash serve_glm.sh "$MODEL" > vllm.log 2>&1 &
SERVER_PID=$!
echo "Server PID: $SERVER_PID"

echo "=== Running inference (client waits for server to be ready) ==="
python3 run_inference_glm.py --model "$MODEL" --out "$OUT"

echo
echo "=== Done ==="
echo "Predictions -> $OUT"
echo "Stop the server: kill $SERVER_PID"
echo
echo "Next steps:"
echo "  scp $OUT <scoring-vm-ip>:/root/"
echo "  scp ../benchmark/score_remediations.py <scoring-vm-ip>:/root/"
echo "  scp ../benchmark/compute_scores.py <scoring-vm-ip>:/root/"
echo "  scp ../benchmark/dataset.jsonl <scoring-vm-ip>:/root/"
