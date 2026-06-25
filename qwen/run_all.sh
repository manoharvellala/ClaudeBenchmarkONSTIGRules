#!/usr/bin/env bash
# One-shot: start the vLLM server in the background, wait for it, run inference
# over all 215 prompts, then leave predictions_qwen25coder7b.jsonl ready to copy
# to the RHEL-8 scoring box.
set -euo pipefail
cd "$(dirname "$0")"

MODEL="${1:-Qwen/Qwen2.5-Coder-7B-Instruct}"
SAFE="$(echo "$MODEL" | tr '/:-' '___' | tr '[:upper:]' '[:lower:]')"
OUT="${2:-predictions_${SAFE}.jsonl}"

pip install -q openai

# start the server detached; logs to vllm.log
echo "Launching vLLM server (logs -> vllm.log)..."
nohup bash serve_qwen.sh "$MODEL" > vllm.log 2>&1 &
SERVER_PID=$!
echo "server pid: $SERVER_PID"

# the inference script itself waits for the server to become reachable
python3 run_inference_qwen.py --model "$MODEL" --out "$OUT"

echo
echo "Done. Predictions -> $OUT"
echo "Stop the server with: kill $SERVER_PID"
echo "Then scp $OUT to the RHEL-8 box and run score_remediations.py + compute_scores.py."
