#!/usr/bin/env bash
# Multi-model inference on ONE GPU pod (A100 recommended).
# For each model: serve with vLLM -> wait -> run inference -> tear down -> next.
# Produces predictions_<model>.jsonl per model, all ready to score.
#
# Usage:
#   bash run_models.sh                       # uses models.txt
#   bash run_models.sh A B C                 # explicit model ids
#   HF_TOKEN=hf_... bash run_models.sh       # for gated repos (Llama, Codestral)
set -uo pipefail
cd "$(dirname "$0")"

PORT="${PORT:-8000}"
MAXLEN="${MAXLEN:-8192}"
GPUUTIL="${GPUUTIL:-0.92}"

# collect model list: args, else non-comment lines of models.txt
if [ "$#" -gt 0 ]; then
  MODELS=("$@")
else
  mapfile -t MODELS < <(grep -vE '^\s*#' models.txt | grep -vE '^\s*$')
fi

echo "Models to run (${#MODELS[@]}):"; printf '  %s\n' "${MODELS[@]}"

command -v vllm >/dev/null 2>&1 || { echo "Installing vLLM..."; pip install -q vllm; }
pip install -q openai

mkdir -p logs

for MODEL in "${MODELS[@]}"; do
  SAFE="$(echo "$MODEL" | tr '/:' '__')"
  OUT="predictions_${SAFE}.jsonl"
  echo
  echo "============================================================"
  echo "MODEL: $MODEL  ->  $OUT"
  echo "============================================================"

  # extra serve flags per model (e.g. AWQ for quantized repos)
  EXTRA=""
  case "$MODEL" in
    *-AWQ|*-awq) EXTRA="--quantization awq" ;;
  esac

  echo "Starting vLLM (log -> logs/${SAFE}.log)..."
  nohup vllm serve "$MODEL" --port "$PORT" --max-model-len "$MAXLEN" \
        --gpu-memory-utilization "$GPUUTIL" --dtype auto $EXTRA \
        > "logs/${SAFE}.log" 2>&1 &
  SPID=$!

  # run inference; the script waits for the server to be reachable, then loads all prompts
  python3 run_inference_qwen.py --model "$MODEL" --out "$OUT" \
          --report "sample_${SAFE}.md" --wait-for-server 1200
  RC=$?

  echo "Tearing down vLLM (pid $SPID)..."
  kill "$SPID" 2>/dev/null
  # wait for the port to free before the next model loads
  for _ in $(seq 1 30); do
    if ! lsof -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then break; fi
    sleep 2
  done
  sleep 3

  if [ "$RC" -ne 0 ]; then
    echo "WARNING: inference for $MODEL exited $RC (see logs/${SAFE}.log). Continuing."
  fi
done

echo
echo "All done. Prediction files:"
ls -1 predictions_*.jsonl 2>/dev/null
echo
echo "Copy these to the RHEL-8 scoring box and run score_remediations.py + compute_scores.py for each."
