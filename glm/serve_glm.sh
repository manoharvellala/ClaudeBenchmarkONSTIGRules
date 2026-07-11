#!/usr/bin/env bash
# Serve GLM-Z1-32B-0414 (or any GLM model) with vLLM on :8000.
# Needs a single 80 GB A100. HF_HOME defaults to /root/hf to avoid
# the RunPod workspace FUSE quota (~19 GB limit); 32B weights are ~65 GB.
set -euo pipefail

MODEL="${1:-THUDM/GLM-Z1-32B-0414}"
PORT="${PORT:-8000}"
MAXLEN="${MAXLEN:-16384}"   # long enough for think block + bash script

if ! command -v vllm >/dev/null 2>&1; then
  echo "Installing vLLM (pulls torch+CUDA, a few minutes)..."
  pip install --upgrade pip
  pip install vllm
fi

export HF_HOME="${HF_HOME:-/root/hf}"
export HF_HUB_DISABLE_XET="${HF_HUB_DISABLE_XET:-1}"
export VLLM_ENGINE_READY_TIMEOUT_S="${VLLM_ENGINE_READY_TIMEOUT_S:-1800}"

echo "Serving $MODEL on port $PORT (max-model-len=$MAXLEN, HF_HOME=$HF_HOME)..."
exec vllm serve "$MODEL" \
  --port "$PORT" \
  --max-model-len "$MAXLEN" \
  --gpu-memory-utilization 0.92 \
  --trust-remote-code \
  --dtype auto
