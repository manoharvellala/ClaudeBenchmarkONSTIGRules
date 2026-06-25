#!/usr/bin/env bash
# Install vLLM (if needed) and serve Qwen2.5-Coder-7B-Instruct with an
# OpenAI-compatible API on :8000. Run this in its own terminal / tmux pane;
# it stays in the foreground. Needs a single >=24 GB NVIDIA GPU.
set -euo pipefail

MODEL="${1:-Qwen/Qwen2.5-Coder-7B-Instruct}"
PORT="${PORT:-8000}"
MAXLEN="${MAXLEN:-8192}"

if ! command -v vllm >/dev/null 2>&1; then
  echo "Installing vLLM (this pulls torch+CUDA, a few minutes)..."
  pip install --upgrade pip
  pip install vllm
fi

export HF_HOME="${HF_HOME:-/workspace/hf}"
export HF_HUB_DISABLE_XET="${HF_HUB_DISABLE_XET:-1}"
export VLLM_ENGINE_READY_TIMEOUT_S="${VLLM_ENGINE_READY_TIMEOUT_S:-1800}"
echo "Serving $MODEL on port $PORT (max-model-len=$MAXLEN, timeout=${VLLM_ENGINE_READY_TIMEOUT_S}s, HF_HOME=$HF_HOME)..."
exec vllm serve "$MODEL" \
  --port "$PORT" \
  --max-model-len "$MAXLEN" \
  --gpu-memory-utilization 0.90 \
  --dtype auto
