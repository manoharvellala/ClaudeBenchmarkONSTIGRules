#!/usr/bin/env bash
# Install Ollama, pull CodeLlama 34B FP16, run all 215 prompts.
# Run on a fresh pod with an A100 80GB.
#
# Usage:
#   bash run_all.sh                                         # CodeLlama 34B FP16 (default)
#   bash run_all.sh codellama:13b-instruct-fp16             # smaller variant
set -euo pipefail

MODEL="${1:-codellama:34b-instruct-fp16}"
SAFE="$(echo "$MODEL" | tr '/: ' '___' | tr '[:upper:]' '[:lower:]')"
OUT="predictions_${SAFE}.jsonl"

# Install Ollama if needed
if ! command -v ollama >/dev/null 2>&1; then
  echo "Installing Ollama..."
  apt-get update -q && apt-get install -y -q zstd
  curl -fsSL https://ollama.com/install.sh | sh
fi

# Install openai client
pip install -q openai

# Start Ollama server
ollama serve > /root/ollama.log 2>&1 &
sleep 3

echo "Pulling $MODEL (~68GB for 34B FP16, may take 10-20 min)..."
ollama pull "$MODEL"

echo "Starting inference..."
python3 "$(dirname "$0")/run_inference_llama.py" --model "$MODEL" --out "$OUT"

echo "Done. Predictions -> $OUT"
echo "scp $OUT to AlmaLinux 8 scoring VM and run score_remediations.py + compute_scores.py"
