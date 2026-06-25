# Qwen2.5-Coder-7B-Instruct — STIG benchmark inference

Self-contained folder to run the **inference** stage of the STIG benchmark for an
open-source model on a GPU box. Produces `predictions_qwen25coder7b.jsonl`, which
is then scored by the **same** `score_remediations.py` on the RHEL-8 box — so the
result is directly comparable to the Claude Opus 4.8 run.

> Inference (GPU box, this folder) and scoring (RHEL-8 box) are separate machines.
> The GPU box needs **no OpenSCAP**; the RHEL-8 box needs **no GPU**.

## GPU / VM spec needed

| Resource | Minimum | Comfortable |
|---|---|---|
| **GPU VRAM** | **24 GB** single GPU | 40–80 GB |
| Example GPUs | NVIDIA **L4**, **A10 / A10G**, RTX **4090 / 3090**, A5000 | A100 40/80 GB, H100 |
| Cloud instances | AWS `g5.xlarge` (A10G 24 GB), GCP `g2` (L4 24 GB), RunPod/Lambda/vast.ai RTX 4090 | AWS `g5.2xlarge`, A100 nodes |
| System RAM | 16 GB | 32 GB |
| Disk free | ~30 GB (model is ~15 GB) | 50 GB |
| Software | recent NVIDIA driver + CUDA 12.x, Python 3.9+ | same |

Qwen2.5-Coder-7B-Instruct in bf16 is ~15 GB of weights + KV cache, so a single
**24 GB** card runs it well at `--max-model-len 8192`. A 16 GB card (T4/A4000) is
too tight for bf16 — use a 24 GB card, or serve a quantized (AWQ/GPTQ) build.

## Files

| File | What |
|---|---|
| `dataset.jsonl` | the 215 benchmark prompts (input) |
| `serve_qwen.sh` | installs vLLM and serves the model (OpenAI-compatible API on :8000) |
| `run_inference_qwen.py` | feeds each prompt to the model, extracts the bash, writes predictions (resumable) |
| `run_all.sh` | one-shot: start server -> wait -> run inference |
| `requirements.txt` | the one client dependency (`openai`); vLLM is installed by `serve_qwen.sh` |

## Run it (two ways)

### Easiest — one command
```bash
bash run_all.sh
```
Starts vLLM in the background (logs to `vllm.log`), waits for it, runs all 215
prompts, writes `predictions_qwen25coder7b.jsonl`.

### Manual — two terminals (more control / see the server logs)
```bash
# terminal 1: serve the model (stays in foreground)
bash serve_qwen.sh

# terminal 2: run inference once the server prints "Application startup complete"
pip install openai
python3 run_inference_qwen.py \
  --model Qwen/Qwen2.5-Coder-7B-Instruct \
  --base-url http://localhost:8000/v1 \
  --out predictions_qwen25coder7b.jsonl
```

Quick smoke test first (5 rules):
```bash
python3 run_inference_qwen.py --limit 5 --out test_qwen.jsonl
```

Inference for all 215 prompts takes roughly 5–15 min on a 24 GB card. The script is
**resumable** — re-run the same command and it skips rules already done.

## Then score it (on the RHEL-8 box, NOT here)

Copy the predictions over and run the identical scorer used for Claude:
```bash
scp predictions_qwen25coder7b.jsonl root@<rhel8-box>:/root/

# on the RHEL-8 box:
DS=/usr/share/xml/scap/ssg/content/ssg-almalinux8-ds.xml
python3 score_remediations.py \
  --predictions predictions_qwen25coder7b.jsonl \
  --dataset dataset.jsonl --datastream "$DS" \
  --phase normal --no-prescan --skip-hazardous \
  --out results_qwen.jsonl
python3 compute_scores.py results_qwen.jsonl
```

`compute_scores.py` prints the same bucket table, giving you Qwen's numbers next to
Claude's.

## Benchmarking a different open model

Everything is model-agnostic. To try, e.g., Llama-3.1-8B-Instruct, just change the
model id (and size the GPU accordingly):
```bash
bash serve_qwen.sh meta-llama/Llama-3.1-8B-Instruct       # needs HF access token for gated repos
python3 run_inference_qwen.py --model meta-llama/Llama-3.1-8B-Instruct \
  --out predictions_llama31_8b.jsonl
```
For gated models (Llama), set `export HF_TOKEN=hf_...` before serving.
