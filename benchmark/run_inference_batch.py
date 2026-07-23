#!/usr/bin/env python3
"""
Multi-model inference via the Claude Batch API -- much faster than sequential
run_inference.py calls, and 50% cheaper. Submits ALL models' requests as ONE
batch (a batch can mix models freely; each Request carries its own model),
then splits results back out per-model.

Usage:
    export ANTHROPIC_API_KEY=sk-ant-...
    python3 benchmark/run_inference_batch.py \
        --dataset benchmark/dataset.jsonl \
        --models claude-opus-4-7,claude-opus-4-5-20251101,claude-sonnet-5,claude-sonnet-4-5-20250929,claude-haiku-4-5-20251001,claude-fable-5 \
        --out-dir benchmark/
"""
import argparse
import json
import os
import re
import sys
import time

import anthropic
from anthropic.types.message_create_params import MessageCreateParamsNonStreaming
from anthropic.types.messages.batch_create_params import Request


def extract_bash(text):
    if not text:
        return ""
    m = re.findall(r"```(?:bash|sh)\s*\n(.*?)```", text, re.DOTALL)
    if m:
        return max(m, key=len).strip()
    m = re.findall(r"```\s*\n?(.*?)```", text, re.DOTALL)
    if m:
        return max(m, key=len).strip()
    return text.strip()


def safe_key(model):
    return model.replace("/", "_").replace(".", "_").replace(":", "_")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="benchmark/dataset.jsonl")
    ap.add_argument("--models", required=True, help="comma-separated model ids")
    ap.add_argument("--out-dir", default="benchmark/")
    ap.add_argument("--max-tokens", type=int, default=2500)
    args = ap.parse_args()

    models = [m.strip() for m in args.models.split(",")]
    rows = [json.loads(l) for l in open(args.dataset) if json.loads(l).get("prompt")]
    print(f"{len(rows)} gradeable rows x {len(models)} models = "
          f"{len(rows) * len(models)} requests", file=sys.stderr)

    client = anthropic.Anthropic()

    requests = []
    meta = {}  # custom_id -> (model, row)
    for model in models:
        mk = safe_key(model)
        for i, row in enumerate(rows):
            cid = f"{mk}__r{i}"
            meta[cid] = (model, row)
            requests.append(Request(
                custom_id=cid,
                params=MessageCreateParamsNonStreaming(
                    model=model,
                    max_tokens=args.max_tokens,
                    messages=[{"role": "user", "content": row["prompt"]}],
                ),
            ))

    print(f"Submitting batch of {len(requests)} requests...", file=sys.stderr)
    batch = client.messages.batches.create(requests=requests)
    print(f"batch id: {batch.id} -- polling...", file=sys.stderr)

    while True:
        b = client.messages.batches.retrieve(batch.id)
        print(f"  status={b.processing_status} counts={b.request_counts}", file=sys.stderr)
        if b.processing_status == "ended":
            break
        time.sleep(30)

    out_files = {}
    n_ok = {m: 0 for m in models}
    n_total = {m: 0 for m in models}
    for result in client.messages.batches.results(batch.id):
        model, row = meta[result.custom_id]
        mk = safe_key(model)
        if mk not in out_files:
            path = os.path.join(args.out_dir, f"predictions_{mk}.jsonl")
            out_files[mk] = open(path, "w")

        n_total[model] += 1
        if result.result.type != "succeeded":
            pred = {"rule_id": row["rule_id"], "stig_id": row["stig_id"], "model": model,
                    "generated_script": "", "extracted_ok": False,
                    "raw_response": f"BATCH_ERROR: {result.result.type}"}
        else:
            msg = result.result.message
            raw = next((b.text for b in msg.content if b.type == "text"), "")
            script = extract_bash(raw)
            fenced = "```bash" in raw or "```sh" in raw or "```" in raw
            pred = {"rule_id": row["rule_id"], "stig_id": row["stig_id"], "model": model,
                    "generated_script": script, "extracted_ok": bool(script) and fenced,
                    "raw_response": raw}
            n_ok[model] += int(pred["extracted_ok"])
        out_files[mk].write(json.dumps(pred) + "\n")

    for f in out_files.values():
        f.close()

    print("\n==== SUMMARY ====", file=sys.stderr)
    for model in models:
        print(f"{model}: {n_ok[model]}/{n_total[model]} cleanly extracted -> "
              f"predictions_{safe_key(model)}.jsonl", file=sys.stderr)


if __name__ == "__main__":
    main()
