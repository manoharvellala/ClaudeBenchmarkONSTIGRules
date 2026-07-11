#!/usr/bin/env python3
"""
STIG benchmark inference for GLM-Z1 (and other GLM models) served by vLLM.

GLM-Z1 is a reasoning model: it emits <think>...</think> before the answer.
This script strips those blocks before extracting the bash script, so the
grader gets clean code regardless of how long the reasoning trace is.

Usage (after vLLM is serving on :8000):
    python3 run_inference_glm.py \
        --model THUDM/GLM-Z1-32B-0414 \
        --out predictions_glm_z1_32b.jsonl

    python3 run_inference_glm.py --limit 5 ...   # quick smoke test

Resumable: re-run the same command and it skips rules already in the output file.
"""
import argparse
import json
import os
import re
import sys
import time

DATASET_DEFAULT = os.path.join(os.path.dirname(__file__), "..", "benchmark", "dataset.jsonl")


def strip_think_blocks(text):
    """Remove <think>...</think> reasoning traces emitted by GLM-Z1."""
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()


def extract_bash(response_text):
    """Pull the bash script from a model reply.
    Strips GLM-Z1 think blocks first, then tries fenced code blocks."""
    if not response_text:
        return ""
    text = strip_think_blocks(response_text)
    m = re.findall(r"```(?:bash|sh)\s*\n(.*?)```", text, re.DOTALL)
    if m:
        return max(m, key=len).strip()
    m = re.findall(r"```\s*\n?(.*?)```", text, re.DOTALL)
    if m:
        return max(m, key=len).strip()
    return text.strip()


def solve(client, model, prompt, max_tokens, temperature):
    resp = client.chat.completions.create(
        model=model,
        max_tokens=max_tokens,
        temperature=temperature,
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.choices[0].message.content or ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default=DATASET_DEFAULT)
    ap.add_argument("--model", default="THUDM/GLM-Z1-32B-0414",
                    help="must match the model id vLLM was started with")
    ap.add_argument("--base-url", default="http://localhost:8000/v1")
    ap.add_argument("--api-key", default="EMPTY", help="vLLM ignores it; any string works")
    ap.add_argument("--temperature", type=float, default=0.0,
                    help="0.0 = greedy/deterministic for reproducible benchmarking")
    ap.add_argument("--max-tokens", type=int, default=4096,
                    help="GLM-Z1 think blocks can be long; 4096 gives plenty of room")
    ap.add_argument("--limit", type=int, default=0, help="0 = all 215 rules")
    ap.add_argument("--out", default=None,
                    help="Output jsonl (default: predictions_<safe_model_name>.jsonl)")
    ap.add_argument("--wait-for-server", type=int, default=600,
                    help="seconds to wait for vLLM to become reachable")
    args = ap.parse_args()

    try:
        from openai import OpenAI
    except ImportError:
        sys.exit("Missing dependency: pip install openai")

    safe_name = re.sub(r"[^a-z0-9]+", "_", args.model.lower()).strip("_")
    out_path = args.out or f"predictions_{safe_name}.jsonl"

    rows = [json.loads(l) for l in open(args.dataset)]
    rows = [r for r in rows if r.get("prompt")]
    if args.limit:
        rows = rows[:args.limit]
    print(f"{len(rows)} gradeable prompts in {args.dataset}", flush=True)

    done = set()
    if os.path.exists(out_path):
        for l in open(out_path):
            try:
                done.add(json.loads(l)["rule_id"])
            except Exception:
                pass
    todo = [r for r in rows if r["rule_id"] not in done]
    if done:
        print(f"Resuming: {len(done)} already done, {len(todo)} remaining.", flush=True)

    client = OpenAI(base_url=args.base_url, api_key=args.api_key)

    deadline = time.time() + args.wait_for_server
    while True:
        try:
            client.models.list()
            print("vLLM server is up.", flush=True)
            break
        except Exception as e:
            if time.time() > deadline:
                sys.exit(f"vLLM server not reachable at {args.base_url}: {e}")
            print(f"waiting for vLLM server at {args.base_url} ...", flush=True)
            time.sleep(5)

    out_f = open(out_path, "a")
    n_ok = 0
    try:
        for i, r in enumerate(todo, 1):
            raw = ""
            for attempt in range(3):
                try:
                    raw = solve(client, args.model, r["prompt"],
                                args.max_tokens, args.temperature)
                    break
                except Exception as e:
                    if attempt == 2:
                        print(f"  ! failed {r['rule_id']} after 3 tries: {e}", flush=True)
                    else:
                        time.sleep(3)

            script = extract_bash(raw)
            fenced = "```" in strip_think_blocks(raw)
            has_think = bool(re.search(r"<think>", raw))
            pred = {
                "rule_id": r["rule_id"],
                "stig_id": r.get("stig_id", ""),
                "model": args.model,
                "generated_script": script,
                "extracted_ok": bool(script) and fenced,
                "has_think_block": has_think,
                "raw_response": raw,
            }
            out_f.write(json.dumps(pred) + "\n")
            out_f.flush()
            n_ok += int(pred["extracted_ok"])
            print(
                f"[{len(done)+i}/{len(rows)}] {r.get('stig_id','')} {r['rule_id']}: "
                f"extracted {len(script)} chars (fenced={fenced}, think={has_think})",
                flush=True,
            )
    finally:
        out_f.close()

    total = len(done) + len(todo)
    ok_total = sum(1 for l in open(out_path)
                   for p in [json.loads(l)] if p.get("extracted_ok"))
    print(f"\nTotal predictions: {total} | cleanly extracted: {ok_total}", flush=True)
    print(f"Predictions -> {out_path}", flush=True)
    print(
        "\nNext: copy predictions file + dataset.jsonl + score_remediations.py "
        "to an AlmaLinux 8 VM and run score_remediations.py + compute_scores.py.",
        flush=True,
    )


if __name__ == "__main__":
    main()
