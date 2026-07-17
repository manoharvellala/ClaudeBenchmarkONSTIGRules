#!/usr/bin/env python3
"""
STIG benchmark inference for Llama/CodeLlama models via Ollama (OpenAI-compatible API).

Usage:
    # Start Ollama first:
    ollama serve &
    ollama pull codellama:34b-instruct-fp16

    # Then run inference:
    python3 run_inference_llama.py \
        --model codellama:34b-instruct-fp16 \
        --out predictions_codellama_34b_fp16.jsonl

    python3 run_inference_llama.py --limit 5 ...   # smoke test

Resumable: re-run the same command and it skips already-done rules.
"""
import argparse
import json
import os
import re
import sys
import time

DATASET_DEFAULT = os.path.join(os.path.dirname(__file__), "..", "benchmark", "dataset.jsonl")


def strip_think_blocks(text):
    """Remove <think>...</think> reasoning traces some models (GLM, DeepSeek-R1-style) emit."""
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()


def extract_bash(response_text):
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


def solve(client, model, prompt, max_tokens, temperature, seed=None):
    kwargs = dict(
        model=model,
        max_tokens=max_tokens,
        temperature=temperature,
        messages=[{"role": "user", "content": prompt}],
    )
    if seed is not None:
        kwargs["seed"] = seed
    resp = client.chat.completions.create(**kwargs)
    return resp.choices[0].message.content or ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default=DATASET_DEFAULT)
    ap.add_argument("--model", default="codellama:34b-instruct-fp16")
    ap.add_argument("--base-url", default="http://localhost:11434/v1")
    ap.add_argument("--api-key", default="ollama")
    ap.add_argument("--temperature", type=float, default=0.0)
    ap.add_argument("--seed", type=int, default=None,
                    help="per-run sampling seed; omit for deterministic temp=0 runs")
    ap.add_argument("--max-tokens", type=int, default=2048)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--out", default=None)
    ap.add_argument("--wait-for-server", type=int, default=300)
    args = ap.parse_args()

    try:
        from openai import OpenAI
    except ImportError:
        sys.exit("pip install openai")

    safe_name = re.sub(r"[^a-z0-9]+", "_", args.model.lower()).strip("_")
    out_path = args.out or f"predictions_{safe_name}.jsonl"

    rows = [json.loads(l) for l in open(args.dataset)]
    rows = [r for r in rows if r.get("prompt")]
    if args.limit:
        rows = rows[:args.limit]
    print(f"{len(rows)} gradeable prompts", flush=True)

    done = set()
    if os.path.exists(out_path):
        for l in open(out_path):
            try:
                done.add(json.loads(l)["rule_id"])
            except Exception:
                pass
    todo = [r for r in rows if r["rule_id"] not in done]
    if done:
        print(f"Resuming: {len(done)} done, {len(todo)} remaining.", flush=True)

    client = OpenAI(base_url=args.base_url, api_key=args.api_key)

    deadline = time.time() + args.wait_for_server
    while True:
        try:
            client.models.list()
            print("Ollama server is up.", flush=True)
            break
        except Exception as e:
            if time.time() > deadline:
                sys.exit(f"Ollama not reachable at {args.base_url}: {e}")
            print(f"waiting for Ollama at {args.base_url} ...", flush=True)
            time.sleep(5)

    out_f = open(out_path, "a")
    try:
        for i, r in enumerate(todo, 1):
            raw = ""
            for attempt in range(3):
                try:
                    raw = solve(client, args.model, r["prompt"],
                                args.max_tokens, args.temperature, args.seed)
                    break
                except Exception as e:
                    if attempt == 2:
                        print(f"  ! failed {r['rule_id']}: {e}", flush=True)
                    else:
                        time.sleep(3)

            script = extract_bash(raw)
            fenced = "```" in strip_think_blocks(raw)
            pred = {
                "rule_id": r["rule_id"],
                "stig_id": r.get("stig_id", ""),
                "model": args.model,
                "generated_script": script,
                "extracted_ok": bool(script) and fenced,
                "has_think_block": bool(re.search(r"<think>", raw)),
                "raw_response": raw,
            }
            out_f.write(json.dumps(pred) + "\n")
            out_f.flush()
            print(
                f"[{len(done)+i}/{len(rows)}] {r.get('stig_id','')} {r['rule_id']}: "
                f"extracted {len(script)} chars (fenced={fenced})",
                flush=True,
            )
    finally:
        out_f.close()

    ok = sum(1 for l in open(out_path) for p in [json.loads(l)] if p.get("extracted_ok"))
    print(f"\nDone. Total: {len(done)+len(todo)} | cleanly extracted: {ok}", flush=True)
    print(f"Predictions -> {out_path}", flush=True)


if __name__ == "__main__":
    main()
