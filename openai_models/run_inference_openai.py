#!/usr/bin/env python3
"""
Run STIG benchmark inference with an OpenAI model.

Usage:
    export OPENAI_API_KEY=sk-...
    python3 run_inference_openai.py --model gpt-4o --out predictions_gpt4o.jsonl
    python3 run_inference_openai.py --model o4-mini --out predictions_o4mini.jsonl
    python3 run_inference_openai.py --model gpt-4o --limit 5 --out test.jsonl  # smoke test

Resumable: re-run the same command and it skips rules already in the output file.
Pure stdlib + openai package. No other dependencies.
"""
import argparse
import json
import os
import re
import sys
import time

try:
    from openai import OpenAI
except ImportError:
    sys.exit("Install the OpenAI client first:  pip install openai")

DATASET = os.path.join(os.path.dirname(__file__), "dataset.jsonl")


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


def solve(client, model, prompt, max_tokens, temperature, reasoning_effort):
    kwargs = dict(
        model=model,
        max_tokens=max_tokens,
        messages=[{"role": "user", "content": prompt}],
    )
    # o-series models use temperature=1 and support reasoning_effort
    if model.startswith("o"):
        kwargs["temperature"] = 1
        if reasoning_effort:
            kwargs["reasoning_effort"] = reasoning_effort
    else:
        kwargs["temperature"] = temperature

    resp = client.chat.completions.create(**kwargs)
    return resp.choices[0].message.content or ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="gpt-4o",
                    help="OpenAI model id (default: gpt-4o)")
    ap.add_argument("--dataset", default=DATASET)
    ap.add_argument("--out", default=None,
                    help="Output jsonl path (default: predictions_<model>.jsonl)")
    ap.add_argument("--limit", type=int, default=None,
                    help="Only score first N rules (smoke test)")
    ap.add_argument("--max-tokens", type=int, default=2048)
    ap.add_argument("--temperature", type=float, default=0.0)
    ap.add_argument("--reasoning-effort", default=None,
                    help="For o-series: low|medium|high (default: medium for o-series)")
    ap.add_argument("--api-key", default=None,
                    help="OpenAI API key (default: $OPENAI_API_KEY)")
    args = ap.parse_args()

    api_key = args.api_key or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        sys.exit("Set OPENAI_API_KEY or pass --api-key")

    # default reasoning effort for o-series
    reasoning_effort = args.reasoning_effort
    if reasoning_effort is None and args.model.startswith("o"):
        reasoning_effort = "medium"

    safe_name = args.model.replace("/", "_").replace("-", "_").replace(".", "_")
    out_path = args.out or f"predictions_{safe_name}.jsonl"

    client = OpenAI(api_key=api_key)

    # load dataset
    rows = [json.loads(l) for l in open(args.dataset) if json.loads(l).get("prompt")]
    if args.limit:
        rows = rows[:args.limit]
    print(f"{len(rows)} gradeable prompts in {args.dataset}")

    # load already-done rule_ids for resumability
    done = set()
    if os.path.exists(out_path):
        for l in open(out_path):
            try:
                done.add(json.loads(l)["rule_id"])
            except Exception:
                pass
    remaining = [r for r in rows if r["rule_id"] not in done]
    print(f"Resuming: {len(done)} already done, {len(remaining)} remaining.")

    out_f = open(out_path, "a")
    clean = total = 0

    for i, row in enumerate(remaining, start=len(done) + 1):
        rule_id = row["rule_id"]
        prompt = row["prompt"]
        response = ""
        for attempt in range(3):
            try:
                response = solve(client, args.model, prompt,
                                 args.max_tokens, args.temperature, reasoning_effort)
                break
            except Exception as e:
                print(f"  attempt {attempt+1} error: {e}")
                time.sleep(2 ** attempt)

        script = extract_bash(response)
        fenced = bool(re.search(r"```", response))
        n = len(script)
        tag = "fenced=True" if fenced else "fenced=False"
        print(f"[{i}/{len(rows)}] {row.get('stig_id','')} {rule_id}: extracted {n} chars ({tag})")

        record = {
            "rule_id": rule_id,
            "stig_id": row.get("stig_id", ""),
            "model": args.model,
            "prompt": prompt,
            "response": response,
            "generated_script": script,
        }
        out_f.write(json.dumps(record) + "\n")
        out_f.flush()
        total += 1
        if fenced and n > 0:
            clean += 1

    out_f.close()
    print(f"\nTotal predictions: {len(done)+total} | cleanly extracted: {clean}/{total} new")
    print(f"Predictions -> {out_path}")
    print(f"\nNext: copy {out_path} to the RHEL-8 scoring box and run score_remediations.py + compute_scores.py")


if __name__ == "__main__":
    main()
