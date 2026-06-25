#!/usr/bin/env python3
"""
Standalone STIG-benchmark inference for an open-source model served by vLLM
(or any OpenAI-compatible endpoint: Ollama, TGI, etc.).

Self-contained: needs only the `openai` package and `dataset.jsonl` in this folder.
It feeds each benchmark prompt to the model, extracts the bash script, and writes
predictions_<model>.jsonl — the exact same artifact the Claude run produces, so it
is scored by the identical score_remediations.py on the RHEL-8 box.

The model gets ONLY the prompt (no system prompt) so we measure its own ability.

Usage (after vLLM is serving on :8000):
    python3 run_inference_qwen.py \
        --base-url http://localhost:8000/v1 \
        --model Qwen/Qwen2.5-Coder-7B-Instruct \
        --out predictions_qwen25coder7b.jsonl

    python3 run_inference_qwen.py --limit 5 ...   # quick smoke test
"""
import argparse
import json
import os
import re
import sys
import time


def extract_bash(response_text):
    """Pull the bash script from a model reply. Tolerant:
    ```bash fence -> any ``` fence -> raw text fallback."""
    if not response_text:
        return ""
    m = re.findall(r"```(?:bash|sh)\s*\n(.*?)```", response_text, re.DOTALL)
    if m:
        return max(m, key=len).strip()
    m = re.findall(r"```\s*\n?(.*?)```", response_text, re.DOTALL)
    if m:
        return max(m, key=len).strip()
    return response_text.strip()  # no fence — assume the whole reply is the script


def solve(client, model, prompt, max_tokens, temperature):
    """Call the OpenAI-compatible endpoint with just the task prompt."""
    resp = client.chat.completions.create(
        model=model,
        max_tokens=max_tokens,
        temperature=temperature,
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.choices[0].message.content or ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="dataset.jsonl")
    ap.add_argument("--model", default="Qwen/Qwen2.5-Coder-7B-Instruct",
                    help="must match the model id vLLM was started with")
    ap.add_argument("--base-url", default="http://localhost:8000/v1")
    ap.add_argument("--api-key", default="EMPTY", help="vLLM ignores it; any string works")
    ap.add_argument("--temperature", type=float, default=0.0,
                    help="0.0 = greedy/deterministic for reproducible benchmarking")
    ap.add_argument("--max-tokens", type=int, default=2500)
    ap.add_argument("--limit", type=int, default=0, help="0 = all rules")
    ap.add_argument("--out", default="predictions_qwen.jsonl")
    ap.add_argument("--report", default="sample_predictions_qwen.md")
    ap.add_argument("--wait-for-server", type=int, default=600,
                    help="seconds to wait for the vLLM server to come up")
    args = ap.parse_args()

    try:
        from openai import OpenAI
    except ImportError:
        sys.exit("Missing dependency: pip install openai")

    rows = [json.loads(l) for l in open(args.dataset)]
    rows = [r for r in rows if r.get("prompt")]      # only rows we can grade
    if args.limit:
        rows = rows[:args.limit]
    print(f"{len(rows)} gradeable prompts in {args.dataset}", flush=True)

    # RESUME: skip rules already present in the output file
    done = set()
    if os.path.exists(args.out):
        for l in open(args.out):
            try:
                done.add(json.loads(l)["rule_id"])
            except Exception:
                pass
    todo = [r for r in rows if r["rule_id"] not in done]
    if done:
        print(f"Resuming: {len(done)} already done, {len(todo)} remaining.", flush=True)

    client = OpenAI(base_url=args.base_url, api_key=args.api_key)

    # wait for the vLLM server to be reachable
    deadline = time.time() + args.wait_for_server
    while True:
        try:
            client.models.list()
            break
        except Exception as e:
            if time.time() > deadline:
                sys.exit(f"vLLM server not reachable at {args.base_url}: {e}")
            print(f"waiting for vLLM server at {args.base_url} ...", flush=True)
            time.sleep(5)

    out_f = open(args.out, "a")          # append so partial progress is never lost
    n_ok = 0
    try:
        for i, r in enumerate(todo, 1):
            for attempt in range(3):
                try:
                    raw = solve(client, args.model, r["prompt"], args.max_tokens, args.temperature)
                    break
                except Exception as e:
                    if attempt == 2:
                        print(f"  ! failed {r['rule_id']} after 3 tries: {e}", flush=True)
                        raw = ""
                    else:
                        time.sleep(3)
            script = extract_bash(raw)
            fenced = "```" in raw
            pred = {
                "rule_id": r["rule_id"], "stig_id": r["stig_id"], "model": args.model,
                "generated_script": script, "extracted_ok": bool(script) and fenced,
                "raw_response": raw,
            }
            out_f.write(json.dumps(pred) + "\n")
            out_f.flush()
            n_ok += int(pred["extracted_ok"])
            print(f"[{len(done)+i}/{len(rows)}] {r['stig_id']} {r['rule_id']}: "
                  f"extracted {len(script)} chars (fenced={fenced})", flush=True)
    finally:
        out_f.close()

    # rebuild the readable report
    preds = [json.loads(l) for l in open(args.out)]
    ds = {r["rule_id"]: r for r in rows}
    md = [f"# Inference predictions — `{args.model}`\n", f"{len(preds)} rules.\n"]
    for p in preds:
        r = ds.get(p["rule_id"], {})
        md += [
            f"\n---\n\n## {p['stig_id']} — `{p['rule_id']}`\n",
            f"**Prompt:** {r.get('task_prompt','')}\n",
            f"**Model-generated script:**\n```bash\n{p['generated_script']}\n```\n",
        ]
    with open(args.report, "w") as f:
        f.write("\n".join(md))

    ok_total = sum(1 for p in preds if p.get("extracted_ok"))
    print(f"\nTotal predictions: {len(preds)} | cleanly extracted: {ok_total}", flush=True)
    print(f"Predictions -> {args.out}\nReport -> {args.report}", flush=True)
    print("\nNext: copy the predictions file to the RHEL-8 scoring box and run "
          "score_remediations.py exactly as for the Claude run.", flush=True)


if __name__ == "__main__":
    main()
