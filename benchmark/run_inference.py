#!/usr/bin/env python3
"""
Inference phase of the STIG benchmark.

Feeds each benchmark `prompt` to a model-under-test, extracts the bash script
from the reply, and saves predictions. This is the artifact the (separate)
execution/scoring phase later runs on a VM.

The model is given ONLY the prompt (no helper system prompt) so we measure the
model's own security knowledge + coding ability.

Usage:
    export ANTHROPIC_API_KEY=sk-ant-...
    python3 benchmark/run_inference.py --limit 5          # quick test (5 rules)
    python3 benchmark/run_inference.py                    # all rules
    python3 benchmark/run_inference.py --model claude-sonnet-4-6 --out benchmark/predictions_sonnet.jsonl
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import anthropic
from build_dataset import extract_bash


def solve_claude(client, model, prompt, max_tokens=2500):
    """The 'solver': call the model under test with just the task prompt."""
    resp = client.messages.create(
        model=model,
        max_tokens=max_tokens,
        messages=[{"role": "user", "content": prompt}],
    )
    return next((b.text for b in resp.content if b.type == "text"), "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="benchmark/dataset.jsonl")
    ap.add_argument("--model", default="claude-opus-4-8")
    ap.add_argument("--limit", type=int, default=0, help="0 = all rules")
    ap.add_argument("--out", default="benchmark/predictions.jsonl")
    ap.add_argument("--report", default="benchmark/sample_predictions.md")
    args = ap.parse_args()

    rows = [json.loads(l) for l in open(args.dataset)]
    rows = [r for r in rows if r.get("prompt")]          # only rows we can grade
    if args.limit:
        rows = rows[:args.limit]

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

    client = anthropic.Anthropic()
    out_f = open(args.out, "a")          # append, so partial progress is never lost
    n_ok = 0
    try:
        for i, r in enumerate(todo, 1):
            try:
                raw = solve_claude(client, args.model, r["prompt"])
            except anthropic.BadRequestError as e:
                if "credit balance" in str(e).lower():
                    print(f"\nSTOPPED: out of API credits. Saved {len(done)+i-1} predictions "
                          f"to {args.out}. Top up credits and re-run the SAME command to resume.",
                          flush=True)
                    break
                if "content filtering" in str(e).lower():
                    print(f"[{len(done)+i}/{len(rows)}] {r['stig_id']} {r['rule_id']}: "
                          f"blocked by content filtering policy, recording as empty", flush=True)
                    raw = ""
                else:
                    raise
            script = extract_bash(raw)
            fenced = "```bash" in raw or "```sh" in raw or "```" in raw
            pred = {
                "rule_id": r["rule_id"], "stig_id": r["stig_id"], "model": args.model,
                "generated_script": script, "extracted_ok": bool(script) and fenced,
                "raw_response": raw,
            }
            out_f.write(json.dumps(pred) + "\n")
            out_f.flush()                # persist immediately
            n_ok += int(pred["extracted_ok"])
            print(f"[{len(done)+i}/{len(rows)}] {r['stig_id']} {r['rule_id']}: "
                  f"extracted {len(script)} chars (fenced={fenced})", flush=True)
    finally:
        out_f.close()

    # rebuild the readable report from the (possibly partial) predictions file
    preds = [json.loads(l) for l in open(args.out)]
    ds = {r["rule_id"]: r for r in rows}
    md = [f"# Inference predictions — `{args.model}`\n", f"{len(preds)} rules.\n"]
    for p in preds:
        r = ds.get(p["rule_id"], {})
        md += [
            f"\n---\n\n## {p['stig_id']} — `{p['rule_id']}`\n",
            f"**Prompt:** {r.get('task_prompt','')}\n",
            f"**Model-generated script:**\n```bash\n{p['generated_script']}\n```\n",
            f"**Reference fix:**\n```bash\n" + (r.get('reference_bash') or '')[:700] + "\n```\n",
        ]
    with open(args.report, "w") as f:
        f.write("\n".join(md))

    ok_total = sum(1 for p in preds if p.get("extracted_ok"))
    print(f"\nTotal predictions: {len(preds)} | cleanly extracted: {ok_total}", flush=True)
    print(f"Predictions -> {args.out}\nReport -> {args.report}", flush=True)


if __name__ == "__main__":
    main()
