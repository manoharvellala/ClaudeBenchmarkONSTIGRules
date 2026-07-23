#!/usr/bin/env python3
"""
Leakage-generalization check: author the same leak-free task prompts as
build_dataset.py's generate_prompts(), but with GPT-4o instead of Claude.

Reuses the IDENTICAL system prompt, few-shot examples, JSON schema, and
leaked() detector from build_dataset.py -- only the authoring model differs.
If a completely different model, trained by a different lab, independently
produces prompts that also don't leak the mechanism, that's evidence the
leak-free design is a property of the task specification, not an artifact
of Claude's specific behavior.

Only rewrites task_prompt/prompt/objective/prompt_leak_tokens/authored_by for
the same 215 rows-with-reference_bash as the original dataset.jsonl -- every
other field (rule_id, reboot_required, severity, initial_state, ...) is
carried over unchanged, so the 168-rule scoreable pool / 151 denominator
structure is identical between the two prompt sets.

Usage:
    export OPENAI_API_KEY=sk-...
    python3 benchmark/generate_prompts_gpt.py \
        --in benchmark/dataset.jsonl --out benchmark/dataset_gpt4o_authored.jsonl \
        --model gpt-4o
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from build_dataset import GENERATOR_SYSTEM, GENERATOR_FEWSHOT, GENERATOR_SCHEMA, \
    OUTPUT_FORMAT_INSTRUCTION, leaked  # noqa: E402

try:
    from openai import OpenAI
except ImportError:
    sys.exit("pip install openai")


def to_chat_messages(user_content):
    """GENERATOR_FEWSHOT is Anthropic-style {role, content:str}; identical shape
    works unchanged as OpenAI chat messages."""
    msgs = [{"role": "system", "content": GENERATOR_SYSTEM}]
    msgs.extend(GENERATOR_FEWSHOT)
    msgs.append({"role": "user", "content": user_content})
    return msgs


def author_one(client, model, row):
    user = (
        f"TITLE: {row['title']}\n"
        f"SEVERITY: {row['severity']}\n"
        f"RATIONALE: {row['rationale']}\n"
        f"DESCRIPTION: {row['description'][:1200]}"
    )
    resp = client.chat.completions.create(
        model=model,
        max_completion_tokens=1200,
        messages=to_chat_messages(user),
        response_format={
            "type": "json_schema",
            "json_schema": {"name": "task_prompt_gen", "schema": GENERATOR_SCHEMA, "strict": True},
        },
    )
    text = resp.choices[0].message.content or ""
    obj = json.loads(text)
    return obj["task_prompt"], obj["objective"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="infile", default="benchmark/dataset.jsonl")
    ap.add_argument("--out", dest="outfile", default="benchmark/dataset_gpt4o_authored.jsonl")
    ap.add_argument("--model", default="gpt-4o")
    ap.add_argument("--limit", type=int, default=0, help="0 = all rows-with-reference_bash")
    args = ap.parse_args()

    client = OpenAI()
    rows = [json.loads(l) for l in open(args.infile)]

    done = {}
    if os.path.exists(args.outfile):
        for l in open(args.outfile):
            r = json.loads(l)
            done[r["rule_id"]] = r

    gen_rows = [r for r in rows if r.get("reference_bash")]
    print(f"{len(rows)} total rows; {len(gen_rows)} have reference_bash (need a prompt); "
          f"{len(done)} already authored.", file=sys.stderr)

    leak_flags = 0
    n_new = 0
    out_rows = []
    to_author_ids = {r["rule_id"] for r in gen_rows if r["rule_id"] not in done}
    if args.limit:
        to_author_ids = set(list(to_author_ids)[:args.limit])

    for r in rows:
        rid = r["rule_id"]
        if rid in done:
            out_rows.append(done[rid])
            if done[rid].get("prompt_leak_tokens"):
                leak_flags += 1
            continue
        if not r.get("reference_bash") or rid not in to_author_ids:
            out_rows.append(r)  # no reference fix to grade against, or outside --limit
            continue

        task = objective = None
        for attempt in range(3):
            try:
                task, objective = author_one(client, args.model, r)
                break
            except Exception as e:
                print(f"  {rid}: attempt {attempt+1} error: {e}", file=sys.stderr)
                time.sleep(2 ** attempt)

        row = dict(r)
        if task is None:
            row["task_prompt"] = None
            row["prompt"] = None
            row["objective"] = None
            row["prompt_leak_tokens"] = None
        else:
            row["task_prompt"] = task
            row["prompt"] = task + OUTPUT_FORMAT_INSTRUCTION
            row["objective"] = objective
            hits = leaked(task, row.get("reference_bash"))
            row["prompt_leak_tokens"] = hits
            if hits:
                leak_flags += 1
                print(f"  {rid}: possible leak -> {hits}", file=sys.stderr)
        row["authored_by"] = args.model
        out_rows.append(row)
        n_new += 1

        # persist incrementally so a crash doesn't lose progress
        with open(args.outfile, "w") as f:
            for rr in out_rows:
                f.write(json.dumps(rr) + "\n")
        print(f"[{len(done) + n_new}/{len(gen_rows)}] {rid}: authored", file=sys.stderr)

    n_with_prompt = sum(1 for r in out_rows if r.get("prompt"))
    print(f"\nDone. {n_new} newly authored this run.", file=sys.stderr)
    print(f"{n_with_prompt}/{len(gen_rows)} rows-with-reference_bash have a prompt "
          f"(compare to original's 215/215).", file=sys.stderr)
    print(f"Flagged for possible leakage: {leak_flags}/{n_with_prompt} "
          f"(compare to original's 2/215).", file=sys.stderr)
    print(f"-> {args.outfile}", file=sys.stderr)


if __name__ == "__main__":
    main()
