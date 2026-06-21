#!/usr/bin/env python3
"""
Quick dry-run of the prompt generator on a few DIVERSE failed rules.
Writes a human-readable report to benchmark/sample_prompts.md so you can
inspect the generated task prompts and the leakage check before running the
full batch.

Usage:
    export ANTHROPIC_API_KEY=sk-ant-...
    python3 benchmark/test_generate.py            # 5 diverse rules
    python3 benchmark/test_generate.py 8          # N rules
"""
import sys, json, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import anthropic
from build_dataset import (GENERATOR_SYSTEM, GENERATOR_FEWSHOT, OUTPUT_FORMAT_INSTRUCTION,
                           parse_results, load_stig_map, leaked)

N = int(sys.argv[1]) if len(sys.argv) > 1 else 5
RESULTS_XML = os.path.join(os.path.dirname(__file__), "..", "stig-results.xml")
OUT_MD = os.path.join(os.path.dirname(__file__), "sample_prompts.md")

rules, results = parse_results(RESULTS_XML)
stig_map = load_stig_map()

# pick failed rules with a bash fix, spread across different rule-type prefixes
buckets = ["sysctl_", "sshd_", "package_", "service_", "file_", "audit_",
           "accounts_", "grub2_", "dconf_", "mount_"]
chosen, seen_prefix = [], set()
fails = [m for full, m in rules.items()
         if results.get(full) == "fail" and m["reference_bash"]]
# one per bucket first
for b in buckets:
    for m in fails:
        if m["rule_id"].startswith(b) and b not in seen_prefix:
            m["stig_id"] = stig_map.get(m["rule_id"])
            chosen.append(m); seen_prefix.add(b); break
    if len(chosen) >= N:
        break
# top up with anything else
for m in fails:
    if len(chosen) >= N:
        break
    if m not in chosen:
        m["stig_id"] = stig_map.get(m["rule_id"])
        chosen.append(m)
chosen = chosen[:N]

client = anthropic.Anthropic()
lines = ["# Sample generated benchmark prompts\n",
         f"Dry run over {len(chosen)} diverse failed STIG rules.\n"]
clean = 0
for m in chosen:
    user = (f"TITLE: {m['title']}\nSEVERITY: {m['severity']}\n"
            f"RATIONALE: {m['rationale']}\nDESCRIPTION: {m['description'][:1200]}")
    resp = client.messages.create(
        model="claude-opus-4-8", max_tokens=1200,
        system=GENERATOR_SYSTEM,
        messages=GENERATOR_FEWSHOT + [{"role": "user", "content": user}],
    )
    text = next((b.text for b in resp.content if b.type == "text"), "")
    try:
        obj = json.loads(text)
    except Exception:
        obj = {"task_prompt": text, "objective": "(unparsed)"}
    task = obj.get("task_prompt", "")
    full_prompt = task + OUTPUT_FORMAT_INSTRUCTION   # exactly what a model under test receives
    hits = leaked(task, m["reference_bash"])
    if not hits:
        clean += 1
    lines += [
        f"\n---\n\n## {m.get('stig_id')} — `{m['rule_id']}`  (severity: {m['severity']})\n",
        f"**Source title:** {m['title']}\n",
        f"**Full prompt fed to model under test:**\n\n> "
        + full_prompt.replace("\n", "\n> ") + "\n",
        f"**Objective:** {obj.get('objective')}\n",
        f"**Leak check:** {'✅ CLEAN' if not hits else '⚠️ FLAGGED → ' + str(hits)}\n",
        "**Reference bash (hidden answer):**\n```bash\n"
        + (m["reference_bash"] or "")[:600] + "\n```\n",
    ]
    print(f"[{m.get('stig_id')}] {m['rule_id']}: "
          f"{'CLEAN' if not hits else 'FLAGGED ' + str(hits)}")

lines.insert(2, f"\n**{clean}/{len(chosen)} prompts passed the leak check.**\n")
with open(OUT_MD, "w") as f:
    f.write("\n".join(lines))
print(f"\nReport written to: {OUT_MD}")
