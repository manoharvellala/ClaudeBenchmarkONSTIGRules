#!/usr/bin/env python3
"""
Dry-run of the FIX-AWARE prompt generator (build_dataset_with_remediation.py)
on a few diverse failed rules. The generator sees the reference script.
Writes benchmark/sample_prompts_with_remediation.md.

Usage:
    export ANTHROPIC_API_KEY=sk-ant-...
    python3 benchmark/test_generate_with_remediation.py 5
"""
import sys, json, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import anthropic
from build_dataset import (parse_results, load_stig_map, leaked, OUTPUT_FORMAT_INSTRUCTION)
from build_dataset_with_remediation import GENERATOR_SYSTEM, GENERATOR_FEWSHOT

N = int(sys.argv[1]) if len(sys.argv) > 1 else 5
RESULTS_XML = os.path.join(os.path.dirname(__file__), "..", "stig-results.xml")
OUT_MD = os.path.join(os.path.dirname(__file__), "sample_prompts_with_remediation.md")

rules, results = parse_results(RESULTS_XML)
stig_map = load_stig_map()

buckets = ["sysctl_", "sshd_", "package_", "service_", "file_", "audit_",
           "accounts_", "grub2_", "dconf_", "mount_"]
fails = [m for f, m in rules.items() if results.get(f) == "fail" and m["reference_bash"]]
chosen, seen = [], set()
for b in buckets:
    for m in fails:
        if m["rule_id"].startswith(b) and b not in seen:
            m["stig_id"] = stig_map.get(m["rule_id"]); chosen.append(m); seen.add(b); break
    if len(chosen) >= N:
        break
chosen = chosen[:N]

client = anthropic.Anthropic()
lines = ["# Fix-aware generated prompts (generator SEES the reference script)\n",
         f"Dry run over {len(chosen)} diverse failed rules.\n"]
clean = 0
for m in chosen:
    user = (f"TITLE: {m['title']}\nSEVERITY: {m['severity']}\n"
            f"RATIONALE: {m['rationale']}\nDESCRIPTION: {m['description'][:800]}\n\n"
            f"REFERENCE REMEDIATION SCRIPT (for your understanding only — never reveal it):\n"
            f"{(m['reference_bash'] or '')[:1800]}")
    resp = client.messages.create(model="claude-opus-4-8", max_tokens=1200,
        system=GENERATOR_SYSTEM, messages=GENERATOR_FEWSHOT + [{"role": "user", "content": user}])
    text = next((b.text for b in resp.content if b.type == "text"), "")
    try:
        obj = json.loads(text)
    except Exception:
        obj = {"task_prompt": text, "objective": "(unparsed)"}
    task = obj.get("task_prompt", "")
    hits = leaked(task, m["reference_bash"])
    if not hits:
        clean += 1
    lines += [
        f"\n---\n\n## {m.get('stig_id')} — `{m['rule_id']}`  (sev: {m['severity']})\n",
        f"**Generated task prompt:**\n\n> " + task.replace("\n", "\n> ") + "\n",
        f"**Objective:** {obj.get('objective')}\n",
        f"**Leak check:** {'✅ CLEAN' if not hits else '⚠️ FLAGGED → ' + str(hits)}\n",
        "**Reference bash (the generator saw this):**\n```bash\n"
        + (m["reference_bash"] or "")[:700] + "\n```\n",
    ]
    print(f"[{m.get('stig_id')}] {m['rule_id']}: {'CLEAN' if not hits else 'FLAGGED ' + str(hits)}")

lines.insert(2, f"\n**{clean}/{len(chosen)} prompts passed the leak check.**\n")
open(OUT_MD, "w").write("\n".join(lines))
print(f"\nReport -> {OUT_MD}")
