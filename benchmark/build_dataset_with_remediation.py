#!/usr/bin/env python3
"""
Fix-AWARE variant of the dataset builder.

Difference from build_dataset.py: the prompt generator is ALSO given the rule's
reference remediation script, so it understands the exact end state the OVAL
check verifies and can make the task statement precise and complete. The script
is provided for understanding only — the generator is instructed never to reveal
its paths/directives/commands, and the programmatic leaked() check still guards
against accidental leakage (anchoring risk is higher here, so the check matters
more).

Outputs the same row schema as build_dataset.py, to benchmark/dataset_with_remediation.jsonl.

Usage:
    export ANTHROPIC_API_KEY=sk-ant-...
    python3 benchmark/build_dataset_with_remediation.py --results stig-results.xml --extract-only
    python3 benchmark/build_dataset_with_remediation.py --results stig-results.xml --generate
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# reuse all the shared machinery from the base builder
from build_dataset import (parse_results, load_stig_map, leaked,
                           OUTPUT_FORMAT_INSTRUCTION, GENERATOR_SCHEMA)

# ----------------------------------------------------------------------------
#  Fix-aware meta-prompt: the generator SEES the reference script and must
#  describe what it achieves WITHOUT revealing how.
# ----------------------------------------------------------------------------
GENERATOR_SYSTEM = """\
You are a senior security-benchmark author. You are given a Linux hardening rule \
AND its reference remediation script (the known-correct fix). Using your full \
understanding of exactly what that script accomplishes, write ONE self-contained \
task statement that tests whether a DIFFERENT language model can INDEPENDENTLY \
produce a correct remediation — the way a coding-interview question tests a candidate.

The reference script is provided ONLY so you know the precise required end state. \
You must NOT reveal or paraphrase its implementation.

Treat it like writing a coding problem: specify WHAT the solution must achieve and \
WHY, and never reveal HOW.

The task statement MUST:
- State the security objective and the precise required end state — accurately \
reflecting everything the reference script ensures (e.g. if it also covers socket \
activation, future-installed kernels, a specific numeric value, or a graceful \
no-op when a component is absent, encode that in the requirement) — so there is \
exactly ONE compliant outcome, verifiable by an automated checker.
- Name the affected service / subsystem / component at a conceptual level \
(e.g. "the SSH server", "the system audit daemon", "the AIDE file-integrity tool").
- Include any required target VALUE or THRESHOLD that defines compliance.
- Briefly convey the threat or rationale.
- Require idempotency and persistence across reboots when relevant.
- Target Red Hat Enterprise Linux 8 and end by asking for a bash remediation script.

The task statement MUST NOT (copying from the reference script is the main risk — \
be vigilant):
- Contain any exact filesystem path, configuration directive/parameter key, or \
sysctl key (do NOT write e.g. "ClientAliveInterval", "kernel.dmesg_restrict", \
"/etc/ssh/sshd_config").
- Contain any shell command, package-manager invocation, or literal config line.
- Give step-by-step instructions or describe the editing mechanism.

Naming the component or a required value is allowed; naming the knob, path, or \
command is not. Keep it to one tight paragraph.

Respond ONLY with a JSON object: {"task_prompt": "...", "objective": "<one-line \
summary of what compliance achieves>"}.\
"""

# Few-shot: the user turn now INCLUDES the reference script; output stays leak-free.
GENERATOR_FEWSHOT = [
    {
        "role": "user",
        "content": (
            "TITLE: Restrict Access to Kernel Message Buffer\n"
            "SEVERITY: low\n"
            "RATIONALE: Unprivileged access to the kernel syslog can expose sensitive "
            "kernel address information.\n"
            "DESCRIPTION: Restrict access to the kernel message buffer.\n\n"
            "REFERENCE REMEDIATION SCRIPT (for your understanding only — never reveal it):\n"
            "sysctl_value=1\n"
            "if grep -q '^kernel.dmesg_restrict' /etc/sysctl.conf ; then\n"
            "  sed -i 's/^kernel.dmesg_restrict.*/kernel.dmesg_restrict = 1/' /etc/sysctl.conf\n"
            "else\n"
            "  echo 'kernel.dmesg_restrict = 1' >> /etc/sysctl.conf\n"
            "fi\n"
            "sysctl -w kernel.dmesg_restrict=1"
        ),
    },
    {
        "role": "assistant",
        "content": (
            '{"task_prompt": "On a RHEL 8 system, unprivileged users can currently read '
            "the kernel's message (ring) buffer, which can expose kernel memory addresses "
            "useful for local privilege-escalation exploits. Write an idempotent bash "
            "remediation script that restricts access to the kernel message buffer so that "
            "only privileged users can read it, applying the change at runtime and ensuring "
            'it persists across reboots.", '
            '"objective": "Only privileged users can read the kernel ring buffer, persistently."}'
        ),
    },
    {
        "role": "user",
        "content": (
            "TITLE: Disable debug-shell SystemD Service\n"
            "SEVERITY: medium\n"
            "RATIONALE: This prevents attackers with physical access from trivially "
            "bypassing security on the boot loader to gain a root shell.\n"
            "DESCRIPTION: The debug-shell service should be disabled.\n\n"
            "REFERENCE REMEDIATION SCRIPT (for your understanding only — never reveal it):\n"
            "systemctl stop debug-shell.service\n"
            "systemctl disable debug-shell.service\n"
            "systemctl mask debug-shell.service\n"
            "if systemctl list-unit-files debug-shell.socket; then\n"
            "  systemctl stop debug-shell.socket\n"
            "  systemctl mask debug-shell.socket\n"
            "fi"
        ),
    },
    {
        "role": "assistant",
        "content": (
            '{"task_prompt": "On a RHEL 8 system, ensure the systemd service that provides '
            "an unauthenticated root debug shell on a virtual console cannot be started — "
            "neither now nor after any future reboot — to stop an attacker with physical "
            "access from using it to obtain root. The service must be stopped and placed in "
            "a state where it can never be activated, and any companion socket-based "
            "activation for it must likewise be prevented. Write an idempotent bash "
            'remediation script that brings the system to this state persistently.", '
            '"objective": "The systemd debug-shell service (and its socket activation) is stopped and cannot be activated."}'
        ),
    },
]


def generate_prompts(rows, model="claude-opus-4-8"):
    """Author task prompts WITH the reference script as context, via the Batch API."""
    import anthropic
    from anthropic.types.message_create_params import MessageCreateParamsNonStreaming
    from anthropic.types.messages.batch_create_params import Request

    client = anthropic.Anthropic()
    by_cid, requests = {}, []
    for i, row in enumerate(rows):
        cid = f"r{i}"
        by_cid[cid] = row
        user = (
            f"TITLE: {row['title']}\n"
            f"SEVERITY: {row['severity']}\n"
            f"RATIONALE: {row['rationale']}\n"
            f"DESCRIPTION: {row['description'][:800]}\n\n"
            f"REFERENCE REMEDIATION SCRIPT (for your understanding only — never reveal it):\n"
            f"{(row['reference_bash'] or '')[:1800]}"
        )
        requests.append(Request(
            custom_id=cid,
            params=MessageCreateParamsNonStreaming(
                model=model,
                max_tokens=1200,
                system=[{"type": "text", "text": GENERATOR_SYSTEM,
                         "cache_control": {"type": "ephemeral"}}],
                messages=GENERATOR_FEWSHOT + [{"role": "user", "content": user}],
                output_config={"format": {"type": "json_schema", "schema": GENERATOR_SCHEMA}},
            ),
        ))

    print(f"Submitting fix-aware batch of {len(requests)} requests...", file=sys.stderr)
    batch = client.messages.batches.create(requests=requests)
    print(f"  batch id: {batch.id} — polling...", file=sys.stderr)

    import time
    while True:
        b = client.messages.batches.retrieve(batch.id)
        if b.processing_status == "ended":
            break
        time.sleep(30)

    leak_flags = 0
    for result in client.messages.batches.results(batch.id):
        row = by_cid.get(result.custom_id)
        if row is None or result.result.type != "succeeded":
            continue
        text = next((b.text for b in result.result.message.content if b.type == "text"), "")
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            continue
        task = obj.get("task_prompt", "")
        row["task_prompt"] = task
        row["prompt"] = task + OUTPUT_FORMAT_INSTRUCTION
        row["objective"] = obj.get("objective", "")
        hits = leaked(task, row.get("reference_bash"))
        row["prompt_leak_tokens"] = hits
        if hits:
            leak_flags += 1
    print(f"  done. prompts flagged for possible leakage: {leak_flags}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    ap.add_argument("--out", default="benchmark/dataset_with_remediation.jsonl")
    ap.add_argument("--include", choices=["fail", "selected", "all"], default="fail")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--extract-only", action="store_true")
    g.add_argument("--generate", action="store_true")
    args = ap.parse_args()

    rules, results = parse_results(args.results)
    stig_map = load_stig_map()
    keep = {"fail": {"fail"},
            "selected": {"fail", "pass", "notapplicable", "notchecked", "error"},
            "all": None}[args.include]

    rows = []
    for full, meta in rules.items():
        res = results.get(full)
        if keep is not None and res not in keep:
            continue
        row = dict(meta)
        row.pop("_full_id", None)
        row["product"] = "rhel8"
        row["initial_state"] = res
        row["stig_id"] = stig_map.get(meta["rule_id"])
        if row["stig_id"]:
            row["references"]["stigid"] = row["stig_id"]
        row["task_prompt"] = None
        row["prompt"] = None
        row["objective"] = None
        row["prompt_leak_tokens"] = None
        rows.append(row)

    has_bash = sum(1 for r in rows if r["reference_bash"])
    print(f"Selected {len(rows)} rules ({args.include}); {has_bash} have a bash reference fix.",
          file=sys.stderr)

    if args.generate:
        generate_prompts([r for r in rows if r["reference_bash"]])

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    print(f"Wrote {len(rows)} rows -> {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
