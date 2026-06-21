#!/usr/bin/env python3
"""
Build the STIG LLM-benchmark ground-truth dataset from an OpenSCAP results file.

Input:
  - stig-results.xml   an XCCDF Benchmark file that ALSO carries a <TestResult>
                       (produced by `oscap xccdf eval --results ...` with the STIG profile).
                       It contains, per rule: title/description/rationale/references,
                       the rendered <fix> remediations, the OVAL <check> reference,
                       and the scan <rule-result> (pass/fail).
  - products/rhel8/controls/stig_rhel8.yml   rule_id -> RHEL-08-XXXXXX map (in repo).

Output:
  - dataset.jsonl      one row per selected STIG rule. The "prompt" field is the
                       hide-the-mechanism task statement; reference_bash + oval_check_id
                       are the (hidden) answer key and scorer.

Two stages:
  1. EXTRACT (no network): parse the XML -> reference data + placeholder prompts.
       python3 benchmark/build_dataset.py --results stig-results.xml --extract-only
  2. GENERATE (Claude Batch API): author the leak-free task prompts.
       python3 benchmark/build_dataset.py --results stig-results.xml --generate
       (requires ANTHROPIC_API_KEY)

By default only rules that FAILED the scan are written (the meaningful targets).
Use --include all|fail|selected to widen the set.
"""
import argparse
import json
import os
import re
import sys
import xml.etree.ElementTree as ET

XCCDF = "{http://checklists.nist.gov/xccdf/1.2}"
RULE_PREFIX = "xccdf_org.ssgproject.content_rule_"
BASH_FIX = "urn:xccdf:fix:script:sh"
ANSIBLE_FIX = "urn:xccdf:fix:script:ansible"

# ----------------------------------------------------------------------------
#  PROMPT ENGINEERING  --  the meta-prompt used to author each benchmark task.
#
#  Design goal: the generated task must state WHAT the system must achieve and
#  WHY, precisely enough to have exactly one compliant outcome (so the OVAL
#  check can grade it), while withholding HOW (file, directive, value-knob,
#  command) so we measure the model's security knowledge + coding ability,
#  not its ability to transcribe instructions.
# ----------------------------------------------------------------------------
GENERATOR_SYSTEM = """\
You are a senior security-benchmark author. You convert a single Linux hardening \
rule into ONE self-contained task statement that tests whether a language model \
can INDEPENDENTLY produce a correct remediation script — the way a coding-interview \
question tests a candidate.

Treat it exactly like writing a coding problem: specify WHAT the solution must \
achieve and WHY it matters, and never reveal HOW to achieve it.

The task statement MUST:
- State the security objective and the required end state precisely enough that \
there is exactly ONE compliant outcome, verifiable by an automated checker.
- Name the affected service, subsystem, or component at a conceptual level \
(e.g. "the SSH server", "the system audit daemon", "the kernel message buffer", \
"the AIDE file-integrity tool") so the requirement is unambiguous.
- Include any required target VALUE or THRESHOLD that defines compliance \
(e.g. "a 10-minute idle timeout", "a minimum length of 15 characters", \
"owned by root") — these are part of the specification.
- Briefly convey the threat or rationale so the objective is grounded.
- Require that the change be idempotent and persist across reboots when relevant.
- Target Red Hat Enterprise Linux 8. End by asking for a bash remediation script.

The task statement MUST NOT:
- Contain any exact filesystem path (e.g. /etc/ssh/sshd_config, /etc/sysctl.d).
- Name the exact configuration directive, parameter key, or sysctl key \
(e.g. do NOT write "ClientAliveInterval", "kernel.dmesg_restrict", "ENCRYPT_METHOD").
- Contain any shell command, package-manager invocation, or literal config line.
- Give step-by-step instructions or describe the editing mechanism.
- Reveal which file to edit, which command to run, or the literal text to write.

If the source description contains implementation specifics (commands, paths, \
parameter names), ABSTRACT them away — describe the goal they accomplish, not the \
mechanism. Naming the component or required value is allowed; naming the knob, \
path, or command is not.

Keep it to one tight paragraph. Be precise, not verbose.

Respond ONLY with a JSON object: {"task_prompt": "...", "objective": "<one-line \
summary of what compliance achieves>"}.\
"""

# Few-shot anchors the calibration (component + value allowed; knob/path/command hidden).
GENERATOR_FEWSHOT = [
    {
        "role": "user",
        "content": (
            "TITLE: Restrict Access to Kernel Message Buffer\n"
            "SEVERITY: low\n"
            "RATIONALE: Unprivileged access to the kernel syslog can expose sensitive "
            "kernel address information.\n"
            "DESCRIPTION: To set the runtime status of the kernel.dmesg_restrict kernel "
            "parameter, run: sudo sysctl -w kernel.dmesg_restrict=1. Add the line "
            "kernel.dmesg_restrict = 1 to a file in /etc/sysctl.d."
        ),
    },
    {
        "role": "assistant",
        "content": (
            '{"task_prompt": "On a RHEL 8 system, unprivileged users can currently read '
            "the kernel's message (ring) buffer, which can expose kernel memory addresses "
            "useful for local privilege-escalation exploits. Write an idempotent bash "
            "remediation script that restricts access to the kernel message buffer so that "
            "only privileged users can read it, and ensure the restriction is applied at "
            'runtime and persists across reboots.", '
            '"objective": "Only privileged users can read the kernel ring buffer, persistently."}'
        ),
    },
    {
        "role": "user",
        "content": (
            "TITLE: Set SSH Idle Timeout Interval\n"
            "SEVERITY: medium\n"
            "RATIONALE: Terminating an idle session within a short time reduces the window "
            "of opportunity for unauthorized personnel to take control of an unattended session.\n"
            "DESCRIPTION: Set ClientAliveInterval to 600 in /etc/ssh/sshd_config."
        ),
    },
    {
        "role": "assistant",
        "content": (
            '{"task_prompt": "On a RHEL 8 system, configure the SSH server so that an '
            "interactive session is automatically terminated after 10 minutes of inactivity, "
            "reducing the chance that an unattended logged-in session is hijacked. Write an "
            "idempotent bash remediation script that enforces this idle-timeout behavior for "
            'new SSH sessions.", '
            '"objective": "SSH sessions terminate after 10 minutes idle."}'
        ),
    },
]

GENERATOR_SCHEMA = {
    "type": "object",
    "properties": {
        "task_prompt": {"type": "string"},
        "objective": {"type": "string"},
    },
    "required": ["task_prompt", "objective"],
    "additionalProperties": False,
}

# Fixed, deterministic output-format instruction appended to every task prompt
# so the script can be extracted from any model's response reliably.
OUTPUT_FORMAT_INSTRUCTION = (
    "\n\nRespond with ONLY a single self-contained bash script and nothing else. "
    "Enclose the entire script in one fenced code block that starts with a line "
    "containing exactly ```bash and ends with a line containing exactly ```. "
    "Do not write any explanation, comments, or text before or after the code block."
)


# ----------------------------------------------------------------------------
#  XML extraction
# ----------------------------------------------------------------------------
def strip_html(s):
    if not s:
        return ""
    s = re.sub(r"<[^>]+>", " ", s)
    s = s.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
    return re.sub(r"\s+", " ", s).strip()


def el_text(rule, tag):
    el = rule.find(XCCDF + tag)
    if el is None:
        return ""
    return strip_html(ET.tostring(el, encoding="unicode", method="xml"))


def load_stig_map():
    import yaml
    path = "products/rhel8/controls/stig_rhel8.yml"
    if not os.path.exists(path):
        return {}
    data = yaml.safe_load(open(path))
    m = {}
    for ctrl in data.get("controls", []):
        for r in ctrl.get("rules", []):
            if "=" not in r:
                m[r] = ctrl["id"]
    return m


def parse_results(path):
    """Return (rules_by_id, result_by_id). rules carry rendered fields + fixes."""
    tree = ET.parse(path)
    root = tree.getroot()

    result_by_id = {}
    for rr in root.iter(XCCDF + "rule-result"):
        res = rr.find(XCCDF + "result")
        result_by_id[rr.get("idref")] = res.text if res is not None else None

    rules = {}
    for rule in root.iter(XCCDF + "Rule"):
        full = rule.get("id", "")
        rid = full.replace(RULE_PREFIX, "")

        refs = {}
        for ref in rule.findall(XCCDF + "reference"):
            href = (ref.get("href") or "").lower()
            val = (ref.text or "").strip()
            if not val:
                continue
            if "nist" in href:
                refs.setdefault("nist", val)
            elif "srg" in href or "disa" in href or "stig" in href:
                refs.setdefault("srg", val)
        idents = {}
        for ident in rule.findall(XCCDF + "ident"):
            sysu = (ident.get("system") or "").lower()
            if "cce" in sysu:
                idents["cce"] = ident.text
            elif "cci" in sysu or "disa" in sysu:
                idents["cci"] = ident.text

        bash = ansible = None
        reboot = False
        for fix in rule.findall(XCCDF + "fix"):
            system = fix.get("system") or ""
            if system == BASH_FIX and bash is None:
                bash = (fix.text or "").strip()
                reboot = (fix.get("reboot", "false").lower() == "true")
            elif system == ANSIBLE_FIX and ansible is None:
                ansible = (fix.text or "").strip()

        oval = None
        chk = rule.find(XCCDF + "check")
        if chk is not None:
            ref = chk.find(XCCDF + "check-content-ref")
            if ref is not None:
                oval = ref.get("name")

        rules[full] = {
            "rule_id": rid,
            "severity": rule.get("severity", ""),
            "title": el_text(rule, "title"),
            "description": el_text(rule, "description"),
            "rationale": el_text(rule, "rationale"),
            "references": refs,
            "idents": idents,
            "reference_bash": bash,
            "reference_ansible": ansible,
            "oval_check_id": oval,
            "reboot_required": reboot,
            "_full_id": full,
        }
    return rules, result_by_id


# ----------------------------------------------------------------------------
#  Leakage check: the authored prompt must not contain mechanism tokens that
#  appear in the reference script.
# ----------------------------------------------------------------------------
def mechanism_tokens(script):
    if not script:
        return set()
    toks = set()
    toks |= set(re.findall(r"/(?:etc|usr|var|run|boot|sys|proc)/[\w./*-]+", script))
    toks |= set(re.findall(r"\b[a-z][a-z0-9_]+(?:\.[a-z0-9_]+){1,}\b", script))  # sysctl-style keys
    # quoted directive names like ^ENCRYPT_METHOD, ClientAliveInterval
    toks |= set(re.findall(r"\b[A-Z][A-Za-z]*(?:[A-Z][a-z]+)+\b", script))      # CamelCase directives
    toks |= set(re.findall(r"\b[A-Z][A-Z0-9_]{3,}\b", script))                  # SHOUTY_DIRECTIVES
    return {t.strip(" ^$") for t in toks if len(t) > 3}


def leaked(prompt, script):
    # whole-word match so "arch" doesn't fire on "architecture", "vers" on "versions"
    hits = []
    for t in mechanism_tokens(script):
        if re.search(r"(?<![\w.])" + re.escape(t) + r"(?![\w.])", prompt, re.IGNORECASE):
            hits.append(t)
    return hits


def extract_bash(response_text):
    """Pull the bash script from a model-under-test response. Tolerant:
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


# ----------------------------------------------------------------------------
#  Claude Batch API prompt generation
# ----------------------------------------------------------------------------
def generate_prompts(rows, model="claude-opus-4-8"):
    """Author task_prompt for each row via the Batch API. Mutates rows in place."""
    import anthropic
    from anthropic.types.message_create_params import MessageCreateParamsNonStreaming
    from anthropic.types.messages.batch_create_params import Request

    client = anthropic.Anthropic()

    # short, unique custom_ids (<=64 chars); map back to rows
    by_cid = {}
    requests = []
    for i, row in enumerate(rows):
        cid = f"r{i}"
        by_cid[cid] = row
        user = (
            f"TITLE: {row['title']}\n"
            f"SEVERITY: {row['severity']}\n"
            f"RATIONALE: {row['rationale']}\n"
            f"DESCRIPTION: {row['description'][:1200]}"
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

    print(f"Submitting batch of {len(requests)} prompt-generation requests...", file=sys.stderr)
    batch = client.messages.batches.create(requests=requests)
    print(f"  batch id: {batch.id} — polling (most finish < 1h)...", file=sys.stderr)

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
        msg = result.result.message
        text = next((b.text for b in msg.content if b.type == "text"), "")
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            continue
        task = obj.get("task_prompt", "")
        row["task_prompt"] = task                              # pure objective
        row["prompt"] = task + OUTPUT_FORMAT_INSTRUCTION       # ready to feed a model
        row["objective"] = obj.get("objective", "")
        hits = leaked(task, row.get("reference_bash"))
        row["prompt_leak_tokens"] = hits
        if hits:
            leak_flags += 1
    print(f"  done. prompts flagged for possible leakage: {leak_flags}", file=sys.stderr)


# ----------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True, help="path to stig-results.xml")
    ap.add_argument("--out", default="benchmark/dataset.jsonl")
    ap.add_argument("--include", choices=["fail", "selected", "all"], default="fail",
                    help="fail = failed rules only (default); selected = any scanned; all = every rule")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--extract-only", action="store_true",
                   help="parse XML only; leave prompts as placeholders (no API call)")
    g.add_argument("--generate", action="store_true",
                   help="author leak-free prompts via the Claude Batch API")
    args = ap.parse_args()

    rules, results = parse_results(args.results)
    stig_map = load_stig_map()
    print(f"Parsed {len(rules)} rules; {len(results)} rule-results.", file=sys.stderr)

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
        row["task_prompt"] = None     # filled by --generate
        row["prompt"] = None          # task_prompt + OUTPUT_FORMAT_INSTRUCTION
        row["objective"] = None
        row["prompt_leak_tokens"] = None
        rows.append(row)

    has_bash = sum(1 for r in rows if r["reference_bash"])
    print(f"Selected {len(rows)} rules ({args.include}); {has_bash} have a bash reference fix.",
          file=sys.stderr)

    if args.generate:
        # only author prompts for rows that have a reference fix to grade against
        gen_rows = [r for r in rows if r["reference_bash"]]
        generate_prompts(gen_rows)

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    print(f"Wrote {len(rows)} rows -> {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
