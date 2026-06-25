#!/usr/bin/env python3
"""
Scoring harness — runs ON a Rocky 8 / AlmaLinux 8 / RHEL 8 box (as root).

For each model-generated remediation:
  1. pre-scan the rule with oscap   (expect: fail  -> a real target)
  2. run the generated bash script
  3. (reboot-required rules are skipped by default — see --include-reboot)
  4. post-scan the rule with oscap  (pass = the script fixed it)
  5. record the outcome

The OVAL check is the oracle: a rule "passes" iff oscap reports `pass` after
the script runs. This is functional scoring — any correct script counts, not
just ones matching the reference.

Setup on the test box (one time):
    sudo dnf install -y openscap-scanner scap-security-guide
    # datastream is then at /usr/share/xml/scap/ssg/content/ssg-rl8-ds.xml (Rocky)
    #                    or /usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml

Run (as root, so remediations and scans work):
    sudo python3 score_remediations.py \
        --predictions predictions.jsonl \
        --dataset dataset.jsonl \
        --datastream /usr/share/xml/scap/ssg/content/ssg-rl8-ds.xml \
        --limit 50 --out results.jsonl

Resumable + incremental (same as the inference harness): re-run to continue.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile

RULE_PREFIX = "xccdf_org.ssgproject.content_rule_"
PROFILE = "xccdf_org.ssgproject.content_profile_stig"

# Rules that can sever remote management access (SSH/console) or need a reboot —
# unsafe to run on a single host you must keep reachable. --skip-hazardous excludes them.
HAZARD_SUBSTRINGS = (
    "crypto_policy", "fips", "harden_sshd_ciphers", "harden_sshd_macs",
    "ssh_server_", "grub2_", "sshd_use_strong",
)


def is_hazardous(rule_id):
    rid = rule_id.lower()
    return any(h in rid for h in HAZARD_SUBSTRINGS)


def oscap_eval(datastream, rule_id):
    """Return 'pass' | 'fail' | 'notapplicable' | 'error' for one rule."""
    full = RULE_PREFIX + rule_id
    cmd = ["oscap", "xccdf", "eval", "--profile", PROFILE, "--rule", full, datastream]
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       universal_newlines=True)
    # oscap prints a "Result\t<state>" line per rule; parse it (robust to exit codes)
    m = re.search(r"^Result\s+(\w+)", p.stdout, re.MULTILINE)
    if m:
        return m.group(1).lower()
    # fallback to exit code: 0 = pass, 2 = fail
    return {0: "pass", 2: "fail"}.get(p.returncode, "error")


def _make_stub_path(tmpdir):
    """Create a bin dir whose stubs neutralize box-killing commands, so no single
    remediation can reboot / power off the machine mid-run. The orchestrator does
    the one controlled reboot for reboot-required rules instead."""
    stub_bin = os.path.join(tmpdir, "bin")
    os.makedirs(stub_bin)
    for name in ("reboot", "shutdown", "poweroff", "halt", "telinit"):
        p = os.path.join(stub_bin, name)
        with open(p, "w") as f:
            f.write('#!/bin/sh\necho "[neutralized: %s $*]" >&2\nexit 0\n' % name)
        os.chmod(p, 0o755)
    # systemctl wrapper: forward everything EXCEPT reboot-like verbs
    real = shutil.which("systemctl") or "/usr/bin/systemctl"
    p = os.path.join(stub_bin, "systemctl")
    with open(p, "w") as f:
        f.write('#!/bin/sh\ncase "$1" in\n'
                '  reboot|poweroff|halt|kexec|emergency|rescue|"isolate")'
                ' echo "[neutralized: systemctl $*]" >&2; exit 0;;\n'
                '  *) exec %s "$@";;\nesac\n' % real)
    os.chmod(p, 0o755)
    return stub_bin


def run_script(script):
    """Execute a generated remediation script with reboot/shutdown neutralized;
    return (exit_code, combined_log)."""
    tmpdir = tempfile.mkdtemp(prefix="stigfix_")
    try:
        stub_bin = _make_stub_path(tmpdir)
        env = dict(os.environ)
        env["PATH"] = stub_bin + ":" + env.get("PATH", "")
        path = os.path.join(tmpdir, "fix.sh")
        with open(path, "w") as f:
            f.write(script)
        p = subprocess.run(["bash", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=300, env=env)
        return p.returncode, (p.stdout + p.stderr)[-2000:]
    except subprocess.TimeoutExpired:
        return 124, "TIMEOUT after 300s"
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def do_rescan(out_path, datastream):
    """Phase 3 (after a reboot): finalize rows marked 'pending_reboot'."""
    if not os.path.exists(out_path):
        print("rescan: no results file, nothing to do.", flush=True)
        return
    recs = [json.loads(l) for l in open(out_path)]
    pend = [r for r in recs if r.get("post_scan") == "pending_reboot"]
    print(f"rescan: finalizing {len(pend)} reboot-required rules.", flush=True)
    for r in pend:
        post = oscap_eval(datastream, r["rule_id"])
        r["post_scan"] = post
        r["passed"] = (post == "pass")
        r["fixed_from_fail"] = (r.get("pre_scan") == "fail" and post == "pass")
        print(f"  {r.get('stig_id')} {r['rule_id']}: post={post} "
              f"{'PASS' if r['passed'] else 'fail'}", flush=True)
    with open(out_path, "w") as f:        # rewrite with finalized rows
        for r in recs:
            f.write(json.dumps(r) + "\n")
    pw = sum(1 for r in recs if r.get("passed"))
    print(f"\n==== FINAL SCORE ====\n{len(recs)} rules | passed: {pw} "
          f"({100*pw/max(len(recs),1):.1f}%)\nResults -> {out_path}", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--predictions")
    ap.add_argument("--dataset", help="for oval/reboot metadata")
    ap.add_argument("--datastream", required=True, help="ssg-almalinux8-ds.xml / ssg-rhel8-ds.xml")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--out", default="results.jsonl")
    ap.add_argument("--phase", choices=["normal", "apply", "rescan"], default="normal",
                    help="normal = score non-reboot rules; apply = run reboot-rule scripts and "
                         "mark them pending; rescan = finalize pending rows (run after a reboot)")
    ap.add_argument("--no-prescan", action="store_true",
                    help="skip the pre-scan (~2x faster): use the dataset's initial_state for "
                         "pre_scan and only run the post-scan after the script")
    ap.add_argument("--skip-hazardous", action="store_true",
                    help="exclude rules that can sever SSH/console access or need reboot "
                         "(crypto policy, FIPS, SSH ciphers/MACs, GRUB) — keeps the host reachable")
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("WARNING: not root — remediations/scans may fail. Re-run with sudo.", flush=True)
    if not os.path.exists(args.datastream):
        raise SystemExit(f"Datastream not found: {args.datastream}")

    if args.phase == "rescan":
        do_rescan(args.out, args.datastream)
        return

    if not args.predictions or not args.dataset:
        raise SystemExit("--predictions and --dataset are required for normal/apply phases")

    meta = {json.loads(l)["rule_id"]: json.loads(l) for l in open(args.dataset)}
    preds = [json.loads(l) for l in open(args.predictions)]

    done = set()
    if os.path.exists(args.out):
        for l in open(args.out):
            try:
                done.add(json.loads(l)["rule_id"])
            except Exception:
                pass

    want_reboot = (args.phase == "apply")     # apply phase = reboot rules; normal = the rest
    todo = []
    for p in preds:
        rid = p["rule_id"]
        if rid in done or not p.get("generated_script"):
            continue
        if bool(meta.get(rid, {}).get("reboot_required")) != want_reboot:
            continue
        if args.skip_hazardous and is_hazardous(rid):
            continue
        todo.append(p)
    if args.limit:
        todo = todo[:args.limit]

    print(f"phase={args.phase}: {len(done)} already recorded; processing {len(todo)} rules.",
          flush=True)
    out_f = open(args.out, "a")
    try:
        for i, p in enumerate(todo, 1):
            rid = p["rule_id"]
            if args.no_prescan:
                pre = meta.get(rid, {}).get("initial_state", "unknown")   # from dataset, no scan
            else:
                pre = oscap_eval(args.datastream, rid)
            rc, log = run_script(p["generated_script"])
            if args.phase == "apply":
                post, passed = "pending_reboot", None        # finalized after the reboot
            else:
                post = oscap_eval(args.datastream, rid)
                passed = (post == "pass")
            rec = {
                "rule_id": rid, "stig_id": p.get("stig_id"), "model": p.get("model"),
                "pre_scan": pre, "post_scan": post, "passed": passed, "script_exit": rc,
                "fixed_from_fail": (None if passed is None else (pre == "fail" and post == "pass")),
                "log_tail": log,
            }
            out_f.write(json.dumps(rec) + "\n")
            out_f.flush()
            tag = "applied (pending reboot)" if args.phase == "apply" else ("PASS" if passed else "fail")
            print(f"[{len(done)+i}] {p.get('stig_id')} {rid}: {pre} -> {post}  {tag} (exit {rc})",
                  flush=True)
    finally:
        out_f.close()

    results = [json.loads(l) for l in open(args.out)]
    pw = sum(1 for r in results if r.get("passed"))
    pend = sum(1 for r in results if r.get("post_scan") == "pending_reboot")
    print(f"\n==== SCORE (phase={args.phase}) ====", flush=True)
    print(f"recorded: {len(results)} | passed: {pw} | pending reboot: {pend}", flush=True)
    print(f"Results -> {args.out}", flush=True)


if __name__ == "__main__":
    main()
