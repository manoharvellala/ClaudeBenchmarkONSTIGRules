#!/usr/bin/env python3
"""
Faster alternative to score_remediations.py's per-rule pre-scan/apply/post-scan loop:
run every remediation script first (no live scanning in between), then do a single
oscap sweep over all of them at the end.

This is NOT the reboot apply/rescan mechanism in score_remediations.py -- no rule here
is reboot-required, and no reboot is ever triggered. It just decouples "run the scripts"
from "check the results" into two passes so oscap's per-invocation startup overhead and
script execution time don't serialize with each other rule-by-rule.

Pre-scan uses the dataset's initial_state (always "fail" for benchmark rules by
construction) instead of a live oscap call, since that would defeat the point of skipping
scans during the apply pass.

Usage:
    python3 apply_then_scan.py \
        --predictions predictions_gpt4o_ubuntu2404_scorable.jsonl \
        --dataset dataset_ubuntu2404.jsonl \
        --datastream /root/ssg-ubuntu2404-ds.xml \
        --out results_gpt4o_ubuntu2404.jsonl

Resumable: re-run the same command to continue (skips rule_ids already finalized in --out).
"""
import argparse
import json
import os
import shutil
import subprocess
import tempfile

from score_remediations import RULE_PREFIX, PROFILE, is_hazardous, oscap_eval, run_script  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--predictions", required=True)
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--datastream", required=True)
    ap.add_argument("--skip-hazardous", action="store_true")
    ap.add_argument("--out", default="results.jsonl")
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("WARNING: not root -- remediations/scans may fail. Re-run with sudo.", flush=True)
    if not os.path.exists(args.datastream):
        raise SystemExit(f"Datastream not found: {args.datastream}")

    meta = {json.loads(l)["rule_id"]: json.loads(l) for l in open(args.dataset)}
    preds = [json.loads(l) for l in open(args.predictions)]

    done = set()
    if os.path.exists(args.out):
        for l in open(args.out):
            try:
                done.add(json.loads(l)["rule_id"])
            except Exception:
                pass

    candidates = []
    for p in preds:
        rid = p["rule_id"]
        if not p.get("generated_script"):
            continue
        if meta.get(rid, {}).get("reboot_required"):
            continue
        if args.skip_hazardous and is_hazardous(rid):
            continue
        candidates.append(p)
    total = len(candidates)
    todo = [p for p in candidates if p["rule_id"] not in done]

    print(f"apply_then_scan: {len(done)} already recorded; applying {len(todo)} of {total} scripts "
          f"(no live scan during this pass)...", flush=True)

    applied = []
    for i, p in enumerate(todo, 1):
        rid = p["rule_id"]
        pre = meta.get(rid, {}).get("initial_state", "unknown")
        rc, log = run_script(p["generated_script"])
        applied.append({"rule_id": rid, "stig_id": p.get("stig_id"), "model": p.get("model"),
                         "pre_scan": pre, "script_exit": rc, "log_tail": log})
        print(f"[apply {i}/{len(todo)}] {p.get('stig_id')} {rid}: script exit {rc}", flush=True)

    print(f"\nAll scripts applied. Now scanning {len(applied)} rules in a single sweep...", flush=True)
    out_f = open(args.out, "a")
    try:
        for i, a in enumerate(applied, 1):
            rid = a["rule_id"]
            post = oscap_eval(args.datastream, rid)
            passed = (post == "pass")
            rec = {
                "rule_id": rid, "stig_id": a["stig_id"], "model": a["model"],
                "pre_scan": a["pre_scan"], "post_scan": post, "passed": passed,
                "script_exit": a["script_exit"],
                "fixed_from_fail": (a["pre_scan"] == "fail" and post == "pass"),
                "log_tail": a["log_tail"],
            }
            out_f.write(json.dumps(rec) + "\n")
            out_f.flush()
            tag = "PASS" if passed else "fail"
            print(f"[scan {i}/{len(applied)}] {a['stig_id']} {rid}: {a['pre_scan']} -> {post}  "
                  f"{tag} (exit {a['script_exit']})", flush=True)
    finally:
        out_f.close()

    results = [json.loads(l) for l in open(args.out)]
    pw = sum(1 for r in results if r.get("passed"))
    print(f"\n==== SCORE ====\nrecorded: {len(results)} | passed: {pw}\nResults -> {args.out}", flush=True)


if __name__ == "__main__":
    main()
