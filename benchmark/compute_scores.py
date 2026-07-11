#!/usr/bin/env python3
"""Recompute every published number from results_opus_full.jsonl.

This is the single source of truth for the README / RESULTS.md table. Run:

    python3 benchmark/compute_scores.py

and confirm the printed figures match the committed documentation. Pure stdlib.
"""
import json
import sys
from collections import defaultdict

PATH = sys.argv[1] if len(sys.argv) > 1 else "benchmark/results_opus_full.jsonl"

# Optional dataset path to look up bucket when results file lacks the field
import os
_DATASET_CANDIDATES = [
    os.path.join(os.path.dirname(PATH), "dataset.jsonl"),
    "benchmark/dataset.jsonl",
    "dataset.jsonl",
]


def _load_bucket_map():
    for p in _DATASET_CANDIDATES:
        if os.path.exists(p):
            return {json.loads(l)["rule_id"]: json.loads(l).get("bucket")
                    for l in open(p) if json.loads(l).get("bucket")}
    return {}


def _classify(rule_id, post_scan):
    """Fallback classifier for results files without an explicit 'bucket' field,
    reverse-engineered from results_opus_full.jsonl (0 mismatches on 198 rows)."""
    if post_scan == "notapplicable":
        return "not_applicable"
    if rule_id.startswith("sshd_"):
        return "sshd"
    if rule_id.startswith("audit_rules_") or rule_id.startswith("auditd_"):
        return "audit"
    hazard = ("crypto_policy", "fips", "harden_sshd_ciphers", "harden_sshd_macs")
    if any(h in rule_id.lower() for h in hazard):
        return "access_breaker"
    return "server_safe"


def main():
    rows = [json.loads(l) for l in open(PATH)]
    bucket_map = _load_bucket_map()
    agg = defaultdict(lambda: {"pass": 0, "fail": 0, "unverified": 0})
    for r in rows:
        b = (r.get("bucket") or bucket_map.get(r.get("rule_id"))
             or _classify(r.get("rule_id", ""), r.get("post_scan")))
        if r["passed"] is True:
            agg[b]["pass"] += 1
        elif r["passed"] is False:
            agg[b]["fail"] += 1
        else:
            agg[b]["unverified"] += 1

    def rate(p, t):
        return f"{p}/{t} = {100 * p / t:.1f}%" if t else f"{p}/0 = n/a"

    ss, au = agg["server_safe"], agg["audit"]
    sh, ab = agg["sshd"], agg["access_breaker"]
    na = agg["not_applicable"]

    ss_t = ss["pass"] + ss["fail"]
    au_t = au["pass"] + au["fail"]
    sh_t = sh["pass"] + sh["fail"]
    ab_t = ab["pass"] + ab["fail"]            # verified crypto only
    na_t = na["pass"] + na["fail"] + na["unverified"]

    print(f"results file: {PATH}")
    print(f"total rows  : {len(rows)}\n")
    print("Bucket                         Passed/Total   Rate")
    print(f"  server config + kernel       {rate(ss['pass'], ss_t)}")
    print(f"  audit rules                  {rate(au['pass'], au_t)}")
    combo_p = ss["pass"] + au["pass"]
    combo_t = ss_t + au_t
    print(f"  -> combined server-safe      {rate(combo_p, combo_t)}   <-- HEADLINE")
    print(f"  sshd                         {rate(sh['pass'], sh_t)}")
    print(f"  crypto/FIPS (verified)       {rate(ab['pass'], ab_t)}   (+{ab['unverified']} unverified)")
    print(f"  not applicable               {na_t} rows (excluded)")

    verified_app_p = ss["pass"] + au["pass"] + sh["pass"] + ab["pass"]
    verified_app_t = ss_t + au_t + sh_t + ab_t
    print(f"  ALL VERIFIED APPLICABLE      {rate(verified_app_p, verified_app_t)}")

    scored = sum(1 for r in rows if r["passed"] is not None)
    unver = sum(1 for r in rows if r["passed"] is None)
    print(f"\ncoverage: {len(rows)} scored rows, {scored} verified, {unver} unverified")


if __name__ == "__main__":
    main()
