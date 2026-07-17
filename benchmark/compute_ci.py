#!/usr/bin/env python3
"""
Aggregate results across multiple seeded runs of the same model into a confidence interval.

Reads either format, one file per run:
  - results_<model>.jsonl   the normal grader output (rule_id, passed, bucket?)
  - score_<model>.log       captured stdout of score_remediations.py (used when SSH access
                             to a scoring host was lost and results were pasted manually),
                             parsed from lines like:
                             [42/168] RHEL-08-... some_rule_id: fail -> pass  PASS (exit 0)

Buckets match compute_scores.py's _classify(). Reports each run's rate, the mean/range
across runs, and a pooled Wilson 95% CI treating every (rule, run) pair as one Bernoulli
trial of "does this model correctly remediate this rule under temp=0.2 sampling."

Usage:
    python3 compute_ci.py --model codellama_34b_fp16 \
        ../ci_runs/run1/logs/run1_score_codellama_34b_fp16.log \
        ../ci_runs/run2/logs/run2_score_codellama_34b_fp16.log \
        ../ci_runs/run3/logs/run3_score_codellama_34b_fp16.log
"""
import argparse
import json
import math
import os
import re

LOG_LINE = re.compile(
    r"^\[(\d+)/(\d+)\]\s+(\S+)\s+(\S+):\s+(\S+)\s+->\s+(\S+)\s+(PASS|fail)\s+\(exit (-?\d+)\)"
)

SERVER_SAFE = {"server_safe", "audit"}  # matches README's "combined server-safe" headline


def _classify(rule_id, post_scan):
    """Same fallback classifier as compute_scores.py (0 mismatches on results_opus_full.jsonl)."""
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


def load_rows(path):
    """Return [{rule_id, passed, bucket}] from a .jsonl results file or a captured text log."""
    rows = []
    if path.endswith(".jsonl"):
        for line in open(path):
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            bucket = r.get("bucket") or _classify(r.get("rule_id", ""), r.get("post_scan"))
            rows.append({"rule_id": r["rule_id"], "passed": r["passed"], "bucket": bucket})
        return rows

    seen = set()
    for line in open(path):
        m = LOG_LINE.match(line.strip())
        if not m:
            continue
        _, _, stig_id, rule_id, pre, post, verdict, exit_code = m.groups()
        if rule_id in seen:
            continue  # dedupe: a partial paste + full paste can overlap
        seen.add(rule_id)
        rows.append({
            "rule_id": rule_id,
            "passed": (verdict == "PASS"),
            "bucket": _classify(rule_id, post),
        })
    return rows


def bucket_rate(rows, buckets):
    p = sum(1 for r in rows if r["bucket"] in buckets and r["passed"] is True)
    t = sum(1 for r in rows if r["bucket"] in buckets and r["passed"] is not None)
    return p, t


def wilson_ci(p, t, z=1.96):
    if t == 0:
        return (0.0, 0.0, 0.0)
    phat = p / t
    denom = 1 + z * z / t
    center = (phat + z * z / (2 * t)) / denom
    margin = (z * math.sqrt(phat * (1 - phat) / t + z * z / (4 * t * t))) / denom
    return (phat, max(0.0, center - margin), min(1.0, center + margin))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("files", nargs="+", help="one results/log file per run, in run order")
    args = ap.parse_args()

    per_run = []
    rates = []
    pooled_p = pooled_t = 0
    print(f"{args.model} — per-run (combined server-safe = server_safe + audit buckets)\n")
    for i, f in enumerate(args.files, 1):
        rows = load_rows(f)
        per_run.append(rows)
        p, t = bucket_rate(rows, SERVER_SAFE)
        rates.append(p / t if t else 0.0)
        pooled_p += p
        pooled_t += t
        print(f"  run{i} ({os.path.basename(f)}): {p}/{t} = {100*p/t:.1f}%  "
              f"({len(rows)} rows parsed)")

    mean = sum(rates) / len(rates)
    lo, hi = min(rates), max(rates)
    phat, ci_lo, ci_hi = wilson_ci(pooled_p, pooled_t)

    print(f"\n  mean across {len(per_run)} runs: {100*mean:.1f}%  (range {100*lo:.1f}%-{100*hi:.1f}%)")
    print(f"  pooled: {pooled_p}/{pooled_t} = {100*phat:.1f}%")
    print(f"  95% Wilson CI (pooled {len(per_run)} runs x {pooled_t//len(per_run)} rules): "
          f"{100*ci_lo:.1f}% - {100*ci_hi:.1f}%")


if __name__ == "__main__":
    main()
