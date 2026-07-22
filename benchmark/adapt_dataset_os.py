#!/usr/bin/env python3
"""
Relabel dataset.jsonl's prompt text from one OS to another (e.g. RHEL 8 -> Ubuntu 24.04).

This ONLY rewrites the plain-English text the model reads (title, description, rationale,
task_prompt, prompt, objective). It does NOT touch rule_id, oval_check_id, reference_bash,
initial_state, or product -- those are still RHEL8-sourced and describe how the *original*
rule was verified/remediated on AlmaLinux/RHEL8.

Before scoring predictions generated from the output of this script against a real Ubuntu
host, you must re-scan Ubuntu with its own STIG/OVAL content (e.g. ssg-ubuntu2404-ds.xml) and
merge in the resulting real oval_check_id / initial_state / reference_bash per rule. Until then,
the output of this script is prompt-only and not a valid scoring dataset by itself.

Usage:
    python3 adapt_dataset_os.py \
        --in dataset.jsonl --out dataset_ubuntu2404.jsonl \
        --from-label "RHEL 8" --to-label "Ubuntu 24.04" \
        --from-full "Red Hat Enterprise Linux 8" --to-full "Ubuntu 24.04 LTS"
"""
import argparse
import json

TEXT_FIELDS = ["title", "description", "rationale", "task_prompt", "prompt", "objective"]


def fix_articles(text, to_label):
    """'a <label>' -> 'an <label>' when the label now starts with a vowel sound."""
    if not to_label or to_label[0].lower() not in "aeiou":
        return text
    text = text.replace(f"a {to_label}", f"an {to_label}")
    text = text.replace(f"A {to_label}", f"An {to_label}")
    return text


def relabel(row, replacements, to_label):
    for field in TEXT_FIELDS:
        val = row.get(field)
        if not isinstance(val, str):
            continue
        for old, new in replacements:
            val = val.replace(old, new)
        val = fix_articles(val, to_label)
        row[field] = val
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="infile", required=True)
    ap.add_argument("--out", dest="outfile", required=True)
    ap.add_argument("--from-label", default="RHEL 8")
    ap.add_argument("--to-label", default="Ubuntu 24.04")
    ap.add_argument("--from-full", default="Red Hat Enterprise Linux 8")
    ap.add_argument("--to-full", default="Ubuntu 24.04 LTS")
    args = ap.parse_args()

    # longest-match-first so "Red Hat Enterprise Linux 8" is replaced before "RHEL 8" would
    # ever be considered (they don't overlap, but keeping this order is safest going forward).
    replacements = [(args.from_full, args.to_full), (args.from_label, args.to_label)]

    n_rows = 0
    n_changed = 0
    with open(args.infile) as fin, open(args.outfile, "w") as fout:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            n_rows += 1
            before = json.dumps(row, sort_keys=True)
            row = relabel(row, replacements, args.to_label)
            if json.dumps(row, sort_keys=True) != before:
                n_changed += 1
            fout.write(json.dumps(row) + "\n")

    print(f"{n_rows} rows read, {n_changed} rows had OS text relabeled -> {args.outfile}")
    print("Reminder: oval_check_id / reference_bash / initial_state are still RHEL8-sourced. "
          "Re-scan Ubuntu and merge those in before scoring.")


if __name__ == "__main__":
    main()
