# Confidence Interval Results

Per-model, per-category pass rates pooled across multiple independent runs, with 95% Wilson
score intervals. Companion to `SCORING_STATUS.md` (which tracks in-progress scoring); this file
is the finalized numbers once a model's runs are all scored.

Methodology: additional runs beyond the original use `temperature=0.2` with a distinct seed per
run (not `temperature=0`, which is deterministic and would just reproduce the same output). Every
`(rule, run)` pair is treated as one Bernoulli trial; buckets use the same `_classify()` scheme as
`benchmark/compute_scores.py`. Reproduce with `benchmark/compute_ci.py`.

---

## CodeLlama-34B-Instruct FP16 (Ollama)

**4 runs**: 1 original greedy run (temp=0) + 3 seeded runs (temp=0.2, seeds 101/102/103).

### Per-run (combined server-safe)

| Run | Sampling | Source | Passed/Total | Rate |
|---|---|---|---|---|
| original | temp=0 (greedy) | `llama/results_codellama_34b_fp16.jsonl` | 29/137 | 21.2% |
| run1 | temp=0.2, seed=101 | `ci_runs/run1/logs/run1_score_codellama_34b_fp16.log` | 29/137 | 21.2% |
| run2 | temp=0.2, seed=102 | `ci_runs/run2/logs/run2_score_codellama_34b_fp16.log` | 25/137 | 18.2% |
| run3 | temp=0.2, seed=103 | `ci_runs/run3/logs/run3_score_codellama_34b_fp16.log` | 26/137 | 19.0% |

### Per-category, pooled across all 4 runs

| Category | Passed/Total | Rate | 95% Wilson CI |
|---|---|---|---|
| Server config + kernel | 78/320 | 24.4% | 20.0% – 29.4% |
| Audit rules (`audit_rules_*`) | 31/228 | 13.6% | 9.7% – 18.7% |
| sshd config | 14/56 | 25.0% | 15.5% – 37.7% |
| **→ Combined server-safe** (server config+kernel + audit) | **109/548** | **19.9%** | **16.8% – 23.4%** |
| **All verified applicable** (+ sshd + access_breaker) | **123/604** | **20.4%** | **17.3% – 23.8%** |

Crypto/FIPS (`access_breaker`) and not-applicable rules contributed 0 rows — excluded from
scoring by `--skip-hazardous`, consistent with every other model's methodology in this repo.

Note: the original single-run point estimate (21.2%) sits inside the CI, near its upper edge —
a single run wasn't a fluke, but also couldn't tell you on its own that it was near the high end
of plausible outcomes rather than the middle.

---

## GLM4-9B FP16 (Ollama)

Scoring in progress: run1 on 104.248.226.231 (started), run2/run3 not yet started. Table to be
added once all 3 finish.

## GLM4-9B 4-bit (Ollama)

**4 runs**: the original greedy run (temp=0, `glm4/results_glm4_9b_q4.jsonl`) plus 3 seeded runs
(temp=0.2, seeds 101/102/103). Seeded runs scored on 3 dedicated droplets — run1
(143.198.189.11) and run2 (104.248.226.231) on the first attempt, run3 (147.182.133.119) after an
image reset and retry (its first attempt's droplet also lost SSH mid-scoring, same failure mode
as every other batch in this study, but the retry completed and matched the original attempt's
tally exactly: 168 scored, 22 passed both times).

### Per-run (combined server-safe)

| Run | Sampling | Source | Passed/Total | Rate |
|---|---|---|---|---|
| original | temp=0 (greedy) | `glm4/results_glm4_9b_q4.jsonl` | 17/137 | 12.4% |
| run1 | temp=0.2, seed=101 | `ci_runs/run1/logs/run1_score_glm4_9b_q4.log` | 17/137 | 12.4% |
| run2 | temp=0.2, seed=102 | `ci_runs/run2/logs/run2_score_glm4_9b_q4.log` | 15/137 | 10.9% |
| run3 | temp=0.2, seed=103 | `ci_runs/run3/logs/run3_score_glm4_9b_q4.log` | 18/137 | 13.1% |

### Per-category, pooled across all 4 runs

| Category | Passed/Total | Rate | 95% Wilson CI |
|---|---|---|---|
| Server config + kernel | 66/320 | 20.6% | 16.6% – 25.4% |
| Audit rules (`audit_rules_*`) | 1/228 | 0.4% | 0.1% – 2.4% |
| sshd config | 13/56 | 23.2% | 14.1% – 35.8% |
| **→ Combined server-safe** (server config+kernel + audit) | **67/548** | **12.2%** | **9.7% – 15.2%** |
| **All verified applicable** (+ sshd + access_breaker) | **80/604** | **13.2%** | **10.8% – 16.2%** |

Crypto/FIPS (`access_breaker`) and not-applicable rules contributed 0 rows — excluded from
scoring by `--skip-hazardous`.

Note: the original single-run estimate (12.4%, 17/137) sits almost exactly in the middle of the
pooled CI — the most stable/representative single run of the three models scored so far.
GLM4-9B 4-bit is nearly incapable of writing correct `auditd` rules across every single run (0 or
1 pass out of 57 each time) — the tightest, most consistent failure mode in this study.

## Qwen2.5-Coder-14B-Instruct

**4 runs**: the original greedy run (temp=0), using its already-published aggregate score since
no per-rule results file was saved for it, plus 3 seeded runs (temp=0.2, seeds 101/102/103).
Seeded runs scored on 3 dedicated droplets (64.227.31.210/67.205.142.115/67.205.134.254), one run
each — same run{N}<->droplet mapping convention as CodeLlama, just a separate set of droplets.

### Per-run (combined server-safe)

| Run | Sampling | Source | Passed/Total | Rate |
|---|---|---|---|---|
| original | temp=0 (greedy) | published aggregate (no per-rule file) | 46/137 | 33.6% |
| run1 | temp=0.2, seed=101 | `ci_runs/run1/logs/run1_score_qwen25coder14b_fp16.log` | 42/137 | 30.7% |
| run2 | temp=0.2, seed=102 | `ci_runs/run2/logs/run2_score_qwen25coder14b_fp16.log` | 32/137 | 23.4% |
| run3 | temp=0.2, seed=103 | `ci_runs/run3/logs/run3_score_qwen25coder14b_fp16.log` | 42/137 | 30.7% |

### Per-category, pooled across all 4 runs

| Category | Passed/Total | Rate | 95% Wilson CI |
|---|---|---|---|
| Server config + kernel | 117/319 | 36.7% | 31.6% – 42.1% |
| Audit rules (`audit_rules_*`) | 45/229 | 19.7% | 15.0% – 25.3% |
| sshd config | 27/56 | 48.2% | 35.7% – 61.0% |
| **→ Combined server-safe** (server config+kernel + audit) | **162/548** | **29.6%** | **25.9% – 33.5%** |
| **All verified applicable** (+ sshd + access_breaker) | **189/604** | **31.3%** | **27.7% – 35.1%** |

Crypto/FIPS (`access_breaker`) and not-applicable rules contributed 0 rows — excluded from
scoring by `--skip-hazardous`. The original run's per-category split (32/79 server config, 14/58
audit) differs by one rule from the seeded runs' split (80/57) — the combined 137 total matches
exactly, it's just one rule classified into a different bucket for that run; pooled as reported.

Note: the originally published single-run estimate (33.6%, 46/137) sits just above this CI's
upper edge (33.5%) — both CodeLlama-34B's and Qwen-14B's original single runs read on the
optimistic side of their respective pooled results. Illustrates the point of this whole exercise:
a single run's number isn't necessarily "wrong," but you can't tell where it sits in the plausible
range without repeats.

## Qwen2.5-Coder-7B-Instruct

Predictions generation in progress on the GPU pod as of this writing.
