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

Scoring in progress across all 3 droplets (run1/run2/run3). Not yet complete — table to be added
once all 3 finish.

## GLM4-9B 4-bit (Ollama)

Not yet started (queued after GLM4-9B FP16 on each droplet).

## Qwen2.5-Coder-14B-Instruct

Predictions complete for all 3 runs (generated on the GPU pod); scoring not yet started on the
droplets (queued after both GLM4-9B variants).

## Qwen2.5-Coder-7B-Instruct

Predictions generation in progress on the GPU pod as of this writing.
