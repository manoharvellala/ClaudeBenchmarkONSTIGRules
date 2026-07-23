# STIG-LLM Benchmark

**A reproducible benchmark that measures how well an LLM can write real Linux security-hardening
scripts — graded functionally, not by string-matching.**

For each [DISA STIG](https://public.cyber.mil/stigs/) rule we hand the model a plain-English security
requirement (the *what* and *why*, with the *how* deliberately hidden), let it generate a Bash
remediation script, then **run that script on a real RHEL-8-family host and re-scan the rule with
OpenSCAP/OVAL**. The script is correct **iff** the rule flips `fail → pass`. No human judgement, no
reference-script diffing — a compliance scanner is the oracle.

> ### Headline Results
>
> | Model | Combined Server-Safe | All Verified Applicable |
> |---|---|---|
> | **Claude Opus 4.8** | **88.8%** (143/161)\* | **83.9%** (151/180)\* |
> | Claude Opus 4.7 | 81.0% (111/137) | 80.8% (122/151) |
> | GPT-4o | 65.7% (90/137) | 66.2% (100/151) |
> | Claude Sonnet 5 | 59.9% (82/137) | 58.9% (89/151) |
> | DeepSeek-Coder-33B-Instruct FP16 (Ollama) | 35.8% (49/137) | 36.4% (55/151) |
> | Qwen2.5-Coder-14B-Instruct | 33.6% (46/137) | 35.1% (53/151) |
> | CodeLlama-34B-Instruct FP16 (Ollama) | 21.2% (29/137) | 21.2% (32/151) |
> | Qwen2.5-Coder-7B-Instruct | 14.6% (20/137) | 15.9% (24/151) |
> | CodeLlama-7B-Instruct FP16 (Ollama) | 14.6% (20/137) | 16.6% (25/151) |
> | GLM4-9B FP16 (Ollama) | 13.1% (18/137) | 13.9% (21/151) |
> | GLM4-9B (4-bit, Ollama) | 12.4% (17/137) | 12.6% (19/151) |
>
> \* Opus 4.8's denominator (161/180) comes from its original scoring pass, which excluded only 1
> hazardous rule instead of the standard `--skip-hazardous` set — every other model here (including
> Opus 4.7) uses the standard 137/151 basis. Not a strict apples-to-apples comparison at the top;
> Opus 4.7's 81.0% is the highest score on the standard basis.
>
> Every row above is a single run (temp=0, greedy). A confidence-interval study re-running some
> of these models multiple times is underway — see
> **[Confidence Interval Results](#confidence-interval-results)** below for how much a single run
> can move. The benchmark has also been ported to Ubuntu 24.04 with zero harness code changes —
> see **[Cross-OS Generalizability](#cross-os-generalizability-ubuntu-2404)** below.
>
> Full breakdown in **[benchmark/RESULTS.md](benchmark/RESULTS.md)**.

---

## Pipeline

```
                                          ┌─ ANTHROPIC_API_KEY ─┐
stig-results.xml ──build_dataset──▶ dataset.jsonl ──run_inference──▶ predictions_<model>.jsonl
 (an OpenSCAP STIG    (NL task + hidden    (215 leak-free   (the model writes    (one Bash script
  scan of RHEL 8)      answer + OVAL id)     prompts)         the Bash)            per rule)
                                                                    │
                                          score_remediations.py / run_benchmark.sh
                                        (run each script on AlmaLinux 8, re-check OVAL)
                                                                    ▼
                                            results_<model>.jsonl  +  RESULTS.md
                                          (per-rule pass/fail = did fail→pass flip?)
```

The key design choice: **decouple generation from execution.** One stage produces scripts (needs an
API key or GPU); a separate stage runs and grades them on a throwaway VM (needs only OpenSCAP, no
API key / GPU). That makes runs cheap to repeat and lets you benchmark any model by swapping one flag.

---

## Results

### Model Comparison

| Bucket | Claude Opus 4.8 | Claude Opus 4.7 | GPT-4o | Claude Sonnet 5 | DeepSeek-Coder-33B FP16 | Qwen2.5-Coder-14B | CodeLlama-34B FP16 | Qwen2.5-Coder-7B | CodeLlama-7B FP16 | GLM4-9B FP16 | GLM4-9B (4-bit) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Server config + kernel | 106/117 = **90.6%** | 71/80 = **88.8%** | 54/79 = **68.4%** | 49/80 = **61.2%**\*\* | 36/80 = **45.0%** | 32/79 = **40.5%** | 21/80 = **26.2%** | 19/79 = **24.1%** | 17/80 = **21.2%** | 17/80 = **21.2%** | 17/80 = **21.2%** |
| Audit rules (`audit_rules_*`) | 37/44 = **84.1%** | 40/57 = **70.2%** | 36/58 = **62.1%** | 33/57 = **57.9%**\*\* | 13/57 = **22.8%** | 14/58 = **24.1%** | 8/57 = **14.0%** | 1/58 = **1.7%** | 3/57 = **5.3%** | 1/57 = **1.8%** | 0/57 = **0.0%** |
| **→ Combined server-safe** | **143/161 = 88.8%**\* | **111/137 = 81.0%** | **90/137 = 65.7%** | **82/137 = 59.9%**\*\* | **49/137 = 35.8%** | **46/137 = 33.6%** | **29/137 = 21.2%** | **20/137 = 14.6%** | **20/137 = 14.6%** | **18/137 = 13.1%** | **17/137 = 12.4%** |
| sshd config | 8/15 = 53.3% | 11/14 = **78.6%** | 10/14 = **71.4%** | 7/14 = 50.0% | 6/14 = **42.9%** | 7/14 = 50.0% | 3/14 = **21.4%** | 4/14 = 28.6% | 5/14 = **35.7%** | 3/14 = **21.4%** | 2/14 = **14.3%** |
| Crypto / FIPS | 0/4 = 0% | — | — | — | — | — | — | — | — | — | — |
| Not applicable (GUI / no hardware) | 17 excluded | 17 excluded | 17 excluded | 17 excluded | 17 excluded | 17 excluded | 17 excluded | 17 excluded | 17 excluded | 17 excluded | 17 excluded |
| **All verified applicable** | **151/180 = 83.9%**\* | **122/151 = 80.8%** | **100/151 = 66.2%** | **89/151 = 58.9%**\*\* | **55/151 = 36.4%** | **53/151 = 35.1%** | **32/151 = 21.2%** | **24/151 = 15.9%** | **25/151 = 16.6%** | **21/151 = 13.9%** | **19/151 = 12.6%** |

**Key findings:**
- Claude Opus 4.8 leads at **88.8%** — strongest on both server config (90.6%) and audit rules (84.1%).
- Claude Opus 4.7 scores **81.0%** on the standard 137/151 basis — the highest of any model measured
  on that basis (Opus 4.8's 88.8% uses a larger, non-standard denominator from its original scoring
  pass — see note above the headline table). Opus 4.7 is also the best of every model tested on sshd
  (78.6%).
- GPT-4o scores **65.7%** — solid mid-tier; notably best on sshd (71.4%) but weaker on audit rules (62.1%).
- Claude Sonnet 5 scores **59.9%**\*\* — behind GPT-4o but well ahead of every open-source model.
- DeepSeek-Coder-33B (FP16) scores **35.8%** — narrowly ahead of Qwen2.5-Coder-14B, with the strongest sshd score (42.9%) among open-source models.
- Qwen2.5-Coder-14B scores **33.6%** — 2× the 7B but still well below GPT-4o; audit rules remain a clear weakness (24.1%).
- CodeLlama-34B (FP16) scores **21.2%** — larger than Qwen-14B but noticeably weaker, underperforming even DeepSeek-Coder-33B by a wide margin despite comparable parameter count.
- Qwen2.5-Coder-7B scores **14.6%** — nearly unable to write correct `auditd` rules (1.7%).
- CodeLlama-7B (FP16) ties Qwen2.5-Coder-7B exactly at **14.6%** combined — its sshd score (35.7%)
  is notably better than CodeLlama-34B's (21.4%), an unusual case of the smaller model in a family
  outperforming the larger one on this specific bucket.
- GLM4-9B scores **~13%** regardless of precision (FP16 vs 4-bit) — weakest model tested, essentially unable to write correct `auditd` rules (0-2%).
- Claude scores **1.35× higher** than GPT-4o, **2.5× higher** than DeepSeek-Coder-33B, **2.6× higher** than Qwen 14B, **4.2× higher** than CodeLlama-34B, **6.1× higher** than Qwen 7B, and **~6.8× higher** than GLM4-9B.
- Denominators are normalized to the standard **137 / 151** split (matching Claude/GPT-4o methodology) across every model. Where a run did not score every rule — either because a scoring host crashed mid-run (CodeLlama-34B, GLM4-9B FP16) or because the original published numbers used a smaller denominator (Qwen2.5-Coder-7B) — the unscored/missing rules are counted as failures rather than excluded, so percentages are directly comparable but may understate a model's true rate slightly.
- \*\* Sonnet 5 only produced a usable script for 148 of the 168 standard rules (20 responses had no
  parseable bash block: 13 in server config, 7 in audit). Those 20 are counted as failures against
  the standard 80/57 sub-denominators, same normalization as above.

Scanner: OpenSCAP 1.3.14 · SSG 0.1.81 `stig` profile · Host: AlmaLinux 8 (RHEL-8
binary-compatible, headless server).

### Confidence Interval Results

A single run — even at temp=0 — is one sample. It doesn't tell you how much the number would
move if you asked the model again. We're re-running some models multiple times at
`temperature=0.2` (a distinct seed per run, so each is an independent draw rather than a repeat of
the same greedy output) and pooling the results into a 95% Wilson score interval, treating every
`(rule, run)` pair as one Bernoulli trial.

| Model | Single Run (temp=0) | Pooled (multi-run) | 95% CI |
|---|---|---|---|
| CodeLlama-34B-Instruct FP16 (Ollama) | 21.2% (29/137) | **19.9%** (109/548, 4 runs) | 16.8% – 23.4% |
| Qwen2.5-Coder-14B-Instruct | 33.6% (46/137) | **29.6%** (162/548, 4 runs) | 25.9% – 33.5% |
| GLM4-9B (4-bit, Ollama) | 12.4% (17/137) | **12.2%** (67/548, 4 runs) | 9.7% – 15.2% |
| GLM4-9B FP16 (Ollama) | 13.1% (18/137) | **14.1%** (77/548, 4 runs) | 11.4% – 17.2% |

All figures above are the "Combined Server-Safe" metric, same denominator basis as the headline
table. Each pools the original single-run result together with 3 independent seeded runs
(temp=0.2). CodeLlama-34B's single-run estimate sits inside its CI, near the upper edge.
Qwen2.5-Coder-14B's sits just above its CI's upper edge (33.6% vs. 33.5%) — both original runs
read as somewhat optimistic relative to the pooled result. GLM4-9B (4-bit)'s single-run estimate
sits right in the middle of its (narrow) CI — the most stable of the three so far. GLM4-9B FP16's
sits comfortably inside its CI too. Qwen2.5-Coder-7B is queued for the same treatment (blocked on
GPU pod access to generate its seeded runs); this table will grow once that's resolved.

**How the 137/151 denominators work** (215 dataset rows down to 137/151): ~5 hazardous rules
(crypto policy/FIPS/SSH cipher) are excluded via `--skip-hazardous` since they can sever SSH mid-run;
35 reboot-required kernel/sysctl rules need a separate apply→reboot→rescan phase and aren't part of
this run; of what's left, 17 turn out not-applicable at scan time (GUI/desktop rules on a headless
box) and are excluded since they can't structurally pass or fail. That leaves **151 = "All Verified
Applicable"** (every rule that could pass or fail) and **137 = "Combined Server-Safe"** — 151 minus
the 14 sshd config rules, reported separately because they carry contamination risk (a bad sshd
change can corrupt every rule scored after it on the same host). 137 is a subset of 151
(151 = 137 + 14 sshd), not a different sample — the same exclusion rules apply identically to every
model.

<details>
<summary>Per-run and per-category breakdown</summary>

**CodeLlama-34B-Instruct FP16** — 4 runs total (the original greedy temp=0 run + 3 seeded
temp=0.2 runs):

| Run | Sampling | Combined server-safe |
|---|---|---|
| original | temp=0 (greedy) | 29/137 = 21.2% |
| run1 | temp=0.2, seed=101 | 29/137 = 21.2% |
| run2 | temp=0.2, seed=102 | 25/137 = 18.2% |
| run3 | temp=0.2, seed=103 | 26/137 = 19.0% |
| **pooled** | | **109/548 = 19.9%, 95% CI 16.8–23.4%** |

Per-category, pooled across all 4 runs: server config+kernel 78/320 = 24.4% (CI 20.0–29.4%),
audit rules 31/228 = 13.6% (CI 9.7–18.7%), sshd config 14/56 = 25.0% (CI 15.5–37.7%),
all verified applicable 123/604 = 20.4% (CI 17.3–23.8%).

**Qwen2.5-Coder-14B-Instruct** — 4 runs total (the original greedy temp=0 run, using its published
aggregate score since no per-rule results file was saved for it, plus 3 seeded temp=0.2 runs):

| Run | Sampling | Combined server-safe |
|---|---|---|
| original | temp=0 (greedy) | 46/137 = 33.6% |
| run1 | temp=0.2, seed=101 | 42/137 = 30.7% |
| run2 | temp=0.2, seed=102 | 32/137 = 23.4% |
| run3 | temp=0.2, seed=103 | 42/137 = 30.7% |
| **pooled** | | **162/548 = 29.6%, 95% CI 25.9–33.5%** |

Per-category, pooled across all 4 runs: server config+kernel 117/319 = 36.7% (CI 31.6–42.1%),
audit rules 45/229 = 19.7% (CI 15.0–25.3%), sshd config 27/56 = 48.2% (CI 35.7–61.0%),
all verified applicable 189/604 = 31.3% (CI 27.7–35.1%).

**GLM4-9B 4-bit (Ollama)** — 4 runs total (the original greedy temp=0 run, `glm4/results_glm4_9b_q4.jsonl`,
plus 3 seeded temp=0.2 runs):

| Run | Sampling | Combined server-safe |
|---|---|---|
| original | temp=0 (greedy) | 17/137 = 12.4% |
| run1 | temp=0.2, seed=101 | 17/137 = 12.4% |
| run2 | temp=0.2, seed=102 | 15/137 = 10.9% |
| run3 | temp=0.2, seed=103 | 18/137 = 13.1% |
| **pooled** | | **67/548 = 12.2%, 95% CI 9.7–15.2%** |

Per-category, pooled across all 4 runs: server config+kernel 66/320 = 20.6% (CI 16.6–25.4%),
audit rules 1/228 = 0.4% (CI 0.1–2.4%), sshd config 13/56 = 23.2% (CI 14.1–35.8%),
all verified applicable 80/604 = 13.2% (CI 10.8–16.2%). Notably, GLM4-9B 4-bit is nearly
incapable of writing correct `auditd` rules across every run (0-1 passes out of 57 each time) —
the tightest, most consistent failure mode seen in this study so far.

**GLM4-9B FP16 (Ollama)** — 4 runs total (the original greedy temp=0 run, `glm4/results_glm4_9b_fp16.jsonl`,
plus 3 seeded temp=0.2 runs):

| Run | Sampling | Combined server-safe |
|---|---|---|
| original | temp=0 (greedy) | 18/137 = 13.1% |
| run1 | temp=0.2, seed=101 | 24/137 = 17.5% |
| run2 | temp=0.2, seed=102 | 17/137 = 12.4% |
| run3 | temp=0.2, seed=103 | 18/137 = 13.1% |
| **pooled** | | **77/548 = 14.1%, 95% CI 11.4–17.2%** |

Per-category, pooled across all 4 runs: server config+kernel 74/320 = 23.1% (CI 18.8–28.0%),
audit rules 3/228 = 1.3% (CI 0.4–3.8%), sshd config 7/56 = 12.5% (CI 6.2–23.6%),
all verified applicable 84/604 = 13.9% (CI 11.4–16.9%). Almost as weak on `auditd` as the
4-bit variant (1.3% vs 0.4%) — precision doesn't move the needle much for this model; both
GLM4-9B variants are essentially unable to write correct audit rules regardless of quantization.
run3 was the most operationally troublesome run of this entire study: its scoring droplet's
`sshd` broke mid-run (a malformed config line written by one of GLM4-9B's own remediation
scripts, the same failure mode suspected behind most of this project's SSH dropouts), forcing a
restart on a second droplet with the completed rows pre-seeded so scoring could resume rather
than restart from zero; one rule (`accounts_users_home_files_groupownership`) never completed
after a second hang and was recorded as a failure rather than left unscored.

Reproduce it: `python3 benchmark/compute_ci.py --model <name> <results_or_log_file> [...]`. It
accepts either standard `results_<model>.jsonl` grader output or a captured
`score_remediations.py` text log (used for most runs above, since scoring-host SSH access was
repeatedly lost mid-run across both batches of droplets and results were retrieved via console
instead — see `ci_runs/` for the raw per-run predictions, logs, and `CI_RESULTS.md` for the full
breakdown).

</details>

### Claude Opus 4.8 — Full Breakdown

Counting is exact and reproducible from `benchmark/results_opus_full.jsonl` (198 rows). Of the
**200** scripts Claude generated, **198 were scored** and **197 functionally verified** — only the
single `gnutls` crypto rule is unverified (it severs SSH access and needs a snapshot-revert VM). The
2 unscored scripts (`xwindows_remove_packages`, `xwindows_runlevel_target`) target X11/GUI and are
not applicable to a headless server. The 32 reboot-required sysctl/kernel rules were verified in a
dedicated apply → reboot → rescan run (**28/32 pass**), then independently re-confirmed by a
full-profile `oscap` scan.

**Core finding:** Claude rarely fails to *write* a working hardening script. It fails on the gap
between "functionally hardened" and "hardened the exact way this OVAL check verifies" — a
non-obvious required value, a specific knob among valid alternatives (`login.defs` vs `pam`), or an
exact audit key string. This mirrors real compliance: a correctly-hardened box can still be flagged
non-compliant because the scanner expected one specific value/mechanism.

---

### Cross-OS Generalizability (Ubuntu 24.04)

**HardEval ports to Ubuntu with zero code changes** — only the OVAL datastream (`ssg-rhel8-ds.xml` →
`ssg-ubuntu2404-ds.xml`) and the OS name in the prompt text change. Both OSes' official STIGs share
the same underlying rule taxonomy (same rule names, same OVAL-based pass/fail definition), so the
harness just points at whichever OS's own content is on the box — nothing RHEL-specific is baked in.
Models confirmed this independently: unprompted, they wrote `apt`/`dpkg` for Ubuntu and `yum`/`rpm`
for RHEL, correctly inferring the right tooling from the OS name alone. All 5 models scored so far,
each on its own clean VM:

| Model | Server config + kernel | Audit rules | sshd config | Total |
|---|---|---|---|---|
| Claude Opus 4.8 | 14/35 (40.0%) | 42/47 (89.4%) | 4/6 (66.7%) | **60/88 (68.2%)** |
| GPT-4o | 15/35 (42.9%) | 36/47 (76.6%) | 4/6 (66.7%) | **55/88 (62.5%)** |
| Claude Sonnet 5 | 16/35 (45.7%) | 35/47 (74.5%) | 2/6 (33.3%) | **53/88 (60.2%)** |
| gpt-5.4-mini | 15/35 (42.9%) | 0/47 (0.0%)\* | 3/6 (50.0%) | **18/88 (20.5%)**\* |
| Claude Haiku 4.5 | 8/35 (22.9%) | 0/47 (0.0%)\* | 3/6 (50.0%) | **11/88 (12.5%)**\* |

Real, non-trivial pass rates — the ported pipeline produces genuine signal, not degenerate
all-pass/all-fail output.

\* Both flagged runs had one script break the audit subsystem (both times via `sssd_enable_smartcards`),
which poisoned every `audit_rules_*` check scored after it. Their 0/47 audit score is a scoring
artifact, not a real measurement of either model's ability.

**Why only 88 rules, not RHEL8's 168:** Ubuntu's own official STIG simply covers fewer hardening
concepts than RHEL8's (275 controls vs. 453 — a younger, less complete guide). Only 88 of RHEL8's
168 scoreable rules have a matching rule in Ubuntu's STIG at all; the other 80 rely on RHEL-only
mechanisms (SELinux, `authselect`) that don't exist on Ubuntu. The 88 aren't a subset we picked —
they're every rule concept the two operating systems' official guides actually have in common.

---

### Cross-Author Prompt Validation (GPT-4o-authored)

The main benchmark's task prompts were authored by Claude from the raw STIG metadata (title,
severity, rationale, description), then checked for leakage. To test whether that authoring
process — and its leak-free result — is specific to Claude or holds for an independently-authored
prompt set, GPT-4o authored its own parallel prompt set from the exact same raw metadata, using the
identical instructions and leak checker (`benchmark/generate_prompts_gpt.py`). GPT-4o's initial
pass flagged 13/215 rows for possible leakage (vs. Claude's 0 genuine leaks); 6 were confirmed real
mechanism leaks (exact file paths / config module names) and regenerated.

Models are then run and scored against this GPT-4o-authored prompt set exactly as with the main
benchmark — same harness, same AlmaLinux 8 host, same OVAL grading:

| Model | Server config + kernel | Audit rules | sshd config | Combined server-safe | All verified applicable |
|---|---|---|---|---|---|
| GPT-4o | 44/80 = 55.0% | 29/57 = 50.9% | 11/14 = 78.6% | **73/137 = 53.3%** | **84/151 = 55.6%** |
| Claude Opus 4.8 | 61/80 = 76.2% | 40/57 = 70.2% | 9/14 = 64.3% | **101/137 = 73.7%** | **110/151 = 72.8%** |

For comparison, on the original **Claude**-authored prompts (same underlying rules), GPT-4o scores
65.7% (90/137) and Opus scores 88.8% — both *higher* than their scores on the GPT-4o-authored set
(53.3% and 73.7% respectively). That's the same direction for both models, not a self-vs-other
effect: neither model does better on the prompts it effectively wrote for itself. GPT-4o actually
does *worse* on its own authored prompts than on Claude's. The consistent pattern is that
Claude-authored prompts yield higher solve rates from both solvers — evidence the prompt set's own
clarity/specificity matters more here than any relationship between the authoring model and the
solving model.

---

## What's in this repo

### Core benchmark (`benchmark/`)

| Path | What it is |
|---|---|
| **`benchmark/dataset.jsonl`** | **The benchmark itself.** 233 rows (215 with prompts). Each row = `prompt`, hidden `reference_bash`, hidden `oval_check_id`, `stig_id`, `severity`, `reboot_required`, `initial_state`. |
| **`benchmark/build_dataset.py`** | Parses `stig-results.xml` → `dataset.jsonl`. With `--generate` authors **leak-free** task prompts via the Anthropic API. |
| **`benchmark/run_inference.py`** | Feeds each `prompt` to any Anthropic model, extracts the bash block → `predictions_<model>.jsonl`. The only part that needs an API key. |
| **`benchmark/predictions_opus.jsonl`** | Claude Opus 4.8's 200 generated scripts (the run scored here). |
| **`benchmark/predictions_kernel.jsonl`** | The 32 reboot-required sysctl/kernel scripts (scored via reboot phase). |
| **`benchmark/score_remediations.py`** | **The grader.** Runs on the target host: pre-scan → run script → post-scan; `passed = (post == pass)`. Python 3.6-compatible (runs on stock RHEL-8). |
| **`benchmark/run_benchmark.sh`** | One-command orchestrator: normal rules + apply/reboot/rescan for kernel rules. |
| **`benchmark/results_opus_full.jsonl`** | Per-rule results (198 rows) for Claude Opus 4.8. |
| **`benchmark/compute_scores.py`** | Recomputes every number in the results table from any `results_*.jsonl` — reviewer-verifiable. |
| **`benchmark/RESULTS.md`** | Full written analysis: buckets, failure clusters, caveats. |
| **`benchmark/BENCHMARK_COMPOSITION.md`** | Rule taxonomy: 14 functional domains, severity distribution, NIST mapping, shell-scripting skill profile. |
| **`stig-results.xml`** | Source of truth: OpenSCAP scan of an unhardened RHEL-8 host under the DISA STIG profile. Everything downstream is derived from this file. |

### OpenAI model inference (`openai_models/`)

Standalone folder to benchmark OpenAI models. No GPU needed — runs from any machine with an API key.

| Path | What it is |
|---|---|
| **`openai_models/run_inference_openai.py`** | Inference client for any OpenAI model (`gpt-4o`, `o4-mini`, `o3`). Resumable, 3-retry, extracts bash blocks. o-series models use `reasoning_effort` parameter. |
| **`openai_models/dataset.jsonl`** | The 215 benchmark prompts (same as `benchmark/dataset.jsonl`). |
| **`openai_models/predictions_gpt4o.jsonl`** | GPT-4o predictions (215 rules). |
| **`openai_models/requirements.txt`** | `openai>=1.0.0` |

### Open-source model inference (`qwen/`)

Self-contained folder to benchmark any open-source model on a GPU box. Produces
`predictions_<model>.jsonl`, graded by the **same** `score_remediations.py` — results are directly
comparable to the Claude run.

| Path | What it is |
|---|---|
| **`qwen/dataset.jsonl`** | The 215 benchmark prompts (same as `benchmark/dataset.jsonl`). |
| **`qwen/run_inference_qwen.py`** | OpenAI-compatible inference client (works with vLLM, Ollama, TGI). Resumable, 3-retry logic, `--wait-for-server` flag. |
| **`qwen/serve_qwen.sh`** | Installs vLLM if needed and serves a model on `:8000`. |
| **`qwen/run_all.sh`** | One-shot: start vLLM → wait → run all 215 prompts. Auto-names output from model ID. |
| **`qwen/run_models.sh`** | Sequential multi-model runner: serve → infer → kill → next model. |
| **`qwen/models.txt`** | Default model list (Qwen2.5-Coder-7B, 32B, DeepSeek-Coder-V2-Lite). |
| **`qwen/predictions_qwen25coder7b.jsonl`** | Qwen2.5-Coder-7B-Instruct predictions (215 rules). |
| **`qwen/requirements.txt`** | Client dependency (`openai`). |

### GLM / CodeLlama / DeepSeek Coder inference (`glm4/`, `llama/`, `deepseek/`)

Same pattern as `qwen/` — served via [Ollama](https://ollama.com) instead of vLLM, one folder per
model family. `glm/` also has a vLLM-based runner for models too large/unsupported for Ollama.

| Path | What it is |
|---|---|
| **`glm4/predictions_glm4_9b_q4.jsonl`** | GLM4-9B, 4-bit (Ollama default `Q4_K_M`), 215 rows. |
| **`glm4/results_glm4_9b_q4.jsonl`** | Scored results (168 rows scored, `--skip-hazardous`). |
| **`glm4/predictions_glm4_9b_fp16.jsonl`** | GLM4-9B, full FP16 precision, 215 rows. |
| **`llama/predictions_codellama_{7b,13b,34b}-instruct-fp16.jsonl`** | CodeLlama family, full FP16, 215 rows each. |
| **`deepseek/predictions_deepseek-coder_33b-instruct-fp16.jsonl`** | DeepSeek Coder 33B, full FP16, 215 rows. |

---

## Reproduce it

### Stage 1 — Build the dataset *(optional; already committed)*

```bash
git clone https://github.com/manoharvellala/ClaudeBenchmarkONSTIGRules.git
cd ClaudeBenchmarkONSTIGRules
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...        # your own key
python3 benchmark/build_dataset.py --results stig-results.xml --generate --out benchmark/dataset.jsonl
```

> Never commit your API key. Pass it via the environment variable as above.

### Stage 2a — Inference with a Claude model *(needs Anthropic API key)*

```bash
python3 benchmark/run_inference.py \
  --model claude-opus-4-8 \
  --dataset benchmark/dataset.jsonl \
  --out benchmark/predictions_opus.jsonl
```

Swap `--model` for any Anthropic model (`claude-sonnet-4-6`, `claude-haiku-4-5-…`).

### Stage 2b — Inference with an OpenAI model *(needs OpenAI API key)*

```bash
cd openai_models/
pip install -r requirements.txt
export OPENAI_API_KEY=sk-...
python3 run_inference_openai.py --model gpt-4o --out predictions_gpt4o.jsonl
# supports gpt-4o, o4-mini, o3 — resumable, 3-retry logic
```

### Stage 2c — Inference with an open-source model *(needs a GPU box)*

On a box with a 24 GB+ NVIDIA GPU (e.g. RunPod A100):

```bash
# install vLLM once
pip install vllm openai

# run inference for a model
export HF_HOME=/path/to/large/disk   # model weights (~15 GB for 7B)
cd qwen/
bash run_all.sh Qwen/Qwen2.5-Coder-7B-Instruct
# output: predictions_qwen__qwen2.5_coder_7b_instruct.jsonl
```

See `qwen/README.md` for GPU requirements and multi-model runs.

### Stage 3 — Score on a throwaway RHEL-8 VM *(no API key / GPU needed)*

```bash
# on AlmaLinux 8 / Rocky 8 / RHEL 8, as root:
dnf install -y openscap-scanner scap-security-guide python3
DS=/usr/share/xml/scap/ssg/content/ssg-almalinux8-ds.xml

# copy score_remediations.py, dataset.jsonl, predictions_<model>.jsonl to /root/
python3 score_remediations.py \
  --predictions predictions_<model>.jsonl \
  --dataset dataset.jsonl \
  --datastream "$DS" \
  --phase normal --no-prescan --skip-hazardous \
  --out results_<model>.jsonl

python3 compute_scores.py results_<model>.jsonl
```

`compute_scores.py` prints the same bucket table for any model — drop-in comparable to Claude's numbers.

### `score_remediations.py` flags

| Flag | Effect |
|---|---|
| `--phase normal\|apply\|rescan` | `normal` = non-reboot rules; `apply` = run reboot-rule scripts; `rescan` = finalize after reboot. |
| `--no-prescan` | Trust the dataset's recorded `initial_state` (halves oscap calls). |
| `--skip-hazardous` | Skip crypto/FIPS/ssh-cipher rules that can sever SSH access. |
| `--limit N` | Score only the first N rules (smoke test). |

---

## How the grading works (the oracle)

```
oscap xccdf eval --rule <rule_id>   →  expect FAIL   (box not hardened yet)
bash <model_generated_script>       →  the model's attempt
oscap xccdf eval --rule <rule_id>   →  PASS = correct, FAIL = didn't satisfy the check
```

`oscap` exit codes: **0 = pass, 2 = fail**. A rule is scored `passed` only if the post-scan flips
to pass. Because the same OVAL definition that DISA ships is the judge, there is no ambiguity and no
reward for "looks plausible."

**Safety:** generated scripts run under a stub `PATH` that turns `reboot`/`shutdown`/`poweroff` and
`systemctl reboot` into no-ops, so a model cannot brick the box mid-run. Reboot-required rules are
handled explicitly by the `apply`/`rescan` phases.

---

## Benchmark composition

200 RHEL-8 DISA STIG rules across 14 functional domains. See
**[benchmark/BENCHMARK_COMPOSITION.md](benchmark/BENCHMARK_COMPOSITION.md)** for the full taxonomy:
severity distribution (175 medium / 16 low / 9 high), NIST 800-53 mapping, and the shell-scripting
skill profile required (auditd syntax, sysctl, PAM, sshd_config, GRUB, kernel module blacklisting).

---

## Caveats

1. **Crypto/FIPS rules (0/4 verified) are an infrastructure artifact, not a model failure.** They
   restrict SSH ciphers and lock you out mid-run. Scoring them fairly needs per-rule snapshot revert.
2. **sshd (53%) is partly contaminated** — crypto rules can break sshd config when run on the same
   host. Use `--skip-hazardous` to isolate.
3. **Single host, no snapshot revert** → some cross-rule interaction is possible.
4. The result characterizes **the model on the RHEL-8 STIG via blind/mechanism-hidden prompts.** A
   value-injected variant (handing the model the exact `xccdf_value`) would separately measure
   "knows the magic number" vs "can implement it."

---

## Credits

- STIG content, OVAL checks and reference remediations: **[ComplianceAsCode/content](https://github.com/ComplianceAsCode/content)** (BSD-3-Clause) — 405 contributors, 43,427 commits, maintained since 2011 by Red Hat and SCAP security engineers.
- Functional scanning: **[OpenSCAP](https://www.open-scap.org/)**.
- Benchmark harness, prompts, analysis, and open-source inference runner: this repo (MIT, see `LICENSE`).
