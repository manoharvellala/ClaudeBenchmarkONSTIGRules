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
> | **Claude Opus 4.8** | **88.8%** (143/161) | **83.9%** (151/180) |
> | GPT-4o | 65.7% (90/137) | 66.2% (100/151) |
> | Qwen2.5-Coder-14B-Instruct | *(scoring in progress)* | *(scoring in progress)* |
> | Qwen2.5-Coder-7B-Instruct | 16.3% (20/123) | 17.5% (24/137) |
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

| Bucket | Claude Opus 4.8 | GPT-4o | Qwen2.5-Coder-14B | Qwen2.5-Coder-7B |
|---|---|---|---|---|
| Server config + kernel | 106/117 = **90.6%** | 54/79 = **68.4%** | *(pending)* | 19/79 = **24.1%** |
| Audit rules (`audit_rules_*`) | 37/44 = **84.1%** | 36/58 = **62.1%** | *(pending)* | 1/44 = **2.3%** |
| **→ Combined server-safe** | **143/161 = 88.8%** | **90/137 = 65.7%** | *(pending)* | **20/123 = 16.3%** |
| sshd config | 8/15 = 53.3% | 10/14 = **71.4%** | *(pending)* | 4/14 = 28.6% |
| Crypto / FIPS | 0/4 = 0% | — | — | — |
| Not applicable (GUI / no hardware) | 17 excluded | 17 excluded | 17 excluded | 17 excluded |
| **All verified applicable** | **151/180 = 83.9%** | **100/151 = 66.2%** | *(pending)* | **24/137 = 17.5%** |

**Key findings:**
- Claude Opus 4.8 leads at **88.8%** — strongest on both server config (90.6%) and audit rules (84.1%).
- GPT-4o scores **65.7%** — solid mid-tier; notably best on sshd (71.4%) but weaker on audit rules (62.1%).
- Qwen2.5-Coder-7B scores **16.3%** — nearly unable to write correct `auditd` rules (2.3%).
- Claude scores **1.35× higher** than GPT-4o and **5.4× higher** than Qwen 7B on combined server-safe.

Scanner: OpenSCAP 1.3.14 · SSG 0.1.81 `stig` profile · Host: AlmaLinux 8 (RHEL-8
binary-compatible, headless server).

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
