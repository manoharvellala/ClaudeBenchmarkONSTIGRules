# Claude Benchmark on STIG Rules

**A reproducible benchmark that measures how well an LLM can write real Linux security-hardening
scripts — graded functionally, not by string-matching.**

For each [DISA STIG](https://public.cyber.mil/stigs/) rule we hand the model a plain-English security
requirement (the *what* and *why*, with the *how* deliberately hidden), let it generate a Bash
remediation script, then **run that script on a real RHEL-8-family host and re-scan the rule with
OpenSCAP/OVAL**. The script is correct **iff** the rule flips `fail → pass`. No human judgement, no
reference-script diffing — a compliance scanner is the oracle.

> ### 🏁 Headline result — Claude Opus 4.8
> **88.8% (143/161) of applicable server-safe RHEL-8 STIG rules remediated correctly**, verified
> functionally via OpenSCAP/OVAL. Failures were almost never coding errors — they were *value/mechanism
> mismatches* (e.g. the rule text says "≥ 5000 hashing rounds" but the STIG profile secretly requires
> **100000**). Full breakdown in **[benchmark/RESULTS.md](benchmark/RESULTS.md)**.

This is the same evaluation pattern as **HumanEval / SWE-bench**:

```
                                              ┌─ ANTHROPIC_API_KEY ─┐
 stig-results.xml ──build_dataset──▶ dataset.jsonl ──run_inference──▶ predictions_<model>.jsonl
  (an OpenSCAP STIG    (NL task + hidden    (215 leak-free   (the model writes    (one Bash script
   scan of RHEL 8)      answer + OVAL id)     prompts)         the Bash)            per rule)
                                                                      │
                                            score_remediations.py / run_benchmark.sh
                                          (run each script on AlmaLinux 8, re-check OVAL)
                                                                      ▼
                                              results_opus_full.jsonl  +  RESULTS.md
                                            (per-rule pass/fail = did fail→pass flip?)
```

The key design choice: **decouple generation from execution.** One stage produces scripts (needs an
API key); a separate stage runs and grades them on a throwaway VM (needs only OpenSCAP, no API key).
That makes runs cheap to repeat and lets you benchmark any model by swapping one flag.

---

## Results

Model under test: `claude-opus-4-8` · Scanner: OpenSCAP 1.3 with SSG 0.1.81 `stig` profile ·
Host: AlmaLinux 8 (RHEL-8 binary-compatible, headless server).

| Bucket | Passed | Total | Rate |
|---|---:|---:|---:|
| **Server config + kernel** (packages, PAM, mount, GRUB, sysctl, kernel-modules, coredump, rsyslog, chronyd, fapolicyd, file-perms, sssd, usbguard) | **106** | **117** | **90.6%** |
| **Audit rules** (`audit_rules_*`) | **37** | **44** | **84.1%** |
| **→ Combined server-safe (headline)** | **143** | **161** | **88.8%** |
| sshd config | 8 | 15 | 53.3% *(partly crypto-contaminated)* |
| Crypto / FIPS (access-breakers) | 0 | 4 | 0% *(+1 unverified; sever SSH, need snapshot isolation)* |
| Not applicable (GUI / no hardware) | — | 17 | excluded |
| **All verified applicable** | **151** | **180** | **83.9%** |

Counting is exact and reproducible from `benchmark/results_opus_full.jsonl` (198 rows). Of the **200**
scripts Claude generated, **198 were scored** and **197 functionally verified** — only the single
`gnutls` crypto rule is unverified (it severs SSH access and needs a snapshot-revert VM). The 2 unscored
scripts (`xwindows_remove_packages`, `xwindows_runlevel_target`) target X11/GUI and are not applicable to
a headless server. "All verified applicable" (151/180) excludes the 17 not-applicable rows and the 1
unverified rule. The 32 reboot-required sysctl/kernel rules were verified in a dedicated apply → reboot →
rescan run (**28/32 pass**), then independently re-confirmed by a full-profile `oscap` scan.

**Core finding:** Claude rarely fails to *write* a working hardening script. It fails on the gap between
"functionally hardened" and "hardened the exact way this OVAL check verifies" — a non-obvious required
value, a specific knob among valid alternatives (`login.defs` vs `pam`), or an exact audit key string.
This mirrors real compliance: a correctly-hardened box can still be flagged non-compliant because the
scanner expected one specific value/mechanism. Read the full failure analysis in
**[benchmark/RESULTS.md](benchmark/RESULTS.md)**.

---

## What's in this repo

| Path | What it is |
|---|---|
| **`stig-results.xml`** | The source of truth: an OpenSCAP scan of an unhardened RHEL-8 host under the DISA STIG profile. Fully rendered (no templating) — per rule it contains the title/description/rationale, the reference fix script, the OVAL check id, and the initial pass/fail. Everything downstream is derived from this one file. |
| **`benchmark/build_dataset.py`** | Parses `stig-results.xml` → `dataset.jsonl`. With `--generate` it authors the **leak-free** task prompts via the Anthropic API (states the requirement, hides file paths / directive names / commands). A programmatic `leaked()` check flags any prompt that accidentally reveals the mechanism. |
| **`benchmark/build_dataset_with_remediation.py`** | A *fix-aware* variant where the prompt author is allowed to see the reference script. More complete prompts, but leakier — kept for comparison only. |
| **`benchmark/dataset.jsonl`** | **The benchmark itself.** 233 rows (215 with prompts). Each row = `prompt`, hidden `reference_bash`, hidden `oval_check_id`, `stig_id`, `severity`, `reboot_required`, `initial_state`. |
| **`benchmark/dataset_with_remediation.jsonl`** | The fix-aware dataset (comparison only). |
| **`benchmark/run_inference.py`** | Feeds each `prompt` to the model under test, extracts the ```bash``` block → `predictions_<model>.jsonl`. Resumable; the *only* part that needs an API key. |
| **`benchmark/predictions_opus.jsonl`** | Claude Opus 4.8's 200 generated scripts (the run scored here). |
| **`benchmark/predictions_kernel.jsonl`** | The 32 reboot-required sysctl/kernel scripts (scored via the reboot phase). |
| **`benchmark/score_remediations.py`** | **The grader.** Runs on the target host: pre-scan → run the model's script → post-scan; `passed = (post == pass)`. Resumable. Pure stdlib, **Python 3.6-compatible** (runs on stock RHEL-8 python). |
| **`benchmark/run_benchmark.sh`** | One-command orchestrator: scores non-reboot rules, applies reboot rules, does one controlled reboot, auto-rescans on boot. |
| **`benchmark/results_opus_full.jsonl`** | Per-rule machine-readable results (198 rows) behind the table above. |
| **`benchmark/compute_scores.py`** | Recomputes every number in the results table from `results_opus_full.jsonl` (`python3 benchmark/compute_scores.py`) — so every figure is reviewer-verifiable. |
| **`benchmark/RESULTS.md`** | The written analysis: buckets, failure clusters, caveats, the paper one-liner. |
| **`benchmark/sample_*.md`** | Human-readable samples of generated prompts and predictions (eyeball the dataset quality without running anything). |
| **`benchmark/test_generate*.py`** | Cheap synchronous dry-runs of the prompt generators (a few rules, no batch job). |
| **`products/rhel8/controls/stig_rhel8.yml`** | The RHEL-8 STIG control→rule mapping, from ComplianceAsCode, for cross-referencing STIG IDs. |

---

## Reproduce it

There are three stages. **Stage 1 (dataset) and Stage 2 (inference) are already done and committed** —
you only need to redo them to regenerate prompts or benchmark a different model. **Stage 3 (scoring) is
the one to run** to verify the result yourself.

### Prerequisites

- An **Anthropic API key** — only for Stages 1 & 2. Get one at <https://console.anthropic.com>.
- A **RHEL-8-family VM** for Stage 3: AlmaLinux 8 / Rocky 8 / RHEL 8, **≥ 2 GB RAM**, root access. A
  cheap cloud droplet works (this run used DigitalOcean AlmaLinux 8). **Use a throwaway box** — these
  scripts harden (and sometimes lock down) the machine on purpose.

```bash
git clone https://github.com/manoharvellala/ClaudeBenchmarkONSTIGRules.git
cd ClaudeBenchmarkONSTIGRules
export ANTHROPIC_API_KEY=sk-ant-...        # your own key (Stages 1 & 2 only)
```

> ⚠️ **Never commit your key.** Pass it via the `ANTHROPIC_API_KEY` environment variable as above; it is
> already covered by `.gitignore` patterns. If a key is ever pasted into a file or shell history, rotate
> it in the Anthropic console.

### Stage 1 — Build the dataset *(optional; already committed)*

```bash
pip install -r requirements.txt
python3 benchmark/build_dataset.py --results stig-results.xml --generate --out benchmark/dataset.jsonl
```

`--extract-only` skips the API and just pulls metadata + reference scripts (no prompts). The full
`--generate` run authors all 215 leak-free prompts via the Anthropic API.

### Stage 2 — Inference: a model writes the scripts *(needs API key)*

```bash
python3 benchmark/run_inference.py \
  --model claude-opus-4-8 \
  --dataset benchmark/dataset.jsonl \
  --out benchmark/predictions_opus.jsonl
```

Swap `--model` for any Anthropic model (`claude-sonnet-4-6`, `claude-haiku-4-5-…`) to benchmark it — the
harness is model-agnostic; only the solver call changes. The run is resumable (re-running skips rules
already in the out file) and flushes after every rule, so a crash or credit-out loses nothing.

### Stage 3 — Score: run + verify on the VM *(no API key; this is the real benchmark)*

On the throwaway RHEL-8 host, as root:

```bash
# 1. install the scanner + the STIG content
dnf install -y openscap-scanner scap-security-guide python3
DS=/usr/share/xml/scap/ssg/content/ssg-almalinux8-ds.xml   # or ssg-rhel8-ds.xml on RHEL

# 2. copy this repo's benchmark/ dir onto the box, then:

# 2a. score all non-reboot rules, skipping access-breakers (crypto/FIPS/ssh-cipher):
python3 score_remediations.py \
  --predictions predictions_opus.jsonl \
  --dataset dataset.jsonl \
  --datastream "$DS" \
  --phase normal --no-prescan --skip-hazardous \
  --out results.jsonl

# 2b. OR run the whole thing end-to-end, including the reboot-required rules,
#     with a single controlled reboot + automatic post-boot rescan:
bash run_benchmark.sh predictions_opus.jsonl
```

`score_remediations.py` flags:

| Flag | Effect |
|---|---|
| `--phase normal\|apply\|rescan` | `normal` = non-reboot rules; `apply` = run reboot-rule scripts and mark them pending; `rescan` = finalize pending rules after a reboot. |
| `--no-prescan` | Trust the dataset's recorded `initial_state` instead of re-scanning before each script (halves the oscap calls). |
| `--skip-hazardous` | Skip crypto/FIPS/ssh-cipher/grub rules that can sever SSH access on a single live host. |
| `--limit N` | Score only the first N rules (smoke test). |

Output: `results.jsonl` (one row per rule with `post_scan` and `passed`). Compare against the published
`benchmark/results_opus_full.jsonl`.

---

## How the grading works (the oracle)

For one rule, `score_remediations.py` does:

```
oscap xccdf eval --rule <rule_id>   →  expect FAIL   (the box isn't hardened yet)
bash <model_generated_script>       →  the model's attempt
oscap xccdf eval --rule <rule_id>   →  PASS = success, FAIL = the script didn't satisfy the check
```

`oscap` exit codes: **0 = pass, 2 = fail**. A rule is scored `passed` only if the post-scan flips to
pass. Because the same OVAL definition that DISA ships is the judge, there's no ambiguity and no reward
for "looks plausible."

**Safety:** generated scripts run under a stub `PATH` that turns `reboot`/`shutdown`/`poweroff`/`halt`
and `systemctl reboot` into no-ops, so a model can't brick the box mid-run. Genuinely reboot-required
rules are handled explicitly by the `apply`/`rescan` phases.

---

## Caveats (read before quoting a number)

1. **Crypto/FIPS rules (0/4 verified, +1 unverified) are an infrastructure artifact, not a model failure.** They restrict SSH
   ciphers/algorithms and lock you out of a single live host mid-run. Scoring them fairly needs a local
   libvirt/QEMU VM with **per-rule snapshot revert** (future work) — that's also the only rigorous way to
   eliminate cross-rule contamination.
2. **sshd (53%) is partly contaminated** — in one run the crypto rules executed before the sshd rules and
   broke sshd's config. A `--skip-hazardous` run isolates this.
3. **Single host, no snapshot revert** → some cross-rule interaction is possible. The buckets are scored
   on separate boxes to limit this.
4. The result characterizes **`claude-opus-4-8` on the RHEL-8 STIG via the blind/mechanism-hidden prompt
   set.** A *value-injected* prompt variant (that hands the model the exact `xccdf_value`) would separate
   "knows the magic number" from "can implement it" — a planned follow-up.

---

## Credits

- STIG content, OVAL checks and reference remediations come from
  **[ComplianceAsCode/content](https://github.com/ComplianceAsCode/content)** (BSD-3-Clause).
- Functional scanning by **[OpenSCAP](https://www.open-scap.org/)**.
- Benchmark harness, prompts, and analysis: this repo (MIT, see `LICENSE`).

Built on the methodology from the author's STIG-remediation LLM fine-tuning work, generalized into a
reusable, model-agnostic benchmark.
