# Benchmark Composition — What the 200 Rules Cover

All figures below are computed directly from `dataset.jsonl` / `results_opus_full.jsonl`
(the source RHEL-8 DISA STIG scan). This document characterizes **what capability the
benchmark measures** so results can be described precisely.

## At a glance

- **200** rules total (drawn from the RHEL-8 DISA STIG, every one a control that failed on an
  unhardened baseline and ships with an automatable check).
- **Severity:** 175 medium · 16 low · 9 high (CAT II–dominant, matching the real STIG distribution).
- **14 functional domains** of Linux system hardening (table below).
- **35 / 200** rules are persistence/reboot-sensitive (must survive a reboot, not just take effect
  at runtime), exercising durability — not just one-shot commands.
- Each rule is graded **functionally**: run the model's Bash on a live RHEL-8 host, re-run the
  rule's DISA OVAL check, score pass **iff** the rule flips `fail → pass`.

## Coverage by functional domain

| # | Domain | Rules | What capability it tests | Opus 4.8 verified |
|--:|---|--:|---|--:|
| 1 | **Audit & accountability** (`auditd`, audit.rules) | 44 | Authoring kernel audit rules with exact syscall/field/key syntax; configuring `auditd` retention, disk-full, and flush policy | 37/44 |
| 2 | **Authentication, PAM & password policy** | 33 | Editing PAM stacks / `authselect`, `pwquality`, `faillock`, `login.defs`; enforcing complexity, lockout, aging, hashing | 25/33 |
| 3 | **Kernel hardening** (`sysctl`, module blacklist) | 32 | Setting & persisting network/kernel `sysctl` parameters; blacklisting unused kernel modules | 28/32 |
| 4 | **Package & service management** | 18 | Installing/removing packages and enabling/masking `systemd` services to reduce attack surface | 15/18 |
| 5 | **SSH server hardening** | 17 | Editing `sshd_config` directives (timeouts, banners, auth restrictions, ciphers/MACs) | 8/17 |
| 6 | **Privilege, identity & misc hardening** | 12 | `sudo` re-auth, SSSD/smartcard, `authselect`, `fapolicyd` default-deny, disabling Ctrl-Alt-Del, GPG check | 9/12 |
| 7 | **Login banners, GUI & session lock** (GNOME/`dconf`) | 12 | DoD warning banners, screensaver/idle lock, disabling the GUI user list & auto-login | 1/10* |
| 8 | **System logging & time services** (`rsyslog`, `chrony`, `journald`) | 8 | Configuring log forwarding, time sync, journald persistence | 8/8 |
| 9 | **Boot / GRUB kernel command line** | 6 | Adding `audit=1`, `audit_backlog_limit`, `slub_debug`, etc. via the bootloader | 6/6 |
| 10 | **Filesystem & mount options** | 5 | Applying `nodev`/`nosuid`/`noexec` mount options; partition separation | 5/5 |
| 11 | **Integrity & mandatory access control** (AIDE, SELinux, `fapolicyd`) | 5 | Initializing file-integrity baselines; enforcing MAC/allow-listing | 4/5 |
| 12 | **Cryptographic policy / FIPS** | 3 | System-wide crypto-policy and FIPS mode (access-breaking; see caveats) | 0/2 |
| 13 | **Process & memory protection** | 3 | Disabling core dumps, restricting `ptrace`/`kexec` | 3/3 |
| 14 | **File & directory permissions** | 1 | Correcting ownership/mode on security-relevant paths | 1/1 |
| 15 | **Peripheral / device control** (USBGuard) | 1 | Generating and enforcing a USB device policy | 1/1 |

\* Two GUI rules (`xwindows_remove_packages`, `xwindows_runlevel_target`) are N/A on a headless
server and were excluded from scoring; the verified denominator for that row is 10.

> Domains 1–15 sum to 200. (Network firewall rules — `firewalld`/`nftables` — are intentionally
> absent: none appeared among the failed, automatable STIG rules in the source scan.)

## What the benchmark actually measures

Mapped to the way security practitioners think about hardening, the 200 rules exercise an LLM's
ability to **defensively configure a Linux system** across the major control families:

- **System & communications protection (NIST SC):** kernel/network `sysctl`, module reduction,
  crypto policy, SSH transport hardening.
- **Audit & accountability (NIST AU):** the single largest block (44 rules) — does the model know
  the *exact* audit-rule grammar a scanner verifies, not merely "enable auditing."
- **Identification & authentication / access control (NIST IA, AC):** PAM, password policy, sudo,
  smartcard/SSSD, session lock — ~45 rules combined.
- **Configuration management (NIST CM):** package/service minimization, boot parameters,
  permissions, mount options — attack-surface reduction.
- **System & information integrity (NIST SI):** AIDE, SELinux, `fapolicyd`, core-dump/ptrace limits.

Because grading is execution-based, it tests **whether the generated script genuinely secures the
host as the compliance scanner verifies it** — not whether the text *looks* like a hardening script.
This is the key distinction from string-similarity or LLM-judge evaluations.

## Shell-scripting competencies exercised

The reference remediations (and therefore the skills under test) require, in rough order of frequency:

- **Idempotent config-file editing** with regex / stream editing (`sed`, `grep`, in-place key=value
  upsert) — the dominant skill, present in the large majority of rules.
- **Conditional control flow** (presence checks, create-or-update, guards) — most non-trivial scripts.
- **Domain-specific config grammars:** `auditd` rule syntax (~45 rules), `sysctl` + persistence
  (~24), PAM/`authselect` (~24), `sshd_config` (~11), `modprobe` blacklists (~9), GRUB args (~6).
- **System-management commands:** `systemctl` enable/mask (~36 rules), package install/remove,
  permission/ownership operations (`chmod`/`chown`/`setfacl`, ~47 rules).
- **Persistence/durability:** 35 rules must survive a reboot (write to the right config file, not
  just set runtime state) — testing whether the model distinguishes ephemeral from persistent changes.

## What it does *not* cover (scope boundaries, for honesty in the writeup)

- **Single platform / single profile:** RHEL-8 family under the DISA STIG profile only (no Windows,
  pfSense, containers, or other distros — though the harness is OS-agnostic).
- **Defensive configuration only:** no offensive security, exploit reasoning, or vulnerability
  detection — this measures *system hardening via remediation scripting*.
- **Thin in a few areas:** firewall/network-filtering (0 rules here), device control (1), file
  permissions (1) — these reflect the failed-rule set of the source scan, not deliberate weighting.
- **Crypto/FIPS (3 rules)** are functionally hard to score on a single live host because they sever
  management access; reported separately.
