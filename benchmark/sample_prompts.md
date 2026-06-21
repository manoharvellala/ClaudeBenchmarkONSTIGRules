# Sample generated benchmark prompts

Dry run over 3 diverse failed STIG rules.


**3/3 prompts passed the leak check.**


---

## RHEL-08-040261 — `sysctl_net_ipv6_conf_all_accept_ra`  (severity: medium)

**Source title:** Configure Accepting Router Advertisements on All IPv6 Interfaces

**Full prompt fed to model under test:**

> On a RHEL 8 system, prevent the host from accepting IPv6 router advertisement messages on all interfaces, since a forged advertisement could let an attacker redirect traffic and conduct a man-in-the-middle attack. Write an idempotent bash remediation script that disables acceptance of IPv6 router advertisements across all interfaces, applying the setting at runtime and ensuring it persists across reboots.
> 
> Respond with ONLY a single self-contained bash script and nothing else. Enclose the entire script in one fenced code block that starts with a line containing exactly ```bash and ends with a line containing exactly ```. Do not write any explanation, comments, or text before or after the code block.

**Objective:** Host ignores IPv6 router advertisements on all interfaces, persistently.

**Leak check:** ✅ CLEAN

**Reference bash (hidden answer):**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of net.ipv6.conf.all.accept_ra from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv6.conf.all.accept_ra.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry
```


---

## RHEL-08-010200 — `sshd_set_keepalive`  (severity: medium)

**Source title:** Set SSH Client Alive Count Max

**Full prompt fed to model under test:**

> On a RHEL 8 system, configure the SSH server so that its keep-alive mechanism does not extend an idle session beyond the configured inactivity interval: the server must terminate an unresponsive client connection as soon as a single keep-alive probe goes unanswered, rather than tolerating multiple missed probes. Set the maximum number of unanswered keep-alive messages allowed before disconnection to 1. This bounds the window in which an unattended or dropped session remains open. Write an idempotent bash remediation script that enforces this setting for new SSH sessions and persists across reboots.
> 
> Respond with ONLY a single self-contained bash script and nothing else. Enclose the entire script in one fenced code block that starts with a line containing exactly ```bash and ends with a line containing exactly ```. Do not write any explanation, comments, or text before or after the code block.

**Objective:** SSH disconnects after a single unanswered keep-alive probe.

**Leak check:** ✅ CLEAN

**Reference bash (hidden answer):**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

var_sshd_set_keepalive='
```


---

## RHEL-08-010359 — `package_aide_installed`  (severity: medium)

**Source title:** Install AIDE

**Full prompt fed to model under test:**

> On a RHEL 8 system, ensure that a host-based file-integrity checking tool is available so that unauthorized modifications to critical system files can be detected. Specifically, the standard AIDE file-integrity tool must be present on the system. Write an idempotent bash remediation script that guarantees this capability is installed.
> 
> Respond with ONLY a single self-contained bash script and nothing else. Enclose the entire script in one fenced code block that starts with a line containing exactly ```bash and ends with a line containing exactly ```. Do not write any explanation, comments, or text before or after the code block.

**Objective:** The AIDE file-integrity package is installed.

**Leak check:** ✅ CLEAN

**Reference bash (hidden answer):**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if ! rpm -q --quiet "aide" ; then
    yum install -y "aide"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```
