# Fix-aware generated prompts (generator SEES the reference script)

Dry run over 5 diverse failed rules.


**5/5 prompts passed the leak check.**


---

## RHEL-08-040261 — `sysctl_net_ipv6_conf_all_accept_ra`  (sev: medium)

**Generated task prompt:**

> On a RHEL 8 system that has a Linux kernel installed, configure the networking stack so that all IPv6 interfaces refuse to accept router advertisement messages, since a forged advertisement could let an attacker reroute traffic and mount a man-in-the-middle attack. The disabling setting (value of 0) must take effect immediately at runtime and persist across reboots; any pre-existing conflicting configuration of this same parameter across the system's runtime-loaded kernel-parameter configuration sources must be neutralized so the compliant value is the one that ultimately applies, and the script must do nothing harmful (gracefully no-op) if no kernel is present. Write an idempotent bash remediation script that achieves this end state.

**Objective:** IPv6 router-advertisement acceptance on all interfaces is set to 0 at runtime and persistently, overriding conflicting prior settings.

**Leak check:** ✅ CLEAN

**Reference bash (the generator saw this):**
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
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv6.conf.all.accept_ra" matches to pre
```


---

## RHEL-08-010200 — `sshd_set_keepalive`  (sev: medium)

**Generated task prompt:**

> On a RHEL 8 system, configure the SSH server so that idle, unresponsive connections are reliably terminated after the keep-alive probe interval elapses. Specifically, the SSH server's setting that controls how many unanswered keep-alive probes are tolerated before disconnecting a client must be set to a value of 0, so that a session is dropped as soon as the keep-alive interval is reached without a client response. This limits exposure from abandoned or hijacked idle sessions. The change must take effect for the SSH service configuration, be applied idempotently, and persist across reboots. Write a bash remediation script to achieve this end state.

**Objective:** The SSH server's tolerated-unanswered-keepalive-probes setting equals 0, persistently.

**Leak check:** ✅ CLEAN

**Reference bash (the generator saw this):**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

var_sshd_set_keepalive='
```


---

## RHEL-08-010359 — `package_aide_installed`  (sev: medium)

**Generated task prompt:**

> On a RHEL 8 host, the system currently lacks a file-integrity checking tool, leaving it unable to detect unauthorized modifications to critical system files. Ensure the standard host-based file-integrity monitoring package (commonly known as AIDE) is present on the system. The script must be idempotent — taking no action if the tool is already installed — and should only attempt installation on a system running a standard kernel, gracefully doing nothing and reporting inapplicability otherwise. Write a bash remediation script that achieves this.

**Objective:** The AIDE file-integrity package is installed (on applicable kernel-based systems).

**Leak check:** ✅ CLEAN

**Reference bash (the generator saw this):**
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


---

## RHEL-08-040180 — `service_debug-shell_disabled`  (sev: medium)

**Generated task prompt:**

> On a RHEL 8 system, the systemd service that exposes an unauthenticated root shell on a virtual console (used only for diagnosing boot problems) must be rendered completely inert so that an attacker with physical access cannot leverage it to gain root after a reboot. Bring the system to a state where this service is stopped, cannot be enabled, and can never be activated — including blocking any companion socket-based activation if such a unit exists — and clear any lingering failed state so the unit ends up cleanly inactive. The remediation must apply only when a kernel package is present on the host, and otherwise do nothing and report that it was not applicable; it must also behave correctly when the system manager is offline. Write an idempotent bash remediation script that achieves this persistent end state.

**Objective:** The systemd debug-shell service and its socket activation are stopped, masked, and cleared of failed state, applied only when a kernel is installed.

**Leak check:** ✅ CLEAN

**Reference bash (the generator saw this):**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

SYSTEMCTL_EXEC='/usr/bin/systemctl'
if [[ $("$SYSTEMCTL_EXEC" is-system-running) != "offline" ]]; then
  "$SYSTEMCTL_EXEC" stop 'debug-shell.service'
fi
"$SYSTEMCTL_EXEC" disable 'debug-shell.service'
"$SYSTEMCTL_EXEC" mask 'debug-shell.service'
# Disable socket activation if we have a unit file for it
if "$SYSTEMCTL_EXEC" -q list-unit-files debug-shell.socket; then
    if [[ $("$SYSTEMCTL_EXEC" is-system-running) != "offline" ]]; then
      "$SYSTEMCTL_EXEC" stop 'debug-shell.socket'
    fi
    "$SYSTEMCTL_EXEC" mask 'debug-shell.socket'
fi
# The service may not be running because it has been started and f
```


---

## RHEL-08-010770 — `file_permission_user_init_files_root`  (sev: medium)

**Generated task prompt:**

> On a RHEL 8 system, the per-user shell initialization files (the hidden startup scripts found in each interactive user's home directory, including root's) may currently be writable or readable by group or other accounts. Because these files run automatically when a user logs in, an attacker able to modify them could hijack an account at next logon. Write an idempotent bash remediation script that locates every such user initialization file across all local interactive user home directories (including root's) and ensures none of them are more permissive than owner read/write/execute plus group read only — that is, tighten any file exceeding this to that maximum permission level while leaving already-compliant files untouched.

**Objective:** All user shell init files are restricted to mode 0740 or less permissive.

**Leak check:** ✅ CLEAN

**Reference bash (the generator saw this):**
```bash
var_user_initialization_files_regex='
```
