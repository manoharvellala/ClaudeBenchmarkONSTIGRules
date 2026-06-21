# Inference predictions — `claude-opus-4-8`

Generated remediation scripts for 5 rules.


---

## RHEL-08-010359 — `package_aide_installed`  (sev: medium)

**Prompt given to model:**

> On a RHEL 8 system, ensure that a host-based file-integrity checking tool is available so that unauthorized modifications to critical system files can later be detected. Specifically, the AIDE file-integrity tool must be present on the system. Write an idempotent bash remediation script that guarantees this tool is installed.

**Model-generated script (extracted):**
```bash
#!/usr/bin/env bash
set -euo pipefail

PACKAGE="aide"

if ! rpm -q "${PACKAGE}" >/dev/null 2>&1; then
    yum install -y "${PACKAGE}"
fi
```

**Reference / ground-truth fix (for comparison):**
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

## RHEL-08-010359 — `aide_build_database`  (sev: medium)

**Prompt given to model:**

> On a RHEL 8 system, the file-integrity monitoring tool (AIDE) must have an established baseline so it can later detect unauthorized modifications to system files; without an initialized known-good database, integrity checks cannot function. Write an idempotent bash remediation script that ensures the file-integrity tool is present and that a valid baseline integrity database has been generated and installed in its active location so that subsequent integrity checks succeed.

**Model-generated script (extracted):**
```bash
#!/usr/bin/env bash
#
# Idempotent remediation: ensure AIDE is installed and a baseline
# integrity database exists in its active location.
#
set -euo pipefail

# Must run as root
if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

AIDE_BIN="/usr/sbin/aide"
AIDE_CONF="/etc/aide.conf"

# 1. Ensure AIDE package is installed (idempotent)
if ! rpm -q aide >/dev/null 2>&1; then
    echo "AIDE not installed; installing..."
    if command -v dnf >/dev/null 2>&1; then
        dnf install -y aide
    elif command -v yum >/dev/null 2>&1; then
        yum install -y aide
    else
        echo "ERROR: No supported package manager (dnf/yum) found." >&2
        exit 1
    fi
else
    echo "AIDE package is already installed."
fi

# Verify the aide binary exists
if [[ ! -x "${AIDE_BIN}" ]]; then
    if command -v aide >/dev/null 2>&1; then
        AIDE_BIN="$(command -v aide)"
    else
        echo "ERROR: aide binary not found after installation." >&2
        exit 1
    fi
fi

# Verify configuration exists
if [[ ! -f "${AIDE_CONF}" ]]; then
    echo "ERROR: AIDE configuration file ${AIDE_CONF} not found." >&2
    exit 1
fi

# 2. Determine the active database paths from the AIDE configuration.
#    Fall back to RHEL 8 defaults if not specified.
get_conf_value() {
    local key="$1"
    local val
    val="$(grep -E "^[[:space:]]*${key}[[:space:]]*=" "${AIDE_CONF}" 2>/dev/null \
        | tail -n1 | sed -E "s/^[[:space:]]*${key}[[:space:]]*=[[:space:]]*//" \
        | tr -d '[:space:]')"
    # Strip leading file: scheme if present
    val="${val#file:}"
    echo "${val}"
}

DB_OUT="$(get_conf_value 'database_out')"
DB_IN="$(get_conf_value 'database')"

# Apply RHEL 8 defaults if values are empty
[[ -z "${DB_OUT}" ]] && DB_OUT="/var/lib/aide/aide.db.new.gz"
[[ -z "${DB_IN}"  ]] && DB_IN="/var/lib/aide/aide.db.gz"

DB_DIR="$(dirname "${DB_IN}")"
mkdir -p "${DB_DIR}"

# 3. Ensure a valid baseline database exists in the active location.
#    Idempotent: only (re)initialize if the active DB is missing or empty.
needs_init=0
if [[ ! -s "${DB_IN}" ]]; then
    needs_init=1
fi

if [[ "${needs_init}" -eq 1 ]]; then
    echo "No valid baseline database found at ${DB_IN}; initializing..."

    # Generate the new database
    "${AIDE_BIN}" --init

    # The init writes to database_out; move it into the active location.
    if [[ -s "${DB_OUT}" ]]; then
        mv -f "${DB_OUT}" "${DB_IN}"
    elif [[ -s "${DB_IN}" ]]; then
        : # already in place
    else
        echo "ERROR: AIDE initialization did not produce a database." >&2
        exit 1
    fi

    chmod 0600 "${DB_IN}"
    echo "Baseline AIDE database installed at ${DB_IN}."
else
    echo "Valid baseline AIDE database already present at ${DB_IN}; nothing to do."
fi

# 4. Final verification
if [[ -s "${DB_IN}" ]]; then
    echo "AIDE baseline integrity database is established."
    exit 0
else
    echo "ERROR: AIDE baseline database is missing after remediation." >&2
    exit 1
fi
```

**Reference / ground-truth fix (for comparison):**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if ! rpm -q --quiet "aide" ; then
    yum install -y "aide"
fi

/usr/sbin/aide --init
/bin/cp -p /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```


---

## RHEL-08-030650 — `aide_check_audit_tools`  (sev: medium)

**Prompt given to model:**

> On a RHEL 8 system, configure the AIDE file-integrity tool so that it monitors and verifies the integrity of the system's audit tools (the binaries used to view, manipulate, and report on audit records). Each of these audit tool executables must be registered with AIDE for cryptographic verification covering their permissions, ownership, and content hashes, so that any modification, replacement, or tampering of the tools can be detected. Write an idempotent bash remediation script that ensures the audit tools are tracked by the file-integrity tool, with the configuration persisting across reboots.

**Model-generated script (extracted):**
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure AIDE monitors the audit tools for integrity.
#
set -u

AIDE_CONF="/etc/aide.conf"

# Audit tools that must be registered with AIDE
AUDIT_TOOLS=(
    "/usr/sbin/auditctl"
    "/usr/sbin/auditd"
    "/usr/sbin/ausearch"
    "/usr/sbin/aureport"
    "/usr/sbin/autrace"
    "/usr/sbin/augenrules"
)

# The verification rule covering permissions, ownership and content hashes.
RULE="p+i+n+u+g+s+b+acl+xattrs+sha512"

# Make sure AIDE is installed.
if ! rpm -q aide >/dev/null 2>&1; then
    yum install -y aide || dnf install -y aide
fi

# Ensure the configuration file exists.
if [ ! -f "$AIDE_CONF" ]; then
    touch "$AIDE_CONF"
fi

# Ensure each audit tool has the correct AIDE rule line (idempotent).
for tool in "${AUDIT_TOOLS[@]}"; do
    # Escape any regex special characters in the path for matching.
    escaped_tool="$(printf '%s' "$tool" | sed 's/[][\.*^$/]/\\&/g')"

    # Look for an existing (non-commented) entry for this tool.
    if grep -Eq "^[[:space:]]*${escaped_tool}[[:space:]]+" "$AIDE_CONF"; then
        # Replace the existing entry to ensure the rule is correct.
        sed -i -E "s|^[[:space:]]*${escaped_tool}[[:space:]]+.*|${tool} ${RULE}|" "$AIDE_CONF"
    else
        # Append a new entry.
        printf '%s %s\n' "$tool" "$RULE" >> "$AIDE_CONF"
    fi
done

# Initialize / update the AIDE database so changes persist and take effect.
if [ ! -f /var/lib/aide/aide.db.gz ]; then
    /usr/sbin/aide --init
    if [ -f /var/lib/aide/aide.db.new.gz ]; then
        mv -f /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
    fi
else
    /usr/sbin/aide --update
    if [ -f /var/lib/aide/aide.db.new.gz ]; then
        mv -f /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
    fi
fi

exit 0
```

**Reference / ground-truth fix (for comparison):**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if ! rpm -q --quiet "aide" ; then
    yum install -y "aide"
fi










if grep -i '^.*/usr/sbin/auditctl.*$' /etc/aide.conf; then
sed -i "s#.*/usr/sbin/auditctl.*#/usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide.conf
else
echo "/usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide.conf
fi

if grep -i '^.*/usr/sbin/auditd.*$' /etc/aide.conf; then
sed -i "s#.*/usr/sbin/auditd.*#/usr/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide.conf
else
echo "/usr/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide.conf
fi

if grep -i '^.*/usr/sbin/ausearch.*$' /etc/aide.conf; then

```


---

## RHEL-08-010360 — `aide_scan_notification`  (sev: medium)

**Prompt given to model:**

> On a RHEL 8 system, the AIDE file-integrity tool is used to detect unauthorized changes to baseline system files, but undetected changes are only useful if responsible staff are alerted. Configure the system so that whenever the periodic AIDE integrity scan completes, the results of that scan are automatically delivered by email to the local root mailbox, ensuring administrators are notified of any detected modifications. Write an idempotent bash remediation script that ensures the scheduled AIDE check reports its scan details via email and that this configuration persists across reboots.

**Model-generated script (extracted):**
```bash
#!/usr/bin/env bash
#
# Remediation: ensure periodic AIDE integrity scan emails its results to root.
#
set -euo pipefail

CRON_FILE="/etc/crontab"
CRON_LINE='05 4 * * * root /usr/sbin/aide --check | /usr/bin/mail -s "$(hostname) - AIDE Integrity Check Report" root@localhost'

# Ensure required packages are present.
if ! rpm -q aide >/dev/null 2>&1; then
    yum install -y aide
fi

if ! rpm -q mailx >/dev/null 2>&1; then
    yum install -y mailx
fi

# Initialize the AIDE database if it does not yet exist.
if [ ! -f /var/lib/aide/aide.db.gz ]; then
    /usr/sbin/aide --init
    if [ -f /var/lib/aide/aide.db.new.gz ]; then
        mv -f /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
    fi
fi

# Ensure the crontab file exists.
if [ ! -f "$CRON_FILE" ]; then
    touch "$CRON_FILE"
    chmod 0644 "$CRON_FILE"
    chown root:root "$CRON_FILE"
fi

# Idempotently configure the scheduled AIDE check that emails its report.
# Remove any existing AIDE cron entries that pipe to mail (avoid duplicates/conflicts).
if grep -Eq '^[^#].*aide[[:space:]]+--check.*(mail|sendmail)' "$CRON_FILE"; then
    sed -i -E '/^[^#].*aide[[:space:]]+--check.*(mail|sendmail)/d' "$CRON_FILE"
fi

# Add the correct, complete cron line if not already present verbatim.
if ! grep -Fxq "$CRON_LINE" "$CRON_FILE"; then
    printf '%s\n' "$CRON_LINE" >> "$CRON_FILE"
fi

# Ensure correct permissions on the crontab file.
chmod 0644 "$CRON_FILE"
chown root:root "$CRON_FILE"

# Ensure cron service is enabled and running so the job persists across reboots.
if systemctl list-unit-files | grep -q '^crond\.service'; then
    systemctl enable crond >/dev/null 2>&1 || true
    systemctl restart crond >/dev/null 2>&1 || true
fi

echo "AIDE periodic check configured to email scan results to root."
```

**Reference / ground-truth fix (for comparison):**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if ! rpm -q --quiet "aide" ; then
    yum install -y "aide"
fi
var_aide_scan_notification_email='
```


---

## RHEL-08-040310 — `aide_verify_acls`  (sev: low)

**Prompt given to model:**

> On a RHEL 8 system, the AIDE file-integrity tool monitors critical files for unauthorized changes, but Access Control List (ACL) attributes can grant permissions beyond the standard file mode and must also be tracked. Configure AIDE so that every file-monitoring ruleset verifies ACLs, ensuring that any ACL change on monitored files is detected during integrity checks. Write an idempotent bash remediation script that ensures all AIDE rulesets include ACL verification.

**Model-generated script (extracted):**
```bash
#!/usr/bin/env bash
#
# Ensure all AIDE rulesets include the 'acl' verification option.
# Idempotent: running multiple times produces the same correct result.

set -euo pipefail

AIDE_CONF="/etc/aide.conf"

# Verify aide package / config presence
if ! rpm -q aide >/dev/null 2>&1; then
    echo "AIDE is not installed; installing..."
    if command -v yum >/dev/null 2>&1; then
        yum install -y aide
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y aide
    else
        echo "ERROR: No supported package manager found to install aide." >&2
        exit 1
    fi
fi

if [[ ! -f "$AIDE_CONF" ]]; then
    echo "ERROR: AIDE configuration file $AIDE_CONF not found." >&2
    exit 1
fi

# Backup the config once per run
backup="${AIDE_CONF}.bak.$(date +%Y%m%d%H%M%S)"
cp -p "$AIDE_CONF" "$backup"

# Process the configuration:
# A ruleset definition line looks like:   NAME = option1+option2+...
# We must ensure 'acl' appears among the '+' separated options.
# Lines that are pure macro/variable definitions starting with '@@'
# (e.g. @@define, @@ifndef) or comments (#) must be left untouched.
# Selection lines (paths) like "/etc  NORMAL" are not ruleset definitions
# and are left untouched.

tmpfile="$(mktemp)"

awk '
function add_acl(rhs,    n, parts, i, has_acl, out) {
    # rhs is the right-hand side (option expression), trimmed
    n = split(rhs, parts, /\+/)
    has_acl = 0
    for (i = 1; i <= n; i++) {
        gsub(/^[ \t]+|[ \t]+$/, "", parts[i])
        if (parts[i] == "acl") { has_acl = 1 }
    }
    if (has_acl) {
        return rhs
    } else {
        return rhs "+acl"
    }
}

{
    line = $0

    # Skip comments and blank lines unchanged
    if (line ~ /^[ \t]*#/ || line ~ /^[ \t]*$/) {
        print line
        next
    }

    # Skip macro/directive lines (@@define, @@ifndef, etc.) unchanged
    if (line ~ /^[ \t]*@@/) {
        print line
        next
    }

    # Ruleset definition: must be of form  NAME = EXPRESSION
    # NAME is a single token (no spaces) followed by = .
    # Use a match to ensure left side is a single identifier.
    if (match(line, /^[ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*=[ \t]*[^ \t]/)) {
        # Split into name and value on the first =
        eqpos = index(line, "=")
        lhs = substr(line, 1, eqpos - 1)
        rhs = substr(line, eqpos + 1)

        # Preserve any trailing inline comment
        comment = ""
        cpos = index(rhs, "#")
        if (cpos > 0) {
            comment = substr(rhs, cpos)
            rhs = substr(rhs, 1, cpos - 1)
        }

        # Trim rhs
        gsub(/^[ \t]+|[ \t]+$/, "", rhs)

        # Only treat as ruleset if the value looks like option expression
        # (contains letters; not a path starting with /).
        if (rhs ~ /^\// || rhs == "") {
            print line
            next
        }

        newrhs = add_acl(rhs)

        # Reconstruct, preserving lhs spacing
        if (comment != "") {
            printf "%s= %s %s\n", lhs, newrhs, comment
        } else {
            printf "%s= %s\n", lhs, newrhs
        }
        next
    }

    # Everything else unchanged
    print line
}
' "$AIDE_CONF" > "$tmpfile"

# Only replace if changed
if ! cmp -s "$tmpfile" "$AIDE_CONF"; then
    cat "$tmpfile" > "$AIDE_CONF"
    echo "AIDE configuration updated: ACL verification ensured in all rulesets."
else
    echo "No changes needed: all AIDE rulesets already include ACL verification."
    # Remove the now-redundant backup to avoid clutter
    rm -f "$backup"
fi

rm -f "$tmpfile"

exit 0
```

**Reference / ground-truth fix (for comparison):**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if ! rpm -q --quiet "aide" ; then
    yum install -y "aide"
fi

aide_conf="/etc/aide.conf"


groups=$(LC_ALL=C grep "^[A-Z][A-Za-z_]*" $aide_conf | grep -v "^ALLXTRAHASHES" | cut -f1 -d '=' | tr -d ' ' | sort -u)


for group in $groups
do
	config=$(grep "^$group\s*=" $aide_conf | cut -f2 -d '=' | tr -d ' ')

	if ! [[ $config = *acl* ]]
	then
		if [[ -z $config ]]
		then
			config="acl"
		else
			config=$config"+acl"
		fi
	fi
	sed -i "s/^$group\s*=.*/$group = $config/g" $aide_conf
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```
