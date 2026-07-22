# Inference predictions — `claude-opus-4-8`

215 rules.


---

## RHEL-08-010359 — `package_aide_installed`

**Prompt:** On an Ubuntu 24.04 system, ensure that a host-based file-integrity checking tool is available so that unauthorized modifications to critical system files can later be detected. Specifically, the AIDE file-integrity tool must be present on the system. Write an idempotent bash remediation script that guarantees this tool is installed.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root." >&2
    exit 1
fi

PACKAGE="aide"

if dpkg-query -W -f='${Status}' "$PACKAGE" 2>/dev/null | grep -q "install ok installed"; then
    echo "Package '$PACKAGE' is already installed."
else
    echo "Installing package '$PACKAGE'..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y "$PACKAGE"
fi

if dpkg-query -W -f='${Status}' "$PACKAGE" 2>/dev/null | grep -q "install ok installed"; then
    echo "Verification successful: '$PACKAGE' is present on the system."
else
    echo "Verification failed: '$PACKAGE' could not be installed." >&2
    exit 1
fi
```

**Reference fix:**
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

## RHEL-08-010359 — `aide_build_database`

**Prompt:** On an Ubuntu 24.04 system, the file-integrity monitoring tool (AIDE) must have an established baseline so it can later detect unauthorized modifications to system files; without an initialized known-good database, integrity checks cannot function. Write an idempotent bash remediation script that ensures the file-integrity tool is present and that a valid baseline integrity database has been generated and installed in its active location so that subsequent integrity checks succeed.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Idempotent remediation script to ensure AIDE (file-integrity monitoring)
# is installed and that a valid baseline database exists in its active location.
#
set -euo pipefail

# Must run as root
if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive

# 1. Ensure AIDE is installed
if ! dpkg -s aide >/dev/null 2>&1 || ! dpkg -s aide-common >/dev/null 2>&1; then
    echo "Installing AIDE..."
    apt-get update -y
    apt-get install -y aide aide-common
else
    echo "AIDE is already installed."
fi

# Locate the aide binary
AIDE_BIN="$(command -v aide || true)"
if [[ -z "${AIDE_BIN}" ]]; then
    if [[ -x /usr/sbin/aide ]]; then
        AIDE_BIN=/usr/sbin/aide
    else
        echo "AIDE binary not found after installation." >&2
        exit 1
    fi
fi

# Determine the active (installed) database location from config
DB_DIR="/var/lib/aide"
ACTIVE_DB="${DB_DIR}/aide.db"
NEW_DB="${DB_DIR}/aide.db.new"

CONF_FILE=""
for c in /etc/aide/aide.conf /etc/aide.conf; do
    if [[ -f "${c}" ]]; then
        CONF_FILE="${c}"
        break
    fi
done

if [[ -n "${CONF_FILE}" ]]; then
    cfg_active="$(awk -F= '/^[[:space:]]*database_out[[:space:]]*=/{next} /^[[:space:]]*database(_in)?[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); sub(/^file:/,"",$2); print $2}' "${CONF_FILE}" | tail -n1 || true)"
    cfg_new="$(awk -F= '/^[[:space:]]*database_out[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); sub(/^file:/,"",$2); print $2}' "${CONF_FILE}" | tail -n1 || true)"
    [[ -n "${cfg_active}" ]] && ACTIVE_DB="${cfg_active}"
    [[ -n "${cfg_new}" ]] && NEW_DB="${cfg_new}"
    DB_DIR="$(dirname "${ACTIVE_DB}")"
fi

# Ensure the database directory exists
mkdir -p "${DB_DIR}"

# 2. Ensure a valid baseline database exists in the active location
db_valid=false
if [[ -s "${ACTIVE_DB}" ]]; then
    # Verify the database is readable/non-trivial
    if [[ "${ACTIVE_DB}" == *.gz ]]; then
        if gzip -t "${ACTIVE_DB}" >/dev/null 2>&1; then
            db_valid=true
        fi
    else
        db_valid=true
    fi
fi

if [[ "${db_valid}" == true ]]; then
    echo "A valid AIDE baseline database already exists at ${ACTIVE_DB}."
    exit 0
fi

echo "Initializing AIDE baseline database (this may take a while)..."

# Prefer the Debian/Ubuntu wrapper if available
if command -v aideinit >/dev/null 2>&1; then
    aideinit -y -f
else
    "${AIDE_BIN}" --init
fi

# Install the newly generated database into the active location
if [[ -s "${NEW_DB}" ]]; then
    mv -f "${NEW_DB}" "${ACTIVE_DB}"
elif [[ ! -s "${ACTIVE_DB}" ]]; then
    echo "Failed to generate AIDE baseline database." >&2
    exit 1
fi

# Final validation
if [[ -s "${ACTIVE_DB}" ]]; then
    chmod 600 "${ACTIVE_DB}" || true
    echo "AIDE baseline database successfully installed at ${ACTIVE_DB}."
else
    echo "AIDE baseline database is missing or empty after initialization." >&2
    exit 1
fi
```

**Reference fix:**
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

## RHEL-08-030650 — `aide_check_audit_tools`

**Prompt:** On an Ubuntu 24.04 system, configure the AIDE file-integrity tool so that it monitors and verifies the integrity of the system's audit tools (the binaries used to view, manipulate, and report on audit records). Each of these audit tool executables must be registered with AIDE for cryptographic verification covering their permissions, ownership, and content hashes, so that any modification, replacement, or tampering of the tools can be detected. Write an idempotent bash remediation script that ensures the audit tools are tracked by the file-integrity tool, with the configuration persisting across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

AIDE_CONF="/etc/aide/aide.conf"

# Ensure AIDE is installed
if ! dpkg -s aide >/dev/null 2>&1 && ! command -v aide >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y aide aide-common
fi

# Determine the config file location
if [ ! -f "$AIDE_CONF" ]; then
    if [ -f /etc/aide.conf ]; then
        AIDE_CONF="/etc/aide.conf"
    else
        touch "$AIDE_CONF"
    fi
fi

# The audit tools that must be monitored
AUDIT_TOOLS="
/sbin/auditctl
/sbin/auditd
/sbin/ausearch
/sbin/aureport
/sbin/autrace
/sbin/augenrules
"

# AIDE rule covering permissions, ownership, and content hashes
RULE="p+i+n+u+g+s+b+acl+xattrs+sha512"

# Ensure each audit tool has a monitoring entry
for tool in $AUDIT_TOOLS; do
    # Escape special regex characters in the path for grep
    escaped=$(printf '%s' "$tool" | sed 's/[\/&]/\\&/g')
    # Check if the tool is already registered (regardless of rule)
    if grep -Eq "^[[:space:]]*${escaped}[[:space:]]+" "$AIDE_CONF"; then
        # Update the existing entry to use the correct rule
        sed -i -E "s|^[[:space:]]*${escaped}[[:space:]]+.*|${tool} ${RULE}|" "$AIDE_CONF"
    else
        # Append a new entry
        printf '%s %s\n' "$tool" "$RULE" >> "$AIDE_CONF"
    fi
done

echo "Audit tools have been registered with AIDE in $AIDE_CONF"

# Initialize/update the AIDE database so the changes persist
if command -v aideinit >/dev/null 2>&1; then
    aideinit -y -f || true
    if [ -f /var/lib/aide/aide.db.new ]; then
        mv -f /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    fi
elif command -v aide >/dev/null 2>&1; then
    aide --config="$AIDE_CONF" --init || true
    if [ -f /var/lib/aide/aide.db.new ]; then
        mv -f /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    fi
fi

echo "AIDE configuration complete."
```

**Reference fix:**
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

## RHEL-08-010360 — `aide_scan_notification`

**Prompt:** On an Ubuntu 24.04 system, the AIDE file-integrity tool is used to detect unauthorized changes to baseline system files, but undetected changes are only useful if responsible staff are alerted. Configure the system so that whenever the periodic AIDE integrity scan completes, the results of that scan are automatically delivered by email to the local root mailbox, ensuring administrators are notified of any detected modifications. Write an idempotent bash remediation script that ensures the scheduled AIDE check reports its scan details via email and that this configuration persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure periodic AIDE integrity scan results are emailed to root.
#
set -euo pipefail

CRON_FILE="/etc/cron.daily/aide"
CONF_FILE="/etc/default/aide"
MAILTO="root"
LOG_TAG="aide-remediation"

log() {
    logger -t "${LOG_TAG}" "$*" 2>/dev/null || true
    echo "$*"
}

# --- Ensure AIDE is installed ---------------------------------------------
if ! command -v aide >/dev/null 2>&1 && ! dpkg -s aide >/dev/null 2>&1; then
    log "Installing AIDE package(s)..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y aide aide-common
fi

# --- Ensure a mail delivery agent is available ----------------------------
if ! command -v mail >/dev/null 2>&1 && \
   ! command -v mailx >/dev/null 2>&1 && \
   ! command -v sendmail >/dev/null 2>&1; then
    log "Installing mailx for local mail delivery..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y bsd-mailx || apt-get install -y mailutils
fi

# --- Configure /etc/default/aide so the daily check mails root ------------
touch "${CONF_FILE}"

set_conf_kv() {
    local key="$1"
    local value="$2"
    local file="$3"
    if grep -qE "^[[:space:]]*#?[[:space:]]*${key}=" "${file}"; then
        sed -i -E "s|^[[:space:]]*#?[[:space:]]*${key}=.*|${key}=${value}|" "${file}"
    else
        printf '%s=%s\n' "${key}" "${value}" >> "${file}"
    fi
}

# Deliver the AIDE report by email to root and make sure it is sent even when clean.
set_conf_kv "MAILTO"       "${MAILTO}"       "${CONF_FILE}"
set_conf_kv "MAILSUBJ"     "\"AIDE integrity check report for \$(hostname)\"" "${CONF_FILE}"
set_conf_kv "QUIETREPORTS" "no"              "${CONF_FILE}"

log "Configured ${CONF_FILE} to email AIDE reports to ${MAILTO}."

# --- Ensure the daily cron job emails the scan output ---------------------
# The stock aide-common package ships /etc/cron.daily/aide. If it exists and
# honours /etc/default/aide, we rely on it. Otherwise create a fallback job.
if [ -f "${CRON_FILE}" ]; then
    # Make sure the shipped script sources the defaults (idempotent check).
    if ! grep -q "/etc/default/aide" "${CRON_FILE}"; then
        log "Existing ${CRON_FILE} does not reference ${CONF_FILE}; leaving package script but adding fallback."
    fi
    chmod 0755 "${CRON_FILE}"
else
    log "Creating fallback daily AIDE cron job at ${CRON_FILE}."
    cat > "${CRON_FILE}" <<'EOF'
#!/bin/bash
#
# Daily AIDE integrity check with emailed results.
#
set -u

MAILTO="root"
CONF="/etc/default/aide"
[ -r "${CONF}" ] && . "${CONF}"

: "${MAILTO:=root}"
HOST="$(hostname)"
SUBJECT="AIDE integrity check report for ${HOST}"
DB="/var/lib/aide/aide.db"
NEWDB="/var/lib/aide/aide.db.new"

if [ ! -f "${DB}" ]; then
    if [ -f "${NEWDB}" ]; then
        cp -a "${NEWDB}" "${DB}"
    fi
fi

OUTPUT="$(aide --check --config=/etc/aide/aide.conf 2>&1)"
RC=$?

{
    echo "AIDE integrity scan completed on ${HOST} at $(date)."
    echo "Exit status: ${RC}"
    echo
    echo "----- Scan details -----"
    echo "${OUTPUT}"
} | mail -s "${SUBJECT}" "${MAILTO}"

exit 0
EOF
    chmod 0755 "${CRON_FILE}"
fi

# --- Initialize AIDE database if missing (so checks are meaningful) -------
if [ ! -f /var/lib/aide/aide.db ] && [ ! -f /var/lib/aide/aide.db.new ]; then
    log "Initializing AIDE database (first run may take a while)..."
    if command -v aideinit >/dev/null 2>&1; then
        aideinit -y -f || true
    else
        aide --init --config=/etc/aide/aide.conf || true
        if [ -f /var/lib/aide/aide.db.new ]; then
            cp -a /var/lib/aide/aide.db.new /var/lib/aide/aide.db
        fi
    fi
fi

# --- Ensure cron is enabled and running so the job persists ---------------
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable --now cron 2>/dev/null || systemctl enable --now crond 2>/dev/null || true
fi

log "AIDE email reporting remediation complete."
exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if ! rpm -q --quiet "aide" ; then
    yum install -y "aide"
fi
var_aide_scan_notification_email='
```


---

## RHEL-08-040310 — `aide_verify_acls`

**Prompt:** On an Ubuntu 24.04 system, the AIDE file-integrity tool monitors critical files for unauthorized changes, but Access Control List (ACL) attributes can grant permissions beyond the standard file mode and must also be tracked. Configure AIDE so that every file-monitoring ruleset verifies ACLs, ensuring that any ACL change on monitored files is detected during integrity checks. Write an idempotent bash remediation script that ensures all AIDE rulesets include ACL verification.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Ensure all AIDE rulesets include ACL verification (acl attribute).
# Idempotent remediation for Ubuntu 24.04.

set -euo pipefail

# Candidate AIDE configuration locations on Ubuntu.
CONFIG_CANDIDATES=(
    "/etc/aide/aide.conf"
    "/etc/aide.conf"
)

CONFIG_DIRS=(
    "/etc/aide/aide.conf.d"
)

# Collect all config files that actually exist.
declare -a CONFIG_FILES=()

for f in "${CONFIG_CANDIDATES[@]}"; do
    [ -f "$f" ] && CONFIG_FILES+=("$f")
done

for d in "${CONFIG_DIRS[@]}"; do
    if [ -d "$d" ]; then
        while IFS= read -r -d '' file; do
            CONFIG_FILES+=("$file")
        done < <(find "$d" -type f -print0)
    fi
done

if [ "${#CONFIG_FILES[@]}" -eq 0 ]; then
    echo "No AIDE configuration files found. Is AIDE installed?" >&2
    exit 1
fi

# A ruleset definition line looks like:
#   NAME = expression
# where expression is a '+'-separated list of predefined groups/attributes.
# We must ensure 'acl' is present in every such ruleset expression.

process_file() {
    local file="$1"
    local changed=0
    local tmp
    tmp="$(mktemp)"

    while IFS= read -r line || [ -n "$line" ]; do
        # Match ruleset definitions: leading name, '=', then an expression
        # containing at least one '+' or a known attribute token.
        # Rule definition: NAME = value   (NAME starts with a letter/underscore)
        if [[ "$line" =~ ^([[:space:]]*)([A-Za-z_][A-Za-z0-9_]*)([[:space:]]*)=([[:space:]]*)([^#]*)(#.*)?$ ]]; then
            local indent="${BASH_REMATCH[1]}"
            local name="${BASH_REMATCH[2]}"
            local eq_pre="${BASH_REMATCH[3]}"
            local eq_post="${BASH_REMATCH[4]}"
            local value="${BASH_REMATCH[5]}"
            local comment="${BASH_REMATCH[6]}"

            # Skip AIDE directives that are not rulesets (e.g. database=, etc.)
            # Real rulesets are expressions of attributes joined by '+'.
            # Heuristic: value contains a '+' OR is a single known attribute macro.
            # Only treat as a ruleset if it looks like an attribute expression.
            local trimmed_value="${value%"${value##*[![:space:]]}"}"

            if [[ "$trimmed_value" == *"+"* ]] || \
               [[ "$trimmed_value" =~ ^[A-Za-z0-9_+]+$ && "$name" =~ ^[A-Z] ]]; then

                # Check if 'acl' already present as a standalone token.
                if [[ "$trimmed_value" =~ (^|[+[:space:]])acl($|[+[:space:]]) ]]; then
                    printf '%s\n' "$line" >>"$tmp"
                else
                    # Append +acl to the expression (preserving trailing whitespace/comment).
                    local newvalue="${trimmed_value}+acl"
                    printf '%s%s%s=%s%s%s\n' \
                        "$indent" "$name" "$eq_pre" "$eq_post" "$newvalue" \
                        "${comment:+ $comment}" >>"$tmp"
                    changed=1
                fi
                continue
            fi
        fi
        printf '%s\n' "$line" >>"$tmp"
    done <"$file"

    if [ "$changed" -eq 1 ]; then
        # Preserve permissions/ownership.
        cat "$tmp" >"$file"
        echo "Updated ACL verification in: $file"
    else
        echo "No changes needed in: $file"
    fi
    rm -f "$tmp"
}

for cfg in "${CONFIG_FILES[@]}"; do
    process_file "$cfg"
done

echo "AIDE ruleset ACL verification enforcement complete."
```

**Reference fix:**
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


---

## RHEL-08-040300 — `aide_verify_ext_attributes`

**Prompt:** On an Ubuntu 24.04 system, configure the AIDE file-integrity tool so that every defined check ruleset also verifies files' extended attributes, since extended attributes can carry security-relevant metadata that would otherwise go unmonitored for tampering. Write an idempotent bash remediation script that ensures extended-attribute checking is enabled across all rulesets in the AIDE configuration, in a way that persists.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Ensure every AIDE ruleset also verifies files' extended attributes (xattrs).
# Idempotent remediation for Ubuntu 24.04.
#
set -euo pipefail

# Candidate AIDE configuration locations on Ubuntu.
CONFIG_CANDIDATES=(
    "/etc/aide/aide.conf"
    "/etc/aide.conf"
)

# Directory holding modular Ubuntu AIDE rule fragments (if present).
CONFIG_DIRS=(
    "/etc/aide/aide.conf.d"
)

# The attribute token we want present in every ruleset.
XATTR_TOKEN="xattrs"

# Collect files that actually contain AIDE rule definitions.
declare -a FILES_TO_PROCESS=()

for f in "${CONFIG_CANDIDATES[@]}"; do
    if [ -f "$f" ]; then
        FILES_TO_PROCESS+=("$f")
    fi
done

for d in "${CONFIG_DIRS[@]}"; do
    if [ -d "$d" ]; then
        while IFS= read -r -d '' file; do
            FILES_TO_PROCESS+=("$file")
        done < <(find "$d" -type f -print0)
    fi
done

if [ "${#FILES_TO_PROCESS[@]}" -eq 0 ]; then
    echo "No AIDE configuration files found; nothing to remediate." >&2
    exit 0
fi

# Process a single file: add 'xattrs' to every ruleset definition line that
# lacks it. A ruleset definition line looks like:
#     NAME = p+i+n+u+g+s+...
# (macro/variable definitions). We only touch lines whose right-hand side is
# an AIDE group/rule expression (contains '+' separated tokens or known attrs),
# and we skip directives and comment lines.
remediate_file() {
    local file="$1"
    local tmp
    tmp="$(mktemp)"
    local changed=0

    while IFS= read -r line || [ -n "$line" ]; do
        # Preserve comments and blank lines verbatim.
        if [[ "$line" =~ ^[[:space:]]*# ]] || [[ -z "${line//[[:space:]]/}" ]]; then
            printf '%s\n' "$line" >>"$tmp"
            continue
        fi

        # Match a ruleset/macro definition:  NAME = value
        # Left side must be a valid AIDE variable name; right side is a rule spec.
        if [[ "$line" =~ ^([[:space:]]*)([A-Za-z_][A-Za-z0-9_]*)([[:space:]]*)=([[:space:]]*)(.+)$ ]]; then
            local lead="${BASH_REMATCH[1]}"
            local name="${BASH_REMATCH[2]}"
            local sp1="${BASH_REMATCH[3]}"
            local sp2="${BASH_REMATCH[4]}"
            local value="${BASH_REMATCH[5]}"

            # Strip trailing whitespace from value for analysis.
            local value_trimmed="${value%%[[:space:]]}"

            # Only treat as a ruleset if the value is a '+'-joined rule expression
            # (i.e., contains a '+' or is a bare group of rule attributes).
            # This avoids touching path directives like: @@define or database=...
            if [[ "$value_trimmed" == *"+"* ]] || \
               [[ "$value_trimmed" =~ ^[A-Za-z0-9_]+$ ]]; then

                # Check whether xattrs is already present as a token.
                if [[ "+$value_trimmed+" == *"+$XATTR_TOKEN+"* ]]; then
                    printf '%s\n' "$line" >>"$tmp"
                else
                    printf '%s%s%s=%s%s+%s\n' \
                        "$lead" "$name" "$sp1" "$sp2" "$value_trimmed" "$XATTR_TOKEN" >>"$tmp"
                    changed=1
                fi
            else
                printf '%s\n' "$line" >>"$tmp"
            fi
        else
            printf '%s\n' "$line" >>"$tmp"
        fi
    done <"$file"

    if [ "$changed" -eq 1 ]; then
        # Back up once, only when a change is actually being made.
        if [ ! -f "${file}.aide-xattr.bak" ]; then
            cp -a "$file" "${file}.aide-xattr.bak"
        fi
        cat "$tmp" >"$file"
        echo "Updated: $file"
    else
        echo "Already compliant: $file"
    fi

    rm -f "$tmp"
}

for f in "${FILES_TO_PROCESS[@]}"; do
    remediate_file "$f"
done

echo "AIDE xattrs remediation complete."
```

**Reference fix:**
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

	if ! [[ $config = *xattrs* ]]
	then
		if [[ -z $config ]]
		then
			config="xattrs"
		else
			config=$config"+xattrs"
		fi
	fi
	sed -i "s/^$group\s*=.*/$group = $config/g" $aide_conf
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```


---

## None — `enable_fips_mode`

**Prompt:** On an Ubuntu 24.04 system, the operating system must use only federally validated, FIPS 140-2 approved cryptographic algorithms across the kernel and system cryptographic services, because weak or untested encryption undermines the protection of sensitive data and the system is required to operate in an approved cryptographic mode. Write an idempotent bash remediation script that brings the system into the federally approved cryptographic operating mode and ensures this mode remains in effect across reboots.

**Model-generated script:**
```bash
```bash
#!/usr/bin/env bash
#
# Remediation: Enable FIPS 140-2 approved cryptographic operating mode
# on Ubuntu 24.04 and ensure it persists across reboots.
#
# This script is idempotent: it can be run repeatedly without changing
# the outcome once the system is in the desired state.

set -euo pipefail

# ---------------------------------------------------------------------------
# Must run as root
# ---------------------------------------------------------------------------
if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive

GRUB_DEFAULT_FILE="/etc/default/grub"
CHANGED=0

# ---------------------------------------------------------------------------
# 1. Ensure the FIPS-enabling tooling is present.
#    Ubuntu provides FIPS support via Ubuntu Pro / the 'ubuntu-advantage-tools'
#    package and the 'ubuntu-fips' meta package.
# ---------------------------------------------------------------------------
echo "Ensuring FIPS enablement tooling is installed..."

if ! command -v pro >/dev/null 2>&1 && ! command -v ua >/dev/null 2>&1; then
    apt-get update -y || true
    apt-get install -y ubuntu-advantage-tools || true
fi

PRO_CMD=""
if command -v pro >/dev/null 2>&1; then
    PRO_CMD="pro"
elif command -v ua >/dev/null 2>&1; then
    PRO_CMD="ua"
fi

# ---------------------------------------------------------------------------
# 2. Attempt to enable the FIPS-validated packages via Ubuntu Pro if attached.
#    If the machine is not attached this step is skipped gracefully; the kernel
#    parameter approach below still enforces FIPS mode.
# ---------------------------------------------------------------------------
if [[ -n "${PRO_CMD}" ]]; then
    if ${PRO_CMD} status 2>/dev/null | grep -qiE 'This machine is (attached|now attached)|Account'; then
        if ! ${PRO_CMD} status 2>/dev/null | grep -iE '^fips[[:space:]]' | grep -qi 'enabled'; then
            echo "Attempting to enable FIPS through Ubuntu Pro..."
            ${PRO_CMD} enable fips-updates --assume-yes 2>/dev/null \
                || ${PRO_CMD} enable fips --assume-yes 2>/dev/null \
                || echo "WARN: Could not enable FIPS via Ubuntu Pro; continuing."
        else
            echo "FIPS already enabled through Ubuntu Pro."
        fi
    else
        echo "WARN: System not attached to Ubuntu Pro. Skipping 'pro enable fips'."
        echo "      Attach with 'pro attach <token>' to install FIPS-validated modules."
    fi
fi

# ---------------------------------------------------------------------------
# 3. Ensure the kernel boots in FIPS mode by adding 'fips=1' (and the boot
#    partition reference when /boot is separate) to the kernel command line.
# ---------------------------------------------------------------------------
echo "Configuring kernel command line for FIPS mode..."

# Determine boot device UUID if /boot is a separate mount.
BOOT_ARG=""
if mountpoint -q /boot; then
    BOOT_UUID="$(findmnt -no UUID /boot 2>/dev/null || true)"
    if [[ -n "${BOOT_UUID}" ]]; then
        BOOT_ARG="boot=UUID=${BOOT_UUID}"
    fi
fi

if [[ ! -f "${GRUB_DEFAULT_FILE}" ]]; then
    touch "${GRUB_DEFAULT_FILE}"
fi

# Read current GRUB_CMDLINE_LINUX value (persistent kernel args).
current_line="$(grep -E '^GRUB_CMDLINE_LINUX=' "${GRUB_DEFAULT_FILE}" | tail -n1 || true)"
current_val=""
if [[ -n "${current_line}" ]]; then
    current_val="$(echo "${current_line}" | sed -E 's/^GRUB_CMDLINE_LINUX="?([^"]*)"?/\1/')"
fi

new_val="${current_val}"

add_arg() {
    local arg="$1"
    local key="${arg%%=*}"
    # Remove any existing occurrence of the key, then append the desired value.
    new_val="$(echo "${new_val}" | sed -E "s/(^| )${key}(=[^ ]*)?//g")"
    new_val="$(echo "${new_val} ${arg}" | tr -s ' ' | sed -E 's/^ +| +$//g')"
}

add_arg "fips=1"
if [[ -n "${BOOT_ARG}" ]]; then
    add_arg "${BOOT_ARG}"
fi

if [[ "${new_val}" != "${current_val}" ]]; then
    if grep -qE '^GRUB_CMDLINE_LINUX=' "${GRUB_DEFAULT_FILE}"; then
        sed -i -E "s|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=\"${new_val}\"|" "${GRUB_DEFAULT_FILE}"
    else
        echo "GRUB_CMDLINE_LINUX=\"${new_val}\"" >> "${GRUB_DEFAULT_FILE}"
    fi
    CHANGED=1
    echo "Updated GRUB_CMDLINE_LINUX to: ${new_val}"
else
    echo "Kernel command line already contains required FIPS parameters."
fi

# ---------------------------------------------------------------------------
# 4. Ensure system-wide OpenSSL / crypto policy operates in FIPS mode where
#    a crypto-policy mechanism exists.
# ---------------------------------------------------------------------------
if command -v update-crypto-policies >/dev/null 2>&1; then
    cur_policy="$(update-crypto-policies --show 2>/dev/null || echo '')"
    if [[ "${cur_policy}" != "FIPS" ]]; then
        echo "Setting system crypto policy to FIPS..."
        update-crypto-policies --set FIPS || echo "WARN: could not set crypto policy."
        CHANGED=1
    else
        echo "System crypto policy already set to FIPS."
    fi
fi

# ---------------------------------------------------------------------------
# 5. Regenerate the GRUB configuration so the kernel parameters take effect.
# ---------------------------------------------------------------------------
if [[ "${CHANGED}" -eq 1 ]]; then
    echo "Regenerating GRUB configuration..."
    if command -v update-grub >/dev/null 2>&1; then
        update-grub
    elif command -v grub-mkconfig >/dev/null 2>&1; then
        grub-mkconfig -o /boot/grub/grub.c
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if ( ! ( [ "${container:-}" == "bwrap-osbuild" ] ) && rpm --quiet -q kernel ); then

if [[ "$OSCAP_BOOTC_BUILD" == "YES" ]]; then
	cat > /usr/lib/bootc/kargs.d/01-fips.toml << EOF
kargs = ["fips=1"]
EOF
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```


---

## RHEL-08-010297 — `configure_crypto_policy`

**Prompt:** On an Ubuntu 24.04 system, ensure the system-wide cryptographic policy is set to the default-strength profile so that all applications and services consistently use vetted, non-weak ciphers and algorithms, eliminating the risk posed by ad-hoc or downgraded cryptography. The configuration back-ends must reflect the selected policy as expected. Write an idempotent bash remediation script that establishes this system-wide cryptographic policy and ensures it persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Set system-wide cryptographic policy to the DEFAULT profile
# on Ubuntu 24.04, ensuring persistence and that back-ends are updated.
#
set -euo pipefail

readonly DESIRED_POLICY="DEFAULT"
readonly CONFIG_FILE="/etc/crypto-policies/config"
readonly STATE_FILE="/etc/crypto-policies/state/current"

log() {
    printf '%s %s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$*"
}

# Must run as root to modify system-wide crypto policy.
if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

# Ensure the crypto-policies tooling is present.
if ! command -v update-crypto-policies >/dev/null 2>&1; then
    log "crypto-policies package not found; installing..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y crypto-policies crypto-policies-scripts || \
        apt-get install -y crypto-policies
fi

if ! command -v update-crypto-policies >/dev/null 2>&1; then
    echo "ERROR: update-crypto-policies is unavailable after installation attempt." >&2
    exit 1
fi

# Determine the currently active policy (normalize to base profile name).
current_policy=""
if current_raw="$(update-crypto-policies --show 2>/dev/null)"; then
    current_policy="${current_raw%%:*}"
fi

# Apply the DEFAULT policy only if it is not already the active one (idempotent),
# but always run --set to guarantee back-ends are regenerated when not confirmed.
if [[ "${current_policy}" == "${DESIRED_POLICY}" ]]; then
    log "System-wide crypto policy already set to ${DESIRED_POLICY}. Ensuring back-ends are consistent."
else
    log "Current crypto policy is '${current_policy:-unknown}'. Setting to ${DESIRED_POLICY}."
fi

# Setting the policy writes the config, regenerates back-end configs, and persists across reboots.
update-crypto-policies --set "${DESIRED_POLICY}"

# Explicitly ensure the persisted configuration file reflects the desired policy.
mkdir -p "$(dirname "${CONFIG_FILE}")"
if [[ ! -f "${CONFIG_FILE}" ]] || [[ "$(tr -d '[:space:]' < "${CONFIG_FILE}")" != "${DESIRED_POLICY}" ]]; then
    printf '%s\n' "${DESIRED_POLICY}" > "${CONFIG_FILE}"
    log "Wrote '${DESIRED_POLICY}' to ${CONFIG_FILE}."
fi

# Verify the result.
verify_raw="$(update-crypto-policies --show 2>/dev/null || true)"
verify_policy="${verify_raw%%:*}"

if [[ "${verify_policy}" != "${DESIRED_POLICY}" ]]; then
    echo "ERROR: Failed to set crypto policy. Active policy is '${verify_policy:-none}'." >&2
    exit 1
fi

# Confirm the persisted state file matches (best-effort check).
if [[ -f "${STATE_FILE}" ]]; then
    state_policy="$(tr -d '[:space:]' < "${STATE_FILE}")"
    state_policy="${state_policy%%:*}"
    if [[ "${state_policy}" != "${DESIRED_POLICY}" ]]; then
        log "WARNING: state file (${STATE_FILE}) shows '${state_policy}'; reapplying."
        update-crypto-policies --set "${DESIRED_POLICY}"
    fi
fi

log "System-wide cryptographic policy is set to ${DESIRED_POLICY} and will persist across reboots."
exit 0
```

**Reference fix:**
```bash
var_system_crypto_policy='
```


---

## None — `configure_gnutls_tls_crypto_policy`

**Prompt:** On an Ubuntu 24.04 system, the GnuTLS library must defer to the centralized system-wide cryptographic policy rather than overriding it with weak protocol versions. Ensure the GnuTLS back-end is configured so that it honors the system crypto policy and does not permit legacy/insecure protocol versions (SSL 3.0, TLS 1.0, TLS 1.1, DTLS 0.9, DTLS 1.0), keeping cryptographic behavior consistent and centrally managed. Write an idempotent bash remediation script that brings the GnuTLS configuration into this compliant, persistent state.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure GnuTLS defers to the system-wide crypto policy and
# disables legacy/insecure protocol versions (SSLv3, TLS1.0, TLS1.1,
# DTLS0.9, DTLS1.0).
#
set -euo pipefail

CONFIG_FILE="/etc/crypto-policies/back-ends/gnutls.config"
CONFIG_DIR="$(dirname "${CONFIG_FILE}")"

# Protocol versions that must be disabled.
DISABLE_LIST=("VERS-SSL3.0" "VERS-TLS1.0" "VERS-TLS1.1" "VERS-DTLS0.9" "VERS-DTLS1.0")

# Ensure the back-end directory exists.
if [ ! -d "${CONFIG_DIR}" ]; then
    mkdir -p "${CONFIG_DIR}"
fi

# The [overrides] block that enforces disabling insecure protocol versions
# while still honoring the centralized system crypto policy.
build_overrides() {
    printf '[overrides]\n'
    for proto in "${DISABLE_LIST[@]}"; do
        printf 'disabled-version = %s\n' "${proto}"
    done
}

# Determine whether the file is already compliant.
is_compliant() {
    [ -f "${CONFIG_FILE}" ] || return 1

    # Must have the [overrides] section.
    grep -qiE '^\s*\[overrides\]\s*$' "${CONFIG_FILE}" || return 1

    # Every required protocol version must be disabled.
    for proto in "${DISABLE_LIST[@]}"; do
        if ! grep -qiE "^\s*disabled-version\s*=\s*${proto}\s*$" "${CONFIG_FILE}"; then
            return 1
        fi
    done

    # Must NOT enable any of the insecure protocols.
    for proto in "${DISABLE_LIST[@]}"; do
        if grep -qiE "^\s*enabled-version\s*=\s*${proto}\s*$" "${CONFIG_FILE}"; then
            return 1
        fi
    done

    return 0
}

if is_compliant; then
    echo "GnuTLS crypto policy back-end is already compliant. No changes made."
    exit 0
fi

# Back up any existing config once.
if [ -f "${CONFIG_FILE}" ] && [ ! -f "${CONFIG_FILE}.bak" ]; then
    cp -a "${CONFIG_FILE}" "${CONFIG_FILE}.bak"
fi

TMP_FILE="$(mktemp)"
trap 'rm -f "${TMP_FILE}"' EXIT

if [ -f "${CONFIG_FILE}" ]; then
    # Strip any pre-existing [overrides] block and any enabled/disabled-version
    # override lines, preserving all other content.
    awk '
        BEGIN { in_overrides = 0 }
        /^[[:space:]]*\[overrides\][[:space:]]*$/ { in_overrides = 1; next }
        /^[[:space:]]*\[.*\][[:space:]]*$/ {
            if (in_overrides) { in_overrides = 0 }
            print
            next
        }
        {
            if (in_overrides) {
                # Drop version override lines inside overrides block.
                if ($0 ~ /^[[:space:]]*(enabled|disabled)-version[[:space:]]*=/) { next }
                # Drop blank lines within overrides block.
                if ($0 ~ /^[[:space:]]*$/) { next }
            }
            print
        }
    ' "${CONFIG_FILE}" > "${TMP_FILE}"

    # Remove trailing blank lines.
    sed -i -e :a -e '/^\n*$/{$d;N;ba}' "${TMP_FILE}"

    # Ensure a trailing newline before appending overrides, if file has content.
    if [ -s "${TMP_FILE}" ]; then
        printf '\n' >> "${TMP_FILE}"
    fi
else
    : > "${TMP_FILE}"
fi

# Append the compliant overrides block.
build_overrides >> "${TMP_FILE}"

# Install the new configuration.
install -m 0644 -o root -g root "${TMP_FILE}" "${CONFIG_FILE}"

# Refresh/apply the system-wide crypto policy so the GnuTLS back-end picks up
# the change, if the tooling is available.
if command -v update-crypto-policies >/dev/null 2>&1; then
    update-crypto-policies >/dev/null 2>&1 || true
fi

echo "GnuTLS crypto policy back-end updated to disable insecure protocol versions."
exit 0
```

**Reference fix:**
```bash
CONF_FILE=/etc/crypto-policies/back-ends/gnutls.config
correct_value='+VERS-ALL:-VERS-DTLS0.9:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1:-VERS-DTLS1.0'

grep -q ${correct_value} ${CONF_FILE}

if [[ $? -ne 0 ]]; then
    # We need to get the existing value, using PCRE to maintain same regex
    existing_value=$(grep -Po '(\+VERS-ALL(?::-VERS-[A-Z]+\d\.\d)+)' ${CONF_FILE})

    if [[ ! -z ${existing_value} ]]; then
        # replace existing_value with correct_value
        sed -i "s/${existing_value}/${correct_value}/g" ${CONF_FILE}
    else
        # ***NOTE*** #
        # This probably means this file is not here or it's been modified
        # unintentionally.
        # ********** #
        # 
```


---

## None — `harden_sshd_ciphers_opensshserver_conf_crypto_policy`

**Prompt:** On an Ubuntu 24.04 system, ensure the SSH server obtains its cipher selection from the centralized system-wide cryptographic policy rather than from a local override, so that only FIPS 140-2 validated ciphers (ordered strongest-to-weakest) are used and the configuration remains consistent and non-fragmented. The relevant crypto-policy back-end for the SSH server must contain the correct cipher specification, uncommented and aligned with the system policy. Write an idempotent bash remediation script that enforces this end state and persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Ensure the SSH server obtains its cipher selection from the system-wide
# crypto-policy back-end rather than a local override, and that only
# FIPS 140-2 validated ciphers (ordered strongest-to-weakest) are used.
#
set -euo pipefail

# -------------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------------
CRYPTO_BACKEND="/etc/crypto-policies/back-ends/opensshserver.config"
SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_CONFIG_DIR="/etc/ssh/sshd_config.d"

# FIPS 140-2 validated ciphers, ordered strongest to weakest.
FIPS_CIPHERS="aes256-gcm@openssh.com,aes256-ctr,aes256-cbc,aes128-gcm@openssh.com,aes128-ctr,aes128-cbc"

# The directive line the back-end must contain.
CIPHER_LINE="Ciphers ${FIPS_CIPHERS}"

# -------------------------------------------------------------------------
# Pre-flight
# -------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

# -------------------------------------------------------------------------
# 1. Remove any local override of Ciphers in the main sshd_config so the
#    system-wide crypto policy is authoritative and configuration is not
#    fragmented.
# -------------------------------------------------------------------------
if [[ -f "${SSHD_CONFIG}" ]]; then
    if grep -Eiq '^[[:space:]]*Ciphers[[:space:]]' "${SSHD_CONFIG}"; then
        cp -a -- "${SSHD_CONFIG}" "${SSHD_CONFIG}.bak.$(date +%Y%m%d%H%M%S)"
        sed -ri '/^[[:space:]]*[Cc]iphers[[:space:]]/d' "${SSHD_CONFIG}"
        echo "Removed local 'Ciphers' override from ${SSHD_CONFIG}."
    fi
fi

# -------------------------------------------------------------------------
# 2. Remove any local override of Ciphers in drop-in config files.
# -------------------------------------------------------------------------
if [[ -d "${SSHD_CONFIG_DIR}" ]]; then
    while IFS= read -r -d '' f; do
        if grep -Eiq '^[[:space:]]*Ciphers[[:space:]]' "${f}"; then
            cp -a -- "${f}" "${f}.bak.$(date +%Y%m%d%H%M%S)"
            sed -ri '/^[[:space:]]*[Cc]iphers[[:space:]]/d' "${f}"
            echo "Removed local 'Ciphers' override from ${f}."
        fi
    done < <(find "${SSHD_CONFIG_DIR}" -maxdepth 1 -type f -name '*.conf' -print0)
fi

# -------------------------------------------------------------------------
# 3. Ensure the crypto-policy back-end exists and contains the correct,
#    uncommented cipher specification.
# -------------------------------------------------------------------------
mkdir -p -- "$(dirname "${CRYPTO_BACKEND}")"

# If it is a symlink managed by update-crypto-policies, we still want to
# write the concrete cipher spec into the resolved file so the SSH server
# picks it up. Resolve the target.
TARGET="${CRYPTO_BACKEND}"
if [[ -L "${CRYPTO_BACKEND}" ]]; then
    TARGET="$(readlink -f -- "${CRYPTO_BACKEND}")"
    mkdir -p -- "$(dirname "${TARGET}")"
fi

touch -- "${TARGET}"

NEEDS_UPDATE=0
if ! grep -Eq "^Ciphers[[:space:]]+${FIPS_CIPHERS//\//\\/}\$" "${TARGET}"; then
    NEEDS_UPDATE=1
fi

if [[ "${NEEDS_UPDATE}" -eq 1 ]]; then
    cp -a -- "${TARGET}" "${TARGET}.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true

    # Remove any existing (commented or uncommented) Ciphers lines.
    sed -ri '/^[[:space:]]*#?[[:space:]]*[Cc]iphers([[:space:]]|=)/d' "${TARGET}"

    # Append the correct, uncommented directive.
    printf '%s\n' "${CIPHER_LINE}" >> "${TARGET}"

    echo "Updated crypto-policy back-end ${TARGET} with FIPS cipher spec."
else
    echo "Crypto-policy back-end ${TARGET} already contains the correct cipher spec."
fi

# -------------------------------------------------------------------------
# 4. Ensure sshd includes the crypto-policy back-end (persistence).
#    On Ubuntu the opensshserver.config is pulled in via the packaged
#    default; we make certain it is referenced.
# -------------------------------------------------------------------------
if [[ -f "${SSHD_CONFIG}" ]]; then
    if ! grep -Eq "^[[:space:]]*Include[[:space:]]+${CRYPTO_BACKEND//\//\\/}" "${SSHD_CONFIG}"; then
        if ! grep -Eq "Include[[:space:]]+/etc/crypto-policies/back-ends/opensshserver.config" "${SSHD_CONFIG}"; then
            printf '\n# Pull cipher selection from the system-wide crypto policy\nInclude %s\n' \
                "${CRYPTO_BACKEND}" >> "${SSHD_CONFIG}"
            echo "Added Include for ${CRYPTO_BACKEND} to ${SSHD_CONFIG}."
        fi
    fi
fi

# -------------------------------------------------------------------------
# 5. Validate configuration and reload the SSH server.
# -------------------------------------------------------------------------
if command -v sshd >/dev/null 2>&1; then
    if sshd -t; then
        echo "sshd configuration validated successfully."
        if command -v systemctl >/dev/null 2>&1; then
            if systemctl is-active --quiet ssh 2>/dev/null; then
                systemctl reload ssh || systemctl restart ssh
                echo "Reloaded ssh service."
            elif systemctl is-active --quiet sshd 2>/dev/null; then
                systemctl reload sshd || systemctl restart sshd
                echo "Reloaded sshd service."
            fi
        fi
    else
        echo "ERROR: sshd configuration test failed. Not reloading." >&2
        exit 1
    fi
fi

echo "Remediation complete: SSH cipher selection is sourced from the system-wide crypto policy."
```

**Reference fix:**
```bash
sshd_approved_ciphers='
```


---

## None — `harden_sshd_macs_opensshserver_conf_crypto_policy`

**Prompt:** On an Ubuntu 24.04 system, the OpenSSH server's message authentication code (MAC) algorithms must be governed by the system-wide cryptographic policy rather than by a local override, ensuring only FIPS 140-2 validated MACs are used and that crypto configuration remains centralized and consistent. A local override that diverges from the system crypto policy weakens assurance and fragments configuration. Write an idempotent bash remediation script that ensures the SSH server's MAC algorithm selection conforms to the system-wide cryptographic policy back-end, persisting across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure OpenSSH server MACs are governed by the system-wide
# crypto policy back-end rather than a local override in sshd_config.
#
# On Ubuntu 24.04 the sshd crypto settings are sourced from the system crypto
# policy back-end file: /etc/crypto-policies/back-ends/opensshserver.config
# A local "MACs" override in sshd_config / sshd_config.d fragments and weakens
# the centralized FIPS-validated configuration and must be removed.
#
set -o errexit
set -o nounset
set -o pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_CONFIG_DIR="/etc/ssh/sshd_config.d"
BACKEND="/etc/crypto-policies/back-ends/opensshserver.config"

if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

changed=0

# Function to strip any active (uncommented) MACs directive from a given file.
strip_macs_override() {
    local file="$1"

    [[ -f "${file}" ]] || return 0

    # Detect an active MACs directive (case-insensitive, allowing leading space)
    if grep -Eiq '^[[:space:]]*MACs[[:space:]]+' "${file}"; then
        local ts
        ts="$(date +%Y%m%d%H%M%S)"
        cp -a --no-preserve=timestamps "${file}" "${file}.bak.${ts}"

        # Comment out any active MACs line so the crypto policy back-end governs.
        sed -ri 's/^([[:space:]]*)(MACs[[:space:]]+.*)$/\1# Removed by crypto-policy remediation: \2/I' "${file}"

        echo "Removed local MACs override from ${file} (backup: ${file}.bak.${ts})"
        changed=1
    fi
}

# 1. Remove local MACs override from the main sshd_config.
strip_macs_override "${SSHD_CONFIG}"

# 2. Remove local MACs override from every drop-in fragment.
if [[ -d "${SSHD_CONFIG_DIR}" ]]; then
    shopt -s nullglob
    for frag in "${SSHD_CONFIG_DIR}"/*.conf; do
        strip_macs_override "${frag}"
    done
    shopt -u nullglob
fi

# 3. Ensure the crypto policy back-end for opensshserver exists / is applied.
if [[ ! -f "${BACKEND}" ]]; then
    echo "Crypto policy back-end ${BACKEND} not found; regenerating via update-crypto-policies." >&2
    if command -v update-crypto-policies >/dev/null 2>&1; then
        update-crypto-policies --no-reload >/dev/null 2>&1 || update-crypto-policies >/dev/null 2>&1 || true
        changed=1
    else
        echo "WARNING: update-crypto-policies not available; cannot regenerate back-end." >&2
    fi
fi

# 4. Validate resulting sshd configuration.
if command -v sshd >/dev/null 2>&1; then
    if ! sshd -t; then
        echo "ERROR: sshd configuration test failed after remediation." >&2
        exit 1
    fi
fi

# 5. Reload/restart sshd only if we made changes and the service is active.
if [[ "${changed}" -eq 1 ]]; then
    if command -v systemctl >/dev/null 2>&1; then
        svc=""
        if systemctl list-unit-files 2>/dev/null | grep -q '^ssh\.service'; then
            svc="ssh"
        elif systemctl list-unit-files 2>/dev/null | grep -q '^sshd\.service'; then
            svc="sshd"
        fi

        if [[ -n "${svc}" ]]; then
            if systemctl is-active --quiet "${svc}"; then
                systemctl reload "${svc}" 2>/dev/null || systemctl restart "${svc}"
                echo "Reloaded ${svc} to apply crypto-policy-governed MACs."
            else
                echo "${svc} is not active; changes will apply on next start."
            fi
        fi
    fi
    echo "Remediation complete: SSH server MACs now governed by system crypto policy."
else
    echo "System already compliant: no local MACs override present."
fi

exit 0
```

**Reference fix:**
```bash
sshd_approved_macs='
```


---

## RHEL-08-020032 — `dconf_gnome_disable_user_list`

**Prompt:** On an Ubuntu 24.04 system running the GNOME graphical desktop environment, the login screen currently displays a list of all known user accounts, allowing anyone with physical access to enumerate valid usernames without authenticating. Configure the graphical login screen so that it no longer displays the list of existing users, and ensure this setting is enforced as a system-wide policy that cannot be overridden by individual users. Write an idempotent bash remediation script that applies this change so it persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

# Ensure running as root
if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

PROFILE_DIR="/etc/dconf/profile"
PROFILE_FILE="${PROFILE_DIR}/gdm"
DB_DIR="/etc/dconf/db/gdm.d"
SETTINGS_FILE="${DB_DIR}/00-login-screen"
LOCKS_DIR="${DB_DIR}/locks"
LOCKS_FILE="${LOCKS_DIR}/00-login-screen"

# Create required directories
mkdir -p "${PROFILE_DIR}"
mkdir -p "${DB_DIR}"
mkdir -p "${LOCKS_DIR}"

# Ensure the gdm dconf profile exists with correct content
desired_profile=$'user-db:user\nsystem-db:gdm\nfile-db:/usr/share/gdm/greeter-dconf-defaults'
if [[ ! -f "${PROFILE_FILE}" ]] || [[ "$(cat "${PROFILE_FILE}")" != "${desired_profile}" ]]; then
    printf '%s\n' "${desired_profile}" > "${PROFILE_FILE}"
fi

# Write the setting to disable the user list
desired_settings=$'[org/gnome/login-screen]\ndisable-user-list=true'
if [[ ! -f "${SETTINGS_FILE}" ]] || [[ "$(cat "${SETTINGS_FILE}")" != "${desired_settings}" ]]; then
    printf '%s\n' "${desired_settings}" > "${SETTINGS_FILE}"
fi

# Lock the setting so it cannot be overridden by individual users
desired_lock='/org/gnome/login-screen/disable-user-list'
if [[ ! -f "${LOCKS_FILE}" ]] || ! grep -qxF "${desired_lock}" "${LOCKS_FILE}" 2>/dev/null; then
    printf '%s\n' "${desired_lock}" > "${LOCKS_FILE}"
fi

# Set sane permissions
chmod 0644 "${PROFILE_FILE}" "${SETTINGS_FILE}" "${LOCKS_FILE}"

# Update the dconf system databases
dconf update

echo "GDM login screen user list has been disabled and locked system-wide."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

# Check for setting in any of the DConf db directories
# If files contain ibus or distro, ignore them.
# The assignment assumes that individual filenames don't contain :
readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/login-screen\\]" "/etc/dconf/db/" \
                                | grep -v 'distro\|ibus\|gdm.d' | cut -d":" -f1)
DCONFFILE="/etc/dconf/db/gdm.d/00-security-settings"
DBDIR="/etc/dconf/db/gdm.d"

mkdir -p "${DBDIR}"

# Comment out the configurations in databases different from the target one
if [ "${#SETTINGSFILES[@]}" -ne 0 ]
th
```


---

## RHEL-08-020050 — `dconf_gnome_lock_screen_on_smartcard_removal`

**Prompt:** On an Ubuntu 24.04 system using the default GNOME graphical desktop environment, configure the desktop so that removing a user's smartcard immediately locks the screen, preventing unauthorized access to an unattended session when a user steps away with their card. The setting must be enforced as a mandatory system-wide policy that ordinary users cannot override, and it must persist across reboots. Write an idempotent bash remediation script that establishes this behavior.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PROFILE_DIR="/etc/dconf/profile"
DB_DIR="/etc/dconf/db/local.d"
LOCK_DIR="/etc/dconf/db/local.d/locks"
PROFILE_FILE="${PROFILE_DIR}/user"
SETTINGS_FILE="${DB_DIR}/00-smartcard-removal"
LOCK_FILE="${LOCK_DIR}/00-smartcard-removal"

# Ensure required directories exist
mkdir -p "${PROFILE_DIR}"
mkdir -p "${DB_DIR}"
mkdir -p "${LOCK_DIR}"

# Ensure the system dconf profile references the local database
if [ ! -f "${PROFILE_FILE}" ]; then
    cat > "${PROFILE_FILE}" <<'EOF'
user-db:user
system-db:local
EOF
else
    grep -qxF 'user-db:user' "${PROFILE_FILE}" || sed -i '1i user-db:user' "${PROFILE_FILE}"
    grep -qxF 'system-db:local' "${PROFILE_FILE}" || echo 'system-db:local' >> "${PROFILE_FILE}"
fi

# Write the mandatory system-wide setting
cat > "${SETTINGS_FILE}" <<'EOF'
[org/gnome/settings-daemon/peripherals/smartcard]
removal-action='lock-screen'
EOF

# Lock the setting so ordinary users cannot override it
cat > "${LOCK_FILE}" <<'EOF'
/org/gnome/settings-daemon/peripherals/smartcard/removal-action
EOF

# Update the dconf system databases
dconf update

echo "Smartcard removal lock-screen policy applied successfully."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

# Check for setting in any of the DConf db directories
# If files contain ibus or distro, ignore them.
# The assignment assumes that individual filenames don't contain :
readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/settings-daemon/peripherals/smartcard\\]" "/etc/dconf/db/" \
                                | grep -v 'distro\|ibus\|local.d' | cut -d":" -f1)
DCONFFILE="/etc/dconf/db/local.d/00-security-settings"
DBDIR="/etc/dconf/db/local.d"

mkdir -p "${DBDIR}"

# Comment out the configurations in databases different from the target one
if [ "$
```


---

## RHEL-08-010820 — `gnome_gdm_disable_automatic_login`

**Prompt:** On an Ubuntu 24.04 system, ensure that the graphical login manager (GNOME Display Manager) never logs any user into a desktop session automatically without requiring credentials, so that every user must authenticate before gaining access. Write an idempotent bash remediation script that disables automatic graphical login, with the setting persisting across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Disable automatic graphical login in GDM (GNOME Display Manager).
# Idempotent remediation script for Ubuntu 24.04.
#

set -euo pipefail

# Must run as root to modify system configuration.
if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

# GDM configuration file locations (Ubuntu uses gdm3).
GDM_CONF=""
for candidate in /etc/gdm3/custom.conf /etc/gdm/custom.conf; do
    if [[ -f "$candidate" ]]; then
        GDM_CONF="$candidate"
        break
    fi
done

# If neither exists, default to the Ubuntu path and create it.
if [[ -z "$GDM_CONF" ]]; then
    GDM_CONF="/etc/gdm3/custom.conf"
    mkdir -p "$(dirname "$GDM_CONF")"
    touch "$GDM_CONF"
fi

echo "Using GDM configuration file: $GDM_CONF"

# Ensure a [daemon] section exists.
if ! grep -qE '^\s*\[daemon\]' "$GDM_CONF"; then
    printf '\n[daemon]\n' >> "$GDM_CONF"
fi

# Function to set a key to a desired value within the [daemon] section.
# Handles commented, active-but-wrong, and missing keys idempotently.
set_daemon_key() {
    local key="$1"
    local value="$2"
    local file="$3"

    # Remove any existing (commented or active) occurrences of the key
    # so we can insert a single canonical entry.
    sed -i -E "/^\s*#?\s*${key}\s*=.*/d" "$file"

    # Insert the desired setting immediately after the [daemon] header.
    awk -v key="$key" -v value="$value" '
        BEGIN { inserted = 0 }
        {
            print $0
            if ($0 ~ /^[[:space:]]*\[daemon\][[:space:]]*$/ && inserted == 0) {
                print key "=" value
                inserted = 1
            }
        }
        END {
            if (inserted == 0) {
                print "[daemon]"
                print key "=" value
            }
        }
    ' "$file" > "${file}.tmp"

    mv "${file}.tmp" "$file"
}

# Explicitly disable automatic login and timed login.
set_daemon_key "AutomaticLoginEnable" "false" "$GDM_CONF"
set_daemon_key "TimedLoginEnable" "false" "$GDM_CONF"

# Set safe permissions on the configuration file.
chmod 0644 "$GDM_CONF"
chown root:root "$GDM_CONF"

echo "Automatic graphical login has been disabled in $GDM_CONF"
echo "Current [daemon] settings:"
grep -E '^\s*(AutomaticLoginEnable|TimedLoginEnable)\s*=' "$GDM_CONF" || true

exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

if rpm --quiet -q gdm
then
	if ! grep -q "^AutomaticLoginEnable=" /etc/gdm/custom.conf
	then
		sed -i "/^\[daemon\]/a \
		AutomaticLoginEnable=False" /etc/gdm/custom.conf
	else
		sed -i "s/^AutomaticLoginEnable=.*/AutomaticLoginEnable=False/g" /etc/gdm/custom.conf
	fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```


---

## RHEL-08-020060 — `dconf_gnome_screensaver_idle_delay`

**Prompt:** On an Ubuntu 24.04 system running the GNOME desktop environment, configure the graphical desktop so that the screensaver automatically activates after 15 minutes of user inactivity, and ensure this setting is enforced system-wide and locked so that individual users cannot override it. This prevents an unattended workstation from remaining accessible when a user steps away. Write an idempotent bash remediation script that establishes and locks this inactivity timeout, taking effect persistently.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Configure and lock the GNOME screensaver idle activation timeout to 15 minutes
# system-wide via dconf. Idempotent remediation script.
#
set -euo pipefail

# 15 minutes expressed in seconds for GNOME idle-delay
IDLE_DELAY=900

# dconf system-wide profile, keyfile directory, and lock directory
DCONF_PROFILE="/etc/dconf/profile/user"
DCONF_DB_DIR="/etc/dconf/db/local.d"
DCONF_LOCK_DIR="/etc/dconf/db/local.d/locks"
DCONF_KEYFILE="${DCONF_DB_DIR}/00-screensaver"
DCONF_LOCKFILE="${DCONF_LOCK_DIR}/00-screensaver"

# Ensure dconf CLI is available
if ! command -v dconf >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -y
        apt-get install -y dconf-cli
    fi
fi

# Ensure the required directories exist
mkdir -p "$(dirname "${DCONF_PROFILE}")"
mkdir -p "${DCONF_DB_DIR}"
mkdir -p "${DCONF_LOCK_DIR}"

# Ensure the system dconf user profile references the local database
if [ ! -f "${DCONF_PROFILE}" ] || ! grep -qx "user-db:user" "${DCONF_PROFILE}" 2>/dev/null || ! grep -qx "system-db:local" "${DCONF_PROFILE}" 2>/dev/null; then
    cat > "${DCONF_PROFILE}" <<'EOF'
user-db:user
system-db:local
EOF
fi

# Write the keyfile that sets the idle delay and enables the screensaver
cat > "${DCONF_KEYFILE}" <<EOF
[org/gnome/desktop/session]
idle-delay=uint32 ${IDLE_DELAY}

[org/gnome/desktop/screensaver]
idle-activation-enabled=true
lock-enabled=true
EOF

# Lock the keys so individual users cannot override them
cat > "${DCONF_LOCKFILE}" <<'EOF'
/org/gnome/desktop/session/idle-delay
/org/gnome/desktop/screensaver/idle-activation-enabled
/org/gnome/desktop/screensaver/lock-enabled
EOF

# Compile the dconf database to apply settings persistently
dconf update

echo "GNOME screensaver inactivity timeout set to ${IDLE_DELAY} seconds and locked system-wide."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

inactivity_timeout_value='
```


---

## RHEL-08-020031 — `dconf_gnome_screensaver_lock_delay`

**Prompt:** On an Ubuntu 24.04 system with the GNOME desktop environment, configure the screensaver so that once it activates, the screen locks immediately (with a lock delay of zero seconds) rather than allowing a grace period during which the unattended session could be accessed. This ensures the session is protected the moment the screensaver engages. Write an idempotent bash remediation script that enforces this screen-lock delay setting system-wide so it persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

# Enforce a screensaver lock-delay of 0 seconds system-wide via dconf.

DCONF_DB_DIR="/etc/dconf/db/local.d"
DCONF_LOCK_DIR="/etc/dconf/db/local.d/locks"
DCONF_PROFILE="/etc/dconf/profile/user"
SETTINGS_FILE="${DCONF_DB_DIR}/00-screensaver"
LOCK_FILE="${DCONF_LOCK_DIR}/00-screensaver"

# Ensure required directories exist.
mkdir -p "${DCONF_DB_DIR}"
mkdir -p "${DCONF_LOCK_DIR}"
mkdir -p "$(dirname "${DCONF_PROFILE}")"

# Ensure the dconf user profile references the local database.
if [ ! -f "${DCONF_PROFILE}" ] || ! grep -qx "user-db:user" "${DCONF_PROFILE}" || ! grep -qx "system-db:local" "${DCONF_PROFILE}"; then
    cat > "${DCONF_PROFILE}" <<'EOF'
user-db:user
system-db:local
EOF
fi

# Write the screensaver lock-delay setting (idempotently).
cat > "${SETTINGS_FILE}" <<'EOF'
[org/gnome/desktop/screensaver]
lock-delay=uint32 0
EOF

# Lock the setting so users cannot override it.
cat > "${LOCK_FILE}" <<'EOF'
/org/gnome/desktop/screensaver/lock-delay
EOF

# Update the dconf system databases.
dconf update

echo "Screensaver lock-delay has been set to 0 seconds system-wide."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

var_screensaver_lock_delay='
```


---

## RHEL-08-020030 — `dconf_gnome_screensaver_lock_enabled`

**Prompt:** On an Ubuntu 24.04 system running the GNOME desktop environment, ensure that whenever the screensaver activates, the screen is automatically locked, so that a user stepping away from an unattended workstation does not leave an open session accessible to others. The lock behavior must be enforced as a mandatory system-wide setting that users cannot override, and it must persist across reboots. Write an idempotent bash remediation script that achieves this end state.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PROFILE_DIR="/etc/dconf/profile"
DB_DIR="/etc/dconf/db"
KEYFILE_DIR="/etc/dconf/db/local.d"
LOCKS_DIR="/etc/dconf/db/local.d/locks"

PROFILE_FILE="${PROFILE_DIR}/user"
KEYFILE="${KEYFILE_DIR}/00-screensaver"
LOCKFILE="${LOCKS_DIR}/00-screensaver"

mkdir -p "$PROFILE_DIR" "$KEYFILE_DIR" "$LOCKS_DIR"

# Ensure the dconf user profile references a system database named "local"
if [ ! -f "$PROFILE_FILE" ]; then
    cat > "$PROFILE_FILE" <<'EOF'
user-db:user
system-db:local
EOF
else
    grep -qxF 'user-db:user' "$PROFILE_FILE" || sed -i '1i user-db:user' "$PROFILE_FILE"
    grep -qxF 'system-db:local' "$PROFILE_FILE" || echo 'system-db:local' >> "$PROFILE_FILE"
fi

# Write the mandatory screensaver lock settings
cat > "$KEYFILE" <<'EOF'
[org/gnome/desktop/screensaver]
lock-enabled=true
lock-delay=uint32 0
EOF

# Lock the keys so users cannot override them
cat > "$LOCKFILE" <<'EOF'
/org/gnome/desktop/screensaver/lock-enabled
/org/gnome/desktop/screensaver/lock-delay
EOF

# Rebuild the dconf system databases
dconf update

echo "Screensaver lock policy applied and enforced system-wide."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

# Check for setting in any of the DConf db directories
# If files contain ibus or distro, ignore them.
# The assignment assumes that individual filenames don't contain :
readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/desktop/screensaver\\]" "/etc/dconf/db/" \
                                | grep -v 'distro\|ibus\|local.d' | cut -d":" -f1)
DCONFFILE="/etc/dconf/db/local.d/00-security-settings"
DBDIR="/etc/dconf/db/local.d"

mkdir -p "${DBDIR}"

# Comment out the configurations in databases different from the target one
if [ "${#SETTINGSFILES[@]
```


---

## RHEL-08-020082 — `dconf_gnome_screensaver_lock_locked`

**Prompt:** On an Ubuntu 24.04 system running the GNOME desktop environment, the automatic screen lock that engages after an idle period must be enforced by the administrator and not overridable by individual users, ensuring that an unattended workstation reliably locks and cannot be silently weakened. Write an idempotent bash remediation script that locks down the GNOME screensaver idle-lock setting so users cannot change it, and ensure the policy is compiled into effect and persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

PROFILE_DIR="/etc/dconf/profile"
PROFILE_FILE="${PROFILE_DIR}/user"
DB_DIR="/etc/dconf/db/local.d"
LOCKS_DIR="${DB_DIR}/locks"
SETTINGS_FILE="${DB_DIR}/00-screensaver"
LOCKS_FILE="${LOCKS_DIR}/00-screensaver"

mkdir -p "$PROFILE_DIR" "$DB_DIR" "$LOCKS_DIR"

# Ensure the dconf user profile references the system database
if [[ ! -f "$PROFILE_FILE" ]]; then
    cat > "$PROFILE_FILE" <<'EOF'
user-db:user
system-db:local
EOF
else
    grep -qxF 'user-db:user' "$PROFILE_FILE" || sed -i '1i user-db:user' "$PROFILE_FILE"
    grep -qxF 'system-db:local' "$PROFILE_FILE" || echo 'system-db:local' >> "$PROFILE_FILE"
fi

# Define the enforced screensaver idle-lock setting
cat > "$SETTINGS_FILE" <<'EOF'
[org/gnome/desktop/screensaver]
lock-enabled=true

[org/gnome/desktop/session]
idle-delay=uint32 900

[org/gnome/desktop/screensaver]
lock-delay=uint32 0
EOF

# Lock the setting so users cannot override it
cat > "$LOCKS_FILE" <<'EOF'
/org/gnome/desktop/screensaver/lock-enabled
/org/gnome/desktop/session/idle-delay
/org/gnome/desktop/screensaver/lock-delay
EOF

# Compile the dconf database so the policy takes effect and persists
dconf update

echo "GNOME idle-lock policy enforced and compiled successfully."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm; then

# Check for setting in any of the DConf db directories
LOCKFILES=$(grep -r "^/org/gnome/desktop/screensaver/lock-enabled$" "/etc/dconf/db/" \
            | grep -v 'distro\|ibus\|local.d' | grep ":" | cut -d":" -f1)
LOCKSFOLDER="/etc/dconf/db/local.d/locks"

mkdir -p "${LOCKSFOLDER}"

# Comment out the configurations in databases different from the target one
if [[ ! -z "${LOCKFILES}" ]]
then
    sed -i -E "s|^/org/gnome/desktop/screensaver/lock-enabled$|#&|" "${LOCKFILES[@]}"
fi

if ! grep -qr "^/org/gnome/desktop/screensaver/lock-enabled$" /etc/dconf/db/local.d/
then
    echo "/org/gnome/desktop/screensaver/
```


---

## RHEL-08-020080 — `dconf_gnome_screensaver_user_locks`

**Prompt:** On an Ubuntu 24.04 system with the GNOME graphical desktop, the automatic screen-lock behavior must be enforced by the administrator and not be overridable by individual users, ensuring that idle sessions reliably lock and cannot be weakened by an end user. Write an idempotent bash remediation script that locks down the GNOME screensaver lock-delay setting so that ordinary users are prevented from changing it, and ensure the policy is loaded into the active desktop configuration.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PROFILE_DIR="/etc/dconf/profile"
PROFILE_FILE="${PROFILE_DIR}/user"
DB_DIR="/etc/dconf/db/local.d"
LOCKS_DIR="${DB_DIR}/locks"
SETTINGS_FILE="${DB_DIR}/00-screensaver"
LOCK_FILE="${LOCKS_DIR}/00-screensaver"

mkdir -p "${PROFILE_DIR}"
mkdir -p "${DB_DIR}"
mkdir -p "${LOCKS_DIR}"

# Ensure the dconf user profile references the local system database
if [ ! -f "${PROFILE_FILE}" ] || ! grep -q '^system-db:local$' "${PROFILE_FILE}"; then
    {
        echo "user-db:user"
        echo "system-db:local"
    } > "${PROFILE_FILE}"
fi

# Define the enforced lock-delay setting
cat > "${SETTINGS_FILE}" <<'EOF'
[org/gnome/desktop/screensaver]
lock-delay=uint32 5
EOF

# Lock the setting so ordinary users cannot override it
cat > "${LOCK_FILE}" <<'EOF'
/org/gnome/desktop/screensaver/lock-delay
EOF

# Load the policy into the active dconf database
dconf update

echo "GNOME screensaver lock-delay policy enforced and loaded."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

# Check for setting in any of the DConf db directories
LOCKFILES=$(grep -r "^/org/gnome/desktop/screensaver/lock-delay$" "/etc/dconf/db/" \
            | grep -v 'distro\|ibus\|local.d' | grep ":" | cut -d":" -f1)
LOCKSFOLDER="/etc/dconf/db/local.d/locks"

mkdir -p "${LOCKSFOLDER}"

# Comment out the configurations in databases different from the target one
if [[ ! -z "${LOCKFILES}" ]]
then
    sed -i -E "s|^/org/gnome/desktop/screensaver/lock-delay$|#&|" "${LOCKFILES[@]}"
fi

if ! grep -qr "^/org/gnome/desktop/screensaver/lock-delay$" /etc/dconf/db/l
```


---

## RHEL-08-020081 — `dconf_gnome_session_idle_user_locks`

**Prompt:** On an Ubuntu 24.04 system with the GNOME graphical desktop, ensure that ordinary users cannot override the system-defined session idle (automatic screen lock) timing. The goal is to lock down the desktop's session idle-delay setting at the system level so that it is enforced and users cannot change it through their own preferences, preventing users from disabling the protection that locks an unattended workstation. Write an idempotent bash remediation script that establishes this enforced, non-overridable configuration so it persists across reboots and dconf database updates.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PROFILE_DIR="/etc/dconf/profile"
PROFILE_FILE="${PROFILE_DIR}/user"
DB_DIR="/etc/dconf/db/local.d"
LOCK_DIR="${DB_DIR}/locks"
SETTINGS_FILE="${DB_DIR}/00-screensaver"
LOCK_FILE="${LOCK_DIR}/00-screensaver"

IDLE_DELAY="900"

mkdir -p "${PROFILE_DIR}"
mkdir -p "${DB_DIR}"
mkdir -p "${LOCK_DIR}"

# Ensure the user profile references the system (local) database
if [ ! -f "${PROFILE_FILE}" ]; then
    cat > "${PROFILE_FILE}" <<'EOF'
user-db:user
system-db:local
EOF
else
    grep -qxF "user-db:user" "${PROFILE_FILE}" || sed -i '1i user-db:user' "${PROFILE_FILE}"
    grep -qxF "system-db:local" "${PROFILE_FILE}" || echo "system-db:local" >> "${PROFILE_FILE}"
fi

# Define the system-level session idle-delay setting
cat > "${SETTINGS_FILE}" <<EOF
[org/gnome/desktop/session]
idle-delay=uint32 ${IDLE_DELAY}
EOF

# Lock the setting so users cannot override it
cat > "${LOCK_FILE}" <<'EOF'
/org/gnome/desktop/session/idle-delay
EOF

# Update the dconf system databases
dconf update

echo "Session idle-delay locked at ${IDLE_DELAY} seconds and enforced system-wide."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

# Check for setting in any of the DConf db directories
LOCKFILES=$(grep -r "^/org/gnome/desktop/session/idle-delay$" "/etc/dconf/db/" \
            | grep -v 'distro\|ibus\|local.d' | grep ":" | cut -d":" -f1)
LOCKSFOLDER="/etc/dconf/db/local.d/locks"

mkdir -p "${LOCKSFOLDER}"

# Comment out the configurations in databases different from the target one
if [[ ! -z "${LOCKFILES}" ]]
then
    sed -i -E "s|^/org/gnome/desktop/session/idle-delay$|#&|" "${LOCKFILES[@]}"
fi

if ! grep -qr "^/org/gnome/desktop/session/idle-delay$" /etc/dconf/db/local.d/
then
```


---

## RHEL-08-040171 — `dconf_gnome_disable_ctrlaltdel_reboot`

**Prompt:** On an Ubuntu 24.04 system running the GNOME graphical desktop, prevent a locally logged-in user from triggering a reboot via the Ctrl-Alt-Del key sequence from within the graphical interface, eliminating the risk of an accidental loss of availability from an unintended reboot. The configuration must be enforced through the desktop's system-wide settings database and locked so that individual users cannot override it. Write an idempotent bash remediation script that establishes and applies this setting persistently.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PROFILE_DIR="/etc/dconf/profile"
PROFILE_FILE="${PROFILE_DIR}/user"
DB_DIR="/etc/dconf/db/local.d"
LOCK_DIR="${DB_DIR}/locks"
SETTINGS_FILE="${DB_DIR}/00-ctrl-alt-del"
LOCK_FILE="${LOCK_DIR}/00-ctrl-alt-del"

mkdir -p "${PROFILE_DIR}" "${DB_DIR}" "${LOCK_DIR}"

# Ensure the dconf user profile references the system database
if [ ! -f "${PROFILE_FILE}" ] || ! grep -qx "user-db:user" "${PROFILE_FILE}" || ! grep -qx "system-db:local" "${PROFILE_FILE}"; then
    cat > "${PROFILE_FILE}" <<'EOF'
user-db:user
system-db:local
EOF
fi

# Configure the system-wide setting to disable Ctrl-Alt-Del reboot
cat > "${SETTINGS_FILE}" <<'EOF'
[org/gnome/settings-daemon/plugins/media-keys]
logout=['']
EOF

# Lock the setting so users cannot override it
cat > "${LOCK_FILE}" <<'EOF'
/org/gnome/settings-daemon/plugins/media-keys/logout
EOF

# Apply the changes to the dconf database
dconf update
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

# Check for setting in any of the DConf db directories
# If files contain ibus or distro, ignore them.
# The assignment assumes that individual filenames don't contain :
readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/settings-daemon/plugins/media-keys\\]" "/etc/dconf/db/" \
                                | grep -v 'distro\|ibus\|local.d' | cut -d":" -f1)
DCONFFILE="/etc/dconf/db/local.d/00-security-settings"
DBDIR="/etc/dconf/db/local.d"

mkdir -p "${DBDIR}"

# Comment out the configurations in databases different from the target one
if [ "${#S
```


---

## RHEL-08-010384 — `sudo_require_reauthentication`

**Prompt:** On an Ubuntu 24.04 system, the privilege-escalation tool (sudo) caches a user's authentication for a period of time, allowing repeated privileged actions without re-entering credentials. To minimize the window in which an unattended or hijacked session could perform unauthorized privileged operations, configure sudo so that its credential-caching interval requires re-authentication on an appropriately short, non-indefinite schedule (the cached authentication must expire and must never be set to never expire). Write an idempotent bash remediation script that enforces a defined, finite re-authentication timeout for sudo and ensures the setting persists.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

TIMEOUT_VALUE=15
DROPIN_DIR="/etc/sudoers.d"
DROPIN_FILE="${DROPIN_DIR}/99-timestamp_timeout"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

mkdir -p "$DROPIN_DIR"
chmod 0755 "$DROPIN_DIR"

# Remove any existing timestamp_timeout settings from main sudoers to avoid conflicts
if [[ -f /etc/sudoers ]]; then
    if grep -Eq '^[[:space:]]*Defaults[[:space:]].*timestamp_timeout' /etc/sudoers; then
        tmp_main="$(mktemp)"
        grep -Ev '^[[:space:]]*Defaults[[:space:]].*timestamp_timeout' /etc/sudoers > "$tmp_main"
        if visudo -cf "$tmp_main" >/dev/null 2>&1; then
            install -m 0440 -o root -g root "$tmp_main" /etc/sudoers
        fi
        rm -f "$tmp_main"
    fi
fi

# Remove timestamp_timeout lines from other drop-in files (except our own)
if [[ -d "$DROPIN_DIR" ]]; then
    for f in "$DROPIN_DIR"/*; do
        [[ -e "$f" ]] || continue
        [[ "$f" == "$DROPIN_FILE" ]] && continue
        if grep -Eq '^[[:space:]]*Defaults[[:space:]].*timestamp_timeout' "$f"; then
            tmp_f="$(mktemp)"
            grep -Ev '^[[:space:]]*Defaults[[:space:]].*timestamp_timeout' "$f" > "$tmp_f"
            if visudo -cf "$tmp_f" >/dev/null 2>&1; then
                install -m 0440 -o root -g root "$tmp_f" "$f"
            fi
            rm -f "$tmp_f"
        fi
    done
fi

DESIRED_LINE="Defaults timestamp_timeout=${TIMEOUT_VALUE}"

# Write the drop-in file idempotently
NEED_WRITE=1
if [[ -f "$DROPIN_FILE" ]]; then
    if grep -Exq "Defaults[[:space:]]+timestamp_timeout=${TIMEOUT_VALUE}" "$DROPIN_FILE"; then
        NEED_WRITE=0
    fi
fi

if [[ "$NEED_WRITE" -eq 1 ]]; then
    tmp_dropin="$(mktemp)"
    printf '%s\n' "$DESIRED_LINE" > "$tmp_dropin"
    if visudo -cf "$tmp_dropin" >/dev/null 2>&1; then
        install -m 0440 -o root -g root "$tmp_dropin" "$DROPIN_FILE"
    else
        echo "Syntax validation failed; aborting." >&2
        rm -f "$tmp_dropin"
        exit 1
    fi
    rm -f "$tmp_dropin"
fi

chmod 0440 "$DROPIN_FILE"
chown root:root "$DROPIN_FILE"

# Final validation
if ! visudo -c >/dev/null 2>&1; then
    echo "sudoers validation failed after changes." >&2
    exit 1
fi

echo "sudo timestamp_timeout enforced to ${TIMEOUT_VALUE} minutes in ${DROPIN_FILE}."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q sudo; then

var_sudo_timestamp_timeout='
```


---

## RHEL-08-010383 — `sudoers_validate_passwd`

**Prompt:** On an Ubuntu 24.04 system, ensure that when a user escalates privileges through the sudo mechanism, the system always requires that user to authenticate with their OWN password rather than the target or root account's password. The privilege-escalation policy must be configured so that the behaviors which would prompt for the root account's password, the target user's password, or the run-as user's password are explicitly disabled, ensuring only the invoking user's credentials are validated. This prevents weaknesses where shared or root credentials could be used and preserves proper accountability. Write an idempotent bash remediation script that enforces this end state persistently.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Enforce that sudo requires the invoking user's own password.
# Disables rootpw, targetpw, and runaspw behaviors via sudoers.
#
set -euo pipefail

SUDOERS_DIR="/etc/sudoers.d"
DROPIN="${SUDOERS_DIR}/99-require-user-password"
MAIN_SUDOERS="/etc/sudoers"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# Ensure the sudoers.d directory exists with correct permissions
if [[ ! -d "$SUDOERS_DIR" ]]; then
    install -d -m 0750 "$SUDOERS_DIR"
fi

# Locate visudo for validation
VISUDO="$(command -v visudo || echo /usr/sbin/visudo)"

# Create the drop-in content
TMPFILE="$(mktemp)"
trap 'rm -f "$TMPFILE"' EXIT

cat > "$TMPFILE" <<'EOF'
# Managed file: enforce that sudo authenticates the invoking user
# with their OWN password. Do not edit manually.
Defaults !rootpw
Defaults !targetpw
Defaults !runaspw
EOF

# Validate the candidate file before installing
if ! "$VISUDO" -cf "$TMPFILE" >/dev/null 2>&1; then
    echo "Validation of new sudoers drop-in failed; aborting." >&2
    exit 1
fi

# Install idempotently: only replace if content differs
if [[ -f "$DROPIN" ]] && cmp -s "$TMPFILE" "$DROPIN"; then
    :
else
    install -m 0440 -o root -g root "$TMPFILE" "$DROPIN"
fi

# Ensure correct ownership/permissions even if file already existed
chown root:root "$DROPIN"
chmod 0440 "$DROPIN"

# Remove any conflicting enabling directives in the main sudoers file.
# Comment out lines that enable rootpw, targetpw, or runaspw (without '!').
if grep -Eq '^[[:space:]]*Defaults[[:space:]].*\b(rootpw|targetpw|runaspw)\b' "$MAIN_SUDOERS" 2>/dev/null; then
    BACKUP="${MAIN_SUDOERS}.bak.$(date +%Y%m%d%H%M%S)"
    cp -p "$MAIN_SUDOERS" "$BACKUP"
    TMPMAIN="$(mktemp)"
    # Comment out any line that turns these ON (i.e., not already negated with !)
    sed -E 's/^([[:space:]]*Defaults[[:space:]]+[^!#]*\b(rootpw|targetpw|runaspw)\b.*)$/# disabled by remediation: \1/' \
        "$MAIN_SUDOERS" > "$TMPMAIN"
    if "$VISUDO" -cf "$TMPMAIN" >/dev/null 2>&1; then
        install -m 0440 -o root -g root "$TMPMAIN" "$MAIN_SUDOERS"
    else
        echo "Warning: could not safely edit $MAIN_SUDOERS; leaving unchanged." >&2
        rm -f "$BACKUP"
    fi
    rm -f "$TMPMAIN"
fi

# Final full validation of the sudoers configuration
if ! "$VISUDO" -cf "$MAIN_SUDOERS" >/dev/null 2>&1; then
    echo "Final sudoers validation failed!" >&2
    exit 1
fi

echo "Sudo policy enforced: users must authenticate with their own password."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q sudo; then

if grep -x '^Defaults targetpw$' /etc/sudoers; then
    sed -i "/Defaults targetpw/d" /etc/sudoers \;
fi
if grep -x '^Defaults targetpw$' /etc/sudoers.d/*; then
    find /etc/sudoers.d/ -type f -exec sed -i "/Defaults targetpw/d" {} \;
fi
if grep -x '^Defaults rootpw$' /etc/sudoers; then
    sed -i "/Defaults rootpw/d" /etc/sudoers \;
fi
if grep -x '^Defaults rootpw$' /etc/sudoers.d/*; then
    find /etc/sudoers.d/ -type f -exec sed -i "/Defaults rootpw/d" {} \;
fi
if grep -x '^Defaults runaspw$' /etc/sudoers; then
    sed -i "/Defaults runaspw/d" /etc/sudoers \;
fi
if grep -x '^Defaults runaspw$' /etc/sudoer
```


---

## RHEL-08-010472 — `package_rng-tools_installed`

**Prompt:** On an Ubuntu 24.04 system, ensure that the tooling which feeds entropy from hardware random number generators into the system's entropy pool is present, so that cryptographic operations such as x509/PKI certificate generation have access to high-quality randomness. Write an idempotent bash remediation script that guarantees this hardware random number generator tooling is installed on the system.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PACKAGE="rng-tools"

if dpkg-query -W -f='${Status}' "$PACKAGE" 2>/dev/null | grep -q "install ok installed"; then
    echo "Package '$PACKAGE' is already installed."
else
    echo "Package '$PACKAGE' is not installed. Installing now..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y "$PACKAGE"
    echo "Package '$PACKAGE' has been installed."
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if ( ! ( [ "$(sysctl -a | grep -c 'fips_enabled.*1')" -eq 1 ] ) && rpm --quiet -q kernel ); then

if ! rpm -q --quiet "rng-tools" ; then
    yum install -y "rng-tools"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```


---

## RHEL-08-040370 — `package_gssproxy_removed`

**Prompt:** On an Ubuntu 24.04 system, ensure that the GSS API credential-handling proxy service (the gssproxy component) is not present, as it is unnecessary on systems that do not require it and may conflict with strict site policies such as FIPS 140. Write an idempotent bash remediation script that guarantees this software is absent from the system.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PACKAGE="gssproxy"

if ! command -v dpkg-query >/dev/null 2>&1; then
    echo "dpkg-query not found; this script requires a Debian/Ubuntu system." >&2
    exit 1
fi

if dpkg-query -W -f='${Status}' "$PACKAGE" 2>/dev/null | grep -q "install ok installed"; then
    echo "Package '$PACKAGE' is installed. Removing..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get purge -y "$PACKAGE"
    apt-get autoremove -y --purge
    echo "Package '$PACKAGE' has been removed."
else
    echo "Package '$PACKAGE' is not installed. Nothing to do."
fi

if dpkg-query -W -f='${Status}' "$PACKAGE" 2>/dev/null | grep -q "install ok installed"; then
    echo "ERROR: Package '$PACKAGE' is still present after remediation attempt." >&2
    exit 1
fi

echo "Verification passed: '$PACKAGE' is absent from the system."
exit 0
```

**Reference fix:**
```bash
# CAUTION: This remediation script will remove gssproxy
#	   from the system, and may remove any packages
#	   that depend on gssproxy. Execute this
#	   remediation AFTER testing on a non-production
#	   system!

if rpm -q --quiet "gssproxy" ; then
yum remove -y "gssproxy"
fi
```


---

## RHEL-08-040380 — `package_iprutils_removed`

**Prompt:** On an Ubuntu 24.04 system, the utility suite for managing and configuring SCSI devices supported by the ipr SCSI storage device driver is unnecessary on most systems and expands the attack surface. Write an idempotent bash remediation script that ensures this iprutils package is not present on the system, leaving the system compliant whether or not the package was installed.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PACKAGE="iprutils"

if dpkg-query -W -f='${Status}' "$PACKAGE" 2>/dev/null | grep -q "install ok installed"; then
    echo "Package '$PACKAGE' is installed. Removing..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get purge -y "$PACKAGE"
    apt-get autoremove -y
    echo "Package '$PACKAGE' has been removed."
else
    echo "Package '$PACKAGE' is not installed. System is compliant."
fi

exit 0
```

**Reference fix:**
```bash
# CAUTION: This remediation script will remove iprutils
#	   from the system, and may remove any packages
#	   that depend on iprutils. Execute this
#	   remediation AFTER testing on a non-production
#	   system!

if rpm -q --quiet "iprutils" ; then
yum remove -y "iprutils"
fi
```


---

## RHEL-08-040001 — `package_libreport-plugin-rhtsupport_removed`

**Prompt:** On an Ubuntu 24.04 system, the automated bug-reporting plugin that submits crash reports into the Red Hat Support system is considered unnecessary and increases the attack surface and risk of inadvertent disclosure of system information. Write an idempotent bash remediation script that ensures this Red Hat Support reporting plugin component of the automated crash-reporting framework is not present on the system.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PACKAGE="libreport-plugin-rhtsupport"

if ! command -v dpkg-query >/dev/null 2>&1; then
    echo "dpkg-query not available; this script targets Debian/Ubuntu systems." >&2
    exit 1
fi

status="$(dpkg-query -W -f='${Status}' "$PACKAGE" 2>/dev/null || true)"

if echo "$status" | grep -q "install ok installed"; then
    echo "Package '$PACKAGE' is installed. Removing..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get remove --purge -y "$PACKAGE"
    apt-get autoremove --purge -y
    echo "Package '$PACKAGE' removed."
else
    echo "Package '$PACKAGE' is not installed. Nothing to do."
fi

if dpkg-query -W -f='${Status}' "$PACKAGE" 2>/dev/null | grep -q "install ok installed"; then
    echo "ERROR: Package '$PACKAGE' is still present after remediation." >&2
    exit 1
fi

echo "Remediation complete: '$PACKAGE' is not present on the system."
```

**Reference fix:**
```bash
# CAUTION: This remediation script will remove libreport-plugin-rhtsupport
#	   from the system, and may remove any packages
#	   that depend on libreport-plugin-rhtsupport. Execute this
#	   remediation AFTER testing on a non-production
#	   system!

if rpm -q --quiet "libreport-plugin-rhtsupport" ; then
yum remove -y "libreport-plugin-rhtsupport"
fi
```


---

## RHEL-08-040390 — `package_tuned_removed`

**Prompt:** On an Ubuntu 24.04 system, ensure that the system-tuning daemon package — which dynamically adjusts performance and power-management settings by continuously monitoring system component usage — is not present on the system, eliminating an unnecessary background service and reducing the attack surface. Write an idempotent bash remediation script that guarantees this package is absent.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PACKAGE="tuned"

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root." >&2
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive

if dpkg-query -W -f='${Status}' "$PACKAGE" 2>/dev/null | grep -q "install ok installed"; then
    echo "Package '$PACKAGE' is installed. Removing..."
    apt-get purge -y "$PACKAGE"
    apt-get autoremove -y
    echo "Package '$PACKAGE' has been removed."
else
    echo "Package '$PACKAGE' is not installed. Nothing to do."
fi

if dpkg-query -W -f='${Status}' "$PACKAGE" 2>/dev/null | grep -q "install ok installed"; then
    echo "Failed to remove package '$PACKAGE'." >&2
    exit 1
fi

echo "Verified: package '$PACKAGE' is absent."
```

**Reference fix:**
```bash
# CAUTION: This remediation script will remove tuned
#	   from the system, and may remove any packages
#	   that depend on tuned. Execute this
#	   remediation AFTER testing on a non-production
#	   system!

if rpm -q --quiet "tuned" ; then
yum remove -y "tuned"
fi
```


---

## RHEL-08-010371 — `ensure_gpgcheck_local_packages`

**Prompt:** On an Ubuntu 24.04 system, ensure that the package-management subsystem cryptographically verifies the GPG signature of locally installed package files before they are installed, so that tampered or untrusted software cannot be installed from local sources. Write an idempotent bash remediation script that globally enforces signature verification for local package installations.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

CONF_DIR="/etc/dpkg/dpkg.cfg.d"
CONF_FILE="${CONF_DIR}/99-disable-no-debsig"
APT_CONF_DIR="/etc/apt/apt.conf.d"
APT_CONF_FILE="${APT_CONF_DIR}/99verify-local-sigs"

if [[ "$(id -u)" -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

mkdir -p "$CONF_DIR"
mkdir -p "$APT_CONF_DIR"

# Ensure dpkg does NOT have no-debsig set (which would disable signature checks)
# Remove any 'no-debsig' directives from dpkg config files.
for f in /etc/dpkg/dpkg.cfg "${CONF_DIR}"/*; do
    [[ -f "$f" ]] || continue
    if grep -Eq '^\s*no-debsig\s*$' "$f"; then
        sed -i -E '/^\s*no-debsig\s*$/d' "$f"
    fi
done

# Enforce debsig signature verification for dpkg by ensuring no-debsig is absent
# and creating an explicit configuration marker.
cat > "$CONF_FILE" <<'EOF'
# Managed by remediation script.
# Do not disable debsig-verify; local package signatures must be verified.
# (Absence of 'no-debsig' enables debsig-verify checking.)
EOF
chmod 0644 "$CONF_FILE"

# Ensure debsig-verify is installed to perform the cryptographic verification.
export DEBIAN_FRONTEND=noninteractive
if ! dpkg -s debsig-verify >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y debsig-verify
fi

# Enforce APT settings so that local .deb installs require verified signatures
# and untrusted/unauthenticated packages are not allowed.
cat > "$APT_CONF_FILE" <<'EOF'
// Managed by remediation script.
// Enforce cryptographic verification for local package installations.
APT::Get::AllowUnauthenticated "false";
Acquire::AllowInsecureRepositories "false";
Acquire::AllowDowngradeToInsecureRepositories "false";
APT::Get::AllowInsecureRepositories "false";
APT::Get::AllowDowngradeToInsecureRepositories "false";
EOF
chmod 0644 "$APT_CONF_FILE"

echo "Local package signature verification has been enforced."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q yum; then

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^localpkg_gpgcheck")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "1"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^localpkg_gpgcheck\\>" "/etc/yum.conf"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' 
```


---

## needed_rules — `enable_authselect`

**Prompt:** On an Ubuntu 24.04 system, the system authentication and identity configuration (the PAM stack and related nsswitch settings) should be managed by the supported profile-based authentication configuration tool rather than hand-edited, to avoid fragile or broken manual configurations. Write an idempotent bash remediation script that ensures user authentication is configured through this profile-based tool by selecting and activating a tested, supported authentication profile. The change must persist across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Idempotent remediation script to ensure user authentication is managed
# by the profile-based authentication configuration tool (authselect) on
# Ubuntu 24.04, selecting and activating a tested, supported profile.

set -euo pipefail

LOG_TAG="authselect-remediation"

log() {
    echo "[$LOG_TAG] $*"
}

if [[ "$(id -u)" -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# Ensure authselect (the profile-based authentication configuration tool)
# is installed.
if ! command -v authselect >/dev/null 2>&1; then
    log "authselect not found; installing..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y authselect
fi

if ! command -v authselect >/dev/null 2>&1; then
    echo "authselect installation failed; cannot continue." >&2
    exit 1
fi

# The tested, supported profile to activate.
DESIRED_PROFILE="sssd"

# Determine the currently active profile (if any).
CURRENT_PROFILE=""
if authselect current >/dev/null 2>&1; then
    CURRENT_PROFILE="$(authselect current 2>/dev/null | awk -F'"' '/Profile ID:/ {print $2} /Profile ID:/ {next}' | head -n1)"
    if [[ -z "$CURRENT_PROFILE" ]]; then
        CURRENT_PROFILE="$(authselect current 2>/dev/null | sed -n 's/.*Profile ID:[[:space:]]*//p' | head -n1)"
    fi
fi

# Verify the desired profile is available.
if ! authselect list 2>/dev/null | awk '{print $1}' | grep -qx "$DESIRED_PROFILE"; then
    echo "Desired profile '$DESIRED_PROFILE' is not available in authselect." >&2
    exit 1
fi

if [[ "$CURRENT_PROFILE" == "$DESIRED_PROFILE" ]]; then
    log "Profile '$DESIRED_PROFILE' is already active."
    # Ensure configuration is consistent/applied; enforce persistence.
    if ! authselect check >/dev/null 2>&1; then
        log "Configuration inconsistent; re-applying profile with --force."
        authselect select "$DESIRED_PROFILE" with-mkhomedir --force
        authselect apply-changes >/dev/null 2>&1 || true
    fi
else
    log "Selecting and activating profile '$DESIRED_PROFILE'..."
    authselect select "$DESIRED_PROFILE" with-mkhomedir --force
    authselect apply-changes >/dev/null 2>&1 || true
fi

# Enable the mkhomedir PAM behavior service if present (persists across reboots).
if command -v systemctl >/dev/null 2>&1; then
    if systemctl list-unit-files 2>/dev/null | grep -q '^oddjobd\.service'; then
        systemctl enable --now oddjobd.service >/dev/null 2>&1 || true
    fi
fi

# Final verification.
if authselect check >/dev/null 2>&1; then
    log "authselect configuration is valid and applied."
else
    log "WARNING: authselect check reported inconsistencies."
fi

log "Current authentication profile:"
authselect current || true

exit 0
```

**Reference fix:**
```bash
var_authselect_profile='
```


---

## RHEL-08-010060 — `banner_etc_issue`

**Prompt:** On an Ubuntu 24.04 system, ensure that a legally approved system-use notification (login banner) is presented to users before they gain access through local console login interfaces, so that all users are warned of monitoring and authorized-use conditions consistent with site/legal policy. The banner must contain the DoD-required notification text exactly. Write an idempotent bash remediation script that establishes this login banner content for console-based logins.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

BANNER_FILE="/etc/issue"

BANNER_TEXT="You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions: -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. -At any time, the USG may inspect and seize data stored on this IS. -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

printf '%s\n' "$BANNER_TEXT" > "$BANNER_FILE"

chown root:root "$BANNER_FILE"
chmod 0644 "$BANNER_FILE"

echo "Login banner configured in $BANNER_FILE"
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

login_banner_text='
```


---

## RHEL-08-010049 — `dconf_gnome_banner_enabled`

**Prompt:** On an Ubuntu 24.04 system that uses the GNOME graphical desktop, configure the GNOME Display Manager so that an approved login warning banner is displayed on the graphical login screen before a user authenticates, satisfying the requirement to present a use-notification message to human users. The banner display must be enabled and locked so that ordinary users cannot disable or override it, and the configuration must persist across reboots. Write an idempotent bash remediation script that achieves this end state.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

BANNER_TEXT="You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions: -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. -At any time, the USG may inspect and seize data stored on this IS. -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

if ! dpkg-query -W -f='${Status}' gnome-shell 2>/dev/null | grep -q "install ok installed"; then
    echo "GNOME is not installed; nothing to configure."
    exit 0
fi

PROFILE_DIR="/etc/dconf/profile"
DB_DIR="/etc/dconf/db/gdm.d"
LOCK_DIR="/etc/dconf/db/gdm.d/locks"

mkdir -p "$PROFILE_DIR" "$DB_DIR" "$LOCK_DIR"

PROFILE_FILE="$PROFILE_DIR/gdm"
cat > "$PROFILE_FILE" <<'EOF'
user-db:user
system-db:gdm
file-db:/usr/share/gdm/greeter-dconf-defaults
EOF

SETTINGS_FILE="$DB_DIR/01-banner-message"
{
    echo "[org/gnome/login-screen]"
    echo "banner-message-enable=true"
    printf "banner-message-text='%s'\n" "${BANNER_TEXT//\'/\\\'}"
} > "$SETTINGS_FILE"

LOCK_FILE="$LOCK_DIR/01-banner-message"
cat > "$LOCK_FILE" <<'EOF'
/org/gnome/login-screen/banner-message-enable
/org/gnome/login-screen/banner-message-text
EOF

dconf update

echo "GDM login banner configured and locked."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm; then

# Check for setting in any of the DConf db directories
# If files contain ibus or distro, ignore them.
# The assignment assumes that individual filenames don't contain :
readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/login-screen\\]" "/etc/dconf/db/" \
                                | grep -v 'distro\|ibus\|gdm.d' | cut -d":" -f1)
DCONFFILE="/etc/dconf/db/gdm.d/00-security-settings"
DBDIR="/etc/dconf/db/gdm.d"

mkdir -p "${DBDIR}"

# Comment out the configurations in databases different from the target one
if [ "${#SETTINGSFILES[@]}" -ne 0 ]
then
    if grep -q "^\\s*banner-message-enable\\s*=" "${SETTI
```


---

## RHEL-08-010050 — `dconf_gnome_login_banner_text`

**Prompt:** On an Ubuntu 24.04 system with a graphical environment, configure the GNOME Display Manager's login screen to display an approved organizational warning/consent banner before users log in, so policy awareness is reinforced and legal enforceability is supported. The banner text must match your environment's approved message exactly, must be enforced as the active value, and must be locked so non-privileged users cannot override it. Write an idempotent bash remediation script that sets and locks the graphical login warning banner text and ensures the change persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Configure and lock the GDM login screen warning/consent banner.
# Idempotent: safe to run multiple times.
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Approved organizational banner text (edit to match your environment exactly)
# ---------------------------------------------------------------------------
BANNER_TEXT='WARNING: This is a restricted system. Access is limited to authorized users for approved business purposes only. By continuing you consent to monitoring and recording of all activity. Unauthorized or improper use may result in disciplinary action and/or civil and criminal penalties.'

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
PROFILE_DIR="/etc/dconf/profile"
PROFILE_FILE="${PROFILE_DIR}/gdm"

DB_DIR="/etc/dconf/db/gdm.d"
BANNER_FILE="${DB_DIR}/00-login-screen"

LOCK_DIR="/etc/dconf/db/gdm.d/locks"
LOCK_FILE="${LOCK_DIR}/00-login-screen-lock"

# ---------------------------------------------------------------------------
# Ensure required tooling / directories exist
# ---------------------------------------------------------------------------
if ! command -v dconf >/dev/null 2>&1; then
    echo "dconf command not found. Installing dconf-cli..." >&2
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y dconf-cli
fi

install -d -m 0755 "${PROFILE_DIR}"
install -d -m 0755 "${DB_DIR}"
install -d -m 0755 "${LOCK_DIR}"

# ---------------------------------------------------------------------------
# 1. dconf profile for GDM (system-db:gdm)
# ---------------------------------------------------------------------------
PROFILE_CONTENT='user-db:user
system-db:gdm
file-db:/usr/share/gdm/greeter-dconf-defaults'

desired_profile_write=1
if [[ -f "${PROFILE_FILE}" ]]; then
    if grep -qxF 'system-db:gdm' "${PROFILE_FILE}"; then
        desired_profile_write=0
    fi
fi

if [[ "${desired_profile_write}" -eq 1 ]]; then
    printf '%s\n' "${PROFILE_CONTENT}" > "${PROFILE_FILE}"
    chmod 0644 "${PROFILE_FILE}"
fi

# ---------------------------------------------------------------------------
# 2. Banner enabled + text keyfile
# ---------------------------------------------------------------------------
# Escape single quotes for GVariant string representation.
escaped_banner="${BANNER_TEXT//\'/\\\'}"

DESIRED_BANNER_CONTENT="[org/gnome/login-screen]
banner-message-enable=true
banner-message-text='${escaped_banner}'"

write_banner=1
if [[ -f "${BANNER_FILE}" ]]; then
    if [[ "$(cat "${BANNER_FILE}")" == "${DESIRED_BANNER_CONTENT}" ]]; then
        write_banner=0
    fi
fi

if [[ "${write_banner}" -eq 1 ]]; then
    printf '%s\n' "${DESIRED_BANNER_CONTENT}" > "${BANNER_FILE}"
    chmod 0644 "${BANNER_FILE}"
fi

# ---------------------------------------------------------------------------
# 3. Lock the keys so non-privileged users cannot override them
# ---------------------------------------------------------------------------
DESIRED_LOCK_CONTENT="/org/gnome/login-screen/banner-message-enable
/org/gnome/login-screen/banner-message-text"

write_lock=1
if [[ -f "${LOCK_FILE}" ]]; then
    if [[ "$(cat "${LOCK_FILE}")" == "${DESIRED_LOCK_CONTENT}" ]]; then
        write_lock=0
    fi
fi

if [[ "${write_lock}" -eq 1 ]]; then
    printf '%s\n' "${DESIRED_LOCK_CONTENT}" > "${LOCK_FILE}"
    chmod 0644 "${LOCK_FILE}"
fi

# ---------------------------------------------------------------------------
# 4. Recompile the dconf databases so changes take effect and persist
# ---------------------------------------------------------------------------
if [[ "${desired_profile_write}" -eq 1 || "${write_banner}" -eq 1 || "${write_lock}" -eq 1 ]]; then
    dconf update
else
    # Ensure the compiled db is present even if source files were unchanged.
    if [[ ! -f "/etc/dconf/db/gdm" ]]; then
        dconf update
    fi
fi

# ---------------------------------------------------------------------------
# 5. Verification
# ---------------------------------------------------------------------------
echo "Verification:"
echo "  Profile file : ${PROFILE_FILE}"
echo "  Banner file  : ${BANNER_FILE}"
echo "  Lock file    : ${LOCK_FILE}"
echo
echo "  Active banner-message-enable setting:"
grep -H 'banner-message-enable' "${BANNER_FILE}" || true
echo "  Active banner-message-text setting:"
grep -H 'banner-message-text' "${BANNER_FILE}" || true
echo "  Locks in effect:"
cat "${LOCK_FILE}"

echo
echo "GDM login screen warning banner configured and locked successfully."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm; then

login_banner_text='
```


---

## RHEL-08-020026 — `account_password_pam_faillock_password_auth`

**Prompt:** On an Ubuntu 24.04 system, ensure that the PAM authentication stack used for password-based logins is configured to track and enforce account lockouts on repeated failed authentication attempts, so that brute-force password-guessing attacks are reliably defeated. The relevant lockout-enforcement mechanism must be active in the appropriate authentication phase of the system's password-authentication PAM configuration. Write an idempotent bash remediation script that ensures this account-lockout enforcement is in place persistently.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Idempotent remediation: ensure pam_faillock account-lockout enforcement is
# active in the auth phase of Ubuntu 24.04's PAM password-auth stack.
#
set -euo pipefail

PAM_FILE="/etc/pam.d/common-auth"

if [[ ! -f "$PAM_FILE" ]]; then
    echo "ERROR: $PAM_FILE not found." >&2
    exit 1
fi

# Backup once
BACKUP="${PAM_FILE}.bak.$(date +%Y%m%d%H%M%S)"
cp -a "$PAM_FILE" "$BACKUP"

# --- Ensure pam_faillock preauth line exists (before pam_unix) ---
if ! grep -Eq '^\s*auth\s+.*pam_faillock\.so\s+preauth' "$PAM_FILE"; then
    # Insert preauth line immediately before the first pam_unix.so auth line
    awk '
        BEGIN { inserted = 0 }
        {
            if (!inserted && $0 ~ /^[[:space:]]*auth[[:space:]].*pam_unix\.so/) {
                print "auth\trequired\t\t\tpam_faillock.so preauth"
                inserted = 1
            }
            print $0
        }
        END {
            if (!inserted) {
                # No pam_unix auth line found; append preauth at end
                print "auth\trequired\t\t\tpam_faillock.so preauth"
            }
        }
    ' "$PAM_FILE" > "${PAM_FILE}.tmp"
    mv "${PAM_FILE}.tmp" "$PAM_FILE"
fi

# --- Ensure pam_faillock authfail line exists (after pam_unix) ---
if ! grep -Eq '^\s*auth\s+.*pam_faillock\.so\s+authfail' "$PAM_FILE"; then
    awk '
        BEGIN { inserted = 0 }
        {
            print $0
            if (!inserted && $0 ~ /^[[:space:]]*auth[[:space:]].*pam_unix\.so/) {
                print "auth\t[default=die]\t\tpam_faillock.so authfail"
                inserted = 1
            }
        }
        END {
            if (!inserted) {
                print "auth\t[default=die]\t\tpam_faillock.so authfail"
            }
        }
    ' "$PAM_FILE" > "${PAM_FILE}.tmp"
    mv "${PAM_FILE}.tmp" "$PAM_FILE"
fi

# --- Ensure account phase includes pam_faillock to reset/track counters ---
ACCT_FILE="/etc/pam.d/common-account"
if [[ -f "$ACCT_FILE" ]]; then
    if ! grep -Eq '^\s*account\s+.*pam_faillock\.so' "$ACCT_FILE"; then
        printf 'account\trequired\t\t\tpam_faillock.so\n' >> "$ACCT_FILE"
    fi
fi

# --- Configure lockout policy persistently in /etc/security/faillock.conf ---
FAILLOCK_CONF="/etc/security/faillock.conf"
touch "$FAILLOCK_CONF"

set_conf() {
    local key="$1" value="$2" file="$3"
    if grep -Eq "^\s*#?\s*${key}\b" "$file"; then
        # Replace existing (commented or not) line
        sed -ri "s|^\s*#?\s*${key}\b.*|${key} = ${value}|" "$file"
    else
        echo "${key} = ${value}" >> "$file"
    fi
}

set_conf "deny"          "5"   "$FAILLOCK_CONF"
set_conf "unlock_time"   "900" "$FAILLOCK_CONF"
set_conf "fail_interval" "900" "$FAILLOCK_CONF"

# Normalize any duplicate/simple boolean keys that take no value
# (audit / silent / no_log_info are boolean-style; leave defaults unless present)

echo "pam_faillock account-lockout enforcement configured."
echo "Backup of original common-auth saved to: $BACKUP"
```

**Reference fix:**
```bash
if [ -f /usr/bin/authselect ]; then
    if ! authselect check; then
echo "
authselect integrity check failed. Remediation aborted!
This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
It is not recommended to manually edit the PAM files when authselect tool is available.
In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
exit 1
fi
authselect enable-feature with-faillock

authselect apply-changes -b
else
    
AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
for pam_file in "${AUTH_FILES[@]}"
do
    if ! grep -qE '^\s*auth\s+required\s
```


---

## RHEL-08-020025 — `account_password_pam_faillock_system_auth`

**Prompt:** On an Ubuntu 24.04 system, configure the system's pluggable authentication framework so that failed login attempts are tracked and accounts can be locked out, defending against password brute-force and guessing attacks. Ensure the account-lockout enforcement mechanism is properly engaged within the system-wide authentication stack so that failures are counted before authentication proceeds. Write an idempotent bash remediation script that establishes this behavior and persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Configure pam_faillock on Ubuntu 24.04 to track failed logins and lock accounts.
# Idempotent remediation script.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

FAILLOCK_CONF="/etc/security/faillock.conf"
AUTH_FILE="/etc/pam.d/common-auth"
ACCOUNT_FILE="/etc/pam.d/common-account"

# Desired faillock policy parameters
DENY=5
UNLOCK_TIME=900
FAIL_INTERVAL=900

timestamp="$(date +%Y%m%d%H%M%S)"

#############################################
# 1. Configure /etc/security/faillock.conf
#############################################
if [[ ! -f "$FAILLOCK_CONF" ]]; then
    touch "$FAILLOCK_CONF"
fi

cp -a "$FAILLOCK_CONF" "${FAILLOCK_CONF}.bak.${timestamp}"

set_faillock_option() {
    local key="$1"
    local value="$2"
    if grep -Eq "^[[:space:]]*#?[[:space:]]*${key}([[:space:]]*=.*)?$" "$FAILLOCK_CONF" 2>/dev/null; then
        # Replace existing (commented or not) line
        sed -i -E "s|^[[:space:]]*#?[[:space:]]*${key}([[:space:]]*=.*)?$|${key} = ${value}|" "$FAILLOCK_CONF"
    else
        echo "${key} = ${value}" >> "$FAILLOCK_CONF"
    fi
}

set_faillock_option "deny" "$DENY"
set_faillock_option "unlock_time" "$UNLOCK_TIME"
set_faillock_option "fail_interval" "$FAIL_INTERVAL"

#############################################
# 2. Configure /etc/pam.d/common-auth
#############################################
cp -a "$AUTH_FILE" "${AUTH_FILE}.bak.${timestamp}"

# Ensure preauth line exists before the first auth statement
if ! grep -Eq "^\s*auth\s+required\s+pam_faillock\.so\s+preauth" "$AUTH_FILE"; then
    # Insert before the first non-comment auth line
    if grep -Eq "^\s*auth\s+" "$AUTH_FILE"; then
        awk '
            !inserted && /^[[:space:]]*auth[[:space:]]+/ && $0 !~ /pam_faillock\.so/ {
                print "auth\trequired\t\t\tpam_faillock.so preauth";
                inserted=1;
            }
            { print }
            END {
                if (!inserted) print "auth\trequired\t\t\tpam_faillock.so preauth";
            }
        ' "$AUTH_FILE" > "${AUTH_FILE}.tmp"
        mv "${AUTH_FILE}.tmp" "$AUTH_FILE"
    else
        echo -e "auth\trequired\t\t\tpam_faillock.so preauth" >> "$AUTH_FILE"
    fi
fi

# Ensure authfail line exists after the pam_unix auth line
if ! grep -Eq "^\s*auth\s+\[default=die\]\s+pam_faillock\.so\s+authfail" "$AUTH_FILE"; then
    if grep -Eq "^\s*auth\s+.*pam_unix\.so" "$AUTH_FILE"; then
        awk '
            { print }
            !inserted && /^[[:space:]]*auth[[:space:]]+.*pam_unix\.so/ {
                print "auth\t[default=die]\t\tpam_faillock.so authfail";
                inserted=1;
            }
            END {
                if (!inserted) print "auth\t[default=die]\t\tpam_faillock.so authfail";
            }
        ' "$AUTH_FILE" > "${AUTH_FILE}.tmp"
        mv "${AUTH_FILE}.tmp" "$AUTH_FILE"
    else
        echo -e "auth\t[default=die]\t\tpam_faillock.so authfail" >> "$AUTH_FILE"
    fi
fi

#############################################
# 3. Configure /etc/pam.d/common-account
#############################################
cp -a "$ACCOUNT_FILE" "${ACCOUNT_FILE}.bak.${timestamp}"

if ! grep -Eq "^\s*account\s+required\s+pam_faillock\.so" "$ACCOUNT_FILE"; then
    # Insert before the first account line
    if grep -Eq "^\s*account\s+" "$ACCOUNT_FILE"; then
        awk '
            !inserted && /^[[:space:]]*account[[:space:]]+/ && $0 !~ /pam_faillock\.so/ {
                print "account\trequired\t\t\tpam_faillock.so";
                inserted=1;
            }
            { print }
            END {
                if (!inserted) print "account\trequired\t\t\tpam_faillock.so";
            }
        ' "$ACCOUNT_FILE" > "${ACCOUNT_FILE}.tmp"
        mv "${ACCOUNT_FILE}.tmp" "$ACCOUNT_FILE"
    else
        echo -e "account\trequired\t\t\tpam_faillock.so" >> "$ACCOUNT_FILE"
    fi
fi

echo "pam_faillock configuration applied successfully."
echo "faillock.conf: deny=${DENY}, unlock_time=${UNLOCK_TIME}, fail_interval=${FAIL_INTERVAL}"
```

**Reference fix:**
```bash
if [ -f /usr/bin/authselect ]; then
    if ! authselect check; then
echo "
authselect integrity check failed. Remediation aborted!
This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
It is not recommended to manually edit the PAM files when authselect tool is available.
In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
exit 1
fi
authselect enable-feature with-faillock

authselect apply-changes -b
else
    
AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
for pam_file in "${AUTH_FILES[@]}"
do
    if ! grep -qE '^\s*auth\s+required\s
```


---

## RHEL-08-020021 — `accounts_passwords_pam_faillock_audit`

**Prompt:** On an Ubuntu 24.04 system, the authentication failure-counting and lockout subsystem must record an audit/log entry whenever an account is locked out due to excessive failed login attempts, so that brute-force attacks and their aftermath can be reliably investigated. Write an idempotent bash remediation script that ensures account-lockout events are logged, with the change persisting across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Ensure account-lockout events are logged via pam_faillock (audit option).
# Idempotent remediation for Ubuntu 24.04.
#
set -euo pipefail

FAILLOCK_CONF="/etc/security/faillock.conf"

# Ensure the faillock configuration file exists
if [[ ! -f "$FAILLOCK_CONF" ]]; then
    touch "$FAILLOCK_CONF"
    chmod 0644 "$FAILLOCK_CONF"
    chown root:root "$FAILLOCK_CONF"
fi

# Ensure the 'audit' directive is present and uncommented in faillock.conf.
# The 'audit' option makes pam_faillock write a log/audit entry when an
# account is locked out (and on failures), enabling investigation.
if grep -Eq '^\s*audit\b' "$FAILLOCK_CONF"; then
    # Already active, ensure it is not commented and is exactly 'audit'
    sed -ri 's/^\s*audit\b.*/audit/' "$FAILLOCK_CONF"
elif grep -Eq '^\s*#\s*audit\b' "$FAILLOCK_CONF"; then
    # Uncomment an existing commented directive
    sed -ri 's/^\s*#\s*audit\b.*/audit/' "$FAILLOCK_CONF"
else
    # Append the directive
    printf '%s\n' 'audit' >> "$FAILLOCK_CONF"
fi

# Also make sure a silent option is not suppressing messages
if grep -Eq '^\s*silent\b' "$FAILLOCK_CONF"; then
    sed -ri 's/^\s*silent\b.*/# silent (disabled to allow lockout logging)/' "$FAILLOCK_CONF"
fi

# Ensure pam_faillock is actually enabled in the PAM stack so lockout occurs
# and the audit option takes effect. On Ubuntu, pam-auth-update manages this,
# but we also verify direct config lines as a fallback.
for PAM_FILE in /etc/pam.d/common-auth /etc/pam.d/common-account; do
    [[ -f "$PAM_FILE" ]] || continue
done

# Enable pam_faillock in common-auth if not already present.
COMMON_AUTH="/etc/pam.d/common-auth"
if [[ -f "$COMMON_AUTH" ]]; then
    if ! grep -Eq '^\s*auth\s+.*pam_faillock\.so\s+preauth' "$COMMON_AUTH"; then
        sed -ri '0,/^\s*auth\s+/s//auth\trequired\t\t\tpam_faillock.so preauth\n&/' "$COMMON_AUTH"
    fi
    if ! grep -Eq '^\s*auth\s+.*pam_faillock\.so\s+authfail' "$COMMON_AUTH"; then
        printf '%s\n' 'auth\t[default=die]\t\t\tpam_faillock.so authfail' >> "$COMMON_AUTH"
    fi
fi

# Enable pam_faillock account phase in common-account if not already present.
COMMON_ACCOUNT="/etc/pam.d/common-account"
if [[ -f "$COMMON_ACCOUNT" ]]; then
    if ! grep -Eq '^\s*account\s+.*pam_faillock\.so' "$COMMON_ACCOUNT"; then
        printf '%s\n' 'account\trequired\t\t\tpam_faillock.so' >> "$COMMON_ACCOUNT"
    fi
fi

echo "faillock audit logging of account-lockout events is configured (persists across reboots)."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if grep -qP "^ID=[\"']?rhel[\"']?$" "/etc/os-release" && { real="$(grep -P "^VERSION_ID=[\"']?[\w.]+[\"']?$" /etc/os-release | sed "s/^VERSION_ID=[\"']\?\([^\"']\+\)[\"']\?$/\1/")"; expected="8.2"; printf "%s\n%s" "$expected" "$real" | sort -VC; }; then

if [ -f /usr/bin/authselect ]; then
    if ! authselect check; then
echo "
authselect integrity check failed. Remediation aborted!
This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
It is not recommended to manually edit the PAM files when authselect tool is available.
In cases where the default authselect profile do
```


---

## RHEL-08-020011 — `accounts_passwords_pam_faillock_deny`

**Prompt:** On an Ubuntu 24.04 system, configure the authentication subsystem so that a user account is automatically locked after no more than 3 consecutive failed login attempts, mitigating password brute-force/guessing attacks. The lockout policy must apply system-wide, be enforced through the standard authentication framework, be idempotent, and persist across reboots. Write a bash remediation script that achieves this end state.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation script: lock a user account after no more than 3 consecutive
# failed login attempts on Ubuntu 24.04 using pam_faillock.
#
# The script is idempotent and persists across reboots because it modifies
# the on-disk PAM configuration files and /etc/security/faillock.conf.
#
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

DENY=3
UNLOCK_TIME=600
FAILLOCK_CONF="/etc/security/faillock.conf"
PAM_AUTH="/etc/pam.d/common-auth"
PAM_ACCOUNT="/etc/pam.d/common-account"

timestamp="$(date +%Y%m%d%H%M%S)"

backup_file() {
    local f="$1"
    if [[ -f "$f" && ! -f "${f}.bak.${timestamp}" ]]; then
        cp -a "$f" "${f}.bak.${timestamp}"
    fi
}

#-----------------------------------------------------------------------
# 1. Configure /etc/security/faillock.conf (system-wide policy)
#-----------------------------------------------------------------------
backup_file "$FAILLOCK_CONF"
touch "$FAILLOCK_CONF"

set_conf_option() {
    local key="$1"
    local value="$2"
    local file="$3"
    if grep -Eq "^[[:space:]]*#?[[:space:]]*${key}([[:space:]]*=.*|[[:space:]]*)$" "$file"; then
        sed -i -E "s|^[[:space:]]*#?[[:space:]]*${key}([[:space:]]*=.*|[[:space:]]*)$|${key} = ${value}|" "$file"
    else
        echo "${key} = ${value}" >> "$file"
    fi
}

# Ensure clean, idempotent entries
sed -i -E '/^[[:space:]]*#?[[:space:]]*deny[[:space:]]*=/d' "$FAILLOCK_CONF"
sed -i -E '/^[[:space:]]*#?[[:space:]]*unlock_time[[:space:]]*=/d' "$FAILLOCK_CONF"

{
    echo "deny = ${DENY}"
    echo "unlock_time = ${UNLOCK_TIME}"
} >> "$FAILLOCK_CONF"

#-----------------------------------------------------------------------
# 2. Configure /etc/pam.d/common-auth
#-----------------------------------------------------------------------
backup_file "$PAM_AUTH"

# Remove any prior pam_faillock lines we may have added to keep idempotent
sed -i -E '/pam_faillock\.so/d' "$PAM_AUTH"

# Insert pam_faillock preauth before the first auth line, and authfail/authsucc
# appropriately. We build a new file to guarantee correct ordering.
tmp="$(mktemp)"

inserted_preauth=0
while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ $inserted_preauth -eq 0 && "$line" =~ ^auth[[:space:]] ]]; then
        echo "auth    required    pam_faillock.so preauth" >> "$tmp"
        inserted_preauth=1
    fi
    echo "$line" >> "$tmp"
    # After the primary unix auth module, add authfail handling
    if [[ "$line" =~ pam_unix\.so ]] && [[ "$line" =~ ^auth[[:space:]] ]]; then
        echo "auth    [default=die]    pam_faillock.so authfail" >> "$tmp"
    fi
done < "$PAM_AUTH"

# If no auth line existed, ensure preauth is present at top
if [[ $inserted_preauth -eq 0 ]]; then
    sed -i '1i auth    required    pam_faillock.so preauth' "$tmp"
fi

# Append authsucc at the end to reset the counter on success
echo "auth    sufficient    pam_faillock.so authsucc" >> "$tmp"

cat "$tmp" > "$PAM_AUTH"
rm -f "$tmp"

#-----------------------------------------------------------------------
# 3. Configure /etc/pam.d/common-account
#-----------------------------------------------------------------------
backup_file "$PAM_ACCOUNT"
if ! grep -Eq '^[[:space:]]*account[[:space:]]+required[[:space:]]+pam_faillock\.so' "$PAM_ACCOUNT"; then
    echo "account    required    pam_faillock.so" >> "$PAM_ACCOUNT"
fi

echo "faillock policy applied: deny=${DENY}, unlock_time=${UNLOCK_TIME}."
echo "Configuration persisted in ${FAILLOCK_CONF}, ${PAM_AUTH}, ${PAM_ACCOUNT}."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_accounts_passwords_pam_faillock_deny='
```


---

## RHEL-08-020023 — `accounts_passwords_pam_faillock_deny_root`

**Prompt:** On an Ubuntu 24.04 system, configure the authentication subsystem so that the root account is subject to the same automatic account-locking policy applied after repeated failed login attempts, ensuring that brute-force password guessing against root results in the account being locked rather than allowing unlimited tries. Write an idempotent bash remediation script that enables failed-attempt lockout enforcement for the root account in a way that is correctly integrated into the system's authentication configuration and persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: enforce failed-attempt account lockout for the root account
# on Ubuntu 24.04 using pam_faillock.
#
# This script is idempotent: it can be run repeatedly and will converge the
# faillock configuration to the desired state without duplicating settings.

set -euo pipefail

FAILLOCK_CONF="/etc/security/faillock.conf"

# Ensure we are running as root
if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# Ensure the faillock configuration file exists
if [[ ! -f "${FAILLOCK_CONF}" ]]; then
    touch "${FAILLOCK_CONF}"
    chmod 0644 "${FAILLOCK_CONF}"
fi

# Function to set (or add) an uncommented directive in faillock.conf
set_faillock_directive() {
    local key="$1"

    # Remove any commented-out form of the directive
    # Then ensure exactly one active, uncommented entry exists.
    if grep -Eq "^[[:space:]]*#?[[:space:]]*${key}([[:space:]]|$)" "${FAILLOCK_CONF}"; then
        # Replace the first matching line (commented or not) with the active directive
        sed -i -E "0,/^[[:space:]]*#?[[:space:]]*${key}([[:space:]]|$).*/s//${key}/" "${FAILLOCK_CONF}"
        # Remove any remaining duplicate lines for this key
        sed -i -E "\|^[[:space:]]*#?[[:space:]]*${key}([[:space:]]|$)|{/^${key}$/!d}" "${FAILLOCK_CONF}"
    else
        echo "${key}" >> "${FAILLOCK_CONF}"
    fi
}

# The key directive: subject the root account to the same lockout policy.
# 'even_deny_root' makes pam_faillock enforce locking for the root account.
set_faillock_directive "even_deny_root"

# Deduplicate the even_deny_root directive if multiple exist.
if [[ "$(grep -Ec '^even_deny_root$' "${FAILLOCK_CONF}")" -gt 1 ]]; then
    # Keep only the first occurrence
    awk '
        /^even_deny_root$/ { if (seen++) next }
        { print }
    ' "${FAILLOCK_CONF}" > "${FAILLOCK_CONF}.tmp"
    mv "${FAILLOCK_CONF}.tmp" "${FAILLOCK_CONF}"
    chmod 0644 "${FAILLOCK_CONF}"
fi

# Ensure pam_faillock is actually enabled in the PAM stack.
# On Ubuntu 24.04, PAM common configs are managed via pam-auth-update profiles,
# but faillock is not enabled by default. We ensure the auth and account
# modules are present in the common PAM files so lockout is enforced and
# persists across reboots.

configure_pam_file() {
    local pamfile="$1"

    [[ -f "${pamfile}" ]] || return 0

    # Backup once
    if [[ ! -f "${pamfile}.faillock.bak" ]]; then
        cp -a "${pamfile}" "${pamfile}.faillock.bak"
    fi

    case "${pamfile}" in
        */common-auth)
            # preauth line: check and record failures before password prompt
            if ! grep -Eq '^\s*auth\s+required\s+pam_faillock\.so\s+preauth' "${pamfile}"; then
                sed -i '1i auth        required                        pam_faillock.so preauth' "${pamfile}"
            fi
            # authfail line: record failure after a failed auth
            if ! grep -Eq '^\s*auth\s+\[default=die\]\s+pam_faillock\.so\s+authfail' "${pamfile}"; then
                echo 'auth        [default=die]                   pam_faillock.so authfail' >> "${pamfile}"
            fi
            # authsucc-style cleanup is handled by account section
            ;;
        */common-account)
            if ! grep -Eq '^\s*account\s+required\s+pam_faillock\.so' "${pamfile}"; then
                echo 'account     required                        pam_faillock.so' >> "${pamfile}"
            fi
            ;;
    esac
}

configure_pam_file "/etc/pam.d/common-auth"
configure_pam_file "/etc/pam.d/common-account"

# Verify final state
echo "faillock.conf now contains:"
grep -E '^even_deny_root$' "${FAILLOCK_CONF}" || true

echo "Root account failed-attempt lockout enforcement has been configured."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

if [ -f /usr/bin/authselect ]; then
    if ! authselect check; then
echo "
authselect integrity check failed. Remediation aborted!
This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
It is not recommended to manually edit the PAM files when authselect tool is available.
In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
exit 1
fi
authselect enable-feature with-faillock

authselect apply-changes -b
else
    
AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-au
```


---

## RHEL-08-020017 — `accounts_passwords_pam_faillock_dir`

**Prompt:** On an Ubuntu 24.04 system, the account-lockout mechanism that disables a user account after repeated failed authentication attempts stores its failure tally in a location that is cleared on every reboot, meaning a locked account would be silently re-enabled when the machine restarts. Reconfigure the authentication subsystem so that failed-login lockout state is recorded in a persistent location and therefore survives a system reboot, while keeping the existing lockout behavior intact and consistent across all relevant authentication stack entries. Write an idempotent bash remediation script that achieves this persistent-lockout end state and remains effective across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Persistent faillock remediation for Ubuntu 24.04
#
# pam_faillock stores its tally in a tmpfs-backed directory by default
# (/run/faillock) which is cleared on reboot. This script reconfigures
# faillock to use a persistent directory (/var/log/faillock) so lockout
# state survives reboots, and ensures the setting is applied consistently
# across all relevant PAM stack entries.

set -euo pipefail

FAILLOCK_CONF="/etc/security/faillock.conf"
PERSIST_DIR="/var/log/faillock"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

#######################################
# 1. Ensure the persistent directory exists with correct ownership/perms.
#######################################
if [[ ! -d "$PERSIST_DIR" ]]; then
    mkdir -p "$PERSIST_DIR"
fi
chown root:root "$PERSIST_DIR"
chmod 0751 "$PERSIST_DIR"

#######################################
# 2. Ensure faillock.conf exists and sets a persistent 'dir'.
#######################################
if [[ ! -f "$FAILLOCK_CONF" ]]; then
    touch "$FAILLOCK_CONF"
    chown root:root "$FAILLOCK_CONF"
    chmod 0644 "$FAILLOCK_CONF"
fi

# Set or update the 'dir' directive idempotently.
if grep -Eq '^[[:space:]]*#?[[:space:]]*dir[[:space:]]*=' "$FAILLOCK_CONF"; then
    # Replace any existing (commented or active) dir line with the persistent one.
    sed -ri "s|^[[:space:]]*#?[[:space:]]*dir[[:space:]]*=.*|dir = ${PERSIST_DIR}|" "$FAILLOCK_CONF"
else
    printf 'dir = %s\n' "$PERSIST_DIR" >> "$FAILLOCK_CONF"
fi

# Collapse any duplicate active 'dir' lines, keeping only the last defined one.
if [[ $(grep -Ec '^[[:space:]]*dir[[:space:]]*=' "$FAILLOCK_CONF") -gt 1 ]]; then
    tmpfile="$(mktemp)"
    # Keep all non-dir lines, then append a single canonical dir line.
    grep -Ev '^[[:space:]]*dir[[:space:]]*=' "$FAILLOCK_CONF" > "$tmpfile"
    printf 'dir = %s\n' "$PERSIST_DIR" >> "$tmpfile"
    cat "$tmpfile" > "$FAILLOCK_CONF"
    rm -f "$tmpfile"
fi

#######################################
# 3. Ensure PAM stack entries reference faillock and, where they carry
#    inline arguments, use the persistent dir consistently.
#######################################
PAM_FILES=(
    "/etc/pam.d/common-auth"
    "/etc/pam.d/common-account"
)

for pf in "${PAM_FILES[@]}"; do
    [[ -f "$pf" ]] || continue

    # For any pam_faillock line that already sets an inline 'dir=' argument,
    # normalize it to the persistent directory so behavior is consistent.
    if grep -Eq 'pam_faillock\.so.*[[:space:]]dir=' "$pf"; then
        sed -ri "/pam_faillock\.so/ s|(dir=)[^[:space:]]+|\1${PERSIST_DIR}|g" "$pf"
    fi
done

#######################################
# 4. Ensure pam_faillock is actually present in the auth stack.
#    On Ubuntu 24.04 this is normally managed by pam-auth-update /
#    the faillock profile. If faillock lines are missing entirely,
#    enable the appropriate profiles non-interactively.
#######################################
COMMON_AUTH="/etc/pam.d/common-auth"
COMMON_ACCOUNT="/etc/pam.d/common-account"

need_pam_update=0

if [[ -f "$COMMON_AUTH" ]] && ! grep -q 'pam_faillock\.so' "$COMMON_AUTH"; then
    need_pam_update=1
fi
if [[ -f "$COMMON_ACCOUNT" ]] && ! grep -q 'pam_faillock\.so' "$COMMON_ACCOUNT"; then
    need_pam_update=1
fi

if [[ "$need_pam_update" -eq 1 ]]; then
    if command -v pam-auth-update >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive pam-auth-update --enable faillock >/dev/null 2>&1 || true
        DEBIAN_FRONTEND=noninteractive pam-auth-update --enable faillock_notify >/dev/null 2>&1 || true
    fi
fi

#######################################
# 5. Re-normalize inline dir args after any pam-auth-update run.
#######################################
for pf in "${PAM_FILES[@]}"; do
    [[ -f "$pf" ]] || continue
    if grep -Eq 'pam_faillock\.so.*[[:space:]]dir=' "$pf"; then
        sed -ri "/pam_faillock\.so/ s|(dir=)[^[:space:]]+|\1${PERSIST_DIR}|g" "$pf"
    fi
done

#######################################
# 6. Report resulting state.
#######################################
echo "Persistent faillock directory: ${PERSIST_DIR}"
echo "----- ${FAILLOCK_CONF} (dir setting) -----"
grep -E '^[[:space:]]*dir[[:space:]]*=' "$FAILLOCK_CONF" || echo "(none)"
echo "----- pam_faillock entries -----"
for pf in "${PAM_FILES[@]}"; do
    [[ -f "$pf" ]] || continue
    grep -Hn 'pam_faillock\.so' "$pf" || true
done

echo "Faillock persistent-lockout remediation complete."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_accounts_passwords_pam_faillock_dir='
```


---

## RHEL-08-020013 — `accounts_passwords_pam_faillock_interval`

**Prompt:** On an Ubuntu 24.04 system, the account-lockout mechanism that counts consecutive failed authentication attempts must use a defined time window for tallying those failures, so that brute-force password-guessing attempts are grouped and trigger a lockout. Configure the system's failed-login tracking facility so that the interval over which failed attempts are counted is set to at least 900 seconds. Write an idempotent bash remediation script that establishes this counting interval and ensures it persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

CONF="/etc/security/faillock.conf"
REQUIRED_INTERVAL=900

# Ensure the faillock.conf file exists
if [[ ! -f "$CONF" ]]; then
    touch "$CONF"
    chmod 0644 "$CONF"
    chown root:root "$CONF"
fi

# Determine current fail_interval value if present (uncommented)
current_line="$(grep -Ei '^[[:space:]]*fail_interval[[:space:]]*=' "$CONF" 2>/dev/null | tail -n 1 || true)"

need_update=1
if [[ -n "$current_line" ]]; then
    current_val="$(echo "$current_line" | sed -E 's/^[[:space:]]*fail_interval[[:space:]]*=[[:space:]]*([0-9]+).*/\1/')"
    if [[ "$current_val" =~ ^[0-9]+$ ]] && (( current_val >= REQUIRED_INTERVAL )); then
        need_update=0
    fi
fi

if (( need_update == 1 )); then
    # Remove any existing fail_interval lines (commented or uncommented)
    sed -i -E '/^[[:space:]]*#?[[:space:]]*fail_interval[[:space:]]*=.*/d' "$CONF"
    # Append the correct setting
    printf 'fail_interval = %s\n' "$REQUIRED_INTERVAL" >> "$CONF"
fi

# Ensure faillock is enabled in PAM via pam-auth-update mechanism if available
if command -v pam-auth-update >/dev/null 2>&1; then
    pam-auth-update --enable faillock >/dev/null 2>&1 || true
fi

# Verify final state
final_val="$(grep -Ei '^[[:space:]]*fail_interval[[:space:]]*=' "$CONF" | tail -n 1 | sed -E 's/^[[:space:]]*fail_interval[[:space:]]*=[[:space:]]*([0-9]+).*/\1/')"
if [[ "$final_val" =~ ^[0-9]+$ ]] && (( final_val >= REQUIRED_INTERVAL )); then
    echo "fail_interval is set to ${final_val} seconds in ${CONF}"
    exit 0
else
    echo "Failed to configure fail_interval in ${CONF}" >&2
    exit 1
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_accounts_passwords_pam_faillock_fail_interval='
```


---

## RHEL-08-020019 — `accounts_passwords_pam_faillock_silent`

**Prompt:** On an Ubuntu 24.04 system, the account lockout mechanism that tracks failed authentication attempts must be configured to suppress any informational feedback shown to the user during the lockout/failure-counting process. Without suppression, the system reveals different behavior for existing versus non-existing accounts, allowing an attacker to enumerate valid usernames. Write an idempotent bash remediation script that ensures the failed-login lockout facility operates without displaying these messages, with the change persisting across reboots and applied consistently across the relevant authentication stacks.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure pam_faillock operates silently (suppress informational
# feedback) to prevent username enumeration on Ubuntu 24.04.
#
# This configures the "silent" option for pam_faillock via faillock.conf
# and ensures the option is not overridden in the PAM common-auth /
# common-account stacks.

set -euo pipefail

FAILLOCK_CONF="/etc/security/faillock.conf"
PAM_AUTH="/etc/pam.d/common-auth"
PAM_ACCOUNT="/etc/pam.d/common-account"

#-----------------------------------------------------------------------
# 1. Ensure /etc/security/faillock.conf exists and contains "silent"
#-----------------------------------------------------------------------
if [[ ! -f "$FAILLOCK_CONF" ]]; then
    touch "$FAILLOCK_CONF"
    chmod 0644 "$FAILLOCK_CONF"
    chown root:root "$FAILLOCK_CONF"
fi

# Match an uncommented "silent" directive (possibly with leading whitespace)
if grep -Eq '^[[:space:]]*silent([[:space:]]*(#.*)?)?$' "$FAILLOCK_CONF"; then
    # Already present and active; normalize any leading whitespace/comment forms.
    sed -ri 's|^[[:space:]]*silent([[:space:]]*(#.*)?)?$|silent|' "$FAILLOCK_CONF"
elif grep -Eq '^[[:space:]]*#[[:space:]]*silent' "$FAILLOCK_CONF"; then
    # Uncomment an existing commented-out entry.
    sed -ri 's|^[[:space:]]*#[[:space:]]*silent.*$|silent|' "$FAILLOCK_CONF"
else
    # Append a new entry.
    printf '\nsilent\n' >> "$FAILLOCK_CONF"
fi

#-----------------------------------------------------------------------
# 2. Ensure pam_faillock lines in the PAM stacks also carry "silent"
#    (in case options are specified inline rather than via faillock.conf).
#-----------------------------------------------------------------------
add_silent_to_pam() {
    local file="$1"
    [[ -f "$file" ]] || return 0

    # For each line that references pam_faillock and lacks the "silent"
    # option, append it. Skip commented lines.
    while IFS= read -r line; do
        :
    done < "$file"

    # Use awk for safe idempotent in-place editing.
    local tmp
    tmp="$(mktemp)"
    awk '
        # Only touch active (non-comment) pam_faillock lines.
        /pam_faillock\.so/ && $0 !~ /^[[:space:]]*#/ {
            if ($0 !~ /(^|[[:space:]])silent([[:space:]]|$)/) {
                $0 = $0 " silent"
            }
        }
        { print }
    ' "$file" > "$tmp"

    if ! cmp -s "$file" "$tmp"; then
        cat "$tmp" > "$file"
    fi
    rm -f "$tmp"
}

add_silent_to_pam "$PAM_AUTH"
add_silent_to_pam "$PAM_ACCOUNT"

echo "pam_faillock 'silent' option ensured in ${FAILLOCK_CONF} and PAM stacks."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

if [ -f /usr/bin/authselect ]; then
    if ! authselect check; then
echo "
authselect integrity check failed. Remediation aborted!
This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
It is not recommended to manually edit the PAM files when authselect tool is available.
In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
exit 1
fi
authselect enable-feature with-faillock

authselect apply-changes -b
else
    
AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-au
```


---

## RHEL-08-020015 — `accounts_passwords_pam_faillock_unlock_time`

**Prompt:** On an Ubuntu 24.04 system, configure the account-lockout policy so that after a series of consecutive failed authentication attempts a user account becomes locked and remains locked for a defined period before automatically becoming available again. This mitigates password brute-forcing by limiting the rate at which guesses can be made. The automatic unlock interval must be set to 900 seconds (or greater); a value of zero (requiring manual administrator unlock) is not compliant. Write an idempotent bash remediation script that enforces this lockout behavior across reboots and integrates correctly with the system's authentication stack.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Configure account lockout policy on Ubuntu 24.04 using pam_faillock.
# - Lock account after N consecutive failed attempts
# - Automatically unlock after unlock_time seconds (>= 900)
#
set -euo pipefail

DENY=5
UNLOCK_TIME=900
FAIL_INTERVAL=900

FAILLOCK_CONF="/etc/security/faillock.conf"
PAM_AUTH="/etc/pam.d/common-auth"
PAM_ACCOUNT="/etc/pam.d/common-account"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

timestamp() { date +%Y%m%d%H%M%S; }

backup_file() {
    local f="$1"
    if [[ -f "$f" && ! -f "${f}.bak.orig" ]]; then
        cp -p "$f" "${f}.bak.orig"
    fi
}

set_faillock_option() {
    # set_faillock_option <key> <value>
    local key="$1"
    local value="$2"
    local line="${key} = ${value}"

    if [[ ! -f "$FAILLOCK_CONF" ]]; then
        touch "$FAILLOCK_CONF"
    fi

    if grep -Eq "^[[:space:]]*#?[[:space:]]*${key}([[:space:]]*=.*)?[[:space:]]*$" "$FAILLOCK_CONF"; then
        sed -i -E "s|^[[:space:]]*#?[[:space:]]*${key}([[:space:]]*=.*)?[[:space:]]*$|${line}|" "$FAILLOCK_CONF"
    else
        printf '%s\n' "$line" >> "$FAILLOCK_CONF"
    fi
}

# ---------------------------------------------------------------------------
# 1. Configure /etc/security/faillock.conf
# ---------------------------------------------------------------------------
backup_file "$FAILLOCK_CONF"

set_faillock_option "deny" "$DENY"
set_faillock_option "unlock_time" "$UNLOCK_TIME"
set_faillock_option "fail_interval" "$FAIL_INTERVAL"

# ---------------------------------------------------------------------------
# 2. Ensure pam_faillock is referenced in common-auth
# ---------------------------------------------------------------------------
backup_file "$PAM_AUTH"

if ! grep -Eq "pam_faillock\.so[[:space:]]+preauth" "$PAM_AUTH"; then
    # Insert preauth line before the first auth pam_unix.so line
    awk '
        BEGIN { inserted=0 }
        {
            if (!inserted && $1=="auth" && $0 ~ /pam_unix\.so/) {
                print "auth\trequired\t\t\tpam_faillock.so preauth"
                inserted=1
            }
            print $0
        }
        END {
            if (!inserted) {
                print "auth\trequired\t\t\tpam_faillock.so preauth"
            }
        }
    ' "$PAM_AUTH" > "${PAM_AUTH}.tmp"
    mv "${PAM_AUTH}.tmp" "$PAM_AUTH"
fi

if ! grep -Eq "pam_faillock\.so[[:space:]]+authfail" "$PAM_AUTH"; then
    # Insert authfail and authsucc lines after the last auth pam_unix.so line
    awk '
        {
            lines[NR]=$0
            if ($1=="auth" && $0 ~ /pam_unix\.so/) { last_unix=NR }
        }
        END {
            for (i=1;i<=NR;i++) {
                print lines[i]
                if (i==last_unix) {
                    print "auth\t[default=die]\t\t\tpam_faillock.so authfail"
                    print "auth\tsufficient\t\t\tpam_faillock.so authsucc"
                }
            }
        }
    ' "$PAM_AUTH" > "${PAM_AUTH}.tmp"
    mv "${PAM_AUTH}.tmp" "$PAM_AUTH"
fi

# ---------------------------------------------------------------------------
# 3. Ensure pam_faillock account entry in common-account
# ---------------------------------------------------------------------------
backup_file "$PAM_ACCOUNT"

if ! grep -Eq "^account[[:space:]]+required[[:space:]]+pam_faillock\.so" "$PAM_ACCOUNT"; then
    printf 'account\trequired\t\t\tpam_faillock.so\n' >> "$PAM_ACCOUNT"
fi

echo "Account lockout policy configured:"
echo "  deny         = ${DENY}"
echo "  unlock_time  = ${UNLOCK_TIME}"
echo "  fail_interval= ${FAIL_INTERVAL}"
echo "Changes are persistent across reboots via PAM configuration."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_accounts_passwords_pam_faillock_unlock_time='
```


---

## RHEL-08-020130 — `accounts_password_pam_dcredit`

**Prompt:** On an Ubuntu 24.04 system, strengthen the system-wide password-quality policy so that every newly set or changed password is required to contain at least one numeric digit, increasing resistance to guessing and brute-force attacks by enlarging the password search space. Write an idempotent bash remediation script that enforces this minimum-digit requirement persistently for password creation and changes.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: enforce at least one numeric digit in new/changed passwords
# via pwquality (dcredit = -1) on Ubuntu 24.04. Idempotent.
#
set -euo pipefail

CONFIG_FILE="/etc/security/pwquality.conf"
PARAM="dcredit"
VALUE="-1"

# Ensure the configuration file exists
if [[ ! -f "$CONFIG_FILE" ]]; then
    touch "$CONFIG_FILE"
    chmod 0644 "$CONFIG_FILE"
    chown root:root "$CONFIG_FILE"
fi

# Regex matching any (possibly commented) dcredit line
LINE_REGEX='^[[:space:]]*#?[[:space:]]*dcredit[[:space:]]*='
DESIRED_LINE="${PARAM} = ${VALUE}"

if grep -Eq "$LINE_REGEX" "$CONFIG_FILE"; then
    # Check whether an active, correct setting already exists
    if grep -Eq "^[[:space:]]*${PARAM}[[:space:]]*=[[:space:]]*${VALUE}[[:space:]]*$" "$CONFIG_FILE"; then
        echo "Password quality policy already enforces at least one digit (${DESIRED_LINE})."
    else
        # Replace the first matching line, comment out any others
        awk -v desired="$DESIRED_LINE" '
            BEGIN { replaced = 0 }
            /^[[:space:]]*#?[[:space:]]*dcredit[[:space:]]*=/ {
                if (replaced == 0) {
                    print desired
                    replaced = 1
                } else {
                    # comment out duplicate settings
                    if ($0 !~ /^[[:space:]]*#/) {
                        print "#" $0
                    } else {
                        print $0
                    }
                }
                next
            }
            { print }
        ' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp"
        mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
        chmod 0644 "$CONFIG_FILE"
        chown root:root "$CONFIG_FILE"
        echo "Updated password quality policy: ${DESIRED_LINE}."
    fi
else
    # Append the setting
    printf '%s\n' "$DESIRED_LINE" >> "$CONFIG_FILE"
    echo "Added password quality policy: ${DESIRED_LINE}."
fi

# Verify final state
if grep -Eq "^[[:space:]]*${PARAM}[[:space:]]*=[[:space:]]*${VALUE}[[:space:]]*$" "$CONFIG_FILE"; then
    echo "Verification succeeded: ${DESIRED_LINE} is active in ${CONFIG_FILE}."
    exit 0
else
    echo "Verification failed: unable to enforce ${DESIRED_LINE} in ${CONFIG_FILE}." >&2
    exit 1
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_password_pam_dcredit='
```


---

## RHEL-08-020300 — `accounts_password_pam_dictcheck`

**Prompt:** On an Ubuntu 24.04 system, strengthen the system's password-quality enforcement so that newly set passwords are rejected if they are based on dictionary words, since such passwords are far more susceptible to guessing and brute-force attacks. Configure the system's password-quality policy (enforced via PAM) to perform dictionary-word checking on all new passwords. Write an idempotent bash remediation script that applies this requirement persistently.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Enforce dictionary-word checking on all new passwords via
# pam_pwquality (pwquality.conf). Sets dictcheck = 1 idempotently.
#
set -euo pipefail

CONF="/etc/security/pwquality.conf"
PARAM="dictcheck"
VALUE="1"

# Ensure the pwquality library / PAM module is present.
if ! dpkg -s libpam-pwquality >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y libpam-pwquality
fi

# Ensure the configuration file exists.
if [ ! -f "$CONF" ]; then
    mkdir -p "$(dirname "$CONF")"
    touch "$CONF"
fi

# Apply the dictcheck setting idempotently.
# Match commented or uncommented, whitespace-tolerant lines.
if grep -Eq "^[[:space:]]*#?[[:space:]]*${PARAM}[[:space:]]*=" "$CONF"; then
    sed -ri "s|^[[:space:]]*#?[[:space:]]*${PARAM}[[:space:]]*=.*|${PARAM} = ${VALUE}|" "$CONF"
else
    printf '%s = %s\n' "$PARAM" "$VALUE" >> "$CONF"
fi

# Verify result.
if grep -Eq "^[[:space:]]*${PARAM}[[:space:]]*=[[:space:]]*${VALUE}[[:space:]]*$" "$CONF"; then
    echo "Successfully configured: ${PARAM} = ${VALUE} in ${CONF}"
else
    echo "Failed to configure ${PARAM} in ${CONF}" >&2
    exit 1
fi

# Ensure the common-password PAM stack references pwquality so the setting
# is actually enforced (Ubuntu enables this by default with the package).
PAM_FILE="/etc/pam.d/common-password"
if [ -f "$PAM_FILE" ]; then
    if ! grep -Eq "pam_pwquality\.so" "$PAM_FILE"; then
        echo "Warning: pam_pwquality.so not found in ${PAM_FILE}." >&2
        echo "Adding pam_pwquality.so to enforce password quality." >&2
        # Insert a pwquality line before the first password pam_unix line.
        if grep -Eq "^password[[:space:]]+.*pam_unix\.so" "$PAM_FILE"; then
            sed -ri "0,/^password[[:space:]]+.*pam_unix\.so/{s|^(password[[:space:]]+.*pam_unix\.so.*)|password\trequisite\t\t\tpam_pwquality.so retry=3\n\1|}" "$PAM_FILE"
        else
            printf 'password\trequisite\t\t\tpam_pwquality.so retry=3\n' >> "$PAM_FILE"
        fi
    fi
fi

echo "Dictionary-word password checking is now enforced."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_password_pam_dictcheck='
```


---

## RHEL-08-020170 — `accounts_password_pam_difok`

**Prompt:** On an Ubuntu 24.04 system, strengthen the system password-quality policy so that whenever a user changes their password, the new password must differ from the previous one by at least 8 characters that were not present in the old password. This makes newly chosen passwords less likely to resemble previously compromised ones and increases resistance to guessing. Write an idempotent bash remediation script that enforces this minimum-different-characters requirement for password changes system-wide, persisting across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

CONF_DIR="/etc/security/pwquality.conf.d"
CONF_FILE="${CONF_DIR}/50-difok.conf"
MAIN_CONF="/etc/security/pwquality.conf"
KEY="difok"
VALUE="8"

mkdir -p "$CONF_DIR"

# Remove any existing difok settings from the main config to avoid conflicts
if [ -f "$MAIN_CONF" ]; then
    sed -i -E "/^[[:space:]]*#?[[:space:]]*${KEY}[[:space:]]*=/d" "$MAIN_CONF"
fi

# Remove stray difok settings from other drop-in files
if [ -d "$CONF_DIR" ]; then
    for f in "$CONF_DIR"/*.conf; do
        [ -e "$f" ] || continue
        [ "$f" = "$CONF_FILE" ] && continue
        sed -i -E "/^[[:space:]]*#?[[:space:]]*${KEY}[[:space:]]*=/d" "$f"
    done
fi

# Write the authoritative drop-in config
if [ -f "$CONF_FILE" ] && grep -qE "^[[:space:]]*${KEY}[[:space:]]*=[[:space:]]*${VALUE}[[:space:]]*$" "$CONF_FILE"; then
    if ! grep -qvE "^[[:space:]]*(#.*)?$|^[[:space:]]*${KEY}[[:space:]]*=" "$CONF_FILE"; then
        :
    fi
fi

cat > "$CONF_FILE" <<EOF
${KEY} = ${VALUE}
EOF

chmod 0644 "$CONF_FILE"
chown root:root "$CONF_FILE"

echo "pam_pwquality difok policy set to ${VALUE} in ${CONF_FILE}"
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_password_pam_difok='
```


---

## RHEL-08-020120 — `accounts_password_pam_lcredit`

**Prompt:** On an Ubuntu 24.04 system, strengthen the system-wide password quality policy so that every newly set password is required to contain at least one lowercase alphabetic character, increasing the search space against guessing and brute-force attacks. Write an idempotent bash remediation script that enforces this lowercase-character requirement persistently for password creation and changes.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Enforce a system-wide password quality policy requiring at least one
# lowercase alphabetic character in every newly set password.
#
# Idempotent remediation for Ubuntu 24.04 using pam_pwquality (pwquality.conf).
#
set -euo pipefail

CONF_FILE="/etc/security/pwquality.conf"
PARAM="lcredit"
VALUE="-1"

# Must run as root to modify system configuration.
if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

# Ensure the libpam-pwquality package (providing pwquality.conf) is installed.
if ! dpkg-query -W -f='${Status}' libpam-pwquality 2>/dev/null | grep -q "install ok installed"; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y libpam-pwquality
fi

# Ensure the configuration file exists.
if [[ ! -f "$CONF_FILE" ]]; then
    touch "$CONF_FILE"
    chmod 0644 "$CONF_FILE"
fi

# Idempotently set lcredit = -1 (require at least one lowercase character).
# Match active or commented lines for the parameter and normalize them.
if grep -Eq '^[[:space:]]*#?[[:space:]]*lcredit[[:space:]]*=' "$CONF_FILE"; then
    sed -ri "s|^[[:space:]]*#?[[:space:]]*${PARAM}[[:space:]]*=.*|${PARAM} = ${VALUE}|" "$CONF_FILE"
else
    printf '%s = %s\n' "$PARAM" "$VALUE" >> "$CONF_FILE"
fi

# Verify the resulting configuration.
if grep -Eq "^[[:space:]]*${PARAM}[[:space:]]*=[[:space:]]*${VALUE}[[:space:]]*$" "$CONF_FILE"; then
    echo "SUCCESS: '${PARAM} = ${VALUE}' is enforced in ${CONF_FILE}."
else
    echo "ERROR: Failed to enforce '${PARAM} = ${VALUE}' in ${CONF_FILE}." >&2
    exit 1
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_password_pam_lcredit='
```


---

## RHEL-08-020140 — `accounts_password_pam_maxclassrepeat`

**Prompt:** On an Ubuntu 24.04 system, strengthen the system-wide password-quality policy so that newly set passwords are rejected when they contain too many consecutive characters drawn from the same character class (for example uppercase letters, lowercase letters, digits, or symbols), since long runs of similar characters make passwords easier to guess. Configure the password-quality enforcement so that no more than 4 consecutive characters from the same character class are permitted (i.e. a run of 5 or more from one class is rejected). Write an idempotent bash remediation script that applies this requirement persistently.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

CONF="/etc/security/pwquality.conf"
KEY="maxclassrepeat"
VALUE="4"

# Ensure the pwquality configuration file exists
if [ ! -f "$CONF" ]; then
    touch "$CONF"
    chmod 0644 "$CONF"
fi

# Idempotently set the maxclassrepeat directive
if grep -Eq "^[[:space:]]*#?[[:space:]]*${KEY}[[:space:]]*=" "$CONF"; then
    sed -ri "s|^[[:space:]]*#?[[:space:]]*${KEY}[[:space:]]*=.*|${KEY} = ${VALUE}|" "$CONF"
else
    printf '%s = %s\n' "$KEY" "$VALUE" >> "$CONF"
fi

# Verify the setting
if grep -Eq "^[[:space:]]*${KEY}[[:space:]]*=[[:space:]]*${VALUE}[[:space:]]*$" "$CONF"; then
    echo "Successfully set ${KEY} = ${VALUE} in ${CONF}"
else
    echo "Failed to set ${KEY} in ${CONF}" >&2
    exit 1
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_password_pam_maxclassrepeat='
```


---

## RHEL-08-020150 — `accounts_password_pam_maxrepeat`

**Prompt:** On an Ubuntu 24.04 system, strengthen the system-wide password quality policy so that when users set or change a password, the password is rejected if it contains more than three consecutive identical characters (i.e. no run of four or more of the same character is allowed). This limits weak, easily guessed passwords and increases resistance to brute-force attacks. Write an idempotent bash remediation script that enforces this constraint persistently for all password changes.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

CONF="/etc/security/pwquality.conf"
PARAM="maxrepeat"
VALUE="3"

# Ensure the configuration file exists
if [ ! -f "$CONF" ]; then
    mkdir -p "$(dirname "$CONF")"
    touch "$CONF"
fi

# Idempotently set the maxrepeat parameter
if grep -Eq "^\s*#?\s*${PARAM}\s*=" "$CONF"; then
    sed -ri "s|^\s*#?\s*${PARAM}\s*=.*|${PARAM} = ${VALUE}|" "$CONF"
else
    printf '%s = %s\n' "$PARAM" "$VALUE" >> "$CONF"
fi

# Verify the setting
if grep -Eq "^\s*${PARAM}\s*=\s*${VALUE}\s*$" "$CONF"; then
    echo "Successfully set '${PARAM} = ${VALUE}' in ${CONF}"
else
    echo "Failed to set '${PARAM}' in ${CONF}" >&2
    exit 1
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_password_pam_maxrepeat='
```


---

## RHEL-08-020160 — `accounts_password_pam_minclass`

**Prompt:** On an Ubuntu 24.04 system, strengthen the system-wide password-quality policy so that any newly set or changed password must contain characters drawn from at least four distinct character categories (uppercase letters, lowercase letters, digits, and special characters), making passwords substantially more resistant to guessing and brute-force attacks. Write an idempotent bash remediation script that enforces this minimum-character-class requirement persistently.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

CONFIG_FILE="/etc/security/pwquality.conf"
PARAM="minclass"
VALUE="4"

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# Ensure the pwquality configuration file exists
if [ ! -f "$CONFIG_FILE" ]; then
    mkdir -p "$(dirname "$CONFIG_FILE")"
    touch "$CONFIG_FILE"
fi

# Remove any existing (including commented) minclass lines, then set the desired value
if grep -Eq '^[[:space:]]*#?[[:space:]]*minclass[[:space:]]*=' "$CONFIG_FILE"; then
    sed -i -E "s|^[[:space:]]*#?[[:space:]]*minclass[[:space:]]*=.*|${PARAM} = ${VALUE}|" "$CONFIG_FILE"
else
    echo "${PARAM} = ${VALUE}" >> "$CONFIG_FILE"
fi

# Collapse to a single authoritative line in case of duplicates
tmpfile="$(mktemp)"
seen=0
while IFS= read -r line; do
    if echo "$line" | grep -Eq '^[[:space:]]*minclass[[:space:]]*='; then
        if [ "$seen" -eq 0 ]; then
            echo "${PARAM} = ${VALUE}"
            seen=1
        fi
    else
        echo "$line"
    fi
done < "$CONFIG_FILE" > "$tmpfile"

if [ "$seen" -eq 0 ]; then
    echo "${PARAM} = ${VALUE}" >> "$tmpfile"
fi

cat "$tmpfile" > "$CONFIG_FILE"
rm -f "$tmpfile"

chmod 0644 "$CONFIG_FILE"
chown root:root "$CONFIG_FILE"

echo "Password quality policy updated: ${PARAM} = ${VALUE} enforced in ${CONFIG_FILE}"
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_password_pam_minclass='
```


---

## RHEL-08-020230 — `accounts_password_pam_minlen`

**Prompt:** On an Ubuntu 24.04 system, strengthen password policy by configuring the system's password-quality enforcement so that any newly set or changed password must be at least 15 characters long, increasing resistance to guessing and brute-force attacks. Write an idempotent bash remediation script that enforces this minimum password length and persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

CONF_FILE="/etc/security/pwquality.conf"
MIN_LEN=15

# Ensure the pwquality configuration file exists
if [[ ! -f "$CONF_FILE" ]]; then
    mkdir -p "$(dirname "$CONF_FILE")"
    touch "$CONF_FILE"
fi

# Back up the file once
if [[ ! -f "${CONF_FILE}.bak" ]]; then
    cp -p "$CONF_FILE" "${CONF_FILE}.bak"
fi

# Idempotently set minlen in pwquality.conf
if grep -Eq '^\s*#?\s*minlen\s*=' "$CONF_FILE"; then
    sed -i -E "s|^\s*#?\s*minlen\s*=.*|minlen = ${MIN_LEN}|" "$CONF_FILE"
else
    echo "minlen = ${MIN_LEN}" >> "$CONF_FILE"
fi

# Verify the change
if grep -Eq "^\s*minlen\s*=\s*${MIN_LEN}\s*$" "$CONF_FILE"; then
    echo "Password minimum length successfully set to ${MIN_LEN} in ${CONF_FILE}."
else
    echo "ERROR: Failed to set minimum password length." >&2
    exit 1
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_password_pam_minlen='
```


---

## RHEL-08-020280 — `accounts_password_pam_ocredit`

**Prompt:** On an Ubuntu 24.04 system, strengthen the password-quality policy enforced by the system's PAM password-complexity module so that every newly set password is required to contain at least one special (non-alphanumeric) character, increasing resistance to guessing and brute-force attacks. Write an idempotent bash remediation script that configures this minimum special-character requirement persistently so it applies to all future password changes.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: enforce at least one special (non-alphanumeric) character in
# every newly set password via the PAM pwquality module (pam_pwquality).
#
# This is achieved by setting "ocredit = -1" in /etc/security/pwquality.conf,
# which requires a minimum of one "other" (special) character.
#
# The script is idempotent: repeated runs converge to the same desired state.

set -euo pipefail

CONF_FILE="/etc/security/pwquality.conf"
PARAM="ocredit"
DESIRED_VALUE="-1"

# Ensure we are running with sufficient privileges.
if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

# Ensure the libpam-pwquality package (which provides pam_pwquality and the
# pwquality.conf file) is installed.
if ! dpkg-query -W -f='${Status}' libpam-pwquality 2>/dev/null | grep -q "install ok installed"; then
    echo "Installing libpam-pwquality ..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y libpam-pwquality
fi

# Ensure the configuration file exists.
if [[ ! -f "$CONF_FILE" ]]; then
    touch "$CONF_FILE"
    chmod 0644 "$CONF_FILE"
fi

# Regex matching any (commented or uncommented) definition of the parameter.
# Matches optional leading whitespace, optional '#', whitespace, the key,
# optional whitespace, '=', optional whitespace, and a value.
MATCH_REGEX="^[[:space:]]*#?[[:space:]]*${PARAM}[[:space:]]*="
DESIRED_LINE="${PARAM} = ${DESIRED_VALUE}"

if grep -Eq "$MATCH_REGEX" "$CONF_FILE"; then
    # Replace the first matching line and remove any additional matches to
    # guarantee a single authoritative entry.
    tmp_file="$(mktemp)"
    replaced=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" =~ ^[[:space:]]*#?[[:space:]]*${PARAM}[[:space:]]*= ]]; then
            if [[ "$replaced" -eq 0 ]]; then
                printf '%s\n' "$DESIRED_LINE" >> "$tmp_file"
                replaced=1
            fi
            # Skip any further matching lines (duplicates/commented versions).
        else
            printf '%s\n' "$line" >> "$tmp_file"
        fi
    done < "$CONF_FILE"

    cat "$tmp_file" > "$CONF_FILE"
    rm -f "$tmp_file"
else
    # No existing entry; append the desired setting.
    printf '%s\n' "$DESIRED_LINE" >> "$CONF_FILE"
fi

# Ensure secure permissions/ownership on the configuration file.
chown root:root "$CONF_FILE"
chmod 0644 "$CONF_FILE"

# Verify the final state.
if grep -Eq "^[[:space:]]*${PARAM}[[:space:]]*=[[:space:]]*${DESIRED_VALUE}[[:space:]]*$" "$CONF_FILE"; then
    echo "SUCCESS: '${PARAM} = ${DESIRED_VALUE}' is set in ${CONF_FILE}."
    echo "Passwords now require at least one special (non-alphanumeric) character."
else
    echo "ERROR: Failed to apply '${PARAM} = ${DESIRED_VALUE}' in ${CONF_FILE}." >&2
    exit 1
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_password_pam_ocredit='
```


---

## RHEL-08-020110 — `accounts_password_pam_ucredit`

**Prompt:** On an Ubuntu 24.04 system, strengthen the system password-quality policy so that every newly set password is required to contain at least one uppercase alphabetic character, raising the cost of guessing and brute-force attacks. The requirement must be enforced through the system's password-quality (PAM-based) mechanism. Write an idempotent bash remediation script that configures this requirement so it persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

CONF="/etc/security/pwquality.conf"
SETTING="ucredit"
VALUE="-1"

# Ensure libpam-pwquality is installed
if ! dpkg -s libpam-pwquality >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y libpam-pwquality
fi

# Ensure the configuration file exists
if [ ! -f "$CONF" ]; then
    touch "$CONF"
    chmod 0644 "$CONF"
fi

# Idempotently set ucredit = -1 (require at least one uppercase character)
if grep -Eq "^[[:space:]]*#?[[:space:]]*${SETTING}[[:space:]]*=" "$CONF"; then
    sed -ri "s|^[[:space:]]*#?[[:space:]]*${SETTING}[[:space:]]*=.*|${SETTING} = ${VALUE}|" "$CONF"
else
    printf '%s = %s\n' "$SETTING" "$VALUE" >> "$CONF"
fi

# Verify the result
if grep -Eq "^[[:space:]]*${SETTING}[[:space:]]*=[[:space:]]*${VALUE}[[:space:]]*$" "$CONF"; then
    echo "Password-quality policy updated: passwords must contain at least one uppercase character."
else
    echo "Failed to apply ${SETTING} = ${VALUE} in ${CONF}" >&2
    exit 1
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_password_pam_ucredit='
```


---

## RHEL-08-010130 — `set_password_hashing_min_rounds_logindefs`

**Prompt:** On an Ubuntu 24.04 system, the strength of stored SHA-based password hashes depends on the number of hashing rounds used; too few rounds makes offline password-cracking attacks easier. Configure the system-wide user-account/password policy so that the SHA password-hashing algorithm uses a minimum of 5000 hashing rounds (both the lower and upper round bounds, where configured, must be no less than 5000). Write an idempotent bash remediation script that enforces this setting persistently.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

MIN_ROUNDS=5000
CONF="/etc/login.defs"

if [[ ! -f "$CONF" ]]; then
    touch "$CONF"
fi

set_login_defs() {
    local key="$1"
    local val="$2"
    local file="$3"

    if grep -Eq "^[[:space:]]*${key}[[:space:]]+" "$file"; then
        local current
        current=$(grep -E "^[[:space:]]*${key}[[:space:]]+" "$file" | tail -n1 | awk '{print $2}')
        if [[ ! "$current" =~ ^[0-9]+$ ]] || [[ "$current" -lt "$MIN_ROUNDS" ]]; then
            sed -i -E "s|^[[:space:]]*${key}[[:space:]]+.*|${key} ${val}|" "$file"
        else
            sed -i -E "s|^[[:space:]]*${key}[[:space:]]+.*|${key} ${current}|" "$file"
        fi
    else
        printf '%s %s\n' "$key" "$val" >> "$file"
    fi
}

set_login_defs "SHA_CRYPT_MIN_ROUNDS" "$MIN_ROUNDS" "$CONF"
set_login_defs "SHA_CRYPT_MAX_ROUNDS" "$MIN_ROUNDS" "$CONF"

# Ensure PAM uses rounds too, where configured (idempotent)
for PAM_FILE in /etc/pam.d/common-password; do
    [[ -f "$PAM_FILE" ]] || continue
    if grep -Eq '^\s*password\s+.*pam_unix\.so' "$PAM_FILE"; then
        while IFS= read -r lineno; do
            line=$(sed -n "${lineno}p" "$PAM_FILE")
            if echo "$line" | grep -Eq 'rounds='; then
                current=$(echo "$line" | grep -oE 'rounds=[0-9]+' | head -n1 | cut -d= -f2)
                if [[ ! "$current" =~ ^[0-9]+$ ]] || [[ "$current" -lt "$MIN_ROUNDS" ]]; then
                    newline=$(echo "$line" | sed -E "s/rounds=[0-9]+/rounds=${MIN_ROUNDS}/")
                    sed -i "${lineno}s|.*|${newline}|" "$PAM_FILE"
                fi
            else
                newline=$(echo "$line" | sed -E "s|(pam_unix\.so)|\1 rounds=${MIN_ROUNDS}|")
                sed -i "${lineno}s|.*|${newline}|" "$PAM_FILE"
            fi
        done < <(grep -nE '^\s*password\s+.*pam_unix\.so' "$PAM_FILE" | cut -d: -f1)
    fi
done

echo "SHA password hashing rounds configured to a minimum of ${MIN_ROUNDS}."
```

**Reference fix:**
```bash
var_password_hashing_min_rounds_login_defs='
```


---

## RHEL-08-040180 — `service_debug-shell_disabled`

**Prompt:** On an Ubuntu 24.04 system, the systemd debug-shell service can provide an unauthenticated root shell on a virtual console after reboot, allowing anyone with physical access to trivially gain root. Write an idempotent bash remediation script that ensures this diagnostic root-shell service is fully disabled and cannot be started, with the change persisting across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemctl not found; systemd is required." >&2
    exit 1
fi

UNIT="debug-shell.service"
changed=0

echo "==> Remediating ${UNIT}"

# Stop the service if it is currently running.
if systemctl is-active --quiet "${UNIT}"; then
    echo "  - Stopping ${UNIT}"
    systemctl stop "${UNIT}" || true
    changed=1
else
    echo "  - ${UNIT} is not active"
fi

# Disable the service so it does not start on boot.
if systemctl is-enabled --quiet "${UNIT}" 2>/dev/null; then
    echo "  - Disabling ${UNIT}"
    systemctl disable "${UNIT}" || true
    changed=1
else
    echo "  - ${UNIT} is not enabled"
fi

# Mask the service so it cannot be started manually or by dependency.
mask_state="$(systemctl is-enabled "${UNIT}" 2>/dev/null || true)"
if [[ "${mask_state}" != "masked" ]]; then
    echo "  - Masking ${UNIT}"
    systemctl mask "${UNIT}" || true
    changed=1
else
    echo "  - ${UNIT} is already masked"
fi

# Reload systemd to ensure state is consistent.
systemctl daemon-reload || true

echo "==> Verifying state"
final_state="$(systemctl is-enabled "${UNIT}" 2>/dev/null || true)"
active_state="$(systemctl is-active "${UNIT}" 2>/dev/null || true)"

echo "  - is-enabled: ${final_state:-unknown}"
echo "  - is-active:  ${active_state:-unknown}"

if [[ "${final_state}" != "masked" ]]; then
    echo "ERROR: ${UNIT} is not masked as expected." >&2
    exit 1
fi

if [[ "${active_state}" == "active" ]]; then
    echo "ERROR: ${UNIT} is still active." >&2
    exit 1
fi

if [[ "${changed}" -eq 1 ]]; then
    echo "==> Remediation applied successfully."
else
    echo "==> System already compliant; no changes needed."
fi

exit 0
```

**Reference fix:**
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

## RHEL-08-040172 — `disable_ctrlaltdel_burstaction`

**Prompt:** On an Ubuntu 24.04 system, the init system will reboot the machine if the Ctrl-Alt-Del key sequence is pressed rapidly several times in succession at the console, creating a risk of accidental, unintended reboots and short-term loss of availability. Configure the system manager so that this rapid Ctrl-Alt-Del burst no longer triggers any action (it must be completely disabled). Write an idempotent bash remediation script that enforces this setting and ensures it persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

# On Ubuntu 24.04 (systemd), rapid Ctrl-Alt-Del bursts are handled by
# systemd's "reboot.target" alias via ctrl-alt-del.target. To completely
# disable this behavior, mask ctrl-alt-del.target.

TARGET="ctrl-alt-del.target"

# Idempotently mask the target so the Ctrl-Alt-Del burst triggers no action.
if ! systemctl is-enabled "$TARGET" 2>/dev/null | grep -q '^masked$'; then
    systemctl mask "$TARGET"
fi

# Ensure the mask symlink points to /dev/null (the effect of masking).
LINK="/etc/systemd/system/${TARGET}"
if [ ! -L "$LINK" ] || [ "$(readlink -f "$LINK")" != "/dev/null" ]; then
    ln -sf /dev/null "$LINK"
fi

# Reload systemd so the change takes effect and persists.
systemctl daemon-reload

# Verify the enforcement.
if systemctl is-enabled "$TARGET" 2>/dev/null | grep -q '^masked$'; then
    echo "Ctrl-Alt-Del burst reboot is disabled (${TARGET} is masked)."
else
    echo "Failed to mask ${TARGET}." >&2
    exit 1
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel && { rpm --quiet -q systemd; }; then

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^CtrlAltDelBurstAction=")

# shellcheck disable=SC2059
printf -v formatted_output "%s=%s" "$stripped_key" "none"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^CtrlAltDelBurstAction=\\>" "/etc/systemd/system.conf";
```


---

## RHEL-08-040170 — `disable_ctrlaltdel_reboot`

**Prompt:** On an Ubuntu 24.04 system, the system manager reboots the machine when the Ctrl-Alt-Del key sequence is pressed at the console; an accidental press can cause an unintended reboot and short-term loss of availability. Write an idempotent bash remediation script that disables the reboot reaction to this key sequence in a way that survives system updates and persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# Mask the ctrl-alt-del.target so that the Ctrl-Alt-Del key sequence
# at the console does not trigger a reboot. Masking symlinks the unit
# to /dev/null, which persists across reboots and survives package
# updates (systemd will not overwrite an admin-created mask).

TARGET="ctrl-alt-del.target"
MASK_LINK="/etc/systemd/system/${TARGET}"

# Determine current state of the unit.
current_state="$(systemctl is-enabled "${TARGET}" 2>/dev/null || true)"

if [[ "${current_state}" == "masked" ]]; then
    echo "${TARGET} is already masked. No changes needed."
else
    echo "Masking ${TARGET}..."
    systemctl mask "${TARGET}"
fi

# Verify the mask symlink points to /dev/null (idempotent verification).
if [[ -L "${MASK_LINK}" && "$(readlink -f "${MASK_LINK}")" == "/dev/null" ]]; then
    echo "Verified: ${MASK_LINK} -> /dev/null"
else
    echo "Ensuring ${MASK_LINK} points to /dev/null..."
    ln -sf /dev/null "${MASK_LINK}"
fi

# Reload systemd to apply changes.
systemctl daemon-reload

# Final confirmation.
final_state="$(systemctl is-enabled "${TARGET}" 2>/dev/null || true)"
if [[ "${final_state}" == "masked" ]]; then
    echo "Success: reboot reaction to Ctrl-Alt-Del is disabled."
    exit 0
else
    echo "Error: failed to mask ${TARGET} (state: ${final_state})." >&2
    exit 1
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if [[ "$OSCAP_BOOTC_BUILD" == "YES" ]] ; then
    systemctl disable ctrl-alt-del.target
    systemctl mask ctrl-alt-del.target
else
    systemctl disable --now ctrl-alt-del.target
    systemctl mask --now ctrl-alt-del.target
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```


---

## RHEL-08-020035 — `logind_session_timeout`

**Prompt:** On an Ubuntu 24.04 system, configure the systemd login manager so that user login sessions are automatically terminated after a defined period of inactivity, reducing the window in which an unattended console or management session could be taken over by unauthorized personnel. Choose a reasonable non-zero idle limit and ensure the setting is applied through the login manager's configuration so it persists across reboots. Write an idempotent bash remediation script that enforces this behavior.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

# Configure systemd-logind to terminate idle user sessions.
# Idempotent remediation for Ubuntu 24.04.

CONF_DIR="/etc/systemd/logind.conf.d"
CONF_FILE="${CONF_DIR}/99-idle-timeout.conf"

# Reasonable non-zero idle limit: 15 minutes.
IDLE_ACTION="lock"
IDLE_ACTION_SEC="900"

if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

mkdir -p "${CONF_DIR}"
chmod 0755 "${CONF_DIR}"

TMP_FILE="$(mktemp)"
cat > "${TMP_FILE}" <<EOF
[Login]
IdleAction=${IDLE_ACTION}
IdleActionSec=${IDLE_ACTION_SEC}
EOF

chmod 0644 "${TMP_FILE}"

if [[ -f "${CONF_FILE}" ]] && cmp -s "${TMP_FILE}" "${CONF_FILE}"; then
    echo "Configuration already in desired state: ${CONF_FILE}"
    rm -f "${TMP_FILE}"
else
    mv "${TMP_FILE}" "${CONF_FILE}"
    echo "Applied idle session configuration to ${CONF_FILE}"
    if systemctl is-active --quiet systemd-logind; then
        systemctl restart systemd-logind || echo "Warning: failed to restart systemd-logind; changes apply after reboot." >&2
    fi
fi

echo "Effective settings:"
grep -E '^(IdleAction|IdleActionSec)=' "${CONF_FILE}"
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel && { ( grep -qP "^ID=[\"']?rhel[\"']?$" "/etc/os-release" && { real="$(grep -P "^VERSION_ID=[\"']?[\w.]+[\"']?$" /etc/os-release | sed "s/^VERSION_ID=[\"']\?\([^\"']\+\)[\"']\?$/\1/")"; expected="8.7"; printf "%s\n%s" "$expected" "$real" | sort -VC; } && grep -qP "^ID=[\"']?rhel[\"']?$" "/etc/os-release" && { real="$(grep -P "^VERSION_ID=[\"']?[\w.]+[\"']?$" /etc/os-release | sed "s/^VERSION_ID=[\"']\?\([^\"']\+\)[\"']\?$/\1/")"; expected="9.0"; [[ "$real" != "$expected" ]]; } ) || grep -qP "^ID=[\"']?ol[\"']?$" "/etc/os-release" && { real="$(grep -P "^VERSION_ID=[\"']?[\w.]+[\"']?$" /etc/os-release | sed "s/^VERS
```


---

## RHEL-08-010410 — `package_opensc_installed`

**Prompt:** On an Ubuntu 24.04 system, ensure the software component that provides smart-card support for multifactor authentication (enabling use of hardware tokens such as a CAC or PIV card) is present. Multifactor authentication using a device separate from the system ensures that a compromise of the system does not expose the authentication credentials. Write an idempotent bash remediation script that guarantees this smart-card support tooling is installed on the system.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PACKAGE="libpam-pkcs11"

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root." >&2
    exit 1
fi

if dpkg-query -W -f='${Status}' "$PACKAGE" 2>/dev/null | grep -q "install ok installed"; then
    echo "Package '$PACKAGE' is already installed."
    exit 0
fi

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y "$PACKAGE"

if dpkg-query -W -f='${Status}' "$PACKAGE" 2>/dev/null | grep -q "install ok installed"; then
    echo "Package '$PACKAGE' successfully installed."
else
    echo "Failed to install package '$PACKAGE'." >&2
    exit 1
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if ! rpm -q --quiet "opensc" ; then
    yum install -y "opensc"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```


---

## RHEL-08-020260 — `account_disable_post_pw_expiration`

**Prompt:** On an Ubuntu 24.04 system, ensure that newly created user accounts are automatically and permanently disabled no more than 30 days after their password expires, so that dormant or abandoned accounts cannot be exploited by an attacker who has obtained their credentials. Configure the system-wide default that governs the post-password-expiration inactivity period applied to new accounts. Write an idempotent bash remediation script that establishes this default and persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

FILE="/etc/default/useradd"
INACTIVE_VALUE=30

# Ensure the file exists
if [[ ! -f "$FILE" ]]; then
    touch "$FILE"
    chmod 0644 "$FILE"
fi

# Idempotently set the INACTIVE default in /etc/default/useradd
if grep -qE '^\s*INACTIVE\s*=' "$FILE"; then
    sed -i -E "s|^\s*INACTIVE\s*=.*|INACTIVE=${INACTIVE_VALUE}|" "$FILE"
else
    printf 'INACTIVE=%s\n' "$INACTIVE_VALUE" >> "$FILE"
fi

# Apply via useradd -D to ensure the tool's stored default is consistent
useradd -D -f "$INACTIVE_VALUE"

# Verify
current="$(useradd -D | grep -E '^INACTIVE=' | cut -d= -f2)"
if [[ "$current" != "$INACTIVE_VALUE" ]]; then
    echo "ERROR: Failed to set INACTIVE default to ${INACTIVE_VALUE} (got '${current}')." >&2
    exit 1
fi

echo "Default account inactivity period set to ${INACTIVE_VALUE} days after password expiration."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q shadow-utils; then

var_account_disable_post_pw_expiration='
```


---

## RHEL-08-020200 — `accounts_maximum_age_login_defs`

**Prompt:** On an Ubuntu 24.04 system, configure the system-wide account policy so that newly created user accounts have a maximum password lifetime of 60 days, forcing periodic password changes to limit the window in which a compromised or cracked password remains valid. Write an idempotent bash remediation script that establishes this maximum password age as the default for new accounts and persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

LOGIN_DEFS="/etc/login.defs"
MAX_DAYS=60

# Ensure the file exists
if [[ ! -f "$LOGIN_DEFS" ]]; then
    touch "$LOGIN_DEFS"
    chmod 0644 "$LOGIN_DEFS"
fi

# Idempotently set PASS_MAX_DAYS to 60 in /etc/login.defs
if grep -Eq '^\s*PASS_MAX_DAYS\s+' "$LOGIN_DEFS"; then
    # Replace existing active setting
    sed -i -E "s/^\s*PASS_MAX_DAYS\s+.*/PASS_MAX_DAYS\t${MAX_DAYS}/" "$LOGIN_DEFS"
elif grep -Eq '^\s*#\s*PASS_MAX_DAYS\s+' "$LOGIN_DEFS"; then
    # Uncomment and set commented setting
    sed -i -E "s/^\s*#\s*PASS_MAX_DAYS\s+.*/PASS_MAX_DAYS\t${MAX_DAYS}/" "$LOGIN_DEFS"
else
    # Append the setting
    printf 'PASS_MAX_DAYS\t%s\n' "$MAX_DAYS" >> "$LOGIN_DEFS"
fi

# Verify the result
if grep -Eq "^\s*PASS_MAX_DAYS\s+${MAX_DAYS}\s*$" "$LOGIN_DEFS"; then
    echo "PASS_MAX_DAYS is set to ${MAX_DAYS} in ${LOGIN_DEFS}"
else
    echo "Failed to set PASS_MAX_DAYS in ${LOGIN_DEFS}" >&2
    exit 1
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q shadow-utils; then

var_accounts_maximum_age_login_defs='
```


---

## RHEL-08-020190 — `accounts_minimum_age_login_defs`

**Prompt:** On an Ubuntu 24.04 system, configure the system-wide account policy so that newly created user accounts must wait at least 1 day before their password can be changed again. This prevents users from rapidly cycling through password changes to circumvent password-reuse history controls. Write an idempotent bash remediation script that establishes this minimum password age default for new accounts and persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

LOGIN_DEFS="/etc/login.defs"
MIN_DAYS=1

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

if [[ ! -f "$LOGIN_DEFS" ]]; then
    echo "Error: $LOGIN_DEFS not found." >&2
    exit 1
fi

# Backup once
if [[ ! -f "${LOGIN_DEFS}.orig" ]]; then
    cp -p "$LOGIN_DEFS" "${LOGIN_DEFS}.orig"
fi

if grep -Eq '^\s*PASS_MIN_DAYS\s+' "$LOGIN_DEFS"; then
    sed -i -E "s|^\s*PASS_MIN_DAYS\s+.*|PASS_MIN_DAYS\t${MIN_DAYS}|" "$LOGIN_DEFS"
elif grep -Eq '^\s*#\s*PASS_MIN_DAYS\s+' "$LOGIN_DEFS"; then
    sed -i -E "s|^\s*#\s*PASS_MIN_DAYS\s+.*|PASS_MIN_DAYS\t${MIN_DAYS}|" "$LOGIN_DEFS"
else
    printf 'PASS_MIN_DAYS\t%s\n' "$MIN_DAYS" >> "$LOGIN_DEFS"
fi

# Verify
current="$(grep -E '^\s*PASS_MIN_DAYS\s+' "$LOGIN_DEFS" | awk '{print $2}' | tail -n1)"
if [[ "$current" == "$MIN_DAYS" ]]; then
    echo "PASS_MIN_DAYS set to ${MIN_DAYS} in ${LOGIN_DEFS}."
else
    echo "Error: failed to set PASS_MIN_DAYS." >&2
    exit 1
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q shadow-utils; then

var_accounts_minimum_age_login_defs='
```


---

## RHEL-08-020231 — `accounts_password_minlen_login_defs`

**Prompt:** On an Ubuntu 24.04 system, configure the system-wide account/login policy so that any newly created user password must be at least 15 characters long, enforcing a larger password search space to make offline password-cracking attacks more difficult. Write an idempotent bash remediation script that establishes this minimum password length requirement and persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

CONF_DIR="/etc/security/pwquality.conf.d"
CONF_FILE="${CONF_DIR}/minlen.conf"
MAIN_CONF="/etc/security/pwquality.conf"
MINLEN_VALUE=15

if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# Ensure the pwquality library/module is available
if ! dpkg -s libpam-pwquality >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y libpam-pwquality
fi

# Ensure the drop-in directory exists
mkdir -p "${CONF_DIR}"
chmod 0755 "${CONF_DIR}"

# Write/refresh the drop-in configuration idempotently
DESIRED_CONTENT="# Managed by remediation script: enforce minimum password length
minlen = ${MINLEN_VALUE}"

if [[ ! -f "${CONF_FILE}" ]] || [[ "$(cat "${CONF_FILE}")" != "${DESIRED_CONTENT}" ]]; then
    printf '%s\n' "${DESIRED_CONTENT}" > "${CONF_FILE}"
fi
chmod 0644 "${CONF_FILE}"

# Ensure the main pwquality.conf does not override with a smaller/conflicting value
if [[ -f "${MAIN_CONF}" ]]; then
    if grep -Eq '^[[:space:]]*minlen[[:space:]]*=' "${MAIN_CONF}"; then
        sed -ri "s/^[[:space:]]*minlen[[:space:]]*=.*/minlen = ${MINLEN_VALUE}/" "${MAIN_CONF}"
    fi
fi

# Verify configuration
if grep -Rq "minlen = ${MINLEN_VALUE}" "${CONF_FILE}"; then
    echo "Minimum password length successfully set to ${MINLEN_VALUE}."
else
    echo "Failed to apply minimum password length setting." >&2
    exit 1
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q shadow-utils; then

var_accounts_password_minlen_login_defs='
```


---

## RHEL-08-020210 — `accounts_password_set_max_life_existing`

**Prompt:** On an Ubuntu 24.04 system, ensure that all existing local user accounts are subject to a maximum password lifetime of 365 days, so that passwords cannot remain valid indefinitely and any compromised credential has a bounded useful lifespan. Write an idempotent bash remediation script that brings every non-compliant account into conformance with this maximum password age requirement.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

MAX_DAYS=365

# 1. Set the default for newly created accounts in /etc/login.defs
LOGIN_DEFS="/etc/login.defs"
if [[ -f "$LOGIN_DEFS" ]]; then
    if grep -Eq '^\s*PASS_MAX_DAYS\s+' "$LOGIN_DEFS"; then
        sed -ri "s/^\s*PASS_MAX_DAYS\s+.*/PASS_MAX_DAYS\t${MAX_DAYS}/" "$LOGIN_DEFS"
    else
        printf 'PASS_MAX_DAYS\t%s\n' "$MAX_DAYS" >> "$LOGIN_DEFS"
    fi
else
    printf 'PASS_MAX_DAYS\t%s\n' "$MAX_DAYS" > "$LOGIN_DEFS"
fi

# 2. Bring existing local user accounts into conformance.
# Iterate over accounts defined in /etc/shadow (local accounts).
while IFS=: read -r username _ _ _ maxdays _; do
    # Skip empty usernames
    [[ -z "$username" ]] && continue

    # Determine if the account has a usable/locked password field.
    # We remediate accounts regardless of lock state to bound credential lifespan,
    # but only those that exist in /etc/passwd as real accounts.
    if ! getent passwd "$username" >/dev/null 2>&1; then
        continue
    fi

    # Normalize maxdays: treat empty or non-numeric as needing remediation.
    if [[ ! "$maxdays" =~ ^[0-9]+$ ]] || (( maxdays > MAX_DAYS )); then
        chage --maxdays "$MAX_DAYS" "$username"
        echo "Updated maximum password age for '$username' to ${MAX_DAYS} days."
    fi
done < /etc/shadow

echo "Password maximum age remediation complete."
```

**Reference fix:**
```bash
var_accounts_maximum_age_login_defs='
```


---

## RHEL-08-020180 — `accounts_password_set_min_life_existing`

**Prompt:** On an Ubuntu 24.04 system, enforce a minimum password age of 1 day (24 hours) for all existing local user accounts that currently allow more frequent changes, so that users cannot rapidly cycle through password changes to circumvent password-reuse/history controls. Write an idempotent bash remediation script that brings all non-compliant accounts into conformance with this minimum password lifetime.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Enforce a minimum password age of 1 day for all existing local user accounts.
# Idempotent: only modifies accounts whose current minimum age is < 1 day.
#
set -euo pipefail

MIN_DAYS=1

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

for cmd in chage passwd getent; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: required command '$cmd' not found." >&2
        exit 1
    fi
done

changed=0
checked=0

# Iterate over local accounts defined in /etc/passwd only.
while IFS=: read -r username _ uid _ _ _ _; do
    [[ -z "$username" ]] && continue

    # Only consider accounts that have shadow entries.
    if ! getent shadow "$username" >/dev/null 2>&1; then
        continue
    fi

    checked=$((checked + 1))

    # Field 4 of /etc/shadow is the minimum password age in days.
    shadow_line="$(getent shadow "$username")"
    current_min="$(echo "$shadow_line" | awk -F: '{print $4}')"

    # Treat empty/unset minimum age as 0 (allows immediate changes).
    if [[ -z "$current_min" || ! "$current_min" =~ ^-?[0-9]+$ ]]; then
        current_min=0
    fi

    if (( current_min < MIN_DAYS )); then
        echo "Setting minimum password age to ${MIN_DAYS} day(s) for user '${username}' (was: ${current_min})."
        chage --mindays "$MIN_DAYS" "$username"
        changed=$((changed + 1))
    fi
done < <(getent passwd)

echo "Remediation complete. Accounts checked: ${checked}, accounts modified: ${changed}."
```

**Reference fix:**
```bash
var_accounts_minimum_age_login_defs='
```


---

## RHEL-08-020331 — `no_empty_passwords`

**Prompt:** On an Ubuntu 24.04 system, the pluggable authentication configuration currently permits accounts with empty passwords to authenticate, which would allow anyone to log in and act as such an account without providing credentials. Write an idempotent bash remediation script that reconfigures the system's authentication stack so that logins to accounts with blank/empty passwords are refused, ensuring the change persists.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: disable authentication to accounts with empty/blank passwords
# on Ubuntu 24.04. Removes the "nullok" (and variants) option from the PAM
# common-auth stack and persists the change so that pam-auth-update does not
# re-introduce it.
#
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

timestamp="$(date +%Y%m%d%H%M%S)"

# Files that may contain the offending nullok option.
declare -a TARGET_FILES=(
    "/etc/pam.d/common-auth"
    "/etc/pam.d/common-password"
)

# PAM profile source files used by pam-auth-update to regenerate common-*.
if [[ -d /usr/share/pam-configs ]]; then
    while IFS= read -r -d '' f; do
        TARGET_FILES+=("$f")
    done < <(find /usr/share/pam-configs -maxdepth 1 -type f -print0)
fi

changed=0

strip_nullok() {
    local file="$1"

    [[ -f "$file" ]] || return 0

    # Only touch the file if it actually contains a nullok variant.
    if ! grep -Eq '\bnullok(_secure|=[^[:space:]]*)?\b' "$file"; then
        return 0
    fi

    cp -a -- "$file" "${file}.bak.${timestamp}"

    # Remove nullok, nullok_secure, and nullok=... tokens, tidying whitespace.
    sed -i -E \
        -e 's/[[:space:]]+nullok(_secure|=[^[:space:]]*)?\b//g' \
        -e 's/\bnullok(_secure|=[^[:space:]]*)?[[:space:]]+//g' \
        -e 's/\bnullok(_secure|=[^[:space:]]*)?\b//g' \
        "$file"

    echo "Removed nullok option from: $file"
    changed=1
}

for f in "${TARGET_FILES[@]}"; do
    strip_nullok "$f"
done

# Regenerate the PAM common-* files from the (now cleaned) profiles so the
# change is authoritative and persists across future package updates.
if command -v pam-auth-update >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive pam-auth-update --force >/dev/null 2>&1 || true
fi

# Verify no nullok remains in the active auth stack.
if grep -Eq '\bnullok(_secure|=[^[:space:]]*)?\b' /etc/pam.d/common-auth /etc/pam.d/common-password 2>/dev/null; then
    echo "ERROR: nullok still present in PAM common configuration after remediation." >&2
    exit 1
fi

if [[ "$changed" -eq 1 ]]; then
    echo "Remediation complete: empty-password logins are now refused."
else
    echo "System already compliant: no nullok option present."
fi

exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if [ -f /usr/bin/authselect ]; then
    if ! authselect check; then
echo "
authselect integrity check failed. Remediation aborted!
This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
It is not recommended to manually edit the PAM files when authselect tool is available.
In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
exit 1
fi
authselect enable-feature without-nullok

authselect apply-changes -b
else
    
if grep -qP "^\s*auth\s+sufficient\s+pam_unix.so\s.*\bnu
```


---

## RHEL-08-020310 — `accounts_logon_fail_delay`

**Prompt:** On an Ubuntu 24.04 system, the system-wide login configuration governing console and shell authentication should impose a mandatory waiting period after each failed login attempt to slow down brute-force password guessing. Configure the system so that there is at least a 4-second delay before a user is re-prompted following a failed login. Write an idempotent bash remediation script that enforces this failed-login delay and ensures it persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

FILE="/etc/pam.d/login"
DELAY_USEC=4000000
MODULE="pam_faildelay.so"

if [[ ! -f "$FILE" ]]; then
    echo "Error: $FILE does not exist." >&2
    exit 1
fi

# Backup once
if [[ ! -f "${FILE}.bak" ]]; then
    cp -p "$FILE" "${FILE}.bak"
fi

if grep -Eq '^\s*auth\s+.*\bpam_faildelay\.so\b' "$FILE"; then
    # Module present; ensure delay is set correctly
    if grep -Eq "^\s*auth\s+.*\bpam_faildelay\.so\b.*\bdelay=${DELAY_USEC}\b" "$FILE"; then
        echo "pam_faildelay.so already configured with delay=${DELAY_USEC}."
    else
        # Replace/normalize the line
        tmp="$(mktemp)"
        while IFS= read -r line; do
            if [[ "$line" =~ ^[[:space:]]*auth[[:space:]].*pam_faildelay\.so ]]; then
                echo "auth       required                     pam_faildelay.so delay=${DELAY_USEC}"
            else
                echo "$line"
            fi
        done < "$FILE" > "$tmp"
        cat "$tmp" > "$FILE"
        rm -f "$tmp"
        echo "Updated pam_faildelay.so delay to ${DELAY_USEC}."
    fi
else
    # Add the line. Prefer to place it near the top of the auth stack.
    tmp="$(mktemp)"
    inserted=0
    while IFS= read -r line; do
        if [[ $inserted -eq 0 && "$line" =~ ^[[:space:]]*auth[[:space:]] ]]; then
            echo "auth       required                     pam_faildelay.so delay=${DELAY_USEC}"
            inserted=1
        fi
        echo "$line"
    done < "$FILE" > "$tmp"

    if [[ $inserted -eq 0 ]]; then
        echo "auth       required                     pam_faildelay.so delay=${DELAY_USEC}" >> "$tmp"
    fi

    cat "$tmp" > "$FILE"
    rm -f "$tmp"
    echo "Inserted pam_faildelay.so with delay=${DELAY_USEC}."
fi

echo "Failed-login delay enforcement complete."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q shadow-utils; then

var_accounts_fail_delay='
```


---

## RHEL-08-020024 — `accounts_max_concurrent_login_sessions`

**Prompt:** On an Ubuntu 24.04 system, configure the system's user resource limits so that any single account is restricted to no more than 10 concurrent login sessions, mitigating denial-of-service conditions caused by excessive or runaway simultaneous logins. Write an idempotent bash remediation script that enforces this per-user concurrent-session cap so it applies to all users and persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

LIMITS_FILE="/etc/security/limits.conf"
LIMITS_DIR="/etc/security/limits.d"
DROPIN="${LIMITS_DIR}/99-maxlogins.conf"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

mkdir -p "$LIMITS_DIR"

# Remove any existing maxlogins entries from limits.conf to avoid conflicts
if [[ -f "$LIMITS_FILE" ]]; then
    tmpfile="$(mktemp)"
    grep -vE '^[[:space:]]*\*[[:space:]]+(hard|soft|-)[[:space:]]+maxlogins[[:space:]]+' "$LIMITS_FILE" > "$tmpfile" || true
    if ! cmp -s "$tmpfile" "$LIMITS_FILE"; then
        cat "$tmpfile" > "$LIMITS_FILE"
    fi
    rm -f "$tmpfile"
fi

# Remove stray maxlogins entries in other drop-in files
if [[ -d "$LIMITS_DIR" ]]; then
    for f in "$LIMITS_DIR"/*.conf; do
        [[ -e "$f" ]] || continue
        [[ "$f" == "$DROPIN" ]] && continue
        if grep -qE '^[[:space:]]*\*[[:space:]]+(hard|soft|-)[[:space:]]+maxlogins[[:space:]]+' "$f"; then
            tmpfile="$(mktemp)"
            grep -vE '^[[:space:]]*\*[[:space:]]+(hard|soft|-)[[:space:]]+maxlogins[[:space:]]+' "$f" > "$tmpfile" || true
            cat "$tmpfile" > "$f"
            rm -f "$tmpfile"
        fi
    done
fi

# Write the enforcing drop-in file idempotently
DESIRED_CONTENT="# Managed by remediation script: limit concurrent login sessions per user
*               hard    maxlogins       10
"

if [[ ! -f "$DROPIN" ]] || [[ "$(cat "$DROPIN")" != "$DESIRED_CONTENT" ]]; then
    printf '%s' "$DESIRED_CONTENT" > "$DROPIN"
    chmod 0644 "$DROPIN"
    chown root:root "$DROPIN"
fi

# Ensure pam_limits is enabled in relevant PAM stacks
for pamfile in /etc/pam.d/common-session /etc/pam.d/common-session-noninteractive; do
    if [[ -f "$pamfile" ]]; then
        if ! grep -qE '^\s*session\s+.*pam_limits\.so' "$pamfile"; then
            echo "session    required    pam_limits.so" >> "$pamfile"
        fi
    fi
done

echo "Per-user concurrent-session cap of 10 has been configured."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_accounts_max_concurrent_login_sessions='
```


---

## RHEL-08-010741 — `accounts_users_home_files_groupownership`

**Prompt:** On an Ubuntu 24.04 system, ensure that every file and directory within each local interactive user's home directory is group-owned by a group of which that user is a member, so that files cannot be inadvertently exposed to unrelated users through an inappropriate group ownership. Write an idempotent bash remediation script that corrects the group ownership of all such files and directories for all local interactive users.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Ensure every file/directory within each local interactive user's home
# directory is group-owned by a group of which that user is a member.
#

# Determine the UID range for interactive users from login.defs
UID_MIN=$(awk '/^\s*UID_MIN\s+/{print $2}' /etc/login.defs)
UID_MAX=$(awk '/^\s*UID_MAX\s+/{print $2}' /etc/login.defs)

[ -z "$UID_MIN" ] && UID_MIN=1000
[ -z "$UID_MAX" ] && UID_MAX=60000

# Iterate over local interactive users from /etc/passwd
while IFS=: read -r username _ uid gid home shell; do
	# Skip users outside the interactive UID range
	if [ "$uid" -lt "$UID_MIN" ] || [ "$uid" -gt "$UID_MAX" ]; then
		continue
	fi

	# Skip nologin/false shells (non-interactive)
	case "$shell" in
		*/nologin|*/false|/bin/sync|/sbin/shutdown|/sbin/halt|"")
			continue
			;;
	esac

	# Skip if home directory doesn't exist or is not a directory
	if [ -z "$home" ] || [ ! -d "$home" ]; then
		continue
	fi

	# Skip system/shared home directories
	case "$home" in
		/|/root|/dev/*|/proc/*|/sys/*)
			continue
			;;
	esac

	# Build the set of group IDs the user is a member of:
	# their primary group plus all supplementary groups.
	declare -A valid_gids=()
	valid_gids["$gid"]=1

	# Get supplementary group GIDs for this user
	while read -r sup_gid; do
		[ -n "$sup_gid" ] && valid_gids["$sup_gid"]=1
	done < <(id -G "$username" 2>/dev/null | tr ' ' '\n')

	# Walk every file/directory in the home directory
	while IFS= read -r -d '' entry; do
		entry_gid=$(stat -c '%g' "$entry" 2>/dev/null)
		[ -z "$entry_gid" ] && continue

		# If the current group ownership is not one of the user's groups,
		# reset it to the user's primary group.
		if [ -z "${valid_gids[$entry_gid]}" ]; then
			chgrp -h "$gid" "$entry"
		fi
	done < <(find "$home" -xdev -print0 2>/dev/null)

	unset valid_gids
done < /etc/passwd
```

**Reference fix:**
```bash
for user in $(awk -F':' '{ if ($3 >= 1000 && $3 != 65534 && $6 != "/") print $1 }' /etc/passwd); do
    home_dir=$(getent passwd $user | cut -d: -f6)
    group=$(getent passwd $user | cut -d: -f4)
    # Only update the group-ownership when necessary. This will avoid changing the inode timestamp
    # when the group is already defined as expected, therefore not impacting in possible integrity
    # check systems that also check inodes timestamps.
    find $home_dir -not -group $group -exec chgrp -f --no-dereference $group {} \;
done
```


---

## RHEL-08-010731 — `accounts_users_home_files_permissions`

**Prompt:** On an Ubuntu 24.04 system, ensure that every non-hidden file and directory within each local interactive user's home directory is no more permissive than owner-read/write/execute and group-read/execute, with no access for others (mode 0750 or stricter). Overly permissive home-directory contents allow other users to read or modify another user's files. Files and directories whose names begin with a dot are exempt. Write an idempotent bash remediation script that brings these files and directories into compliance.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

# Determine the minimum UID for local interactive users
UID_MIN=$(awk '/^UID_MIN/{print $2}' /etc/login.defs)
UID_MIN=${UID_MIN:-1000}

# Iterate over local interactive users from /etc/passwd
while IFS=: read -r username _ uid _ _ homedir shell; do
    # Skip users below UID_MIN or above 65533 (nobody etc.)
    if [ "$uid" -lt "$UID_MIN" ] || [ "$uid" -gt 65533 ]; then
        continue
    fi

    # Skip users without a valid login shell
    case "$shell" in
        */nologin|*/false|"") continue ;;
    esac

    # Skip if home directory doesn't exist or isn't a directory
    if [ -z "$homedir" ] || [ ! -d "$homedir" ]; then
        continue
    fi

    # Process non-hidden files and directories within the home directory,
    # excluding dotfiles/dotdirs at any level under the home directory.
    find "$homedir" -mindepth 1 \
        \( -name '.*' -prune \) -o \
        \( -perm /0027 -print0 \) | \
    while IFS= read -r -d '' entry; do
        chmod g-w,o-rwx "$entry"
    done
done < /etc/passwd
```

**Reference fix:**
```bash
for home_dir in $(awk -F':' '{ if ($3 >= 1000 && $3 != 65534 && $6 != "/") print $6 }' /etc/passwd); do
    # Only update the permissions when necessary. This will avoid changing the inode timestamp when
    # the permission is already defined as expected, therefore not impacting in possible integrity
    # check systems that also check inodes timestamps.
    find "$home_dir" -perm /7027 \! -type l -exec chmod u-s,g-w-s,o=- {} \;
done
```


---

## RHEL-08-010770 — `file_permission_user_init_files_root`

**Prompt:** On an Ubuntu 24.04 system, the per-user shell initialization files (the dot-files that configure each user's shell environment at login, including root's) may currently be more permissive than necessary, allowing other users to read or alter them and potentially compromise an account at logon. Write an idempotent bash remediation script that ensures every interactive user's local initialization files (for all human users with home directories as well as the root account) are no more permissive than owner read/write/execute plus group read only (octal 0740), tightening any that exceed this without loosening any that are already stricter.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: ensure per-user shell init dot-files are no more permissive
# than 0740 (owner rwx, group r, other none). Only tighten, never loosen.
#
set -u

# List of interactive shell initialization dot-files to check.
INIT_FILES=(
    .bashrc
    .bash_profile
    .bash_login
    .bash_logout
    .profile
    .bash_aliases
    .cshrc
    .tcshrc
    .login
    .logout
    .kshrc
    .zshrc
    .zshenv
    .zprofile
    .zlogin
    .zlogout
    .xinitrc
    .Xdefaults
)

# Maximum allowed permission bits (octal).
MAX_PERM=0740

# Collect the list of home directories to inspect.
# Gather human users (UID within the login-defs interactive range) plus root.

# Determine UID_MIN / UID_MAX from /etc/login.defs (with sane defaults).
UID_MIN=$(awk '/^UID_MIN[[:space:]]/ {print $2}' /etc/login.defs 2>/dev/null)
UID_MAX=$(awk '/^UID_MAX[[:space:]]/ {print $2}' /etc/login.defs 2>/dev/null)
[ -z "${UID_MIN:-}" ] && UID_MIN=1000
[ -z "${UID_MAX:-}" ] && UID_MAX=60000

# Build an associative list of home directories (dedup).
declare -A HOMES

while IFS=: read -r username _ uid _ _ homedir shell; do
    # Skip entries without a valid home directory.
    [ -z "$homedir" ] && continue
    [ -d "$homedir" ] || continue

    if [ "$uid" -eq 0 ]; then
        # root account always included.
        HOMES["$homedir"]=1
        continue
    fi

    # Human users within the interactive UID range.
    if [ "$uid" -ge "$UID_MIN" ] && [ "$uid" -le "$UID_MAX" ]; then
        HOMES["$homedir"]=1
    fi
done < /etc/passwd

# Convert an octal permission string to a decimal integer for comparison.
oct_to_dec() {
    printf '%d' "0$1"
}

MAX_DEC=$(oct_to_dec "$MAX_PERM")

for home in "${!HOMES[@]}"; do
    for fname in "${INIT_FILES[@]}"; do
        f="$home/$fname"

        # Only regular files that actually exist. Skip symlinks.
        [ -f "$f" ] || continue
        [ -L "$f" ] && continue

        cur=$(stat -c '%a' "$f" 2>/dev/null) || continue

        # Normalize to 4 digits worth of comparison via decimal.
        cur_dec=$(oct_to_dec "$cur")

        # Compute the intersection: keep only bits allowed by MAX_PERM.
        # This tightens without ever adding bits.
        new_dec=$(( cur_dec & MAX_DEC ))

        if [ "$new_dec" -ne "$cur_dec" ]; then
            new_oct=$(printf '%o' "$new_dec")
            chmod "$new_oct" "$f" && \
                echo "Tightened $f from $cur to $new_oct"
        fi
    done
done

exit 0
```

**Reference fix:**
```bash
var_user_initialization_files_regex='
```


---

## RHEL-08-020353 — `accounts_umask_etc_bashrc`

**Prompt:** On an Ubuntu 24.04 system, the default file-creation permission mask for users of the Bash shell may be too permissive, allowing newly created files to be accessible by group or other users and risking unauthorized disclosure or modification. Write an idempotent bash remediation script that sets the default Bash shell file-creation mask system-wide to 027, so that newly created files deny write access to group members and all access to others by default, ensuring the setting persists across reboots and new login sessions.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

TARGET_FILE="/etc/profile.d/set-umask.sh"
UMASK_VALUE="027"

# Ensure the profile.d directory exists
if [ ! -d /etc/profile.d ]; then
    mkdir -p /etc/profile.d
    chmod 0755 /etc/profile.d
fi

# Write the umask setting idempotently
cat > "$TARGET_FILE" <<EOF
# Set default file-creation mask system-wide for Bash login/interactive shells
# Managed by remediation script - do not edit manually
umask ${UMASK_VALUE}
EOF

chmod 0644 "$TARGET_FILE"
chown root:root "$TARGET_FILE"

# Also enforce the umask in /etc/login.defs so it applies broadly
LOGIN_DEFS="/etc/login.defs"
if [ -f "$LOGIN_DEFS" ]; then
    if grep -Eq '^\s*UMASK\s+' "$LOGIN_DEFS"; then
        sed -ri "s/^\s*UMASK\s+.*/UMASK\t\t${UMASK_VALUE}/" "$LOGIN_DEFS"
    else
        printf 'UMASK\t\t%s\n' "${UMASK_VALUE}" >> "$LOGIN_DEFS"
    fi
fi

# Ensure /etc/bash.bashrc enforces the umask for interactive non-login shells
BASHRC="/etc/bash.bashrc"
if [ -f "$BASHRC" ]; then
    if grep -Eq '^\s*umask\s+' "$BASHRC"; then
        sed -ri "s/^\s*umask\s+.*/umask ${UMASK_VALUE}/" "$BASHRC"
    else
        printf '\n# Set default file-creation mask (remediation)\numask %s\n' "${UMASK_VALUE}" >> "$BASHRC"
    fi
else
    printf '# Set default file-creation mask (remediation)\numask %s\n' "${UMASK_VALUE}" > "$BASHRC"
    chmod 0644 "$BASHRC"
fi

# Ensure /etc/profile enforces the umask for login shells
PROFILE="/etc/profile"
if [ -f "$PROFILE" ]; then
    if grep -Eq '^\s*umask\s+' "$PROFILE"; then
        sed -ri "s/^\s*umask\s+.*/umask ${UMASK_VALUE}/" "$PROFILE"
    else
        printf '\n# Set default file-creation mask (remediation)\numask %s\n' "${UMASK_VALUE}" >> "$PROFILE"
    fi
fi

echo "Default Bash umask set to ${UMASK_VALUE} system-wide."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q bash; then

var_accounts_user_umask='
```


---

## RHEL-08-020353 — `accounts_umask_etc_csh_cshrc`

**Prompt:** On an Ubuntu 24.04 system, ensure that the default file-creation mask for users of the C shell is configured so that newly created files and directories do not grant any permissions to group or other users (i.e. a umask of 077). An overly permissive default mask can cause newly created files to be readable or writable by unauthorized accounts. Write an idempotent bash remediation script that sets this restrictive default umask for C shell users and ensures it takes effect for new shell sessions.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

CSHRC="/etc/csh.cshrc"

# Ensure the C shell configuration file exists
if [ ! -f "$CSHRC" ]; then
    touch "$CSHRC"
    chown root:root "$CSHRC"
    chmod 0644 "$CSHRC"
fi

# Remove any existing umask lines to avoid duplicates/conflicting values
if grep -Eq '^[[:space:]]*umask[[:space:]]+[0-7]+' "$CSHRC"; then
    sed -i -E '/^[[:space:]]*umask[[:space:]]+[0-7]+/d' "$CSHRC"
fi

# Add the restrictive umask setting
echo "umask 077" >> "$CSHRC"

# Verify the result
if grep -Eq '^[[:space:]]*umask[[:space:]]+077[[:space:]]*$' "$CSHRC"; then
    echo "C shell default umask successfully set to 077 in $CSHRC"
else
    echo "Failed to set C shell default umask in $CSHRC" >&2
    exit 1
fi
```

**Reference fix:**
```bash
var_accounts_user_umask='
```


---

## RHEL-08-020351 — `accounts_umask_etc_login_defs`

**Prompt:** On an Ubuntu 24.04 system, the system-wide default file-creation mask that governs the permissions newly created files and directories receive for users is too permissive, which could allow unauthorized users to read or modify other users' files. Configure the system's default user file-creation mask so that newly created files are not accessible to group or other users (i.e., the most restrictive standard setting of 077), applied through the central login-defaults configuration. Write an idempotent bash remediation script that enforces this default, ensuring the change persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

FILE="/etc/login.defs"
DESIRED_MASK="077"

# Ensure the login.defs file exists
if [[ ! -f "$FILE" ]]; then
    touch "$FILE"
    chmod 0644 "$FILE"
fi

# Check for an existing active (non-commented) UMASK line
if grep -Eq '^[[:space:]]*UMASK[[:space:]]+' "$FILE"; then
    # Replace all active UMASK lines with the desired value
    sed -i -E "s|^[[:space:]]*UMASK[[:space:]]+.*|UMASK\t\t${DESIRED_MASK}|" "$FILE"
else
    # No active UMASK line; append one
    printf 'UMASK\t\t%s\n' "$DESIRED_MASK" >> "$FILE"
fi

# Verify the result is idempotent and correct
if grep -Eq "^[[:space:]]*UMASK[[:space:]]+${DESIRED_MASK}([[:space:]]|$)" "$FILE"; then
    echo "UMASK is correctly set to ${DESIRED_MASK} in ${FILE}"
else
    echo "Failed to set UMASK to ${DESIRED_MASK} in ${FILE}" >&2
    exit 1
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q shadow-utils; then

var_accounts_user_umask='
```


---

## RHEL-08-040004 — `grub2_pti_argument`

**Prompt:** On an Ubuntu 24.04 system, enable Kernel Page-Table Isolation to mitigate the Meltdown vulnerability and strengthen defenses against attempts to defeat kernel address-space layout randomization. Write an idempotent bash remediation script that turns on this kernel hardening feature via the bootloader so that it takes effect on boot, applies to all currently installed kernels, and is automatically carried over to any newly installed kernels, persisting across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

GRUB_FILE="/etc/default/grub"
PARAM="pti=on"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

if [[ ! -f "$GRUB_FILE" ]]; then
    echo "Error: $GRUB_FILE not found." >&2
    exit 1
fi

# Backup once
if [[ ! -f "${GRUB_FILE}.bak" ]]; then
    cp -a "$GRUB_FILE" "${GRUB_FILE}.bak"
fi

# Ensure GRUB_CMDLINE_LINUX exists
if ! grep -q '^GRUB_CMDLINE_LINUX=' "$GRUB_FILE"; then
    echo 'GRUB_CMDLINE_LINUX=""' >> "$GRUB_FILE"
fi

# Read current value
current_line=$(grep '^GRUB_CMDLINE_LINUX=' "$GRUB_FILE" | head -n1)
current_val=$(echo "$current_line" | sed -E 's/^GRUB_CMDLINE_LINUX="?(.*)"?$/\1/')
current_val=${current_val%\"}

# Remove any existing pti= setting to avoid conflicts/duplicates
new_val=$(echo "$current_val" | sed -E 's/\bpti=[^ ]*//g')

# Add pti=on if not present
if ! echo "$new_val" | grep -qw "$PARAM"; then
    new_val="$new_val $PARAM"
fi

# Normalize whitespace
new_val=$(echo "$new_val" | tr -s ' ' | sed -E 's/^ +| +$//g')

# Write back
escaped_val=$(printf '%s' "$new_val" | sed 's/[&/\]/\\&/g')
sed -i -E "s|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=\"${escaped_val}\"|" "$GRUB_FILE"

# Update bootloader so it applies to all installed kernels
if command -v update-grub >/dev/null 2>&1; then
    update-grub
else
    grub-mkconfig -o /boot/grub/grub.cfg
fi

echo "Kernel Page-Table Isolation (pti=on) has been enabled. Reboot to take effect."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if ( rpm --quiet -q grub2-common && rpm --quiet -q kernel ); then

expected_value="on"


if [[ "$OSCAP_BOOTC_BUILD" == "YES" ]] ; then
    KARGS_DIR="/usr/lib/bootc/kargs.d/"
    if grep -q -E "pti" "$KARGS_DIR/*.toml" ; then
        sed -i -E "s/^(\s*kargs\s*=\s*\[.*)\"pti=[^\"]*\"(.*]\s*)/\1\"pti=$expected_value\"\2/" "$KARGS_DIR/*.toml"
    else
        echo "kargs = [\"pti=$expected_value\"]" >> "$KARGS_DIR/10-pti.toml"
    fi
else

    grubby --update-kernel=ALL --args=pti=on --env=/boot/grub2/grubenv

fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```


---

## RHEL-08-010422 — `grub2_vsyscall_argument`

**Prompt:** On an Ubuntu 24.04 system, the legacy virtual system-call mechanism provides predictable, fixed memory locations that an attacker controlling the return instruction pointer can leverage during exploitation. Write an idempotent bash remediation script that disables this virtual syscall capability via the kernel boot configuration, ensuring the setting applies to all currently installed kernels and is automatically inherited by any kernels installed in the future so it persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Disable the legacy vsyscall mechanism (vsyscall=none)
# via the kernel boot configuration on Ubuntu 24.04.
# Idempotent: safe to run multiple times.

set -euo pipefail

GRUB_DEFAULT_FILE="/etc/default/grub"
PARAM="vsyscall=none"
PARAM_KEY="vsyscall"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

if [[ ! -f "$GRUB_DEFAULT_FILE" ]]; then
    echo "Error: $GRUB_DEFAULT_FILE not found." >&2
    exit 1
fi

# Backup once (do not overwrite an existing backup).
if [[ ! -f "${GRUB_DEFAULT_FILE}.bak" ]]; then
    cp -a "$GRUB_DEFAULT_FILE" "${GRUB_DEFAULT_FILE}.bak"
fi

update_grub_line() {
    local key="$1"   # e.g. GRUB_CMDLINE_LINUX_DEFAULT
    local file="$2"

    if grep -qE "^[[:space:]]*${key}=" "$file"; then
        # Extract current value between quotes.
        local current
        current="$(grep -E "^[[:space:]]*${key}=" "$file" | head -n1 \
            | sed -E "s/^[[:space:]]*${key}=\"?([^\"]*)\"?.*$/\1/")"

        # Remove any pre-existing vsyscall=... token to avoid duplicates/conflicts.
        local cleaned
        cleaned="$(echo "$current" | tr ' ' '\n' | grep -vE "^${PARAM_KEY}=" | tr '\n' ' ' | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//')"

        # Append our parameter.
        local newval
        if [[ -z "$cleaned" ]]; then
            newval="$PARAM"
        else
            newval="${cleaned} ${PARAM}"
        fi

        # Only rewrite if changed.
        if [[ "$current" != "$newval" ]]; then
            sed -i -E "s|^[[:space:]]*${key}=.*$|${key}=\"${newval}\"|" "$file"
            echo "Updated ${key} in $file -> \"${newval}\""
        else
            echo "${key} already correct in $file."
        fi
    else
        # Key not present; add it.
        echo "${key}=\"${PARAM}\"" >> "$file"
        echo "Added ${key}=\"${PARAM}\" to $file"
    fi
}

# Apply to both the default and the general kernel command line so it
# is inherited by all current and future kernels.
update_grub_line "GRUB_CMDLINE_LINUX_DEFAULT" "$GRUB_DEFAULT_FILE"
update_grub_line "GRUB_CMDLINE_LINUX" "$GRUB_DEFAULT_FILE"

# Regenerate the bootloader configuration so the change applies to all
# installed kernel entries.
if command -v update-grub >/dev/null 2>&1; then
    update-grub
elif command -v grub-mkconfig >/dev/null 2>&1; then
    if [[ -d /boot/grub ]]; then
        grub-mkconfig -o /boot/grub/grub.cfg
    else
        grub-mkconfig -o /boot/grub2/grub.cfg
    fi
else
    echo "Warning: no grub config-generation tool found." >&2
    exit 1
fi

echo "vsyscall=none has been applied. A reboot is required for it to take effect."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if ( rpm --quiet -q grub2-common && rpm --quiet -q kernel ) && { ( grep -sqE "^.*\.x86_64$" /proc/sys/kernel/osrelease || grep -sqE "^x86_64$" /proc/sys/kernel/arch; ); }; then

expected_value="none"


if [[ "$OSCAP_BOOTC_BUILD" == "YES" ]] ; then
    KARGS_DIR="/usr/lib/bootc/kargs.d/"
    if grep -q -E "vsyscall" "$KARGS_DIR/*.toml" ; then
        sed -i -E "s/^(\s*kargs\s*=\s*\[.*)\"vsyscall=[^\"]*\"(.*]\s*)/\1\"vsyscall=$expected_value\"\2/" "$KARGS_DIR/*.toml"
    else
        echo "kargs = [\"vsyscall=$expected_value\"]" >> "$KARGS_DIR/10-vsyscall.toml"
    fi
else

    grubby --update-kernel=ALL --args=vsyscall=none --env=/boot/gru
```


---

## RHEL-08-030720 — `rsyslog_encrypt_offload_actionsendstreamdriverauthmode`

**Prompt:** On an Ubuntu 24.04 system, the system logging service forwards audit and log records to a remote collector. To prevent records from being sent to an impersonated or unauthorized destination, the logging service must be configured to authenticate the remote peer using certificate-based (x.509) verification of the peer's name before off-loading any records over the encrypted connection. Write an idempotent bash remediation script that enforces certificate-name authentication of the remote log destination, ensuring the setting persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Enforce x.509 certificate-name authentication for rsyslog remote log forwarding.
# Idempotent remediation for Ubuntu 24.04.
#
set -euo pipefail

CONF_DIR="/etc/rsyslog.d"
DROPIN="${CONF_DIR}/99-remote-tls-authmode.conf"
MAIN_CONF="/etc/rsyslog.conf"

# Directive that enforces certificate-based verification of the peer's name.
DIRECTIVE='$ActionSendStreamDriverAuthMode x509/name'
DRIVER_DIRECTIVE='$DefaultNetstreamDriver gtls'

if ! command -v rsyslogd >/dev/null 2>&1; then
    echo "rsyslog is not installed; nothing to remediate." >&2
    exit 0
fi

mkdir -p "${CONF_DIR}"

# Remove any conflicting (non-x509/name) AuthMode settings from existing configs
# so our drop-in takes authoritative effect. Only touch files that set it wrongly.
shopt -s nullglob
for f in "${MAIN_CONF}" "${CONF_DIR}"/*.conf; do
    [ -f "$f" ] || continue
    [ "$f" = "${DROPIN}" ] && continue
    if grep -Eq '^[[:space:]]*\$ActionSendStreamDriverAuthMode[[:space:]]+' "$f"; then
        # Comment out any AuthMode line that is not x509/name
        if grep -Eq '^[[:space:]]*\$ActionSendStreamDriverAuthMode[[:space:]]+x509/name[[:space:]]*$' "$f"; then
            # Correct value already present; leave as-is but ensure not duplicated wrongly
            :
        else
            sed -ri 's|^([[:space:]]*\$ActionSendStreamDriverAuthMode[[:space:]]+.*)$|# \1  # disabled by remediation: enforcing x509/name|' "$f"
        fi
    fi
done
shopt -u nullglob

# Create/refresh the authoritative drop-in
write_dropin() {
    cat > "${DROPIN}" <<EOF
# Managed by remediation script - do not edit.
# Enforce certificate-based (x.509) verification of the remote peer's name
# before forwarding any log/audit records over the encrypted connection.
${DRIVER_DIRECTIVE}
${DIRECTIVE}
EOF
    chmod 0644 "${DROPIN}"
    chown root:root "${DROPIN}"
}

need_write=1
if [ -f "${DROPIN}" ]; then
    if grep -Eq '^[[:space:]]*\$ActionSendStreamDriverAuthMode[[:space:]]+x509/name[[:space:]]*$' "${DROPIN}" && \
       grep -Eq '^[[:space:]]*\$DefaultNetstreamDriver[[:space:]]+gtls[[:space:]]*$' "${DROPIN}"; then
        need_write=0
    fi
fi

if [ "${need_write}" -eq 1 ]; then
    write_dropin
    echo "Wrote certificate-name authentication configuration to ${DROPIN}"
else
    echo "Certificate-name authentication already enforced in ${DROPIN}"
fi

# Validate configuration syntax before restarting.
if rsyslogd -N1 >/dev/null 2>&1; then
    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart rsyslog >/dev/null 2>&1 || systemctl restart rsyslog.service >/dev/null 2>&1 || true
        systemctl enable rsyslog >/dev/null 2>&1 || true
    else
        service rsyslog restart >/dev/null 2>&1 || true
    fi
    echo "rsyslog configuration validated and service reloaded."
else
    echo "WARNING: rsyslog configuration validation failed; not restarting service." >&2
    exit 1
fi

# Final verification
if grep -Eq '^[[:space:]]*\$ActionSendStreamDriverAuthMode[[:space:]]+x509/name[[:space:]]*$' "${DROPIN}"; then
    echo "Remediation complete: remote log destination now requires x509/name authentication."
else
    echo "ERROR: expected directive not present after remediation." >&2
    exit 1
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel && rpm --quiet -q rsyslog; then

sed -i '/^.*\$ActionSendStreamDriverAuthMode.*/d' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2> /dev/null

if [ -e "/etc/rsyslog.d/stream_driver_auth.conf" ] ; then
    
    LC_ALL=C sed -i "/^\s*\$ActionSendStreamDriverAuthMode /Id" "/etc/rsyslog.d/stream_driver_auth.conf"
else
    touch "/etc/rsyslog.d/stream_driver_auth.conf"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/rsyslog.d/stream_driver_auth.conf"

cp "/etc/rsyslog.d/stream_driver_auth.conf" "/etc/rsyslog.d/stream_driver_auth.conf.bak"
# Insert at the end of the file
printf '%s\n' "\$ActionSendStreamDrive
```


---

## RHEL-08-030710 — `rsyslog_encrypt_offload_actionsendstreamdrivermode`

**Prompt:** On an Ubuntu 24.04 system, the system logging service forwards (off-loads) audit and log records to a remote collector, but these records contain sensitive configuration and authentication details that must not traverse the network in cleartext. Configure the system logging service so that all forwarded log traffic is sent using encrypted (TLS-protected) network transport rather than an unencrypted channel. Write an idempotent bash remediation script that enforces encrypted off-loading of log records and ensures the setting persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Enforce encrypted (TLS) off-loading of rsyslog log records on Ubuntu 24.04.
# Idempotent remediation script.
#
set -euo pipefail

# --- Configuration values (adjust remote collector as needed) ---------------
REMOTE_HOST="${REMOTE_LOG_HOST:-logcollector.example.com}"
REMOTE_PORT="${REMOTE_LOG_PORT:-6514}"

CA_FILE="/etc/rsyslog.d/certs/ca-cert.pem"
CERT_FILE="/etc/rsyslog.d/certs/client-cert.pem"
KEY_FILE="/etc/rsyslog.d/certs/client-key.pem"

TLS_CONF="/etc/rsyslog.d/50-tls-forwarding.conf"
CERT_DIR="/etc/rsyslog.d/certs"

# --- Must run as root -------------------------------------------------------
if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

# --- Ensure rsyslog and the GnuTLS driver package are installed -------------
ensure_package() {
    local pkg="$1"
    if ! dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
        echo "Installing package: $pkg"
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -y
        apt-get install -y "$pkg"
    else
        echo "Package already installed: $pkg"
    fi
}

ensure_package rsyslog
ensure_package rsyslog-gnutls

# --- Ensure certificate directory exists ------------------------------------
if [[ ! -d "$CERT_DIR" ]]; then
    echo "Creating certificate directory: $CERT_DIR"
    install -d -m 0755 -o root -g root "$CERT_DIR"
fi

# --- Warn (non-fatally) if certificates are missing -------------------------
for f in "$CA_FILE" "$CERT_FILE" "$KEY_FILE"; do
    if [[ ! -f "$f" ]]; then
        echo "WARNING: Expected TLS certificate file not found: $f" >&2
        echo "         Place the appropriate CA/client certificates before rsyslog can" >&2
        echo "         establish an encrypted connection to the remote collector." >&2
    fi
done

# --- Build desired TLS forwarding configuration -----------------------------
read -r -d '' DESIRED_CONF <<EOF || true
# Managed by remediation script - encrypted (TLS) log off-loading
# Do not edit manually; changes may be overwritten.

# Load the GnuTLS network stream driver
global(
    DefaultNetstreamDriver="gtls"
    DefaultNetstreamDriverCAFile="${CA_FILE}"
    DefaultNetstreamDriverCertFile="${CERT_FILE}"
    DefaultNetstreamDriverKeyFile="${KEY_FILE}"
)

# Forward all logs to the remote collector over TLS
action(
    type="omfwd"
    target="${REMOTE_HOST}"
    port="${REMOTE_PORT}"
    protocol="tcp"
    StreamDriver="gtls"
    StreamDriverMode="1"
    StreamDriverAuthMode="x509/name"
    StreamDriverPermittedPeers="${REMOTE_HOST}"
    action.resumeRetryCount="-1"
    queue.type="LinkedList"
    queue.filename="fwdTlsQueue"
    queue.maxDiskSpace="1g"
    queue.saveOnShutdown="on"
)
EOF

# --- Write configuration only if it differs (idempotent) --------------------
write_conf=1
if [[ -f "$TLS_CONF" ]]; then
    if diff -q <(printf '%s\n' "$DESIRED_CONF") "$TLS_CONF" >/dev/null 2>&1; then
        write_conf=0
        echo "TLS forwarding configuration already up to date: $TLS_CONF"
    fi
fi

if [[ "$write_conf" -eq 1 ]]; then
    echo "Writing TLS forwarding configuration: $TLS_CONF"
    printf '%s\n' "$DESIRED_CONF" > "$TLS_CONF"
    chmod 0644 "$TLS_CONF"
    chown root:root "$TLS_CONF"
fi

# --- Remove any cleartext forwarding directives from other configs ----------
# Scan for insecure plain omfwd (single @ = UDP, @@ = plain TCP) forwarding.
shopt -s nullglob
for f in /etc/rsyslog.conf /etc/rsyslog.d/*.conf; do
    [[ "$f" == "$TLS_CONF" ]] && continue
    if grep -Eq '^[[:space:]]*[^#].*(@@?[^"]*:[0-9]+)' "$f" 2>/dev/null; then
        echo "WARNING: Possible cleartext forwarding directive found in $f" >&2
        echo "         Commenting out insecure forwarding lines." >&2
        cp -a "$f" "${f}.bak.$(date +%Y%m%d%H%M%S)"
        sed -i -E 's|^([[:space:]]*)(\*\.\*[[:space:]]*@@?[^[:space:]]+.*)$|\1#\2 # disabled: cleartext forwarding|' "$f"
        sed -i -E 's|^([[:space:]]*)([^#].*action\([^)]*type="omfwd"[^)]*StreamDriver="")|\1#\2 # disabled: cleartext forwarding|' "$f"
    fi
done
shopt -u nullglob

# --- Validate rsyslog configuration -----------------------------------------
if rsyslogd -N1 >/dev/null 2>&1; then
    echo "rsyslog configuration syntax OK."
else
    echo "WARNING: rsyslog configuration validation reported issues." >&2
    rsyslogd -N1 || true
fi

# --- Enable and restart rsyslog to persist across reboots -------------------
systemctl enable rsyslog >/dev/null 2>&1 || true

echo "Restarting rsyslog service..."
systemctl restart rsyslog

if systemctl is-active --quiet rsyslog; then
    echo "rsyslog is active and configured for TLS-encrypted log off-loading."
else
    echo "ERROR: rsyslog failed to start after configuration." >&2
    exit 1
fi

echo "Remediation complete: log forwarding to ${REMOTE_HOST}:${REMOTE_PORT} is TLS-encrypted."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel && rpm --quiet -q rsyslog; then

if [ -e "/etc/rsyslog.d/encrypt.conf" ] ; then
    
    LC_ALL=C sed -i "/^\s*\$ActionSendStreamDriverMode /Id" "/etc/rsyslog.d/encrypt.conf"
else
    touch "/etc/rsyslog.d/encrypt.conf"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/rsyslog.d/encrypt.conf"

cp "/etc/rsyslog.d/encrypt.conf" "/etc/rsyslog.d/encrypt.conf.bak"
# Insert at the end of the file
printf '%s\n' "\$ActionSendStreamDriverMode 1" >> "/etc/rsyslog.d/encrypt.conf"
# Clean up after ourselves.
rm "/etc/rsyslog.d/encrypt.conf.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done
```


---

## RHEL-08-030710 — `rsyslog_encrypt_offload_defaultnetstreamdriver`

**Prompt:** On an Ubuntu 24.04 system, the system logging service forwards audit and log records to remote collectors, and these records contain sensitive details about system configuration and user authentication that must be protected in transit. Configure the system logging service so that the default network stream transport uses TLS-based encryption (via the GnuTLS secure-communications driver) when off-loading logs to remote hosts. Write an idempotent bash remediation script that enforces this encrypted-transport setting and persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Enforce TLS-based (GnuTLS) default network stream driver for rsyslog.
# Idempotent remediation script for Ubuntu 24.04.
#
set -euo pipefail

CONF_DIR="/etc/rsyslog.d"
CONF_FILE="${CONF_DIR}/60-tls-transport.conf"
DIRECTIVE='$DefaultNetstreamDriver gtls'

# Ensure rsyslog is installed
if ! command -v rsyslogd >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -y
        apt-get install -y rsyslog
    fi
fi

# Ensure the GnuTLS network driver package is present
if command -v dpkg >/dev/null 2>&1; then
    if ! dpkg -s rsyslog-gnutls >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -y || true
        apt-get install -y rsyslog-gnutls
    fi
fi

# Ensure the drop-in directory exists
mkdir -p "${CONF_DIR}"

# Remove any conflicting DefaultNetstreamDriver settings elsewhere,
# leaving the canonical config file untouched.
shopt -s nullglob
for f in /etc/rsyslog.conf "${CONF_DIR}"/*.conf; do
    [ "${f}" = "${CONF_FILE}" ] && continue
    if grep -Eq '^[[:space:]]*\$DefaultNetstreamDriver[[:space:]]+' "${f}" 2>/dev/null; then
        sed -i -E '/^[[:space:]]*\$DefaultNetstreamDriver[[:space:]]+/d' "${f}"
    fi
done
shopt -u nullglob

# Write the canonical config idempotently
NEED_WRITE=1
if [ -f "${CONF_FILE}" ]; then
    if grep -Eq '^[[:space:]]*\$DefaultNetstreamDriver[[:space:]]+gtls[[:space:]]*$' "${CONF_FILE}"; then
        NEED_WRITE=0
    fi
fi

if [ "${NEED_WRITE}" -eq 1 ]; then
    cat > "${CONF_FILE}" <<EOF
# Managed by remediation script: enforce TLS (GnuTLS) for remote log transport
${DIRECTIVE}
EOF
    chmod 0644 "${CONF_FILE}"
    chown root:root "${CONF_FILE}"
fi

# Validate rsyslog configuration before applying
if rsyslogd -N1 >/dev/null 2>&1; then
    # Enable and restart the service so the change persists across reboots
    if command -v systemctl >/dev/null 2>&1; then
        systemctl enable rsyslog >/dev/null 2>&1 || true
        systemctl restart rsyslog
    else
        service rsyslog restart || true
    fi
else
    echo "rsyslog configuration validation failed; not restarting service." >&2
    exit 1
fi

# Verify the setting is in effect
if grep -Eqr '^[[:space:]]*\$DefaultNetstreamDriver[[:space:]]+gtls[[:space:]]*$' "${CONF_FILE}"; then
    echo "TLS (GnuTLS) default network stream driver enforced successfully."
else
    echo "Failed to enforce TLS default network stream driver." >&2
    exit 1
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel && rpm --quiet -q rsyslog; then

if [ -e "/etc/rsyslog.d/encrypt.conf" ] ; then
    
    LC_ALL=C sed -i "/^\s*\$DefaultNetstreamDriver /Id" "/etc/rsyslog.d/encrypt.conf"
else
    touch "/etc/rsyslog.d/encrypt.conf"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/rsyslog.d/encrypt.conf"

cp "/etc/rsyslog.d/encrypt.conf" "/etc/rsyslog.d/encrypt.conf.bak"
# Insert at the end of the file
printf '%s\n' "\$DefaultNetstreamDriver gtls" >> "/etc/rsyslog.d/encrypt.conf"
# Clean up after ourselves.
rm "/etc/rsyslog.d/encrypt.conf.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```


---

## RHEL-08-010070 — `rsyslog_remote_access_monitoring`

**Prompt:** On an Ubuntu 24.04 system, ensure that the system logging service is configured to capture and record all authentication, privileged-authentication, and system daemon activity to persistent log files, so that remote access attempts and related events are monitored for intrusion detection and compliance. Specifically, authentication and privileged-authentication messages must be routed to the secure log, and daemon messages to the general system message log. Write an idempotent bash remediation script that establishes this logging configuration and ensures it remains in effect across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RSYSLOG_DROPIN_DIR="/etc/rsyslog.d"
CONFIG_FILE="${RSYSLOG_DROPIN_DIR}/50-auth-daemon-monitoring.conf"

# Ensure rsyslog is installed
if ! dpkg -s rsyslog >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y rsyslog
fi

# Ensure the drop-in configuration directory exists
mkdir -p "${RSYSLOG_DROPIN_DIR}"

# Ensure rsyslog main config includes the drop-in directory
if [ -f /etc/rsyslog.conf ]; then
    if ! grep -Eq '^\s*\$IncludeConfig\s+/etc/rsyslog.d/\*\.conf' /etc/rsyslog.conf \
        && ! grep -Eq '^\s*include\(\s*file="/etc/rsyslog.d/\*\.conf"' /etc/rsyslog.conf; then
        printf '\n$IncludeConfig /etc/rsyslog.d/*.conf\n' >> /etc/rsyslog.conf
    fi
fi

# Desired configuration content
read -r -d '' DESIRED_CONFIG <<'EOF' || true
# Managed by remediation script - authentication, privileged-auth and daemon logging
auth,authpriv.*                 /var/log/auth.log
daemon.*                        /var/log/syslog
EOF

# Write configuration idempotently
if [ ! -f "${CONFIG_FILE}" ] || [ "$(cat "${CONFIG_FILE}")" != "${DESIRED_CONFIG}" ]; then
    printf '%s\n' "${DESIRED_CONFIG}" > "${CONFIG_FILE}"
    chmod 0644 "${CONFIG_FILE}"
    chown root:root "${CONFIG_FILE}"
    CHANGED=1
else
    CHANGED=0
fi

# Ensure the target log files exist with appropriate ownership and permissions
for logfile in /var/log/auth.log /var/log/syslog; do
    if [ ! -e "${logfile}" ]; then
        touch "${logfile}"
    fi
    chmod 0640 "${logfile}"
    if getent group adm >/dev/null 2>&1; then
        chown syslog:adm "${logfile}" 2>/dev/null || chown root:adm "${logfile}" 2>/dev/null || true
    fi
done

# Enable rsyslog to start at boot
systemctl enable rsyslog >/dev/null 2>&1 || true

# Validate configuration before restart
if command -v rsyslogd >/dev/null 2>&1; then
    if ! rsyslogd -N1 >/dev/null 2>&1; then
        echo "ERROR: rsyslog configuration validation failed." >&2
        exit 1
    fi
fi

# Restart rsyslog to apply changes
if systemctl is-active rsyslog >/dev/null 2>&1; then
    if [ "${CHANGED}" -eq 1 ]; then
        systemctl restart rsyslog
    fi
else
    systemctl start rsyslog
fi

echo "rsyslog authentication, privileged-authentication, and daemon logging configuration enforced."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel && rpm --quiet -q rsyslog; then

declare -A REMOTE_METHODS=( ['auth.*']='^[^#]*auth\.\*.*$' ['authpriv.*']='^[^#]*authpriv\.\*.*$' ['daemon.*']='^[^#]*daemon\.\*.*$' )
declare -A LOCATIONS=( ['auth.*']='/var/log/secure' ['authpriv.*']='/var/log/secure' ['daemon.*']='/var/log/messages' )

if [[ ! -f /etc/rsyslog.conf ]]; then
	# Something is not right, create the file
	touch /etc/rsyslog.conf
fi


# Loop through the remote methods associative array
for K in "${!REMOTE_METHODS[@]}"
do
	# Check to see if selector/value exists
	if ! grep -rq "${REMOTE_METHODS[$K]}" /etc/rsyslog.*; then
        APPEND_LINE=$(sed -rn "/
```


---

## RHEL-08-030690 — `rsyslog_remote_loghost`

**Prompt:** On an Ubuntu 24.04 system, configure the system logging daemon to forward all of its log messages to a centralized remote log server (loghost). Centralized logging preserves an authoritative copy of log data off-host, so that if a system is compromised its locally stored logs—which may have been tampered with—can be corroborated against the remote copy. Assume the remote collector is reachable at the resolvable hostname "loghost". Write an idempotent bash remediation script that ensures all log facilities and priorities are forwarded to this remote host, with the change persisting across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

CONF_DIR="/etc/rsyslog.d"
CONF_FILE="${CONF_DIR}/50-remote-loghost.conf"
LOGHOST="loghost"
FORWARD_RULE="*.* @@${LOGHOST}:514"

if ! command -v rsyslogd >/dev/null 2>&1 && ! dpkg -s rsyslog >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y rsyslog
fi

mkdir -p "${CONF_DIR}"

DESIRED_CONTENT="# Managed by remediation script: forward all logs to remote loghost
${FORWARD_RULE}
"

if [ ! -f "${CONF_FILE}" ] || [ "$(cat "${CONF_FILE}")" != "${DESIRED_CONTENT}" ]; then
    printf '%s' "${DESIRED_CONTENT}" > "${CONF_FILE}"
    chmod 0644 "${CONF_FILE}"
    CHANGED=1
else
    CHANGED=0
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl enable rsyslog >/dev/null 2>&1 || true
    if [ "${CHANGED}" -eq 1 ]; then
        systemctl restart rsyslog
    else
        systemctl is-active --quiet rsyslog || systemctl start rsyslog
    fi
else
    if [ "${CHANGED}" -eq 1 ]; then
        service rsyslog restart || true
    else
        service rsyslog start || true
    fi
fi

echo "rsyslog configured to forward all logs to ${LOGHOST} (changed=${CHANGED})"
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

rsyslog_remote_loghost_address='
```


---

## RHEL-08-040261 — `sysctl_net_ipv6_conf_all_accept_ra`

**Prompt:** On an Ubuntu 24.04 system, prevent all IPv6 network interfaces from accepting router advertisement messages, since a forged advertisement could let an attacker reroute traffic and perform a man-in-the-middle attack. Write an idempotent bash remediation script that disables acceptance of IPv6 router advertisements across all interfaces, applying the change at runtime and ensuring it persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

SYSCTL_DIR="/etc/sysctl.d"
CONF_FILE="${SYSCTL_DIR}/60-disable-ipv6-ra.conf"

PARAMS=(
    "net.ipv6.conf.all.accept_ra"
    "net.ipv6.conf.default.accept_ra"
)

mkdir -p "${SYSCTL_DIR}"

# Create/refresh the persistent configuration file idempotently.
TMP_FILE="$(mktemp)"
{
    echo "# Managed by IPv6 RA remediation script"
    echo "# Disable acceptance of IPv6 router advertisements on all interfaces"
    for p in "${PARAMS[@]}"; do
        echo "${p} = 0"
    done
} > "${TMP_FILE}"

if [[ -f "${CONF_FILE}" ]] && cmp -s "${TMP_FILE}" "${CONF_FILE}"; then
    echo "Persistent configuration already up to date: ${CONF_FILE}"
    rm -f "${TMP_FILE}"
else
    mv "${TMP_FILE}" "${CONF_FILE}"
    chmod 0644 "${CONF_FILE}"
    echo "Wrote persistent configuration: ${CONF_FILE}"
fi

# Remove conflicting settings that enable accept_ra in other sysctl files.
for dir in /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d /run/sysctl.d; do
    if [[ -e "${dir}" ]]; then
        while IFS= read -r -d '' f; do
            [[ "${f}" == "${CONF_FILE}" ]] && continue
            if grep -Eq '^[[:space:]]*net\.ipv6\.conf\.(all|default)\.accept_ra[[:space:]]*=[[:space:]]*[1-9]' "${f}" 2>/dev/null; then
                sed -ri 's/^([[:space:]]*net\.ipv6\.conf\.(all|default)\.accept_ra[[:space:]]*=[[:space:]]*)[1-9][0-9]*/\10/' "${f}"
                echo "Normalized conflicting entry in: ${f}"
            fi
        done < <(find "${dir}" -maxdepth 1 -type f -print0 2>/dev/null)
    fi
done

# Apply the persistent settings at runtime.
sysctl --system >/dev/null

# Explicitly apply to every currently existing interface for immediate effect.
for iface_path in /proc/sys/net/ipv6/conf/*; do
    iface="$(basename "${iface_path}")"
    ra_file="${iface_path}/accept_ra"
    if [[ -w "${ra_file}" ]]; then
        current="$(cat "${ra_file}")"
        if [[ "${current}" != "0" ]]; then
            echo 0 > "${ra_file}"
            echo "Set net.ipv6.conf.${iface}.accept_ra = 0"
        fi
    fi
done

echo "Verification:"
for p in "${PARAMS[@]}"; do
    val="$(sysctl -n "${p}" 2>/dev/null || echo 'N/A')"
    echo "  ${p} = ${val}"
done

echo "IPv6 router advertisement acceptance has been disabled."
```

**Reference fix:**
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

## RHEL-08-040280 — `sysctl_net_ipv6_conf_all_accept_redirects`

**Prompt:** On an Ubuntu 24.04 system, the kernel currently accepts IPv6 ICMP redirect messages on all interfaces, which an attacker could abuse to alter routing and stage a man-in-the-middle attack. Write an idempotent bash remediation script that configures the kernel's IPv6 networking so that ICMP redirect messages are not accepted on any interface, applying the change at runtime and ensuring it persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PARAM_ALL="net.ipv6.conf.all.accept_redirects"
PARAM_DEFAULT="net.ipv6.conf.default.accept_redirects"
CONF_FILE="/etc/sysctl.d/99-disable-ipv6-redirects.conf"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# Ensure the persistent configuration file contains the correct settings idempotently.
mkdir -p "$(dirname "$CONF_FILE")"

write_setting() {
    local key="$1"
    local value="$2"
    local file="$3"

    if grep -Eq "^[[:space:]]*${key}[[:space:]]*=" "$file" 2>/dev/null; then
        sed -i -E "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${value}|" "$file"
    else
        echo "${key} = ${value}" >> "$file"
    fi
}

touch "$CONF_FILE"
write_setting "$PARAM_ALL" "0" "$CONF_FILE"
write_setting "$PARAM_DEFAULT" "0" "$CONF_FILE"

# Apply the settings at runtime.
sysctl -w "${PARAM_ALL}=0"
sysctl -w "${PARAM_DEFAULT}=0"

# Also apply to any currently existing interfaces to ensure immediate effect.
for iface_path in /proc/sys/net/ipv6/conf/*/accept_redirects; do
    [[ -w "$iface_path" ]] && echo 0 > "$iface_path" || true
done

# Reload sysctl configuration to confirm persistence handling.
sysctl -p "$CONF_FILE" >/dev/null 2>&1 || true

echo "IPv6 ICMP redirect acceptance disabled at runtime and persisted in ${CONF_FILE}."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of net.ipv6.conf.all.accept_redirects from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv6.conf.all.accept_redirects.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv6.conf.all.accept_redi
```


---

## RHEL-08-040240 — `sysctl_net_ipv6_conf_all_accept_source_route`

**Prompt:** On an Ubuntu 24.04 system, configure the kernel networking stack so that source-routed IPv6 packets are rejected on all IPv6 interfaces. Accepting source-routed packets lets an attacker dictate the network path a packet takes, which can be used to bypass network security controls and spoof traffic; this should be disabled. Write an idempotent bash remediation script that disables acceptance of source-routed IPv6 packets across all interfaces, applying the change at runtime and ensuring it persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PARAM_ALL="net.ipv6.conf.all.accept_source_route"
PARAM_DEFAULT="net.ipv6.conf.default.accept_source_route"
VALUE="0"
CONF_FILE="/etc/sysctl.d/60-disable-ipv6-source-route.conf"

# Ensure the sysctl.d directory exists
mkdir -p /etc/sysctl.d

# Write persistent configuration idempotently
cat > "$CONF_FILE" <<EOF
# Reject source-routed IPv6 packets on all interfaces
${PARAM_ALL} = ${VALUE}
${PARAM_DEFAULT} = ${VALUE}
EOF

# Remove any conflicting settings in other sysctl config files
for f in /etc/sysctl.conf /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
    [ -f "$f" ] || continue
    [ "$f" = "$CONF_FILE" ] && continue
    if grep -Eq "^\s*(${PARAM_ALL//./\\.}|${PARAM_DEFAULT//./\\.})\s*=" "$f"; then
        sed -ri "/^\s*(${PARAM_ALL//./\\.}|${PARAM_DEFAULT//./\\.})\s*=/d" "$f"
    fi
done

# Apply at runtime for all current interfaces
sysctl -w "${PARAM_ALL}=${VALUE}" >/dev/null
sysctl -w "${PARAM_DEFAULT}=${VALUE}" >/dev/null

# Apply to any per-interface settings that may exist
for iface_param in /proc/sys/net/ipv6/conf/*/accept_source_route; do
    [ -f "$iface_param" ] || continue
    echo "$VALUE" > "$iface_param" 2>/dev/null || true
done

# Reload sysctl settings from the system configuration
sysctl --system >/dev/null 2>&1 || true

# Verification
runtime_all=$(sysctl -n "$PARAM_ALL")
runtime_default=$(sysctl -n "$PARAM_DEFAULT")

if [ "$runtime_all" = "$VALUE" ] && [ "$runtime_default" = "$VALUE" ]; then
    echo "Source-routed IPv6 packets are now rejected on all interfaces."
else
    echo "Failed to apply IPv6 source-route rejection settings." >&2
    exit 1
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of net.ipv6.conf.all.accept_source_route from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv6.conf.all.accept_source_route.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv6.conf.all.accep
```


---

## RHEL-08-040260 — `sysctl_net_ipv6_conf_all_forwarding`

**Prompt:** On an Ubuntu 24.04 system that is not acting as a router, ensure the kernel does not forward IPv6 packets between network interfaces, since unnecessary packet forwarding can allow the host to be misused to route traffic between networks. Write an idempotent bash remediation script that disables IPv6 packet forwarding for all interfaces, applying the setting at runtime and ensuring it persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PARAM="net.ipv6.conf.all.forwarding"
VALUE="0"
PERSIST_FILE="/etc/sysctl.d/60-disable-ipv6-forwarding.conf"

# Remove any conflicting definitions of this parameter from existing sysctl config files
for f in /etc/sysctl.conf /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do
    [ -f "$f" ] || continue
    if [ "$f" = "$PERSIST_FILE" ]; then
        continue
    fi
    if grep -Eq "^[[:space:]]*${PARAM}[[:space:]]*=" "$f"; then
        sed -i -E "\|^[[:space:]]*${PARAM}[[:space:]]*=|d" "$f"
    fi
done

# Write the persistent configuration idempotently
mkdir -p "$(dirname "$PERSIST_FILE")"
DESIRED_LINE="${PARAM} = ${VALUE}"
if [ ! -f "$PERSIST_FILE" ] || ! grep -Eq "^[[:space:]]*${PARAM}[[:space:]]*=[[:space:]]*${VALUE}[[:space:]]*$" "$PERSIST_FILE"; then
    printf '%s\n' "$DESIRED_LINE" > "$PERSIST_FILE"
fi

# Apply the setting at runtime
sysctl -w "${PARAM}=${VALUE}" >/dev/null

# Reload settings to ensure consistency
sysctl --system >/dev/null

# Verify
CURRENT="$(sysctl -n "$PARAM")"
if [ "$CURRENT" != "$VALUE" ]; then
    echo "Error: failed to set ${PARAM} to ${VALUE} (current: ${CURRENT})" >&2
    exit 1
fi

echo "IPv6 packet forwarding disabled (${PARAM}=${VALUE})."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of net.ipv6.conf.all.forwarding from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv6.conf.all.forwarding.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv6.conf.all.forwarding" matches to 
```


---

## RHEL-08-040262 — `sysctl_net_ipv6_conf_default_accept_ra`

**Prompt:** On an Ubuntu 24.04 system, the kernel's network stack is currently configured to accept IPv6 router advertisements by default on network interfaces, which could allow an attacker to inject forged advertisements and stage a man-in-the-middle attack. Write an idempotent bash remediation script that ensures newly initialized IPv6 interfaces do not accept router advertisements by default, applying the change both at runtime and persistently across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PARAM="net.ipv6.conf.default.accept_ra"
VALUE="0"
CONF_DIR="/etc/sysctl.d"
CONF_FILE="${CONF_DIR}/60-disable-ipv6-default-accept-ra.conf"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

mkdir -p "$CONF_DIR"

# Remove any existing definitions of this parameter from other sysctl config files
for f in /etc/sysctl.conf "$CONF_DIR"/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf; do
    [[ -f "$f" ]] || continue
    [[ "$f" == "$CONF_FILE" ]] && continue
    if grep -Eq "^[[:space:]]*${PARAM//./\\.}[[:space:]]*=" "$f"; then
        sed -i -E "/^[[:space:]]*${PARAM//./\\.}[[:space:]]*=/d" "$f"
    fi
done

# Write the persistent configuration idempotently
DESIRED_LINE="${PARAM} = ${VALUE}"
if [[ ! -f "$CONF_FILE" ]] || ! grep -Fxq "$DESIRED_LINE" "$CONF_FILE"; then
    printf '%s\n' "$DESIRED_LINE" > "$CONF_FILE"
fi
chmod 0644 "$CONF_FILE"

# Apply the setting at runtime
sysctl -w "${PARAM}=${VALUE}" >/dev/null

# Verify runtime value
CURRENT="$(sysctl -n "$PARAM")"
if [[ "$CURRENT" != "$VALUE" ]]; then
    echo "Failed to set ${PARAM} to ${VALUE} (current: ${CURRENT})." >&2
    exit 1
fi

echo "${PARAM} is set to ${VALUE} at runtime and persistently in ${CONF_FILE}."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of net.ipv6.conf.default.accept_ra from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv6.conf.default.accept_ra.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv6.conf.default.accept_ra" ma
```


---

## RHEL-08-040210 — `sysctl_net_ipv6_conf_default_accept_redirects`

**Prompt:** On an Ubuntu 24.04 system, the network stack currently accepts ICMP redirect messages by default on IPv6 interfaces, which an attacker could abuse to alter routing tables and stage a man-in-the-middle attack. Write an idempotent bash remediation script that prevents the system from accepting ICMP redirect messages by default on all IPv6 interfaces, applying the change immediately at runtime and ensuring it persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PARAM="net.ipv6.conf.default.accept_redirects"
VALUE="0"
CONF_FILE="/etc/sysctl.d/99-ipv6-default-accept-redirects.conf"

# Ensure the config directory exists
mkdir -p /etc/sysctl.d

# Idempotently write/update the persistent configuration
if [ -f "$CONF_FILE" ] && grep -qE "^\s*${PARAM}\s*=" "$CONF_FILE"; then
    sed -i -E "s|^\s*${PARAM}\s*=.*|${PARAM} = ${VALUE}|" "$CONF_FILE"
else
    printf '%s = %s\n' "$PARAM" "$VALUE" >> "$CONF_FILE"
fi

# Remove conflicting definitions in other common sysctl files
for f in /etc/sysctl.conf /etc/sysctl.d/*.conf; do
    [ -f "$f" ] || continue
    [ "$f" = "$CONF_FILE" ] && continue
    if grep -qE "^\s*${PARAM}\s*=" "$f"; then
        sed -i -E "/^\s*${PARAM}\s*=.*/d" "$f"
    fi
done

# Apply the change immediately at runtime
sysctl -w "${PARAM}=${VALUE}"

# Reload persistent settings to confirm consistency
sysctl -p "$CONF_FILE" >/dev/null 2>&1 || true

# Verify
CURRENT="$(sysctl -n "$PARAM")"
if [ "$CURRENT" != "$VALUE" ]; then
    echo "Failed to set ${PARAM} to ${VALUE} (current: ${CURRENT})" >&2
    exit 1
fi

echo "${PARAM} is set to ${CURRENT} and will persist across reboots."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of net.ipv6.conf.default.accept_redirects from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv6.conf.default.accept_redirects.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv6.conf.default
```


---

## RHEL-08-040250 — `sysctl_net_ipv6_conf_default_accept_source_route`

**Prompt:** On an Ubuntu 24.04 system, configure the kernel's default IPv6 networking behavior so that source-routed IPv6 packets are not accepted on network interfaces by default. Source routing lets a packet's sender dictate its network path, which can be abused to bypass network security controls, and it has few legitimate uses. Write an idempotent bash remediation script that disables acceptance of source-routed IPv6 packets for the default interface configuration, applying the change at runtime and ensuring it persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PARAM="net.ipv6.conf.default.accept_source_route"
VALUE="0"
CONF_DIR="/etc/sysctl.d"
CONF_FILE="${CONF_DIR}/60-disable-ipv6-source-route.conf"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

mkdir -p "$CONF_DIR"

# Remove any existing settings for this parameter from other sysctl config files
for f in /etc/sysctl.conf /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
    [[ -f "$f" ]] || continue
    [[ "$f" == "$CONF_FILE" ]] && continue
    if grep -Eq "^\s*${PARAM//./\\.}\s*=" "$f" 2>/dev/null; then
        sed -i -E "/^\s*${PARAM//./\\.}\s*=/d" "$f"
    fi
done

# Write our persistent configuration idempotently
DESIRED_LINE="${PARAM} = ${VALUE}"
if [[ ! -f "$CONF_FILE" ]] || ! grep -Eq "^\s*${PARAM//./\\.}\s*=\s*${VALUE}\s*$" "$CONF_FILE"; then
    printf '%s\n' "$DESIRED_LINE" > "$CONF_FILE"
    chmod 0644 "$CONF_FILE"
fi

# Apply at runtime
sysctl -w "${PARAM}=${VALUE}" >/dev/null

# Verify
CURRENT="$(sysctl -n "$PARAM")"
if [[ "$CURRENT" != "$VALUE" ]]; then
    echo "Failed to set ${PARAM} to ${VALUE} (current: ${CURRENT})." >&2
    exit 1
fi

echo "${PARAM} is set to ${VALUE} and persisted in ${CONF_FILE}."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of net.ipv6.conf.default.accept_source_route from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv6.conf.default.accept_source_route.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv6.conf.d
```


---

## RHEL-08-040279 — `sysctl_net_ipv4_conf_all_accept_redirects`

**Prompt:** On an Ubuntu 24.04 system, the IPv4 networking stack currently accepts ICMP redirect messages on all interfaces. Because these messages are unauthenticated and can be forged to alter the host's routing table, they enable man-in-the-middle attacks and should be refused unless explicitly required. Write an idempotent bash remediation script that prevents the system from accepting ICMP redirect messages on all IPv4 interfaces, applying the change at runtime and ensuring it persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

# Must run as root
if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

CONF_FILE="/etc/sysctl.d/60-disable-icmp-redirects.conf"

PARAMS=(
    "net.ipv4.conf.all.accept_redirects"
    "net.ipv4.conf.default.accept_redirects"
)

# Create/update the persistent configuration idempotently
mkdir -p /etc/sysctl.d

TMP_FILE="$(mktemp)"
cat > "${TMP_FILE}" <<'EOF'
# Refuse ICMP redirect messages on all IPv4 interfaces
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
EOF

if [[ ! -f "${CONF_FILE}" ]] || ! cmp -s "${TMP_FILE}" "${CONF_FILE}"; then
    mv "${TMP_FILE}" "${CONF_FILE}"
    chmod 0644 "${CONF_FILE}"
    echo "Updated ${CONF_FILE}"
else
    rm -f "${TMP_FILE}"
    echo "${CONF_FILE} already up to date"
fi

# Neutralize any conflicting settings in other sysctl config sources
for f in /etc/sysctl.conf /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
    [[ -f "${f}" ]] || continue
    [[ "${f}" == "${CONF_FILE}" ]] && continue
    for p in "${PARAMS[@]}"; do
        esc_p="${p//./\\.}"
        if grep -Eq "^[[:space:]]*${esc_p}[[:space:]]*=" "${f}" 2>/dev/null; then
            if grep -Eq "^[[:space:]]*${esc_p}[[:space:]]*=[[:space:]]*0([[:space:]#].*)?$" "${f}"; then
                continue
            fi
            sed -ri "s|^[[:space:]]*(${esc_p})[[:space:]]*=.*|\1 = 0|" "${f}"
            echo "Overrode conflicting ${p} in ${f}"
        fi
    done
done

# Apply the settings at runtime
for p in "${PARAMS[@]}"; do
    sysctl -w "${p}=0" >/dev/null
done

# Reload from config files to ensure consistency
sysctl --system >/dev/null

# Verify runtime state
rc=0
for p in "${PARAMS[@]}"; do
    val="$(sysctl -n "${p}")"
    if [[ "${val}" != "0" ]]; then
        echo "ERROR: ${p} is ${val}, expected 0" >&2
        rc=1
    else
        echo "OK: ${p} = ${val}"
    fi
done

exit "${rc}"
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of net.ipv4.conf.all.accept_redirects from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.all.accept_redirects.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.all.accept_redi
```


---

## RHEL-08-040259 — `sysctl_net_ipv4_conf_all_forwarding`

**Prompt:** On an Ubuntu 24.04 system that is not intended to act as a router, configure the kernel so that it does not forward IPv4 packets between any network interfaces, preventing the host from inadvertently bridging or routing traffic between networks. Write an idempotent bash remediation script that disables IPv4 packet forwarding across all interfaces, applying the setting at runtime and ensuring it persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

PARAM="net.ipv4.ip_forward"
VALUE="0"
PERSIST_FILE="/etc/sysctl.d/60-disable-ipv4-forwarding.conf"

# Ensure the sysctl.d directory exists
mkdir -p /etc/sysctl.d

# Write the persistent configuration idempotently
DESIRED_LINE="${PARAM} = ${VALUE}"
if [[ -f "${PERSIST_FILE}" ]] && grep -Eq "^\s*${PARAM}\s*=" "${PERSIST_FILE}"; then
    # Update existing entry if it differs
    if ! grep -Eq "^\s*${PARAM}\s*=\s*${VALUE}\s*$" "${PERSIST_FILE}"; then
        sed -i -E "s|^\s*${PARAM}\s*=.*|${DESIRED_LINE}|" "${PERSIST_FILE}"
    fi
else
    printf '%s\n' "${DESIRED_LINE}" >> "${PERSIST_FILE}"
fi

# Remove/override any conflicting settings in other common sysctl files
for f in /etc/sysctl.conf /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
    [[ -f "${f}" ]] || continue
    [[ "${f}" == "${PERSIST_FILE}" ]] && continue
    if grep -Eq "^\s*${PARAM}\s*=\s*1\s*$" "${f}" 2>/dev/null; then
        sed -i -E "s|^(\s*${PARAM}\s*=\s*)1(\s*)$|\10\2|" "${f}"
    fi
done

# Apply the setting at runtime
sysctl -w "${PARAM}=${VALUE}" >/dev/null

# Reload persistent settings to ensure our file takes effect
sysctl --system >/dev/null

# Verify
CURRENT="$(sysctl -n "${PARAM}")"
if [[ "${CURRENT}" != "${VALUE}" ]]; then
    echo "ERROR: Failed to set ${PARAM} to ${VALUE} (current: ${CURRENT})." >&2
    exit 1
fi

echo "IPv4 packet forwarding disabled (${PARAM}=${CURRENT}) and persisted in ${PERSIST_FILE}."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of net.ipv4.conf.all.forwarding from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.all.forwarding.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.all.forwarding" matches to 
```


---

## RHEL-08-040209 — `sysctl_net_ipv4_conf_default_accept_redirects`

**Prompt:** On an Ubuntu 24.04 system, the IPv4 networking stack currently accepts ICMP redirect messages on newly initialized interfaces by default; because these unauthenticated messages can alter the host's routing table and enable man-in-the-middle attacks, they must be rejected. Write an idempotent bash remediation script that ensures the kernel does not accept ICMP redirects by default for IPv4 interfaces, applying the setting at runtime and persisting it across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PARAM="net.ipv4.conf.default.accept_redirects"
VALUE="0"
CONF_FILE="/etc/sysctl.d/99-disable-icmp-redirects.conf"
SETTING="${PARAM} = ${VALUE}"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

mkdir -p "$(dirname "$CONF_FILE")"

if [[ -f "$CONF_FILE" ]] && grep -qE "^\s*${PARAM}\s*=" "$CONF_FILE"; then
    sed -i -E "s|^\s*${PARAM}\s*=.*|${SETTING}|" "$CONF_FILE"
else
    printf '%s\n' "$SETTING" >> "$CONF_FILE"
fi

for f in /etc/sysctl.conf /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
    [[ -f "$f" ]] || continue
    [[ "$f" == "$CONF_FILE" ]] && continue
    if grep -qE "^\s*${PARAM}\s*=" "$f"; then
        sed -i -E "s|^\s*(${PARAM}\s*=.*)|# \1 (overridden by ${CONF_FILE})|" "$f"
    fi
done

sysctl -w "${PARAM}=${VALUE}" >/dev/null

for iface_path in /proc/sys/net/ipv4/conf/*/accept_redirects; do
    [[ -w "$iface_path" ]] || continue
    echo "$VALUE" > "$iface_path"
done

sysctl --system >/dev/null 2>&1 || true

CURRENT="$(sysctl -n "$PARAM")"
if [[ "$CURRENT" == "$VALUE" ]]; then
    echo "Success: ${PARAM} is set to ${CURRENT} and persisted in ${CONF_FILE}"
else
    echo "Error: ${PARAM} is ${CURRENT}, expected ${VALUE}" >&2
    exit 1
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of net.ipv4.conf.default.accept_redirects from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.default.accept_redirects.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.default
```


---

## RHEL-08-040249 — `sysctl_net_ipv4_conf_default_accept_source_route`

**Prompt:** On an Ubuntu 24.04 system, configure the kernel's IPv4 networking so that source-routed packets are not accepted by default on network interfaces. Source routing lets a packet's sender dictate its forwarding path, which can be abused to bypass network security controls, and it has few legitimate uses on a non-router host. Write an idempotent bash remediation script that disables default acceptance of IPv4 source-routed packets, applying the change at runtime and ensuring it persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PARAM="net.ipv4.conf.default.accept_source_route"
VALUE="0"
CONF_FILE="/etc/sysctl.d/60-disable-source-route.conf"

# Ensure the sysctl.d directory exists
mkdir -p /etc/sysctl.d

# Remove any existing definitions of this parameter from persistent config
# files so our setting is authoritative, then write our own.
for f in /etc/sysctl.conf /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
    [ -f "$f" ] || continue
    if [ "$f" = "$CONF_FILE" ]; then
        continue
    fi
    if grep -Eq "^[[:space:]]*${PARAM}[[:space:]]*=" "$f" 2>/dev/null; then
        sed -i -E "/^[[:space:]]*${PARAM}[[:space:]]*=.*/d" "$f"
    fi
done

# Write the persistent configuration idempotently
cat > "$CONF_FILE" <<EOF
# Disable acceptance of IPv4 source-routed packets by default
${PARAM} = ${VALUE}
EOF
chmod 0644 "$CONF_FILE"

# Apply the setting at runtime for the default interface template
sysctl -w "${PARAM}=${VALUE}" >/dev/null

# Reload all sysctl settings to ensure persistence config is active
sysctl --system >/dev/null

# Verify
CURRENT=$(sysctl -n "$PARAM")
if [ "$CURRENT" = "$VALUE" ]; then
    echo "Success: ${PARAM} = ${CURRENT}"
else
    echo "Error: ${PARAM} is ${CURRENT}, expected ${VALUE}" >&2
    exit 1
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of net.ipv4.conf.default.accept_source_route from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.default.accept_source_route.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.d
```


---

## RHEL-08-040230 — `sysctl_net_ipv4_icmp_echo_ignore_broadcasts`

**Prompt:** On an Ubuntu 24.04 system, configure the IPv4 networking stack so that the host ignores ICMP echo requests sent to broadcast or multicast addresses, preventing the system from participating in network-mapping reconnaissance and ICMP amplification attacks. Write an idempotent bash remediation script that applies this behavior immediately and ensures it persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PARAM="net.ipv4.icmp_echo_ignore_broadcasts"
VALUE="1"
CONF_FILE="/etc/sysctl.d/99-icmp-broadcast-hardening.conf"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# Ensure the persistent configuration directory exists
mkdir -p /etc/sysctl.d

# Write/update the persistent configuration idempotently
if [[ -f "$CONF_FILE" ]] && grep -Eq "^\s*${PARAM}\s*=\s*${VALUE}\s*$" "$CONF_FILE"; then
    echo "Persistent setting already present in $CONF_FILE"
else
    # Remove any existing entries for this parameter, then append the correct one
    if [[ -f "$CONF_FILE" ]]; then
        sed -i -E "/^\s*${PARAM}\s*=.*/d" "$CONF_FILE"
    fi
    echo "${PARAM} = ${VALUE}" >> "$CONF_FILE"
    echo "Updated persistent setting in $CONF_FILE"
fi

chmod 0644 "$CONF_FILE"

# Apply immediately
CURRENT="$(sysctl -n "$PARAM" 2>/dev/null || echo "")"
if [[ "$CURRENT" == "$VALUE" ]]; then
    echo "Runtime value already set: ${PARAM} = ${VALUE}"
else
    sysctl -w "${PARAM}=${VALUE}" >/dev/null
    echo "Applied runtime value: ${PARAM} = ${VALUE}"
fi

# Reload sysctl config to confirm persistence integration
sysctl -p "$CONF_FILE" >/dev/null

# Verify
FINAL="$(sysctl -n "$PARAM")"
if [[ "$FINAL" == "$VALUE" ]]; then
    echo "Verification succeeded: ${PARAM} = ${FINAL}"
else
    echo "Verification FAILED: ${PARAM} = ${FINAL}" >&2
    exit 1
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of net.ipv4.icmp_echo_ignore_broadcasts from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.icmp_echo_ignore_broadcasts.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.icmp_echo_ignore
```


---

## RHEL-08-040220 — `sysctl_net_ipv4_conf_all_send_redirects`

**Prompt:** On an Ubuntu 24.04 system that is not acting as a router, the networking stack is currently permitted to send ICMP redirect messages on all IPv4 interfaces, which can leak portions of the system's routing table and network topology. Write an idempotent bash remediation script that disables the sending of ICMP redirect messages across all IPv4 interfaces, ensuring the setting takes effect immediately at runtime and persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

CONF_DIR="/etc/sysctl.d"
CONF_FILE="${CONF_DIR}/60-disable-send-redirects.conf"

mkdir -p "${CONF_DIR}"

cat > "${CONF_FILE}" <<'EOF'
# Disable sending of ICMP redirects (system is not a router)
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
EOF

chmod 0644 "${CONF_FILE}"

# Apply immediately at runtime for all existing interfaces
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0

for iface_path in /proc/sys/net/ipv4/conf/*/send_redirects; do
    [[ -w "${iface_path}" ]] || continue
    echo 0 > "${iface_path}"
done

# Reload persistent settings to confirm
sysctl --system >/dev/null

echo "ICMP redirect sending disabled on all IPv4 interfaces (runtime + persistent)."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of net.ipv4.conf.all.send_redirects from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.all.send_redirects.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.all.send_redirects"
```


---

## RHEL-08-040270 — `sysctl_net_ipv4_conf_default_send_redirects`

**Prompt:** On an Ubuntu 24.04 system that is not acting as a router, the default network configuration currently permits the system to send ICMP redirect messages on IPv4 interfaces, which can leak route-table details and portions of the network topology. Write an idempotent bash remediation script that disables the sending of IPv4 ICMP redirects for the default interface configuration, applying the change at runtime and ensuring it persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PARAM_ALL="net.ipv4.conf.all.send_redirects"
PARAM_DEFAULT="net.ipv4.conf.default.send_redirects"
CONF_FILE="/etc/sysctl.d/60-disable-icmp-redirects.conf"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# Ensure persistent configuration file exists with correct settings
mkdir -p /etc/sysctl.d

write_conf() {
    cat > "$CONF_FILE" <<'EOF'
# Disable sending of IPv4 ICMP redirects (system is not a router)
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
EOF
}

if [[ ! -f "$CONF_FILE" ]]; then
    write_conf
else
    if ! grep -Eq '^[[:space:]]*net\.ipv4\.conf\.all\.send_redirects[[:space:]]*=[[:space:]]*0[[:space:]]*$' "$CONF_FILE" \
        || ! grep -Eq '^[[:space:]]*net\.ipv4\.conf\.default\.send_redirects[[:space:]]*=[[:space:]]*0[[:space:]]*$' "$CONF_FILE"; then
        write_conf
    fi
fi

# Remove/neutralize conflicting settings in other sysctl files
for f in /etc/sysctl.conf /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
    [[ -f "$f" ]] || continue
    [[ "$f" == "$CONF_FILE" ]] && continue
    if grep -Eq '^[[:space:]]*net\.ipv4\.conf\.(all|default)\.send_redirects[[:space:]]*=[[:space:]]*[^0]' "$f" 2>/dev/null; then
        sed -ri 's/^([[:space:]]*net\.ipv4\.conf\.(all|default)\.send_redirects[[:space:]]*=.*)$/# \1  # disabled by remediation/' "$f"
    fi
done

# Apply at runtime for all existing IPv4 interfaces and the all/default keys
for key in "$PARAM_ALL" "$PARAM_DEFAULT"; do
    current="$(sysctl -n "$key" 2>/dev/null || echo "")"
    if [[ "$current" != "0" ]]; then
        sysctl -w "$key=0" >/dev/null
    fi
done

for path in /proc/sys/net/ipv4/conf/*/send_redirects; do
    [[ -f "$path" ]] || continue
    if [[ "$(cat "$path")" != "0" ]]; then
        echo 0 > "$path"
    fi
done

# Reload sysctl settings to ensure consistency
sysctl --system >/dev/null 2>&1 || true

echo "IPv4 ICMP redirect sending disabled (runtime and persistent)."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of net.ipv4.conf.default.send_redirects from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.default.send_redirects.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.default.sen
```


---

## RHEL-08-040021 — `kernel_module_atm_disabled`

**Prompt:** On an Ubuntu 24.04 system, the Asynchronous Transfer Mode (ATM) networking protocol support is an unneeded, rarely used capability whose presence increases the kernel's attack surface; flaws in its implementation could be exploited. Write an idempotent bash remediation script that prevents the ATM kernel module from being loaded, including blocking both automatic and manual on-demand loading, with the change persisting across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

MODULE="atm"
CONF_FILE="/etc/modprobe.d/${MODULE}.conf"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# Ensure the modprobe.d directory exists
mkdir -p /etc/modprobe.d

# Desired content: block automatic and manual on-demand loading
DESIRED_CONTENT="install ${MODULE} /bin/true
blacklist ${MODULE}"

# Write the configuration idempotently
if [[ ! -f "${CONF_FILE}" ]] || [[ "$(cat "${CONF_FILE}")" != "${DESIRED_CONTENT}" ]]; then
    printf '%s\n' "${DESIRED_CONTENT}" > "${CONF_FILE}"
    chmod 0644 "${CONF_FILE}"
    echo "Wrote ${CONF_FILE}"
else
    echo "${CONF_FILE} already up to date"
fi

# Unload the module now if it is currently loaded and not in use
if lsmod | awk '{print $1}' | grep -qx "${MODULE}"; then
    if modprobe -r "${MODULE}" 2>/dev/null; then
        echo "Unloaded ${MODULE} module"
    else
        echo "Could not unload ${MODULE} (may be in use); it will remain blocked after reboot." >&2
    fi
else
    echo "${MODULE} module is not currently loaded"
fi

echo "Remediation for ${MODULE} complete."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if LC_ALL=C grep -q -m 1 "^install atm" /etc/modprobe.d/atm.conf ; then
	
	sed -i 's#^install atm.*#install atm /bin/false#g' /etc/modprobe.d/atm.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/atm.conf
	echo "install atm /bin/false" >> /etc/modprobe.d/atm.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist atm$" /etc/modprobe.d/atm.conf ; then
	echo "blacklist atm" >> /etc/modprobe.d/atm.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```


---

## RHEL-08-040022 — `kernel_module_can_disabled`

**Prompt:** On an Ubuntu 24.04 system, the Controller Area Network (CAN) protocol is an uncommon serial communications protocol that is unnecessary on most systems; leaving its kernel support available expands the attack surface for exploitation of flaws in its implementation. Write an idempotent bash remediation script that ensures the CAN protocol kernel module cannot be loaded and is prevented from being used, with the configuration persisting across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure the CAN kernel module cannot be loaded or used.
# Idempotent and persistent across reboots.

set -euo pipefail

MODULE="can"
CONF_DIR="/etc/modprobe.d"
CONF_FILE="${CONF_DIR}/${MODULE}.conf"

# Ensure the modprobe configuration directory exists
if [ ! -d "${CONF_DIR}" ]; then
    mkdir -p "${CONF_DIR}"
fi

# Desired configuration lines
BLACKLIST_LINE="blacklist ${MODULE}"
INSTALL_LINE="install ${MODULE} /bin/false"

# Ensure the blacklist directive is present
if ! grep -Eqs "^[[:space:]]*blacklist[[:space:]]+${MODULE}([[:space:]]|$)" "${CONF_FILE}" 2>/dev/null; then
    echo "${BLACKLIST_LINE}" >> "${CONF_FILE}"
fi

# Ensure the install directive is present to prevent loading
if ! grep -Eqs "^[[:space:]]*install[[:space:]]+${MODULE}[[:space:]]+/bin/false([[:space:]]|$)" "${CONF_FILE}" 2>/dev/null; then
    echo "${INSTALL_LINE}" >> "${CONF_FILE}"
fi

# Unload the module if it is currently loaded
if lsmod | awk '{print $1}' | grep -qx "${MODULE}"; then
    modprobe -r "${MODULE}" 2>/dev/null || rmmod "${MODULE}" 2>/dev/null || true
fi

echo "CAN kernel module has been blacklisted and disabled."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if LC_ALL=C grep -q -m 1 "^install can" /etc/modprobe.d/can.conf ; then
	
	sed -i 's#^install can.*#install can /bin/false#g' /etc/modprobe.d/can.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/can.conf
	echo "install can /bin/false" >> /etc/modprobe.d/can.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist can$" /etc/modprobe.d/can.conf ; then
	echo "blacklist can" >> /etc/modprobe.d/can.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```


---

## RHEL-08-040026 — `kernel_module_firewire-core_disabled`

**Prompt:** On an Ubuntu 24.04 system, the IEEE 1394 (FireWire) high-speed serial bus support presents an attack surface through potential flaws in its implementation and via direct-memory-access risks. Configure the system so that FireWire support cannot be loaded or used: the relevant kernel driver must be prevented from loading and from being activated on demand. Write an idempotent bash remediation script that enforces this persistently across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

CONF_FILE="/etc/modprobe.d/firewire-blacklist.conf"
MODULES=(
    "firewire_core"
    "firewire_ohci"
    "firewire_sbp2"
    "firewire_net"
    "firewire-core"
    "firewire-ohci"
    "firewire-sbp2"
    "firewire-net"
)

# Ensure the modprobe.d directory exists
mkdir -p /etc/modprobe.d

# Build the desired configuration content
TMP_FILE="$(mktemp)"
{
    echo "# FireWire (IEEE 1394) support disabled to reduce attack surface (DMA risks)."
    echo "# Managed by remediation script. Do not edit manually."
    for mod in firewire_core firewire_ohci firewire_sbp2 firewire_net; do
        echo "install ${mod} /bin/false"
        echo "blacklist ${mod}"
    done
} > "$TMP_FILE"

# Idempotently write the configuration only if it differs
if [[ ! -f "$CONF_FILE" ]] || ! cmp -s "$TMP_FILE" "$CONF_FILE"; then
    install -m 0644 "$TMP_FILE" "$CONF_FILE"
fi
rm -f "$TMP_FILE"

# Unload any currently loaded FireWire modules (best-effort, dependency-aware)
for mod in firewire_net firewire_sbp2 firewire_ohci firewire_core; do
    normalized="${mod//-/_}"
    if lsmod | awk '{print $1}' | grep -qx "$normalized"; then
        modprobe -r "$normalized" 2>/dev/null || rmmod "$normalized" 2>/dev/null || true
    fi
done

# Update initramfs so the change persists across reboots
if command -v update-initramfs >/dev/null 2>&1; then
    update-initramfs -u
fi

echo "FireWire (IEEE 1394) support has been disabled persistently."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if LC_ALL=C grep -q -m 1 "^install firewire-core" /etc/modprobe.d/firewire-core.conf ; then
	
	sed -i 's#^install firewire-core.*#install firewire-core /bin/false#g' /etc/modprobe.d/firewire-core.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/firewire-core.conf
	echo "install firewire-core /bin/false" >> /etc/modprobe.d/firewire-core.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist firewire-core$" /etc/modprobe.d/firewire-core.conf ; then
	echo "blacklist firewire-core" >> /etc/modprobe.d/firewire-core.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
```


---

## RHEL-08-040023 — `kernel_module_sctp_disabled`

**Prompt:** On an Ubuntu 24.04 system, the Stream Control Transmission Protocol (SCTP) transport is an unneeded networking capability whose presence increases the attack surface and could be exploited through flaws in its implementation. Write an idempotent bash remediation script that ensures the kernel support for the SCTP protocol cannot be loaded or used, so that any attempt to bring this capability into the running kernel is prevented, and that this restriction persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

MODULE="sctp"
CONF_DIR="/etc/modprobe.d"
CONF_FILE="${CONF_DIR}/${MODULE}.conf"

# Ensure the modprobe configuration directory exists
mkdir -p "${CONF_DIR}"

# Ensure the module is blacklisted and disabled via a fake install
# Write the configuration idempotently
BLACKLIST_LINE="blacklist ${MODULE}"
INSTALL_LINE="install ${MODULE} /bin/false"

TMP_FILE="$(mktemp)"
{
    echo "${INSTALL_LINE}"
    echo "${BLACKLIST_LINE}"
} > "${TMP_FILE}"

if [ ! -f "${CONF_FILE}" ] || ! cmp -s "${TMP_FILE}" "${CONF_FILE}"; then
    install -m 0644 "${TMP_FILE}" "${CONF_FILE}"
fi
rm -f "${TMP_FILE}"

# Unload the module if it is currently loaded
if lsmod | awk '{print $1}' | grep -qx "${MODULE}"; then
    modprobe -r "${MODULE}" 2>/dev/null || rmmod "${MODULE}" 2>/dev/null || true
fi

exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if LC_ALL=C grep -q -m 1 "^install sctp" /etc/modprobe.d/sctp.conf ; then
	
	sed -i 's#^install sctp.*#install sctp /bin/false#g' /etc/modprobe.d/sctp.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/sctp.conf
	echo "install sctp /bin/false" >> /etc/modprobe.d/sctp.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist sctp$" /etc/modprobe.d/sctp.conf ; then
	echo "blacklist sctp" >> /etc/modprobe.d/sctp.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```


---

## RHEL-08-040024 — `kernel_module_tipc_disabled`

**Prompt:** On an Ubuntu 24.04 system, the Transparent Inter-Process Communication (TIPC) protocol provides messaging between nodes in a cluster but is rarely needed and increases the kernel's attack surface; any flaw in its implementation could be exploited. Write an idempotent bash remediation script that ensures the TIPC networking protocol support cannot be loaded or used on this system, with the configuration persisting across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

CONF_FILE="/etc/modprobe.d/tipc.conf"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# Ensure the configuration directory exists
mkdir -p /etc/modprobe.d

# Create/overwrite the modprobe configuration idempotently
cat > "$CONF_FILE" <<'EOF'
# Disable loading of the TIPC kernel module
install tipc /bin/false
blacklist tipc
EOF

chmod 0644 "$CONF_FILE"

# Unload the module if currently loaded and not in use
if lsmod | awk '{print $1}' | grep -qx "tipc"; then
    if modprobe -r tipc 2>/dev/null; then
        echo "Unloaded tipc module."
    else
        echo "Warning: tipc module is loaded and could not be unloaded (may be in use). It will remain disabled after reboot." >&2
    fi
fi

echo "TIPC protocol has been disabled. Configuration written to $CONF_FILE"
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if LC_ALL=C grep -q -m 1 "^install tipc" /etc/modprobe.d/tipc.conf ; then
	
	sed -i 's#^install tipc.*#install tipc /bin/false#g' /etc/modprobe.d/tipc.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/tipc.conf
	echo "install tipc /bin/false" >> /etc/modprobe.d/tipc.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist tipc$" /etc/modprobe.d/tipc.conf ; then
	echo "blacklist tipc" >> /etc/modprobe.d/tipc.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```


---

## RHEL-08-040111 — `kernel_module_bluetooth_disabled`

**Prompt:** On an Ubuntu 24.04 system, the Bluetooth wireless subsystem expands the attack surface and is not needed in many server environments. Write an idempotent bash remediation script that prevents the Bluetooth kernel module from being loaded, both on demand and automatically, so that attempts to activate Bluetooth functionality fail. The change must persist across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

CONF_FILE="/etc/modprobe.d/bluetooth.conf"
CONF_DIR="$(dirname "${CONF_FILE}")"

mkdir -p "${CONF_DIR}"

DESIRED_CONTENT="install bluetooth /bin/false
blacklist bluetooth"

if [[ -f "${CONF_FILE}" ]] && [[ "$(cat "${CONF_FILE}")" == "${DESIRED_CONTENT}" ]]; then
    echo "Bluetooth module already blacklisted in ${CONF_FILE}; no change needed."
else
    printf '%s\n' "${DESIRED_CONTENT}" > "${CONF_FILE}"
    chmod 0644 "${CONF_FILE}"
    echo "Wrote Bluetooth blacklist configuration to ${CONF_FILE}."
fi

if lsmod | grep -q '^bluetooth'; then
    echo "Attempting to unload the currently loaded bluetooth module..."
    if modprobe -r bluetooth 2>/dev/null; then
        echo "Bluetooth module unloaded."
    else
        echo "Could not unload bluetooth module now (likely in use); the change will take effect on reboot." >&2
    fi
else
    echo "Bluetooth module is not currently loaded."
fi

if command -v systemctl >/dev/null 2>&1; then
    if systemctl list-unit-files | grep -q '^bluetooth.service'; then
        systemctl disable --now bluetooth.service 2>/dev/null || true
        systemctl mask bluetooth.service 2>/dev/null || true
        echo "bluetooth.service disabled and masked."
    fi
fi

echo "Bluetooth remediation complete."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if LC_ALL=C grep -q -m 1 "^install bluetooth" /etc/modprobe.d/bluetooth.conf ; then
	
	sed -i 's#^install bluetooth.*#install bluetooth /bin/false#g' /etc/modprobe.d/bluetooth.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/bluetooth.conf
	echo "install bluetooth /bin/false" >> /etc/modprobe.d/bluetooth.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist bluetooth$" /etc/modprobe.d/bluetooth.conf ; then
	echo "blacklist bluetooth" >> /etc/modprobe.d/bluetooth.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```


---

## RHEL-08-040025 — `kernel_module_cramfs_disabled`

**Prompt:** On an Ubuntu 24.04 system, reduce the kernel's local attack surface by ensuring that support for the cramfs filesystem—an uncommon compressed read-only filesystem—is disabled, so that its kernel module cannot be loaded automatically or on demand. Write an idempotent bash remediation script that persistently prevents this filesystem type from being loaded or used across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

MODULE="cramfs"
CONF_DIR="/etc/modprobe.d"
CONF_FILE="${CONF_DIR}/${MODULE}.conf"

# Ensure the modprobe.d directory exists
if [ ! -d "${CONF_DIR}" ]; then
    mkdir -p "${CONF_DIR}"
fi

# Desired configuration content
TMP_FILE="$(mktemp)"
cat > "${TMP_FILE}" <<EOF
# Disable ${MODULE} filesystem to reduce kernel attack surface
install ${MODULE} /bin/false
blacklist ${MODULE}
EOF

# Write idempotently: only update if content differs
if [ ! -f "${CONF_FILE}" ] || ! cmp -s "${TMP_FILE}" "${CONF_FILE}"; then
    install -m 0644 -o root -g root "${TMP_FILE}" "${CONF_FILE}"
    echo "Updated ${CONF_FILE}"
else
    echo "${CONF_FILE} already up to date"
fi

rm -f "${TMP_FILE}"

# Unload the module if it is currently loaded and not in use
if lsmod | awk '{print $1}' | grep -qx "${MODULE}"; then
    if rmmod "${MODULE}" 2>/dev/null; then
        echo "Unloaded currently loaded module ${MODULE}"
    else
        echo "Warning: could not unload ${MODULE} (may be in use); it will remain disabled after reboot"
    fi
else
    echo "Module ${MODULE} is not currently loaded"
fi

echo "Remediation complete: ${MODULE} is disabled and prevented from loading."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if LC_ALL=C grep -q -m 1 "^install cramfs" /etc/modprobe.d/cramfs.conf ; then
	
	sed -i 's#^install cramfs.*#install cramfs /bin/false#g' /etc/modprobe.d/cramfs.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/cramfs.conf
	echo "install cramfs /bin/false" >> /etc/modprobe.d/cramfs.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist cramfs$" /etc/modprobe.d/cramfs.conf ; then
	echo "blacklist cramfs" >> /etc/modprobe.d/cramfs.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```


---

## RHEL-08-040080 — `kernel_module_usb-storage_disabled`

**Prompt:** On an Ubuntu 24.04 system, prevent the use of USB mass-storage devices, which can be used to exfiltrate data or introduce malicious software, by configuring the kernel module subsystem so that the USB storage driver is neither automatically loaded nor loadable through the normal module-loading mechanism. Write an idempotent bash remediation script that disables and blacklists this driver so the change persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

MODULE="usb-storage"
CONF_FILE="/etc/modprobe.d/usb-storage.conf"

# Ensure the modprobe.d directory exists
mkdir -p /etc/modprobe.d

# Desired configuration lines
INSTALL_LINE="install ${MODULE} /bin/false"
BLACKLIST_LINE="blacklist ${MODULE}"

# Create or update the configuration file idempotently
NEED_WRITE=0

if [ ! -f "${CONF_FILE}" ]; then
    NEED_WRITE=1
else
    if ! grep -Eq "^[[:space:]]*install[[:space:]]+${MODULE}[[:space:]]+/bin/false[[:space:]]*$" "${CONF_FILE}"; then
        NEED_WRITE=1
    fi
    if ! grep -Eq "^[[:space:]]*blacklist[[:space:]]+${MODULE}[[:space:]]*$" "${CONF_FILE}"; then
        NEED_WRITE=1
    fi
fi

if [ "${NEED_WRITE}" -eq 1 ]; then
    {
        echo "${INSTALL_LINE}"
        echo "${BLACKLIST_LINE}"
    } > "${CONF_FILE}"
    chmod 0644 "${CONF_FILE}"
    echo "Wrote configuration to ${CONF_FILE}"
else
    echo "Configuration in ${CONF_FILE} already correct"
fi

# Unload the module if it is currently loaded (best effort)
if lsmod | grep -q "^${MODULE//-/_}\b"; then
    if rmmod "${MODULE}" 2>/dev/null; then
        echo "Unloaded currently loaded module ${MODULE}"
    else
        echo "Warning: could not unload ${MODULE} (may be in use); it will remain disabled after reboot" >&2
    fi
fi

# Update initramfs so the change persists in early boot as well
if command -v update-initramfs >/dev/null 2>&1; then
    update-initramfs -u
    echo "Regenerated initramfs"
fi

echo "USB mass-storage driver (${MODULE}) has been disabled and blacklisted."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if LC_ALL=C grep -q -m 1 "^install usb-storage" /etc/modprobe.d/usb-storage.conf ; then
	
	sed -i 's#^install usb-storage.*#install usb-storage /bin/false#g' /etc/modprobe.d/usb-storage.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/usb-storage.conf
	echo "install usb-storage /bin/false" >> /etc/modprobe.d/usb-storage.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist usb-storage$" /etc/modprobe.d/usb-storage.conf ; then
	echo "blacklist usb-storage" >> /etc/modprobe.d/usb-storage.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```


---

## RHEL-08-010571 — `mount_option_boot_nosuid`

**Prompt:** On an Ubuntu 24.04 system, the boot partition should never need to honor set-user-ID or set-group-ID permission bits, and allowing them there expands the attack surface for privilege escalation. Write an idempotent bash remediation script that ensures the boot partition is mounted in a way that prevents the operating system from honoring SUID/SGID bits on files stored there, with the setting taking effect on the running system and persisting across reboots. If the boot partition is not a separately mounted filesystem, the script should handle that gracefully.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: ensure /boot is mounted with nosuid to prevent the OS from
# honoring SUID/SGID bits on files stored there. Idempotent.
#

set -euo pipefail

MOUNT_POINT="/boot"
FSTAB="/etc/fstab"

log() {
    printf '%s\n' "$*"
}

# Require root to modify fstab and remount.
if [[ "${EUID}" -ne 0 ]]; then
    log "This script must be run as root." >&2
    exit 1
fi

# Determine whether /boot is a separately mounted filesystem.
if ! mountpoint -q "${MOUNT_POINT}"; then
    log "${MOUNT_POINT} is not a separately mounted filesystem; nothing to remediate."
    exit 0
fi

# --- Persist the setting in /etc/fstab ---------------------------------------
if [[ ! -f "${FSTAB}" ]]; then
    log "${FSTAB} not found; cannot persist mount options." >&2
    exit 1
fi

# Back up fstab once.
backup="${FSTAB}.bak.$(date +%Y%m%d%H%M%S)"
cp -a "${FSTAB}" "${backup}"
log "Backed up ${FSTAB} to ${backup}"

# Rewrite the fstab line for /boot to ensure 'nosuid' is present in the options.
tmp="$(mktemp)"
updated=0
found=0

while IFS= read -r line || [[ -n "${line}" ]]; do
    # Preserve comments and blank lines verbatim.
    if [[ "${line}" =~ ^[[:space:]]*# ]] || [[ -z "${line// }" ]]; then
        printf '%s\n' "${line}" >>"${tmp}"
        continue
    fi

    # Split into fields.
    read -r f_spec f_mount f_type f_opts f_dump f_pass rest <<<"${line}"

    if [[ "${f_mount}" == "${MOUNT_POINT}" ]]; then
        found=1

        # Default options if empty.
        if [[ -z "${f_opts}" || "${f_opts}" == "-" ]]; then
            f_opts="defaults"
        fi

        # Check whether nosuid is already present.
        if [[ ",${f_opts}," == *",nosuid,"* ]]; then
            printf '%s\n' "${line}" >>"${tmp}"
        else
            new_opts="${f_opts},nosuid"
            # Preserve dump/pass fields if present, else supply sensible defaults.
            f_dump="${f_dump:-0}"
            f_pass="${f_pass:-0}"
            printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
                "${f_spec}" "${f_mount}" "${f_type}" "${new_opts}" "${f_dump}" "${f_pass}" >>"${tmp}"
            updated=1
        fi
    else
        printf '%s\n' "${line}" >>"${tmp}"
    fi
done <"${FSTAB}"

if [[ "${found}" -eq 0 ]]; then
    log "No ${MOUNT_POINT} entry found in ${FSTAB}, though it is mounted."
    log "Refusing to fabricate an fstab entry; remounting live only."
    rm -f "${tmp}"
else
    if [[ "${updated}" -eq 1 ]]; then
        cat "${tmp}" >"${FSTAB}"
        log "Updated ${FSTAB}: added 'nosuid' to ${MOUNT_POINT} options."
    else
        log "${FSTAB} already contains 'nosuid' for ${MOUNT_POINT}; no change needed."
    fi
    rm -f "${tmp}"
fi

# --- Apply the setting to the running system ---------------------------------
# Remount honoring nosuid immediately.
if mount | grep -E "on ${MOUNT_POINT} " | grep -qw "nosuid"; then
    log "${MOUNT_POINT} is already mounted with 'nosuid' on the running system."
else
    if mount -o remount,nosuid "${MOUNT_POINT}"; then
        log "Remounted ${MOUNT_POINT} with 'nosuid' on the running system."
    else
        log "Failed to remount ${MOUNT_POINT} with 'nosuid'." >&2
        exit 1
    fi
fi

log "Remediation complete."
exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if ( ! ( { rpm --quiet -q kernel ;} && { rpm --quiet -q rpm-ostree ;} && { rpm --quiet -q bootc ;} && { ! rpm --quiet -q openshift-kubelet ;} ) && ! ( [ -f /.dockerenv ] || [ -f /run/.containerenv ] ) ); then

function perform_remediation {
    
        # the mount point /boot has to be defined in /etc/fstab
        # before this remediation can be executed. In case it is not defined, the
        # remediation aborts and no changes regarding the mount point are done.
        mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" "/boot")"

    grep "$mount_point_match_regexp" -q /etc/fstab \
        || { echo "Th
```


---

## RHEL-08-040120 — `mount_option_dev_shm_nodev`

**Prompt:** On an Ubuntu 24.04 system, the shared-memory temporary filesystem mounted at /dev/shm should not permit the interpretation of device files, since legitimate character and block device files belong only under the system device directory and allowing them in a world-writable temporary area could be abused to bypass access controls. Write an idempotent bash remediation script that ensures the /dev/shm filesystem disallows device-file interpretation, applied immediately and persistently across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

FSTAB="/etc/fstab"
MOUNT_POINT="/dev/shm"
REQUIRED_OPT="nodev"

# --- Ensure a persistent entry exists in /etc/fstab with the nodev option ---

if grep -qE '^\s*[^#].*\s+/dev/shm\s+' "$FSTAB"; then
    # An entry for /dev/shm exists; ensure it has nodev in its options.
    awk -v mp="$MOUNT_POINT" -v opt="$REQUIRED_OPT" '
    {
        if ($0 ~ /^[[:space:]]*#/ || $0 !~ ("[[:space:]]"mp"[[:space:]]")) {
            print $0
            next
        }
        # Split into fields, field 4 is the options
        n = split($0, f, /[[:space:]]+/)
        # Rebuild preserving original tokens
        # Find the mount point field index
        for (i = 1; i <= n; i++) {
            if (f[i] == mp) { mpidx = i; break }
        }
        optidx = mpidx + 2
        # Check if opt already present
        split(f[optidx], opts, ",")
        found = 0
        for (j in opts) {
            if (opts[j] == opt) { found = 1 }
        }
        if (found == 0) {
            f[optidx] = f[optidx] "," opt
        }
        line = f[1]
        for (i = 2; i <= n; i++) {
            line = line " " f[i]
        }
        print line
    }
    ' "$FSTAB" > "${FSTAB}.tmp"
    if ! cmp -s "${FSTAB}.tmp" "$FSTAB"; then
        cp -a "$FSTAB" "${FSTAB}.bak.$(date +%Y%m%d%H%M%S)"
        mv "${FSTAB}.tmp" "$FSTAB"
    else
        rm -f "${FSTAB}.tmp"
    fi
else
    # No entry; add a standard tmpfs entry for /dev/shm with secure options.
    printf 'tmpfs %s tmpfs defaults,nodev,nosuid,noexec 0 0\n' "$MOUNT_POINT" >> "$FSTAB"
fi

# --- Apply immediately ---

if mountpoint -q "$MOUNT_POINT"; then
    mount -o remount,nodev "$MOUNT_POINT"
else
    mount "$MOUNT_POINT"
fi

# --- Verify ---

if findmnt -kn -o OPTIONS "$MOUNT_POINT" | grep -qw "$REQUIRED_OPT"; then
    echo "Success: $MOUNT_POINT is mounted with '$REQUIRED_OPT'."
else
    echo "Error: failed to apply '$REQUIRED_OPT' to $MOUNT_POINT." >&2
    exit 1
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if ( ! ( { rpm --quiet -q kernel ;} && { rpm --quiet -q rpm-ostree ;} && { rpm --quiet -q bootc ;} && { ! rpm --quiet -q openshift-kubelet ;} ) && ! ( [ -f /.dockerenv ] || [ -f /run/.containerenv ] ) ); then

function perform_remediation {
    


    mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" /dev/shm)"

    # If the mount point is not in /etc/fstab, get previous mount options from /etc/mtab
    if ! grep -q "$mount_point_match_regexp" /etc/fstab; then
        # runtime opts without some automatic kernel/userspace-added defaults
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/mtab
```


---

## RHEL-08-040122 — `mount_option_dev_shm_noexec`

**Prompt:** On an Ubuntu 24.04 system, the shared-memory temporary filesystem (the world-writable in-memory storage mounted at /dev/shm) currently permits executing binaries from it, which attackers can abuse to run malicious code from world-writable storage. Write an idempotent bash remediation script that ensures this shared-memory filesystem is configured to forbid execution of binaries, with the setting applied to the active mount and persisting across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

FSTAB="/etc/fstab"
MOUNT_POINT="/dev/shm"

# Ensure we are running as root
if [[ "$(id -u)" -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# --- 1. Ensure /etc/fstab has a persistent entry for /dev/shm with noexec ---

if grep -qE '^[^#]*[[:space:]]+/dev/shm[[:space:]]' "$FSTAB"; then
    # An entry already exists; ensure it has noexec (and keep nosuid/nodev if present)
    while IFS= read -r line; do
        # Match the /dev/shm entry (non-commented)
        if [[ "$line" =~ ^[^#]*[[:space:]]+/dev/shm[[:space:]] ]]; then
            # Split into fields
            read -r f_spec f_file f_vfstype f_opts f_dump f_pass <<< "$line"

            # Normalize options: ensure noexec present
            opts="$f_opts"
            if [[ ",$opts," != *",noexec,"* ]]; then
                if [[ -z "$opts" || "$opts" == "defaults" ]]; then
                    opts="defaults,noexec"
                else
                    opts="${opts},noexec"
                fi
            fi

            # Provide defaults for possibly-missing dump/pass fields
            f_dump="${f_dump:-0}"
            f_pass="${f_pass:-0}"

            printf '%s\t%s\t%s\t%s\t%s %s\n' \
                "$f_spec" "$f_file" "$f_vfstype" "$opts" "$f_dump" "$f_pass"
        else
            printf '%s\n' "$line"
        fi
    done < "$FSTAB" > "${FSTAB}.tmp.$$"

    mv "${FSTAB}.tmp.$$" "$FSTAB"
else
    # No entry exists; append one
    printf 'tmpfs\t/dev/shm\ttmpfs\tdefaults,noexec,nodev,nosuid\t0 0\n' >> "$FSTAB"
fi

# --- 2. Apply the setting to the currently active mount ---

if mountpoint -q "$MOUNT_POINT"; then
    mount -o remount "$MOUNT_POINT"
else
    mount "$MOUNT_POINT" 2>/dev/null || mount -t tmpfs -o defaults,noexec,nodev,nosuid tmpfs "$MOUNT_POINT"
fi

# --- 3. Verify noexec is active ---

if findmnt -no OPTIONS "$MOUNT_POINT" | grep -qw noexec; then
    echo "Success: $MOUNT_POINT is mounted with noexec."
else
    echo "Error: failed to apply noexec to $MOUNT_POINT." >&2
    exit 1
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if ( ! ( { rpm --quiet -q kernel ;} && { rpm --quiet -q rpm-ostree ;} && { rpm --quiet -q bootc ;} && { ! rpm --quiet -q openshift-kubelet ;} ) && ! ( [ -f /.dockerenv ] || [ -f /run/.containerenv ] ) ); then

function perform_remediation {
    


    mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" /dev/shm)"

    # If the mount point is not in /etc/fstab, get previous mount options from /etc/mtab
    if ! grep -q "$mount_point_match_regexp" /etc/fstab; then
        # runtime opts without some automatic kernel/userspace-added defaults
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/mtab
```


---

## RHEL-08-040121 — `mount_option_dev_shm_nosuid`

**Prompt:** On an Ubuntu 24.04 system, the shared-memory filesystem mounted at /dev/shm is world-writable, and allowing setuid/setgid binaries to take effect there gives attackers a path to privilege escalation. Configure this shared-memory mount so that the setuid and setgid bits on any executables stored there are ignored, and ensure this protection is active immediately and persists across reboots. Write an idempotent bash remediation script that enforces this.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

FSTAB="/etc/fstab"
MOUNT="/dev/shm"
BACKUP="${FSTAB}.bak.$(date +%Y%m%d%H%M%S)"

# Ensure we run as root
if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# Backup fstab before modifying
cp -a "${FSTAB}" "${BACKUP}"

# Desired options for /dev/shm
DESIRED_OPTS="defaults,nosuid,nodev,noexec"

# Check whether an entry for /dev/shm already exists (ignoring comments)
if awk -v m="${MOUNT}" '($1 !~ /^#/) && ($2 == m) {found=1} END{exit !found}' "${FSTAB}"; then
    # Entry exists: ensure nosuid (and nodev) are present in its options field
    awk -v m="${MOUNT}" '
    {
        if ($1 !~ /^#/ && $2 == m) {
            n = split($4, opts, ",")
            has_nosuid = 0; has_nodev = 0
            for (i = 1; i <= n; i++) {
                if (opts[i] == "nosuid") has_nosuid = 1
                if (opts[i] == "nodev")  has_nodev = 1
            }
            newopts = $4
            if (!has_nosuid) newopts = newopts ",nosuid"
            if (!has_nodev)  newopts = newopts ",nodev"
            $4 = newopts
            # Rebuild line with single spaces
            printf "%s %s %s %s %s %s\n", $1, $2, $3, $4, $5, $6
            next
        }
        print
    }' "${FSTAB}" > "${FSTAB}.tmp"
    mv "${FSTAB}.tmp" "${FSTAB}"
else
    # No entry: add one
    printf "tmpfs %s tmpfs %s 0 0\n" "${MOUNT}" "${DESIRED_OPTS}" >> "${FSTAB}"
fi

# If fstab was unchanged, remove the redundant backup
if cmp -s "${FSTAB}" "${BACKUP}"; then
    rm -f "${BACKUP}"
fi

# Apply immediately: remount with nosuid (and nodev) active now
if mountpoint -q "${MOUNT}"; then
    mount -o remount,nosuid,nodev "${MOUNT}"
else
    mount "${MOUNT}"
fi

# Verify nosuid is active
if mount | grep -E " on ${MOUNT} " | grep -q "nosuid"; then
    echo "Success: ${MOUNT} is mounted with nosuid."
else
    echo "Warning: nosuid does not appear active on ${MOUNT}." >&2
    exit 1
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if ( ! ( { rpm --quiet -q kernel ;} && { rpm --quiet -q rpm-ostree ;} && { rpm --quiet -q bootc ;} && { ! rpm --quiet -q openshift-kubelet ;} ) && ! ( [ -f /.dockerenv ] || [ -f /run/.containerenv ] ) ); then

function perform_remediation {
    


    mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" /dev/shm)"

    # If the mount point is not in /etc/fstab, get previous mount options from /etc/mtab
    if ! grep -q "$mount_point_match_regexp" /etc/fstab; then
        # runtime opts without some automatic kernel/userspace-added defaults
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/mtab
```


---

## RHEL-08-010580 — `mount_option_nodev_nonroot_local_partitions`

**Prompt:** On an Ubuntu 24.04 system, ensure that every non-root local filesystem is mounted in a way that prevents any files on it from being interpreted as character or block device nodes, since legitimate device files should exist only under the root partition's device directory (or within purpose-built chroot jails). Permitting device-node interpretation on other partitions could let an attacker plant rogue device files to gain unauthorized access to underlying hardware or memory. Write an idempotent bash remediation script that applies this protection to all non-root local partitions so that it persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Ensure every non-root local filesystem is mounted with the "nodev" option
# so that no files on it can be interpreted as character or block device nodes.
# This script is idempotent and makes the change persist across reboots by
# editing /etc/fstab, then re-applies the option to currently mounted FS.

set -euo pipefail

FSTAB="/etc/fstab"
TIMESTAMP="$(date +%Y%m%d%H%M%S)"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

if [[ ! -f "$FSTAB" ]]; then
    echo "Error: $FSTAB not found." >&2
    exit 1
fi

# Local (non-network, non-virtual) filesystem types we care about.
LOCAL_FS_TYPES="ext2 ext3 ext4 xfs btrfs jfs reiserfs vfat ntfs f2fs exfat"

is_local_fs() {
    local fstype="$1"
    for t in $LOCAL_FS_TYPES; do
        [[ "$fstype" == "$t" ]] && return 0
    done
    return 1
}

# Add nodev to an options string if it is not already present.
add_nodev_opt() {
    local opts="$1"
    # Split, check, rebuild.
    if [[ ",$opts," == *",nodev,"* ]]; then
        echo "$opts"
        return
    fi
    if [[ -z "$opts" || "$opts" == "defaults" ]]; then
        echo "defaults,nodev"
    else
        echo "${opts},nodev"
    fi
}

backup_made=0
make_backup() {
    if [[ $backup_made -eq 0 ]]; then
        cp -a "$FSTAB" "${FSTAB}.bak.${TIMESTAMP}"
        echo "Backup of $FSTAB saved to ${FSTAB}.bak.${TIMESTAMP}"
        backup_made=1
    fi
}

TMP_FSTAB="$(mktemp)"
trap 'rm -f "$TMP_FSTAB"' EXIT

changed=0

# Process /etc/fstab.
while IFS= read -r line || [[ -n "$line" ]]; do
    # Preserve blank lines and comments verbatim.
    if [[ -z "${line// }" || "$line" =~ ^[[:space:]]*# ]]; then
        printf '%s\n' "$line" >> "$TMP_FSTAB"
        continue
    fi

    # Parse fields.
    read -r spec mountpoint fstype options dump pass rest <<< "$line"

    # If the line is malformed (missing fields), pass it through unchanged.
    if [[ -z "$spec" || -z "$mountpoint" || -z "$fstype" || -z "$options" ]]; then
        printf '%s\n' "$line" >> "$TMP_FSTAB"
        continue
    fi

    # Skip the root filesystem.
    if [[ "$mountpoint" == "/" ]]; then
        printf '%s\n' "$line" >> "$TMP_FSTAB"
        continue
    fi

    # Only act on local filesystem types.
    if ! is_local_fs "$fstype"; then
        printf '%s\n' "$line" >> "$TMP_FSTAB"
        continue
    fi

    new_options="$(add_nodev_opt "$options")"

    if [[ "$new_options" != "$options" ]]; then
        changed=1
        # Rebuild the line preserving alignment reasonably.
        dump="${dump:-0}"
        pass="${pass:-0}"
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$spec" "$mountpoint" "$fstype" "$new_options" "$dump" "$pass" >> "$TMP_FSTAB"
        echo "Adding 'nodev' to $mountpoint ($fstype) in fstab."
    else
        printf '%s\n' "$line" >> "$TMP_FSTAB"
    fi
done < "$FSTAB"

if [[ $changed -eq 1 ]]; then
    make_backup
    cat "$TMP_FSTAB" > "$FSTAB"
    echo "$FSTAB updated."
else
    echo "$FSTAB already compliant; no changes needed."
fi

# Reload systemd's view of fstab if available.
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

# Re-apply nodev to currently mounted, non-root, local filesystems so the
# protection takes effect immediately without requiring a reboot.
while read -r src mnt fstype mntopts _; do
    [[ "$mnt" == "/" ]] && continue
    is_local_fs "$fstype" || continue

    if [[ ",$mntopts," != *",nodev,"* ]]; then
        echo "Remounting $mnt with nodev."
        if mount -o remount,nodev "$mnt" 2>/dev/null; then
            echo "Remounted $mnt successfully."
        else
            echo "Warning: could not remount $mnt; change will apply on next mount/reboot." >&2
        fi
    fi
done < <(findmnt -rn -o SOURCE,TARGET,FSTYPE,OPTIONS 2>/dev/null || true)

echo "nodev enforcement completed for all non-root local filesystems."
exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if ( ! ( { rpm --quiet -q kernel ;} && { rpm --quiet -q rpm-ostree ;} && { rpm --quiet -q bootc ;} && { ! rpm --quiet -q openshift-kubelet ;} ) && ! ( [ -f /.dockerenv ] || [ -f /run/.containerenv ] ) ); then

MOUNT_OPTION="nodev"
# Create array of local non-root partitions
readarray -t partitions_records < <(findmnt --mtab --raw --evaluate | grep "^/\w" | grep -v "^/proc" | grep "\s/dev/\w")

# Create array of polyinstantiated directories, in case one of them is found in mtab
readarray -t polyinstantiated_dirs < \
    <(grep -oP "^\s*[^#\s]+\s+\S+" /etc/security/namespace.conf | grep -oP "(?<=\s)\S+?(?=/?\$)")


for partition_record in "
```


---

## RHEL-08-040020 — `kernel_module_uvcvideo_disabled`

**Prompt:** On an Ubuntu 24.04 system, the built-in USB video (webcam) capability must be disabled so that the camera cannot be activated, preventing unauthorized surveillance or capture of information through a collaborative computing device. Write an idempotent bash remediation script that prevents the kernel driver responsible for USB webcams from being loaded — both ensuring it is not loaded on demand and preventing it from being loaded manually — with the change persisting across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

MODULE="uvcvideo"
CONF_FILE="/etc/modprobe.d/${MODULE}.conf"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# Ensure the modprobe.d directory exists
mkdir -p /etc/modprobe.d

# Desired configuration content
DESIRED_CONTENT="install ${MODULE} /bin/false
blacklist ${MODULE}"

# Write the config only if it differs (idempotent)
if [[ ! -f "${CONF_FILE}" ]] || [[ "$(cat "${CONF_FILE}")" != "${DESIRED_CONTENT}" ]]; then
    printf '%s\n' "${DESIRED_CONTENT}" > "${CONF_FILE}"
    chmod 0644 "${CONF_FILE}"
fi

# Unload the module now if it is currently loaded
if lsmod | grep -q "^${MODULE}\b"; then
    modprobe -r "${MODULE}" 2>/dev/null || rmmod "${MODULE}" 2>/dev/null || true
fi

# Rebuild the initramfs so the change persists across reboots
if command -v update-initramfs >/dev/null 2>&1; then
    update-initramfs -u
fi

echo "Remediation complete: ${MODULE} is disabled and blacklisted."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if LC_ALL=C grep -q -m 1 "^install uvcvideo" /etc/modprobe.d/uvcvideo.conf ; then
	
	sed -i 's#^install uvcvideo.*#install uvcvideo /bin/false#g' /etc/modprobe.d/uvcvideo.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/uvcvideo.conf
	echo "install uvcvideo /bin/false" >> /etc/modprobe.d/uvcvideo.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist uvcvideo$" /etc/modprobe.d/uvcvideo.conf ; then
	echo "blacklist uvcvideo" >> /etc/modprobe.d/uvcvideo.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```


---

## RHEL-08-010671 — `sysctl_kernel_core_pattern`

**Prompt:** On an Ubuntu 24.04 system, prevent the operating system from storing application core dumps, since these memory images can capture sensitive in-memory data and are generally only useful for debugging. Configure the system so that core dumps are not written to disk, and ensure this behavior takes effect immediately and persists across reboots. Write an idempotent bash remediation script that achieves this end state.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

# Ensure running as root
if [[ "$(id -u)" -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

#######################################
# 1. Disable core dumps via limits.conf
#######################################
LIMITS_FILE="/etc/security/limits.conf"
LIMITS_DIR="/etc/security/limits.d"
CUSTOM_LIMITS="${LIMITS_DIR}/99-disable-coredumps.conf"

mkdir -p "$LIMITS_DIR"

# Remove any conflicting core limit entries from limits.conf
if [[ -f "$LIMITS_FILE" ]]; then
    sed -i '/^\s*\*\s\+\(hard\|soft\)\s\+core\b/d' "$LIMITS_FILE"
fi

# Create/update the drop-in file idempotently
cat > "$CUSTOM_LIMITS" <<'EOF'
* hard core 0
* soft core 0
EOF
chmod 0644 "$CUSTOM_LIMITS"

#######################################
# 2. Disable setuid program core dumps via sysctl
#######################################
SYSCTL_FILE="/etc/sysctl.d/99-disable-coredumps.conf"

cat > "$SYSCTL_FILE" <<'EOF'
fs.suid_dumpable = 0
kernel.core_pattern = |/bin/false
EOF
chmod 0644 "$SYSCTL_FILE"

# Apply sysctl settings immediately
sysctl -w fs.suid_dumpable=0 >/dev/null
sysctl -w kernel.core_pattern="|/bin/false" >/dev/null

#######################################
# 3. Disable core dumps via systemd (coredump.conf)
#######################################
COREDUMP_CONF_DIR="/etc/systemd/coredump.conf.d"
COREDUMP_CONF="${COREDUMP_CONF_DIR}/99-disable-coredumps.conf"

mkdir -p "$COREDUMP_CONF_DIR"

cat > "$COREDUMP_CONF" <<'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
chmod 0644 "$COREDUMP_CONF"

#######################################
# 4. Mask systemd-coredump socket/service if present
#######################################
if systemctl list-unit-files 2>/dev/null | grep -q '^systemd-coredump\.socket'; then
    systemctl daemon-reload || true
    systemctl mask systemd-coredump.socket 2>/dev/null || true
fi

# Reload systemd to pick up coredump.conf changes
systemctl daemon-reload || true

echo "Core dump storage has been disabled and settings applied."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of kernel.core_pattern from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*kernel.core_pattern.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "kernel.core_pattern" matches to preserve user data
      se
```


---

## RHEL-08-010375 — `sysctl_kernel_dmesg_restrict`

**Prompt:** On an Ubuntu 24.04 system, unprivileged users can currently read the kernel's message (ring) buffer, which may leak sensitive kernel memory addresses that aid local privilege-escalation attacks. Write an idempotent bash remediation script that restricts read access to the kernel message buffer so that only privileged users may view it, applying the change immediately at runtime and ensuring it persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: restrict access to the kernel message (ring) buffer
# so that only privileged users may read it via dmesg / /dev/kmsg.
# Controlled by the kernel.dmesg_restrict sysctl.
#
set -euo pipefail

SYSCTL_PARAM="kernel.dmesg_restrict"
DESIRED_VALUE="1"
SYSCTL_DIR="/etc/sysctl.d"
CONF_FILE="${SYSCTL_DIR}/99-dmesg-restrict.conf"

# Must be run as root to apply changes.
if [[ "${EUID}" -ne 0 ]]; then
    echo "Error: this script must be run as root." >&2
    exit 1
fi

# Ensure the persistent configuration directory exists.
mkdir -p "${SYSCTL_DIR}"

# Write/refresh the persistent configuration idempotently.
DESIRED_LINE="${SYSCTL_PARAM} = ${DESIRED_VALUE}"
if [[ -f "${CONF_FILE}" ]] && grep -qxF "${DESIRED_LINE}" "${CONF_FILE}" 2>/dev/null \
    && [[ "$(grep -c '^[[:space:]]*'"${SYSCTL_PARAM}"'[[:space:]]*=' "${CONF_FILE}")" -eq 1 ]]; then
    echo "Persistent setting already present in ${CONF_FILE}."
else
    cat > "${CONF_FILE}" <<EOF
# Restrict access to the kernel message (ring) buffer to privileged users.
# Managed by remediation script; do not edit manually.
${DESIRED_LINE}
EOF
    chmod 0644 "${CONF_FILE}"
    echo "Wrote persistent setting to ${CONF_FILE}."
fi

# Neutralize any conflicting settings in other sysctl locations so our
# value wins after reboot (only comment out lines that set a different value).
for f in /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf; do
    [[ -f "${f}" ]] || continue
    [[ "${f}" == "${CONF_FILE}" ]] && continue
    if grep -Eq "^[[:space:]]*${SYSCTL_PARAM}[[:space:]]*=[[:space:]]*0" "${f}" 2>/dev/null; then
        sed -i -E "s|^([[:space:]]*${SYSCTL_PARAM}[[:space:]]*=[[:space:]]*0.*)$|# \1 (disabled by dmesg-restrict remediation)|" "${f}"
        echo "Disabled conflicting entry in ${f}."
    fi
done

# Apply the setting immediately at runtime.
CURRENT_VALUE="$(sysctl -n "${SYSCTL_PARAM}" 2>/dev/null || echo "")"
if [[ "${CURRENT_VALUE}" != "${DESIRED_VALUE}" ]]; then
    sysctl -w "${SYSCTL_PARAM}=${DESIRED_VALUE}" >/dev/null
    echo "Applied runtime setting: ${SYSCTL_PARAM}=${DESIRED_VALUE}."
else
    echo "Runtime setting already ${SYSCTL_PARAM}=${DESIRED_VALUE}."
fi

# Verify.
FINAL_VALUE="$(sysctl -n "${SYSCTL_PARAM}" 2>/dev/null || echo "")"
if [[ "${FINAL_VALUE}" == "${DESIRED_VALUE}" ]]; then
    echo "Success: ${SYSCTL_PARAM} is set to ${FINAL_VALUE}."
    exit 0
else
    echo "Error: failed to set ${SYSCTL_PARAM} (current value: '${FINAL_VALUE}')." >&2
    exit 1
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of kernel.dmesg_restrict from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*kernel.dmesg_restrict.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "kernel.dmesg_restrict" matches to preserve user data
  
```


---

## RHEL-08-010372 — `sysctl_kernel_kexec_load_disabled`

**Prompt:** On an Ubuntu 24.04 system, prevent the loading of a replacement kernel image into memory, which an attacker with sufficient privileges could otherwise use to boot into a malicious kernel without a normal reboot. Write an idempotent bash remediation script that disables this kernel-image-loading capability, applying it at runtime and ensuring it persists across reboots. Note that once disabled at runtime this setting cannot be re-enabled without a reboot.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: disable kexec_load (loading a replacement kernel image)
# via kernel.kexec_load_disabled sysctl on Ubuntu 24.04.
#
# This script is idempotent: it can be run multiple times safely.
# Note: once kernel.kexec_load_disabled is set to 1 at runtime it cannot
# be reset to 0 without a reboot.

set -euo pipefail

SYSCTL_KEY="kernel.kexec_load_disabled"
SYSCTL_FILE="/etc/sysctl.d/99-disable-kexec.conf"
SYSCTL_LINE="${SYSCTL_KEY} = 1"

if [[ "$(id -u)" -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# 1. Persist the setting across reboots.
if [[ -f "$SYSCTL_FILE" ]] && grep -Eq "^\s*${SYSCTL_KEY}\s*=\s*1\s*$" "$SYSCTL_FILE"; then
    echo "Persistent setting already present in ${SYSCTL_FILE}."
else
    # Remove any conflicting/existing entries for this key, then add ours.
    if [[ -f "$SYSCTL_FILE" ]]; then
        sed -i "\|^\s*${SYSCTL_KEY}\s*=|d" "$SYSCTL_FILE"
    fi
    echo "$SYSCTL_LINE" >> "$SYSCTL_FILE"
    echo "Wrote persistent setting to ${SYSCTL_FILE}."
fi

# 2. Apply at runtime (only if not already disabled, since it can't be undone).
current="$(sysctl -n "$SYSCTL_KEY" 2>/dev/null || echo "0")"
if [[ "$current" == "1" ]]; then
    echo "Runtime setting ${SYSCTL_KEY} is already 1; nothing to change."
else
    sysctl -w "${SYSCTL_KEY}=1" >/dev/null
    echo "Applied runtime setting ${SYSCTL_KEY}=1."
fi

echo "kexec kernel-image loading has been disabled."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of kernel.kexec_load_disabled from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*kernel.kexec_load_disabled.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "kernel.kexec_load_disabled" matches to preser
```


---

## RHEL-08-010376 — `sysctl_kernel_perf_event_paranoid`

**Prompt:** On an Ubuntu 24.04 system, unprivileged users can currently use kernel performance-monitoring facilities in ways that may disclose sensitive information about kernel behavior. Configure the system so that unprivileged users are restricted to the most limited level of access to performance event monitoring (allowing only per-process kernel and CPU profiling, while disallowing the broader unprivileged profiling capabilities). Write an idempotent bash remediation script that applies this restriction immediately at runtime and ensures it persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

SYSCTL_PARAM="kernel.perf_event_paranoid"
SYSCTL_VALUE="3"
CONF_FILE="/etc/sysctl.d/99-perf-event-paranoid.conf"

# Ensure the sysctl drop-in directory exists
mkdir -p /etc/sysctl.d

# Remove any existing definitions of this parameter from common sysctl files
for f in /etc/sysctl.conf /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
    [ -f "$f" ] || continue
    if [ "$f" != "$CONF_FILE" ]; then
        if grep -Eq "^[[:space:]]*${SYSCTL_PARAM}[[:space:]]*=" "$f" 2>/dev/null; then
            sed -i -E "/^[[:space:]]*${SYSCTL_PARAM}[[:space:]]*=.*/d" "$f"
        fi
    fi
done

# Write the persistent configuration idempotently
printf '%s = %s\n' "$SYSCTL_PARAM" "$SYSCTL_VALUE" > "$CONF_FILE"
chmod 0644 "$CONF_FILE"

# Apply the setting immediately at runtime
sysctl -w "${SYSCTL_PARAM}=${SYSCTL_VALUE}" >/dev/null

# Verify the runtime value
CURRENT_VALUE="$(sysctl -n "$SYSCTL_PARAM")"
if [ "$CURRENT_VALUE" != "$SYSCTL_VALUE" ]; then
    echo "ERROR: Failed to set ${SYSCTL_PARAM} to ${SYSCTL_VALUE} (current: ${CURRENT_VALUE})" >&2
    exit 1
fi

echo "${SYSCTL_PARAM} is set to ${SYSCTL_VALUE} (runtime and persistent)."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of kernel.perf_event_paranoid from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*kernel.perf_event_paranoid.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "kernel.perf_event_paranoid" matches to preser
```


---

## RHEL-08-040281 — `sysctl_kernel_unprivileged_bpf_disabled`

**Prompt:** On an Ubuntu 24.04 system, unprivileged processes can currently invoke the kernel's Berkeley Packet Filter facility to load and access packet-filter programs and maps, which risks exposing sensitive kernel state. Write an idempotent bash remediation script that prevents unprivileged (non-root) processes from using this packet-filter syscall, ensuring the restriction takes effect at runtime and persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

SYSCTL_KEY="kernel.unprivileged_bpf_disabled"
SYSCTL_VALUE="1"
CONF_FILE="/etc/sysctl.d/99-disable-unprivileged-bpf.conf"

# Persist the setting across reboots (idempotently)
DESIRED_LINE="${SYSCTL_KEY} = ${SYSCTL_VALUE}"

if [[ -f "$CONF_FILE" ]] && grep -Eq "^\s*${SYSCTL_KEY}\s*=" "$CONF_FILE"; then
    # Replace any existing line for this key to ensure correct value
    sed -i -E "s|^\s*${SYSCTL_KEY}\s*=.*|${DESIRED_LINE}|" "$CONF_FILE"
else
    # Remove any stray occurrences elsewhere isn't needed; just ensure our file has it
    if [[ -f "$CONF_FILE" ]]; then
        # File exists but without the key
        printf '%s\n' "$DESIRED_LINE" >> "$CONF_FILE"
    else
        printf '%s\n' "# Disable unprivileged BPF syscall access" "$DESIRED_LINE" > "$CONF_FILE"
    fi
fi

# Apply at runtime
sysctl -w "${SYSCTL_KEY}=${SYSCTL_VALUE}" >/dev/null

# Verify
CURRENT="$(sysctl -n "${SYSCTL_KEY}" 2>/dev/null || echo "")"
if [[ "$CURRENT" == "$SYSCTL_VALUE" ]]; then
    echo "Unprivileged BPF is now disabled (${SYSCTL_KEY}=${CURRENT})."
    echo "Persistent configuration written to ${CONF_FILE}."
else
    echo "Failed to set ${SYSCTL_KEY} to ${SYSCTL_VALUE} (current: '${CURRENT}')." >&2
    exit 1
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of kernel.unprivileged_bpf_disabled from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*kernel.unprivileged_bpf_disabled.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "kernel.unprivileged_bpf_disabled"
```


---

## RHEL-08-040282 — `sysctl_kernel_yama_ptrace_scope`

**Prompt:** On an Ubuntu 24.04 system, the process-tracing facility is currently unrestricted, allowing a compromised program to inspect or manipulate other processes owned by the same user and steal sensitive data such as SSH sessions or browser memory. Configure the system so that process tracing is restricted to direct descendant processes only, preventing arbitrary same-user process attachment. Write an idempotent bash remediation script that applies this restriction immediately and ensures it persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

SYSCTL_KEY="kernel.yama.ptrace_scope"
DESIRED_VALUE="1"
CONF_FILE="/etc/sysctl.d/10-ptrace.conf"

if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# Apply the setting immediately (runtime).
current_value="$(sysctl -n "${SYSCTL_KEY}" 2>/dev/null || echo "")"
if [[ "${current_value}" != "${DESIRED_VALUE}" ]]; then
    sysctl -w "${SYSCTL_KEY}=${DESIRED_VALUE}"
else
    echo "Runtime ${SYSCTL_KEY} already set to ${DESIRED_VALUE}."
fi

# Ensure persistence across reboots (idempotent).
desired_line="${SYSCTL_KEY} = ${DESIRED_VALUE}"

if [[ -f "${CONF_FILE}" ]] && grep -Eq "^\s*${SYSCTL_KEY}\s*=\s*${DESIRED_VALUE}\s*$" "${CONF_FILE}"; then
    echo "Persistent configuration already present in ${CONF_FILE}."
else
    tmp_file="$(mktemp)"
    if [[ -f "${CONF_FILE}" ]]; then
        # Remove any existing ptrace_scope lines, keep everything else.
        grep -Ev "^\s*${SYSCTL_KEY}\s*=" "${CONF_FILE}" > "${tmp_file}" || true
    fi
    echo "${desired_line}" >> "${tmp_file}"
    install -m 0644 -o root -g root "${tmp_file}" "${CONF_FILE}"
    rm -f "${tmp_file}"
    echo "Wrote persistent configuration to ${CONF_FILE}."
fi

# Reload sysctl settings to confirm persistence file is valid and applied.
sysctl -p "${CONF_FILE}" >/dev/null

# Verify final state.
final_value="$(sysctl -n "${SYSCTL_KEY}")"
if [[ "${final_value}" == "${DESIRED_VALUE}" ]]; then
    echo "Success: ${SYSCTL_KEY} is now ${final_value} (restricted to child processes)."
else
    echo "Error: ${SYSCTL_KEY} is ${final_value}, expected ${DESIRED_VALUE}." >&2
    exit 1
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of kernel.yama.ptrace_scope from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*kernel.yama.ptrace_scope.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "kernel.yama.ptrace_scope" matches to preserve use
```


---

## RHEL-08-040286 — `sysctl_net_core_bpf_jit_harden`

**Prompt:** On an Ubuntu 24.04 system, the kernel's extended Berkeley Packet Filter just-in-time compiler can leak kernel addresses and is a known target for exploitation. Configure the system so that the BPF JIT compiler runs in its fully hardened mode for all users (the strongest available setting, which randomizes addresses in BPF programs and maps and avoids exposing JIT addresses). Write an idempotent bash remediation script that applies this hardening at runtime and ensures it persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PARAM="net.core.bpf_jit_harden"
VALUE="2"
PROC_PATH="/proc/sys/net/core/bpf_jit_harden"
CONF_DIR="/etc/sysctl.d"
CONF_FILE="${CONF_DIR}/99-bpf-jit-harden.conf"

if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# Ensure the sysctl parameter exists on this kernel
if [[ ! -e "${PROC_PATH}" ]]; then
    echo "Error: ${PROC_PATH} does not exist; BPF JIT hardening is not supported on this kernel." >&2
    exit 1
fi

# Ensure the sysctl.d directory exists
mkdir -p "${CONF_DIR}"

# Write the persistent configuration idempotently
DESIRED_LINE="${PARAM} = ${VALUE}"
NEED_WRITE=1
if [[ -f "${CONF_FILE}" ]]; then
    if grep -Eq "^[[:space:]]*${PARAM}[[:space:]]*=[[:space:]]*${VALUE}[[:space:]]*$" "${CONF_FILE}"; then
        # Ensure no other conflicting lines exist in this file
        if ! grep -Eq "^[[:space:]]*${PARAM}[[:space:]]*=" <(grep -Ev "^[[:space:]]*${PARAM}[[:space:]]*=[[:space:]]*${VALUE}[[:space:]]*$" "${CONF_FILE}"); then
            NEED_WRITE=0
        fi
    fi
fi

if [[ "${NEED_WRITE}" -eq 1 ]]; then
    tmpfile="$(mktemp)"
    if [[ -f "${CONF_FILE}" ]]; then
        grep -Ev "^[[:space:]]*${PARAM}[[:space:]]*=" "${CONF_FILE}" > "${tmpfile}" || true
    fi
    echo "${DESIRED_LINE}" >> "${tmpfile}"
    install -m 0644 "${tmpfile}" "${CONF_FILE}"
    rm -f "${tmpfile}"
    echo "Persistent configuration written to ${CONF_FILE}"
else
    echo "Persistent configuration already correct in ${CONF_FILE}"
fi

# Apply at runtime idempotently
CURRENT_VALUE="$(cat "${PROC_PATH}")"
if [[ "${CURRENT_VALUE}" != "${VALUE}" ]]; then
    sysctl -w "${PARAM}=${VALUE}" >/dev/null
    echo "Runtime value set: ${PARAM}=${VALUE}"
else
    echo "Runtime value already set: ${PARAM}=${VALUE}"
fi

# Verify
FINAL_VALUE="$(cat "${PROC_PATH}")"
if [[ "${FINAL_VALUE}" == "${VALUE}" ]]; then
    echo "BPF JIT hardening is active (${PARAM}=${FINAL_VALUE})."
else
    echo "Error: failed to apply ${PARAM}=${VALUE} (current: ${FINAL_VALUE})." >&2
    exit 1
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of net.core.bpf_jit_harden from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.core.bpf_jit_harden.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.core.bpf_jit_harden" matches to preserve user d
```


---

## None — `sysctl_user_max_user_namespaces`

**Prompt:** On an Ubuntu 24.04 system that does not run Linux containers, the kernel's user-namespace feature presents an unnecessary attack surface that has been the source of multiple privilege-escalation vulnerabilities. Write an idempotent bash remediation script that completely disables the ability to create user namespaces by setting the relevant kernel limit to zero, ensuring the change takes effect immediately and persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

SYSCTL_KEY="kernel.unprivileged_userns_clone"
MAXNS_KEY="user.max_user_namespaces"
CONF_FILE="/etc/sysctl.d/99-disable-userns.conf"

# Build the desired configuration content.
# kernel.unprivileged_userns_clone is a Debian/Ubuntu-specific knob that may or
# may not exist depending on kernel build; user.max_user_namespaces is the
# upstream limit that reliably caps namespace creation to zero.
{
    echo "# Disable creation of user namespaces (managed by remediation script)"
    echo "${MAXNS_KEY} = 0"
    if [[ -e "/proc/sys/kernel/unprivileged_userns_clone" ]]; then
        echo "${SYSCTL_KEY} = 0"
    fi
} > "${CONF_FILE}.tmp"

# Idempotent write: only replace if content differs.
if [[ -f "${CONF_FILE}" ]] && cmp -s "${CONF_FILE}.tmp" "${CONF_FILE}"; then
    rm -f "${CONF_FILE}.tmp"
else
    mv "${CONF_FILE}.tmp" "${CONF_FILE}"
    chmod 0644 "${CONF_FILE}"
fi

# Apply immediately.
if [[ -e "/proc/sys/kernel/unprivileged_userns_clone" ]]; then
    sysctl -w "${SYSCTL_KEY}=0" >/dev/null
fi

# Set the max user namespaces limit to zero immediately.
sysctl -w "${MAXNS_KEY}=0" >/dev/null

# Reload the sysctl configuration to ensure persistence and consistency.
sysctl --system >/dev/null

# Verification.
CURRENT_MAXNS="$(sysctl -n ${MAXNS_KEY})"
if [[ "${CURRENT_MAXNS}" != "0" ]]; then
    echo "ERROR: Failed to set ${MAXNS_KEY} to 0 (current: ${CURRENT_MAXNS})." >&2
    exit 1
fi

if [[ -e "/proc/sys/kernel/unprivileged_userns_clone" ]]; then
    CURRENT_CLONE="$(sysctl -n ${SYSCTL_KEY})"
    if [[ "${CURRENT_CLONE}" != "0" ]]; then
        echo "ERROR: Failed to set ${SYSCTL_KEY} to 0 (current: ${CURRENT_CLONE})." >&2
        exit 1
    fi
fi

echo "User namespace creation has been disabled and the change persists across reboots."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of user.max_user_namespaces from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*user.max_user_namespaces.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "user.max_user_namespaces" matches to preserve use
```


---

## RHEL-08-010672 — `service_systemd-coredump_disabled`

**Prompt:** On an Ubuntu 24.04 system, the system service responsible for collecting, saving, and processing application core dumps poses a risk because core dumps can capture sensitive in-memory data and are rarely needed outside development. Write an idempotent bash remediation script that fully disables the acquisition, saving, and processing of core dumps by the relevant systemd core-dump handling unit, ensuring it cannot be started or activated and that this state persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

SOCKET_UNIT="systemd-coredump.socket"
SERVICE_UNIT="systemd-coredump@.service"
SYSCTL_FILE="/etc/sysctl.d/99-disable-coredump.conf"
COREDUMP_CONF_DIR="/etc/systemd/coredump.conf.d"
COREDUMP_CONF="${COREDUMP_CONF_DIR}/99-disable.conf"
LIMITS_FILE="/etc/security/limits.d/99-disable-coredump.conf"

echo "Disabling systemd core-dump handling units..."

# Stop and disable the coredump socket if present
if systemctl list-unit-files | grep -q "^${SOCKET_UNIT}"; then
    systemctl stop "${SOCKET_UNIT}" 2>/dev/null || true
    systemctl disable "${SOCKET_UNIT}" 2>/dev/null || true
fi

# Mask the socket so it cannot be started or activated
systemctl mask "${SOCKET_UNIT}" 2>/dev/null || true

# Mask the per-instance coredump service so it cannot be triggered
systemctl mask "${SERVICE_UNIT}" 2>/dev/null || true

# Ensure the coredump collection is disabled via coredump.conf
mkdir -p "${COREDUMP_CONF_DIR}"
cat > "${COREDUMP_CONF}" <<'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
chmod 0644 "${COREDUMP_CONF}"

# Disable core dumps at the kernel level via sysctl (persistent across reboots)
cat > "${SYSCTL_FILE}" <<'EOF'
kernel.core_pattern=|/bin/false
fs.suid_dumpable=0
EOF
chmod 0644 "${SYSCTL_FILE}"

# Apply sysctl settings now
sysctl -p "${SYSCTL_FILE}" >/dev/null 2>&1 || true
sysctl -w kernel.core_pattern="|/bin/false" >/dev/null 2>&1 || true
sysctl -w fs.suid_dumpable=0 >/dev/null 2>&1 || true

# Disable core dumps via limits (persistent across reboots)
cat > "${LIMITS_FILE}" <<'EOF'
* hard core 0
* soft core 0
root hard core 0
root soft core 0
EOF
chmod 0644 "${LIMITS_FILE}"

# Reload systemd to pick up changes
systemctl daemon-reload 2>/dev/null || true

echo "Core dump acquisition, saving, and processing have been disabled."
echo "Current status:"
systemctl is-enabled "${SOCKET_UNIT}" 2>/dev/null || true
systemctl is-active "${SOCKET_UNIT}" 2>/dev/null || true
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

SOCKET_NAME="systemd-coredump.socket"
SYSTEMCTL_EXEC='/usr/bin/systemctl'

if "$SYSTEMCTL_EXEC" -q list-unit-files --type socket | grep -q "$SOCKET_NAME"; then
    if [[ $("$SYSTEMCTL_EXEC" is-system-running) != "offline" ]]; then
      "$SYSTEMCTL_EXEC" stop "$SOCKET_NAME"
    fi
    "$SYSTEMCTL_EXEC" mask "$SOCKET_NAME"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```


---

## RHEL-08-010675 — `coredump_disable_backtraces`

**Prompt:** On an Ubuntu 24.04 system, ensure that the systemd core-dump handling subsystem does not generate backtraces from core dumps, since processed core dumps can capture sensitive in-memory data that should not be retained or analyzed on production systems. The effective configuration must set the maximum processed core size to zero so that no backtrace is produced. Write an idempotent bash remediation script that enforces this end state persistently.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

CONF_DIR="/etc/systemd/coredump.conf.d"
CONF_FILE="${CONF_DIR}/99-disable-backtrace.conf"

mkdir -p "${CONF_DIR}"

DESIRED_CONTENT="[Coredump]
ProcessSizeMax=0
"

if [[ ! -f "${CONF_FILE}" ]] || [[ "$(cat "${CONF_FILE}")" != "${DESIRED_CONTENT}" ]]; then
    printf '%s' "${DESIRED_CONTENT}" > "${CONF_FILE}"
    chmod 0644 "${CONF_FILE}"
    chown root:root "${CONF_FILE}"
fi

# Also enforce in the main coredump.conf if the key exists uncommented differently
MAIN_CONF="/etc/systemd/coredump.conf"
if [[ -f "${MAIN_CONF}" ]]; then
    if grep -Eq '^\s*ProcessSizeMax\s*=' "${MAIN_CONF}"; then
        sed -ri 's/^\s*ProcessSizeMax\s*=.*/ProcessSizeMax=0/' "${MAIN_CONF}"
    fi
fi

# Reload systemd configuration so changes take effect
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    # Restart the coredump socket/service if present to pick up new config
    if systemctl list-unit-files 2>/dev/null | grep -q '^systemd-coredump.socket'; then
        systemctl restart systemd-coredump.socket 2>/dev/null || true
    fi
fi

# Verify effective configuration
if command -v systemd-analyze >/dev/null 2>&1; then
    if systemd-analyze cat-config systemd/coredump.conf 2>/dev/null | grep -Eq '^\s*ProcessSizeMax\s*=\s*0\s*$'; then
        echo "Effective ProcessSizeMax=0 confirmed."
    else
        echo "Warning: could not confirm effective ProcessSizeMax=0 via systemd-analyze." >&2
    fi
fi

echo "Remediation complete: systemd coredump backtrace processing disabled (ProcessSizeMax=0)."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q systemd; then

found=false

# set value in all files if they contain section or key
for f in $(echo -n "/etc/systemd/coredump.conf"); do
    if [ ! -e "$f" ]; then
        continue
    fi

    # find key in section and change value
    if grep -qzosP "[[:space:]]*\[Coredump\]([^\n\[]*\n+)+?[[:space:]]*ProcessSizeMax" "$f"; then

            sed -i "s/ProcessSizeMax[^(\n)]*/ProcessSizeMax=0/" "$f"

            found=true

    # find section and add key = value to it
    elif grep -qs "[[:space:]]*\[Coredump\]" "$f"; then

            sed -i "/[[:space:]]*\[Coredump\]/a ProcessSizeMax=0" "$f"

            found=true
    fi
```


---

## RHEL-08-010674 — `coredump_disable_storage`

**Prompt:** On an Ubuntu 24.04 system, configure the system's core-dump handling service so that core dumps are never written to persistent storage. Core dumps capture a process's memory at the moment of a crash and may contain sensitive information such as credentials or cryptographic keys, so they should not be retained on production systems. Write an idempotent bash remediation script that ensures core dumps are not stored, with the setting persisting across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

CONF_DIR="/etc/systemd/coredump.conf.d"
CONF_FILE="${CONF_DIR}/disable-storage.conf"

mkdir -p "$CONF_DIR"

desired_content="[Coredump]
Storage=none
ProcessSizeMax=0
"

if [[ ! -f "$CONF_FILE" ]] || [[ "$(cat "$CONF_FILE")" != "$desired_content" ]]; then
    printf '%s' "$desired_content" > "$CONF_FILE"
    echo "Wrote coredump configuration to $CONF_FILE"
else
    echo "Coredump configuration already up to date at $CONF_FILE"
fi

chmod 0644 "$CONF_FILE"
chown root:root "$CONF_FILE"

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    if systemctl list-unit-files 2>/dev/null | grep -q '^systemd-coredump.socket'; then
        systemctl restart systemd-coredump.socket 2>/dev/null || true
    fi
fi

echo "Core-dump storage has been disabled (Storage=none)."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q systemd; then

found=false

# set value in all files if they contain section or key
for f in $(echo -n "/etc/systemd/coredump.conf"); do
    if [ ! -e "$f" ]; then
        continue
    fi

    # find key in section and change value
    if grep -qzosP "[[:space:]]*\[Coredump\]([^\n\[]*\n+)+?[[:space:]]*Storage" "$f"; then

            sed -i "s/Storage[^(\n)]*/Storage=none/" "$f"

            found=true

    # find section and add key = value to it
    elif grep -qs "[[:space:]]*\[Coredump\]" "$f"; then

            sed -i "/[[:space:]]*\[Coredump\]/a Storage=none" "$f"

            found=true
    fi
done

# if section no
```


---

## RHEL-08-010673 — `disable_users_coredumps`

**Prompt:** On an Ubuntu 24.04 system, prevent any user from generating process core dumps, since these memory images can capture sensitive in-memory data and are rarely needed outside development. Write an idempotent bash remediation script that enforces a hard limit of zero on core dump size for all users via the system resource-limits configuration, ensuring the setting persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

LIMITS_FILE="/etc/security/limits.conf"
LIMITS_DIR="/etc/security/limits.d"
DROPIN="${LIMITS_DIR}/99-disable-coredumps.conf"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# Ensure the limits.d directory exists
mkdir -p "$LIMITS_DIR"

# Remove any existing core limit entries from the main limits.conf to avoid conflicts
if [[ -f "$LIMITS_FILE" ]]; then
    sed -i -E '/^[[:space:]]*\*[[:space:]]+(hard|soft)[[:space:]]+core[[:space:]]+/d' "$LIMITS_FILE"
fi

# Desired configuration content
read -r -d '' DESIRED_CONTENT <<'EOF' || true
# Disable core dumps for all users to protect sensitive in-memory data
* hard core 0
* soft core 0
EOF

# Write the drop-in file idempotently
if [[ ! -f "$DROPIN" ]] || [[ "$(cat "$DROPIN")" != "$DESIRED_CONTENT" ]]; then
    printf '%s\n' "$DESIRED_CONTENT" > "$DROPIN"
    echo "Updated ${DROPIN} to enforce zero core dump limit."
else
    echo "${DROPIN} already enforces zero core dump limit."
fi

chmod 0644 "$DROPIN"
chown root:root "$DROPIN"

echo "Core dump hard limit of zero enforced for all users."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

SECURITY_LIMITS_FILE="/etc/security/limits.conf"

if grep -qE '^\s*\*\s+hard\s+core' $SECURITY_LIMITS_FILE; then
        sed -ri 's/(hard\s+core\s+)[[:digit:]]+/\1 0/' $SECURITY_LIMITS_FILE
else
        echo "*     hard   core    0" >> $SECURITY_LIMITS_FILE
fi

if ls /etc/security/limits.d/*.conf > /dev/null; then
        sed -ri '/^\s*\*\s+hard\s+core/d' /etc/security/limits.d/*.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```


---

## RHEL-08-010430 — `sysctl_kernel_randomize_va_space`

**Prompt:** On an Ubuntu 24.04 system, ensure the kernel applies full randomization of process virtual address space layout (ASLR), so that both the positions of introduced attack code and existing reusable code are unpredictable, hardening the system against memory-corruption and return-oriented-programming exploits. The system must be configured for the maximum/full randomization level, and the setting must take effect at runtime and persist across reboots. Write an idempotent bash remediation script that achieves this end state.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PARAM="kernel.randomize_va_space"
VALUE="2"
CONF_DIR="/etc/sysctl.d"
CONF_FILE="${CONF_DIR}/60-aslr-hardening.conf"

if [[ "$(id -u)" -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

mkdir -p "${CONF_DIR}"

# Remove any conflicting settings for this parameter from other sysctl files
for f in /etc/sysctl.conf ${CONF_DIR}/*.conf /run/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf; do
    [[ -f "$f" ]] || continue
    [[ "$f" == "$CONF_FILE" ]] && continue
    if grep -Eq "^\s*${PARAM}\s*=" "$f"; then
        sed -i -E "/^\s*${PARAM}\s*=/d" "$f"
    fi
done

# Write the desired setting idempotently
DESIRED_LINE="${PARAM} = ${VALUE}"
if [[ -f "${CONF_FILE}" ]] && grep -Eq "^\s*${PARAM}\s*=" "${CONF_FILE}"; then
    sed -i -E "s|^\s*${PARAM}\s*=.*|${DESIRED_LINE}|" "${CONF_FILE}"
else
    printf '%s\n' "${DESIRED_LINE}" >> "${CONF_FILE}"
fi

chmod 0644 "${CONF_FILE}"

# Apply at runtime
sysctl -w "${PARAM}=${VALUE}" >/dev/null

# Reload all sysctl settings to ensure persistence config is valid/applied
sysctl --system >/dev/null

# Verify
CURRENT="$(sysctl -n "${PARAM}")"
if [[ "${CURRENT}" != "${VALUE}" ]]; then
    echo "Failed to set ${PARAM} to ${VALUE} (current: ${CURRENT})." >&2
    exit 1
fi

echo "ASLR configured: ${PARAM} = ${CURRENT} (persisted in ${CONF_FILE})"
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of kernel.randomize_va_space from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*kernel.randomize_va_space.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "kernel.randomize_va_space" matches to preserve 
```


---

## RHEL-08-010421 — `grub2_page_poison_argument`

**Prompt:** On an Ubuntu 24.04 system, harden memory management by enabling the kernel's free-page poisoning feature, which writes a known value into freed memory pages so that use-after-free accesses and leftover sensitive data are detected and prevented. The setting must be present on the boot loader command line for all currently installed kernels and must also be applied automatically to any kernels installed in the future, so the protection persists across reboots and upgrades. Write an idempotent bash remediation script that achieves this end state.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PARAM="page_poison=1"

# 1. Ensure the parameter is applied to all currently installed kernels via GRUB
GRUB_DEFAULT="/etc/default/grub"

if [ ! -f "$GRUB_DEFAULT" ]; then
    echo "GRUB_CMDLINE_LINUX_DEFAULT=\"$PARAM\"" > "$GRUB_DEFAULT"
else
    if grep -q '^GRUB_CMDLINE_LINUX_DEFAULT=' "$GRUB_DEFAULT"; then
        current="$(grep '^GRUB_CMDLINE_LINUX_DEFAULT=' "$GRUB_DEFAULT" | head -n1)"
        value="$(echo "$current" | sed -E 's/^GRUB_CMDLINE_LINUX_DEFAULT=//; s/^"//; s/"$//')"
        if ! echo " $value " | grep -qw "page_poison=1"; then
            # remove any existing page_poison setting to avoid duplicates/conflicts
            value="$(echo "$value" | sed -E 's/\bpage_poison=[^ ]*//g' | sed -E 's/  +/ /g; s/^ //; s/ $//')"
            if [ -n "$value" ]; then
                newvalue="$value $PARAM"
            else
                newvalue="$PARAM"
            fi
            sed -i -E "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=\"$newvalue\"|" "$GRUB_DEFAULT"
        fi
    else
        echo "GRUB_CMDLINE_LINUX_DEFAULT=\"$PARAM\"" >> "$GRUB_DEFAULT"
    fi
fi

# 2. Regenerate the GRUB configuration so all installed kernels get the setting
if command -v update-grub >/dev/null 2>&1; then
    update-grub
elif command -v grub-mkconfig >/dev/null 2>&1; then
    if [ -d /sys/firmware/efi ]; then
        GRUB_CFG="/boot/efi/EFI/ubuntu/grub.cfg"
        [ -f "$GRUB_CFG" ] || GRUB_CFG="/boot/grub/grub.cfg"
    else
        GRUB_CFG="/boot/grub/grub.cfg"
    fi
    grub-mkconfig -o "$GRUB_CFG"
fi

echo "Free-page poisoning ($PARAM) has been configured for current and future kernels."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel && { rpm --quiet -q grub2-common; }; then

expected_value="1"


if [[ "$OSCAP_BOOTC_BUILD" == "YES" ]] ; then
    KARGS_DIR="/usr/lib/bootc/kargs.d/"
    if grep -q -E "page_poison" "$KARGS_DIR/*.toml" ; then
        sed -i -E "s/^(\s*kargs\s*=\s*\[.*)\"page_poison=[^\"]*\"(.*]\s*)/\1\"page_poison=$expected_value\"\2/" "$KARGS_DIR/*.toml"
    else
        echo "kargs = [\"page_poison=$expected_value\"]" >> "$KARGS_DIR/10-page_poison.toml"
    fi
else

    grubby --update-kernel=ALL --args=page_poison=1 --env=/boot/grub2/grubenv

fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```


---

## None — `grub2_slub_debug_argument`

**Prompt:** On an Ubuntu 24.04 system, enable the kernel memory allocator's object-poisoning feature so that freed kernel objects are overwritten with a sentinel value, allowing many use-after-free and uninitialized-memory bugs to be detected and prevented. The setting must be applied as a boot-time kernel parameter for all currently installed kernels and must also be inherited by any kernels installed in the future, persisting across reboots. Write an idempotent bash remediation script that achieves this end state.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PARAM="slub_debug=P"
GRUB_FILE="/etc/default/grub"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

if [[ ! -f "$GRUB_FILE" ]]; then
    echo "GRUB configuration file $GRUB_FILE not found." >&2
    exit 1
fi

# Ensure GRUB_CMDLINE_LINUX_DEFAULT exists
if ! grep -q '^GRUB_CMDLINE_LINUX_DEFAULT=' "$GRUB_FILE"; then
    echo 'GRUB_CMDLINE_LINUX_DEFAULT=""' >> "$GRUB_FILE"
fi

# Read current value
current_line=$(grep '^GRUB_CMDLINE_LINUX_DEFAULT=' "$GRUB_FILE" | head -n1)

# Extract value between quotes
current_value=$(echo "$current_line" | sed -E 's/^GRUB_CMDLINE_LINUX_DEFAULT=["'\'']?(.*)["'\'']?$/\1/' | sed -E 's/["'\'']+$//')

# Check if slub_debug already present
if echo " $current_value " | grep -qE ' slub_debug(=[^ ]*)?( |$)'; then
    # Normalize: replace existing slub_debug setting with the desired one
    new_value=$(echo "$current_value" | sed -E "s/slub_debug(=[^ ]*)?/${PARAM}/")
else
    if [[ -z "$current_value" ]]; then
        new_value="$PARAM"
    else
        new_value="$current_value $PARAM"
    fi
fi

# Trim extra spaces
new_value=$(echo "$new_value" | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//')

# Only update if changed
if [[ "$current_value" != "$new_value" ]]; then
    # Escape for sed replacement
    escaped_value=$(printf '%s' "$new_value" | sed -e 's/[\/&]/\\&/g')
    sed -i -E "s/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT=\"${escaped_value}\"/" "$GRUB_FILE"
    echo "Updated GRUB_CMDLINE_LINUX_DEFAULT to: \"$new_value\""
else
    echo "GRUB_CMDLINE_LINUX_DEFAULT already contains required setting."
fi

# Regenerate GRUB configuration to apply to all installed kernels
if command -v update-grub >/dev/null 2>&1; then
    update-grub
elif command -v grub-mkconfig >/dev/null 2>&1; then
    if [[ -d /boot/grub ]]; then
        grub-mkconfig -o /boot/grub/grub.cfg
    elif [[ -d /boot/grub2 ]]; then
        grub-mkconfig -o /boot/grub2/grub.cfg
    fi
fi

echo "slub_debug=P poisoning has been enabled as a boot-time kernel parameter."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel && { rpm --quiet -q grub2-common; }; then

var_slub_debug_options='
```


---

## RHEL-08-010670 — `service_kdump_disabled`

**Prompt:** On an Ubuntu 24.04 system that is not used for kernel development or testing, the kernel crash-dump analyzer service should be fully disabled, because crash dumps can capture the entire contents of system memory and consume large amounts of disk space, creating both a data-exposure and denial-of-service risk. Write an idempotent bash remediation script that ensures this crash-dump service is stopped and permanently prevented from starting, including across reboots and manual activation attempts.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

SERVICE="kdump-tools.service"

# Ensure we are running as root
if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# Reload systemd to make sure it knows the current unit state
systemctl daemon-reload || true

# Stop the service if it is currently running
if systemctl is-active --quiet "${SERVICE}"; then
    echo "Stopping ${SERVICE}..."
    systemctl stop "${SERVICE}" || true
else
    echo "${SERVICE} is not active."
fi

# Disable the service so it does not start at boot
if systemctl is-enabled --quiet "${SERVICE}" 2>/dev/null; then
    echo "Disabling ${SERVICE}..."
    systemctl disable "${SERVICE}" || true
else
    echo "${SERVICE} is already disabled (or not enabled)."
fi

# Mask the service to prevent manual or dependency-based activation
MASK_STATE="$(systemctl is-enabled "${SERVICE}" 2>/dev/null || true)"
if [[ "${MASK_STATE}" != "masked" ]]; then
    echo "Masking ${SERVICE}..."
    systemctl mask "${SERVICE}" || true
else
    echo "${SERVICE} is already masked."
fi

# Final reload to ensure changes are applied
systemctl daemon-reload || true

# Report final state
echo "Final state of ${SERVICE}:"
systemctl is-active "${SERVICE}" || true
systemctl is-enabled "${SERVICE}" 2>/dev/null || true

echo "Remediation complete: ${SERVICE} is stopped, disabled, and masked."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

SYSTEMCTL_EXEC='/usr/bin/systemctl'
if [[ $("$SYSTEMCTL_EXEC" is-system-running) != "offline" ]]; then
  "$SYSTEMCTL_EXEC" stop 'kdump.service'
fi
"$SYSTEMCTL_EXEC" disable 'kdump.service'
"$SYSTEMCTL_EXEC" mask 'kdump.service'
# Disable socket activation if we have a unit file for it
if "$SYSTEMCTL_EXEC" -q list-unit-files kdump.socket; then
    if [[ $("$SYSTEMCTL_EXEC" is-system-running) != "offline" ]]; then
      "$SYSTEMCTL_EXEC" stop 'kdump.socket'
    fi
    "$SYSTEMCTL_EXEC" mask 'kdump.socket'
fi
# The service may not be running because it has been started and failed,
# so let's reset the state so
```


---

## RHEL-08-040135 — `package_fapolicyd_installed`

**Prompt:** On an Ubuntu 24.04 system, ensure that the application whitelisting capability that controls which executables and files are permitted to run is available, so the system can enforce policy-based application execution control and reduce the risk of unauthorized or malicious software running. Write an idempotent bash remediation script that ensures the file access policy daemon software is present on the system.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation script: Ensure the File Access Policy Daemon (fapolicyd) is installed.
# fapolicyd provides application whitelisting capability to control which
# executables and files are permitted to run, enforcing policy-based
# application execution control.
#
# This script is idempotent: it only installs the package if it is missing.

set -euo pipefail

PACKAGE="fapolicyd"

# Must run as root to install packages.
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# Check whether the package is already installed.
if dpkg-query -W -f='${Status}' "${PACKAGE}" 2>/dev/null | grep -q "install ok installed"; then
    echo "Package '${PACKAGE}' is already installed. No action required."
    exit 0
fi

echo "Package '${PACKAGE}' is not installed. Installing now..."

# Refresh package lists (non-fatal if it fails, apt-get install will still try).
export DEBIAN_FRONTEND=noninteractive
apt-get update -y || true

# Install the package.
apt-get install -y "${PACKAGE}"

# Verify installation succeeded.
if dpkg-query -W -f='${Status}' "${PACKAGE}" 2>/dev/null | grep -q "install ok installed"; then
    echo "Package '${PACKAGE}' has been successfully installed."
    exit 0
else
    echo "Failed to install package '${PACKAGE}'." >&2
    exit 1
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if ! rpm -q --quiet "fapolicyd" ; then
    yum install -y "fapolicyd"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```


---

## RHEL-08-040136 — `service_fapolicyd_enabled`

**Prompt:** On an Ubuntu 24.04 system, the file access policy daemon, which enforces application allow-listing to control which executables and files may be accessed, must be active to prevent untrusted applications from running. Write an idempotent bash remediation script that ensures this file access policy service is enabled to start automatically at boot and is running, persisting across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

SERVICE="fapolicyd"

if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemctl not found; cannot manage services." >&2
    exit 1
fi

if ! dpkg -s fapolicyd >/dev/null 2>&1; then
    echo "Installing fapolicyd package..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y fapolicyd
fi

if ! systemctl is-enabled --quiet "${SERVICE}" 2>/dev/null; then
    echo "Enabling ${SERVICE} to start at boot..."
    systemctl enable "${SERVICE}"
else
    echo "${SERVICE} is already enabled."
fi

if ! systemctl is-active --quiet "${SERVICE}" 2>/dev/null; then
    echo "Starting ${SERVICE}..."
    systemctl start "${SERVICE}"
else
    echo "${SERVICE} is already running."
fi

systemctl is-enabled --quiet "${SERVICE}" && echo "${SERVICE} enabled: OK"
systemctl is-active --quiet "${SERVICE}" && echo "${SERVICE} active: OK"
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

SYSTEMCTL_EXEC='/usr/bin/systemctl'
"$SYSTEMCTL_EXEC" unmask 'fapolicyd.service'
if [[ $("$SYSTEMCTL_EXEC" is-system-running) != "offline" ]]; then
  "$SYSTEMCTL_EXEC" start 'fapolicyd.service'
fi
"$SYSTEMCTL_EXEC" enable 'fapolicyd.service'

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```


---

## RHEL-08-040137 — `fapolicy_default_deny`

**Prompt:** On an Ubuntu 24.04 system, configure the application allowlisting (file-access policy) subsystem so that it operates under a deny-all, permit-by-exception model: only explicitly authorized software programs may execute, and all other binaries are blocked from running. This limits the attack surface by ensuring only vetted, trusted software can run. Write an idempotent bash remediation script that installs and enables this control with an enforcing default-deny posture, persisting across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Configure application allowlisting on Ubuntu 24.04 using fapolicyd
# Deny-all, permit-by-exception (default-deny) enforcing posture.
# Idempotent remediation script.
#
set -euo pipefail

#-----------------------------------------------------------------------
# Preconditions
#-----------------------------------------------------------------------
if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive

#-----------------------------------------------------------------------
# Install fapolicyd (application allowlisting daemon)
#-----------------------------------------------------------------------
if ! dpkg-query -W -f='${Status}' fapolicyd 2>/dev/null | grep -q "install ok installed"; then
    echo "Installing fapolicyd..."
    apt-get update -y
    apt-get install -y fapolicyd
else
    echo "fapolicyd already installed."
fi

#-----------------------------------------------------------------------
# Ensure configuration directories exist
#-----------------------------------------------------------------------
CONF_DIR="/etc/fapolicyd"
RULES_D="${CONF_DIR}/rules.d"
mkdir -p "${RULES_D}"

#-----------------------------------------------------------------------
# Configure fapolicyd.conf for ENFORCING (permissive = 0) posture
#-----------------------------------------------------------------------
CONF_FILE="${CONF_DIR}/fapolicyd.conf"

if [[ -f "${CONF_FILE}" ]]; then
    if grep -qE '^\s*permissive\s*=' "${CONF_FILE}"; then
        sed -i -E 's/^\s*permissive\s*=.*/permissive = 0/' "${CONF_FILE}"
    else
        echo "permissive = 0" >> "${CONF_FILE}"
    fi
else
    cat > "${CONF_FILE}" <<'EOF'
permissive = 0
nice_val = 14
q_size = 800
uid = fapolicyd
gid = fapolicyd
do_stat_report = 1
detailed_report = 1
db_max_size = 50
subj_cache_size = 1549
obj_cache_size = 8191
watch_fs = ext2,ext3,ext4,tmpfs,xfs,vfat,btrfs
trust = rpmdb,file
integrity = none
syslog_format = rule,dec,perm,uid,gid,pid,exe,:,path,ftype,trust
rpm_sha256_only = 0
allow_filesystem_mark = 0
report_interval = 0
EOF
fi

#-----------------------------------------------------------------------
# Install a default-deny rule set (permit-by-exception)
# The last rule denies all execution not explicitly permitted above.
#-----------------------------------------------------------------------
RULE_FILE="${RULES_D}/99-deny-all.rules"

# Deploy the base permit-by-exception rules if not already the shipped set.
# Preserve any vendor-provided rule fragments; only ensure the final deny.
cat > "${RULE_FILE}" <<'EOF'
# Deny-all, permit-by-exception final rule.
# Anything not explicitly allowed by preceding rules is denied.
deny_audit perm=any all : all
EOF

# Ensure the permit rules for trusted files/languages exist.
# These allow execution/opening of trusted (allowlisted) binaries.
PERMIT_FILE="${RULES_D}/00-permit-trusted.rules"
cat > "${PERMIT_FILE}" <<'EOF'
# Permit trusted, allowlisted executables and libraries.
allow perm=any all : all trust=1
allow perm=open all : all ftype=%languages trust=1
deny_audit perm=any pattern=ld_so all : all
deny_audit perm=execute all : all ftype=application/x-executable trust=0
allow perm=open all : all ftype=%languages
allow perm=any all : all ftype=text/x-shellscript trust=1
EOF

#-----------------------------------------------------------------------
# Compile rules into the active policy
#-----------------------------------------------------------------------
if command -v fagenrules >/dev/null 2>&1; then
    echo "Compiling fapolicyd rules..."
    fagenrules --load || true
fi

#-----------------------------------------------------------------------
# Build/refresh the trust database from the system package manager & files
#-----------------------------------------------------------------------
echo "Updating fapolicyd trust database..."
fapolicyd-cli --update || true

#-----------------------------------------------------------------------
# Enable and (re)start the service so it persists across reboots
#-----------------------------------------------------------------------
systemctl unmask fapolicyd 2>/dev/null || true
systemctl enable fapolicyd

if systemctl is-active --quiet fapolicyd; then
    echo "Restarting fapolicyd to apply enforcing policy..."
    systemctl restart fapolicyd
else
    echo "Starting fapolicyd..."
    systemctl start fapolicyd
fi

#-----------------------------------------------------------------------
# Verify enforcing posture
#-----------------------------------------------------------------------
sleep 2
if systemctl is-active --quiet fapolicyd; then
    echo "fapolicyd is active."
else
    echo "ERROR: fapolicyd failed to start." >&2
    systemctl status fapolicyd --no-pager || true
    exit 1
fi

if grep -qE '^\s*permissive\s*=\s*0\s*$' "${CONF_FILE}"; then
    echo "SUCCESS: fapolicyd configured in ENFORCING (deny-all, permit-by-exception) mode."
else
    echo "WARNING: permissive mode not set to 0 in ${CONF_FILE}." >&2
    exit 1
fi

echo "Application allowlisting (default-deny) is installed, enabled, and persistent."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

cat > /etc/fapolicyd/rules.d/99-deny-everything.rules << EOF
# Red Hat KCS 7003854 (https://access.redhat.com/solutions/7003854)
deny perm=any all : all
EOF

chmod 644 /etc/fapolicyd/rules.d/99-deny-everything.rules
chgrp fapolicyd /etc/fapolicyd/rules.d/99-deny-everything.rules

if [ -e "/etc/fapolicyd/fapolicyd.conf" ] ; then
    
    LC_ALL=C sed -i "/^\s*permissive\s*=\s*/Id" "/etc/fapolicyd/fapolicyd.conf"
else
    touch "/etc/fapolicyd/fapolicyd.conf"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/fapolicyd/fapolicyd.conf"

cp "/etc/fapolicyd/fapolicyd.conf" "/etc/fapolicyd/fapolicyd
```


---

## RHEL-08-010358 — `package_mailx_installed`

**Prompt:** On an Ubuntu 24.04 system, ensure that a command-line mail-sending utility is present so that system processes can deliver email notifications about important events such as failures or security warnings to designated personnel. Write an idempotent bash remediation script that guarantees the standard mailx mail client is installed on the system.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PACKAGE="bsd-mailx"

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root." >&2
    exit 1
fi

if dpkg-query -W -f='${Status}' "$PACKAGE" 2>/dev/null | grep -q "install ok installed"; then
    echo "Package '$PACKAGE' is already installed. No action needed."
    exit 0
fi

echo "Package '$PACKAGE' is not installed. Installing..."

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y "$PACKAGE"

if dpkg-query -W -f='${Status}' "$PACKAGE" 2>/dev/null | grep -q "install ok installed"; then
    echo "Package '$PACKAGE' successfully installed."
    exit 0
else
    echo "Failed to install package '$PACKAGE'." >&2
    exit 1
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if ! rpm -q --quiet "mailx" ; then
    yum install -y "mailx"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```


---

## RHEL-08-030030 — `package_postfix_installed`

**Prompt:** On an Ubuntu 24.04 system, a local mail transfer agent must be present so the system can deliver notifications about important events such as failures or security warnings to designated personnel. Write an idempotent bash remediation script that ensures the standard Postfix mail server software is installed on the system.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PACKAGE="postfix"

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root." >&2
    exit 1
fi

if dpkg-query -W -f='${Status}' "$PACKAGE" 2>/dev/null | grep -q "install ok installed"; then
    echo "Package '$PACKAGE' is already installed. No action needed."
    exit 0
fi

echo "Package '$PACKAGE' is not installed. Installing now..."

export DEBIAN_FRONTEND=noninteractive

apt-get update

apt-get install -y "$PACKAGE"

if dpkg-query -W -f='${Status}' "$PACKAGE" 2>/dev/null | grep -q "install ok installed"; then
    echo "Package '$PACKAGE' was installed successfully."
else
    echo "Failed to install package '$PACKAGE'." >&2
    exit 1
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if ! rpm -q --quiet "postfix" ; then
    yum install -y "postfix"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```


---

## RHEL-08-030741 — `chronyd_client_only`

**Prompt:** On an Ubuntu 24.04 system, the system time-synchronization daemon (chrony) may be configured to listen for incoming connections and act as a time server, which expands the attack surface and violates the principle of least functionality. Configure chrony to operate strictly in client-only mode so that it never opens any listening network port for serving time to other hosts. Write an idempotent bash remediation script that enforces this client-only configuration and persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

# Enforce chrony client-only mode on Ubuntu 24.04 by adding "port 0" and
# "cmdport 0" directives so chrony never opens any listening network port.

CONF_DIR="/etc/chrony/conf.d"
CONF_FILE="${CONF_DIR}/disable-server.conf"
MAIN_CONF="/etc/chrony/chrony.conf"

# Ensure the conf.d drop-in directory exists.
if [ ! -d "$CONF_DIR" ]; then
    mkdir -p "$CONF_DIR"
    chmod 0755 "$CONF_DIR"
fi

# Ensure the main config includes the conf.d directory; add if missing.
if [ -f "$MAIN_CONF" ]; then
    if ! grep -Eq '^[[:space:]]*(confdir|include)[[:space:]]+.*conf\.d' "$MAIN_CONF"; then
        if ! grep -Eq "^[[:space:]]*confdir[[:space:]]+${CONF_DIR}" "$MAIN_CONF"; then
            printf '\nconfdir %s\n' "$CONF_DIR" >> "$MAIN_CONF"
        fi
    fi
fi

# Desired client-only content.
DESIRED_CONTENT="$(cat <<'EOF'
# Managed by remediation script: enforce chrony client-only mode.
# Disable the NTP server listening socket (client-only).
port 0
# Disable the command/monitoring socket.
cmdport 0
EOF
)"

# Write the drop-in file only if content differs (idempotent).
if [ ! -f "$CONF_FILE" ] || [ "$(cat "$CONF_FILE")" != "$DESIRED_CONTENT" ]; then
    printf '%s\n' "$DESIRED_CONTENT" > "$CONF_FILE"
    chmod 0644 "$CONF_FILE"
    CHANGED=1
else
    CHANGED=0
fi

# Remove/neutralize any conflicting directives in the main config.
if [ -f "$MAIN_CONF" ]; then
    if grep -Eq '^[[:space:]]*(allow|bindaddress|bindcmdaddress|port|cmdport)[[:space:]]' "$MAIN_CONF"; then
        # Only comment out server-enabling directives; leave "port 0"/"cmdport 0" alone.
        TMP="$(mktemp)"
        while IFS= read -r line; do
            if printf '%s' "$line" | grep -Eq '^[[:space:]]*(allow|bindaddress|bindcmdaddress)[[:space:]]'; then
                printf '# disabled by remediation (client-only): %s\n' "$line"
                CHANGED=1
            elif printf '%s' "$line" | grep -Eq '^[[:space:]]*port[[:space:]]+[1-9]'; then
                printf '# disabled by remediation (client-only): %s\n' "$line"
                CHANGED=1
            elif printf '%s' "$line" | grep -Eq '^[[:space:]]*cmdport[[:space:]]+[1-9]'; then
                printf '# disabled by remediation (client-only): %s\n' "$line"
                CHANGED=1
            else
                printf '%s\n' "$line"
            fi
        done < "$MAIN_CONF" > "$TMP"
        if ! cmp -s "$TMP" "$MAIN_CONF"; then
            cat "$TMP" > "$MAIN_CONF"
            CHANGED=1
        fi
        rm -f "$TMP"
    fi
fi

# Determine chrony service name.
SERVICE=""
if systemctl list-unit-files 2>/dev/null | grep -q '^chrony\.service'; then
    SERVICE="chrony"
elif systemctl list-unit-files 2>/dev/null | grep -q '^chronyd\.service'; then
    SERVICE="chronyd"
fi

# Restart chrony to apply changes if service exists and something changed.
if [ -n "$SERVICE" ]; then
    systemctl enable "$SERVICE" >/dev/null 2>&1 || true
    if [ "${CHANGED:-0}" -eq 1 ] || ! systemctl is-active --quiet "$SERVICE"; then
        systemctl restart "$SERVICE" || true
    fi
fi

echo "chrony client-only mode enforced (config: ${CONF_FILE})."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel && { rpm --quiet -q chrony; }; then

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^port")

# shellcheck disable=SC2059
printf -v formatted_output "%s %s" "$stripped_key" "0"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^port\\>" "/etc/chrony.conf"; then
    escaped_formatted_output=$(sed -e 's|/
```


---

## RHEL-08-030742 — `chronyd_no_chronyc_network`

**Prompt:** On an Ubuntu 24.04 system, the time-synchronization (chrony) daemon should not act as a network-accessible service for runtime management connections, since exposing this management interface needlessly increases the attack surface. Configure the chrony daemon so that it does not listen on its management network port (it should neither monitor commands over the network nor open that command socket). Write an idempotent bash remediation script that enforces this and persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

CONF="/etc/chrony/chrony.conf"

# Ensure the config file exists
if [ ! -f "$CONF" ]; then
    # Fallback for alternate locations
    if [ -f "/etc/chrony.conf" ]; then
        CONF="/etc/chrony.conf"
    else
        touch "$CONF"
    fi
fi

# Remove any existing 'cmdport' or 'bindcmdaddress' directives to avoid conflicts
sed -i -E '/^[[:space:]]*cmdport[[:space:]].*/Id' "$CONF"
sed -i -E '/^[[:space:]]*bindcmdaddress[[:space:]].*/Id' "$CONF"

# Add the directive to disable the command port
if ! grep -qiE '^[[:space:]]*cmdport[[:space:]]+0[[:space:]]*$' "$CONF"; then
    printf '\ncmdport 0\n' >> "$CONF"
fi

# Restart chrony to apply changes
if command -v systemctl >/dev/null 2>&1; then
    if systemctl list-unit-files | grep -q '^chrony\.service'; then
        systemctl restart chrony.service || true
    elif systemctl list-unit-files | grep -q '^chronyd\.service'; then
        systemctl restart chronyd.service || true
    fi
fi

echo "chrony command port disabled (cmdport 0) in $CONF"
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel && { rpm --quiet -q chrony; }; then

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^cmdport")

# shellcheck disable=SC2059
printf -v formatted_output "%s %s" "$stripped_key" "0"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^cmdport\\>" "/etc/chrony.conf"; then
    escaped_formatted_output=$(sed -
```


---

## RHEL-08-030740 — `chronyd_or_ntpd_set_maxpoll`

**Prompt:** On an Ubuntu 24.04 system, the time-synchronization service must be configured so that every configured upstream time source is polled at a bounded maximum interval, ensuring the system clock is continuously and reliably synchronized; accurate timestamps are essential for correlating events and conducting forensic analysis. Write an idempotent bash remediation script that ensures each remote time source used by the system's time daemon has an explicit maximum polling interval defined, with this setting persisting across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Ensure every configured upstream time source for systemd-timesyncd
# has an explicit maximum polling interval (maxpoll) defined so the
# system clock is polled at a bounded interval and stays synchronized.
#
set -euo pipefail

# Default maxpoll value (2^10 = 1024s ~ 17 minutes). Adjust if needed.
MAXPOLL_VALUE="10"

CONF_MAIN="/etc/systemd/timesyncd.conf"
CONF_DIR="/etc/systemd/timesyncd.conf.d"
DROPIN="${CONF_DIR}/50-maxpoll.conf"

require_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        echo "This script must be run as root." >&2
        exit 1
    fi
}

require_root

# Make sure the service package/binary exists.
if ! command -v timedatectl >/dev/null 2>&1; then
    echo "systemd-timesyncd tooling not found (timedatectl missing)." >&2
    exit 1
fi

# Gather the currently configured NTP / fallback NTP servers from the
# effective configuration (main file + any drop-ins).
collect_sources() {
    local files=()
    [[ -f "$CONF_MAIN" ]] && files+=("$CONF_MAIN")
    if [[ -d "$CONF_DIR" ]]; then
        while IFS= read -r -d '' f; do
            files+=("$f")
        done < <(find "$CONF_DIR" -maxdepth 1 -type f -name '*.conf' -print0 2>/dev/null)
    fi

    if [[ ${#files[@]} -gt 0 ]]; then
        # Extract NTP= and FallbackNTP= directives, strip key, split values.
        grep -hEi '^[[:space:]]*(NTP|FallbackNTP)[[:space:]]*=' "${files[@]}" 2>/dev/null \
            | sed -E 's/^[[:space:]]*[A-Za-z]+[[:space:]]*=[[:space:]]*//' \
            | tr ' ' '\n' \
            | sed -E 's/[[:space:]]+//g' \
            | grep -v '^$' || true
    fi
}

mapfile -t SOURCES < <(collect_sources | awk '!seen[$0]++')

# If no upstream sources are configured anywhere, fall back to the
# vendor default pool so there is at least one bounded source.
if [[ ${#SOURCES[@]} -eq 0 ]]; then
    SOURCES=("ntp.ubuntu.com")
fi

# Append the maxpoll option to any source that lacks it.
declare -a NEW_SOURCES=()
for src in "${SOURCES[@]}"; do
    if [[ "$src" == *"maxpoll"* ]]; then
        NEW_SOURCES+=("$src")
    else
        # A source token may carry other iburst-style options separated by
        # commas in some setups; timesyncd uses space-separated hosts only,
        # so simply attach the maxpoll option to the host token.
        NEW_SOURCES+=("${src} maxpoll=${MAXPOLL_VALUE}")
    fi
done

# Build the NTP= line. Because timesyncd treats space-separated entries as
# separate servers, we set maxpoll globally via the option and list hosts.
# systemd-timesyncd does not support per-host maxpoll in NTP=, so we set
# the global PollIntervalMaxSec instead, expressed in seconds.
MAX_SECONDS=$(( 2 ** MAXPOLL_VALUE ))

# Reconstruct a clean, space-separated host list (without inline options).
declare -a HOST_LIST=()
for src in "${SOURCES[@]}"; do
    host="${src%% *}"
    HOST_LIST+=("$host")
done
NTP_LINE="$(printf '%s ' "${HOST_LIST[@]}" | sed -E 's/[[:space:]]+$//')"

# Ensure the drop-in directory exists.
mkdir -p "$CONF_DIR"
chmod 0755 "$CONF_DIR"

# Generate the desired drop-in content idempotently.
TMP_FILE="$(mktemp)"
trap 'rm -f "$TMP_FILE"' EXIT

cat > "$TMP_FILE" <<EOF
[Time]
NTP=${NTP_LINE}
PollIntervalMaxSec=${MAX_SECONDS}
EOF

chmod 0644 "$TMP_FILE"

# Only write/replace if content differs (idempotency).
if [[ ! -f "$DROPIN" ]] || ! cmp -s "$TMP_FILE" "$DROPIN"; then
    cp -f "$TMP_FILE" "$DROPIN"
    chmod 0644 "$DROPIN"
    CHANGED=1
else
    CHANGED=0
fi

rm -f "$TMP_FILE"
trap - EXIT

# Ensure the service is enabled so the configuration persists across reboots.
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable systemd-timesyncd.service >/dev/null 2>&1 || true

    if [[ "${CHANGED}" -eq 1 ]]; then
        systemctl restart systemd-timesyncd.service >/dev/null 2>&1 || true
    else
        # Make sure it is running even if config was already correct.
        if ! systemctl is-active --quiet systemd-timesyncd.service; then
            systemctl start systemd-timesyncd.service >/dev/null 2>&1 || true
        fi
    fi
fi

echo "systemd-timesyncd configured with bounded max poll interval (${MAX_SECONDS}s)."
echo "Sources: ${NTP_LINE}"
if [[ "${CHANGED}" -eq 1 ]]; then
    echo "Configuration updated: ${DROPIN}"
else
    echo "Configuration already compliant: ${DROPIN}"
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel && { ( rpm --quiet -q chrony || rpm --quiet -q ntp ); }; then

var_time_service_set_maxpoll='
```


---

## RHEL-08-010200 — `sshd_set_keepalive`

**Prompt:** On an Ubuntu 24.04 system, configure the SSH server so that an unresponsive client connection is dropped immediately once the idle-timeout interval elapses, rather than allowing additional unanswered keep-alive probes to extend the session. Specifically, ensure the server permits zero additional keep-alive attempts before disconnecting an unresponsive session (so that termination occurs precisely at the configured idle interval). Write an idempotent bash remediation script that enforces this end state for new SSH sessions and persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

CONFIG_FILE="/etc/ssh/sshd_config"
PARAM="ClientAliveCountMax"
VALUE="0"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Error: $CONFIG_FILE not found." >&2
    exit 1
fi

# Backup once
if [[ ! -f "${CONFIG_FILE}.bak" ]]; then
    cp -p "$CONFIG_FILE" "${CONFIG_FILE}.bak"
fi

# Remove any existing (commented or active) ClientAliveCountMax lines
sed -i -E "/^[[:space:]]*#?[[:space:]]*${PARAM}[[:space:]]+.*/d" "$CONFIG_FILE"

# Append the desired directive
echo "${PARAM} ${VALUE}" >> "$CONFIG_FILE"

# Validate configuration
if command -v sshd >/dev/null 2>&1; then
    sshd -t
elif [[ -x /usr/sbin/sshd ]]; then
    /usr/sbin/sshd -t
fi

# Determine service name and reload
if systemctl list-unit-files | grep -q '^ssh\.service'; then
    SERVICE="ssh"
elif systemctl list-unit-files | grep -q '^sshd\.service'; then
    SERVICE="sshd"
else
    SERVICE="ssh"
fi

systemctl reload "$SERVICE" 2>/dev/null || systemctl restart "$SERVICE"

echo "SSH server configured: ${PARAM} ${VALUE}"
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

var_sshd_set_keepalive='
```


---

## RHEL-08-010201 — `sshd_set_idle_timeout`

**Prompt:** On an Ubuntu 24.04 system, configure the SSH server so that it probes connected clients for network responsiveness and automatically disconnects an unresponsive client after a 10-minute (600-second) interval of no response. This limits the window in which an unattended or orphaned management session could be taken over by unauthorized personnel. Write an idempotent bash remediation script that enforces this client-responsiveness timeout for the SSH server and persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

# Configure SSH server client responsiveness timeout:
# ClientAliveInterval 300 + ClientAliveCountMax 2 = 600s (10 min) before disconnect.

SSHD_CONFIG="/etc/ssh/sshd_config"
DROPIN_DIR="/etc/ssh/sshd_config.d"
DROPIN_FILE="${DROPIN_DIR}/99-client-alive-timeout.conf"

INTERVAL=300
COUNTMAX=2

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# Ensure main sshd_config exists
if [[ ! -f "$SSHD_CONFIG" ]]; then
    echo "Error: ${SSHD_CONFIG} not found." >&2
    exit 1
fi

# Comment out any conflicting directives in the main sshd_config
for directive in ClientAliveInterval ClientAliveCountMax; do
    if grep -Eiq "^[[:space:]]*${directive}[[:space:]]" "$SSHD_CONFIG"; then
        sed -ri "s/^([[:space:]]*)(${directive}[[:space:]].*)$/#\1\2/I" "$SSHD_CONFIG"
    fi
done

# Comment out conflicting directives in any existing drop-in files (except ours)
if [[ -d "$DROPIN_DIR" ]]; then
    for f in "$DROPIN_DIR"/*.conf; do
        [[ -e "$f" ]] || continue
        [[ "$f" == "$DROPIN_FILE" ]] && continue
        for directive in ClientAliveInterval ClientAliveCountMax; do
            if grep -Eiq "^[[:space:]]*${directive}[[:space:]]" "$f"; then
                sed -ri "s/^([[:space:]]*)(${directive}[[:space:]].*)$/#\1\2/I" "$f"
            fi
        done
    done
fi

# Ensure the drop-in directory exists
mkdir -p "$DROPIN_DIR"
chmod 0755 "$DROPIN_DIR"

# Confirm the main config includes the drop-in directory
if ! grep -Eiq "^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf" "$SSHD_CONFIG"; then
    sed -i "1i Include ${DROPIN_DIR}/*.conf" "$SSHD_CONFIG"
fi

# Build desired drop-in content
DESIRED_CONTENT="# Managed by remediation script - enforces 600s client responsiveness timeout
ClientAliveInterval ${INTERVAL}
ClientAliveCountMax ${COUNTMAX}"

# Write drop-in file only if content differs (idempotent)
if [[ ! -f "$DROPIN_FILE" ]] || [[ "$(cat "$DROPIN_FILE")" != "$DESIRED_CONTENT" ]]; then
    printf '%s\n' "$DESIRED_CONTENT" > "$DROPIN_FILE"
fi
chmod 0644 "$DROPIN_FILE"
chown root:root "$DROPIN_FILE"

# Validate configuration
if ! sshd -t; then
    echo "Error: sshd configuration validation failed." >&2
    exit 1
fi

# Determine the SSH service unit name
SSH_SERVICE="ssh"
if ! systemctl list-unit-files 2>/dev/null | grep -q "^ssh\.service"; then
    if systemctl list-unit-files 2>/dev/null | grep -q "^sshd\.service"; then
        SSH_SERVICE="sshd"
    fi
fi

# Enable and reload the service so changes persist across reboots
systemctl enable "$SSH_SERVICE" >/dev/null 2>&1 || true

if systemctl is-active --quiet "$SSH_SERVICE"; then
    systemctl reload "$SSH_SERVICE" 2>/dev/null || systemctl restart "$SSH_SERVICE"
else
    systemctl restart "$SSH_SERVICE"
fi

echo "SSH client responsiveness timeout configured: ClientAliveInterval=${INTERVAL}, ClientAliveCountMax=${COUNTMAX} (600s total)."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

sshd_idle_timeout_value='
```


---

## RHEL-08-020330 — `sshd_disable_empty_passwords`

**Prompt:** On an Ubuntu 24.04 system, configure the SSH server so that remote logins to accounts that have empty passwords are explicitly forbidden. Even if an account is misconfigured with a blank password, the SSH service must refuse such authentication, closing a high-risk avenue for unauthorized remote access. Write an idempotent bash remediation script that enforces this restriction for the SSH daemon, ensuring the setting persists across reboots and service restarts.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PARAM="PermitEmptyPasswords"
VALUE="no"
MAIN_CONFIG="/etc/ssh/sshd_config"
DROPIN_DIR="/etc/ssh/sshd_config.d"
DROPIN_FILE="${DROPIN_DIR}/00-disable-empty-passwords.conf"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# Neutralize any conflicting settings in the main config file.
if [[ -f "$MAIN_CONFIG" ]]; then
    if grep -Eiq '^[[:space:]]*PermitEmptyPasswords[[:space:]]+' "$MAIN_CONFIG"; then
        sed -ri "s/^[[:space:]]*(PermitEmptyPasswords)[[:space:]]+.*/# \1 (managed via ${DROPIN_FILE})/I" "$MAIN_CONFIG"
    fi
fi

# Neutralize any conflicting settings in other drop-in files.
if [[ -d "$DROPIN_DIR" ]]; then
    for f in "$DROPIN_DIR"/*.conf; do
        [[ -e "$f" ]] || continue
        [[ "$f" == "$DROPIN_FILE" ]] && continue
        if grep -Eiq '^[[:space:]]*PermitEmptyPasswords[[:space:]]+' "$f"; then
            sed -ri "s/^[[:space:]]*(PermitEmptyPasswords)[[:space:]]+.*/# \1 (managed via ${DROPIN_FILE})/I" "$f"
        fi
    done
fi

mkdir -p "$DROPIN_DIR"
chmod 0755 "$DROPIN_DIR"

DESIRED_CONTENT="${PARAM} ${VALUE}"

if [[ ! -f "$DROPIN_FILE" ]] || [[ "$(cat "$DROPIN_FILE")" != "$DESIRED_CONTENT" ]]; then
    printf '%s\n' "$DESIRED_CONTENT" > "$DROPIN_FILE"
fi
chmod 0644 "$DROPIN_FILE"
chown root:root "$DROPIN_FILE"

# Validate configuration before reloading.
if command -v sshd >/dev/null 2>&1; then
    sshd -t
fi

# Reload/restart the SSH service to apply and ensure persistence.
if command -v systemctl >/dev/null 2>&1; then
    SVC=""
    if systemctl list-unit-files | grep -q '^ssh\.service'; then
        SVC="ssh"
    elif systemctl list-unit-files | grep -q '^sshd\.service'; then
        SVC="sshd"
    fi
    if [[ -n "$SVC" ]]; then
        systemctl enable "$SVC" >/dev/null 2>&1 || true
        if systemctl is-active --quiet "$SVC"; then
            systemctl reload "$SVC" 2>/dev/null || systemctl restart "$SVC"
        else
            systemctl start "$SVC" || true
        fi
    fi
fi

echo "PermitEmptyPasswords is now enforced as '${VALUE}'."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if [ -e "/etc/ssh/sshd_config" ] ; then
    
    LC_ALL=C sed -i "/^\s*PermitEmptyPasswords\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"

cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert at the beginning of the file
printf '%s\n' "PermitEmptyPasswords no" > "/etc/ssh/sshd_config"
cat "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```


---

## RHEL-08-010522 — `sshd_disable_gssapi_auth`

**Prompt:** On an Ubuntu 24.04 system, the SSH server should not permit unnecessary authentication mechanisms that expand its attack surface. Specifically, the GSSAPI-based authentication mechanism must be explicitly disabled in the SSH server's configuration, since exposing it to remote hosts provides no benefit unless that mechanism is actively required and only increases risk. Write an idempotent bash remediation script that ensures GSSAPI-based authentication is explicitly turned off for the SSH server and that the setting persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
DROPIN_DIR="/etc/ssh/sshd_config.d"
DROPIN_FILE="${DROPIN_DIR}/00-disable-gssapi.conf"
DESIRED_SETTING="GSSAPIAuthentication no"

# Ensure the main sshd_config exists
if [[ ! -f "$SSHD_CONFIG" ]]; then
    echo "Error: $SSHD_CONFIG does not exist." >&2
    exit 1
fi

# Comment out any existing (uncommented) GSSAPIAuthentication lines in the main config
if grep -Eiq '^\s*GSSAPIAuthentication\b' "$SSHD_CONFIG"; then
    sed -ri 's/^(\s*)(GSSAPIAuthentication\b.*)$/#\1\2/I' "$SSHD_CONFIG"
fi

# Comment out any existing (uncommented) GSSAPIAuthentication lines in drop-in files
if [[ -d "$DROPIN_DIR" ]]; then
    while IFS= read -r -d '' f; do
        [[ "$f" == "$DROPIN_FILE" ]] && continue
        if grep -Eiq '^\s*GSSAPIAuthentication\b' "$f"; then
            sed -ri 's/^(\s*)(GSSAPIAuthentication\b.*)$/#\1\2/I' "$f"
        fi
    done < <(find "$DROPIN_DIR" -maxdepth 1 -type f -name '*.conf' -print0)
fi

# Ensure the drop-in directory exists
mkdir -p "$DROPIN_DIR"
chmod 0755 "$DROPIN_DIR"

# Write the authoritative drop-in file (idempotent)
if [[ ! -f "$DROPIN_FILE" ]] || [[ "$(cat "$DROPIN_FILE" 2>/dev/null)" != "$DESIRED_SETTING" ]]; then
    printf '%s\n' "$DESIRED_SETTING" > "$DROPIN_FILE"
fi
chmod 0600 "$DROPIN_FILE"

# Verify configuration syntax
if command -v sshd >/dev/null 2>&1; then
    sshd -t
fi

# Reload the SSH service to apply changes, if it is active
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet ssh 2>/dev/null; then
        systemctl reload ssh || systemctl restart ssh
    elif systemctl is-active --quiet sshd 2>/dev/null; then
        systemctl reload sshd || systemctl restart sshd
    fi
fi

echo "GSSAPI authentication has been explicitly disabled."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if [ -e "/etc/ssh/sshd_config" ] ; then
    
    LC_ALL=C sed -i "/^\s*GSSAPIAuthentication\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"

cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert at the beginning of the file
printf '%s\n' "GSSAPIAuthentication no" > "/etc/ssh/sshd_config"
cat "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```


---

## RHEL-08-010521 — `sshd_disable_kerb_auth`

**Prompt:** On an Ubuntu 24.04 system, ensure the SSH server does not permit Kerberos-based authentication, eliminating an unnecessary remote authentication pathway that could expose the system's Kerberos implementation or be exploited if misconfigured. Write an idempotent bash remediation script that explicitly disables Kerberos authentication in the SSH server's configuration and ensures the setting persists.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

SETTING="KerberosAuthentication no"
KEY="KerberosAuthentication"

# Primary config file
MAIN_CONFIG="/etc/ssh/sshd_config"

# Drop-in directory (preferred on Ubuntu 24.04)
DROPIN_DIR="/etc/ssh/sshd_config.d"
DROPIN_FILE="${DROPIN_DIR}/50-disable-kerberos.conf"

# Remove any existing (possibly conflicting) KerberosAuthentication directives
# from the main config file so our setting is authoritative.
if [ -f "$MAIN_CONFIG" ]; then
    if grep -qiE '^\s*KerberosAuthentication\b' "$MAIN_CONFIG"; then
        sed -i -E 's/^(\s*KerberosAuthentication\b.*)$/# \1 (disabled by remediation script)/I' "$MAIN_CONFIG"
    fi
fi

# Remove KerberosAuthentication directives from any other drop-in files
if [ -d "$DROPIN_DIR" ]; then
    for f in "$DROPIN_DIR"/*.conf; do
        [ -e "$f" ] || continue
        [ "$f" = "$DROPIN_FILE" ] && continue
        if grep -qiE '^\s*KerberosAuthentication\b' "$f"; then
            sed -i -E 's/^(\s*KerberosAuthentication\b.*)$/# \1 (disabled by remediation script)/I' "$f"
        fi
    done
fi

# Ensure drop-in directory exists
mkdir -p "$DROPIN_DIR"
chmod 0755 "$DROPIN_DIR"

# Write the authoritative setting into a drop-in file (idempotent)
if [ ! -f "$DROPIN_FILE" ] || ! grep -qiE "^\s*${KEY}\s+no\s*$" "$DROPIN_FILE"; then
    printf '%s\n' "$SETTING" > "$DROPIN_FILE"
fi
chmod 0644 "$DROPIN_FILE"
chown root:root "$DROPIN_FILE"

# Validate configuration before reloading
if command -v sshd >/dev/null 2>&1; then
    if ! sshd -t; then
        echo "ERROR: sshd configuration test failed. Not reloading." >&2
        exit 1
    fi
fi

# Reload SSH service to apply changes
if command -v systemctl >/dev/null 2>&1; then
    if systemctl list-unit-files | grep -qE '^ssh\.service'; then
        systemctl reload ssh 2>/dev/null || systemctl restart ssh
    elif systemctl list-unit-files | grep -qE '^sshd\.service'; then
        systemctl reload sshd 2>/dev/null || systemctl restart sshd
    fi
fi

echo "KerberosAuthentication has been disabled in the SSH server configuration."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if [ -e "/etc/ssh/sshd_config" ] ; then
    
    LC_ALL=C sed -i "/^\s*KerberosAuthentication\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"

cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert at the beginning of the file
printf '%s\n' "KerberosAuthentication no" > "/etc/ssh/sshd_config"
cat "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```


---

## RHEL-08-010550 — `sshd_disable_root_login`

**Prompt:** On an Ubuntu 24.04 system, configure the SSH server so that the root account can never authenticate or log in directly over the network. Direct remote root logins remove individual accountability and present a high-value target for password-guessing attacks; administrators should instead log in with their own accounts and escalate privileges. Write an idempotent bash remediation script that ensures direct remote root login through SSH is denied, and that the change persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation script: Deny direct remote root login over SSH.
# Idempotent and persistent across reboots.
#
set -euo pipefail

# Must run as root to modify sshd configuration and restart the service.
if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

SSHD_CONFIG="/etc/ssh/sshd_config"
DROPIN_DIR="/etc/ssh/sshd_config.d"
DROPIN_FILE="${DROPIN_DIR}/00-disable-root-login.conf"
DESIRED_VALUE="no"
DIRECTIVE="PermitRootLogin"

# Ensure the main sshd_config exists.
if [[ ! -f "${SSHD_CONFIG}" ]]; then
    echo "ERROR: ${SSHD_CONFIG} not found. Is the SSH server installed?" >&2
    exit 1
fi

# Neutralize any active (uncommented) PermitRootLogin lines in the main config
# so they cannot override our drop-in. Comment them out idempotently.
if grep -Eiq '^[[:space:]]*PermitRootLogin[[:space:]]+' "${SSHD_CONFIG}"; then
    # Backup once before first modification.
    if [[ ! -f "${SSHD_CONFIG}.orig-permitrootlogin" ]]; then
        cp -a "${SSHD_CONFIG}" "${SSHD_CONFIG}.orig-permitrootlogin"
    fi
    sed -ri 's/^([[:space:]]*)(PermitRootLogin[[:space:]]+.*)$/\1# \2  # disabled by remediation/I' "${SSHD_CONFIG}"
fi

# Ensure the drop-in directory exists (Ubuntu 24.04 includes it by default).
if [[ ! -d "${DROPIN_DIR}" ]]; then
    mkdir -p "${DROPIN_DIR}"
    chmod 0755 "${DROPIN_DIR}"
fi

# Confirm the main config includes the drop-in directory; if not, add it.
if ! grep -Eiq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "${SSHD_CONFIG}"; then
    printf '\nInclude /etc/ssh/sshd_config.d/*.conf\n' >> "${SSHD_CONFIG}"
fi

# Write the authoritative drop-in file to deny root login.
DESIRED_CONTENT="# Managed by remediation script: deny direct remote root SSH login.
${DIRECTIVE} ${DESIRED_VALUE}
"

if [[ ! -f "${DROPIN_FILE}" ]] || [[ "$(cat "${DROPIN_FILE}")" != "${DESIRED_CONTENT}" ]]; then
    printf '%s' "${DESIRED_CONTENT}" > "${DROPIN_FILE}"
fi
chmod 0644 "${DROPIN_FILE}"
chown root:root "${DROPIN_FILE}"

# Validate the resulting SSH configuration before applying.
if ! sshd -t; then
    echo "ERROR: sshd configuration test failed. Not restarting service." >&2
    exit 1
fi

# Verify the effective setting resolves to 'no'.
EFFECTIVE="$(sshd -T 2>/dev/null | awk 'tolower($1)=="permitrootlogin"{print tolower($2)}' | tail -n1)"
if [[ "${EFFECTIVE}" != "${DESIRED_VALUE}" ]]; then
    echo "ERROR: Effective PermitRootLogin is '${EFFECTIVE}', expected '${DESIRED_VALUE}'." >&2
    exit 1
fi

# Determine the correct SSH service unit name and reload/restart to persist.
if systemctl list-unit-files 2>/dev/null | grep -q '^ssh\.service'; then
    SSH_SERVICE="ssh"
elif systemctl list-unit-files 2>/dev/null | grep -q '^sshd\.service'; then
    SSH_SERVICE="sshd"
else
    SSH_SERVICE="ssh"
fi

# Ensure the service is enabled so the change persists across reboots.
systemctl enable "${SSH_SERVICE}" >/dev/null 2>&1 || true

# Apply the configuration to the running service if it is active.
if systemctl is-active --quiet "${SSH_SERVICE}"; then
    systemctl reload "${SSH_SERVICE}" 2>/dev/null || systemctl restart "${SSH_SERVICE}"
fi

echo "SUCCESS: Direct remote root SSH login is disabled (PermitRootLogin ${DESIRED_VALUE})."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if [ -e "/etc/ssh/sshd_config" ] ; then
    
    LC_ALL=C sed -i "/^\s*PermitRootLogin\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"

cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert at the beginning of the file
printf '%s\n' "PermitRootLogin no" > "/etc/ssh/sshd_config"
cat "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```


---

## RHEL-08-010520 — `sshd_disable_user_known_hosts`

**Prompt:** On an Ubuntu 24.04 system, configure the SSH server so that it does not trust or rely on any per-user cache of previously seen remote host public keys when authenticating connections. This hardens authentication by ensuring such cached host keys cannot be used to bypass normal credential checks, even if other settings are misconfigured. Write an idempotent bash remediation script that enforces this behavior for the SSH server and ensures it persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure the SSH server does not trust/rely on per-user cached
# host keys (~/.ssh/known_hosts) when authenticating connections.
#
# This is controlled by the sshd option "IgnoreUserKnownHosts yes".
#
set -euo pipefail

CONFIG_MAIN="/etc/ssh/sshd_config"
DROPIN_DIR="/etc/ssh/sshd_config.d"
DROPIN_FILE="${DROPIN_DIR}/99-ignore-user-known-hosts.conf"
DESIRED_KEY="IgnoreUserKnownHosts"
DESIRED_VALUE="yes"

if [[ $(id -u) -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# Comment out any conflicting/existing settings in the main config file so the
# drop-in authoritatively controls the value.
if [[ -f "${CONFIG_MAIN}" ]]; then
    if grep -Eiq '^[[:space:]]*IgnoreUserKnownHosts[[:space:]]' "${CONFIG_MAIN}"; then
        cp -a "${CONFIG_MAIN}" "${CONFIG_MAIN}.bak.$(date +%Y%m%d%H%M%S)"
        sed -ri 's/^([[:space:]]*)(IgnoreUserKnownHosts[[:space:]].*)$/\1# \2 # disabled by remediation/I' "${CONFIG_MAIN}"
    fi
fi

# Comment out any conflicting settings in other drop-in files (except ours).
if [[ -d "${DROPIN_DIR}" ]]; then
    shopt -s nullglob
    for f in "${DROPIN_DIR}"/*.conf; do
        [[ "${f}" == "${DROPIN_FILE}" ]] && continue
        if grep -Eiq '^[[:space:]]*IgnoreUserKnownHosts[[:space:]]' "${f}"; then
            cp -a "${f}" "${f}.bak.$(date +%Y%m%d%H%M%S)"
            sed -ri 's/^([[:space:]]*)(IgnoreUserKnownHosts[[:space:]].*)$/\1# \2 # disabled by remediation/I' "${f}"
        fi
    done
    shopt -u nullglob
fi

# Ensure the drop-in directory exists.
mkdir -p "${DROPIN_DIR}"
chmod 0755 "${DROPIN_DIR}"

# Write the authoritative drop-in configuration idempotently.
DESIRED_CONTENT="# Managed by remediation script - do not edit
${DESIRED_KEY} ${DESIRED_VALUE}"

if [[ ! -f "${DROPIN_FILE}" ]] || [[ "$(cat "${DROPIN_FILE}")" != "${DESIRED_CONTENT}" ]]; then
    printf '%s\n' "${DESIRED_CONTENT}" > "${DROPIN_FILE}"
fi
chmod 0600 "${DROPIN_FILE}"
chown root:root "${DROPIN_FILE}"

# Validate the configuration before reloading.
if command -v sshd >/dev/null 2>&1; then
    if ! sshd -t; then
        echo "sshd configuration validation failed. Aborting." >&2
        exit 1
    fi
fi

# Determine the correct service name and reload to persist across reboots.
SERVICE=""
if systemctl list-unit-files 2>/dev/null | grep -q '^ssh\.service'; then
    SERVICE="ssh"
elif systemctl list-unit-files 2>/dev/null | grep -q '^sshd\.service'; then
    SERVICE="sshd"
fi

if [[ -n "${SERVICE}" ]]; then
    systemctl enable "${SERVICE}" >/dev/null 2>&1 || true
    if systemctl is-active --quiet "${SERVICE}"; then
        systemctl reload "${SERVICE}" 2>/dev/null || systemctl restart "${SERVICE}"
    else
        systemctl restart "${SERVICE}" || true
    fi
fi

# Verify effective setting.
if command -v sshd >/dev/null 2>&1; then
    if sshd -T 2>/dev/null | grep -qi '^ignoreuserknownhosts yes'; then
        echo "Success: IgnoreUserKnownHosts is set to yes."
    else
        echo "Warning: could not confirm IgnoreUserKnownHosts=yes via 'sshd -T'." >&2
    fi
fi

echo "Remediation complete."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if [ -e "/etc/ssh/sshd_config" ] ; then
    
    LC_ALL=C sed -i "/^\s*IgnoreUserKnownHosts\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"

cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert at the beginning of the file
printf '%s\n' "IgnoreUserKnownHosts yes" > "/etc/ssh/sshd_config"
cat "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```


---

## RHEL-08-040340 — `sshd_disable_x11_forwarding`

**Prompt:** On an Ubuntu 24.04 system, configure the SSH server so that it does not tunnel graphical (X11) display traffic over SSH connections, since forwarded X11 sessions can expose a user's local display server to compromise by other users on the remote host. Write an idempotent bash remediation script that explicitly disables this graphical forwarding capability for the SSH server, ensuring the setting persists across reboots and service restarts.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
DIRECTIVE="X11Forwarding"
VALUE="no"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

if [[ ! -f "$SSHD_CONFIG" ]]; then
    echo "SSH server configuration file not found: $SSHD_CONFIG" >&2
    exit 1
fi

# Backup once
if [[ ! -f "${SSHD_CONFIG}.bak" ]]; then
    cp -p "$SSHD_CONFIG" "${SSHD_CONFIG}.bak"
fi

# Neutralize any X11Forwarding directives in drop-in config files that could override our setting
DROPIN_DIR="/etc/ssh/sshd_config.d"
if [[ -d "$DROPIN_DIR" ]]; then
    for f in "$DROPIN_DIR"/*.conf; do
        [[ -e "$f" ]] || continue
        if grep -Eiq '^[[:space:]]*X11Forwarding[[:space:]]+' "$f"; then
            sed -ri "s|^[[:space:]]*(X11Forwarding)[[:space:]]+.*|\1 ${VALUE}|I" "$f"
        fi
    done
fi

# Ensure the main sshd_config has the correct setting
if grep -Eiq '^[[:space:]]*X11Forwarding[[:space:]]+' "$SSHD_CONFIG"; then
    sed -ri "s|^[[:space:]]*#?[[:space:]]*(X11Forwarding)[[:space:]]+.*|\1 ${VALUE}|I" "$SSHD_CONFIG"
elif grep -Eiq '^[[:space:]]*#[[:space:]]*X11Forwarding[[:space:]]+' "$SSHD_CONFIG"; then
    sed -ri "s|^[[:space:]]*#[[:space:]]*(X11Forwarding)[[:space:]]+.*|\1 ${VALUE}|I" "$SSHD_CONFIG"
else
    printf '\n%s %s\n' "$DIRECTIVE" "$VALUE" >> "$SSHD_CONFIG"
fi

# Verify only a single effective directive set to no
if ! grep -Eiq "^[[:space:]]*X11Forwarding[[:space:]]+${VALUE}[[:space:]]*$" "$SSHD_CONFIG"; then
    echo "Failed to set ${DIRECTIVE} to ${VALUE} in ${SSHD_CONFIG}" >&2
    exit 1
fi

# Validate configuration
if command -v sshd >/dev/null 2>&1; then
    if ! sshd -t; then
        echo "sshd configuration test failed. Restoring backup." >&2
        cp -p "${SSHD_CONFIG}.bak" "$SSHD_CONFIG"
        exit 1
    fi
fi

# Restart/reload the SSH service to apply changes
if command -v systemctl >/dev/null 2>&1; then
    SVC=""
    for candidate in ssh.service sshd.service; do
        if systemctl list-unit-files --type=service 2>/dev/null | grep -q "^${candidate}"; then
            SVC="$candidate"
            break
        fi
    done
    if [[ -n "$SVC" ]]; then
        if systemctl is-active --quiet "$SVC"; then
            systemctl restart "$SVC"
        fi
        systemctl enable "$SVC" >/dev/null 2>&1 || true
    fi
fi

echo "X11 forwarding has been disabled for the SSH server."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if [ -e "/etc/ssh/sshd_config" ] ; then
    
    LC_ALL=C sed -i "/^\s*X11Forwarding\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"

cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert at the beginning of the file
printf '%s\n' "X11Forwarding no" > "/etc/ssh/sshd_config"
cat "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```


---

## RHEL-08-010830 — `sshd_do_not_permit_user_env`

**Prompt:** On an Ubuntu 24.04 system, configure the SSH server so that users cannot supply or override environment variables when establishing an SSH connection, preventing them from manipulating the session environment to bypass access restrictions. Write an idempotent bash remediation script that explicitly disables user environment processing in the SSH server configuration and ensures the setting persists.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
DROPIN_DIR="/etc/ssh/sshd_config.d"
DROPIN_FILE="${DROPIN_DIR}/99-disable-user-environment.conf"
DESIRED_SETTING="PermitUserEnvironment no"

# Ensure the main config exists
if [[ ! -f "$SSHD_CONFIG" ]]; then
    echo "Error: $SSHD_CONFIG not found." >&2
    exit 1
fi

# Comment out any existing PermitUserEnvironment lines in the main config
if grep -Eiq '^\s*PermitUserEnvironment\b' "$SSHD_CONFIG"; then
    sed -ri 's/^(\s*)(PermitUserEnvironment\b.*)$/#\1\2/I' "$SSHD_CONFIG"
fi

# Comment out any existing PermitUserEnvironment lines in drop-in files
if [[ -d "$DROPIN_DIR" ]]; then
    for f in "$DROPIN_DIR"/*.conf; do
        [[ -e "$f" ]] || continue
        [[ "$f" == "$DROPIN_FILE" ]] && continue
        if grep -Eiq '^\s*PermitUserEnvironment\b' "$f"; then
            sed -ri 's/^(\s*)(PermitUserEnvironment\b.*)$/#\1\2/I' "$f"
        fi
    done
fi

# Ensure the drop-in directory exists
mkdir -p "$DROPIN_DIR"
chmod 0755 "$DROPIN_DIR"

# Ensure the main config includes the drop-in directory
if ! grep -Eiq '^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf' "$SSHD_CONFIG"; then
    printf '\nInclude /etc/ssh/sshd_config.d/*.conf\n' >> "$SSHD_CONFIG"
fi

# Write the authoritative drop-in file idempotently
if [[ ! -f "$DROPIN_FILE" ]] || [[ "$(cat "$DROPIN_FILE")" != "$DESIRED_SETTING" ]]; then
    printf '%s\n' "$DESIRED_SETTING" > "$DROPIN_FILE"
fi
chmod 0600 "$DROPIN_FILE"
chown root:root "$DROPIN_FILE"

# Validate the SSH configuration
if command -v sshd >/dev/null 2>&1; then
    sshd -t
fi

# Reload the SSH service to apply changes
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet ssh; then
        systemctl reload ssh || systemctl restart ssh
    elif systemctl is-active --quiet sshd; then
        systemctl reload sshd || systemctl restart sshd
    fi
fi

echo "PermitUserEnvironment has been disabled successfully."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if [ -e "/etc/ssh/sshd_config" ] ; then
    
    LC_ALL=C sed -i "/^\s*PermitUserEnvironment\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"

cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert at the beginning of the file
printf '%s\n' "PermitUserEnvironment no" > "/etc/ssh/sshd_config"
cat "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```


---

## RHEL-08-010500 — `sshd_enable_strictmodes`

**Prompt:** On an Ubuntu 24.04 system, configure the SSH server so that before accepting a login it verifies the ownership and permissions of the user's home directory and SSH-related files, rejecting authentication when those files are world-writable or otherwise insecurely owned. This prevents an attacker who can modify another user's SSH files from logging in as that user. Write an idempotent bash remediation script that explicitly enforces this checking and ensures the setting persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: enforce SSH StrictModes so sshd verifies ownership and
# permissions of user home directories and SSH-related files before
# accepting a login. Rejects authentication when those files are
# world-writable or otherwise insecurely owned.
#
set -euo pipefail

DIRECTIVE="StrictModes"
VALUE="yes"
MAIN_CONFIG="/etc/ssh/sshd_config"
DROPIN_DIR="/etc/ssh/sshd_config.d"
DROPIN_FILE="${DROPIN_DIR}/00-strictmodes.conf"

if [[ ${EUID} -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# Ensure drop-in directory exists.
mkdir -p "${DROPIN_DIR}"
chmod 0755 "${DROPIN_DIR}"

# Confirm the main config includes the drop-in directory; if not, add it.
if [[ -f "${MAIN_CONFIG}" ]]; then
    if ! grep -Eq '^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf' "${MAIN_CONFIG}"; then
        echo "Include ${DROPIN_DIR}/*.conf" >> "${MAIN_CONFIG}"
    fi
fi

# Comment out any conflicting StrictModes settings in the main config.
if [[ -f "${MAIN_CONFIG}" ]]; then
    if grep -Eiq '^\s*StrictModes\b' "${MAIN_CONFIG}"; then
        sed -ri 's/^(\s*)(StrictModes\b.*)$/\1#\2  # disabled by remediation/I' "${MAIN_CONFIG}"
    fi
fi

# Comment out conflicting StrictModes settings in other drop-in files.
if [[ -d "${DROPIN_DIR}" ]]; then
    for f in "${DROPIN_DIR}"/*.conf; do
        [[ -e "${f}" ]] || continue
        [[ "${f}" == "${DROPIN_FILE}" ]] && continue
        if grep -Eiq '^\s*StrictModes\b' "${f}"; then
            sed -ri 's/^(\s*)(StrictModes\b.*)$/\1#\2  # disabled by remediation/I' "${f}"
        fi
    done
fi

# Write the authoritative drop-in configuration idempotently.
DESIRED_CONTENT="# Managed by remediation script - enforce SSH StrictModes
${DIRECTIVE} ${VALUE}"

if [[ ! -f "${DROPIN_FILE}" ]] || [[ "$(cat "${DROPIN_FILE}")" != "${DESIRED_CONTENT}" ]]; then
    printf '%s\n' "${DESIRED_CONTENT}" > "${DROPIN_FILE}"
fi

chmod 0644 "${DROPIN_FILE}"
chown root:root "${DROPIN_FILE}"

# Validate configuration before restarting.
if ! sshd -t; then
    echo "sshd configuration test failed. Aborting without restart." >&2
    exit 1
fi

# Determine correct service name and reload/restart to apply.
SERVICE=""
if systemctl list-unit-files 2>/dev/null | grep -q '^ssh\.service'; then
    SERVICE="ssh"
elif systemctl list-unit-files 2>/dev/null | grep -q '^sshd\.service'; then
    SERVICE="sshd"
fi

if [[ -n "${SERVICE}" ]]; then
    systemctl enable "${SERVICE}" >/dev/null 2>&1 || true
    if systemctl is-active --quiet "${SERVICE}"; then
        systemctl reload "${SERVICE}" 2>/dev/null || systemctl restart "${SERVICE}"
    else
        systemctl restart "${SERVICE}" || true
    fi
fi

echo "StrictModes has been set to '${VALUE}' in ${DROPIN_FILE} and applied."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if [ -e "/etc/ssh/sshd_config" ] ; then
    
    LC_ALL=C sed -i "/^\s*StrictModes\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"

cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert at the beginning of the file
printf '%s\n' "StrictModes yes" > "/etc/ssh/sshd_config"
cat "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```


---

## RHEL-08-010040 — `sshd_enable_warning_banner`

**Prompt:** On an Ubuntu 24.04 system, configure the SSH server so that it presents the system-wide warning banner to users before authentication, reinforcing policy awareness at logon and supporting potential legal action against unauthorized access. The banner displayed must be the standard system-wide login warning message. Write an idempotent bash remediation script that ensures the SSH server displays this banner for connecting users, with the change persisting across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

BANNER_FILE="/etc/issue.net"
SSHD_CONFIG="/etc/ssh/sshd_config"
DROPIN_DIR="/etc/ssh/sshd_config.d"

# Ensure the system-wide warning banner file exists with standard content
if [ ! -s "$BANNER_FILE" ]; then
    cat > "$BANNER_FILE" <<'EOF'
Authorized uses only. All activity may be monitored and reported.
EOF
    chmod 0644 "$BANNER_FILE"
    chown root:root "$BANNER_FILE"
fi

configure_banner() {
    local file="$1"

    # Remove any existing Banner directives (commented or not)
    if [ -f "$file" ]; then
        sed -ri '/^\s*#?\s*Banner\s+/d' "$file"
    fi
}

# Clean any Banner directives in drop-in files
if [ -d "$DROPIN_DIR" ]; then
    for f in "$DROPIN_DIR"/*.conf; do
        [ -e "$f" ] || continue
        configure_banner "$f"
    done
fi

# Clean main config
configure_banner "$SSHD_CONFIG"

# Add authoritative Banner setting via a drop-in file (if drop-in dir is used)
if [ -d "$DROPIN_DIR" ] && grep -qE '^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf' "$SSHD_CONFIG"; then
    DROPIN_FILE="$DROPIN_DIR/99-banner.conf"
    echo "Banner $BANNER_FILE" > "$DROPIN_FILE"
    chmod 0644 "$DROPIN_FILE"
    chown root:root "$DROPIN_FILE"
else
    echo "Banner $BANNER_FILE" >> "$SSHD_CONFIG"
fi

# Validate configuration
if command -v sshd >/dev/null 2>&1; then
    sshd -t
fi

# Restart SSH service to apply changes
if systemctl list-unit-files | grep -qE '^ssh\.service'; then
    systemctl restart ssh
elif systemctl list-unit-files | grep -qE '^sshd\.service'; then
    systemctl restart sshd
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if [ -e "/etc/ssh/sshd_config" ] ; then
    
    LC_ALL=C sed -i "/^\s*Banner\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"

cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert at the beginning of the file
printf '%s\n' "Banner /etc/issue" > "/etc/ssh/sshd_config"
cat "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```


---

## RHEL-08-020350 — `sshd_print_last_log`

**Prompt:** On an Ubuntu 24.04 system, ensure the SSH server displays the date and time of each user's last successful login when they authenticate. Showing this information helps users notice and report unauthorized use of their accounts. Write an idempotent bash remediation script that explicitly enables this last-login notification behavior in the SSH server configuration so it takes effect for subsequent logins.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
DROPIN_DIR="/etc/ssh/sshd_config.d"
DROPIN_FILE="${DROPIN_DIR}/50-printlastlog.conf"

# Ensure the main config file exists
if [[ ! -f "$SSHD_CONFIG" ]]; then
    echo "Error: $SSHD_CONFIG not found." >&2
    exit 1
fi

# Remove/comment any conflicting PrintLastLog directives in the main config
if grep -Eiq '^\s*PrintLastLog\b' "$SSHD_CONFIG"; then
    sed -ri 's/^\s*PrintLastLog\b.*/# &/I' "$SSHD_CONFIG"
fi

# Remove/comment any conflicting PrintLastLog directives in existing drop-in files
if [[ -d "$DROPIN_DIR" ]]; then
    for f in "$DROPIN_DIR"/*.conf; do
        [[ -e "$f" ]] || continue
        [[ "$f" == "$DROPIN_FILE" ]] && continue
        if grep -Eiq '^\s*PrintLastLog\b' "$f"; then
            sed -ri 's/^\s*PrintLastLog\b.*/# &/I' "$f"
        fi
    done
fi

# Create the drop-in directory if needed
mkdir -p "$DROPIN_DIR"
chmod 0755 "$DROPIN_DIR"

# Write the authoritative drop-in configuration
cat > "$DROPIN_FILE" <<'EOF'
# Managed by remediation script: display last successful login on authentication
PrintLastLog yes
EOF
chmod 0644 "$DROPIN_FILE"

# Ensure the main config includes drop-in files (Ubuntu 24.04 default does)
if ! grep -Eiq '^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf' "$SSHD_CONFIG"; then
    sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' "$SSHD_CONFIG"
fi

# Validate the configuration
if command -v sshd >/dev/null 2>&1; then
    sshd -t
elif [[ -x /usr/sbin/sshd ]]; then
    /usr/sbin/sshd -t
fi

# Reload/restart the SSH service so the change takes effect for subsequent logins
if command -v systemctl >/dev/null 2>&1; then
    if systemctl list-unit-files 2>/dev/null | grep -q '^ssh\.service'; then
        systemctl reload ssh 2>/dev/null || systemctl restart ssh
    elif systemctl list-unit-files 2>/dev/null | grep -q '^sshd\.service'; then
        systemctl reload sshd 2>/dev/null || systemctl restart sshd
    fi
fi

echo "PrintLastLog enabled in ${DROPIN_FILE}."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if [ -e "/etc/ssh/sshd_config" ] ; then
    
    LC_ALL=C sed -i "/^\s*PrintLastLog\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"

cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert at the beginning of the file
printf '%s\n' "PrintLastLog yes" > "/etc/ssh/sshd_config"
cat "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```


---

## RHEL-08-040161 — `sshd_rekey_limit`

**Prompt:** On an Ubuntu 24.04 system, harden the SSH server by forcing more frequent renegotiation of session encryption keys, which limits the volume of data and the time window an attacker could exploit against a given key. Configure the SSH server so that the session key is renegotiated after at most 512 megabytes of transmitted data and after at most one hour of elapsed time, whichever comes first. Write an idempotent bash remediation script that enforces these limits persistently.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
DROPIN_DIR="/etc/ssh/sshd_config.d"
DROPIN_FILE="${DROPIN_DIR}/99-rekey-limit.conf"

DESIRED_VALUE="512M 3600"

# Ensure the sshd_config exists
if [[ ! -f "${SSHD_CONFIG}" ]]; then
    echo "Error: ${SSHD_CONFIG} not found." >&2
    exit 1
fi

# Comment out any existing RekeyLimit directives in the main config
if grep -Eiq '^[[:space:]]*RekeyLimit[[:space:]]' "${SSHD_CONFIG}"; then
    sed -ri 's/^([[:space:]]*)(RekeyLimit[[:space:]].*)$/#\1\2/I' "${SSHD_CONFIG}"
fi

# Comment out any existing RekeyLimit directives in existing drop-in files
if [[ -d "${DROPIN_DIR}" ]]; then
    for f in "${DROPIN_DIR}"/*.conf; do
        [[ -e "${f}" ]] || continue
        [[ "${f}" == "${DROPIN_FILE}" ]] && continue
        if grep -Eiq '^[[:space:]]*RekeyLimit[[:space:]]' "${f}"; then
            sed -ri 's/^([[:space:]]*)(RekeyLimit[[:space:]].*)$/#\1\2/I' "${f}"
        fi
    done
fi

# Ensure the main config includes the drop-in directory
if ! grep -Eiq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "${SSHD_CONFIG}"; then
    # Prepend Include directive at the top of the config
    tmpfile="$(mktemp)"
    {
        echo "Include ${DROPIN_DIR}/*.conf"
        cat "${SSHD_CONFIG}"
    } > "${tmpfile}"
    cat "${tmpfile}" > "${SSHD_CONFIG}"
    rm -f "${tmpfile}"
fi

# Create the drop-in directory if it does not exist
mkdir -p "${DROPIN_DIR}"
chmod 0755 "${DROPIN_DIR}"

# Write the desired configuration idempotently
DESIRED_CONTENT="# Managed by hardening script: force frequent SSH rekeying
RekeyLimit ${DESIRED_VALUE}
"

if [[ ! -f "${DROPIN_FILE}" ]] || [[ "$(cat "${DROPIN_FILE}")" != "${DESIRED_CONTENT}" ]]; then
    printf '%s' "${DESIRED_CONTENT}" > "${DROPIN_FILE}"
fi

chmod 0644 "${DROPIN_FILE}"
chown root:root "${DROPIN_FILE}"

# Validate the SSH configuration
if ! sshd -t; then
    echo "Error: sshd configuration validation failed." >&2
    exit 1
fi

# Reload/restart the SSH service to apply changes
if command -v systemctl >/dev/null 2>&1; then
    if systemctl list-unit-files | grep -q '^ssh\.service'; then
        systemctl reload ssh 2>/dev/null || systemctl restart ssh
    elif systemctl list-unit-files | grep -q '^sshd\.service'; then
        systemctl reload sshd 2>/dev/null || systemctl restart sshd
    fi
fi

echo "SSH RekeyLimit successfully set to '${DESIRED_VALUE}' in ${DROPIN_FILE}."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

var_rekey_limit_size='
```


---

## RHEL-08-010292 — `sshd_use_strong_rng`

**Prompt:** On an Ubuntu 24.04 system, the SSH server relies on the underlying crypto library's default random-number source, which is not guaranteed to draw from a high-entropy source; weak randomness could let an attacker predict encryption keys, padding, or initialization vectors. Configure the SSH server's environment so that it seeds its random-number generator from a high-quality entropy source using 32 bytes of entropy. Write an idempotent bash remediation script that enforces this setting persistently.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

SEED_FILE="/etc/ssh/prng_seed"
ENV_FILE="/etc/environment"
SSHD_CONFIG="/etc/ssh/sshd_config"
SEED_BYTES=32

# Ensure we run as root
if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# 1. Create/refresh a high-quality entropy seed file (32 bytes from /dev/random)
umask 077
tmp_seed="$(mktemp)"
dd if=/dev/random of="${tmp_seed}" bs=1 count="${SEED_BYTES}" 2>/dev/null

# Verify we actually got 32 bytes
actual_size="$(stat -c '%s' "${tmp_seed}")"
if [[ "${actual_size}" -ne "${SEED_BYTES}" ]]; then
    echo "Failed to gather ${SEED_BYTES} bytes of entropy (got ${actual_size})." >&2
    rm -f "${tmp_seed}"
    exit 1
fi

install -m 0600 -o root -g root "${tmp_seed}" "${SEED_FILE}"
rm -f "${tmp_seed}"

# 2. Persist EGD/PRNG environment variables so OpenSSL/SSH seeds from high-quality source.
#    OPENSSL_ALLOW_PROXY_CERTS is unrelated; we use RANDFILE and EGD-style settings.
ensure_env_var() {
    local key="$1"
    local value="$2"
    local file="$3"
    local line="${key}=\"${value}\""

    touch "${file}"
    if grep -qE "^[[:space:]]*${key}=" "${file}"; then
        sed -i "s|^[[:space:]]*${key}=.*|${line}|" "${file}"
    else
        printf '%s\n' "${line}" >> "${file}"
    fi
}

# RANDFILE points OpenSSL's PRNG at our 32-byte high-entropy seed file.
ensure_env_var "RANDFILE" "${SEED_FILE}" "${ENV_FILE}"

# 3. Provide an sshd environment file so the SSH daemon inherits the RANDFILE setting.
SSHD_ENV_DIR="/etc/systemd/system/ssh.service.d"
SSHD_ENV_DROPIN="${SSHD_ENV_DIR}/prng-seed.conf"
mkdir -p "${SSHD_ENV_DIR}"

desired_dropin="$(cat <<EOF
[Service]
Environment="RANDFILE=${SEED_FILE}"
EOF
)"

if [[ ! -f "${SSHD_ENV_DROPIN}" ]] || [[ "$(cat "${SSHD_ENV_DROPIN}")" != "${desired_dropin}" ]]; then
    printf '%s\n' "${desired_dropin}" > "${SSHD_ENV_DROPIN}"
    chmod 0644 "${SSHD_ENV_DROPIN}"
    systemctl daemon-reload
fi

# 4. Ensure SSH accepts the user environment setting so the seed var is honored.
ensure_sshd_option() {
    local key="$1"
    local value="$2"
    local line="${key} ${value}"

    touch "${SSHD_CONFIG}"
    if grep -qE "^[[:space:]]*#?[[:space:]]*${key}[[:space:]]" "${SSHD_CONFIG}"; then
        sed -i "s|^[[:space:]]*#\?[[:space:]]*${key}[[:space:]].*|${line}|" "${SSHD_CONFIG}"
    else
        printf '%s\n' "${line}" >> "${SSHD_CONFIG}"
    fi
}

ensure_sshd_option "PermitUserEnvironment" "yes"

# 5. Validate sshd config and restart service if config is valid.
if sshd -t 2>/dev/null; then
    if systemctl list-unit-files | grep -qE '^ssh\.service'; then
        systemctl restart ssh
    elif systemctl list-unit-files | grep -qE '^sshd\.service'; then
        systemctl restart sshd
    fi
else
    echo "sshd configuration test failed; not restarting service." >&2
    exit 1
fi

echo "SSH PRNG seeding configured with ${SEED_BYTES} bytes of high-quality entropy."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if [ -e "/etc/sysconfig/sshd" ] ; then
    
    LC_ALL=C sed -i "/^\s*SSH_USE_STRONG_RNG\s*=\s*/d" "/etc/sysconfig/sshd"
else
    touch "/etc/sysconfig/sshd"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/sysconfig/sshd"

cp "/etc/sysconfig/sshd" "/etc/sysconfig/sshd.bak"
# Insert before the line matching the regex '^#\s*SSH_USE_STRONG_RNG'.
line_number="$(LC_ALL=C grep -n "^#\s*SSH_USE_STRONG_RNG" "/etc/sysconfig/sshd.bak" | LC_ALL=C sed 's/:.*//g')"
if [ -z "$line_number" ]; then
    # There was no match of '^#\s*SSH_USE_STRONG_RNG', insert at
    # the end of the file.
    printf '%s\n'
```


---

## RHEL-08-040341 — `sshd_x11_use_localhost`

**Prompt:** On an Ubuntu 24.04 system, configure the SSH server so that when X11 display forwarding is in use, the forwarding proxy display is bound only to the loopback interface and cannot be reached by remote hosts, limiting exposure of forwarded X11 sessions to off-host connections. Write an idempotent bash remediation script that enforces this loopback-only behavior for the SSH X11 forwarding proxy display and ensures it persists.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure SSH X11 forwarding proxy display is bound to loopback only.
# Sets "X11UseLocalhost yes" in the sshd configuration idempotently.

set -euo pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
DROPIN_DIR="/etc/ssh/sshd_config.d"
DROPIN_FILE="${DROPIN_DIR}/50-x11-localhost.conf"
DIRECTIVE="X11UseLocalhost"
VALUE="yes"

if [[ $(id -u) -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

if [[ ! -f "${SSHD_CONFIG}" ]]; then
    echo "Error: ${SSHD_CONFIG} not found. Is openssh-server installed?" >&2
    exit 1
fi

# Comment out any active (non-commented) X11UseLocalhost lines in the main config
# to avoid conflicting/overriding directives. sshd uses the first occurrence,
# so we neutralize existing ones and rely on our authoritative setting.
if grep -Eiq '^[[:space:]]*X11UseLocalhost[[:space:]]+' "${SSHD_CONFIG}"; then
    timestamp="$(date +%Y%m%d%H%M%S)"
    cp -a "${SSHD_CONFIG}" "${SSHD_CONFIG}.bak.${timestamp}"
    sed -ri 's/^([[:space:]]*)(X11UseLocalhost[[:space:]]+.*)$/\1# \2 # commented by remediation/I' "${SSHD_CONFIG}"
    echo "Neutralized existing ${DIRECTIVE} directives in ${SSHD_CONFIG} (backup: ${SSHD_CONFIG}.bak.${timestamp})."
fi

# Ensure the drop-in directory exists and is included by the main config.
if [[ -d "${DROPIN_DIR}" ]] && grep -Eiq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' "${SSHD_CONFIG}"; then
    mkdir -p "${DROPIN_DIR}"
    chmod 0755 "${DROPIN_DIR}"

    desired_content=$'# Managed by remediation script: bind X11 forwarding proxy to loopback only.\n'"${DIRECTIVE} ${VALUE}"$'\n'

    if [[ -f "${DROPIN_FILE}" ]] && [[ "$(cat "${DROPIN_FILE}")" == "${desired_content}" ]]; then
        echo "Drop-in ${DROPIN_FILE} already enforces ${DIRECTIVE} ${VALUE}. No change needed."
    else
        printf '%s' "${desired_content}" > "${DROPIN_FILE}"
        chmod 0644 "${DROPIN_FILE}"
        echo "Wrote ${DROPIN_FILE} enforcing ${DIRECTIVE} ${VALUE}."
    fi
else
    # No drop-in support; append/set directly in main config.
    mkdir -p "${DROPIN_DIR}" || true
    if grep -Eiq '^[[:space:]]*'"${DIRECTIVE}"'[[:space:]]+'"${VALUE}"'[[:space:]]*$' "${SSHD_CONFIG}"; then
        echo "${DIRECTIVE} ${VALUE} already present in ${SSHD_CONFIG}. No change needed."
    else
        printf '\n# Managed by remediation script: bind X11 forwarding proxy to loopback only.\n%s %s\n' "${DIRECTIVE}" "${VALUE}" >> "${SSHD_CONFIG}"
        echo "Appended ${DIRECTIVE} ${VALUE} to ${SSHD_CONFIG}."
    fi
fi

# Validate configuration before applying.
if ! sshd -t; then
    echo "Error: sshd configuration test failed. Not restarting service." >&2
    exit 1
fi

# Reload/restart SSH service to apply changes.
service_name=""
for svc in ssh sshd; do
    if systemctl list-unit-files 2>/dev/null | grep -q "^${svc}\.service"; then
        service_name="${svc}"
        break
    fi
done

if [[ -n "${service_name}" ]]; then
    if systemctl is-active --quiet "${service_name}"; then
        systemctl reload "${service_name}" 2>/dev/null || systemctl restart "${service_name}"
        echo "Reloaded ${service_name} service."
    else
        echo "${service_name} service is not active; configuration will apply when started."
    fi
else
    echo "Warning: could not determine SSH service unit; please reload sshd manually." >&2
fi

echo "Remediation complete: SSH X11 forwarding proxy display is bound to loopback only."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if [ -e "/etc/ssh/sshd_config" ] ; then
    
    LC_ALL=C sed -i "/^\s*X11UseLocalhost\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"

cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert at the beginning of the file
printf '%s\n' "X11UseLocalhost yes" > "/etc/ssh/sshd_config"
cat "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```


---

## RHEL-08-010400 — `sssd_certificate_verification`

**Prompt:** On an Ubuntu 24.04 system using the system security services daemon (SSSD) for smart-card / certificate-based multifactor authentication, configure it so that the validity of authentication certificates is verified in real time against the issuing authority's revocation status using the Online Certificate Status Protocol (OCSP). This prevents revoked or compromised certificates from being accepted for login. Write an idempotent bash remediation script that enables OCSP-based certificate status checking in SSSD and ensures the setting persists.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Enable OCSP-based certificate revocation checking in SSSD
# for smart-card / certificate-based authentication on Ubuntu 24.04.
#
set -euo pipefail

SSSD_CONF="/etc/sssd/sssd.conf"
SSSD_CONF_DIR="/etc/sssd/conf.d"
DROPIN="${SSSD_CONF_DIR}/999-ocsp-cert-verification.conf"

# Must run as root to modify SSSD configuration.
if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

# The desired certificate_verification value enabling OCSP checking.
DESIRED_VALUE="ocsp_dgst=sha1, no_ocsp=false"
DESIRED_SETTING="certificate_verification = ${DESIRED_VALUE}"

# Ensure the SSSD configuration directory exists with correct permissions.
if [[ ! -d "${SSSD_CONF_DIR}" ]]; then
    install -d -m 0711 -o root -g root "${SSSD_CONF_DIR}"
fi

configure_file() {
    local file="$1"
    local tmp
    tmp="$(mktemp)"

    if [[ -f "${file}" ]]; then
        cp -a "${file}" "${tmp}"
    else
        : > "${tmp}"
    fi

    # Determine if an [sssd] section exists.
    if grep -qE '^\s*\[sssd\]\s*$' "${tmp}"; then
        if grep -qE '^\s*certificate_verification\s*=' "${tmp}"; then
            # Replace existing certificate_verification line(s).
            sed -i -E "s|^\s*certificate_verification\s*=.*|${DESIRED_SETTING}|" "${tmp}"
        else
            # Insert the setting right after the [sssd] section header.
            awk -v setting="${DESIRED_SETTING}" '
                BEGIN { inserted=0 }
                {
                    print $0
                    if ($0 ~ /^[[:space:]]*\[sssd\][[:space:]]*$/ && inserted==0) {
                        print setting
                        inserted=1
                    }
                }
            ' "${tmp}" > "${tmp}.new"
            mv "${tmp}.new" "${tmp}"
        fi
    else
        # No [sssd] section: append one.
        {
            printf '\n[sssd]\n'
            printf '%s\n' "${DESIRED_SETTING}"
        } >> "${tmp}"
    fi

    # Only replace the target file if content changed (idempotency).
    if [[ ! -f "${file}" ]] || ! cmp -s "${tmp}" "${file}"; then
        install -m 0600 -o root -g root "${tmp}" "${file}"
        echo "Updated ${file} with OCSP certificate verification setting."
        CHANGED=1
    else
        echo "${file} already configured correctly; no change needed."
    fi

    rm -f "${tmp}"
}

CHANGED=0

# Prefer the drop-in configuration directory so the setting persists cleanly.
configure_file "${DROPIN}"

# If a main sssd.conf exists and defines certificate_verification with a
# conflicting/OCSP-disabling value, correct it as well so it does not override intent.
if [[ -f "${SSSD_CONF}" ]]; then
    if grep -qE '^\s*certificate_verification\s*=' "${SSSD_CONF}"; then
        if grep -qiE '^\s*certificate_verification\s*=.*no_ocsp\s*=\s*true' "${SSSD_CONF}" \
           || ! grep -qiE '^\s*certificate_verification\s*=.*no_ocsp\s*=\s*false' "${SSSD_CONF}"; then
            configure_file "${SSSD_CONF}"
        else
            echo "${SSSD_CONF} certificate_verification already enables OCSP."
        fi
    fi
fi

# Enforce correct ownership/permissions on config files (SSSD requires 0600).
chmod 0600 "${DROPIN}"
chown root:root "${DROPIN}"
if [[ -f "${SSSD_CONF}" ]]; then
    chmod 0600 "${SSSD_CONF}"
    chown root:root "${SSSD_CONF}"
fi

# Restart SSSD only if a change was made and the service is present.
if [[ "${CHANGED}" -eq 1 ]]; then
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl list-unit-files 2>/dev/null | grep -qE '^sssd\.service'; then
            echo "Restarting sssd to apply changes..."
            systemctl restart sssd || {
                echo "WARNING: Failed to restart sssd. Please review configuration." >&2
            }
        else
            echo "sssd.service not found; skipping restart."
        fi
    fi
else
    echo "No configuration changes required; SSSD not restarted."
fi

echo "OCSP certificate revocation checking configuration complete."
exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q sssd-common; then

var_sssd_certificate_verification_digest_function='
```


---

## RHEL-08-020250 — `sssd_enable_smartcards`

**Prompt:** On an Ubuntu 24.04 system, configure the system security services daemon to support smart-card (e.g. CAC/PIV token) based authentication, so that users can authenticate using a separate hardware credential rather than relying solely on passwords — providing multi-factor assurance even if the host itself is compromised. The end state must enable smart-card authentication within the system services daemon and integrate it into the host's authentication stack so that certificate-based login via the daemon is honored during authentication. Write an idempotent bash remediation script that establishes this configuration and persists across reboots.

**Model-generated script:**
```bash
```bash
#!/usr/bin/env bash
#
# Configure SSSD to support smart-card (CAC/PIV) based authentication on
# Ubuntu 24.04 and integrate it into the host's PAM authentication stack.
#
# This script is idempotent: it can be run multiple times and will only make
# changes when required, leaving a working configuration that persists across
# reboots.

set -euo pipefail

# --- Must run as root ------------------------------------------------------
if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive

SSSD_CONF="/etc/sssd/sssd.conf"
SSSD_CONF_DIR="/etc/sssd/conf.d"
PAM_CONFIG_DIR="/usr/share/pam-configs"
PAM_SSS_PROFILE="${PAM_CONFIG_DIR}/sss-smartcard"

# --- 1. Install required packages ------------------------------------------
REQUIRED_PKGS=(
    sssd
    sssd-tools
    libpam-sss
    opensc
    opensc-pkcs11
    pcscd
    libpcsclite1
    p11-kit
)

MISSING_PKGS=()
for pkg in "${REQUIRED_PKGS[@]}"; do
    if ! dpkg-query -W -f='${Status}' "${pkg}" 2>/dev/null | grep -q "install ok installed"; then
        MISSING_PKGS+=("${pkg}")
    fi
done

if [[ "${#MISSING_PKGS[@]}" -gt 0 ]]; then
    apt-get update -y
    apt-get install -y "${MISSING_PKGS[@]}"
fi

# --- 2. Ensure the pcscd smartcard daemon is enabled -----------------------
if systemctl list-unit-files | grep -q '^pcscd.socket'; then
    systemctl enable --now pcscd.socket 2>/dev/null || true
fi
if systemctl list-unit-files | grep -q '^pcscd.service'; then
    systemctl enable pcscd.service 2>/dev/null || true
fi

# --- 3. Create/patch the main sssd.conf ------------------------------------
mkdir -p "$(dirname "${SSSD_CONF}")"
mkdir -p "${SSSD_CONF_DIR}"

if [[ ! -f "${SSSD_CONF}" ]]; then
    cat > "${SSSD_CONF}" <<'EOF'
[sssd]
config_file_version = 2
services = nss, pam

[pam]
pam_cert_auth = True
EOF
fi

# Helper: ensure a key=value exists under a given [section] in an ini file.
# Adds the section if missing and updates or inserts the key.
ensure_ini_kv() {
    local file="$1" section="$2" key="$3" value="$4"
    python3 - "$file" "$section" "$key" "$value" <<'PYEOF'
import sys, re

path, section, key, value = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

try:
    with open(path, "r") as f:
        lines = f.readlines()
except FileNotFoundError:
    lines = []

sec_header = "[%s]" % section
out = []
in_section = False
found_section = False
key_written = False
key_re = re.compile(r'^\s*' + re.escape(key) + r'\s*=', re.IGNORECASE)
sec_re = re.compile(r'^\s*\[.*\]\s*$')

i = 0
n = len(lines)
while i < n:
    line = lines[i]
    stripped = line.strip()
    if sec_re.match(stripped):
        if in_section and not key_written:
            out.append("%s = %s\n" % (key, value))
            key_written = True
        in_section = (stripped == sec_header)
        if in_section:
            found_section = True
        out.append(line)
        i += 1
        continue
    if in_section and key_re.match(line):
        if not key_written:
            out.append("%s = %s\n" % (key, value))
            key_written = True
        i += 1
        continue
    out.append(line)
    i += 1

if in_section and not key_written:
    out.append("%s = %s\n" % (key, value))
    key_written = True

if not found_section:
    if out and not out[-1].endswith("\n"):
        out.append("\n")
    if out:
        out.append("\n")
    out.append("%s\n" % sec_header)
    out.append("%s = %s\n" % (key, value))

with open(path, "w") as f:
    f.writelines(out)
PYEOF
}

# Ensure the pam service is registered.
if grep -qE '^\s*services\s*=' "${SSSD_CONF}"; then
    if ! grep -E '^\s*services\s*=' "${SSSD_CONF}" | grep -q 'pam'; then
        sed -i -E 's/^(\s*services\s*=.*)$/\1, pam/' "${SSSD_CONF}"
    fi
else
    ensure_ini_kv "${SSSD_CONF}" "sssd" "services" "nss, pam"
fi

# Ensure config version.
ensure_ini_kv "${SSSD_CONF}" "sssd" "config_file_version" "2"

# Enable certificate-based (smart card) authentication in the pam responder.
ensure_ini_kv "${SSSD_CONF}" "pam" "pam_cert_auth" "True"

# Point SSSD at the OpenSC PKCS#11 module for smart card token reading.
if [[ -f /usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so ]]; then
    ensure_ini_kv "${SSSD_CONF}" "pam" "pam_p11_allowed_services" "+gdm-smartcard"
    ensure_ini_kv "${SSSD_CONF}" "pam" "p11_child_timeout" "60"
fi

# Certificate verification settings (no OCSP by default; can be tightened).
ensure_ini_kv "${SSSD_CONF}" "sssd" "certificate_verification" "no_ocsp"

chown root:root "${SSSD_CONF}"
chmod 0600 "${SSSD_CONF}"

# --- 4. Integrate smart card auth into the PAM stack -----------------------
# Provide a pam-auth-update profile so pam_sss smart card auth is honored and
# persists across package updates / reboots.
if [[ ! -f "${PAM_SSS_PROFILE}" ]]; then
    cat > "${PAM_SSS_PROFILE}" <<'EOF'
Name: SSSD smart-card authentication
Default: yes
Priority: 258
Auth-Type: Primary
Auth:
	[success=end default=ignore]	pam_sss.so allow_missing_name
Auth-Initial:
	[success=end default=ignore]	pam_sss.so allow_missing_name
EOF
    chmod 0644 "${PAM_SSS_PROFILE}"
fi

# Apply PAM profiles non-interactively (enables SSS auth module etc.).
if command -v pam-auth-
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q sssd-common; then

# sssd configuration files must be created with 600 permissions if they don't exist
# otherwise the sssd module fails to start
OLD_UMASK=$(umask)
umask u=rw,go=

found=false

# set value in all files if they contain section or key
for f in $(echo -n "/etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf"); do
    if [ ! -e "$f" ]; then
        continue
    fi

    # find key in section and change value
    if grep -qzosP "[[:space:]]*\[pam\]([^\n\[]*\n+)+?[[:space:]]*pam_cert_auth" "$f"; then

            sed -i "s/pam_cert_auth[^(\n)]*/pam_cert_auth=True/" "$f"

            found=true

    # find section and ad
```


---

## RHEL-08-040139 — `package_usbguard_installed`

**Prompt:** On an Ubuntu 24.04 system, ensure the software framework that protects against rogue or unauthorized USB devices through device-attribute allow/block listing is present on the system, so that USB-based attacks can be mitigated. Write an idempotent bash remediation script that guarantees this USB device-authorization framework is installed.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Idempotent remediation script to ensure the USBGuard framework is installed.
# USBGuard protects against rogue/unauthorized USB devices via device-attribute
# allow/block listing.

set -euo pipefail

PACKAGE="usbguard"

# Must run as root to install packages
if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

# Check if the package is already installed
if dpkg-query -W -f='${Status}' "${PACKAGE}" 2>/dev/null | grep -q "install ok installed"; then
    echo "Package '${PACKAGE}' is already installed. No action required."
    exit 0
fi

echo "Package '${PACKAGE}' is not installed. Installing now..."

# Ensure non-interactive installation
export DEBIAN_FRONTEND=noninteractive

# Refresh package lists
apt-get update -y

# Install the USBGuard framework
apt-get install -y "${PACKAGE}"

# Verify installation succeeded
if dpkg-query -W -f='${Status}' "${PACKAGE}" 2>/dev/null | grep -q "install ok installed"; then
    echo "Package '${PACKAGE}' has been successfully installed."
    exit 0
else
    echo "ERROR: Failed to install package '${PACKAGE}'." >&2
    exit 1
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if ( ! ( grep -sqE "^.*\.s390x$" /proc/sys/kernel/osrelease || grep -sqE "^s390x$" /proc/sys/kernel/arch; ) && rpm --quiet -q kernel ); then

if ! rpm -q --quiet "usbguard" ; then
    yum install -y "usbguard"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```


---

## RHEL-08-040141 — `service_usbguard_enabled`

**Prompt:** On an Ubuntu 24.04 system, the USB device authorization framework must be actively running to enforce policy over which USB devices may connect, preventing unauthorized or malicious USB hardware from being used as an attack vector. Write an idempotent bash remediation script that ensures the USB device authorization service is enabled to start automatically at boot and is currently active, persisting across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

SERVICE="usbguard.service"

if ! command -v systemctl >/dev/null 2>&1; then
    echo "Error: systemctl not found. This script requires systemd." >&2
    exit 1
fi

# Ensure usbguard is installed
if ! dpkg -s usbguard >/dev/null 2>&1; then
    echo "Installing usbguard..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y usbguard
fi

# Generate an initial policy if none exists, so the service can start safely
POLICY_FILE="/etc/usbguard/rules.conf"
if [ ! -s "${POLICY_FILE}" ]; then
    echo "Generating initial USBGuard policy..."
    install -d -m 0755 /etc/usbguard
    usbguard generate-policy > "${POLICY_FILE}"
    chmod 0600 "${POLICY_FILE}"
fi

# Enable the service to start at boot (idempotent)
if ! systemctl is-enabled --quiet "${SERVICE}"; then
    echo "Enabling ${SERVICE}..."
    systemctl enable "${SERVICE}"
else
    echo "${SERVICE} is already enabled."
fi

# Ensure the service is currently active (idempotent)
if ! systemctl is-active --quiet "${SERVICE}"; then
    echo "Starting ${SERVICE}..."
    systemctl start "${SERVICE}"
else
    echo "${SERVICE} is already active."
fi

# Verify final state
if systemctl is-enabled --quiet "${SERVICE}" && systemctl is-active --quiet "${SERVICE}"; then
    echo "${SERVICE} is enabled and active."
else
    echo "Error: ${SERVICE} is not in the desired state." >&2
    systemctl status "${SERVICE}" --no-pager || true
    exit 1
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if ( ! ( grep -sqE "^.*\.s390x$" /proc/sys/kernel/osrelease || grep -sqE "^s390x$" /proc/sys/kernel/arch; ) && rpm --quiet -q kernel ); then

SYSTEMCTL_EXEC='/usr/bin/systemctl'
"$SYSTEMCTL_EXEC" unmask 'usbguard.service'
if [[ $("$SYSTEMCTL_EXEC" is-system-running) != "offline" ]]; then
  "$SYSTEMCTL_EXEC" start 'usbguard.service'
fi
"$SYSTEMCTL_EXEC" enable 'usbguard.service'

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```


---

## RHEL-08-040140 — `usbguard_generate_policy`

**Prompt:** On an Ubuntu 24.04 system that uses the USB device-authorization subsystem (USBGuard) to control which USB devices may connect, an empty policy will block all USB devices by default and can lock administrators out of systems that rely on USB keyboards or mice. Write an idempotent bash remediation script that generates an initial device-authorization policy reflecting the USB devices currently connected to the system, so that legitimate existing devices remain permitted, and ensure the resulting policy is in place and persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Idempotent remediation script to generate an initial USBGuard policy
# reflecting currently connected USB devices, ensuring legitimate devices
# remain permitted and the policy persists across reboots.
#
set -euo pipefail

RULES_FILE="/etc/usbguard/rules.conf"
CONF_FILE="/etc/usbguard/usbguard-daemon.conf"

# Must run as root
if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

# Ensure USBGuard is installed
if ! command -v usbguard >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y usbguard
fi

# Ensure the configuration directory exists
install -d -m 0755 /etc/usbguard

# Generate a policy reflecting currently connected devices.
# Write to a temp file first so we only replace the real file if it changes,
# preserving idempotency.
TMP_RULES="$(mktemp)"
trap 'rm -f "$TMP_RULES"' EXIT

# generate-policy produces "allow" rules for every currently attached device.
usbguard generate-policy > "$TMP_RULES"

# Safety check: refuse to install an empty policy (would lock everything out).
if [[ ! -s "$TMP_RULES" ]]; then
    echo "ERROR: Generated policy is empty; refusing to install (would block all USB devices)." >&2
    exit 1
fi

# Only replace the rules file if content differs (idempotent).
if [[ ! -f "$RULES_FILE" ]] || ! cmp -s "$TMP_RULES" "$RULES_FILE"; then
    install -m 0600 -o root -g root "$TMP_RULES" "$RULES_FILE"
    echo "USBGuard rules updated at ${RULES_FILE}."
else
    # Ensure correct permissions even if unchanged
    chmod 0600 "$RULES_FILE"
    chown root:root "$RULES_FILE"
    echo "USBGuard rules already up to date."
fi

# Ensure the daemon config points at the rules file and applies to present devices.
if [[ -f "$CONF_FILE" ]]; then
    # RuleFile
    if grep -q '^[[:space:]]*RuleFile=' "$CONF_FILE"; then
        sed -i "s|^[[:space:]]*RuleFile=.*|RuleFile=${RULES_FILE}|" "$CONF_FILE"
    else
        echo "RuleFile=${RULES_FILE}" >> "$CONF_FILE"
    fi

    # Apply policy to devices already present at daemon start so existing
    # (already authorized) devices are kept, avoiding lockout.
    if grep -q '^[[:space:]]*PresentDevicePolicy=' "$CONF_FILE"; then
        sed -i "s|^[[:space:]]*PresentDevicePolicy=.*|PresentDevicePolicy=apply-policy|" "$CONF_FILE"
    else
        echo "PresentDevicePolicy=apply-policy" >> "$CONF_FILE"
    fi

    if grep -q '^[[:space:]]*PresentControllerPolicy=' "$CONF_FILE"; then
        sed -i "s|^[[:space:]]*PresentControllerPolicy=.*|PresentControllerPolicy=keep|" "$CONF_FILE"
    else
        echo "PresentControllerPolicy=keep" >> "$CONF_FILE"
    fi

    chmod 0600 "$CONF_FILE"
    chown root:root "$CONF_FILE"
fi

# Enable the service so the policy persists across reboots (idempotent).
systemctl enable usbguard.service >/dev/null 2>&1 || true

# Start or restart the daemon to load the current policy.
if systemctl is-active --quiet usbguard.service; then
    systemctl restart usbguard.service
else
    systemctl start usbguard.service
fi

echo "USBGuard is active and configured to persist across reboots."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if ( ! ( grep -sqE "^.*\.s390x$" /proc/sys/kernel/osrelease || grep -sqE "^s390x$" /proc/sys/kernel/arch; ) && rpm --quiet -q kernel ); then

if rpm --quiet -q usbguard
then
    USBGUARD_CONF=/etc/usbguard/rules.conf
    if [ ! -f "$USBGUARD_CONF" ] || [ ! -s "$USBGUARD_CONF" ]; then
        usbguard generate-policy > $USBGUARD_CONF
        if [ ! -s "$USBGUARD_CONF" ]; then
            # make sure OVAL check doesn't fail on systems where
            # generate-policy doesn't find any USB devices (for
            # example a system might not have a USB bus)
            echo "# No USB devices found" > $USBGUARD_CONF
        fi
        # ma
```


---

## RHEL-08-040320 — `xwindows_remove_packages`

**Prompt:** On an Ubuntu 24.04 system, the graphical windowing environment is unnecessary on a server and expands the attack surface due to its long history of security vulnerabilities. Write an idempotent bash remediation script that ensures the X Windows graphical display server components are not present on the system, so the host cannot be booted into a graphical desktop mode. The resulting state must be persistent.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure X Windows graphical display server components are absent
# Target: Ubuntu 24.04
# Idempotent and persistent.

set -o errexit
set -o nounset
set -o pipefail

export DEBIAN_FRONTEND=noninteractive

# Must be run as root
if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

echo "== Ensuring the system does not boot into a graphical target =="

# Set default systemd target to multi-user (non-graphical) if graphical is set
if command -v systemctl >/dev/null 2>&1; then
    current_target="$(systemctl get-default 2>/dev/null || echo '')"
    if [[ "${current_target}" != "multi-user.target" ]]; then
        echo "Setting default systemd target to multi-user.target (was: ${current_target})"
        systemctl set-default multi-user.target
    else
        echo "Default systemd target already multi-user.target."
    fi

    # Disable and stop common display managers if present
    for dm in gdm3 gdm lightdm sddm lxdm nodm xdm wdm slim; do
        if systemctl list-unit-files --no-legend 2>/dev/null | awk '{print $1}' | grep -qx "${dm}.service"; then
            echo "Disabling and stopping display manager: ${dm}"
            systemctl disable --now "${dm}.service" >/dev/null 2>&1 || true
        fi
    done

    # Mask the generic display-manager alias if it exists
    if systemctl list-unit-files --no-legend 2>/dev/null | awk '{print $1}' | grep -qx "display-manager.service"; then
        echo "Masking display-manager.service"
        systemctl mask display-manager.service >/dev/null 2>&1 || true
    fi
fi

echo "== Removing X Windows and graphical display server packages =="

# Packages/patterns representing the X Windows server and graphical stack.
# Removing xserver-xorg-core and the Xorg meta-packages removes the display server.
PACKAGES=(
    xorg
    xserver-xorg
    xserver-xorg-core
    xserver-xorg-core-hwe-24.04
    xserver-common
    xserver-xephyr
    xserver-xorg-legacy
    xwayland
    x11-common
    x11-xserver-utils
    xinit
    gdm3
    lightdm
    sddm
    lxdm
    nodm
    xdm
    wdm
    slim
    ubuntu-desktop
    ubuntu-desktop-minimal
    gnome-shell
    gnome-session
    plasma-desktop
    xfce4
    lxde
    lubuntu-desktop
    kubuntu-desktop
    xubuntu-desktop
)

# Build list of currently installed packages from the target set
to_remove=()
for pkg in "${PACKAGES[@]}"; do
    if dpkg-query -W -f='${Status}' "${pkg}" 2>/dev/null | grep -q "install ok installed"; then
        to_remove+=("${pkg}")
    fi
done

if [[ "${#to_remove[@]}" -gt 0 ]]; then
    echo "Purging packages: ${to_remove[*]}"
    apt-get purge -y "${to_remove[@]}"
else
    echo "No targeted X Windows packages currently installed."
fi

# Also purge any remaining xserver-xorg* video/input driver packages
mapfile -t xorg_leftover < <(dpkg-query -W -f='${Package} ${Status}\n' 'xserver-xorg-*' 2>/dev/null \
    | awk '/install ok installed/ {print $1}')
if [[ "${#xorg_leftover[@]}" -gt 0 ]]; then
    echo "Purging remaining xserver-xorg-* packages: ${xorg_leftover[*]}"
    apt-get purge -y "${xorg_leftover[@]}"
fi

echo "== Removing now-unneeded dependencies =="
apt-get autoremove --purge -y

echo "== Preventing reinstallation of the X server (persistent hold via apt preferences) =="

PREF_FILE="/etc/apt/preferences.d/99-disable-xserver"
cat > "${PREF_FILE}" <<'EOF'
# Managed by remediation script: block X Windows graphical display server packages.
Package: xserver-xorg-core xserver-xorg xserver-xorg-core-hwe-24.04 xorg xwayland
Pin: release *
Pin-Priority: -1
EOF
chmod 0644 "${PREF_FILE}"
echo "Wrote apt pin file: ${PREF_FILE}"

echo "== Verification =="
xserver_present=0
for pkg in xserver-xorg-core xserver-xorg xorg xwayland; do
    if dpkg-query -W -f='${Status}' "${pkg}" 2>/dev/null | grep -q "install ok installed"; then
        echo "WARNING: ${pkg} is still installed." >&2
        xserver_present=1
    fi
done

if [[ "${xserver_present}" -eq 0 ]]; then
    echo "OK: X Windows display server components are not present."
fi

if command -v systemctl >/dev/null 2>&1; then
    echo "Default target is now: $(systemctl get-default 2>/dev/null || echo unknown)"
fi

echo "Remediation complete."
```

**Reference fix:**
```bash
# remove packages
if rpm -q --quiet "xorg-x11-server-Xorg" ; then
yum remove -y "xorg-x11-server-Xorg"
fi
if rpm -q --quiet "xorg-x11-server-utils" ; then
yum remove -y "xorg-x11-server-utils"
fi
if rpm -q --quiet "xorg-x11-server-common" ; then
yum remove -y "xorg-x11-server-common"
fi

if rpm -q --quiet "xorg-x11-server-Xwayland" ; then
yum remove -y "xorg-x11-server-Xwayland"
fi
```


---

## RHEL-08-040321 — `xwindows_runlevel_target`

**Prompt:** On an Ubuntu 24.04 server that does not require a graphical desktop, ensure the system boots by default into a non-graphical, multi-user (text/console) mode rather than starting the graphical environment automatically. This reduces the attack surface by preventing unnecessary graphical services from running. Write an idempotent bash remediation script that sets the system's default boot state to the multi-user, non-graphical mode and ensures this persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

TARGET="multi-user.target"

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root." >&2
    exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemctl not found; this system does not use systemd." >&2
    exit 1
fi

CURRENT_DEFAULT="$(systemctl get-default 2>/dev/null || echo '')"

if [ "$CURRENT_DEFAULT" = "$TARGET" ]; then
    echo "Default target is already set to $TARGET. No changes needed."
else
    echo "Current default target: ${CURRENT_DEFAULT:-unknown}"
    echo "Setting default target to $TARGET..."
    systemctl set-default "$TARGET"
fi

NEW_DEFAULT="$(systemctl get-default 2>/dev/null || echo '')"
if [ "$NEW_DEFAULT" = "$TARGET" ]; then
    echo "Verified: default boot target is now $TARGET."
    exit 0
else
    echo "Failed to set default target to $TARGET (current: ${NEW_DEFAULT:-unknown})." >&2
    exit 1
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

systemctl set-default multi-user.target

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```


---

## RHEL-08-030601 — `grub2_audit_argument`

**Prompt:** On an Ubuntu 24.04 system, processes that start early in the boot sequence — before the audit daemon is running — may escape having their activity recorded, leaving a gap in the audit trail. Configure the system so that auditing is enabled for every process from the very start of boot, ensuring this kernel-level setting applies to all currently installed kernels and to any kernels installed in the future, and that it persists across reboots. Write an idempotent bash remediation script that achieves this end state.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

GRUB_DEFAULT="/etc/default/grub"
PARAM="audit=1"

# Ensure the GRUB default config exists
if [[ ! -f "$GRUB_DEFAULT" ]]; then
    echo "Error: $GRUB_DEFAULT not found." >&2
    exit 1
fi

# Function to add the parameter to a given GRUB variable if missing
add_param_to_var() {
    local varname="$1"
    local file="$2"

    if grep -qE "^${varname}=" "$file"; then
        # Variable exists; check if audit param already present
        local current
        current=$(grep -E "^${varname}=" "$file" | tail -n1)

        # Extract value between quotes
        local value
        value=$(echo "$current" | sed -E "s/^${varname}=\"?(.*)\"?\$/\1/" | sed 's/"$//')

        # Check whether audit= is already set to 1
        if echo "$value" | grep -qwE "audit=1"; then
            # Already correct
            return 0
        elif echo "$value" | grep -qwE "audit=[0-9]+"; then
            # Replace any existing audit=N with audit=1
            value=$(echo "$value" | sed -E "s/audit=[0-9]+/${PARAM}/g")
        else
            # Append the parameter
            if [[ -z "$value" ]]; then
                value="${PARAM}"
            else
                value="${value} ${PARAM}"
            fi
        fi

        # Normalize whitespace
        value=$(echo "$value" | tr -s ' ' | sed -E 's/^ +| +$//g')

        # Rewrite the line
        sed -i -E "s|^${varname}=.*|${varname}=\"${value}\"|" "$file"
    else
        # Variable not present; add it
        echo "${varname}=\"${PARAM}\"" >> "$file"
    fi
}

add_param_to_var "GRUB_CMDLINE_LINUX" "$GRUB_DEFAULT"

# Regenerate the GRUB configuration so it applies to all installed kernels
if command -v update-grub >/dev/null 2>&1; then
    update-grub
elif command -v grub-mkconfig >/dev/null 2>&1; then
    if [[ -d /boot/grub ]]; then
        grub-mkconfig -o /boot/grub/grub.cfg
    elif [[ -d /boot/grub2 ]]; then
        grub-mkconfig -o /boot/grub2/grub.cfg
    else
        grub-mkconfig -o /boot/grub/grub.cfg
    fi
else
    echo "Error: no grub config regeneration tool found." >&2
    exit 1
fi

echo "audit=1 has been ensured in GRUB_CMDLINE_LINUX and GRUB config regenerated."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel && { rpm --quiet -q grub2-common; }; then

expected_value="1"


if [[ "$OSCAP_BOOTC_BUILD" == "YES" ]] ; then
    KARGS_DIR="/usr/lib/bootc/kargs.d/"
    if grep -q -E "audit" "$KARGS_DIR/*.toml" ; then
        sed -i -E "s/^(\s*kargs\s*=\s*\[.*)\"audit=[^\"]*\"(.*]\s*)/\1\"audit=$expected_value\"\2/" "$KARGS_DIR/*.toml"
    else
        echo "kargs = [\"audit=$expected_value\"]" >> "$KARGS_DIR/10-audit.toml"
    fi
else

    grubby --update-kernel=ALL --args=audit=1 --env=/boot/grub2/grubenv

fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```


---

## RHEL-08-030602 — `grub2_audit_backlog_limit_argument`

**Prompt:** On an Ubuntu 24.04 system, the kernel must be able to queue audit events generated during early boot before the audit daemon starts; if this queue is too small it can overflow and trigger the audit failure action, causing loss of audit records. Configure the system so that the boot-time audit event queue holds at least 8192 entries, ensuring this setting applies to all currently installed kernels and to any kernels installed in the future, and persists across reboots. Write an idempotent bash remediation script that achieves this.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PARAM="audit_backlog_limit"
VALUE="8192"
GRUB_DEFAULT="/etc/default/grub"

# Ensure the parameter is set in GRUB_CMDLINE_LINUX so it applies to all
# current and future kernels and persists across reboots.

ensure_param_in_var() {
    local varname="$1"
    local file="$2"

    if grep -q "^${varname}=" "$file"; then
        # Extract current value between quotes
        local current
        current=$(grep "^${varname}=" "$file" | head -n1 | sed -E "s/^${varname}=\"?(.*[^\"])\"?$/\1/")

        # Remove any existing occurrences of the parameter
        current=$(echo "$current" | sed -E "s/(^| )${PARAM}=[^ ]*//g")
        # Trim whitespace
        current=$(echo "$current" | sed -E 's/^ +//; s/ +$//; s/  +/ /g')

        # Append the desired parameter
        if [ -n "$current" ]; then
            new_value="${current} ${PARAM}=${VALUE}"
        else
            new_value="${PARAM}=${VALUE}"
        fi

        # Replace the line
        sed -i -E "s|^${varname}=.*|${varname}=\"${new_value}\"|" "$file"
    else
        echo "${varname}=\"${PARAM}=${VALUE}\"" >> "$file"
    fi
}

if [ ! -f "$GRUB_DEFAULT" ]; then
    touch "$GRUB_DEFAULT"
fi

ensure_param_in_var "GRUB_CMDLINE_LINUX" "$GRUB_DEFAULT"

# Regenerate the grub configuration so the change applies to all installed kernels.
if command -v update-grub >/dev/null 2>&1; then
    update-grub
elif command -v grub-mkconfig >/dev/null 2>&1; then
    if [ -d /boot/grub ]; then
        grub-mkconfig -o /boot/grub/grub.cfg
    elif [ -d /boot/grub2 ]; then
        grub-mkconfig -o /boot/grub2/grub.cfg
    fi
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel && { rpm --quiet -q grub2-common; }; then

expected_value="8192"


if [[ "$OSCAP_BOOTC_BUILD" == "YES" ]] ; then
    KARGS_DIR="/usr/lib/bootc/kargs.d/"
    if grep -q -E "audit_backlog_limit" "$KARGS_DIR/*.toml" ; then
        sed -i -E "s/^(\s*kargs\s*=\s*\[.*)\"audit_backlog_limit=[^\"]*\"(.*]\s*)/\1\"audit_backlog_limit=$expected_value\"\2/" "$KARGS_DIR/*.toml"
    else
        echo "kargs = [\"audit_backlog_limit=$expected_value\"]" >> "$KARGS_DIR/10-audit_backlog_limit.toml"
    fi
else

    grubby --update-kernel=ALL --args=audit_backlog_limit=8192 --env=/boot/grub2/grubenv

fi

else
    >&2 echo 'Remediati
```


---

## RHEL-08-030121 — `audit_rules_immutable`

**Prompt:** On an Ubuntu 24.04 system, harden the system audit daemon so that its loaded rule set is locked and cannot be altered while the system is running; once configured, the audit configuration must be immutable, with a system reboot being the only way to change audit rules afterward. This prevents accidental or malicious tampering with the audit policy at runtime. Write an idempotent bash remediation script that ensures the audit configuration becomes immutable on the next audit-rules load and persists across reboots, accounting for the mechanism the daemon uses to read its rules at startup.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Harden auditd so its loaded rule set becomes immutable (-e 2).
# On Ubuntu 24.04, auditd rules are compiled by augenrules from files in
# /etc/audit/rules.d/*.rules into /etc/audit/audit.rules at load time.
# The "-e 2" directive must be the LAST rule loaded, so we place it in a
# file that sorts last among the rules.d files.
#
set -euo pipefail

RULES_DIR="/etc/audit/rules.d"
IMMUTABLE_FILE="${RULES_DIR}/99-finalize.rules"
DIRECTIVE="-e 2"

# Ensure we are running as root
if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# Ensure the audit package/tooling is available
if ! command -v augenrules >/dev/null 2>&1; then
    echo "augenrules not found. Installing auditd..." >&2
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y auditd audispd-plugins
fi

# Ensure the rules.d directory exists
if [[ ! -d "${RULES_DIR}" ]]; then
    mkdir -p "${RULES_DIR}"
    chmod 0750 "${RULES_DIR}"
fi

# Remove any stray "-e <n>" directives from OTHER rules files so that the
# only enable/immutable directive is the final one we manage. Leaving an
# "-e 2" in an earlier-sorted file would make the ruleset immutable before
# subsequent files are loaded, breaking rule loading.
shopt -s nullglob
for f in "${RULES_DIR}"/*.rules; do
    # Skip the file we manage
    if [[ "${f}" == "${IMMUTABLE_FILE}" ]]; then
        continue
    fi
    if grep -Eq '^[[:space:]]*-e[[:space:]]+[0-9]+' "${f}"; then
        tmp="$(mktemp)"
        grep -Ev '^[[:space:]]*-e[[:space:]]+[0-9]+' "${f}" > "${tmp}"
        cat "${tmp}" > "${f}"
        rm -f "${tmp}"
    fi
done
shopt -u nullglob

# Idempotently ensure the finalize file contains exactly the immutable directive
NEED_WRITE=1
if [[ -f "${IMMUTABLE_FILE}" ]]; then
    if grep -Eq '^[[:space:]]*-e[[:space:]]+2[[:space:]]*$' "${IMMUTABLE_FILE}"; then
        NEED_WRITE=0
    fi
fi

if [[ "${NEED_WRITE}" -eq 1 ]]; then
    printf '%s\n' "${DIRECTIVE}" > "${IMMUTABLE_FILE}"
fi

chmod 0640 "${IMMUTABLE_FILE}"
chown root:root "${IMMUTABLE_FILE}"

# Regenerate the compiled ruleset so the change persists and takes effect on
# the next load. This compiles /etc/audit/rules.d/*.rules -> /etc/audit/audit.rules.
augenrules --load || true

# Report current status (may show "still enabled" until reboot if already immutable)
if command -v auditctl >/dev/null 2>&1; then
    echo "Current audit status:"
    auditctl -s || true
fi

echo "Audit configuration set to immutable (-e 2) via ${IMMUTABLE_FILE}."
echo "The rule set will be locked on the next audit-rules load and persists across reboots."
echo "A reboot is required to modify audit rules once the immutable flag is active."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

# Traverse all of:
#
# /etc/audit/audit.rules,			(for auditctl case)
# /etc/audit/rules.d/*.rules			(for augenrules case)
#
# files to check if '-e .*' setting is present in that '*.rules' file already.
# If found, delete such occurrence since auditctl(8) manual page instructs the
# '-e 2' rule should be placed as the last rule in the configuration
find /etc/audit /etc/audit/rules.d -maxdepth 1 -type f -name '*.rules' -exec sed -i '/-e[[:space:]]\+.*/d' {} ';'

# Append '-e 2' requirement at the end of both:
# * /etc/audit/audit.rules file 		(for auditctl case)
# * /etc/audit/rules.d
```


---

## RHEL-08-030122 — `audit_rules_immutable_login_uids`

**Prompt:** On an Ubuntu 24.04 system, configure the system audit subsystem so that once a user's login UID is established for a session it becomes immutable and cannot be altered, even by privileged processes lacking special capabilities. This prevents tampering that would obscure the accountability trail in audit logs. Write an idempotent bash remediation script that makes login UIDs immutable, ensuring the setting is part of the persistent audit rule configuration so it takes effect on subsequent audit daemon startups and across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULE="--loginuid-immutable"
RULES_DIR="/etc/audit/rules.d"
TARGET_FILE="${RULES_DIR}/immutable.rules"

# Ensure the audit rules directory exists
mkdir -p "${RULES_DIR}"

# Check if the loginuid-immutable rule already exists in any rules file
found=0
if grep -rPsq -- '^\s*--loginuid-immutable\b' "${RULES_DIR}"/*.rules 2>/dev/null; then
    found=1
fi

if [ "${found}" -eq 0 ]; then
    # Append the rule to the target file
    printf '%s\n' "${RULE}" >> "${TARGET_FILE}"
    echo "Added '${RULE}' to ${TARGET_FILE}"
else
    echo "'${RULE}' already present in audit rules; no change needed."
fi

# Ensure proper permissions on the rules file
if [ -f "${TARGET_FILE}" ]; then
    chown root:root "${TARGET_FILE}"
    chmod 0640 "${TARGET_FILE}"
fi

# Regenerate and load the audit rules so the setting takes effect
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    auditctl "${RULE}" || true
fi

echo "Login UID immutability configuration is in place."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

# in case auditctl is used
if grep -q '^\s*ExecStartPost=-/sbin/auditctl' /usr/lib/systemd/system/auditd.service; then
  if ! grep -q '^\s*--loginuid-immutable\s*$' /etc/audit/audit.rules; then
    echo "--loginuid-immutable" >> /etc/audit/audit.rules
  fi
else
  immutable_found=0
  while IFS= read -r -d '' f; do
    if grep -q '^\s*--loginuid-immutable\s*$' "$f"; then
      immutable_found=1
    fi
  done <    <(find /etc/audit/rules.d -maxdepth 1 -name '*.rules' -print0)
  if [ $immutable_found -eq 0 ]; then
    echo "--loginuid-immutable" >> /etc/audit/rules.d/immutable.rules
  fi
```


---

## RHEL-08-030302 — `audit_rules_media_export`

**Prompt:** On an Ubuntu 24.04 system, configure the system audit daemon so that it records every successful use of the filesystem mount operation performed by regular users (those with a login UID of 1000 or greater, excluding unset UIDs), capturing both 32-bit and 64-bit invocations as appropriate for the system's architecture. This audit trail helps detect unauthorized exportation of data to external media. The relevant events should be grouped under an identifying audit key of 'export'. Write an idempotent bash remediation script that establishes these audit rules so they take effect and persist across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULES_FILE="/etc/audit/rules.d/audit.rules"

# Ensure auditd and rules directory exist
if ! dpkg -s auditd >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

mkdir -p /etc/audit/rules.d
touch "$RULES_FILE"

# Determine architecture
declare -a ARCHES=()
if [[ "$(uname -m)" == "x86_64" || "$(uname -m)" == "aarch64" || "$(uname -m)" == "ppc64le" || "$(uname -m)" == "s390x" ]]; then
    ARCHES+=("b32" "b64")
else
    ARCHES+=("b32")
fi

for ARCH in "${ARCHES[@]}"; do
    RULE="-a always,exit -F arch=${ARCH} -S mount -F auid>=1000 -F auid!=unset -F key=export"
    # Idempotency: remove any existing matching mount/export rule for this arch
    if ! grep -Eq -- "^-a[[:space:]]+always,exit[[:space:]]+-F[[:space:]]+arch=${ARCH}[[:space:]].*-S[[:space:]]+mount.*(key=export|-k[[:space:]]+export)" "$RULES_FILE"; then
        echo "$RULE" >> "$RULES_FILE"
    fi
done

# Load rules
augenrules --load || true

# Restart auditd to ensure rules take effect (service restart via service tool)
if command -v service >/dev/null 2>&1; then
    service auditd restart 2>/dev/null || systemctl restart auditd 2>/dev/null || true
else
    systemctl restart auditd 2>/dev/null || true
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="mount"
	KEY="perm_mod"
	SYSCALL_GROUPING=""

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
```


---

## RHEL-08-030171 — `audit_rules_sudoers`

**Prompt:** On an Ubuntu 24.04 system, configure the system audit daemon so that any write or attribute change to the primary sudo privilege-configuration file (the system-wide sudoers policy file) is recorded, in order to detect attackers attempting to establish persistent elevated access by altering administrator privileges. The audit events must be tagged with an identifiable key so they can be queried later, and the rule must be effective whether the audit daemon loads rules via the rules-merging program or the direct rule-loading utility. Write an idempotent bash remediation script that establishes this audit rule and ensures it persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULE_KEY="privileged-actions"
WATCH_FILE="/etc/sudoers"
AUDIT_RULE="-w ${WATCH_FILE} -p wa -k ${RULE_KEY}"

RULES_DIR="/etc/audit/rules.d"
RULES_FILE="${RULES_DIR}/50-sudoers.rules"

# Ensure the audit rules directory exists
mkdir -p "${RULES_DIR}"

# Ensure the persistent rule is present (idempotent)
if [ -f "${RULES_FILE}" ]; then
    if ! grep -Fxq "${AUDIT_RULE}" "${RULES_FILE}"; then
        # Remove any stale variant referencing the same file/key then add correct rule
        grep -vE "^-w[[:space:]]+${WATCH_FILE}[[:space:]]" "${RULES_FILE}" > "${RULES_FILE}.tmp" || true
        mv "${RULES_FILE}.tmp" "${RULES_FILE}"
        echo "${AUDIT_RULE}" >> "${RULES_FILE}"
    fi
else
    echo "${AUDIT_RULE}" > "${RULES_FILE}"
fi

chmod 0640 "${RULES_FILE}"

# Load the rules so the change is effective immediately.
# Prefer augenrules (rules-merging program); fall back to auditctl (direct loading utility).
loaded=false

if command -v augenrules >/dev/null 2>&1; then
    if augenrules --load >/dev/null 2>&1; then
        loaded=true
    fi
fi

if [ "${loaded}" = false ] && command -v auditctl >/dev/null 2>&1; then
    # Add the rule directly only if not already active
    if ! auditctl -l 2>/dev/null | grep -Fq -- "-w ${WATCH_FILE} -p wa -k ${RULE_KEY}"; then
        auditctl ${AUDIT_RULE} >/dev/null 2>&1 || true
    fi
    loaded=true
fi

# Try to restart/reload the audit daemon so persistence and runtime stay consistent
if command -v service >/dev/null 2>&1; then
    service auditd reload >/dev/null 2>&1 || service auditd restart >/dev/null 2>&1 || true
elif command -v systemctl >/dev/null 2>&1; then
    systemctl reload auditd >/dev/null 2>&1 || systemctl restart auditd >/dev/null 2>&1 || true
fi

echo "Audit rule for ${WATCH_FILE} with key '${RULE_KEY}' is configured and persistent."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# ---------------------
```


---

## RHEL-08-030172 — `audit_rules_sudoers_d`

**Prompt:** On an Ubuntu 24.04 system, the audit subsystem must record any modification to the supplementary sudo configuration directory where administrator privilege definitions are stored, so that attempts to alter privilege-escalation rules (a common persistence technique) are logged for accountability and forensic review. Write an idempotent bash remediation script that ensures the system audit daemon generates audit records for all write and attribute changes to that sudo configuration directory, tagged so the events are identifiable, and that the rule persists across reboots and applies regardless of whether the daemon loads rules via the generation utility or directly.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULE='-w /etc/sudoers.d/ -p wa -k identity'
PERSIST_FILE="/etc/audit/rules.d/identity.rules"
ACTIVE_FILE="/etc/audit/audit.rules"

mkdir -p /etc/audit/rules.d

# Ensure the rule persists in the rules.d file
if [ -f "$PERSIST_FILE" ]; then
    if ! grep -Eq '^\s*-w\s+/etc/sudoers\.d/?\s+-p\s+wa\s+-k\s+\S+' "$PERSIST_FILE"; then
        printf '%s\n' "$RULE" >> "$PERSIST_FILE"
    fi
else
    printf '%s\n' "$RULE" > "$PERSIST_FILE"
fi

# Ensure the rule is present in the directly-loaded audit.rules as well
if [ -f "$ACTIVE_FILE" ]; then
    if ! grep -Eq '^\s*-w\s+/etc/sudoers\.d/?\s+-p\s+wa\s+-k\s+\S+' "$ACTIVE_FILE"; then
        printf '%s\n' "$RULE" >> "$ACTIVE_FILE"
    fi
else
    printf '%s\n' "$RULE" > "$ACTIVE_FILE"
fi

# Load the rules into the running audit system
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    if ! auditctl -l 2>/dev/null | grep -Eq '\s*-w\s+/etc/sudoers\.d/?\s+-p\s+wa\s+-k\s+\S+'; then
        auditctl -w /etc/sudoers.d/ -p wa -k identity || true
    fi
fi

exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# ---------------------
```


---

## RHEL-08-030000 — `audit_rules_suid_privilege_function`

**Prompt:** On an Ubuntu 24.04 system, configure the system audit subsystem to generate an audit record whenever a user executes a program in a way that elevates their effective privileges — specifically whenever a process is executed with an effective user or group ID that differs from the real one (i.e. privilege escalation via setuid/setgid execution). The configuration must cover both 32-bit and 64-bit system architectures and apply to both the user-ID and group-ID escalation cases. These audit records help detect misuse of privileged functions by insiders or compromised accounts. Write an idempotent bash remediation script that establishes these audit rules so they persist across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULES_FILE="/etc/audit/rules.d/privilege-escalation.rules"

mkdir -p /etc/audit/rules.d

declare -a RULES=(
    "-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F key=execpriv"
    "-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F key=execpriv"
    "-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -F key=execpriv"
    "-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -F key=execpriv"
)

touch "$RULES_FILE"

for rule in "${RULES[@]}"; do
    if ! grep -qF -- "$rule" "$RULES_FILE"; then
        echo "$rule" >> "$RULES_FILE"
    fi
done

if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    for rule in "${RULES[@]}"; do
        auditctl $rule || true
    done
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl restart auditd 2>/dev/null || service auditd restart 2>/dev/null || true
fi

exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
    
	OTHER_FILTERS="-C uid!=euid -F euid=0"
	
	AUID_FILTERS=""
	SYSCALL="execve"
	KEY="setuid"
	SYSCALL_GROUPING=""
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit

```


---

## RHEL-08-030170 — `audit_rules_usergroup_modification_group`

**Prompt:** On an Ubuntu 24.04 system, configure the system audit daemon to monitor the system's group-account definition file so that any write or attribute change to it generates an audit record, enabling administrators to detect unexpected or unauthorized modifications to group accounts. The audit rule must persist across reboots and be loaded regardless of which rule-loading mechanism the audit daemon uses, and the configuration must be idempotent. Write a bash remediation script that achieves this.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULE="-w /etc/group -p wa -k audit_rules_usergroup_modification"

# Ensure auditd is installed
if ! command -v auditctl >/dev/null 2>&1; then
    echo "auditd not installed; installing..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y auditd audispd-plugins
fi

RULES_D="/etc/audit/rules.d"
AUDIT_RULES="/etc/audit/audit.rules"

mkdir -p "$RULES_D"

TARGET_FILE="${RULES_D}/audit.rules"

# Remove any existing matching rule lines across rules.d to avoid duplicates,
# then ensure the canonical rule exists in the target file.
add_rule_to_file() {
    local file="$1"
    if [ -f "$file" ]; then
        if grep -Fxq "$RULE" "$file"; then
            return 0
        fi
    fi
    echo "$RULE" >> "$file"
}

# Clean up any partial/variant rules referencing /etc/group with wa in rules.d
for f in "$RULES_D"/*.rules; do
    [ -e "$f" ] || continue
    # remove existing lines that are exactly our rule (will re-add to target)
    if grep -Fxq "$RULE" "$f" 2>/dev/null; then
        grep -vFx "$RULE" "$f" > "${f}.tmp" || true
        mv "${f}.tmp" "$f"
    fi
done

add_rule_to_file "$TARGET_FILE"

# Ensure it's present in the flat audit.rules as well (for the mechanism
# that reads audit.rules directly), idempotently.
if [ -f "$AUDIT_RULES" ]; then
    if ! grep -Fxq "$RULE" "$AUDIT_RULES"; then
        echo "$RULE" >> "$AUDIT_RULES"
    fi
else
    echo "$RULE" >> "$AUDIT_RULES"
fi

# Load the rule into the running kernel if auditd is active
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    if ! auditctl -l 2>/dev/null | grep -Fq -- "-p wa" | grep -Fq "/etc/group"; then
        auditctl "$RULE" || true
    fi
fi

echo "Audit rule for /etc/group configured."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# --------------------
```


---

## RHEL-08-030160 — `audit_rules_usergroup_modification_gshadow`

**Prompt:** On an Ubuntu 24.04 system, configure the system audit daemon to record all write and attribute-change events affecting the secure group-account database (the file holding group password and shadow group information), so that any unauthorized creation, deletion, or modification of group account data is logged for later review. The audit rule must be tagged with an identifier suitable for grouping user/group modification events, and must work whether audit rules are loaded via the rules-compilation mechanism or the direct-load utility. Write an idempotent bash remediation script that establishes this auditing and ensures it persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

# Target file: secure group-account database = /etc/gshadow
AUDIT_FILE="/etc/gshadow"
KEY="identity"
RULE="-w ${AUDIT_FILE} -p wa -k ${KEY}"

RULES_DIR="/etc/audit/rules.d"
RULES_FILE="${RULES_DIR}/identity.rules"

# Ensure auditd is installed
if ! command -v auditctl >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y auditd audispd-plugins
fi

# Ensure rules directory exists
mkdir -p "${RULES_DIR}"

# --- Persist rule via rules-compilation mechanism (augenrules) ---
touch "${RULES_FILE}"

# Remove any existing rule referencing the target file to avoid duplicates,
# then add the canonical rule.
if grep -Eq -- "-w[[:space:]]+${AUDIT_FILE}[[:space:]]" "${RULES_FILE}"; then
    sed -i -E "\|-w[[:space:]]+${AUDIT_FILE}[[:space:]]|d" "${RULES_FILE}"
fi

if ! grep -Fxq -- "${RULE}" "${RULES_FILE}"; then
    echo "${RULE}" >> "${RULES_FILE}"
fi

# --- Load rule now via direct-load utility (auditctl) if not already present ---
if command -v auditctl >/dev/null 2>&1; then
    if ! auditctl -l 2>/dev/null | grep -Eq -- "-w[[:space:]]+${AUDIT_FILE}[[:space:]]+-p[[:space:]]+wa[[:space:]]+-k[[:space:]]+${KEY}"; then
        auditctl ${RULE} || true
    fi
fi

# --- Apply compiled rules if augenrules is available ---
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
fi

exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# --------------------
```


---

## RHEL-08-030140 — `audit_rules_usergroup_modification_opasswd`

**Prompt:** On an Ubuntu 24.04 system, the system audit daemon must monitor the file that stores users' previous (old) passwords so that any write or attribute change to it is recorded for later review; unmonitored modifications to account-related files could allow unauthorized account changes to go undetected. Write an idempotent bash remediation script that configures persistent audit rules to capture write and attribute-change events on the old-password store, tagging these events under an identifiable key, and ensure the rules work whether the audit daemon loads rules via the rule-compilation program or the direct rule-loading utility, persisting across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Configure persistent audit rules to monitor the old-password store
# (/etc/security/opasswd) for write and attribute-change events.
#
set -euo pipefail

TARGET_FILE="/etc/security/opasswd"
AUDIT_KEY="audit_rules_usergroup_modification"
RULE_LINE="-w ${TARGET_FILE} -p wa -k ${AUDIT_KEY}"

# Files used by the two rule-loading mechanisms:
#   augenrules (rule-compilation program) reads *.rules under /etc/audit/rules.d/
#   auditctl   (direct rule-loading utility) reads /etc/audit/audit.rules
RULES_D_FILE="/etc/audit/rules.d/audit.rules"
AUDIT_RULES_FILE="/etc/audit/audit.rules"

ensure_rule_in_file() {
    local file="$1"
    local dir
    dir="$(dirname "$file")"

    # Make sure the directory exists.
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir"
        chmod 0750 "$dir"
    fi

    # Create the file if it does not exist.
    if [ ! -f "$file" ]; then
        touch "$file"
        chmod 0640 "$file"
    fi

    # Idempotently add the rule if an equivalent one is not already present.
    # Match on the file path and the wa permission to avoid duplicates.
    if ! grep -Eq "^[[:space:]]*-w[[:space:]]+${TARGET_FILE//\//\\/}[[:space:]]+-p[[:space:]]+wa([[:space:]]|$)" "$file"; then
        printf '%s\n' "$RULE_LINE" >> "$file"
    fi
}

# Configure the augenrules source file.
ensure_rule_in_file "$RULES_D_FILE"

# Configure the direct auditctl rules file.
ensure_rule_in_file "$AUDIT_RULES_FILE"

# Attempt to load the new rules into the running kernel so they take
# effect immediately, preferring augenrules, then falling back to auditctl.
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "$AUDIT_RULES_FILE" || true
fi

# Reflect the running configuration for immediate coverage (best effort).
if command -v auditctl >/dev/null 2>&1; then
    if ! auditctl -l 2>/dev/null | grep -Eq "${TARGET_FILE//\//\\/}.*-p[[:space:]]*wa.*${AUDIT_KEY}"; then
        auditctl -w "$TARGET_FILE" -p wa -k "$AUDIT_KEY" || true
    fi
fi

exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# --------------------
```


---

## RHEL-08-030150 — `audit_rules_usergroup_modification_passwd`

**Prompt:** On an Ubuntu 24.04 system, configure the system audit daemon so that any write or attribute change to the system's primary user-account database file is recorded, allowing administrators to detect unauthorized creation or modification of user accounts. The audit rule must persist across reboots and be loaded regardless of which rule-loading mechanism the audit daemon uses, and it must be tagged with an identifier of audit_rules_usergroup_modification. Write an idempotent bash remediation script that establishes this audit watch.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

FILE_TO_WATCH="/etc/passwd"
KEY="audit_rules_usergroup_modification"
RULE="-w ${FILE_TO_WATCH} -p wa -k ${KEY}"

AUDIT_RULES_D="/etc/audit/rules.d"
AUDIT_RULES_FILE="${AUDIT_RULES_D}/audit_rules_usergroup_modification.rules"
AUDIT_MAIN_RULES="/etc/audit/audit.rules"

# Ensure rules.d directory exists
mkdir -p "${AUDIT_RULES_D}"

# Helper: check whether an equivalent watch rule already exists in a file
rule_present() {
    local target_file="$1"
    [ -f "${target_file}" ] || return 1
    grep -Eq "^[[:space:]]*-w[[:space:]]+${FILE_TO_WATCH}([[:space:]]|$).*-p[[:space:]]+wa([[:space:]]|$).*-k[[:space:]]+${KEY}([[:space:]]|$)" "${target_file}"
}

# Configure the persistent rules.d file (used by augenrules)
if ! rule_present "${AUDIT_RULES_FILE}"; then
    # Remove any stale/partial watches for this file in this rules file
    if [ -f "${AUDIT_RULES_FILE}" ]; then
        sed -i "\|-w[[:space:]]\+${FILE_TO_WATCH}[[:space:]]|d" "${AUDIT_RULES_FILE}"
    fi
    printf '%s\n' "${RULE}" >> "${AUDIT_RULES_FILE}"
fi

# Configure the main audit.rules file (used when auditd reads audit.rules directly)
if ! rule_present "${AUDIT_MAIN_RULES}"; then
    if [ -f "${AUDIT_MAIN_RULES}" ]; then
        sed -i "\|-w[[:space:]]\+${FILE_TO_WATCH}[[:space:]]|d" "${AUDIT_MAIN_RULES}"
    fi
    printf '%s\n' "${RULE}" >> "${AUDIT_MAIN_RULES}"
fi

# Attempt to load the rules into the running kernel audit system.
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load >/dev/null 2>&1 || true
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "${AUDIT_MAIN_RULES}" >/dev/null 2>&1 || true
fi

exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# --------------------
```


---

## RHEL-08-030130 — `audit_rules_usergroup_modification_shadow`

**Prompt:** On an Ubuntu 24.04 system, the system audit daemon must record every write and attribute change made to the file that stores user account password hashes, so that any unexpected modification to credential data can be detected and investigated. Write an idempotent bash remediation script that configures the audit subsystem to monitor write and attribute-change events on that shadow password file, tags the events with a recognizable key for user/group modification tracking, and ensures the rule persists across reboots regardless of whether rules are loaded via the rule-compilation mechanism or the direct rule-loading utility.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Idempotent remediation: audit write and attribute changes to /etc/shadow
#

set -euo pipefail

FILE="/etc/shadow"
KEY="usergroup_modification"
RULE="-w ${FILE} -p wa -k ${KEY}"

RULES_D="/etc/audit/rules.d"
RULES_FILE="${RULES_D}/audit_shadow.rules"

# Ensure the audit package/directory is available
if ! command -v auditctl >/dev/null 2>&1; then
    echo "auditctl not found. Installing auditd..." >&2
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y auditd audispd-plugins
fi

# Ensure the rules.d directory exists (used by augenrules / rule-compilation)
mkdir -p "${RULES_D}"

# --- Persist the rule for the rule-compilation mechanism (augenrules) ---
if [ -f "${RULES_FILE}" ]; then
    # Remove any existing matching rule to avoid duplicates
    grep -vE "^[[:space:]]*-w[[:space:]]+${FILE}[[:space:]]+-p[[:space:]]+wa[[:space:]]+-k[[:space:]]+${KEY}[[:space:]]*$" \
        "${RULES_FILE}" > "${RULES_FILE}.tmp" 2>/dev/null || true
    mv "${RULES_FILE}.tmp" "${RULES_FILE}"
fi

if ! grep -qE "^[[:space:]]*-w[[:space:]]+${FILE}[[:space:]]+-p[[:space:]]+wa[[:space:]]+-k[[:space:]]+${KEY}[[:space:]]*$" "${RULES_FILE}" 2>/dev/null; then
    echo "${RULE}" >> "${RULES_FILE}"
fi

chmod 0640 "${RULES_FILE}"

# --- Persist the rule for the direct rule-loading utility (audit.rules) ---
DIRECT_RULES="/etc/audit/audit.rules"
if [ -f "${DIRECT_RULES}" ]; then
    if ! grep -qE "^[[:space:]]*-w[[:space:]]+${FILE}[[:space:]]+-p[[:space:]]+wa[[:space:]]+-k[[:space:]]+${KEY}[[:space:]]*$" "${DIRECT_RULES}" 2>/dev/null; then
        echo "${RULE}" >> "${DIRECT_RULES}"
    fi
fi

# --- Load the rule into the running kernel audit subsystem (idempotent) ---
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
fi

if ! auditctl -l 2>/dev/null | grep -qE "\-w[[:space:]]+${FILE}[[:space:]]+-p[[:space:]]+wa[[:space:]]+-k[[:space:]]+${KEY}"; then
    auditctl ${RULE} || true
fi

echo "Audit rule for ${FILE} (key: ${KEY}) configured and loaded."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# --------------------
```


---

## RHEL-08-030490 — `audit_rules_dac_modification_chmod`

**Prompt:** On an Ubuntu 24.04 system, configure the audit subsystem to record every use of the discretionary-access-control operation that changes a file's permission bits, performed by any regular (non-system) user. Tracking such permission changes helps detect attempts to gain unauthorized access to protected information. The audit records must be tagged with an identifying key so they can be retrieved, must cover both 32-bit and 64-bit invocations on a 64-bit host, and must apply only to user accounts with login UIDs at or above the normal user threshold (excluding unset login UIDs). Ensure the configuration is idempotent and persists across reboots so the rules are reloaded automatically when the audit daemon starts. Write a bash remediation script that achieves this.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

# Determine the normal user UID threshold (UID_MIN) from login.defs
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs 2>/dev/null)
if [ -z "${UID_MIN:-}" ]; then
    UID_MIN=1000
fi

RULES_DIR="/etc/audit/rules.d"
RULES_FILE="${RULES_DIR}/perm_mod.rules"
KEY="perm_mod"

mkdir -p "${RULES_DIR}"

# The DAC permission-changing syscalls
SYSCALLS="chmod fchmod fchmodat"

declare -a NEW_RULES=()
NEW_RULES+=("-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=${UID_MIN} -F auid!=unset -F key=${KEY}")
NEW_RULES+=("-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=${UID_MIN} -F auid!=unset -F key=${KEY}")

# Build the file idempotently
touch "${RULES_FILE}"

for rule in "${NEW_RULES[@]}"; do
    arch=$(printf '%s\n' "${rule}" | grep -oP 'arch=b\d+')
    # Remove any existing matching arch rule with the key to avoid duplicates
    grep -vE "arch=${arch#arch=}.*key=${KEY}" "${RULES_FILE}" > "${RULES_FILE}.tmp" 2>/dev/null || true
    mv "${RULES_FILE}.tmp" "${RULES_FILE}"
    printf '%s\n' "${rule}" >> "${RULES_FILE}"
done

# Deduplicate lines while preserving order
awk '!seen[$0]++' "${RULES_FILE}" > "${RULES_FILE}.tmp"
mv "${RULES_FILE}.tmp" "${RULES_FILE}"

chmod 0640 "${RULES_FILE}"

# Reload audit rules so they take effect and persist across reboots
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "${RULES_FILE}" || true
fi

# Ensure auditd is enabled to reload rules on start
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable auditd 2>/dev/null || true
fi

exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel && { ! ( ( grep -sqE "^.*\.aarch64$" /proc/sys/kernel/osrelease || grep -sqE "^aarch64$" /proc/sys/kernel/arch; ) ); }; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="chmod"
	KEY="perm_mod"
	SYSCALL_GROUPING="chmod fchmod fchmodat"

	# Perform the remediation for both possible tools: 
```


---

## RHEL-08-030480 — `audit_rules_dac_modification_chown`

**Prompt:** On an Ubuntu 24.04 system, the audit subsystem must record every successful use of the system call that changes file ownership, so that attempts to alter discretionary access controls can be traced to a user. Configure the system audit daemon to capture these ownership-change events for all regular (non-system) users — those with login UIDs at or above the standard threshold of 1000, excluding unset login UIDs — on both 32-bit and 64-bit system-call interfaces, and tag the events with an identifying key for permission modifications. Write an idempotent bash remediation script that establishes these audit rules so they survive reboots and are loaded by the audit daemon at startup.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULE_FILE="/etc/audit/rules.d/perm_mod.rules"
mkdir -p /etc/audit/rules.d

RULE_B64="-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=unset -k perm_mod"
RULE_B32="-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=unset -k perm_mod"

touch "$RULE_FILE"

if ! grep -qF -- "$RULE_B64" "$RULE_FILE"; then
    echo "$RULE_B64" >> "$RULE_FILE"
fi

if ! grep -qF -- "$RULE_B32" "$RULE_FILE"; then
    echo "$RULE_B32" >> "$RULE_FILE"
fi

chmod 0640 "$RULE_FILE"

if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "$RULE_FILE" || true
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel && { ! ( ( grep -sqE "^.*\.aarch64$" /proc/sys/kernel/osrelease || grep -sqE "^aarch64$" /proc/sys/kernel/arch; ) ); }; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="chown"
	KEY="perm_mod"
	SYSCALL_GROUPING="chown fchown fchownat lchown"

	# Perform the remediation for both possible 
```


---

## RHEL-08-030490 — `audit_rules_dac_modification_fchmod`

**Prompt:** On an Ubuntu 24.04 system, configure the system audit daemon to record every use of the system call that changes the discretionary access control permissions of an already-open file, since such permission changes can signal attempts to gain unauthorized access to protected data. The audit rule must capture these events for all non-system user accounts (i.e., login UIDs of 1000 and above, excluding unset UIDs), apply to both 32-bit and 64-bit system call interfaces on a 64-bit system, and tag matching events with an identifying key for permission modifications. Ensure the rule persists across reboots and that the script is idempotent. Provide a bash remediation script.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULES_FILE="/etc/audit/rules.d/perm_mod.rules"

mkdir -p /etc/audit/rules.d
touch "$RULES_FILE"

RULE_32="-a always,exit -F arch=b32 -S fchmod -F auid>=1000 -F auid!=unset -k perm_mod"
RULE_64="-a always,exit -F arch=b64 -S fchmod -F auid>=1000 -F auid!=unset -k perm_mod"

add_rule() {
    local rule="$1"
    if ! grep -qF -- "$rule" "$RULES_FILE"; then
        echo "$rule" >> "$RULES_FILE"
    fi
}

add_rule "$RULE_32"
add_rule "$RULE_64"

if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "$RULES_FILE" || true
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="fchmod"
	KEY="perm_mod"
	SYSCALL_GROUPING="chmod fchmod fchmodat"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_e
```


---

## RHEL-08-030490 — `audit_rules_dac_modification_fchmodat`

**Prompt:** On an Ubuntu 24.04 system, the audit subsystem must record every attempt by a regular user (login UID 1000 or greater) to alter a file's discretionary access-control permissions using the operation that changes the mode of a file relative to a directory file descriptor, since such changes can signal attempts to gain unauthorized access to protected data. Write an idempotent bash remediation script that ensures the system audit daemon persistently captures these permission-modification events for both 32-bit and 64-bit invocations, tags them under a consistent key for later review, applies on both auditctl-based and augenrules-based rule loading, and survives reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

SYSCALL="fchmodat"
KEY="perm_mod"
RULE_32="-a always,exit -F arch=b32 -S ${SYSCALL} -F auid>=1000 -F auid!=unset -F key=${KEY}"
RULE_64="-a always,exit -F arch=b64 -S ${SYSCALL} -F auid>=1000 -F auid!=unset -F key=${KEY}"

AUGENRULES_FILE="/etc/audit/rules.d/50-perm_mod.rules"
AUDITCTL_FILE="/etc/audit/audit.rules"

# Ensure directories exist
mkdir -p /etc/audit/rules.d

# --- augenrules-based persistent rules ---
ensure_rule_in_file() {
    local file="$1"
    local rule="$2"
    touch "$file"
    if ! grep -qF -- "$rule" "$file"; then
        printf '%s\n' "$rule" >> "$file"
    fi
}

ensure_rule_in_file "$AUGENRULES_FILE" "$RULE_32"
ensure_rule_in_file "$AUGENRULES_FILE" "$RULE_64"

# --- auditctl-based persistent rules ---
ensure_rule_in_file "$AUDITCTL_FILE" "$RULE_32"
ensure_rule_in_file "$AUDITCTL_FILE" "$RULE_64"

# --- Load rules into the running kernel audit subsystem ---
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    # Add live rules if not already present
    if ! auditctl -l 2>/dev/null | grep -q "${SYSCALL}.*${KEY}"; then
        auditctl $RULE_32 || true
        auditctl $RULE_64 || true
    fi
fi

exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="fchmodat"
	KEY="perm_mod"
	SYSCALL_GROUPING="chmod fchmod fchmodat"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to
```


---

## RHEL-08-030480 — `audit_rules_dac_modification_fchown`

**Prompt:** On an Ubuntu 24.04 system, the audit subsystem must record every successful use of the system call that changes file ownership via an open file descriptor, so that discretionary-access-control modifications by ordinary users can be detected and traced as potential abuse. Configure the system audit daemon to capture this event for all regular users (those with login UIDs of 1000 or greater, excluding unset UIDs) on both 32-bit and 64-bit system-call interfaces, tagging the records with an identifier that groups permission-modification events. Ensure the rule applies to both audit-rule loading mechanisms as appropriate, is idempotent, and persists across reboots. Write a bash remediation script.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULES_FILE="/etc/audit/rules.d/perm_mod.rules"

RULE_64="-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=unset -k perm_mod"
RULE_32="-a always,exit -F arch=b32 -S fchown -F auid>=1000 -F auid!=unset -k perm_mod"

mkdir -p /etc/audit/rules.d
touch "$RULES_FILE"

if ! grep -qF -- "$RULE_64" "$RULES_FILE"; then
    echo "$RULE_64" >> "$RULES_FILE"
fi

if ! grep -qF -- "$RULE_32" "$RULES_FILE"; then
    echo "$RULE_32" >> "$RULES_FILE"
fi

if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "$RULES_FILE" || true
fi

if command -v auditctl >/dev/null 2>&1; then
    auditctl -l | grep -qF -- "-S fchown" || {
        auditctl "$RULE_64" 2>/dev/null || true
        auditctl "$RULE_32" 2>/dev/null || true
    }
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="fchown"
	KEY="perm_mod"
	SYSCALL_GROUPING="chown fchown fchownat lchown"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset fi
```


---

## RHEL-08-030480 — `audit_rules_dac_modification_fchownat`

**Prompt:** On an Ubuntu 24.04 system, the audit subsystem must record every use of the system call that changes file ownership relative to a directory file descriptor, so that attempts to alter discretionary access controls can be detected and attributed. Configure the system audit daemon to capture these ownership-change events for all regular (non-system) users — those with login UIDs at or above the standard user threshold — tagging the records with an identifier denoting permission modifications, and ensure the rules apply to both 32-bit and 64-bit invocations on a 64-bit system. Write an idempotent bash remediation script that establishes these audit rules so they persist across reboots and load on audit daemon startup.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULES_FILE="/etc/audit/rules.d/perm_mod.rules"
SYSCALL="fchownat"
KEY="perm_mod"
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs 2>/dev/null || true)
UID_MIN=${UID_MIN:-1000}

mkdir -p /etc/audit/rules.d
touch "$RULES_FILE"

ARCHES=("b64")
if [ "$(uname -m)" = "x86_64" ]; then
    ARCHES=("b32" "b64")
fi

for arch in "${ARCHES[@]}"; do
    RULE="-a always,exit -F arch=${arch} -S ${SYSCALL} -F auid>=${UID_MIN} -F auid!=unset -k ${KEY}"
    if ! grep -Fxq "$RULE" "$RULES_FILE"; then
        echo "$RULE" >> "$RULES_FILE"
    fi
done

chmod 0640 "$RULES_FILE"

if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
fi

if pidof auditd >/dev/null 2>&1; then
    systemctl restart auditd 2>/dev/null || service auditd restart 2>/dev/null || true
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="fchownat"
	KEY="perm_mod"
	SYSCALL_GROUPING="chown fchown fchownat lchown"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset 
```


---

## RHEL-08-030200 — `audit_rules_dac_modification_fremovexattr`

**Prompt:** On an Ubuntu 24.04 system, configure the system audit daemon to record every use of the system call that removes a file's extended attributes, since such operations can alter discretionary access controls and may signal attempts to gain unauthorized access to protected data. The auditing must capture these events for both regular users (those with login UIDs of 1000 or greater) and the root account, must cover both 32-bit and 64-bit invocations on a 64-bit system, must be tagged with an identifier that groups permission-modification events together, and must work whether the audit daemon loads its rules via the generated-rules approach or the direct rule-loading approach. Write an idempotent bash remediation script that establishes this auditing and ensures it persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

# Determine syscall for removing extended attributes: removexattr, lremovexattr, fremovexattr
# The specific "removes a file's extended attributes" syscall is removexattr (and its variants).
# We cover the required rules for root (auid=0) and regular users (auid>=1000).

RULES_DIR="/etc/audit/rules.d"
RULES_FILE="${RULES_DIR}/audit.rules"
PERM_RULES_FILE="${RULES_DIR}/perm_mod.rules"
KEY="perm_mod"

mkdir -p "${RULES_DIR}"

# Detect 64-bit system
ARCH_64=false
if [ "$(uname -m)" = "x86_64" ] || [ "$(uname -m)" = "aarch64" ]; then
    ARCH_64=true
fi

# Build the desired rule lines
declare -a DESIRED_RULES

if [ "${ARCH_64}" = true ]; then
    DESIRED_RULES+=("-a always,exit -F arch=b64 -S removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -F key=${KEY}")
    DESIRED_RULES+=("-a always,exit -F arch=b64 -S removexattr,lremovexattr,fremovexattr -F auid=0 -F key=${KEY}")
    DESIRED_RULES+=("-a always,exit -F arch=b32 -S removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -F key=${KEY}")
    DESIRED_RULES+=("-a always,exit -F arch=b32 -S removexattr,lremovexattr,fremovexattr -F auid=0 -F key=${KEY}")
else
    DESIRED_RULES+=("-a always,exit -F arch=b32 -S removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -F key=${KEY}")
    DESIRED_RULES+=("-a always,exit -F arch=b32 -S removexattr,lremovexattr,fremovexattr -F auid=0 -F key=${KEY}")
fi

# Function to ensure a rule exists in a given file (idempotent)
ensure_rule_in_file() {
    local file="$1"
    local rule="$2"
    touch "${file}"
    if ! grep -Fxq "${rule}" "${file}" 2>/dev/null; then
        echo "${rule}" >> "${file}"
    fi
}

# Approach 1: generated-rules approach -> augenrules reads all *.rules in rules.d
# Write rules to a dedicated perm_mod.rules file
for rule in "${DESIRED_RULES[@]}"; do
    ensure_rule_in_file "${PERM_RULES_FILE}" "${rule}"
done

# Approach 2: direct rule-loading approach (auditctl reads /etc/audit/audit.rules)
# Some setups use /etc/audit/rules.d/audit.rules as the single file too.
for rule in "${DESIRED_RULES[@]}"; do
    ensure_rule_in_file "${RULES_FILE}" "${rule}"
done

# Also ensure the main /etc/audit/audit.rules (direct load) contains the rules
MAIN_AUDIT_RULES="/etc/audit/audit.rules"
if [ -f "${MAIN_AUDIT_RULES}" ] || [ -d "/etc/audit" ]; then
    touch "${MAIN_AUDIT_RULES}"
    for rule in "${DESIRED_RULES[@]}"; do
        ensure_rule_in_file "${MAIN_AUDIT_RULES}" "${rule}"
    done
fi

# Load the rules into the running kernel
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
fi

# Ensure rules are active via auditctl as a fallback (idempotent: auditctl ignores duplicates errors)
if command -v auditctl >/dev/null 2>&1; then
    for rule in "${DESIRED_RULES[@]}"; do
        # shellcheck disable=SC2086
        auditctl ${rule} 2>/dev/null || true
    done
fi

# Restart/enable the audit daemon to persist across reboots
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable auditd 2>/dev/null || true
    if systemctl is-active --quiet auditd; then
        systemctl restart auditd 2>/dev/null || service auditd restart 2>/dev/null || true
    else
        systemctl start auditd 2>/dev/null || service auditd start 2>/dev/null || true
    fi
elif command -v service >/dev/null 2>&1; then
    service auditd restart 2>/dev/null || true
fi

echo "Audit rules for extended attribute removal (key=${KEY}) have been configured."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="fremovexattr"
	KEY="perm_mod"
	SYSCALL_GROUPING="fremovexattr lremovexattr removexattr fsetxattr lsetxattr setxattr"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
```


---

## RHEL-08-030200 — `audit_rules_dac_modification_fsetxattr`

**Prompt:** On an Ubuntu 24.04 system, configure the system audit daemon to record every use of the kernel operation that sets extended attributes on an open file descriptor, since changes to file permissions and access controls can signal attempts to gain unauthorized access and auditing them helps detect abuse. The audit rules must capture this activity for both unprivileged users (login UID 1000 and above, excluding unset) and the root account, must cover both 32-bit and 64-bit system call interfaces on a 64-bit system, and must be tagged with an identifier that groups permission-modification events together. Ensure the rules are persistent across reboots and integrate with whichever rule-loading mechanism the audit daemon uses, and make the script idempotent. Provide a bash remediation script.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Configure auditd to record use of the fsetxattr syscall for
# unprivileged users (auid>=1000) and root (auid=0), on both
# 32-bit and 64-bit syscall interfaces, tagged with key
# "perm_mod". Rules are made persistent and idempotent.
#

set -euo pipefail

RULES_FILE="/etc/audit/rules.d/perm_mod.rules"
KEY="perm_mod"

# Ensure audit package/tools are present
if ! command -v auditctl >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y auditd audispd-plugins
fi

# Ensure the rules directory exists
mkdir -p /etc/audit/rules.d

# Define the desired rules
RULES=(
"-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=${KEY}"
"-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=${KEY}"
"-a always,exit -F arch=b64 -S fsetxattr -F auid=0 -F key=${KEY}"
"-a always,exit -F arch=b32 -S fsetxattr -F auid=0 -F key=${KEY}"
)

# Create the rules file if it does not exist
touch "$RULES_FILE"
chmod 0640 "$RULES_FILE"

# Add each rule idempotently
for rule in "${RULES[@]}"; do
    if ! grep -qF -- "$rule" "$RULES_FILE"; then
        echo "$rule" >> "$RULES_FILE"
    fi
done

# Load the rules using the audit daemon's rule-loading mechanism
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v systemctl >/dev/null 2>&1; then
    systemctl restart auditd || service auditd restart || true
else
    service auditd restart || true
fi

echo "Audit rules for fsetxattr (key=${KEY}) configured in ${RULES_FILE}."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="fsetxattr"
	KEY="perm_mod"
	SYSCALL_GROUPING="fremovexattr lremovexattr removexattr fsetxattr lsetxattr setxattr"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
un
```


---

## RHEL-08-030480 — `audit_rules_dac_modification_lchown`

**Prompt:** On an Ubuntu 24.04 system, the audit subsystem must record every attempt by ordinary users (those with login UIDs of 1000 or greater, excluding unset) to change file ownership via the lchown operation, so that discretionary-access-control changes can be traced to identify abuse. Configure the system audit daemon to capture these ownership-change events for both 32-bit and 64-bit system call interfaces, tagged with an identifying key, and ensure the rules apply to the running audit configuration and persist across reboots. Write an idempotent bash remediation script that achieves this.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULES_DIR="/etc/audit/rules.d"
RULES_FILE="${RULES_DIR}/audit_rules_dac_modification_lchown.rules"

mkdir -p "$RULES_DIR"

RULE_64="-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=unset -F key=perm_mod"
RULE_32="-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=unset -F key=perm_mod"

# Ensure persistent rules file contains the required rules idempotently
touch "$RULES_FILE"

if ! grep -qE -- '-a[[:space:]]+always,exit.*-F[[:space:]]+arch=b64.*-S[[:space:]]+lchown.*auid>=1000.*auid!=unset.*key=perm_mod' "$RULES_FILE"; then
    echo "$RULE_64" >> "$RULES_FILE"
fi

if ! grep -qE -- '-a[[:space:]]+always,exit.*-F[[:space:]]+arch=b32.*-S[[:space:]]+lchown.*auid>=1000.*auid!=unset.*key=perm_mod' "$RULES_FILE"; then
    echo "$RULE_32" >> "$RULES_FILE"
fi

# Load rules into running configuration
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "$RULES_FILE" || true
fi

# Ensure the rules are present in the running configuration
if command -v auditctl >/dev/null 2>&1; then
    if ! auditctl -l 2>/dev/null | grep -qE 'arch=b64.*lchown.*auid>=1000.*auid!=unset.*key=perm_mod'; then
        auditctl $RULE_64 || true
    fi
    if ! auditctl -l 2>/dev/null | grep -qE 'arch=b32.*lchown.*auid>=1000.*auid!=unset.*key=perm_mod'; then
        auditctl $RULE_32 || true
    fi
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel && { ! ( ( grep -sqE "^.*\.aarch64$" /proc/sys/kernel/osrelease || grep -sqE "^aarch64$" /proc/sys/kernel/arch; ) ); }; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="lchown"
	KEY="perm_mod"
	SYSCALL_GROUPING="chown fchown fchownat lchown"

	# Perform the remediation for both possible
```


---

## RHEL-08-030200 — `audit_rules_dac_modification_lremovexattr`

**Prompt:** On an Ubuntu 24.04 system, configure the system audit daemon so that it records every use of the operation that removes an extended attribute from a symbolic link, since such discretionary-access-control changes can signal attempts to gain unauthorized access to protected information. The audit configuration must capture this event for both unprivileged users (login UID 1000 and above, excluding unset login UIDs) and the root user, tag the resulting records with an identifier denoting permission modifications, and cover both 32-bit and 64-bit system call interfaces on 64-bit hardware. The rules must integrate with whichever rule-loading mechanism the audit daemon is configured to use and remain in effect across reboots. Write an idempotent bash remediation script that achieves this end state.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

# The syscall that removes an extended attribute from a symbolic link is lremovexattr.
# We create audit rules for both unprivileged (auid>=1000) and root (auid=0) users,
# tagged with key "perm_mod", covering b32 and b64 architectures.

RULE_B64_UNPRIV='-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod'
RULE_B32_UNPRIV='-a always,exit -F arch=b32 -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod'
RULE_B64_ROOT='-a always,exit -F arch=b64 -S lremovexattr -F auid=0 -F key=perm_mod'
RULE_B32_ROOT='-a always,exit -F arch=b32 -S lremovexattr -F auid=0 -F key=perm_mod'

# Determine whether auditd uses augenrules (rules.d) or auditctl (audit.rules)
if grep -qE '^\s*ExecStartPost=.*augenrules' /usr/lib/systemd/system/auditd.service 2>/dev/null || \
   grep -rqE '^\s*ExecStartPost=.*augenrules' /etc/systemd/system/auditd.service.d/ 2>/dev/null || \
   [ -d /etc/audit/rules.d ]; then
    USE_AUGENRULES=1
else
    USE_AUGENRULES=0
fi

if [ "${USE_AUGENRULES}" -eq 1 ] && [ -d /etc/audit/rules.d ]; then
    RULE_FILE="/etc/audit/rules.d/perm_mod.rules"
else
    USE_AUGENRULES=0
    RULE_FILE="/etc/audit/audit.rules"
fi

# Determine if system is 64-bit
ARCH_BITS="$(getconf LONG_BIT 2>/dev/null || echo 64)"

# Build the list of rules we need
declare -a WANTED_RULES=()
if [ "${ARCH_BITS}" = "64" ]; then
    WANTED_RULES+=("${RULE_B64_UNPRIV}")
    WANTED_RULES+=("${RULE_B64_ROOT}")
fi
WANTED_RULES+=("${RULE_B32_UNPRIV}")
WANTED_RULES+=("${RULE_B32_ROOT}")

touch "${RULE_FILE}"

# Idempotently ensure each rule is present. Match on lremovexattr + arch + auid clause.
rule_present() {
    local arch="$1" auidclause="$2"
    grep -Eq -- "^-a[[:space:]]+always,exit.*arch=${arch}\b.*lremovexattr.*${auidclause}" "${RULE_FILE}"
}

add_rule() {
    local rule="$1"
    echo "${rule}" >> "${RULE_FILE}"
}

# 64-bit rules
if [ "${ARCH_BITS}" = "64" ]; then
    rule_present "b64" 'auid>=1000' || add_rule "${RULE_B64_UNPRIV}"
    rule_present "b64" 'auid=0'     || add_rule "${RULE_B64_ROOT}"
fi

# 32-bit rules
rule_present "b32" 'auid>=1000' || add_rule "${RULE_B32_UNPRIV}"
rule_present "b32" 'auid=0'     || add_rule "${RULE_B32_ROOT}"

# Load the rules into the running kernel
if [ "${USE_AUGENRULES}" -eq 1 ]; then
    if command -v augenrules >/dev/null 2>&1; then
        augenrules --load || true
    fi
else
    if command -v auditctl >/dev/null 2>&1; then
        while IFS= read -r line; do
            [ -z "${line}" ] && continue
            case "${line}" in
                \#*) continue ;;
            esac
            # shellcheck disable=SC2086
            auditctl ${line} 2>/dev/null || true
        done < "${RULE_FILE}"
    fi
fi

exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="lremovexattr"
	KEY="perm_mod"
	SYSCALL_GROUPING="fremovexattr lremovexattr removexattr fsetxattr lsetxattr setxattr"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
```


---

## RHEL-08-030200 — `audit_rules_dac_modification_lsetxattr`

**Prompt:** On an Ubuntu 24.04 system, configure the system audit daemon to record every use of the operation that sets an extended attribute on a file (the lsetxattr system call), since such calls can alter discretionary access controls and may indicate attempts to gain unauthorized access; auditing them helps detect abuse by both authorized and unauthorized users. The audit rules must capture these events for all regular users (login UID 1000 and above) and for root, must apply to both 32-bit and 64-bit invocations on a 64-bit system, must be tagged with an identifier that groups permission-modification events together, must work whether the daemon loads rules via the augenrules or auditctl mechanism, and must persist across reboots. Write an idempotent bash remediation script that establishes these audit rules.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULE_FILE="/etc/audit/rules.d/perm_mod.rules"

RULE_64='-a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod'
RULE_64_ROOT='-a always,exit -F arch=b64 -S lsetxattr -F auid=0 -F key=perm_mod'
RULE_32='-a always,exit -F arch=b32 -S lsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod'
RULE_32_ROOT='-a always,exit -F arch=b32 -S lsetxattr -F auid=0 -F key=perm_mod'

mkdir -p /etc/audit/rules.d
touch "$RULE_FILE"

add_rule() {
    local rule="$1"
    if ! grep -qF -- "$rule" "$RULE_FILE"; then
        echo "$rule" >> "$RULE_FILE"
    fi
}

add_rule "$RULE_64"
add_rule "$RULE_64_ROOT"
add_rule "$RULE_32"
add_rule "$RULE_32_ROOT"

if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "$RULE_FILE" || true
fi

exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="lsetxattr"
	KEY="perm_mod"
	SYSCALL_GROUPING="fremovexattr lremovexattr removexattr fsetxattr lsetxattr setxattr"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
un
```


---

## RHEL-08-030200 — `audit_rules_dac_modification_removexattr`

**Prompt:** On an Ubuntu 24.04 system, configure the system audit daemon to record every use of the operation that removes a file's extended attributes, since such discretionary-access-control changes can signal attempts to gain unauthorized access to protected information. The audit configuration must capture this system call for both unprivileged users (login UID 1000 and above, excluding unset) and the root user (login UID 0), for both 32-bit and 64-bit calling conventions on a 64-bit system, and must group these events under a consistent permission-modification audit key. Ensure the rules are loaded persistently across reboots regardless of whether rules are read at daemon startup via the generated-rules mechanism or the direct rule-loading utility. Write an idempotent bash remediation script that achieves this.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

# The system call that removes a file's extended attributes: removexattr / lremovexattr / fremovexattr
# We target the perm_mod audit key for both unprivileged (>=1000) and root (=0) users.

RULES_DIR="/etc/audit/rules.d"
RULES_FILE="${RULES_DIR}/perm_mod.rules"

mkdir -p "${RULES_DIR}"
touch "${RULES_FILE}"

# Define the desired rules
declare -a DESIRED_RULES=(
"-a always,exit -F arch=b32 -S removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod"
"-a always,exit -F arch=b64 -S removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod"
"-a always,exit -F arch=b32 -S removexattr,lremovexattr,fremovexattr -F auid=0 -F key=perm_mod"
"-a always,exit -F arch=b64 -S removexattr,lremovexattr,fremovexattr -F auid=0 -F key=perm_mod"
)

# Idempotently ensure each rule exists in the rules file.
for rule in "${DESIRED_RULES[@]}"; do
    if ! grep -Fxq "${rule}" "${RULES_FILE}"; then
        echo "${rule}" >> "${RULES_FILE}"
    fi
done

# Ensure rules are loaded via the direct rule-loading utility (auditctl) as well.
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "${RULES_FILE}" || true
fi

# Attempt to load directly with auditctl too, to cover the direct utility path.
if command -v auditctl >/dev/null 2>&1; then
    for rule in "${DESIRED_RULES[@]}"; do
        # shellcheck disable=SC2086
        auditctl ${rule} 2>/dev/null || true
    done
fi

exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="removexattr"
	KEY="perm_mod"
	SYSCALL_GROUPING="fremovexattr lremovexattr removexattr fsetxattr lsetxattr setxattr"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping

```


---

## RHEL-08-030200 — `audit_rules_dac_modification_setxattr`

**Prompt:** On an Ubuntu 24.04 system, configure the system audit daemon to record every use of the system call that sets extended file attributes (the setxattr operation), since changes to discretionary access controls can indicate attempts to gain unauthorized access to protected information. The audit configuration must capture this activity for both regular users (those with a login UID of 1000 or greater) and the root account, must cover both 32-bit and 64-bit system call interfaces on a 64-bit system, and must tag the resulting records with an identifier that groups permission-modification events together. Ensure the rules are persistent across reboots and compatible with whichever rule-loading mechanism the audit daemon uses. Write an idempotent bash remediation script that achieves this.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

# Determine the appropriate rules file location based on the loading mechanism
RULES_DIR="/etc/audit/rules.d"
RULES_FILE="${RULES_DIR}/perm_mod.rules"

if [ -d "${RULES_DIR}" ]; then
    TARGET="${RULES_FILE}"
else
    TARGET="/etc/audit/audit.rules"
fi

mkdir -p "$(dirname "${TARGET}")"
touch "${TARGET}"

# Define the required audit rules
declare -a RULES=(
    "-a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F auid!=unset -F key=perm_mod"
    "-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=unset -F key=perm_mod"
    "-a always,exit -F arch=b32 -S setxattr -F auid=0 -F key=perm_mod"
    "-a always,exit -F arch=b64 -S setxattr -F auid=0 -F key=perm_mod"
)

# Idempotently add each rule if not already present
for RULE in "${RULES[@]}"; do
    if ! grep -qF -- "${RULE}" "${TARGET}"; then
        echo "${RULE}" >> "${TARGET}"
    fi
done

# Reload the audit rules using whichever mechanism is available
if command -v augenrules >/dev/null 2>&1 && [ -d "${RULES_DIR}" ]; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "${TARGET}" || true
fi

exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="setxattr"
	KEY="perm_mod"
	SYSCALL_GROUPING="fremovexattr lremovexattr removexattr fsetxattr lsetxattr setxattr"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
uns
```


---

## RHEL-08-030570 — `audit_rules_execution_chacl`

**Prompt:** On an Ubuntu 24.04 system, the system audit daemon must generate an audit record every time the access-control-list modification utility 'chacl' is executed, capturing such attempts by both regular users (login UID 1000 and above) and root, so that security-relevant privileged actions can be reliably attributed and investigated after an incident. Write an idempotent bash remediation script that ensures these execution attempts are audited and that the rule persists across reboots regardless of whether the audit daemon loads rules via the compiled or the direct-load method.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULE_PRIV='-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_mod'
RULE_ROOT='-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid=0 -k perm_mod'

RULES_DIR="/etc/audit/rules.d"
RULES_FILE="${RULES_DIR}/perm_mod.rules"
AUDIT_RULES="/etc/audit/audit.rules"

mkdir -p "$RULES_DIR"
touch "$RULES_FILE"

add_rule_to_file() {
    local rule="$1"
    local file="$2"
    if ! grep -Fxq "$rule" "$file" 2>/dev/null; then
        printf '%s\n' "$rule" >> "$file"
    fi
}

# Ensure rules are present in the rules.d file (compiled method via augenrules)
add_rule_to_file "$RULE_PRIV" "$RULES_FILE"
add_rule_to_file "$RULE_ROOT" "$RULES_FILE"

# Ensure rules are present in the direct-load audit.rules file
if [ -f "$AUDIT_RULES" ]; then
    add_rule_to_file "$RULE_PRIV" "$AUDIT_RULES"
    add_rule_to_file "$RULE_ROOT" "$AUDIT_RULES"
fi

# Load the rules into the running kernel
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "$RULES_FILE" || true
fi

# Add rules directly to the running config if not already loaded
if command -v auditctl >/dev/null 2>&1; then
    if ! auditctl -l 2>/dev/null | grep -Fq -- '-F path=/usr/bin/chacl' | grep -Fq 'auid>=1000'; then
        auditctl $RULE_PRIV 2>/dev/null || true
    fi
    if ! auditctl -l 2>/dev/null | grep -Fq -- '-F path=/usr/bin/chacl'; then
        auditctl $RULE_ROOT 2>/dev/null || true
    fi
fi

exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/bin/chacl -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit 
```


---

## RHEL-08-030330 — `audit_rules_execution_setfacl`

**Prompt:** On an Ubuntu 24.04 system, the audit subsystem must record every attempt to execute the command that modifies file access control lists (the setfacl utility), for all regular users (those with login UIDs of 1000 or greater) as well as accounts tracked through the audit login ID, so that misuse of privileged ACL-changing operations can be investigated after an incident. Write an idempotent bash remediation script that configures the system audit daemon to generate an audit record on each execution of this command, ensuring the rule works regardless of which rule-loading mechanism the audit daemon uses and that it persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

# Remediation: audit execution of /usr/bin/setfacl for uid>=1000 and by auid.

AUDIT_RULE='-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -F key=perm_mod'

# Determine which mechanism the audit daemon uses.
if [ -d /etc/audit/rules.d ]; then
    RULES_FILE="/etc/audit/rules.d/setfacl.rules"
else
    RULES_FILE="/etc/audit/audit.rules"
fi

# Ensure the directory/file exists.
mkdir -p "$(dirname "$RULES_FILE")"
touch "$RULES_FILE"

# Idempotently add the rule to the rules.d file (or audit.rules).
if ! grep -Fxq -- "$AUDIT_RULE" "$RULES_FILE"; then
    # Remove any prior partial/variant rules referencing setfacl to avoid duplicates.
    if grep -q -- '/usr/bin/setfacl' "$RULES_FILE"; then
        grep -v -- '/usr/bin/setfacl' "$RULES_FILE" > "${RULES_FILE}.tmp" || true
        mv "${RULES_FILE}.tmp" "$RULES_FILE"
    fi
    echo "$AUDIT_RULE" >> "$RULES_FILE"
fi

# Also ensure it is present in /etc/audit/audit.rules if that file exists and is
# used independently (covers systems loading audit.rules directly).
if [ -f /etc/audit/audit.rules ] && [ "$RULES_FILE" != "/etc/audit/audit.rules" ]; then
    if ! grep -Fxq -- "$AUDIT_RULE" /etc/audit/audit.rules; then
        if grep -q -- '/usr/bin/setfacl' /etc/audit/audit.rules; then
            grep -v -- '/usr/bin/setfacl' /etc/audit/audit.rules > /etc/audit/audit.rules.tmp || true
            mv /etc/audit/audit.rules.tmp /etc/audit/audit.rules
        fi
        echo "$AUDIT_RULE" >> /etc/audit/audit.rules
    fi
fi

# Load the rules so they take effect immediately and persist via the files above.
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R /etc/audit/audit.rules || true
fi

exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/bin/setfacl -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audi
```


---

## RHEL-08-030260 — `audit_rules_execution_chcon`

**Prompt:** On an Ubuntu 24.04 system, configure the system audit daemon so that every execution of the SELinux file-context changing utility (the chcon command) is recorded for all regular users (those with login UIDs at or above 1000) as well as for accounts that have logged in, capturing such attempts as privileged-command usage. This auditing helps detect misuse of privileged functions and potential privilege-escalation activity. Write an idempotent bash remediation script that establishes this audit rule and ensures it remains in effect across reboots and audit-daemon restarts, regardless of whether rules are loaded via augenrules or auditctl.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULE='-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged'

# Determine which audit binary is in use to decide default handling
# We support both augenrules (files in /etc/audit/rules.d/) and auditctl (/etc/audit/audit.rules)

# --- Handle augenrules style: /etc/audit/rules.d/ ---
RULES_D="/etc/audit/rules.d"
PRIV_FILE="${RULES_D}/privileged.rules"

if [ -d "$RULES_D" ]; then
    # Remove any existing chcon privileged rule lines from all files in rules.d
    for f in "$RULES_D"/*.rules; do
        [ -e "$f" ] || continue
        if grep -Pq -- '^-a always,exit.*/usr/bin/chcon' "$f"; then
            grep -Pv -- '^-a always,exit.*/usr/bin/chcon' "$f" > "${f}.tmp" || true
            mv "${f}.tmp" "$f"
        fi
    done
    # Add the desired rule to the privileged rules file
    touch "$PRIV_FILE"
    if ! grep -Fxq -- "$RULE" "$PRIV_FILE"; then
        printf '%s\n' "$RULE" >> "$PRIV_FILE"
    fi
fi

# --- Handle auditctl style: /etc/audit/audit.rules ---
AUDIT_RULES="/etc/audit/audit.rules"
if [ -f "$AUDIT_RULES" ]; then
    if grep -Pq -- '^-a always,exit.*/usr/bin/chcon' "$AUDIT_RULES"; then
        grep -Pv -- '^-a always,exit.*/usr/bin/chcon' "$AUDIT_RULES" > "${AUDIT_RULES}.tmp" || true
        mv "${AUDIT_RULES}.tmp" "$AUDIT_RULES"
    fi
    if ! grep -Fxq -- "$RULE" "$AUDIT_RULES"; then
        printf '%s\n' "$RULE" >> "$AUDIT_RULES"
    fi
fi

# --- Load the rules into the running kernel ---
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "$AUDIT_RULES" || true
fi

# Ensure the rule is active in the running configuration
if command -v auditctl >/dev/null 2>&1; then
    if ! auditctl -l 2>/dev/null | grep -Pq -- '/usr/bin/chcon'; then
        auditctl -a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged || true
    fi
fi

exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/bin/chcon -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit 
```


---

## RHEL-08-030313 — `audit_rules_execution_semanage`

**Prompt:** On an Ubuntu 24.04 system, the system audit daemon must record every attempt to execute the SELinux management utility (the semanage command), since this privileged program is a potential target for privilege-escalation and misuse, and auditing its use is essential for detecting insider and advanced-persistent threats. Configure the audit subsystem so that any execution of this command by all regular users (those with a login UID of 1000 or greater) and by root is captured, with the events grouped under a recognizable tag for privileged activity. Write an idempotent bash remediation script that establishes this audit rule and ensures it persists across reboots and audit-daemon restarts.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULE_FILE="/etc/audit/rules.d/privileged.rules"
SEMANAGE="/usr/sbin/semanage"

RULE_UID1000="-a always,exit -F path=${SEMANAGE} -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged"
RULE_ROOT="-a always,exit -F path=${SEMANAGE} -F perm=x -F auid=0 -F key=privileged"

mkdir -p "$(dirname "${RULE_FILE}")"
touch "${RULE_FILE}"

# Remove any existing rules referencing semanage to avoid duplicates
if [ -f "${RULE_FILE}" ]; then
    grep -v -- "-F path=${SEMANAGE} " "${RULE_FILE}" > "${RULE_FILE}.tmp" 2>/dev/null || true
    mv "${RULE_FILE}.tmp" "${RULE_FILE}"
fi

# Add the required rules
echo "${RULE_UID1000}" >> "${RULE_FILE}"
echo "${RULE_ROOT}" >> "${RULE_FILE}"

chmod 0640 "${RULE_FILE}"

# Load the rules into the running audit system
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "${RULE_FILE}" || true
fi

# Ensure auditd is enabled and running to persist across reboots
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable auditd >/dev/null 2>&1 || true
    if systemctl is-active --quiet auditd; then
        service auditd restart >/dev/null 2>&1 || systemctl restart auditd >/dev/null 2>&1 || true
    else
        systemctl start auditd >/dev/null 2>&1 || true
    fi
fi

exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/sbin/semanage -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of au
```


---

## RHEL-08-030314 — `audit_rules_execution_setfiles`

**Prompt:** On an Ubuntu 24.04 system, ensure that the system audit subsystem records every execution attempt of the privileged SELinux file-context labeling utility (setfiles) by all users, including root, so that misuse of this privileged program can be detected and investigated. The audit rule must apply to executions by both regular users (login UID 1000 and above) and capture the events under a consistent identifying key for privileged-command monitoring. Write an idempotent bash remediation script that configures this auditing such that the rule is effective and persists across reboots regardless of whether the audit daemon loads its rules via the standard rule-compilation mechanism or a single consolidated rules file.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

BIN="/usr/sbin/setfiles"
KEY="privileged"
RULE="-a always,exit -F path=${BIN} -F perm=x -F auid>=1000 -F auid!=unset -k ${KEY}"

# Determine the correct location for the persistent rule
RULES_DIR="/etc/audit/rules.d"
RULES_FILE="${RULES_DIR}/privileged.rules"
CONSOLIDATED="/etc/audit/audit.rules"

# Ensure the binary path exists; if not, still write the rule (path-based rules are valid)
if [ ! -e "$BIN" ]; then
    echo "Warning: ${BIN} does not exist on this system; writing rule anyway." >&2
fi

# --- Handle the augenrules mechanism (rules.d) ---
if [ -d "$RULES_DIR" ]; then
    touch "$RULES_FILE"
    # Remove any prior setfiles rule to keep idempotent
    if grep -qsE "^[^#]*-F[[:space:]]+path=${BIN//\//\\/}([[:space:]]|$)" "$RULES_FILE" 2>/dev/null; then
        sed -i "\|path=${BIN}|d" "$RULES_FILE"
    fi
    echo "$RULE" >> "$RULES_FILE"
    chmod 0640 "$RULES_FILE"
fi

# --- Handle the single consolidated audit.rules mechanism ---
if [ -f "$CONSOLIDATED" ]; then
    if grep -qsE "path=${BIN//\//\\/}([[:space:]]|$)" "$CONSOLIDATED" 2>/dev/null; then
        sed -i "\|path=${BIN}|d" "$CONSOLIDATED"
    fi
    echo "$RULE" >> "$CONSOLIDATED"
    chmod 0640 "$CONSOLIDATED"
fi

# --- Load the rules so they are effective immediately ---
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    # Load the rule directly if not already present in the running config
    if ! auditctl -l 2>/dev/null | grep -qE "path=${BIN//\//\\/}([[:space:]]|$)"; then
        auditctl -a always,exit -F path="${BIN}" -F perm=x -F auid>=1000 -F auid!=unset -k "${KEY}" || true
    fi
fi

# --- Verify ---
if command -v auditctl >/dev/null 2>&1; then
    if auditctl -l 2>/dev/null | grep -qE "path=${BIN//\//\\/}([[:space:]]|$)"; then
        echo "Audit rule for ${BIN} is active."
    else
        echo "Warning: audit rule not currently active (auditd may need a restart/enabling)." >&2
    fi
fi

echo "Remediation complete: setfiles execution auditing configured with key '${KEY}'."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/sbin/setfiles -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of au
```


---

## RHEL-08-030316 — `audit_rules_execution_setsebool`

**Prompt:** On an Ubuntu 24.04 system, the audit subsystem must record every execution attempt of the privileged command used to toggle SELinux boolean settings, so that misuse of this privileged function — whether by authorized users, compromised accounts, or attackers attempting privilege escalation — can be detected and investigated. Write an idempotent bash remediation script that ensures the system audit daemon persistently logs all executions of this command by any user with a real (login) user ID of 1000 or greater, tagging the events with an identifier that marks them as privileged-command usage, with the rule surviving reboots and audit-rule reloads.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

COMMAND="/usr/sbin/setsebool"
RULES_FILE="/etc/audit/rules.d/50-privileged-setsebool.rules"
RULE="-a always,exit -F path=${COMMAND} -F perm=x -F auid>=1000 -F auid!=unset -k privileged"

# Ensure the auditd rules directory exists
mkdir -p /etc/audit/rules.d

# Ensure the command exists before adding a rule referencing it
if [ ! -e "${COMMAND}" ]; then
    echo "Warning: ${COMMAND} not found on system; adding rule anyway for persistence." >&2
fi

# Idempotently ensure the rule is present in the rules file
if [ -f "${RULES_FILE}" ]; then
    if ! grep -Fxq "${RULE}" "${RULES_FILE}"; then
        printf '%s\n' "${RULE}" >> "${RULES_FILE}"
    fi
else
    printf '%s\n' "${RULE}" > "${RULES_FILE}"
fi

chmod 0640 "${RULES_FILE}"
chown root:root "${RULES_FILE}"

# Load the rules so they take effect immediately (and persist across reboots via rules.d)
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "${RULES_FILE}" || true
fi

echo "Audit rule for ${COMMAND} ensured in ${RULES_FILE}."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/sbin/setsebool -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of a
```


---

## RHEL-08-030361 — `audit_rules_file_deletion_events_rename`

**Prompt:** On an Ubuntu 24.04 system, the audit subsystem must maintain a trail of file-deletion activity so that malicious attempts to remove files (for example, to hide an intrusion by deleting logs) can be detected and investigated. Configure the system audit daemon to record events where files are removed via the rename operation, covering all regular users and root (auditable user IDs of 1000 and above, excluding unset IDs), for both 32-bit and 64-bit system call interfaces as applicable, and group these events under a deletion-related audit key. Write an idempotent bash remediation script that establishes these audit rules so they take effect and persist across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULES_FILE="/etc/audit/rules.d/delete.rules"

mkdir -p /etc/audit/rules.d

# Determine architecture support
declare -a ARCHES
if [ "$(uname -m)" = "x86_64" ] || [ "$(uname -m)" = "aarch64" ]; then
    ARCHES=(b32 b64)
else
    ARCHES=(b32)
fi

# Build the desired rule lines
declare -a DESIRED_RULES
for arch in "${ARCHES[@]}"; do
    DESIRED_RULES+=("-a always,exit -F arch=${arch} -S rename -F auid>=1000 -F auid!=unset -F key=delete")
done

# Ensure the rules file exists
touch "$RULES_FILE"

# Add each rule idempotently
for rule in "${DESIRED_RULES[@]}"; do
    if ! grep -Eq -- "^${rule}$" "$RULES_FILE" 2>/dev/null; then
        echo "$rule" >> "$RULES_FILE"
    fi
done

# Load the rules so they take effect now
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    for rule in "${DESIRED_RULES[@]}"; do
        auditctl $rule || true
    done
fi

# Restart the audit service if possible to ensure persistence
if command -v service >/dev/null 2>&1; then
    service auditd restart 2>/dev/null || systemctl restart auditd 2>/dev/null || true
elif command -v systemctl >/dev/null 2>&1; then
    systemctl restart auditd 2>/dev/null || true
fi

exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel && { ! ( ( grep -sqE "^.*\.aarch64$" /proc/sys/kernel/osrelease || grep -sqE "^aarch64$" /proc/sys/kernel/arch; ) ); }; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="rename"
	KEY="delete"
	SYSCALL_GROUPING="unlink unlinkat rename renameat rmdir"
	# Perform the remediation for both po
```


---

## RHEL-08-030361 — `audit_rules_file_deletion_events_renameat`

**Prompt:** On an Ubuntu 24.04 system, the system audit daemon must create an audit trail for file deletion and rename operations so that attempts to remove or rename files—potentially to conceal malicious activity—can be detected and investigated. Configure the audit subsystem to record the rename-style file removal/relocation activity performed by all regular users (those with login UIDs of 1000 or greater, excluding unset UIDs), covering both 32-bit and 64-bit system call interfaces as appropriate to the platform. The rules must persist across reboots and be loaded by the audit daemon at startup, and the script must be idempotent. Write a bash remediation script that achieves this.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULES_FILE="/etc/audit/rules.d/50-delete.rules"

# Ensure the rules directory exists
mkdir -p /etc/audit/rules.d

# Ensure the rules file exists
touch "$RULES_FILE"

# Determine syscalls to monitor based on architecture
SYSCALLS="rename,unlink,unlinkat,renameat"

# Build the desired rules
declare -a DESIRED_RULES=()

# 64-bit rule (b64) if applicable
if [ "$(getconf LONG_BIT)" = "64" ]; then
    DESIRED_RULES+=("-a always,exit -F arch=b64 -S ${SYSCALLS} -F auid>=1000 -F auid!=unset -F key=delete")
fi

# 32-bit rule (b32) - applicable on both 32-bit and 64-bit multilib systems
DESIRED_RULES+=("-a always,exit -F arch=b32 -S ${SYSCALLS} -F auid>=1000 -F auid!=unset -F key=delete")

# Idempotently add each rule
for rule in "${DESIRED_RULES[@]}"; do
    if ! grep -qF -- "$rule" "$RULES_FILE" 2>/dev/null; then
        echo "$rule" >> "$RULES_FILE"
    fi
done

# Reload the audit rules if auditd is available
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "$RULES_FILE" || true
fi

exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="renameat"
	KEY="delete"
	SYSCALL_GROUPING="unlink unlinkat rename renameat rmdir"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall

```


---

## RHEL-08-030361 — `audit_rules_file_deletion_events_rmdir`

**Prompt:** On an Ubuntu 24.04 system, the audit subsystem must maintain a trail of file and directory deletion activity so that malicious attempts to remove files (for example, to conceal an intrusion by deleting logs) can be detected and investigated. Configure the system audit daemon to record every directory-removal operation performed by regular (non-system) users — those with login UIDs of 1000 or greater — for all applicable system architectures, ensuring such events are captured under a recognizable deletion-tracking label. Write an idempotent bash remediation script that establishes this auditing so it survives reboots and audit-rule reloads.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULES_FILE="/etc/audit/rules.d/delete.rules"

mkdir -p /etc/audit/rules.d
touch "$RULES_FILE"

declare -a DESIRED_RULES=(
    "-a always,exit -F arch=b32 -S rmdir -F auid>=1000 -F auid!=unset -F key=delete"
    "-a always,exit -F arch=b64 -S rmdir -F auid>=1000 -F auid!=unset -F key=delete"
)

for rule in "${DESIRED_RULES[@]}"; do
    if ! grep -qF -- "$rule" "$RULES_FILE"; then
        echo "$rule" >> "$RULES_FILE"
    fi
done

chmod 0640 "$RULES_FILE"

if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "$RULES_FILE" || true
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl restart auditd 2>/dev/null || service auditd restart 2>/dev/null || true
fi

exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel && { ! ( ( grep -sqE "^.*\.aarch64$" /proc/sys/kernel/osrelease || grep -sqE "^aarch64$" /proc/sys/kernel/arch; ) ); }; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="rmdir"
	KEY="delete"
	SYSCALL_GROUPING="unlink unlinkat rename renameat rmdir"
	# Perform the remediation for both pos
```


---

## RHEL-08-030361 — `audit_rules_file_deletion_events_unlink`

**Prompt:** On an Ubuntu 24.04 system, configure the system audit daemon to record file-deletion attempts performed via the unlink operation. The audit trail must capture these events for all regular and privileged user actions (i.e., for login UIDs of 1000 and above, excluding unset UIDs), covering both 32-bit and 64-bit invocations as appropriate for the architecture, and the matching events should be tagged with an identifier that groups them as deletion activity. This audit trail helps detect malicious attempts to remove files such as logs to conceal activity. Write an idempotent bash remediation script that ensures these audit rules are present and take effect persistently across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULES_FILE="/etc/audit/rules.d/audit.rules"

# Ensure the rules directory and file exist
mkdir -p /etc/audit/rules.d
touch "$RULES_FILE"

# Determine architecture support
ARCHES=("b64")
if [ "$(uname -m)" != "aarch64" ] && [ "$(uname -m)" != "arm64" ]; then
    ARCHES=("b32" "b64")
fi

for ARCH in "${ARCHES[@]}"; do
    RULE="-a always,exit -F arch=${ARCH} -S unlink -F auid>=1000 -F auid!=unset -F key=delete"
    # Check for an existing equivalent rule (allowing for -k or -F key= form)
    if ! grep -Eq -- "^-a[[:space:]]+always,exit[[:space:]].*-F[[:space:]]+arch=${ARCH}([[:space:]].*)?-S[[:space:]]+unlink([[:space:]].*)?auid>=1000([[:space:]].*)?auid!=unset([[:space:]].*)?(-k[[:space:]]+delete|-F[[:space:]]+key=delete)" "$RULES_FILE"; then
        echo "$RULE" >> "$RULES_FILE"
    fi
done

# Load the rules persistently and into the running kernel
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "$RULES_FILE" || true
fi

# Restart the audit daemon if possible to ensure rules take effect
if command -v service >/dev/null 2>&1; then
    service auditd restart 2>/dev/null || systemctl restart auditd 2>/dev/null || true
elif command -v systemctl >/dev/null 2>&1; then
    systemctl restart auditd 2>/dev/null || true
fi

exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel && { ! ( ( grep -sqE "^.*\.aarch64$" /proc/sys/kernel/osrelease || grep -sqE "^aarch64$" /proc/sys/kernel/arch; ) ); }; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="unlink"
	KEY="delete"
	SYSCALL_GROUPING="unlink unlinkat rename renameat rmdir"
	# Perform the remediation for both po
```


---

## RHEL-08-030361 — `audit_rules_file_deletion_events_unlinkat`

**Prompt:** On an Ubuntu 24.04 system, the system audit daemon must record file deletion events so that attempts to remove files — including malicious efforts to erase log files and hide intrusions — leave an audit trail. Specifically, ensure the audit subsystem captures use of the file-unlinking deletion operation (the variant that removes a directory entry relative to a directory file descriptor) performed by all regular users (those with login UIDs of 1000 or greater, excluding unset IDs), for both 32-bit and 64-bit invocations as appropriate to the architecture, tagged with an identifier of "delete". The configuration must be idempotent and persist across reboots and audit-daemon restarts. Write a bash remediation script that achieves this.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULES_FILE="/etc/audit/rules.d/audit.rules"

mkdir -p /etc/audit/rules.d
touch "$RULES_FILE"

# Determine architecture
ARCH="$(uname -m)"

add_rule() {
    local rule="$1"
    if ! grep -qF -- "$rule" "$RULES_FILE"; then
        echo "$rule" >> "$RULES_FILE"
    fi
}

if [[ "$ARCH" == "x86_64" || "$ARCH" == "aarch64" || "$ARCH" == "ppc64le" || "$ARCH" == "s390x" ]]; then
    add_rule "-a always,exit -F arch=b32 -S unlinkat -F auid>=1000 -F auid!=unset -F key=delete"
    add_rule "-a always,exit -F arch=b64 -S unlinkat -F auid>=1000 -F auid!=unset -F key=delete"
else
    add_rule "-a always,exit -F arch=b32 -S unlinkat -F auid>=1000 -F auid!=unset -F key=delete"
fi

# Reload audit rules to persist and apply
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "$RULES_FILE" || true
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="unlinkat"
	KEY="delete"
	SYSCALL_GROUPING="unlink unlinkat rename renameat rmdir"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall

```


---

## RHEL-08-030420 — `audit_rules_unsuccessful_file_modification_creat`

**Prompt:** On an Ubuntu 24.04 system, configure the system audit daemon to record unsuccessful attempts by regular users to create files via the file-creation system call, since failed file-access attempts can indicate malicious activity or an in-progress compromise. The audit configuration must capture both permission-denied and operation-not-permitted failures of this system call for all unprivileged users (those with login UIDs of 1000 or greater, excluding unset UIDs), must cover both 32-bit and 64-bit invocations on a 64-bit system, and must tag these events with a consistent identifying label. Ensure the rules are loaded into the running audit configuration and persist across reboots regardless of which rule-loading mechanism the audit daemon uses. Write an idempotent bash remediation script that achieves this.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

KEY="unsuccessful-create"
RULES_DIR="/etc/audit/rules.d"
RULES_FILE="${RULES_DIR}/50-${KEY}.rules"

mkdir -p "$RULES_DIR"

# Determine relevant syscall creation call. The "creat" syscall.
# Build the rule lines for both EACCES and EPERM, both arches.
declare -a RULES=(
  "-a always,exit -F arch=b32 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=${KEY}"
  "-a always,exit -F arch=b32 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=${KEY}"
  "-a always,exit -F arch=b64 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=${KEY}"
  "-a always,exit -F arch=b64 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=${KEY}"
)

# Write persistent rules file idempotently.
{
  for r in "${RULES[@]}"; do
    echo "$r"
  done
} > "${RULES_FILE}.tmp"

if [ ! -f "$RULES_FILE" ] || ! cmp -s "${RULES_FILE}.tmp" "$RULES_FILE"; then
  mv "${RULES_FILE}.tmp" "$RULES_FILE"
else
  rm -f "${RULES_FILE}.tmp"
fi

chmod 0640 "$RULES_FILE"

# Load rules into the running configuration.
# Prefer augenrules if the daemon uses rules.d; otherwise fall back to auditctl.
if command -v augenrules >/dev/null 2>&1; then
  augenrules --load || true
fi

# Ensure each rule is present in the running configuration; add any missing.
if command -v auditctl >/dev/null 2>&1; then
  for r in "${RULES[@]}"; do
    if ! auditctl -l 2>/dev/null | grep -Fq -- "$r"; then
      auditctl $r || true
    fi
  done
fi

echo "Audit rules for '${KEY}' configured and loaded."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel && { ! ( ( grep -sqE "^.*\.aarch64$" /proc/sys/kernel/osrelease || grep -sqE "^aarch64$" /proc/sys/kernel/arch; ) ); }; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL="creat"
KEY="access"
SYSCALL_GROUPING="creat ftruncate truncate open openat open_by_handle_at"

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS="-F exit=-EACCES"
	# Perform
```


---

## RHEL-08-030420 — `audit_rules_unsuccessful_file_modification_ftruncate`

**Prompt:** On an Ubuntu 24.04 system, configure the system audit daemon to record every unsuccessful attempt to truncate a file that fails due to permission-denied or operation-not-permitted errors, for all regular user accounts (those with login UIDs of 1000 or greater, excluding unset/system IDs), tagged with an identifier of 'access'. Such failed file-access attempts can indicate malicious probing and serve as evidence of compromise. The rules must cover both 32-bit and 64-bit system call interfaces on a 64-bit machine, be compatible with whichever rule-loading mechanism the audit daemon uses at startup, be idempotent, and persist across reboots. Write a bash remediation script that achieves this.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

# Determine the audit rules file destination based on the loading mechanism.
if [ -d /etc/audit/rules.d ]; then
    RULES_FILE="/etc/audit/rules.d/access.rules"
    USE_RULESD=1
else
    RULES_FILE="/etc/audit/audit.rules"
    USE_RULESD=0
fi

# Ensure the auditd package tools are present.
if ! command -v auditctl >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get update -y
        DEBIAN_FRONTEND=noninteractive apt-get install -y auditd audispd-plugins
    fi
fi

# Ensure the rules file exists.
touch "$RULES_FILE"
chmod 0640 "$RULES_FILE"

# Define the rules for both 64-bit and 32-bit interfaces.
RULE_64_EACCES="-a always,exit -F arch=b64 -S truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access"
RULE_64_EPERM="-a always,exit -F arch=b64 -S truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access"
RULE_32_EACCES="-a always,exit -F arch=b32 -S truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access"
RULE_32_EPERM="-a always,exit -F arch=b32 -S truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access"

add_rule() {
    local rule="$1"
    if ! grep -qF -- "$rule" "$RULES_FILE"; then
        echo "$rule" >> "$RULES_FILE"
    fi
}

add_rule "$RULE_64_EACCES"
add_rule "$RULE_64_EPERM"
add_rule "$RULE_32_EACCES"
add_rule "$RULE_32_EPERM"

# Load the rules into the running kernel audit subsystem.
if [ "$USE_RULESD" -eq 1 ]; then
    if command -v augenrules >/dev/null 2>&1; then
        augenrules --load || true
    fi
else
    if command -v auditctl >/dev/null 2>&1; then
        auditctl -R "$RULES_FILE" || true
    fi
fi

# Ensure auditd is enabled and running so rules persist across reboots.
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable auditd 2>/dev/null || true
    systemctl restart auditd 2>/dev/null || service auditd restart 2>/dev/null || true
fi

exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL="ftruncate"
KEY="access"
SYSCALL_GROUPING="creat ftruncate truncate open openat open_by_handle_at"

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS="-F exit=-EACCES"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset
```


---

## RHEL-08-030420 — `audit_rules_unsuccessful_file_modification_open`

**Prompt:** On an Ubuntu 24.04 system, configure the system audit daemon to record unsuccessful attempts to open files, since failed file-access attempts can indicate malicious activity or a compromise. The audit system must capture open operations that fail due to permission-denied and operation-not-permitted errors, for all regular user accounts (those with a login UID of 1000 or greater, excluding unset UIDs), on both 32-bit and 64-bit system call interfaces where applicable, and tag these events with an identifying key of "access". The rules must be applied in a way compatible with how the daemon loads its rules and must persist across reboots. Write an idempotent bash remediation script that establishes these audit rules.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULE_FILE="/etc/audit/rules.d/access.rules"

mkdir -p /etc/audit/rules.d

declare -a RULES=(
"-a always,exit -F arch=b32 -S open,openat,open_by_handle_at,creat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access"
"-a always,exit -F arch=b32 -S open,openat,open_by_handle_at,creat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access"
"-a always,exit -F arch=b64 -S open,openat,open_by_handle_at,creat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access"
"-a always,exit -F arch=b64 -S open,openat,open_by_handle_at,creat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access"
)

touch "$RULE_FILE"

for rule in "${RULES[@]}"; do
    if ! grep -qF -- "$rule" "$RULE_FILE"; then
        echo "$rule" >> "$RULE_FILE"
    fi
done

chmod 0640 "$RULE_FILE"

if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "$RULE_FILE" || true
fi

if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet auditd; then
        systemctl restart auditd || service auditd restart || true
    fi
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel && { ! ( ( grep -sqE "^.*\.aarch64$" /proc/sys/kernel/osrelease || grep -sqE "^aarch64$" /proc/sys/kernel/arch; ) ); }; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL="open"
KEY="access"
SYSCALL_GROUPING="creat ftruncate truncate open openat open_by_handle_at"

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS="-F exit=-EACCES"
	# Perform 
```


---

## RHEL-08-030420 — `audit_rules_unsuccessful_file_modification_open_by_handle_at`

**Prompt:** On an Ubuntu 24.04 system, configure the system audit daemon to record unsuccessful attempts by regular users (those with login UIDs of 1000 or greater, excluding unset) to access files via the open_by_handle_at system call, capturing both permission-denied and operation-not-permitted failures and tagging these events with the audit key "access". Such failed access attempts can indicate malicious activity or a system compromise, so they must be logged for both 32-bit and 64-bit system call interfaces. Write an idempotent bash remediation script that establishes these audit rules so they take effect on the next audit rule load and persist across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULES_FILE="/etc/audit/rules.d/access.rules"

mkdir -p /etc/audit/rules.d
touch "$RULES_FILE"

declare -a RULES=(
"-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access"
"-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access"
"-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access"
"-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access"
)

for rule in "${RULES[@]}"; do
    if ! grep -qF -- "$rule" "$RULES_FILE" 2>/dev/null; then
        echo "$rule" >> "$RULES_FILE"
    fi
done

if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "$RULES_FILE"
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL="open_by_handle_at"
KEY="access"
SYSCALL_GROUPING="creat ftruncate truncate open openat open_by_handle_at"

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS="-F exit=-EACCES"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_groupi
```


---

## RHEL-08-030420 — `audit_rules_unsuccessful_file_modification_openat`

**Prompt:** On an Ubuntu 24.04 system, configure the system audit daemon to record unsuccessful attempts by regular users (those with login UID 1000 or greater, excluding unset) to open files via the relevant file-open operation, capturing both permission-denied and access-denied failure outcomes, tagged with an identifying key of "access". The rules must cover both 32-bit and 64-bit system call interfaces on a 64-bit system, since failed file-access attempts can indicate malicious activity or a compromised system. Write an idempotent bash remediation script that establishes these audit rules so they persist across reboots and are loaded by the audit daemon.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULES_FILE="/etc/audit/rules.d/access.rules"

mkdir -p /etc/audit/rules.d

RULES=(
"-a always,exit -F arch=b32 -S open -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access"
"-a always,exit -F arch=b32 -S open -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access"
"-a always,exit -F arch=b64 -S open -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access"
"-a always,exit -F arch=b64 -S open -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access"
)

touch "$RULES_FILE"

for rule in "${RULES[@]}"; do
    if ! grep -qF -- "$rule" "$RULES_FILE"; then
        echo "$rule" >> "$RULES_FILE"
    fi
done

chmod 0640 "$RULES_FILE"

if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "$RULES_FILE" || true
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl restart auditd 2>/dev/null || service auditd restart 2>/dev/null || true
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL="openat"
KEY="access"
SYSCALL_GROUPING="creat ftruncate truncate open openat open_by_handle_at"

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS="-F exit=-EACCES"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset sy
```


---

## RHEL-08-030420 — `audit_rules_unsuccessful_file_modification_truncate`

**Prompt:** On an Ubuntu 24.04 system, configure the system audit daemon to record every unsuccessful attempt to truncate a file when that attempt fails due to permission-denied or operation-not-permitted errors, for all regular user accounts (those with login UIDs of 1000 or greater, excluding unset UIDs). Such failed file-access attempts can indicate malicious probing or a compromised system, so they must be captured as audit evidence. The rules must apply to both 32-bit and 64-bit system call interfaces (where applicable), be tagged with an identifying audit key of "access", take effect through the daemon's normal rule-loading mechanism, and persist across reboots. Provide an idempotent bash remediation script.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULES_FILE="/etc/audit/rules.d/access.rules"

mkdir -p /etc/audit/rules.d

declare -a DESIRED_RULES=(
"-a always,exit -F arch=b32 -S truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access"
"-a always,exit -F arch=b32 -S truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access"
"-a always,exit -F arch=b64 -S truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access"
"-a always,exit -F arch=b64 -S truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access"
)

touch "$RULES_FILE"

for rule in "${DESIRED_RULES[@]}"; do
    if ! grep -qF -- "$rule" "$RULES_FILE"; then
        echo "$rule" >> "$RULES_FILE"
    fi
done

chmod 0640 "$RULES_FILE"

if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "$RULES_FILE" || true
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl restart auditd 2>/dev/null || service auditd restart 2>/dev/null || true
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL="truncate"
KEY="access"
SYSCALL_GROUPING="creat ftruncate truncate open openat open_by_handle_at"

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS="-F exit=-EACCES"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset 
```


---

## RHEL-08-030390 — `audit_rules_kernel_module_loading_delete`

**Prompt:** On an Ubuntu 24.04 system, configure the system audit daemon to record every event in which a kernel module is unloaded from the running kernel, since removing modules can be used to subvert kernel behavior and hide malicious activity, making an audit trail essential. The audit rule must capture module-removal actions performed by all non-system users (those with login UID 1000 or greater), apply to every hardware architecture the system supports, and be associated with an identifying key of "modules". Write an idempotent bash remediation script that establishes this auditing so it is active and persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULES_DIR="/etc/audit/rules.d"
RULES_FILE="${RULES_DIR}/modules.rules"

mkdir -p "${RULES_DIR}"

# Determine architectures to cover
ARCHES=("b64")
if grep -qE 'lm|i386' /proc/cpuinfo 2>/dev/null; then
    # 64-bit CPU may support both; include b32 for compatibility
    ARCHES=("b32" "b64")
fi
# Fallback: if we can't tell, cover both
if [ "${#ARCHES[@]}" -eq 0 ]; then
    ARCHES=("b32" "b64")
fi

# Build desired rule lines
declare -a DESIRED_RULES
for arch in "${ARCHES[@]}"; do
    DESIRED_RULES+=("-a always,exit -F arch=${arch} -S delete_module -F auid>=1000 -F auid!=unset -k modules")
done

# Ensure the rules file exists
touch "${RULES_FILE}"

# Add each desired rule if not already present (idempotent)
for rule in "${DESIRED_RULES[@]}"; do
    if ! grep -qxF "${rule}" "${RULES_FILE}"; then
        echo "${rule}" >> "${RULES_FILE}"
    fi
done

# Load the rules into the running kernel and make persistent
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    for rule in "${DESIRED_RULES[@]}"; do
        # shellcheck disable=SC2086
        auditctl ${rule} || true
    done
fi

# Restart/ensure auditd is running so config persists across reboots
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable auditd >/dev/null 2>&1 || true
    if systemctl is-active --quiet auditd; then
        systemctl restart auditd || service auditd restart || true
    else
        systemctl start auditd || service auditd start || true
    fi
fi

echo "Audit rules for kernel module removal have been configured."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
# Note: 32-bit and 64-bit kernel syscall numbers not always line up =>
#       it's required on a 64-bit system to check also for the presence
#       of 32-bit's equivalent of the corresponding rule.
#       (See `man 7 audit.rules` for details )
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	
	AUID_FILTERS="-F auid>=1000 -F auid!=unse
```


---

## RHEL-08-030360 — `audit_rules_kernel_module_loading_finit`

**Prompt:** On an Ubuntu 24.04 system, the system audit daemon must record every use by ordinary users (those with login UID 1000 or greater) of the kernel facility that loads a module into the running kernel, because surreptitious kernel module loading can be used to inject malicious code and must leave a tamper-evident audit trail. Write an idempotent bash remediation script that adds a persistent audit rule capturing this module-loading activity for both 32-bit and 64-bit invocations as appropriate to the architecture, tagged with an identifying key, so the rule survives reboots and is loaded by the audit daemon at startup.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULES_DIR="/etc/audit/rules.d"
RULES_FILE="${RULES_DIR}/module_load.rules"
KEY="module-load"

mkdir -p "${RULES_DIR}"
touch "${RULES_FILE}"

# Determine architecture to decide whether 32-bit rules are needed
ARCH="$(uname -m)"

# Build the list of required rules
declare -a REQUIRED_RULES=()

case "${ARCH}" in
    x86_64|aarch64|ppc64|ppc64le|s390x|mips64|riscv64)
        # 64-bit systems: capture both b64 and b32
        REQUIRED_RULES+=("-a always,exit -F arch=b64 -S init_module -S finit_module -F auid>=1000 -F auid!=unset -k ${KEY}")
        REQUIRED_RULES+=("-a always,exit -F arch=b32 -S init_module -S finit_module -F auid>=1000 -F auid!=unset -k ${KEY}")
        ;;
    *)
        # 32-bit only systems
        REQUIRED_RULES+=("-a always,exit -F arch=b32 -S init_module -S finit_module -F auid>=1000 -F auid!=unset -k ${KEY}")
        ;;
esac

# Idempotently add each required rule if not already present
for rule in "${REQUIRED_RULES[@]}"; do
    if ! grep -qF -- "${rule}" "${RULES_FILE}" 2>/dev/null; then
        echo "${rule}" >> "${RULES_FILE}"
    fi
done

chmod 0640 "${RULES_FILE}"

# Load the rules so the audit daemon uses them
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v service >/dev/null 2>&1; then
    service auditd restart || true
elif command -v systemctl >/dev/null 2>&1; then
    systemctl restart auditd || true
fi

exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
# Note: 32-bit and 64-bit kernel syscall numbers not always line up =>
#       it's required on a 64-bit system to check also for the presence
#       of 32-bit's equivalent of the corresponding rule.
#       (See `man 7 audit.rules` for details )
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	
	AUID_FILTERS="-F auid>=1000 -F auid!=unse
```


---

## RHEL-08-030360 — `audit_rules_kernel_module_loading_init`

**Prompt:** On an Ubuntu 24.04 system, the system audit daemon must maintain an audit trail of kernel module load events, because loading modules can alter kernel behavior and inject malicious code into kernel space. Write an idempotent bash remediation script that configures audit rules to record every attempt by a non-system user (login UID 1000 or greater) to load a kernel module into the running kernel, tagging these events with an identifier of 'modules'. The configuration must cover all applicable hardware architectures of the host and persist across reboots so the rules are active after the audit system reloads.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULES_FILE="/etc/audit/rules.d/modules.rules"

mkdir -p "$(dirname "$RULES_FILE")"
touch "$RULES_FILE"

# Determine applicable architectures
ARCHES=("b32")
if [ "$(uname -m)" = "x86_64" ] || [ "$(getconf LONG_BIT 2>/dev/null)" = "64" ]; then
    ARCHES+=("b64")
fi

# Build the desired rule lines
declare -a DESIRED_RULES=()
for arch in "${ARCHES[@]}"; do
    DESIRED_RULES+=("-a always,exit -F arch=${arch} -S init_module,finit_module,delete_module -F auid>=1000 -F auid!=unset -k modules")
done

# Remove any existing module-related rules that we manage, then re-add
# First, strip out existing lines that reference the syscalls we manage or the modules key
TMP_FILE="$(mktemp)"
if [ -f "$RULES_FILE" ]; then
    grep -vE '(-S[[:space:]]*(init_module|finit_module|delete_module)|-k[[:space:]]*modules|-F[[:space:]]*key=modules)' "$RULES_FILE" > "$TMP_FILE" || true
else
    : > "$TMP_FILE"
fi

# Append desired rules idempotently
for rule in "${DESIRED_RULES[@]}"; do
    if ! grep -qF -- "$rule" "$TMP_FILE"; then
        echo "$rule" >> "$TMP_FILE"
    fi
done

# Install the updated rules file
install -m 0640 "$TMP_FILE" "$RULES_FILE"
rm -f "$TMP_FILE"

# Reload audit rules so they are active
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "$RULES_FILE" || true
fi

exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
# Note: 32-bit and 64-bit kernel syscall numbers not always line up =>
#       it's required on a 64-bit system to check also for the presence
#       of 32-bit's equivalent of the corresponding rule.
#       (See `man 7 audit.rules` for details )
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	
	AUID_FILTERS="-F auid>=1000 -F auid!=unse
```


---

## RHEL-08-030590 — `audit_rules_login_events_faillock`

**Prompt:** On an Ubuntu 24.04 system, the audit subsystem must be configured to monitor the system files that record failed authentication and login/logout events, so that any manual modification (write or attribute change) to these records is captured under a dedicated audit key labeled "logins" — this helps detect attackers attempting to tamper with or erase evidence of their access. Write an idempotent bash remediation script that adds the appropriate audit watch rules in a way compatible with however the audit daemon loads its rules, and ensure the rules persist and take effect across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: monitor failed authentication and login/logout record files
# with the audit subsystem under the "logins" key.
#
set -euo pipefail

# Files that record login/logout and failed authentication events.
# /var/log/faillog   - failed login attempts
# /var/log/lastlog   - last login records
# /var/log/tallylog  - login failure counts (pam_tally2)
FILES=(
    "/var/log/faillog"
    "/var/log/lastlog"
    "/var/log/tallylog"
)

AUDIT_KEY="logins"
PERM="wa"

# Determine how auditd loads its rules.
RULES_D="/etc/audit/rules.d"
LEGACY_RULES="/etc/audit/audit.rules"

if [ -d "$RULES_D" ]; then
    RULES_FILE="${RULES_D}/logins.rules"
else
    RULES_FILE="$LEGACY_RULES"
fi

# Ensure the rules file exists.
touch "$RULES_FILE"
chmod 0640 "$RULES_FILE"

# Add each watch rule idempotently.
for f in "${FILES[@]}"; do
    RULE="-w ${f} -p ${PERM} -k ${AUDIT_KEY}"

    # Check for an existing rule that watches this file (ignoring perm/key ordering),
    # match on the exact rule line to remain idempotent.
    if ! grep -Eq "^[[:space:]]*-w[[:space:]]+${f}([[:space:]]|$)" "$RULES_FILE"; then
        echo "$RULE" >> "$RULES_FILE"
    else
        # A watch for this file exists; make sure it exactly matches our desired rule.
        # Remove any divergent watch lines for this file and re-add the canonical rule.
        if ! grep -Fxq "$RULE" "$RULES_FILE"; then
            sed -i -E "\#^[[:space:]]*-w[[:space:]]+${f}([[:space:]]|\$)#d" "$RULES_FILE"
            echo "$RULE" >> "$RULES_FILE"
        fi
    fi
done

# Load the new rules so they take effect immediately, then verify persistence.
if command -v augenrules >/dev/null 2>&1 && [ -d "$RULES_D" ]; then
    # augenrules compiles rules.d/*.rules into the active ruleset.
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    for f in "${FILES[@]}"; do
        auditctl -w "$f" -p "$PERM" -k "$AUDIT_KEY" 2>/dev/null || true
    done
fi

# Ensure the audit daemon is enabled and running so rules persist across reboots.
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable auditd 2>/dev/null || true
    if systemctl is-active --quiet auditd; then
        # Reload rules via service to apply persistently.
        systemctl reload auditd 2>/dev/null || augenrules --load 2>/dev/null || true
    else
        systemctl start auditd 2>/dev/null || true
    fi
fi

echo "Audit watch rules for login/failed-authentication records applied under key '${AUDIT_KEY}'."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'


var_accounts_passwords_pam_faillock_dir='
```


---

## RHEL-08-030600 — `audit_rules_login_events_lastlog`

**Prompt:** On an Ubuntu 24.04 system, ensure the system audit daemon records all write and attribute-change attempts to the file that tracks each user's most recent login (the lastlog record), so that tampering meant to hide intrusion evidence is captured. The audit rule must be tagged with the key "logins", apply to write and attribute-change access, work whether the audit daemon loads rules via the augenrules or auditctl mechanism, and persist across reboots. Write an idempotent bash remediation script that establishes this audit rule.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULE="-w /var/log/lastlog -p wa -k logins"

# --- augenrules mechanism (persistent rules dir) ---
AUGEN_FILE="/etc/audit/rules.d/logins.rules"
mkdir -p /etc/audit/rules.d

if [ -f "$AUGEN_FILE" ]; then
    if ! grep -qsE '^\s*-w\s+/var/log/lastlog\s+-p\s+wa\s+-k\s+logins\s*$' "$AUGEN_FILE"; then
        printf '%s\n' "$RULE" >> "$AUGEN_FILE"
    fi
else
    printf '%s\n' "$RULE" > "$AUGEN_FILE"
fi

# Remove any duplicate/variant lines for lastlog outside the canonical form, keep one canonical rule
# (Ensure exactly one canonical line remains)
tmpfile="$(mktemp)"
grep -vE '^\s*-w\s+/var/log/lastlog\s+-p\s+.*-k\s+logins\s*$' "$AUGEN_FILE" > "$tmpfile" || true
printf '%s\n' "$RULE" >> "$tmpfile"
mv "$tmpfile" "$AUGEN_FILE"
chmod 0640 "$AUGEN_FILE"

# --- auditctl mechanism (legacy /etc/audit/audit.rules) ---
AUDITCTL_FILE="/etc/audit/audit.rules"
if [ -f "$AUDITCTL_FILE" ]; then
    if ! grep -qsE '^\s*-w\s+/var/log/lastlog\s+-p\s+wa\s+-k\s+logins\s*$' "$AUDITCTL_FILE"; then
        printf '%s\n' "$RULE" >> "$AUDITCTL_FILE"
    fi
fi

# --- Load the rule into the running kernel if audit is active ---
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    if ! auditctl -l 2>/dev/null | grep -qE '^\s*-w\s+/var/log/lastlog\s+-p\s+wa\s+-k\s+logins\s*$'; then
        auditctl $RULE || true
    fi
fi

exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'


# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -------------------
```


---

## RHEL-08-030580 — `audit_rules_privileged_commands_kmod`

**Prompt:** On an Ubuntu 24.04 system, the system audit daemon must generate an audit record whenever the kernel module management utility (the program used to load, unload, and manage kernel modules) is executed by any regular user (those with a login UID of 1000 or greater), so that misuse of this privileged command can be reconstructed during incident investigations. Write an idempotent bash remediation script that ensures execution of this utility is audited and tagged for privileged-command tracking, with the rule persisting across reboots regardless of whether audit rules are loaded via the rule-compilation program or the direct rule-loading utility at daemon startup.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

# The kernel module management utility on Ubuntu is kmod, accessed via
# /usr/bin/kmod (with insmod, rmmod, modprobe, lsmod, etc. symlinking to it).

RULE='-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=unset -k privileged-modules'

AUGENRULES_DIR="/etc/audit/rules.d"
AUGENRULES_FILE="${AUGENRULES_DIR}/privileged.rules"
AUDITCTL_FILE="/etc/audit/audit.rules"

mkdir -p "${AUGENRULES_DIR}"

# Ensure rule persists for the rule-compilation program (augenrules) via rules.d
touch "${AUGENRULES_FILE}"
if ! grep -Eq -- '-F[[:space:]]+path=/usr/bin/kmod[[:space:]].*-F[[:space:]]+perm=x' "${AUGENRULES_FILE}" 2>/dev/null; then
    echo "${RULE}" >> "${AUGENRULES_FILE}"
fi

# Ensure rule persists for the direct rule-loading utility (auditctl) via audit.rules
touch "${AUDITCTL_FILE}"
if ! grep -Eq -- '-F[[:space:]]+path=/usr/bin/kmod[[:space:]].*-F[[:space:]]+perm=x' "${AUDITCTL_FILE}" 2>/dev/null; then
    echo "${RULE}" >> "${AUDITCTL_FILE}"
fi

# Attempt to load the rule into the running kernel now (non-fatal).
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load >/dev/null 2>&1 || true
elif command -v auditctl >/dev/null 2>&1; then
    auditctl "${RULE}" >/dev/null 2>&1 || true
fi

exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/bin/kmod -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *
```


---

## RHEL-08-030311 — `audit_rules_privileged_commands_postdrop`

**Prompt:** On an Ubuntu 24.04 system, the audit subsystem must record every execution of the privileged postdrop mail-queue helper program by ordinary (non-system) users, so that misuse or privilege-escalation attempts involving this setuid utility can be detected and investigated. Write an idempotent bash remediation script that ensures the system audit daemon persistently logs all executions of the postdrop binary performed by users with login UIDs of 1000 or greater, with the event tagged under a privileged-command identifier, and that the rule survives reboots and audit-rule reloads.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

BINARY="/usr/sbin/postdrop"
RULES_DIR="/etc/audit/rules.d"
RULES_FILE="${RULES_DIR}/privileged.rules"
RULE="-a always,exit -F path=${BINARY} -F perm=x -F auid>=1000 -F auid!=unset -k privileged"

# Ensure the audit package/tools are available
if ! command -v auditctl >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -y
        apt-get install -y auditd audispd-plugins
    fi
fi

# Ensure rules directory exists
mkdir -p "${RULES_DIR}"

# Create the rules file if it does not exist
if [[ ! -f "${RULES_FILE}" ]]; then
    touch "${RULES_FILE}"
    chmod 0640 "${RULES_FILE}"
fi

# Add the rule idempotently (match on the postdrop path regardless of exact formatting)
if ! grep -Eq "^[[:space:]]*-a[[:space:]]+always,exit.*-F[[:space:]]+path=${BINARY}([[:space:]]|$)" "${RULES_FILE}"; then
    printf '%s\n' "${RULE}" >> "${RULES_FILE}"
fi

# Load the rules into the running kernel audit subsystem
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "${RULES_FILE}" || true
fi

# Ensure auditd is enabled and running so rules persist and are active
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable auditd >/dev/null 2>&1 || true
    if systemctl is-active --quiet auditd; then
        systemctl reload auditd 2>/dev/null || systemctl restart auditd 2>/dev/null || true
    else
        systemctl start auditd 2>/dev/null || service auditd start 2>/dev/null || true
    fi
fi

# Verify the rule is loaded in the running configuration
if command -v auditctl >/dev/null 2>&1; then
    if auditctl -l 2>/dev/null | grep -Eq "path=${BINARY}([[:space:]]|$)"; then
        echo "postdrop audit rule is active."
    else
        echo "Warning: postdrop audit rule not currently active in kernel; it will apply on next reload/reboot." >&2
    fi
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/sbin/postdrop -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of au
```


---

## RHEL-08-030312 — `audit_rules_privileged_commands_postqueue`

**Prompt:** On an Ubuntu 24.04 system, configure the system audit daemon to record every execution of the privileged mail-queue management command 'postqueue' by any regular user (those with login UIDs of 1000 or greater) so that misuse of this privileged program can be detected. The audit rule must apply to executions of this command, be associated with an audit key identifying privileged-command use, integrate with the audit daemon's rule-loading mechanism so it is active after a reboot, and be applied idempotently. Write a bash remediation script that achieves this end state.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULE_FILE="/etc/audit/rules.d/privileged.rules"
BIN="/usr/sbin/postqueue"

if [ ! -e "$BIN" ]; then
    CANDIDATE="$(command -v postqueue 2>/dev/null || true)"
    if [ -n "$CANDIDATE" ]; then
        BIN="$CANDIDATE"
    fi
fi

RULE="-a always,exit -F path=${BIN} -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged"

mkdir -p /etc/audit/rules.d

if [ ! -f "$RULE_FILE" ]; then
    touch "$RULE_FILE"
fi

# Remove any existing rule referencing this binary to avoid duplicates
if grep -q "path=${BIN}[[:space:]]" "$RULE_FILE" 2>/dev/null || grep -qE "path=${BIN}\b" "$RULE_FILE" 2>/dev/null; then
    grep -vE "path=${BIN}([[:space:]]|$)" "$RULE_FILE" > "${RULE_FILE}.tmp" || true
    mv "${RULE_FILE}.tmp" "$RULE_FILE"
fi

# Add the rule if not already present exactly
if ! grep -qxF "$RULE" "$RULE_FILE"; then
    echo "$RULE" >> "$RULE_FILE"
fi

# Load the rules into the running audit system
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "$RULE_FILE" || true
fi

if systemctl is-active --quiet auditd 2>/dev/null; then
    systemctl restart auditd 2>/dev/null || service auditd restart 2>/dev/null || true
fi

exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/sbin/postqueue -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of a
```


---

## RHEL-08-030280 — `audit_rules_privileged_commands_ssh_agent`

**Prompt:** On an Ubuntu 24.04 system, the system audit daemon must record every attempt to execute the SSH authentication agent program (the helper that holds decrypted private keys for SSH sessions), so that use of this privileged credential-management tool can be reviewed during incident investigations. Configure auditing to capture all execution attempts of this program by both regular users (those with login UIDs at or above the normal user threshold of 1000) and root, tagging the events with an identifiable key. Write an idempotent bash remediation script that establishes this audit rule so it loads on audit daemon startup and persists across reboots, accounting for whichever rule-loading mechanism the daemon is configured to use.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Configure auditd to record execution attempts of the SSH authentication
# agent program (ssh-agent) by both regular users (auid>=1000) and root
# (auid=0), tagged with an identifiable key.
#

set -euo pipefail

AGENT_BIN="/usr/bin/ssh-agent"
KEY="privileged-ssh"

# Determine the correct architecture rule set.
ARCHES=()
case "$(uname -m)" in
    x86_64|aarch64|ppc64|ppc64le|s390x)
        ARCHES=(b32 b64)
        ;;
    *)
        ARCHES=(b32)
        ;;
esac

# Verify the ssh-agent binary exists; if not, still write the rule but warn.
if [ ! -e "$AGENT_BIN" ]; then
    echo "Warning: $AGENT_BIN not found; installing rule anyway." >&2
fi

# Build the desired rule lines.
declare -a RULES=()
for arch in "${ARCHES[@]}"; do
    RULES+=("-a always,exit -F path=${AGENT_BIN} -F perm=x -F arch=${arch} -F auid>=1000 -F auid!=unset -F key=${KEY}")
    RULES+=("-a always,exit -F path=${AGENT_BIN} -F perm=x -F arch=${arch} -F auid=0 -F key=${KEY}")
done

# Determine which rule-loading mechanism the audit daemon uses.
augenrules_present=0
if [ -x /sbin/augenrules ] || [ -x /usr/sbin/augenrules ] || command -v augenrules >/dev/null 2>&1; then
    augenrules_present=1
fi

USES_AUGENRULES=0
if [ -d /etc/audit/rules.d ] && [ "$augenrules_present" -eq 1 ]; then
    USES_AUGENRULES=1
fi

if [ "$USES_AUGENRULES" -eq 1 ]; then
    TARGET="/etc/audit/rules.d/${KEY}.rules"
else
    TARGET="/etc/audit/audit.rules"
fi

# Ensure the directory exists.
mkdir -p "$(dirname "$TARGET")"
touch "$TARGET"

# Idempotently ensure each desired rule line is present.
add_rule_line() {
    local line="$1"
    local file="$2"
    if ! grep -Fxq "$line" "$file" 2>/dev/null; then
        printf '%s\n' "$line" >> "$file"
    fi
}

for r in "${RULES[@]}"; do
    add_rule_line "$r" "$TARGET"
done

# Set safe permissions on the rules file.
chmod 0640 "$TARGET" 2>/dev/null || true

# Load the rules into the running kernel.
if [ "$USES_AUGENRULES" -eq 1 ]; then
    if command -v augenrules >/dev/null 2>&1; then
        augenrules --load || true
    elif [ -x /sbin/augenrules ]; then
        /sbin/augenrules --load || true
    elif [ -x /usr/sbin/augenrules ]; then
        /usr/sbin/augenrules --load || true
    fi
else
    if command -v auditctl >/dev/null 2>&1; then
        for r in "${RULES[@]}"; do
            # shellcheck disable=SC2086
            auditctl $r 2>/dev/null || true
        done
    fi
fi

echo "Audit rule(s) for ${AGENT_BIN} with key '${KEY}' configured in ${TARGET}."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/bin/ssh-agent -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of au
```


---

## RHEL-08-030320 — `audit_rules_privileged_commands_ssh_keysign`

**Prompt:** On an Ubuntu 24.04 system, the system audit daemon must record every execution of the privileged SSH key-signing helper (the ssh-keysign program shipped with OpenSSH) so that misuse of this set-privilege binary by ordinary users can be detected and investigated. Configure auditing so that any execution of that helper by a non-system user (login UID 1000 or greater, excluding unset login UIDs) is logged and associated with a 'privileged' identifier. Write an idempotent bash remediation script that establishes this audit rule, ensures it is loaded regardless of which rule-loading mechanism auditd uses, and persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: audit execution of ssh-keysign by non-system users (auid>=1000)
# Idempotent: safe to run multiple times.
#

set -u

BIN="/usr/lib/openssh/ssh-keysign"

# Fall back to locating the binary if the default path is absent.
if [ ! -e "$BIN" ]; then
    if command -v ssh-keysign >/dev/null 2>&1; then
        BIN="$(command -v ssh-keysign)"
    else
        FOUND="$(find / -xdev -type f -name 'ssh-keysign' 2>/dev/null | head -n1)"
        if [ -n "$FOUND" ]; then
            BIN="$FOUND"
        fi
    fi
fi

# The canonical audit rule.
RULE="-a always,exit -F path=${BIN} -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged"

# ---------------------------------------------------------------------------
# 1. Persist the rule in a rules file (used by augenrules).
# ---------------------------------------------------------------------------
RULES_DIR="/etc/audit/rules.d"
RULES_FILE="${RULES_DIR}/privileged.rules"

mkdir -p "$RULES_DIR"
touch "$RULES_FILE"

# Remove any stale ssh-keysign privileged lines, then add the correct one.
if grep -Eq "path=.*ssh-keysign" "$RULES_FILE" 2>/dev/null; then
    sed -i "\#path=.*ssh-keysign#d" "$RULES_FILE"
fi
printf '%s\n' "$RULE" >> "$RULES_FILE"
chmod 0640 "$RULES_FILE"

# ---------------------------------------------------------------------------
# 2. Persist the rule in the single audit.rules file (used by auditctl -R).
#    Ubuntu's auditd may load either /etc/audit/audit.rules directly or
#    via augenrules; handle both so the rule is loaded regardless.
# ---------------------------------------------------------------------------
AUDIT_RULES="/etc/audit/audit.rules"
if [ -f "$AUDIT_RULES" ] && [ ! -L "$AUDIT_RULES" ]; then
    if grep -Eq "path=.*ssh-keysign" "$AUDIT_RULES" 2>/dev/null; then
        sed -i "\#path=.*ssh-keysign#d" "$AUDIT_RULES"
    fi
    printf '%s\n' "$RULE" >> "$AUDIT_RULES"
    chmod 0640 "$AUDIT_RULES"
fi

# ---------------------------------------------------------------------------
# 3. Load the rule into the running kernel audit subsystem now.
# ---------------------------------------------------------------------------
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load >/dev/null 2>&1
fi

# Ensure the specific rule is active; add it live if not already present.
if command -v auditctl >/dev/null 2>&1; then
    if ! auditctl -l 2>/dev/null | grep -Eq "path=${BIN}[[:space:]].*(-F auid>=1000|auid>=1000).*(key=privileged|privileged)"; then
        auditctl "$RULE" >/dev/null 2>&1 || \
        auditctl -a always,exit -F path="${BIN}" -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged >/dev/null 2>&1
    fi
fi

exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/libexec/openssh/ssh-keysign -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Creat
```


---

## RHEL-08-030310 — `audit_rules_privileged_commands_unix_update`

**Prompt:** On an Ubuntu 24.04 system, the audit subsystem must record every execution of the privileged 'unix_update' helper program by any non-system user (those with a login UID of 1000 or greater), so that misuse of privileged functionality can be detected and attributed. Configure the system audit daemon so that each invocation of this privileged command is captured as an execution event and tagged for later identification as privileged activity. Write an idempotent bash remediation script that establishes this auditing rule and ensures it persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULE_FILE="/etc/audit/rules.d/privileged.rules"
BINARY="/sbin/unix_update"

# Determine actual path of the binary if present
for candidate in /sbin/unix_update /usr/sbin/unix_update; do
    if [ -e "$candidate" ]; then
        BINARY="$candidate"
        break
    fi
done

RULE="-a always,exit -F path=${BINARY} -F perm=x -F auid>=1000 -F auid!=unset -k privileged"

# Ensure rules directory exists
mkdir -p /etc/audit/rules.d

# Create the rules file if it does not exist
touch "$RULE_FILE"

# Add the rule idempotently
if ! grep -Fxq "$RULE" "$RULE_FILE"; then
    # Remove any stale rules for this binary to avoid duplicates
    if grep -q "path=${BINARY}" "$RULE_FILE" 2>/dev/null; then
        sed -i "\#path=${BINARY}#d" "$RULE_FILE"
    fi
    echo "$RULE" >> "$RULE_FILE"
fi

# Load the rules into the running audit system
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "$RULE_FILE" || true
fi

# Ensure auditd is enabled and running
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable auditd >/dev/null 2>&1 || true
    systemctl restart auditd >/dev/null 2>&1 || service auditd restart >/dev/null 2>&1 || true
fi

exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/sbin/unix_update -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of
```


---

## RHEL-08-030560 — `audit_rules_privileged_commands_usermod`

**Prompt:** On an Ubuntu 24.04 system, the system audit daemon must record every execution of the privileged user-account modification utility (the command used to modify existing user accounts) by any non-system user, so that misuse of this privileged function can be detected and investigated. Configure auditing such that each invocation of this program by users with a login UID of 1000 or greater is logged as an executable-access event tagged with the identifier "privileged". Write an idempotent bash remediation script that establishes this audit rule and ensures it persists across reboots regardless of which rule-loading mechanism auditd uses.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

# The privileged user-account modification utility on Ubuntu
BINARY="/usr/sbin/usermod"

# The audit rule to enforce
RULE="-a always,exit -F path=${BINARY} -F perm=x -F auid>=1000 -F auid!=unset -k privileged"

# Determine the rules directory / file location
AUDIT_RULES_D="/etc/audit/rules.d"
AUDIT_RULES_FILE="${AUDIT_RULES_D}/privileged.rules"
LEGACY_RULES_FILE="/etc/audit/audit.rules"

# Ensure the audit rules.d directory exists
if [ ! -d "${AUDIT_RULES_D}" ]; then
    mkdir -p "${AUDIT_RULES_D}"
fi

# Function to add the rule idempotently to a given file
add_rule_to_file() {
    local file="$1"

    # Create file if it does not exist
    if [ ! -f "${file}" ]; then
        touch "${file}"
    fi

    # Check for an existing matching rule (match on path and privileged key)
    if grep -Eq -- "^[[:space:]]*-a[[:space:]]+always,exit.*-F[[:space:]]+path=${BINARY}([[:space:]]|$).*-F[[:space:]]+perm=x.*auid>=1000.*-k[[:space:]]+privileged" "${file}"; then
        # Rule already present, nothing to do
        return 0
    fi

    # Remove any stale/partial rules referencing this binary to avoid duplicates
    if grep -Eq -- "path=${BINARY}([[:space:]]|$)" "${file}"; then
        sed -i -E "\|path=${BINARY}([[:space:]]\|\$)|d" "${file}"
    fi

    # Append the correct rule
    printf '%s\n' "${RULE}" >> "${file}"
}

# Add rule to the modern rules.d mechanism
add_rule_to_file "${AUDIT_RULES_FILE}"

# Also ensure persistence in the legacy audit.rules if it is used directly
if [ -f "${LEGACY_RULES_FILE}" ]; then
    add_rule_to_file "${LEGACY_RULES_FILE}"
fi

# Load the rules into the running kernel audit system
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "${AUDIT_RULES_FILE}" || auditctl ${RULE} || true
fi

# Restart auditd to make sure the rules are active (using service to respect auditd's restart handling)
if command -v service >/dev/null 2>&1; then
    service auditd restart 2>/dev/null || systemctl restart auditd 2>/dev/null || true
elif command -v systemctl >/dev/null 2>&1; then
    systemctl restart auditd 2>/dev/null || true
fi

exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/sbin/usermod -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of aud
```


---

## RHEL-08-030040 — `auditd_data_disk_error_action`

**Prompt:** On an Ubuntu 24.04 system, configure the system audit daemon so that when it encounters a disk error while writing audit records, it responds by switching the system into single-user mode for corrective action, minimizing the risk of silently losing audit data. Acceptable compliant responses for such errors are limited to switching to single-user mode, halting the system, or notifying via the system logger; your configuration must select the single-user-mode response. Write an idempotent bash remediation script that enforces this behavior and persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

CONF="/etc/audit/auditd.conf"
KEY="disk_error_action"
VALUE="SINGLE"

if [ ! -f "$CONF" ]; then
    mkdir -p "$(dirname "$CONF")"
    touch "$CONF"
fi

if grep -qiE "^\s*${KEY}\s*=" "$CONF"; then
    sed -i -E "s|^\s*${KEY}\s*=.*|${KEY} = ${VALUE}|I" "$CONF"
else
    printf '%s = %s\n' "$KEY" "$VALUE" >> "$CONF"
fi

# Verify
if ! grep -qiE "^\s*${KEY}\s*=\s*${VALUE}\s*$" "$CONF"; then
    echo "Failed to set ${KEY} to ${VALUE} in ${CONF}" >&2
    exit 1
fi

# Reload auditd configuration to persist behavior
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load >/dev/null 2>&1 || true
fi

if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet auditd 2>/dev/null; then
        systemctl kill --signal=HUP auditd 2>/dev/null || \
        service auditd reload 2>/dev/null || true
    fi
elif command -v service >/dev/null 2>&1; then
    service auditd reload 2>/dev/null || true
fi

echo "auditd ${KEY} configured to ${VALUE} in ${CONF}"
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

var_auditd_disk_error_action='
```


---

## RHEL-08-030060 — `auditd_data_disk_full_action`

**Prompt:** On an Ubuntu 24.04 system, configure the system audit daemon so that when the volume holding audit records becomes completely full, the system takes a defined protective action rather than silently losing audit data — specifically, it must switch the system to single-user mode for corrective intervention. Write an idempotent bash remediation script that establishes this disk-full response and ensures it persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

CONF="/etc/audit/auditd.conf"
KEY="disk_full_action"
VALUE="single"

if [ ! -f "$CONF" ]; then
    echo "Error: $CONF not found. Is auditd installed?" >&2
    exit 1
fi

if grep -qiE "^\s*${KEY}\s*=" "$CONF"; then
    sed -i -E "s|^\s*${KEY}\s*=.*|${KEY} = ${VALUE}|I" "$CONF"
else
    printf '%s = %s\n' "$KEY" "$VALUE" >> "$CONF"
fi

# Verify the setting
if ! grep -qiE "^\s*${KEY}\s*=\s*${VALUE}\s*$" "$CONF"; then
    echo "Error: failed to set ${KEY} in $CONF" >&2
    exit 1
fi

# Reload auditd configuration so change persists and takes effect
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load >/dev/null 2>&1 || true
fi

if command -v service >/dev/null 2>&1; then
    service auditd reload >/dev/null 2>&1 || systemctl reload auditd >/dev/null 2>&1 || systemctl restart auditd >/dev/null 2>&1 || true
else
    systemctl reload auditd >/dev/null 2>&1 || systemctl restart auditd >/dev/null 2>&1 || true
fi

echo "Configured ${KEY} = ${VALUE} in ${CONF}"
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

var_auditd_disk_full_action='
```


---

## RHEL-08-030731 — `auditd_data_retention_space_left_action`

**Prompt:** On an Ubuntu 24.04 system, configure the system audit daemon so that when available disk space falls below its low-space warning threshold it notifies administrators by sending an email alert (rather than the default behavior), giving staff a chance to act before audit logging is disrupted. Write an idempotent bash remediation script that sets this low-disk-space response and ensures it persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

AUDITD_CONF="/etc/audit/auditd.conf"

# Ensure the auditd configuration file exists
if [[ ! -f "$AUDITD_CONF" ]]; then
    echo "Error: $AUDITD_CONF not found. Is auditd installed?" >&2
    exit 1
fi

# Set space_left_action to email in an idempotent manner
if grep -Eq '^\s*space_left_action\s*=' "$AUDITD_CONF"; then
    sed -ri 's|^\s*space_left_action\s*=.*|space_left_action = email|' "$AUDITD_CONF"
else
    echo "space_left_action = email" >> "$AUDITD_CONF"
fi

# Verify the change
if ! grep -Eq '^\s*space_left_action\s*=\s*email\s*$' "$AUDITD_CONF"; then
    echo "Error: Failed to set space_left_action = email" >&2
    exit 1
fi

# Reload auditd configuration so the change persists and takes effect
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load >/dev/null 2>&1 || true
fi

if command -v service >/dev/null 2>&1; then
    service auditd reload >/dev/null 2>&1 || systemctl reload auditd >/dev/null 2>&1 || true
else
    systemctl reload auditd >/dev/null 2>&1 || true
fi

echo "space_left_action is set to email in $AUDITD_CONF"
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

var_auditd_space_left_action='
```


---

## RHEL-08-030730 — `auditd_data_retention_space_left_percentage`

**Prompt:** On an Ubuntu 24.04 system, configure the system audit daemon to proactively warn administrators before its log storage runs out of space, so that audit records are not silently lost. Specifically, ensure that when free disk space available to the audit logs falls to 25 percent or below remaining capacity, the daemon triggers its low-space notification action. Write an idempotent bash remediation script that enforces this threshold and persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

CONF="/etc/audit/auditd.conf"

# Ensure auditd is installed / config exists
if [ ! -f "$CONF" ]; then
    echo "auditd configuration file $CONF not found. Is auditd installed?" >&2
    exit 1
fi

# Backup once (idempotent-ish: only if no backup yet for this run pattern)
cp -a "$CONF" "${CONF}.bak.$(date +%Y%m%d%H%M%S)"

# Set space_left_percent to 25
if grep -Eiq '^[[:space:]]*space_left[[:space:]]*=' "$CONF"; then
    # Remove any plain space_left (byte based) lines to avoid conflict/ambiguity
    :
fi

if grep -Eiq '^[[:space:]]*space_left_percent[[:space:]]*=' "$CONF"; then
    sed -ri 's|^[[:space:]]*space_left_percent[[:space:]]*=.*|space_left_percent = 25|I' "$CONF"
else
    printf '%s\n' 'space_left_percent = 25' >> "$CONF"
fi

# Ensure a notification action is configured so the threshold triggers a warning
if grep -Eiq '^[[:space:]]*space_left_action[[:space:]]*=' "$CONF"; then
    sed -ri 's|^[[:space:]]*space_left_action[[:space:]]*=.*|space_left_action = SYSLOG|I' "$CONF"
else
    printf '%s\n' 'space_left_action = SYSLOG' >> "$CONF"
fi

# Restart auditd to apply (auditd cannot be restarted via systemctl on some setups)
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
fi

if command -v service >/dev/null 2>&1; then
    service auditd restart 2>/dev/null || systemctl restart auditd 2>/dev/null || true
else
    systemctl restart auditd 2>/dev/null || true
fi

echo "auditd space_left_percent set to 25 with SYSLOG notification action."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

var_auditd_space_left_percentage='
```


---

## RHEL-08-030062 — `auditd_name_format`

**Prompt:** On an Ubuntu 24.04 system, configure the system audit daemon so that every recorded audit event is tagged with a unique computer node name identifier, ensuring that logs forwarded or aggregated from multiple machines can be reliably distinguished from one another. The node name must be recorded using the fully qualified domain name format. Write an idempotent bash remediation script that enforces this audit logging behavior so it persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

AUDITD_CONF="/etc/audit/auditd.conf"

if [ ! -f "$AUDITD_CONF" ]; then
    echo "Error: $AUDITD_CONF not found. Is auditd installed?" >&2
    exit 1
fi

# Ensure name_format is set to hostname (FQDN)
if grep -qiE '^\s*name_format\s*=' "$AUDITD_CONF"; then
    sed -i -E 's/^\s*name_format\s*=.*/name_format = hostname/I' "$AUDITD_CONF"
else
    printf '\nname_format = hostname\n' >> "$AUDITD_CONF"
fi

# Determine the fully qualified domain name
FQDN="$(hostname -f 2>/dev/null || true)"
if [ -z "$FQDN" ]; then
    FQDN="$(hostname 2>/dev/null || true)"
fi

# Ensure name is set to the FQDN
if grep -qiE '^\s*name\s*=' "$AUDITD_CONF"; then
    sed -i -E "s/^\s*name\s*=.*/name = ${FQDN}/I" "$AUDITD_CONF"
else
    printf 'name = %s\n' "$FQDN" >> "$AUDITD_CONF"
fi

# Reload/restart auditd to apply changes persistently
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load >/dev/null 2>&1 || true
fi

if command -v service >/dev/null 2>&1; then
    service auditd restart >/dev/null 2>&1 || systemctl restart auditd >/dev/null 2>&1 || true
else
    systemctl restart auditd >/dev/null 2>&1 || true
fi

# Verify configuration
echo "Current auditd node name configuration:"
grep -iE '^\s*name(_format)?\s*=' "$AUDITD_CONF"
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

var_auditd_name_format='
```


---

## RHEL-08-030610 — `file_permissions_etc_audit_rulesd`

**Prompt:** On an Ubuntu 24.04 system, the rule files that define which events the system audit daemon records must be protected from unauthorized reading or modification, since loose permissions could let unprivileged users discover or tamper with audit coverage and hide malicious activity. Ensure that every audit rule definition file used by the audit subsystem permits access only to its owner (read and write, with no permissions for group or others, i.e. mode 0600). Write an idempotent bash remediation script that brings these files into compliance.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

for dir in /etc/audit /etc/audit/rules.d; do
    [ -d "$dir" ] || continue
    while IFS= read -r -d '' file; do
        chmod 0600 "$file"
    done < <(find "$dir" -maxdepth 1 -type f -name '*.rules' -print0)
done
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

find -L /etc/audit/rules.d/ -maxdepth 1 -perm /u+xs,g+xwrs,o+xwrt  -type f -regextype posix-extended -regex '^.*rules$' -exec chmod u-xs,g-xwrs,o-xwrt {} \;

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
```
