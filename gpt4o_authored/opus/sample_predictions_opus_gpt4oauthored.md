# Inference predictions — `claude-opus-4-8`

215 rules.


---

## RHEL-08-010359 — `package_aide_installed`

**Prompt:** On a RHEL 8 system, ensure that the AIDE (Advanced Intrusion Detection Environment) tool is installed, which is necessary to perform file integrity monitoring and detect unauthorized changes to system files. Write an idempotent bash remediation script that verifies AIDE is installed and available for use.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation script to ensure AIDE (Advanced Intrusion Detection Environment)
# is installed on a RHEL 8 system for file integrity monitoring.
#
# This script is idempotent: it only installs AIDE if it is not already present.

set -o errexit
set -o nounset
set -o pipefail

PACKAGE_NAME="aide"

# Ensure the script is run as root
if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

# Determine which package manager is available
if command -v dnf >/dev/null 2>&1; then
    PKG_MGR="dnf"
elif command -v yum >/dev/null 2>&1; then
    PKG_MGR="yum"
else
    echo "ERROR: Neither dnf nor yum package manager found." >&2
    exit 1
fi

# Check if AIDE is already installed
if rpm -q "${PACKAGE_NAME}" >/dev/null 2>&1; then
    echo "AIDE is already installed. No action required."
else
    echo "AIDE is not installed. Installing ${PACKAGE_NAME}..."
    "${PKG_MGR}" install -y "${PACKAGE_NAME}"
fi

# Verify installation succeeded
if rpm -q "${PACKAGE_NAME}" >/dev/null 2>&1; then
    echo "Verification successful: AIDE is installed."
else
    echo "ERROR: AIDE installation could not be verified." >&2
    exit 1
fi

# Verify the aide binary is available for use
if command -v aide >/dev/null 2>&1; then
    echo "AIDE binary is available at: $(command -v aide)"
else
    echo "ERROR: AIDE package is installed but the aide binary is not available." >&2
    exit 1
fi

echo "AIDE is installed and ready for use."
exit 0
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

**Prompt:** On a RHEL 8 system, ensure the AIDE file integrity tool has been properly setup with an initial database of known-good file states, which is essential for its operation in monitoring unintended changes to files. Write an idempotent bash remediation script that initializes the AIDE database and installs it, ensuring that the database reflects the current file states accurately. Then, perform a verification test to confirm that AIDE is functioning correctly with this new database. Ensure that future checks against the database can identify unauthorized modifications effectively.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# AIDE file integrity tool setup and verification for RHEL 8
# Idempotent remediation script.
#
set -u

AIDE_BIN="/usr/sbin/aide"
AIDE_CONF="/etc/aide.conf"
AIDE_DB_NEW="/var/lib/aide/aide.db.new.gz"
AIDE_DB="/var/lib/aide/aide.db.gz"

log() {
    printf '%s %s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$*"
}

fail() {
    log "ERROR: $*"
    exit 1
}

# Must run as root
if [ "$(id -u)" -ne 0 ]; then
    fail "This script must be run as root."
fi

# 1. Ensure AIDE package is installed
if ! rpm -q aide >/dev/null 2>&1; then
    log "AIDE package not found. Installing..."
    if command -v dnf >/dev/null 2>&1; then
        dnf -y install aide || fail "Failed to install aide via dnf."
    elif command -v yum >/dev/null 2>&1; then
        yum -y install aide || fail "Failed to install aide via yum."
    else
        fail "No supported package manager (dnf/yum) found."
    fi
else
    log "AIDE package already installed."
fi

# Verify aide binary exists
if [ ! -x "$AIDE_BIN" ]; then
    # Fall back to PATH lookup
    if command -v aide >/dev/null 2>&1; then
        AIDE_BIN="$(command -v aide)"
    else
        fail "AIDE binary not found after installation."
    fi
fi

# Verify configuration file exists
if [ ! -f "$AIDE_CONF" ]; then
    fail "AIDE configuration file $AIDE_CONF not found."
fi

# Ensure the database directory exists
DB_DIR="$(dirname "$AIDE_DB")"
if [ ! -d "$DB_DIR" ]; then
    mkdir -p "$DB_DIR" || fail "Failed to create $DB_DIR."
fi

# 2. Initialize the AIDE database if a valid installed database is not present.
#    This is idempotent: only (re)initialize when the installed DB is missing
#    or empty/invalid.
need_init=0
if [ ! -s "$AIDE_DB" ]; then
    need_init=1
    log "No valid installed AIDE database found; initialization required."
else
    log "Existing installed AIDE database found at $AIDE_DB."
fi

if [ "$need_init" -eq 1 ]; then
    log "Initializing AIDE database (this may take a while)..."
    "$AIDE_BIN" --init --config="$AIDE_CONF"
    rc=$?
    # aide --init returns non-zero in some builds even on success; verify the file.
    if [ ! -s "$AIDE_DB_NEW" ]; then
        fail "AIDE database initialization failed (rc=$rc); $AIDE_DB_NEW not created."
    fi
    log "AIDE database initialized successfully."

    # 3. Install the newly generated database as the active database.
    cp -f "$AIDE_DB_NEW" "$AIDE_DB" || fail "Failed to install new AIDE database."
    log "New AIDE database installed to $AIDE_DB."

    # Set restrictive permissions on databases.
    chmod 0600 "$AIDE_DB" 2>/dev/null || true
    chmod 0600 "$AIDE_DB_NEW" 2>/dev/null || true
else
    log "Skipping initialization; database already present and non-empty."
fi

# Final sanity check that the active database exists and is non-empty.
if [ ! -s "$AIDE_DB" ]; then
    fail "Active AIDE database $AIDE_DB is missing or empty after setup."
fi

# 4. Verification test: run a check against the installed database.
#    A freshly-installed database should report no changes (rc=0).
log "Running AIDE verification check against the installed database..."
CHECK_OUTPUT="$("$AIDE_BIN" --check --config="$AIDE_CONF" 2>&1)"
CHECK_RC=$?

printf '%s\n' "$CHECK_OUTPUT"

# AIDE exit codes:
#   0        = no differences detected
#   1,2,4    = new/removed/changed entries detected (bitwise)
#   >=14     = configuration/runtime errors
if [ "$CHECK_RC" -eq 0 ]; then
    log "Verification successful: AIDE reports no differences. Integrity monitoring is operational."
elif [ "$CHECK_RC" -ge 1 ] && [ "$CHECK_RC" -le 7 ]; then
    log "Verification completed: AIDE detected differences (rc=$CHECK_RC)."
    log "This is expected if files changed after initialization; the database is functional."
else
    fail "AIDE verification check encountered an error (rc=$CHECK_RC)."
fi

log "AIDE setup and verification complete."
exit 0
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

**Prompt:** On a RHEL 8 system, the AIDE (Advanced Intrusion Detection Environment) file-integrity tool must be configured to include the verification of all audit-related tools and scripts to ensure they have not been tampered with. This includes vendor-provided, open-source, and any custom scripts related to auditing system activity. Write an idempotent bash remediation script that adds the necessary configuration entries to AIDE so it routinely checks the integrity of all audit tools using cryptographic methods such as checksums. Ensure the configuration is sustainable across AIDE database updates.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure AIDE verifies the integrity of all audit tools using
# cryptographic checksums so tampering can be detected.
#
# This script is idempotent: it only adds missing entries and leaves
# existing correct configuration untouched.

set -euo pipefail

AIDE_CONF="/etc/aide.conf"

# Cryptographic + metadata rule set applied to each audit tool.
# p+i+n+u+g+s+b+acl+xattrs+sha512 provides checksum-based (sha512)
# integrity verification plus ownership/permission monitoring.
RULE="p+i+n+u+g+s+b+acl+xattrs+sha512"

# List of audit tools/scripts that must be monitored.
AUDIT_TOOLS=(
    "/usr/sbin/auditctl"
    "/usr/sbin/auditd"
    "/usr/sbin/ausearch"
    "/usr/sbin/aureport"
    "/usr/sbin/autrace"
    "/usr/sbin/augenrules"
    "/usr/sbin/audispd"
    "/usr/sbin/rsyslogd"
)

# Ensure AIDE is installed.
if ! command -v aide >/dev/null 2>&1; then
    if command -v dnf >/dev/null 2>&1; then
        dnf install -y aide
    elif command -v yum >/dev/null 2>&1; then
        yum install -y aide
    else
        echo "ERROR: Unable to install AIDE (no dnf/yum found)." >&2
        exit 1
    fi
fi

# Ensure the AIDE configuration file exists.
if [[ ! -f "$AIDE_CONF" ]]; then
    echo "ERROR: $AIDE_CONF not found." >&2
    exit 1
fi

# Backup once (idempotent: don't clobber an existing backup).
if [[ ! -f "${AIDE_CONF}.orig" ]]; then
    cp -a "$AIDE_CONF" "${AIDE_CONF}.orig"
fi

MARKER_BEGIN="# BEGIN audit tools integrity monitoring (managed)"
MARKER_END="# END audit tools integrity monitoring (managed)"

# Remove any previously managed block so we can rewrite it cleanly.
if grep -qF "$MARKER_BEGIN" "$AIDE_CONF"; then
    sed -i "/^${MARKER_BEGIN}\$/,/^${MARKER_END}\$/d" "$AIDE_CONF"
fi

# Build the managed block, only including tools that exist on the system.
{
    echo ""
    echo "$MARKER_BEGIN"
    for tool in "${AUDIT_TOOLS[@]}"; do
        if [[ -e "$tool" ]]; then
            echo "${tool} ${RULE}"
        fi
    done
    echo "$MARKER_END"
} >> "$AIDE_CONF"

# Validate the configuration syntax if supported.
if aide --config="$AIDE_CONF" --config-check >/dev/null 2>&1; then
    :
fi

# Initialize / update the AIDE database so the new rules are baselined.
if command -v aide >/dev/null 2>&1; then
    aide --init --config="$AIDE_CONF" >/dev/null 2>&1 || true
    NEW_DB="/var/lib/aide/aide.db.new.gz"
    ACTIVE_DB="/var/lib/aide/aide.db.gz"
    if [[ -f "$NEW_DB" ]]; then
        mv -f "$NEW_DB" "$ACTIVE_DB"
    fi
fi

echo "AIDE audit tool integrity monitoring configured successfully."
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

**Prompt:** On a RHEL 8 system, ensure that the AIDE file-integrity tool automatically sends a notification email to designated security personnel whenever it completes a scan. This helps detect and alert on unauthorized changes to system configurations. Write an idempotent bash remediation script that configures AIDE to send the scan details to an appropriate email address after each automated run. The solution must ensure notifications occur regardless of the current method used to schedule AIDE scans, and email should be sent to `root@localhost`.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure AIDE emails scan results to security personnel (root@localhost)
# after each automated run, regardless of scheduling method (cron or systemd timer).
#
set -u

EMAIL_ADDRESS="root@localhost"

########################################
# Helper: ensure AIDE package installed
########################################
if ! rpm -q aide >/dev/null 2>&1; then
    if command -v yum >/dev/null 2>&1; then
        yum install -y aide
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y aide
    fi
fi

########################################
# 1. Handle cron-based scheduling
########################################
# Look for existing AIDE cron entries and ensure they pipe output to mail.
# We search common cron locations for lines invoking aide --check (or /usr/sbin/aide --check).

CRON_LOCATIONS=(
    "/etc/crontab"
    "/var/spool/cron/root"
)

# Include drop-in cron directories
for d in /etc/cron.d; do
    if [ -d "$d" ]; then
        while IFS= read -r -d '' f; do
            CRON_LOCATIONS+=("$f")
        done < <(find "$d" -type f -print0 2>/dev/null)
    fi
done

# Also check per-user crontabs directory
if [ -d /var/spool/cron ]; then
    while IFS= read -r -d '' f; do
        CRON_LOCATIONS+=("$f")
    done < <(find /var/spool/cron -type f -print0 2>/dev/null)
fi

found_cron=0

for cronfile in "${CRON_LOCATIONS[@]}"; do
    [ -f "$cronfile" ] || continue
    # Does this file reference an aide --check invocation?
    if grep -Eq '(^|[^#[:alnum:]_/])(/usr/sbin/)?aide[[:space:]]+(--check|-C)' "$cronfile" 2>/dev/null; then
        found_cron=1
        # For each aide --check line that does NOT already pipe to mail with our address,
        # append a mail pipe. Idempotent: skip lines already containing our email.
        tmpfile="$(mktemp)"
        while IFS= read -r line || [ -n "$line" ]; do
            if echo "$line" | grep -Eq '(^|[^#[:alnum:]_/])(/usr/sbin/)?aide[[:space:]]+(--check|-C)'; then
                if echo "$line" | grep -q "$EMAIL_ADDRESS"; then
                    # Already sends to our address
                    printf '%s\n' "$line" >> "$tmpfile"
                else
                    # Strip any existing trailing mail pipe, then append correct one
                    newline="$(echo "$line" | sed -E 's/[[:space:]]*\|[[:space:]]*(\/bin\/|\/usr\/bin\/)?mail(x)?[[:space:]].*$//')"
                    printf '%s | /bin/mail -s "$(hostname) - AIDE Integrity Check" %s\n' "$newline" "$EMAIL_ADDRESS" >> "$tmpfile"
                fi
            else
                printf '%s\n' "$line" >> "$tmpfile"
            fi
        done < "$cronfile"
        # Preserve permissions
        cat "$tmpfile" > "$cronfile"
        rm -f "$tmpfile"
    fi
done

########################################
# 2. Handle systemd timer-based scheduling (RHEL 8 default aidecheck.service)
########################################
AIDECHECK_SERVICE="/etc/systemd/system/aidecheck.service"
AIDECHECK_TIMER="/etc/systemd/system/aidecheck.timer"

# Only create/manage a systemd unit if no cron entry was found OR if a timer already exists,
# ensuring notifications occur regardless of the scheduling method in use.
timer_exists=0
if systemctl list-unit-files 2>/dev/null | grep -q '^aidecheck.timer' || [ -f "$AIDECHECK_TIMER" ]; then
    timer_exists=1
fi

if [ "$found_cron" -eq 0 ] || [ "$timer_exists" -eq 1 ]; then
    # Create the aidecheck.service to run aide and email the results
    cat > "$AIDECHECK_SERVICE" <<'EOF'
[Unit]
Description=Aide Check

[Service]
Type=simple
ExecStart=/usr/sbin/aide --check | /bin/mail -s "$(hostname) - AIDE Integrity Check" root@localhost
EOF

    # ExecStart cannot use a shell pipe directly; wrap in /bin/sh -c
    cat > "$AIDECHECK_SERVICE" <<EOF
[Unit]
Description=Aide Check

[Service]
Type=simple
ExecStart=/bin/sh -c "/usr/sbin/aide --check | /bin/mail -s \"\$(hostname) - AIDE Integrity Check\" ${EMAIL_ADDRESS}"

[Install]
WantedBy=multi-user.target
EOF

    # Create the aidecheck.timer if it doesn't already exist
    if [ ! -f "$AIDECHECK_TIMER" ]; then
        cat > "$AIDECHECK_TIMER" <<'EOF'
[Unit]
Description=Aide check every day at 5AM

[Timer]
OnCalendar=*-*-* 05:00:00
Unit=aidecheck.service

[Install]
WantedBy=multi-user.target
EOF
    fi

    chmod 0644 "$AIDECHECK_SERVICE" "$AIDECHECK_TIMER"

    systemctl daemon-reload
    systemctl enable aidecheck.timer >/dev/null 2>&1
    systemctl --now enable aidecheck.timer >/dev/null 2>&1
fi

echo "AIDE notification remediation complete. Scan results will be emailed to ${EMAIL_ADDRESS}."
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

**Prompt:** On a RHEL 8 system using the AIDE file-integrity tool, the rulesets currently do not verify Access Control Lists (ACLs), which increases the risk of unnoticed illicit privilege assignments. Write an idempotent bash remediation script that configures AIDE to include ACLs in its file integrity checks across all applicable rulesets, ensuring any discrepancies in ACLs are detected during integrity verification. The configuration must persist across AIDE runs.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure AIDE rulesets verify Access Control Lists (ACLs)
# Idempotent script for RHEL 8
#

set -o nounset
set -o pipefail

AIDE_CONF="/etc/aide.conf"

# Ensure the AIDE configuration file exists
if [[ ! -f "${AIDE_CONF}" ]]; then
    echo "ERROR: AIDE configuration file '${AIDE_CONF}' not found. Is aide installed?" >&2
    exit 1
fi

# Backup the configuration once (timestamped)
backup_file="${AIDE_CONF}.bak.$(date +%Y%m%d%H%M%S)"
cp -a "${AIDE_CONF}" "${backup_file}"
echo "Backup of AIDE configuration created at: ${backup_file}"

# Process each active ruleset definition line and ensure 'acl' is present.
# Ruleset definition lines look like:  NAME = p+i+n+u+g+s+...
# We only touch lines that:
#   - are not comments (do not start with #)
#   - contain an '=' assignment
#   - contain '+' separated attribute groups (typical ruleset definitions)
#
# We append '+acl' to the attribute list if 'acl' is not already present.

tmp_file="$(mktemp)"
changed=0

while IFS= read -r line; do
    # Preserve blank lines and comments unchanged
    if [[ -z "${line}" || "${line}" =~ ^[[:space:]]*# ]]; then
        printf '%s\n' "${line}" >> "${tmp_file}"
        continue
    fi

    # Match ruleset definition lines: <NAME> = <attr>+<attr>+...
    if [[ "${line}" =~ ^([[:space:]]*[A-Za-z0-9_]+[[:space:]]*)=([[:space:]]*)(.+)$ ]]; then
        lhs="${BASH_REMATCH[1]}"
        eqspace="${BASH_REMATCH[2]}"
        rhs="${BASH_REMATCH[3]}"

        # Only treat as a ruleset if the value contains attribute groups joined by '+'
        if [[ "${rhs}" == *+* ]]; then
            # Strip trailing whitespace / comments from rhs for evaluation
            rhs_trimmed="${rhs%%#*}"
            rhs_trimmed="${rhs_trimmed%"${rhs_trimmed##*[![:space:]]}"}"

            # Check if 'acl' is already a token in the attribute list
            if [[ "+${rhs_trimmed}+" == *"+acl+"* ]]; then
                printf '%s\n' "${line}" >> "${tmp_file}"
            else
                new_line="${lhs}=${eqspace}${rhs_trimmed}+acl"
                printf '%s\n' "${new_line}" >> "${tmp_file}"
                changed=1
                echo "Added 'acl' to ruleset: ${lhs}=${eqspace}${rhs_trimmed}"
            fi
        else
            printf '%s\n' "${line}" >> "${tmp_file}"
        fi
    else
        printf '%s\n' "${line}" >> "${tmp_file}"
    fi
done < "${AIDE_CONF}"

if [[ "${changed}" -eq 1 ]]; then
    # Preserve original ownership/permissions
    cat "${tmp_file}" > "${AIDE_CONF}"
    echo "AIDE configuration updated to include ACL checking."
else
    echo "AIDE configuration already includes ACL checking in all rulesets. No changes made."
    # Remove the unnecessary backup we just took to keep things clean
    rm -f "${backup_file}"
fi

rm -f "${tmp_file}"

exit 0
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

**Prompt:** On a RHEL 8 system, ensure that the AIDE file-integrity tool is configured to verify extended attributes (xattrs) for all rule sets defined in its main configuration file. Extended attributes can contain sensitive metadata that may be overlooked without proper checking. Write an idempotent bash remediation script that configures AIDE to include verification of extended attributes for every rule set within its configuration file, ensuring ongoing integrity checks include this important file attribute.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

AIDE_CONF="/etc/aide.conf"

if [ ! -f "$AIDE_CONF" ]; then
    echo "AIDE configuration file $AIDE_CONF not found. Is AIDE installed?" >&2
    exit 1
fi

# Add 'xattrs' to every AIDE rule set definition that does not already include it.
# A rule set definition line looks like:
#   RuleName = p+i+n+u+g+s+...
# We only touch lines that define a rule set (i.e. contain '=' and are not
# directory/file selection lines starting with '/', '!', '=', or macros '@@').

tmpfile="$(mktemp)"
trap 'rm -f "$tmpfile"' EXIT

while IFS= read -r line || [ -n "$line" ]; do
    # Strip leading whitespace for detection
    trimmed="${line#"${line%%[![:space:]]*}"}"

    # Skip comments, blank lines, macros, and file/dir selection lines
    if [[ -z "$trimmed" ]] \
       || [[ "$trimmed" == \#* ]] \
       || [[ "$trimmed" == @@* ]] \
       || [[ "$trimmed" == /* ]] \
       || [[ "$trimmed" == \!* ]] \
       || [[ "$trimmed" == =* ]]; then
        printf '%s\n' "$line" >> "$tmpfile"
        continue
    fi

    # Must be a rule definition: NAME = value
    if [[ "$trimmed" =~ ^[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=[[:space:]]* ]]; then
        # Split into key and value on the first '='
        key="${line%%=*}"
        value="${line#*=}"

        # Check if xattrs already present as a whole token in the value
        if [[ "$value" =~ (^|[^A-Za-z])xattrs($|[^A-Za-z]) ]]; then
            printf '%s\n' "$line" >> "$tmpfile"
        else
            # Trim trailing whitespace from value for clean append
            value_trimmed="${value%"${value##*[![:space:]]}"}"
            printf '%s=%s+xattrs\n' "$key" "$value_trimmed" >> "$tmpfile"
        fi
    else
        printf '%s\n' "$line" >> "$tmpfile"
    fi
done < "$AIDE_CONF"

# Only replace if changes were made
if ! cmp -s "$tmpfile" "$AIDE_CONF"; then
    cp -a "$AIDE_CONF" "${AIDE_CONF}.bak.$(date +%Y%m%d%H%M%S)"
    cat "$tmpfile" > "$AIDE_CONF"
    echo "AIDE configuration updated to include xattrs in all rule sets."
else
    echo "AIDE configuration already includes xattrs in all rule sets. No changes made."
fi
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

**Prompt:** On a RHEL 8 system, ensure that the Federal Information Processing Standards (FIPS) mode is enabled at installation time to guarantee compliance with federal cryptographic standards, which require the use of validated cryptographic algorithms only. Write a script or outline the installation-time procedure that ensures the operating system's kernel is initialized with FIPS mode enabled, acknowledging that enabling FIPS mode on existing installations isn't supported.

**Model-generated script:**
```bash
```bash
#!/usr/bin/env bash
#
# fips-install.sh
#
# Purpose:
#   Ensure that RHEL 8 is installed with FIPS mode enabled at installation
#   time. Per Red Hat guidance, FIPS mode MUST be enabled during the OS
#   installation; enabling it on an already-installed system is not supported
#   for compliance because the initial cryptographic keys/material may have
#   been generated with non-approved algorithms.
#
# This script performs two roles:
#   1. When run WITHOUT a live/installed target (default): it emits the
#      Kickstart directives and boot parameters needed to install RHEL 8 with
#      FIPS enabled, so they can be embedded in your installation workflow.
#   2. When run on a freshly installed system (post-install %post or first
#      boot verification): it validates that FIPS was actually enabled at
#      install time and reports compliance status.
#
set -euo pipefail

PROG="$(basename "$0")"

usage() {
    cat <<EOF
Usage: ${PROG} [--emit-kickstart] [--emit-boot-args] [--verify] [--help]

  --emit-kickstart   Print a Kickstart snippet that enables FIPS at install.
  --emit-boot-args   Print the kernel boot arguments required at install time.
  --verify           Verify (on an installed system) that FIPS mode is active.
  --help             Show this help.

If no option is given, all three sections are produced/attempted in order.
EOF
}

emit_kickstart() {
    cat <<'KS'
###############################################################################
# Kickstart snippet: enable FIPS mode at INSTALLATION time
#
# Place the following line in the top-level command section of your Kickstart
# file. This instructs Anaconda to install the system in FIPS mode so that the
# kernel is initialized with fips=1 and validated cryptography is used from the
# very first boot.
###############################################################################

# Enable FIPS mode during installation
fips --enabled

# Recommended companion settings for compliant installs:
#   - Use a separate /boot partition (required so the kernel can find its
#     integrity-checked modules early in boot).
#   - Choose an approved partitioning/encryption scheme if disk encryption is
#     needed (LUKS with approved ciphers).
#
# Example partition layout (adjust to your environment):
# part /boot --fstype=xfs --size=1024
# part pv.01 --size=1 --grow
# volgroup vg00 pv.01
# logvol / --fstype=xfs --name=root --vgname=vg00 --size=1 --grow

%post --interpreter=/bin/bash --log=/root/ks-post-fips.log
# Post-install verification that FIPS was enabled by the installer.
if [ -f /proc/sys/crypto/fips_enabled ] && \
   [ "$(cat /proc/sys/crypto/fips_enabled)" = "1" ]; then
    echo "FIPS mode successfully enabled during installation."
else
    echo "WARNING: FIPS mode is NOT enabled. This installation is NOT compliant."
fi
%end
KS
}

emit_boot_args() {
    cat <<'BOOT'
###############################################################################
# Manual (non-Kickstart) installation: kernel boot arguments
#
# If you are performing an interactive installation, append the following
# argument to the installer kernel command line (edit the boot entry, e.g.
# by pressing 'e' at the GRUB/ISOLINUX menu) BEFORE starting the install:
###############################################################################

fips=1

# Notes:
#   * This ensures Anaconda runs and installs the system in FIPS mode.
#   * If /boot is on a separate partition, the installed system's boot loader
#     will also receive:  fips=1 boot=UUID=<uuid-of-/boot>
#   * Enabling FIPS after installation (fips-mode-setup --enable on a running
#     system) is NOT a supported path for guaranteed compliance and is
#     therefore intentionally not performed by this script.
BOOT
}

verify_fips() {
    echo "=== Verifying FIPS mode on this system ==="

    local rc=0

    # 1. Kernel-level flag exposed via procfs.
    if [ -r /proc/sys/crypto/fips_enabled ]; then
        local kflag
        kflag="$(cat /proc/sys/crypto/fips_enabled)"
        if [ "${kflag}" = "1" ]; then
            echo "[PASS] Kernel FIPS flag (/proc/sys/crypto/fips_enabled) = 1"
        else
            echo "[FAIL] Kernel FIPS flag (/proc/sys/crypto/fips_enabled) = ${kflag}"
            rc=1
        fi
    else
        echo "[FAIL] /proc/sys/crypto/fips_enabled not available."
        rc=1
    fi

    # 2. RHEL 8 crypto policy / mode reporting tool.
    if command -v fips-mode-setup >/dev/null 2>&1; then
        if fips-mode-setup --check >/tmp/fips_check.$$ 2>&1; then
            if grep -qi "FIPS mode is enabled" /tmp/fips_check.$$; then
                echo "[PASS] fips-mode-setup --check reports FIPS mode enabled."
            else
                echo "[FAIL] fips-mode-setup --check does not confirm FIPS enabled:"
                sed 's/^/        /' /tmp/fips_check.$$
                rc=1
            fi
        else
            echo "[WARN] fips-mode-setup --check returned non-zero exit status:"
            sed 's/^/        /' /tmp/fips_check.$$
            rc=1
        fi
        rm -f /tmp/fips_check.$$
    else
        echo "[WARN] fips-mode-setup not found; relying on kernel flag only."
    fi

    # 3. Kernel command line should have carried fips=1 from install time.
    if [ -r /proc/cmdline ]; then
        if grep -qw "fips=1" /proc/cmdline; then
            echo "[PASS] Kernel command line contains fips=1."
        else
            echo "[WARN] fips=1 not present on kernel command line."
        fi
    fi

    echo
    if [ "${rc}" -eq 0 ]; then
        echo "RESULT: System is running in FIPS mode. Compliant."
    else
        echo "RESULT: System is NOT in a verified FIPS mode."
        echo "        Remediation: REINSTALL RHEL 8 with fips=1 / 'fips --enabled'."
        echo "        Enabling FIPS on an existing install is not supported for compliance."
    fi
    return "${rc}"
}

main() {
    local do_ks=0 do_boot=0 do_verify=0 any=0

    if [ "$#" -eq 0 ]; then
        do_ks=1; do_boot=1; do_verify=1; any=1
    fi

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --emit-kickstart) do_ks=1; any=1 ;;
            --emit-boot-args) do_boot=1; any=1 ;;
            --verify)         do_verify=1; any=1 ;;
            --help|-h
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

**Prompt:** On a RHEL 8 system, establish a system-wide cryptographic policy that enforces the use of a specified set of secure ciphers for all applications and system components to ensure consistent security standards and mitigate the risks associated with weak encryption algorithms. Write an idempotent bash remediation script that sets the cryptographic policy so that only the approved ciphers within the selected policy are used. The configuration should be persistent and align with the established system cryptography policy framework.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation script: Enforce a system-wide cryptographic policy on RHEL 8.
#
# This script configures the crypto-policies framework so that only the
# approved ciphers within the selected policy are used across all
# applications and system components. It is idempotent and persistent.
#

set -o errexit
set -o nounset
set -o pipefail

# The desired system-wide cryptographic policy.
# FUTURE provides a stronger, forward-looking set of secure ciphers.
DESIRED_POLICY="FUTURE"

CONFIG_FILE="/etc/crypto-policies/config"
UPDATE_CMD="/usr/bin/update-crypto-policies"

# Ensure the crypto-policies tooling is available.
if [ ! -x "${UPDATE_CMD}" ]; then
    echo "ERROR: ${UPDATE_CMD} not found. Installing crypto-policies-scripts..."
    if command -v yum >/dev/null 2>&1; then
        yum -y install crypto-policies-scripts
    elif command -v dnf >/dev/null 2>&1; then
        dnf -y install crypto-policies-scripts
    else
        echo "ERROR: No supported package manager found to install crypto-policies." >&2
        exit 1
    fi
fi

if [ ! -x "${UPDATE_CMD}" ]; then
    echo "ERROR: ${UPDATE_CMD} is still unavailable after attempted install." >&2
    exit 1
fi

# Determine the currently active policy (strip any sub-policy modifiers).
CURRENT_POLICY="$(${UPDATE_CMD} --show 2>/dev/null || true)"
CURRENT_BASE="${CURRENT_POLICY%%:*}"

# Determine the policy recorded in the config file (if any).
FILE_POLICY=""
if [ -f "${CONFIG_FILE}" ]; then
    FILE_POLICY="$(grep -vE '^\s*(#|$)' "${CONFIG_FILE}" 2>/dev/null | head -n1 | tr -d '[:space:]')"
fi

NEED_UPDATE=0

if [ "${CURRENT_BASE}" != "${DESIRED_POLICY}" ]; then
    echo "Active crypto policy is '${CURRENT_POLICY:-none}'; expected '${DESIRED_POLICY}'."
    NEED_UPDATE=1
fi

if [ "${FILE_POLICY}" != "${DESIRED_POLICY}" ]; then
    echo "Configured crypto policy in ${CONFIG_FILE} is '${FILE_POLICY:-none}'; expected '${DESIRED_POLICY}'."
    NEED_UPDATE=1
fi

if [ "${NEED_UPDATE}" -eq 0 ]; then
    echo "System-wide cryptographic policy is already set to '${DESIRED_POLICY}'. No changes required."
    exit 0
fi

echo "Applying system-wide cryptographic policy: ${DESIRED_POLICY}"
"${UPDATE_CMD}" --set "${DESIRED_POLICY}"

# Verify the change was applied and persisted.
NEW_POLICY="$(${UPDATE_CMD} --show 2>/dev/null || true)"
NEW_BASE="${NEW_POLICY%%:*}"

NEW_FILE_POLICY=""
if [ -f "${CONFIG_FILE}" ]; then
    NEW_FILE_POLICY="$(grep -vE '^\s*(#|$)' "${CONFIG_FILE}" 2>/dev/null | head -n1 | tr -d '[:space:]')"
fi

if [ "${NEW_BASE}" = "${DESIRED_POLICY}" ] && [ "${NEW_FILE_POLICY}" = "${DESIRED_POLICY}" ]; then
    echo "Successfully set system-wide cryptographic policy to '${DESIRED_POLICY}'."
    echo "NOTE: A reboot is recommended so all services adopt the new policy."
    exit 0
else
    echo "ERROR: Failed to verify cryptographic policy. Active='${NEW_POLICY}', File='${NEW_FILE_POLICY}'." >&2
    exit 1
fi
```

**Reference fix:**
```bash
var_system_crypto_policy='
```


---

## None — `configure_gnutls_tls_crypto_policy`

**Prompt:** On a RHEL 8 system, ensure that the GnuTLS library abides by system-wide crypto policies, which include disabling deprecated and insecure protocols like SSL 3.0, TLS 1.0, and TLS 1.1. This ensures the use of strong, modern encryption and minimizes vulnerabilities related to outdated protocols. Write an idempotent bash remediation script to check for compliance and configure GnuTLS accordingly if necessary, ensuring the change persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure GnuTLS abides by system-wide crypto policies.
# This disables deprecated/insecure protocols (SSL 3.0, TLS 1.0, TLS 1.1)
# by making GnuTLS follow the system-wide crypto policy configuration.
#

set -o nounset
set -o pipefail

CONFIG_FILE="/etc/crypto-policies/back-ends/gnutls.config"
POLICY_FILE="/etc/crypto-policies/config"
DESIRED_POLICY="DEFAULT"
EXPECTED_LINK_TARGET="/usr/share/crypto-policies"

# Ensure crypto-policies tooling is available
if ! command -v update-crypto-policies >/dev/null 2>&1; then
    echo "ERROR: update-crypto-policies command not found. Installing crypto-policies package..."
    if command -v yum >/dev/null 2>&1; then
        yum install -y crypto-policies crypto-policies-scripts || {
            echo "ERROR: Failed to install crypto-policies packages."
            exit 1
        }
    else
        echo "ERROR: Cannot install crypto-policies; package manager not found."
        exit 1
    fi
fi

# Determine the currently active system-wide crypto policy
current_policy=""
if command -v update-crypto-policies >/dev/null 2>&1; then
    current_policy="$(update-crypto-policies --show 2>/dev/null | awk '{print $1}')"
fi

# Fall back to reading the policy config file if the command output is empty
if [ -z "${current_policy}" ] && [ -f "${POLICY_FILE}" ]; then
    current_policy="$(grep -vE '^\s*#' "${POLICY_FILE}" | head -n1 | tr -d '[:space:]')"
fi

echo "Current system-wide crypto policy: ${current_policy:-unknown}"

needs_change=0

# A policy that weakens protocols would be LEGACY; ensure at least DEFAULT.
case "${current_policy}" in
    DEFAULT|FUTURE|FIPS|"")
        # DEFAULT/FUTURE/FIPS disable SSL3, TLS1.0, TLS1.1. If unknown/empty, force apply.
        if [ -z "${current_policy}" ]; then
            needs_change=1
        fi
        ;;
    LEGACY|*LEGACY*)
        echo "Policy '${current_policy}' permits deprecated protocols; remediation required."
        needs_change=1
        ;;
    *)
        # Custom or subpolicy; be safe and reapply a strong base policy.
        echo "Non-standard policy detected: ${current_policy}; enforcing ${DESIRED_POLICY}."
        needs_change=1
        ;;
esac

# Verify that the GnuTLS back-end config exists and is managed by crypto-policies
if [ ! -e "${CONFIG_FILE}" ]; then
    echo "GnuTLS crypto-policies back-end config is missing; remediation required."
    needs_change=1
else
    # Ensure GnuTLS back-end is a symlink into the crypto-policies tree
    # (managed configuration) rather than a manual override.
    if [ -L "${CONFIG_FILE}" ]; then
        link_target="$(readlink -f "${CONFIG_FILE}" 2>/dev/null)"
        case "${link_target}" in
            ${EXPECTED_LINK_TARGET}*)
                : # properly managed
                ;;
            *)
                echo "GnuTLS back-end symlink not managed by crypto-policies; remediation required."
                needs_change=1
                ;;
        esac
    fi
    # Check that insecure protocols are not explicitly re-enabled in the config.
    if grep -Eiq '\+VERS-SSL3\.0|\+VERS-TLS1\.0|\+VERS-TLS1\.1' "${CONFIG_FILE}"; then
        echo "GnuTLS config explicitly enables deprecated protocols; remediation required."
        needs_change=1
    fi
fi

if [ "${needs_change}" -eq 0 ]; then
    echo "COMPLIANT: GnuTLS already abides by a strong system-wide crypto policy."
    exit 0
fi

echo "Applying system-wide crypto policy '${DESIRED_POLICY}' to enforce GnuTLS compliance..."

# Set and regenerate the back-end configurations idempotently.
if update-crypto-policies --set "${DESIRED_POLICY}"; then
    echo "Successfully set crypto policy to ${DESIRED_POLICY}."
else
    echo "ERROR: Failed to set crypto policy."
    exit 1
fi

# Regenerate back-end configs to ensure GnuTLS picks up the policy immediately.
update-crypto-policies >/dev/null 2>&1 || true

# Verify remediation
new_policy="$(update-crypto-policies --show 2>/dev/null | awk '{print $1}')"
if [ "${new_policy}" = "${DESIRED_POLICY}" ] || [ "${new_policy}" = "FUTURE" ] || [ "${new_policy}" = "FIPS" ]; then
    echo "COMPLIANT: GnuTLS now follows system-wide crypto policy '${new_policy}'."
    echo "Deprecated protocols (SSL 3.0, TLS 1.0, TLS 1.1) are disabled."
    echo "Note: A reboot or service restart may be required for all applications to reload the policy."
    exit 0
else
    echo "ERROR: Remediation did not result in a compliant policy (current: ${new_policy:-unknown})."
    exit 1
fi
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

**Prompt:** On a RHEL 8 system, ensure that the SSH server uses only FIPS 140-2 validated cryptographic ciphers as defined by the system's centralized crypto policies. This avoids fragmented crypto settings and ensures compliance with security standards. Write an idempotent bash remediation script that configures the SSH server to adhere to the system's crypto policy regarding cipher selection, ensuring that it automatically attempts to use the strongest FIPS-compliant cipher available.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure the SSH server uses ciphers defined by the
# system-wide centralized crypto policy (FIPS 140-2 validated).
#
# On RHEL 8, the correct approach is to NOT hard-code a "Ciphers" line
# in sshd_config, but instead let sshd inherit ciphers from the
# system-wide crypto policy via /etc/crypto-policies/back-ends/opensshserver.config
# (referenced by /etc/sysconfig/sshd through CRYPTO_POLICY).
#
# Any explicit "Ciphers" directive in sshd_config or its drop-in files
# overrides the crypto policy and fragments the configuration, so we
# remove such overrides to guarantee the strongest FIPS-compliant
# cipher available is negotiated automatically.

set -o errexit
set -o nounset
set -o pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_CONFIG_DIR="/etc/ssh/sshd_config.d"
SYSCONFIG_SSHD="/etc/sysconfig/sshd"
TIMESTAMP="$(date +%Y%m%d%H%M%S)"

changed=0

# --- Helper: remove any explicit "Ciphers" directive from a given file ---
remove_ciphers_directive() {
    local file="$1"

    [ -f "$file" ] || return 0

    # Match lines that start (optionally with leading whitespace) with the
    # "Ciphers" keyword (case-insensitive), which would override crypto policy.
    if grep -Eiq '^[[:space:]]*Ciphers[[:space:]]+' "$file"; then
        cp -a -- "$file" "${file}.bak.${TIMESTAMP}"
        # Delete matching lines in-place.
        sed -i -E '/^[[:space:]]*[Cc][Ii][Pp][Hh][Ee][Rr][Ss][[:space:]]+/d' "$file"
        echo "Removed explicit 'Ciphers' override from ${file}"
        changed=1
    fi
}

# --- 1. Remove Ciphers overrides from main sshd_config ---
remove_ciphers_directive "$SSHD_CONFIG"

# --- 2. Remove Ciphers overrides from any drop-in config files ---
if [ -d "$SSHD_CONFIG_DIR" ]; then
    # Iterate safely over all files in the drop-in directory.
    while IFS= read -r -d '' dropin; do
        remove_ciphers_directive "$dropin"
    done < <(find "$SSHD_CONFIG_DIR" -maxdepth 1 -type f -print0)
fi

# --- 3. Ensure sshd inherits the system-wide crypto policy ---
# The CRYPTO_POLICY variable in /etc/sysconfig/sshd MUST NOT be set to
# an empty value or overridden, otherwise sshd opts out of the crypto
# policy. The stock configuration ships this line commented out, which
# means the policy IS applied. We ensure no active override exists.
if [ -f "$SYSCONFIG_SSHD" ]; then
    if grep -Eq '^[[:space:]]*CRYPTO_POLICY=' "$SYSCONFIG_SSHD"; then
        cp -a -- "$SYSCONFIG_SSHD" "${SYSCONFIG_SSHD}.bak.${TIMESTAMP}"
        # Comment out any active CRYPTO_POLICY assignment so the
        # system-wide crypto policy is honored.
        sed -i -E 's/^[[:space:]]*(CRYPTO_POLICY=.*)$/# \1/' "$SYSCONFIG_SSHD"
        echo "Disabled crypto policy opt-out in ${SYSCONFIG_SSHD}"
        changed=1
    fi
fi

# --- 4. Ensure the crypto-policies back-end for openssh server exists ---
# This is provided by the crypto-policies package. If missing, apply the
# current policy to regenerate the back-end files.
OPENSSH_BACKEND="/etc/crypto-policies/back-ends/opensshserver.config"
if [ ! -e "$OPENSSH_BACKEND" ]; then
    if command -v update-crypto-policies >/dev/null 2>&1; then
        current_policy="$(update-crypto-policies --show 2>/dev/null || echo DEFAULT)"
        echo "Crypto policy back-end missing; re-applying policy: ${current_policy}"
        update-crypto-policies --set "$current_policy" >/dev/null 2>&1 || \
            update-crypto-policies --set DEFAULT >/dev/null 2>&1 || true
        changed=1
    fi
fi

# --- 5. Validate the resulting sshd configuration ---
if command -v sshd >/dev/null 2>&1; then
    if ! sshd -t 2>/dev/null; then
        echo "ERROR: sshd configuration test failed after remediation." >&2
        exit 1
    fi
fi

# --- 6. Restart sshd only if changes were made ---
if [ "$changed" -eq 1 ]; then
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active --quiet sshd 2>/dev/null || \
           systemctl list-unit-files 2>/dev/null | grep -q '^sshd\.service'; then
            systemctl restart sshd
            echo "Restarted sshd service to apply crypto policy cipher settings."
        fi
    fi
    echo "SSH server now uses ciphers from the system-wide FIPS crypto policy."
else
    echo "System already compliant: SSH server inherits ciphers from crypto policy."
fi

exit 0
```

**Reference fix:**
```bash
sshd_approved_ciphers='
```


---

## None — `harden_sshd_macs_opensshserver_conf_crypto_policy`

**Prompt:** Ensure that the OpenSSH server on a RHEL 8 system adheres to the centrally managed system-wide crypto policies, which enforce the use of cryptographic algorithms compliant with FIPS 140-2 standards. This avoids fragmentation and unexpected security policy violations. Write an idempotent bash remediation script that configures the SSH server to consistently use these validated Message Authentication Codes (MACs) as dictated by the system crypto policy.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation script to ensure the OpenSSH server adheres to the
# system-wide crypto policy (FIPS 140-2 compliant) on RHEL 8.
#
# The presence of a MACs setting in sshd_config that is NOT sourced from
# the system crypto policy fragments the policy. This script removes any
# hardcoded MACs override so that sshd consistently uses the centrally
# managed crypto policy via /etc/crypto-policies/back-ends/opensshserver.config.
#
set -euo pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_CONFIG_DIR="/etc/ssh/sshd_config.d"
CRYPTO_BACKEND="/etc/crypto-policies/back-ends/opensshserver.config"

# Function to strip explicit MACs directives from a given file (idempotent).
remove_macs_override() {
    local file="$1"
    [ -f "$file" ] || return 0

    # Only act if there is an active (uncommented) MACs directive.
    if grep -qiE '^[[:space:]]*MACs[[:space:]]+' "$file"; then
        echo "Removing explicit MACs override from ${file}"
        # Comment out any active MACs lines so the crypto policy takes effect.
        sed -ri 's/^([[:space:]]*)(MACs[[:space:]]+.*)$/\1# \2  # Removed to defer to system crypto policy/I' "$file"
    fi
}

# Remove overrides from the main sshd_config.
remove_macs_override "$SSHD_CONFIG"

# Remove overrides from any drop-in config files.
if [ -d "$SSHD_CONFIG_DIR" ]; then
    while IFS= read -r -d '' dropin; do
        remove_macs_override "$dropin"
    done < <(find "$SSHD_CONFIG_DIR" -maxdepth 1 -type f -name '*.conf' -print0)
fi

# Ensure the crypto policy back-end for the SSH server exists; if not, (re)apply
# the current system-wide crypto policy so the configuration is regenerated.
if [ ! -f "$CRYPTO_BACKEND" ]; then
    echo "Crypto policy back-end missing; reapplying system-wide crypto policy."
    if command -v update-crypto-policies >/dev/null 2>&1; then
        current_policy="$(update-crypto-policies --show 2>/dev/null || echo DEFAULT)"
        update-crypto-policies --set "$current_policy" >/dev/null 2>&1 || \
            update-crypto-policies --set DEFAULT >/dev/null 2>&1 || true
    fi
fi

# Validate the resulting sshd configuration before attempting a reload.
if command -v sshd >/dev/null 2>&1; then
    if ! sshd -t; then
        echo "ERROR: sshd configuration test failed. Not reloading service." >&2
        exit 1
    fi
fi

# Reload sshd to apply changes if the service is active.
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet sshd.service 2>/dev/null || \
       systemctl is-enabled --quiet sshd.service 2>/dev/null; then
        echo "Reloading sshd service to apply crypto policy."
        systemctl reload sshd.service 2>/dev/null || systemctl restart sshd.service 2>/dev/null || true
    fi
fi

echo "OpenSSH server now defers MAC selection to the system-wide crypto policy."
exit 0
```

**Reference fix:**
```bash
sshd_approved_macs='
```


---

## RHEL-08-020032 — `dconf_gnome_disable_user_list`

**Prompt:** On a RHEL 8 system using GNOME3, the login screen currently displays a list of all user accounts, which poses a security risk by allowing anyone to enumerate user accounts without authentication. Write an idempotent bash remediation script that configures the system's graphical login screen to hide the user list by default, ensuring that only users with knowledge of a valid username can attempt to log in. Ensure this setting is not user-modifiable and persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PROFILE_DIR="/etc/dconf/profile"
PROFILE_FILE="${PROFILE_DIR}/user"
DB_DIR="/etc/dconf/db/gdm.d"
SETTINGS_FILE="${DB_DIR}/00-login-screen"
LOCK_DIR="/etc/dconf/db/gdm.d/locks"
LOCK_FILE="${LOCK_DIR}/00-login-screen"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# Ensure required directories exist
mkdir -p "${PROFILE_DIR}"
mkdir -p "${DB_DIR}"
mkdir -p "${LOCK_DIR}"

# Ensure the dconf user profile references the gdm database
if [[ ! -f "${PROFILE_FILE}" ]] || ! grep -q '^system-db:gdm$' "${PROFILE_FILE}" 2>/dev/null; then
    cat > "${PROFILE_FILE}" <<'EOF'
user-db:user
system-db:gdm
system-db:local
EOF
fi

# Desired settings content to disable the user list
DESIRED_SETTINGS=$(cat <<'EOF'
[org/gnome/login-screen]
disable-user-list=true
EOF
)

# Write settings file only if different (idempotent)
if [[ ! -f "${SETTINGS_FILE}" ]] || [[ "$(cat "${SETTINGS_FILE}")" != "${DESIRED_SETTINGS}" ]]; then
    printf '%s\n' "${DESIRED_SETTINGS}" > "${SETTINGS_FILE}"
fi

# Desired lock content to prevent user modification
DESIRED_LOCK="/org/gnome/login-screen/disable-user-list"

# Write lock file only if the lock entry is missing (idempotent)
if [[ ! -f "${LOCK_FILE}" ]] || ! grep -qxF "${DESIRED_LOCK}" "${LOCK_FILE}" 2>/dev/null; then
    printf '%s\n' "${DESIRED_LOCK}" > "${LOCK_FILE}"
fi

# Update the dconf databases so changes persist and take effect
dconf update

echo "GDM login screen configured to hide user list (disable-user-list=true)."
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

**Prompt:** On a RHEL 8 system running the GNOME3 desktop environment, configure the system to automatically lock the screen whenever a smartcard is removed, enhancing security by preventing unauthorized access to a logged-in session. Ensure that this setting is enforced such that the user cannot modify it. Write an idempotent bash remediation script that applies this configuration and persists it across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Lock GNOME3 session on smartcard removal and prevent user override.
# Idempotent script for RHEL 8 / GNOME3.
#
set -euo pipefail

DCONF_DB_DIR="/etc/dconf/db/local.d"
DCONF_LOCKS_DIR="/etc/dconf/db/local.d/locks"
DCONF_PROFILE="/etc/dconf/profile/user"
SETTINGS_FILE="${DCONF_DB_DIR}/00-security-settings"
LOCKS_FILE="${DCONF_LOCKS_DIR}/00-security-settings-lock"

# Ensure dconf is installed
if ! command -v dconf >/dev/null 2>&1; then
    echo "dconf command not found. Installing dconf..."
    if command -v dnf >/dev/null 2>&1; then
        dnf install -y dconf
    elif command -v yum >/dev/null 2>&1; then
        yum install -y dconf
    else
        echo "No supported package manager found to install dconf." >&2
        exit 1
    fi
fi

# Create required directories
mkdir -p "${DCONF_DB_DIR}"
mkdir -p "${DCONF_LOCKS_DIR}"
mkdir -p "$(dirname "${DCONF_PROFILE}")"

# Ensure the dconf user profile references the local database
if [ ! -f "${DCONF_PROFILE}" ] || ! grep -qE '^\s*user-db:user\s*$' "${DCONF_PROFILE}" || ! grep -qE '^\s*system-db:local\s*$' "${DCONF_PROFILE}"; then
    cat > "${DCONF_PROFILE}" <<'EOF'
user-db:user
system-db:local
EOF
fi

# Write the smartcard removal action setting
if [ ! -f "${SETTINGS_FILE}" ] || \
   ! grep -qE '^\[org/gnome/settings-daemon/peripherals/smartcard\]' "${SETTINGS_FILE}" || \
   ! grep -qE "^removal-action='lock-screen'" "${SETTINGS_FILE}"; then
    cat > "${SETTINGS_FILE}" <<'EOF'
[org/gnome/settings-daemon/peripherals/smartcard]
removal-action='lock-screen'
EOF
fi

# Lock the setting so users cannot change it
if [ ! -f "${LOCKS_FILE}" ] || \
   ! grep -qE '^/org/gnome/settings-daemon/peripherals/smartcard/removal-action$' "${LOCKS_FILE}"; then
    cat > "${LOCKS_FILE}" <<'EOF'
/org/gnome/settings-daemon/peripherals/smartcard/removal-action
EOF
fi

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

**Prompt:** On a RHEL 8 system, ensure the GNOME Display Manager (GDM) requires users to manually authenticate upon login, preventing automatic logins which bypass credential checks. Write an idempotent bash remediation script that disables any automatic login capability in GDM, ensuring users must always authenticate to access the system.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Disable GDM Automatic Login on RHEL 8
# Ensures users must authenticate manually at login.
#

set -o nounset
set -o pipefail

GDM_CONF="/etc/gdm/custom.conf"

# Only proceed if GDM is installed (package or config directory present).
if ! rpm -q gdm >/dev/null 2>&1 && [ ! -d /etc/gdm ]; then
    echo "GDM is not installed; no remediation needed."
    exit 0
fi

# Ensure the GDM configuration directory exists.
if [ ! -d /etc/gdm ]; then
    mkdir -p /etc/gdm
fi

# Ensure the custom.conf file exists.
if [ ! -f "${GDM_CONF}" ]; then
    printf '%s\n' "[daemon]" > "${GDM_CONF}"
    chmod 0644 "${GDM_CONF}"
fi

# Function to set a key=value under the [daemon] section idempotently.
set_daemon_key() {
    local key="$1"
    local value="$2"
    local file="$3"

    # Ensure the [daemon] section exists.
    if ! grep -q '^\[daemon\]' "${file}"; then
        printf '\n%s\n' "[daemon]" >> "${file}"
    fi

    # If any (commented or active) occurrence of the key exists, normalize it.
    if grep -Eq "^[[:space:]]*#?[[:space:]]*${key}[[:space:]]*=" "${file}"; then
        # Replace the first matching line with the correct setting, remove others.
        awk -v key="${key}" -v val="${value}" '
            BEGIN { done = 0 }
            {
                line = $0
                # Match commented or uncommented key assignments.
                if (line ~ "^[[:space:]]*#?[[:space:]]*" key "[[:space:]]*=") {
                    if (done == 0) {
                        print key "=" val
                        done = 1
                    }
                    # Skip additional duplicate lines.
                    next
                }
                print line
            }
        ' "${file}" > "${file}.tmp" && mv "${file}.tmp" "${file}"
    else
        # Insert the key right after the [daemon] section header.
        awk -v key="${key}" -v val="${value}" '
            {
                print $0
                if ($0 ~ /^\[daemon\]/ && inserted == 0) {
                    print key "=" val
                    inserted = 1
                }
            }
        ' "${file}" > "${file}.tmp" && mv "${file}.tmp" "${file}"
    fi
}

# Disable automatic login and timed login.
set_daemon_key "AutomaticLoginEnable" "false" "${GDM_CONF}"
set_daemon_key "TimedLoginEnable" "false" "${GDM_CONF}"

# Ensure proper permissions.
chmod 0644 "${GDM_CONF}"
chown root:root "${GDM_CONF}"

echo "GDM automatic login has been disabled in ${GDM_CONF}."
echo "Users must now authenticate manually."

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

**Prompt:** On a RHEL 8 system using GNOME3, configure the screensaver inactivity timeout so that the session is automatically locked after 15 minutes of inactivity. This helps prevent unauthorized access when a user steps away but forgets to manually lock the screen. Write an idempotent bash remediation script to set the idle timeout to 900 seconds by updating the appropriate dconf database configuration files, and ensure the setting is immutable by users.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Configure GNOME3 screensaver idle timeout to 900 seconds (15 min)
# and lock the screen, enforcing the setting as immutable for users.
#
set -euo pipefail

IDLE_DELAY=900

DCONF_DB_DIR="/etc/dconf/db/local.d"
DCONF_LOCK_DIR="/etc/dconf/db/local.d/locks"
DCONF_PROFILE="/etc/dconf/profile/user"
KEYFILE="${DCONF_DB_DIR}/00-screensaver"
LOCKFILE="${DCONF_LOCK_DIR}/00-screensaver"

# Ensure dconf is installed
if ! command -v dconf >/dev/null 2>&1; then
    echo "dconf not found. Installing dconf..."
    if command -v dnf >/dev/null 2>&1; then
        dnf install -y dconf
    elif command -v yum >/dev/null 2>&1; then
        yum install -y dconf
    else
        echo "ERROR: Could not install dconf; no supported package manager found." >&2
        exit 1
    fi
fi

# Ensure required directories exist
mkdir -p "${DCONF_DB_DIR}"
mkdir -p "${DCONF_LOCK_DIR}"
mkdir -p "$(dirname "${DCONF_PROFILE}")"

# Ensure the user dconf profile references the 'local' database (idempotent)
if [ ! -f "${DCONF_PROFILE}" ]; then
    cat > "${DCONF_PROFILE}" <<'EOF'
user-db:user
system-db:local
EOF
else
    grep -qxF 'user-db:user' "${DCONF_PROFILE}" || echo 'user-db:user' >> "${DCONF_PROFILE}"
    grep -qxF 'system-db:local' "${DCONF_PROFILE}" || echo 'system-db:local' >> "${DCONF_PROFILE}"
fi

# Write the keyfile with the idle timeout and screensaver lock settings (idempotent)
DESIRED_KEYFILE_CONTENT=$(cat <<EOF
[org/gnome/desktop/session]
idle-delay=uint32 ${IDLE_DELAY}

[org/gnome/desktop/screensaver]
lock-enabled=true
lock-delay=uint32 0
EOF
)

if [ ! -f "${KEYFILE}" ] || [ "$(cat "${KEYFILE}")" != "${DESIRED_KEYFILE_CONTENT}" ]; then
    printf '%s\n' "${DESIRED_KEYFILE_CONTENT}" > "${KEYFILE}"
fi

# Write the lock file to make the settings immutable for users (idempotent)
DESIRED_LOCK_CONTENT=$(cat <<'EOF'
/org/gnome/desktop/session/idle-delay
/org/gnome/desktop/screensaver/lock-enabled
/org/gnome/desktop/screensaver/lock-delay
EOF
)

if [ ! -f "${LOCKFILE}" ] || [ "$(cat "${LOCKFILE}")" != "${DESIRED_LOCK_CONTENT}" ]; then
    printf '%s\n' "${DESIRED_LOCK_CONTENT}" > "${LOCKFILE}"
fi

# Update the dconf database to apply changes
dconf update

echo "GNOME screensaver idle timeout configured to ${IDLE_DELAY} seconds and locked as immutable."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

inactivity_timeout_value='
```


---

## RHEL-08-020031 — `dconf_gnome_screensaver_lock_delay`

**Prompt:** In the GNOME3 desktop environment on a RHEL 8 system, ensure that whenever the screensaver activates, a screen lock is triggered without delay to prevent unauthorized access to the user's session. Write an idempotent bash remediation script that configures the screensaver to immediately activate the lock screen as soon as it starts, and ensures the setting is properly applied and persists across user sessions.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Enable GNOME3 screensaver lock delay of 0 (immediate lock)
# Idempotently configures /etc/dconf/db/local.d and locks the setting.

set -o errexit
set -o nounset
set -o pipefail

# Ensure dconf is installed
if ! rpm -q dconf >/dev/null 2>&1; then
    echo "dconf package is not installed; cannot remediate. Attempting to continue if binaries exist."
fi

# Only proceed if GNOME/dconf tooling is present
if ! command -v dconf >/dev/null 2>&1; then
    echo "dconf command not found. Skipping remediation (GNOME3 not present)."
    exit 0
fi

DCONF_DB_DIR="/etc/dconf/db/local.d"
DCONF_LOCK_DIR="/etc/dconf/db/local.d/locks"
DCONF_PROFILE="/etc/dconf/profile/user"

SETTINGS_FILE="${DCONF_DB_DIR}/00-security-settings"
LOCKS_FILE="${DCONF_LOCK_DIR}/00-security-settings-lock"

# Ensure required directories exist
mkdir -p "${DCONF_DB_DIR}"
mkdir -p "${DCONF_LOCK_DIR}"
mkdir -p "$(dirname "${DCONF_PROFILE}")"

# Ensure the user profile references the local database
if [ ! -f "${DCONF_PROFILE}" ]; then
    cat > "${DCONF_PROFILE}" <<'EOF'
user-db:user
system-db:local
EOF
else
    grep -q '^user-db:user$'   "${DCONF_PROFILE}" || echo 'user-db:user'   >> "${DCONF_PROFILE}"
    grep -q '^system-db:local$' "${DCONF_PROFILE}" || echo 'system-db:local' >> "${DCONF_PROFILE}"
fi

# Configure lock-delay = 0 (immediate lock on screensaver activation)
# Idempotently manage the [org/gnome/desktop/screensaver] section.
KEY_SECTION="org/gnome/desktop/screensaver"
KEY_NAME="lock-delay"
KEY_VALUE="uint32 0"

if [ ! -f "${SETTINGS_FILE}" ]; then
    cat > "${SETTINGS_FILE}" <<EOF
[${KEY_SECTION}]
${KEY_NAME}=${KEY_VALUE}
EOF
else
    if ! grep -q "^\[${KEY_SECTION}\]" "${SETTINGS_FILE}"; then
        # Append the section and key
        {
            echo ""
            echo "[${KEY_SECTION}]"
            echo "${KEY_NAME}=${KEY_VALUE}"
        } >> "${SETTINGS_FILE}"
    else
        if grep -qE "^\s*${KEY_NAME}\s*=" "${SETTINGS_FILE}"; then
            # Update existing key
            sed -ri "s|^(\s*${KEY_NAME}\s*=).*|\1${KEY_VALUE}|" "${SETTINGS_FILE}"
        else
            # Insert key right after the section header
            sed -ri "/^\[${KEY_SECTION//\//\\/}\]/a ${KEY_NAME}=${KEY_VALUE}" "${SETTINGS_FILE}"
        fi
    fi
fi

# Lock the setting so users cannot override it
LOCK_LINE="/${KEY_SECTION}/${KEY_NAME}"
if [ ! -f "${LOCKS_FILE}" ]; then
    echo "${LOCK_LINE}" > "${LOCKS_FILE}"
else
    grep -qxF "${LOCK_LINE}" "${LOCKS_FILE}" || echo "${LOCK_LINE}" >> "${LOCKS_FILE}"
fi

# Update the dconf system databases
dconf update

echo "GNOME3 screensaver lock-delay set to 0 (immediate lock) and locked."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

var_screensaver_lock_delay='
```


---

## RHEL-08-020030 — `dconf_gnome_screensaver_lock_enabled`

**Prompt:** On a RHEL 8 system running the GNOME3 desktop environment, ensure that the screensaver engages a lock when activated to secure an unattended session. Write an idempotent bash remediation script that configures the GNOME3 screensaver to enable the lock feature after activation and prevents users from altering this setting. Ensure the configuration is applied system-wide and persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PROFILE_DIR="/etc/dconf/profile"
DB_DIR="/etc/dconf/db/local.d"
LOCK_DIR="/etc/dconf/db/local.d/locks"
PROFILE_FILE="${PROFILE_DIR}/user"
SETTINGS_FILE="${DB_DIR}/00-screensaver"
LOCKS_FILE="${LOCK_DIR}/screensaver-lock"

mkdir -p "${PROFILE_DIR}"
mkdir -p "${DB_DIR}"
mkdir -p "${LOCK_DIR}"

if [ ! -f "${PROFILE_FILE}" ] || ! grep -q '^user-db:user$' "${PROFILE_FILE}" 2>/dev/null || ! grep -q '^system-db:local$' "${PROFILE_FILE}" 2>/dev/null; then
    cat > "${PROFILE_FILE}" <<'EOF'
user-db:user
system-db:local
EOF
fi

if [ ! -f "${SETTINGS_FILE}" ] || ! grep -qx 'lock-enabled=true' "${SETTINGS_FILE}" 2>/dev/null; then
    cat > "${SETTINGS_FILE}" <<'EOF'
[org/gnome/desktop/screensaver]
lock-enabled=true
EOF
fi

if [ ! -f "${LOCKS_FILE}" ] || ! grep -qx '/org/gnome/desktop/screensaver/lock-enabled' "${LOCKS_FILE}" 2>/dev/null; then
    cat > "${LOCKS_FILE}" <<'EOF'
/org/gnome/desktop/screensaver/lock-enabled
EOF
fi

dconf update
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

**Prompt:** On a RHEL 8 system using GNOME 3, restrict all users from changing the screensaver lock settings, ensuring that screensaver timeout settings cannot be disabled or altered by regular users. Write an idempotent bash remediation script that enforces this lockdown of the screensaver lock behavior, ensuring no user can disable or modify this policy, and that the configuration persists after system updates and reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

DCONF_DB_DIR="/etc/dconf/db"
PROFILE_FILE="/etc/dconf/profile/user"
LOCAL_DB_DIR="${DCONF_DB_DIR}/local.d"
LOCAL_LOCKS_DIR="${LOCAL_DB_DIR}/locks"
SETTINGS_FILE="${LOCAL_DB_DIR}/00-screensaver"
LOCKS_FILE="${LOCAL_LOCKS_DIR}/screensaver"

IDLE_DELAY="uint32 900"
LOCK_DELAY="uint32 5"

if ! command -v dconf >/dev/null 2>&1; then
    if command -v dnf >/dev/null 2>&1; then
        dnf install -y dconf
    else
        echo "ERROR: dconf is not installed and cannot be installed automatically." >&2
        exit 1
    fi
fi

mkdir -p "$LOCAL_DB_DIR"
mkdir -p "$LOCAL_LOCKS_DIR"
mkdir -p "$(dirname "$PROFILE_FILE")"

# Ensure the user profile references the local database
if [[ ! -f "$PROFILE_FILE" ]] || ! grep -qx "user-db:user" "$PROFILE_FILE" 2>/dev/null || ! grep -qx "system-db:local" "$PROFILE_FILE" 2>/dev/null; then
    cat > "$PROFILE_FILE" <<'EOF'
user-db:user
system-db:local
EOF
fi

# Write the screensaver settings
cat > "$SETTINGS_FILE" <<EOF
[org/gnome/desktop/session]
idle-delay=${IDLE_DELAY}

[org/gnome/desktop/screensaver]
lock-enabled=true
lock-delay=${LOCK_DELAY}
idle-activation-enabled=true
EOF

# Write the locks to prevent regular users from changing the settings
cat > "$LOCKS_FILE" <<'EOF'
/org/gnome/desktop/session/idle-delay
/org/gnome/desktop/screensaver/lock-enabled
/org/gnome/desktop/screensaver/lock-delay
/org/gnome/desktop/screensaver/idle-activation-enabled
EOF

chmod 0644 "$PROFILE_FILE" "$SETTINGS_FILE" "$LOCKS_FILE"

# Update the dconf database
dconf update

echo "Screensaver lock policy enforced and locked for all users."
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

**Prompt:** On a RHEL 8 system, GNOME 3 desktop users must not be able to modify the screensaver lock settings to ensure session lock enforcement when inactive. Write an idempotent bash remediation script that configures the system so any attempt to change the screensaver lock delay is overridden by admin settings, ensuring the lock cannot be user-modified and persists across uses.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Prevent GNOME 3 users from modifying the screensaver lock-delay.
# Enforces the setting via dconf system database and locks it so user changes
# are overridden by administrator settings.
#
# Idempotent: safe to run multiple times.

set -euo pipefail

DCONF_DB_DIR="/etc/dconf/db/local.d"
DCONF_LOCKS_DIR="/etc/dconf/db/local.d/locks"
DCONF_PROFILE="/etc/dconf/profile/user"
SETTINGS_FILE="${DCONF_DB_DIR}/00-screensaver"
LOCKS_FILE="${DCONF_LOCKS_DIR}/00-screensaver"

# Bail out early if dconf is not installed (no GNOME environment).
if ! command -v dconf >/dev/null 2>&1; then
    echo "dconf not found; GNOME is likely not installed. Nothing to remediate."
    exit 0
fi

# Ensure required directories exist.
mkdir -p "${DCONF_DB_DIR}"
mkdir -p "${DCONF_LOCKS_DIR}"
mkdir -p "$(dirname "${DCONF_PROFILE}")"

# Ensure a dconf user profile exists that references the local system database.
if [ ! -f "${DCONF_PROFILE}" ] || ! grep -qxF "user-db:user" "${DCONF_PROFILE}" 2>/dev/null || ! grep -qxF "system-db:local" "${DCONF_PROFILE}" 2>/dev/null; then
    cat > "${DCONF_PROFILE}" <<'EOF'
user-db:user
system-db:local
EOF
fi

# Define the enforced screensaver settings.
# lock-delay of 5 seconds after screensaver activation, with lock enabled.
DESIRED_SETTINGS=$(cat <<'EOF'
[org/gnome/desktop/screensaver]
lock-delay=uint32 5
lock-enabled=true

[org/gnome/desktop/session]
idle-delay=uint32 900
EOF
)

# Write the settings file only if content differs (idempotency).
if [ ! -f "${SETTINGS_FILE}" ] || [ "$(cat "${SETTINGS_FILE}")" != "${DESIRED_SETTINGS}" ]; then
    printf '%s\n' "${DESIRED_SETTINGS}" > "${SETTINGS_FILE}"
fi

# Define the locks that prevent users from overriding the settings.
DESIRED_LOCKS=$(cat <<'EOF'
/org/gnome/desktop/screensaver/lock-delay
/org/gnome/desktop/screensaver/lock-enabled
/org/gnome/desktop/session/idle-delay
EOF
)

# Write the locks file only if content differs (idempotency).
if [ ! -f "${LOCKS_FILE}" ] || [ "$(cat "${LOCKS_FILE}")" != "${DESIRED_LOCKS}" ]; then
    printf '%s\n' "${DESIRED_LOCKS}" > "${LOCKS_FILE}"
fi

# Set safe permissions on the created files.
chmod 0644 "${SETTINGS_FILE}" "${LOCKS_FILE}" "${DCONF_PROFILE}"

# Update the dconf system databases to apply the changes.
dconf update

echo "GNOME screensaver lock settings enforced and locked from user modification."
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

**Prompt:** On a RHEL 8 system using the GNOME 3 desktop environment, ensure users are unable to modify the session idle settings that govern automatic screen locking when the user session is idle. This measure ensures that the screen-lock timeout policy is consistently enforced to secure unattended sessions. Write an idempotent bash remediation script that sets this restriction so that it applies persistently across reboots and GNOME sessions.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

# Ensure dconf is installed and GNOME is present
if ! rpm -q dconf >/dev/null 2>&1; then
    echo "dconf is not installed; GNOME environment may not be present. Exiting."
    exit 0
fi

DCONF_DB_DIR="/etc/dconf/db/local.d"
DCONF_LOCK_DIR="/etc/dconf/db/local.d/locks"
DCONF_PROFILE="/etc/dconf/profile/user"
SETTINGS_FILE="${DCONF_DB_DIR}/00-screensaver"
LOCK_FILE="${DCONF_LOCK_DIR}/00-screensaver"

# Ensure the user profile exists and references the local database
mkdir -p "$(dirname "${DCONF_PROFILE}")"
if [ ! -f "${DCONF_PROFILE}" ]; then
    cat > "${DCONF_PROFILE}" <<'EOF'
user-db:user
system-db:local
EOF
else
    grep -qxF 'user-db:user' "${DCONF_PROFILE}" || sed -i '1i user-db:user' "${DCONF_PROFILE}"
    grep -qxF 'system-db:local' "${DCONF_PROFILE}" || echo 'system-db:local' >> "${DCONF_PROFILE}"
fi

# Create the settings directory
mkdir -p "${DCONF_DB_DIR}"
mkdir -p "${DCONF_LOCK_DIR}"

# Define the session idle settings (idle-delay controls automatic screen locking)
cat > "${SETTINGS_FILE}" <<'EOF'
[org/gnome/desktop/session]
idle-delay=uint32 900
EOF

# Lock the setting so users cannot modify it
cat > "${LOCK_FILE}" <<'EOF'
/org/gnome/desktop/session/idle-delay
EOF

# Update the dconf system databases
dconf update

echo "Session idle settings have been enforced and locked."
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

**Prompt:** On a RHEL 8 system using GNOME3, configure the system to disable the default behavior whereby pressing Ctrl-Alt-Del in the graphical user interface initiates a reboot. To prevent both accidental and intentional disruptions caused by this shortcut, write an idempotent bash remediation script that effectively disables Ctrl-Alt-Del from rebooting the system while in the GUI, ensures this configuration is locked to prevent user changes, and persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Disable Ctrl-Alt-Del reboot behavior in GNOME3 (RHEL 8)
# Idempotent remediation script.

set -euo pipefail

# --- Configuration paths ---
DCONF_DB_DIR="/etc/dconf/db/local.d"
DCONF_LOCK_DIR="/etc/dconf/db/local.d/locks"
DCONF_PROFILE="/etc/dconf/profile/user"
SETTINGS_FILE="${DCONF_DB_DIR}/00-disable-CAD"
LOCK_FILE="${DCONF_LOCK_DIR}/00-disable-CAD"

# --- Ensure required directories exist ---
mkdir -p "${DCONF_DB_DIR}"
mkdir -p "${DCONF_LOCK_DIR}"
mkdir -p "$(dirname "${DCONF_PROFILE}")"

# --- Ensure the dconf user profile references the local database ---
if [ ! -f "${DCONF_PROFILE}" ]; then
    cat > "${DCONF_PROFILE}" <<'EOF'
user-db:user
system-db:local
EOF
else
    grep -qxF "user-db:user" "${DCONF_PROFILE}" || \
        sed -i '1i user-db:user' "${DCONF_PROFILE}"
    grep -qxF "system-db:local" "${DCONF_PROFILE}" || \
        echo "system-db:local" >> "${DCONF_PROFILE}"
fi

# --- Write the GNOME setting to disable Ctrl-Alt-Del logout/reboot binding ---
DESIRED_SETTINGS="[org/gnome/settings-daemon/plugins/media-keys]
logout=''"

if [ ! -f "${SETTINGS_FILE}" ] || \
   [ "$(cat "${SETTINGS_FILE}")" != "${DESIRED_SETTINGS}" ]; then
    printf '%s\n' "${DESIRED_SETTINGS}" > "${SETTINGS_FILE}"
fi

# --- Lock the setting to prevent user changes ---
LOCK_LINE="/org/gnome/settings-daemon/plugins/media-keys/logout"

if [ ! -f "${LOCK_FILE}" ] || ! grep -qxF "${LOCK_LINE}" "${LOCK_FILE}"; then
    printf '%s\n' "${LOCK_LINE}" > "${LOCK_FILE}"
fi

# --- Mask the systemd ctrl-alt-del.target to disable the reboot action ---
# This provides an additional layer ensuring Ctrl-Alt-Del does not reboot.
if [ "$(systemctl is-enabled ctrl-alt-del.target 2>/dev/null || true)" != "masked" ]; then
    systemctl mask ctrl-alt-del.target
fi

# --- Update the dconf system databases ---
dconf update

echo "Ctrl-Alt-Del reboot has been disabled and locked."
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

**Prompt:** On a RHEL 8 system, ensure that the sudo command requires re-authentication each time it is executed, eliminating the grace period during which privilege can be re-escalated without re-entering the password. Write an idempotent bash remediation script that configures the sudo subsystem so that re-authentication is mandatory for every sudo invocation, and ensure this setting persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

DROPIN_DIR="/etc/sudoers.d"
DROPIN_FILE="${DROPIN_DIR}/99-timestamp-timeout"
SETTING="Defaults timestamp_timeout=0"

# Ensure sudoers.d directory exists with correct permissions
if [ ! -d "${DROPIN_DIR}" ]; then
    mkdir -p "${DROPIN_DIR}"
    chmod 0750 "${DROPIN_DIR}"
fi

# Remove any existing timestamp_timeout settings from main sudoers file
if grep -Eq '^[[:space:]]*Defaults.*timestamp_timeout' /etc/sudoers 2>/dev/null; then
    cp -a /etc/sudoers /etc/sudoers.bak.$(date +%Y%m%d%H%M%S)
    sed -i -E '/^[[:space:]]*Defaults.*timestamp_timeout/d' /etc/sudoers
fi

# Remove timestamp_timeout settings from any other drop-in files (except our target)
if [ -d "${DROPIN_DIR}" ]; then
    for f in "${DROPIN_DIR}"/*; do
        [ -e "${f}" ] || continue
        [ "${f}" = "${DROPIN_FILE}" ] && continue
        if grep -Eq '^[[:space:]]*Defaults.*timestamp_timeout' "${f}" 2>/dev/null; then
            sed -i -E '/^[[:space:]]*Defaults.*timestamp_timeout/d' "${f}"
        fi
    done
fi

# Write the desired setting to the drop-in file (idempotent)
TMP_FILE="$(mktemp)"
printf '%s\n' "${SETTING}" > "${TMP_FILE}"

if [ ! -f "${DROPIN_FILE}" ] || ! diff -q "${TMP_FILE}" "${DROPIN_FILE}" >/dev/null 2>&1; then
    # Validate syntax before installing
    if visudo -cf "${TMP_FILE}" >/dev/null 2>&1; then
        install -m 0440 -o root -g root "${TMP_FILE}" "${DROPIN_FILE}"
    else
        rm -f "${TMP_FILE}"
        echo "ERROR: sudoers syntax validation failed" >&2
        exit 1
    fi
fi

rm -f "${TMP_FILE}"

# Ensure correct permissions on the drop-in file
chmod 0440 "${DROPIN_FILE}"
chown root:root "${DROPIN_FILE}"

# Final validation of the entire sudoers configuration
if ! visudo -c >/dev/null 2>&1; then
    echo "ERROR: overall sudoers validation failed" >&2
    exit 1
fi

echo "sudo re-authentication is now required for every invocation (timestamp_timeout=0)."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q sudo; then

var_sudo_timestamp_timeout='
```


---

## RHEL-08-010383 — `sudoers_validate_passwd`

**Prompt:** On a RHEL 8 system, configure the sudoers policy so that the invoking user's password is always required for privilege escalation via sudo, rather than the target or root user passwords. Write an idempotent bash remediation script that ensures this password requirement is enforced for all sudo operations.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Idempotent remediation: ensure sudo requires the invoking user's password
# (rootpw, targetpw, and runaspw must NOT be enabled).
#
set -euo pipefail

SUDOERS_FILE="/etc/sudoers"
DROPIN_DIR="/etc/sudoers.d"
REMEDIATION_FILE="${DROPIN_DIR}/99-require-invoker-password"

# Must be run as root
if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

# Ensure the sudoers.d directory exists with correct perms
if [[ ! -d "${DROPIN_DIR}" ]]; then
    install -d -m 0750 "${DROPIN_DIR}"
fi

# Backup helper
backup_file() {
    local f="$1"
    if [[ -f "$f" ]]; then
        cp -a --no-clobber "$f" "${f}.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
    fi
}

# Comment out any Defaults lines enabling rootpw, targetpw, or runaspw
# in a given file (only active, uncommented lines).
neutralize_pw_defaults() {
    local file="$1"
    [[ -f "$file" ]] || return 0

    # Match lines like:  Defaults   rootpw
    #                    Defaults:user targetpw
    #                    Defaults !rootpw  (leave negations alone - they already disable)
    # We only comment lines that ENABLE these options.
    if grep -Eq '^[[:space:]]*Defaults[^#]*[[:space:]!]*(rootpw|targetpw|runaspw)([[:space:]]|=|$)' "$file"; then
        # Determine which lines actually enable (not those preceded by '!')
        if grep -Eq '^[[:space:]]*Defaults[^#]*[[:space:]](rootpw|targetpw|runaspw)([[:space:]]|=|$)' "$file" \
           && ! grep -Eq '^[[:space:]]*Defaults[^#]*![[:space:]]*(rootpw|targetpw|runaspw)' "$file"; then
            backup_file "$file"
        fi
        # Comment out enabling occurrences
        sed -r -i \
            's/^([[:space:]]*Defaults[^#]*[[:space:]])(rootpw|targetpw|runaspw)([[:space:]]|=|$)/# \1\2\3/' \
            "$file" 2>/dev/null || true
    fi
}

# Neutralize in main sudoers file
neutralize_pw_defaults "${SUDOERS_FILE}"

# Neutralize in all drop-in files (except our remediation file)
if [[ -d "${DROPIN_DIR}" ]]; then
    while IFS= read -r -d '' f; do
        [[ "$f" == "${REMEDIATION_FILE}" ]] && continue
        neutralize_pw_defaults "$f"
    done < <(find "${DROPIN_DIR}" -maxdepth 1 -type f -print0)
fi

# Desired content for our remediation drop-in.
# Explicitly disable rootpw/targetpw/runaspw so the invoking user's
# own password is always used. Also require authentication.
DESIRED_CONTENT=$(cat <<'EOF'
# Managed by remediation script - do not edit manually.
# Ensure the invoking user's password (not root/target) is required for sudo.
Defaults !rootpw
Defaults !targetpw
Defaults !runaspw
Defaults authenticate
EOF
)

# Write drop-in only if content differs (idempotency)
write_needed=1
if [[ -f "${REMEDIATION_FILE}" ]]; then
    if [[ "$(cat "${REMEDIATION_FILE}")" == "${DESIRED_CONTENT}" ]]; then
        write_needed=0
    fi
fi

if [[ "${write_needed}" -eq 1 ]]; then
    tmpfile="$(mktemp)"
    printf '%s\n' "${DESIRED_CONTENT}" > "${tmpfile}"

    # Validate the resulting configuration before applying
    if visudo -cf "${tmpfile}" >/dev/null 2>&1; then
        install -m 0440 -o root -g root "${tmpfile}" "${REMEDIATION_FILE}"
    else
        rm -f "${tmpfile}"
        echo "ERROR: Generated sudoers content failed validation. Aborting." >&2
        exit 1
    fi
    rm -f "${tmpfile}"
fi

# Ensure correct permissions on the drop-in even if unchanged
if [[ -f "${REMEDIATION_FILE}" ]]; then
    chown root:root "${REMEDIATION_FILE}"
    chmod 0440 "${REMEDIATION_FILE}"
fi

# Final full validation of the entire sudoers configuration
if ! visudo -c >/dev/null 2>&1; then
    echo "ERROR: sudoers configuration is invalid after remediation!" >&2
    exit 1
fi

echo "Remediation complete: sudo now requires the invoking user's password."
exit 0
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

**Prompt:** On a RHEL 8 system, ensure the proper functioning of hardware random number generators by installing the rng-tools package. Write an idempotent bash remediation script that confirms the package is installed and available, thereby supporting cryptographic functions that rely on high-quality randomness.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation script: Ensure rng-tools package is installed on RHEL 8
# Purpose: Support hardware random number generators for cryptographic functions
# Idempotent: Safe to run multiple times.

set -euo pipefail

PACKAGE="rng-tools"

# Ensure the script is run as root
if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

# Determine the available package manager
if command -v dnf >/dev/null 2>&1; then
    PKG_MGR="dnf"
elif command -v yum >/dev/null 2>&1; then
    PKG_MGR="yum"
else
    echo "ERROR: Neither dnf nor yum package manager was found." >&2
    exit 1
fi

# Check whether the package is already installed
if rpm -q "${PACKAGE}" >/dev/null 2>&1; then
    echo "Package '${PACKAGE}' is already installed. No action required."
else
    echo "Package '${PACKAGE}' is not installed. Installing now..."
    "${PKG_MGR}" install -y "${PACKAGE}"
fi

# Verify installation succeeded
if rpm -q "${PACKAGE}" >/dev/null 2>&1; then
    echo "Verification successful: '${PACKAGE}' is installed and available."
    exit 0
else
    echo "ERROR: Failed to install '${PACKAGE}'." >&2
    exit 1
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

**Prompt:** On a RHEL 8 system, the presence of the gssproxy package may introduce compatibility issues with site security policies, such as FIPS 140 compliance. Write an idempotent bash remediation script that uninstalls the gssproxy package, ensuring it is not present on the system to avoid potential policy violations.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation script: Ensure the gssproxy package is not installed on RHEL 8.
#
# This script is idempotent: if gssproxy is already absent, it does nothing
# and exits successfully.

set -o nounset
set -o pipefail

PACKAGE="gssproxy"

# Ensure the script is run with root privileges.
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

# Determine which package manager to use.
if command -v dnf >/dev/null 2>&1; then
    PKG_MGR="dnf"
elif command -v yum >/dev/null 2>&1; then
    PKG_MGR="yum"
elif command -v rpm >/dev/null 2>&1; then
    PKG_MGR="rpm"
else
    echo "ERROR: No supported package manager (dnf/yum/rpm) found." >&2
    exit 1
fi

# Check whether the package is currently installed.
if rpm -q "${PACKAGE}" >/dev/null 2>&1; then
    echo "Package '${PACKAGE}' is installed. Removing it..."

    case "${PKG_MGR}" in
        dnf)
            dnf -y remove "${PACKAGE}"
            ;;
        yum)
            yum -y remove "${PACKAGE}"
            ;;
        rpm)
            rpm -e "${PACKAGE}"
            ;;
    esac

    # Verify removal.
    if rpm -q "${PACKAGE}" >/dev/null 2>&1; then
        echo "ERROR: Failed to remove package '${PACKAGE}'." >&2
        exit 1
    fi

    echo "Package '${PACKAGE}' successfully removed."
else
    echo "Package '${PACKAGE}' is not installed. No action required."
fi

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

**Prompt:** On a RHEL 8 system, the presence of the iprutils package, which provides utilities specific to certain SCSI devices, may not be necessary and can potentially introduce security risks if not managed properly. Write an idempotent bash remediation script that ensures the iprutils package is completely uninstalled from the system, preventing any inadvertent use of these tools.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PACKAGE="iprutils"

if rpm -q "$PACKAGE" &>/dev/null; then
    echo "Package '$PACKAGE' is installed. Removing..."
    if yum remove -y "$PACKAGE"; then
        echo "Package '$PACKAGE' successfully removed."
    else
        echo "Failed to remove package '$PACKAGE'." >&2
        exit 1
    fi
else
    echo "Package '$PACKAGE' is not installed. No action needed."
fi

if rpm -q "$PACKAGE" &>/dev/null; then
    echo "Package '$PACKAGE' is still present after remediation." >&2
    exit 1
fi

echo "Remediation complete: '$PACKAGE' is not present on the system."
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

**Prompt:** On a RHEL 8 system, the package 'libreport-plugin-rhtsupport', which facilitates reporting bugs to the Red Hat Support system, should be uninstalled to minimize unnecessary software and limit potential attack vectors. Develop an idempotent bash remediation script that ensures this package is removed from the system.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PACKAGE="libreport-plugin-rhtsupport"

if rpm -q "${PACKAGE}" &>/dev/null; then
    echo "Package '${PACKAGE}' is installed. Removing..."
    yum remove -y "${PACKAGE}"
    echo "Package '${PACKAGE}' has been removed."
else
    echo "Package '${PACKAGE}' is not installed. No action required."
fi
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

**Prompt:** On a RHEL 8 system, the tuned package and its associated tuning daemon can introduce modifications to system settings that may not align with your security policies or operational requirements. Write an idempotent bash remediation script that uninstalls the tuned package to ensure it is not present on the system.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PACKAGE="tuned"

if rpm -q "${PACKAGE}" >/dev/null 2>&1; then
    echo "Package '${PACKAGE}' is installed. Attempting to stop and disable the service."

    if systemctl is-active "${PACKAGE}.service" >/dev/null 2>&1; then
        systemctl stop "${PACKAGE}.service" || true
    fi

    if systemctl is-enabled "${PACKAGE}.service" >/dev/null 2>&1; then
        systemctl disable "${PACKAGE}.service" || true
    fi

    echo "Removing package '${PACKAGE}'."
    yum -y remove "${PACKAGE}"

    if rpm -q "${PACKAGE}" >/dev/null 2>&1; then
        echo "ERROR: Failed to remove package '${PACKAGE}'." >&2
        exit 1
    else
        echo "Package '${PACKAGE}' successfully removed."
    fi
else
    echo "Package '${PACKAGE}' is not installed. No action required."
fi

exit 0
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

**Prompt:** On a RHEL 8 system, ensure that all locally installed software packages are verified against a trusted source to prevent tampering. To achieve this, configure the package management system to require signature verification of local package files prior to installation. This configuration must be idempotent and must persist across system reboots, ensuring gpgcheck for local packages is always enabled.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

DNF_CONF="/etc/dnf/dnf.conf"

# Ensure the config file exists
if [[ ! -f "$DNF_CONF" ]]; then
    echo "[main]" > "$DNF_CONF"
fi

# Ensure a [main] section exists
if ! grep -q '^\[main\]' "$DNF_CONF"; then
    sed -i '1i [main]' "$DNF_CONF"
fi

# Idempotently set localpkg_gpgcheck=1 within the [main] section
if grep -Eq '^\s*localpkg_gpgcheck\s*=' "$DNF_CONF"; then
    sed -i -E 's/^\s*localpkg_gpgcheck\s*=.*/localpkg_gpgcheck=1/' "$DNF_CONF"
else
    # Insert right after the [main] section header
    sed -i '/^\[main\]/a localpkg_gpgcheck=1' "$DNF_CONF"
fi

# Verify the setting
if grep -Eq '^\s*localpkg_gpgcheck\s*=\s*1\s*$' "$DNF_CONF"; then
    echo "localpkg_gpgcheck is enabled in $DNF_CONF"
else
    echo "Failed to set localpkg_gpgcheck in $DNF_CONF" >&2
    exit 1
fi
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

**Prompt:** On a RHEL 8 system, ensure that the user authentication mechanism is managed by 'authselect', the default tool that provides a standardized method for system authentication and identity source configuration through supported profiles, thereby reducing the risk of misconfiguration in the PAM stack. Write a bash remediation script that checks if an authselect profile is active, and if not, enables the 'sssd' profile with the default options, ensuring persistence across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation script: ensure authselect manages system authentication.
# If no authselect profile is currently active, enable the 'sssd' profile
# with default options and force the configuration so it persists.

set -o nounset
set -o pipefail

# Ensure the authselect binary is available.
if ! command -v authselect >/dev/null 2>&1; then
    echo "ERROR: 'authselect' is not installed. Attempting to install it..."
    if command -v dnf >/dev/null 2>&1; then
        dnf install -y authselect || {
            echo "ERROR: Failed to install authselect. Aborting."
            exit 1
        }
    elif command -v yum >/dev/null 2>&1; then
        yum install -y authselect || {
            echo "ERROR: Failed to install authselect. Aborting."
            exit 1
        }
    else
        echo "ERROR: No supported package manager found to install authselect."
        exit 1
    fi
fi

# Determine whether an authselect profile is currently active.
# 'authselect current' returns non-zero and prints "No existing configuration detected"
# when no profile is selected.
current_output="$(authselect current 2>&1)"
current_rc=$?

if [ "${current_rc}" -eq 0 ] && ! echo "${current_output}" | grep -qi "No existing configuration"; then
    echo "An authselect profile is already active:"
    echo "${current_output}"
    echo "No changes required."
    exit 0
fi

echo "No active authselect profile detected. Enabling the 'sssd' profile..."

# Try to select the sssd profile with default options.
if authselect select sssd --backup=authselect-backup-"$(date +%Y%m%d-%H%M%S)"; then
    echo "Successfully selected the 'sssd' profile."
else
    echo "Standard selection failed (likely due to existing unmanaged files)."
    echo "Retrying with --force to overwrite the current PAM/nsswitch configuration..."
    if authselect select sssd --force --backup=authselect-backup-"$(date +%Y%m%d-%H%M%S)"; then
        echo "Successfully selected the 'sssd' profile using --force."
    else
        echo "ERROR: Failed to enable the 'sssd' authselect profile."
        exit 1
    fi
fi

# Apply/ensure the configuration is written to the system files for persistence.
if authselect apply-changes 2>/dev/null; then
    echo "authselect changes applied."
else
    # apply-changes may not exist on all versions; select already applies changes.
    echo "Note: 'apply-changes' not required or unavailable on this version."
fi

# Verify the resulting configuration.
echo "Verifying active authselect configuration..."
if authselect current >/dev/null 2>&1; then
    authselect current
    echo "authselect is now managing system authentication."
    exit 0
else
    echo "ERROR: authselect profile could not be verified as active."
    exit 1
fi
```

**Reference fix:**
```bash
var_authselect_profile='
```


---

## RHEL-08-010060 — `banner_etc_issue`

**Prompt:** On a RHEL 8 system, configure the system's login banner to display a specific message before granting access. The message should comply with the DoD requirement, as described: "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only..." (full text truncated for brevity). Write an idempotent bash remediation script that replaces the current login banner message with this approved use notification, ensuring that it persists across reboots and is visible on all login interfaces where human users may access the system.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Idempotent remediation script to configure the DoD login banner on RHEL 8.
# Configures /etc/issue (local console), /etc/issue.net (network/telnet),
# and the SSH daemon banner so the notification is visible on all interfaces
# where human users may access the system.
#
set -euo pipefail

# --- The DoD approved use notification banner text -------------------------
read -r -d '' BANNER_TEXT <<'EOF' || true
You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions: -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. -At any time, the USG may inspect and seize data stored on this IS. -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.
EOF

BANNER_FILE="/etc/issue"
BANNER_NET_FILE="/etc/issue.net"
SSHD_CONFIG="/etc/ssh/sshd_config"
SSH_BANNER_FILE="/etc/issue.net"

# --- Helper: write banner file only if content differs (idempotent) --------
write_banner_file() {
    local target="$1"
    local tmp
    tmp="$(mktemp)"
    printf '%s\n' "$BANNER_TEXT" > "$tmp"

    if [[ -f "$target" ]] && cmp -s "$tmp" "$target"; then
        echo "Banner already correct: $target"
        rm -f "$tmp"
    else
        install -m 0644 -o root -g root "$tmp" "$target"
        rm -f "$tmp"
        echo "Updated banner: $target"
    fi
}

# --- Configure local and network login banners -----------------------------
write_banner_file "$BANNER_FILE"
write_banner_file "$BANNER_NET_FILE"

# --- Configure the SSH daemon to present the banner ------------------------
if [[ -f "$SSHD_CONFIG" ]]; then
    # Remove any commented or existing Banner directives, then set ours.
    if grep -qiE '^\s*#?\s*Banner\b' "$SSHD_CONFIG"; then
        sed -i -E "s|^\s*#?\s*Banner\b.*|Banner ${SSH_BANNER_FILE}|I" "$SSHD_CONFIG"
    else
        printf 'Banner %s\n' "$SSH_BANNER_FILE" >> "$SSHD_CONFIG"
    fi

    # Collapse potential duplicate Banner lines, keeping the last one.
    if [[ $(grep -ciE '^\s*Banner\b' "$SSHD_CONFIG") -gt 1 ]]; then
        awk '
            /^[[:space:]]*Banner[[:space:]]/ { last=NR; lines[NR]=$0; next }
            { print }
            END { }
        ' "$SSHD_CONFIG" > /dev/null 2>&1 || true
        # Simpler robust approach: strip all Banner lines then append once.
        sed -i -E '/^\s*Banner\b/Id' "$SSHD_CONFIG"
        printf 'Banner %s\n' "$SSH_BANNER_FILE" >> "$SSHD_CONFIG"
    fi
    echo "Configured SSH Banner directive in $SSHD_CONFIG"

    # Validate configuration and reload sshd if it is active.
    if command -v sshd >/dev/null 2>&1; then
        if sshd -t 2>/dev/null; then
            if systemctl is-active --quiet sshd 2>/dev/null; then
                systemctl reload sshd || systemctl restart sshd || true
                echo "Reloaded sshd service."
            fi
        else
            echo "WARNING: sshd config validation failed; not reloading." >&2
        fi
    fi
else
    echo "WARNING: $SSHD_CONFIG not found; skipping SSH banner configuration." >&2
fi

# --- Configure GDM graphical login banner if GNOME/dconf present -----------
if command -v dconf >/dev/null 2>&1 && [[ -d /etc/dconf/db ]]; then
    GDM_PROFILE_DIR="/etc/dconf/profile"
    GDM_DB_DIR="/etc/dconf/db/gdm.d"
    mkdir -p "$GDM_PROFILE_DIR" "$GDM_DB_DIR"

    GDM_PROFILE="$GDM_PROFILE_DIR/gdm"
    if [[ ! -f "$GDM_PROFILE" ]] || ! grep -q '^user-db:user' "$GDM_PROFILE"; then
        cat > "$GDM_PROFILE" <<'PEOF'
user-db:user
system-db:gdm
file-db:/usr/share/gdm/greeter-dconf-defaults
PEOF
        echo "Configured dconf gdm profile."
    fi

    # dconf strings escape newlines; build single-line message.
    ESCAPED_MSG="$(printf '%s' "$BANNER_TEXT" | sed "s/'/\\\\'/g")"
    GDM_BANNER_CONF="$GDM_DB_DIR/01-banner-message"
    NEW_CONF="$(cat <<EOF
[org/gnome/login-screen]
banner-message-enable=true
banner-message-text='${ESCAPED_MSG}'
EOF
)"
    if [[ ! -f "$GDM_BANNER_CONF" ]] || [[ "$(cat "$GDM_BANNER_CONF")" != "$NEW_CONF" ]]; then
        printf '%s\n' "$NEW_CONF" > "$GDM_BANNER_CONF"
        chmod 0644 "$GDM_BANNER_CONF"
        echo "Configured GDM banner message."
    else
        echo "GDM banner already correct."
    fi

    dconf update || true
fi

echo "Login banner remediation complete."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

login_banner_text='
```


---

## RHEL-08-010049 — `dconf_gnome_banner_enabled`

**Prompt:** On a RHEL 8 system using the GNOME Display Manager, configure the login screen to display a security warning banner, ensuring the message appears consistently across graphical logins and aligns with security policies. The banner must be enforced and unmodifiable by users. Write an idempotent bash remediation script that enables and locks this login message feature, ensuring both the configuration and the lock file are applied persistently and that the system is updated accordingly.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Configure and enforce the GDM login screen security warning banner on RHEL 8.
# Idempotent remediation script.
#
set -euo pipefail

BANNER_TEXT='This system is for the use of authorized users only. Individuals using this computer system without authority, or in excess of their authority, are subject to having all of their activities on this system monitored and recorded by system personnel.'

DCONF_PROFILE="/etc/dconf/profile/gdm"
DCONF_DB_DIR="/etc/dconf/db/gdm.d"
DCONF_LOCK_DIR="/etc/dconf/db/gdm.d/locks"
DCONF_KEYFILE="${DCONF_DB_DIR}/00-security-settings"
DCONF_LOCKFILE="${DCONF_LOCK_DIR}/00-security-settings-lock"

# Ensure GDM/dconf packages are present.
if ! rpm -q gdm >/dev/null 2>&1; then
    yum install -y gdm
fi
if ! rpm -q dconf >/dev/null 2>&1; then
    yum install -y dconf
fi

# Ensure the gdm dconf profile exists and references user + gdm databases.
mkdir -p "$(dirname "${DCONF_PROFILE}")"
if [ ! -f "${DCONF_PROFILE}" ] || ! grep -q '^user-db:user$' "${DCONF_PROFILE}" || ! grep -q '^system-db:gdm$' "${DCONF_PROFILE}"; then
    cat > "${DCONF_PROFILE}" <<'EOF'
user-db:user
system-db:gdm
file-db:/usr/share/gdm/greeter-dconf-defaults
EOF
fi

# Ensure directories exist.
mkdir -p "${DCONF_DB_DIR}"
mkdir -p "${DCONF_LOCK_DIR}"

# Write the keyfile enabling and setting the login banner.
cat > "${DCONF_KEYFILE}" <<EOF
[org/gnome/login-screen]
banner-message-enable=true
banner-message-text='${BANNER_TEXT}'
EOF

# Write the lock file to prevent user modification.
cat > "${DCONF_LOCKFILE}" <<'EOF'
/org/gnome/login-screen/banner-message-enable
/org/gnome/login-screen/banner-message-text
EOF

# Set correct permissions.
chmod 0644 "${DCONF_PROFILE}" "${DCONF_KEYFILE}" "${DCONF_LOCKFILE}"

# Update the dconf system databases.
dconf update

echo "GDM login banner configured, enforced, and locked."
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

**Prompt:** On a RHEL 8 system using GNOME3 for graphical logins, configure the GNOME Display Manager's login screen to display an approved warning message, reinforcing security policy awareness at user login. Ensure that this warning banner text is persistently enforced, preventing user modifications, and that it takes effect without requiring a restart of the system. The warning banner should display multi-line messages formatted correctly, if applicable. Write an idempotent bash remediation script achieving this.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

# Approved warning banner text
BANNER_TEXT="You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions: -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. -At any time, the USG may inspect and seize data stored on this IS. -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

# Ensure dconf directory structure exists
mkdir -p /etc/dconf/db/gdm.d
mkdir -p /etc/dconf/db/gdm.d/locks

# Create/update the gdm profile so the gdm database is used
PROFILE_FILE="/etc/dconf/profile/gdm"
cat > "${PROFILE_FILE}" <<'EOF'
user-db:user
system-db:gdm
file-db:/usr/share/gdm/greeter-dconf-defaults
EOF

# Escape the banner text for the dconf key (single-quoted GVariant string).
# Backslashes and single quotes must be escaped.
ESCAPED_TEXT="${BANNER_TEXT//\\/\\\\}"
ESCAPED_TEXT="${ESCAPED_TEXT//\'/\\\'}"

# Configure the banner in the gdm database
BANNER_CONF="/etc/dconf/db/gdm.d/01-banner-message"
cat > "${BANNER_CONF}" <<EOF
[org/gnome/login-screen]
banner-message-enable=true
banner-message-text='${ESCAPED_TEXT}'
EOF

# Lock the settings to prevent user modification
LOCK_CONF="/etc/dconf/db/gdm.d/locks/01-banner-message-lock"
cat > "${LOCK_CONF}" <<'EOF'
/org/gnome/login-screen/banner-message-enable
/org/gnome/login-screen/banner-message-text
EOF

# Update the dconf databases so changes take effect without a reboot
dconf update
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm; then

login_banner_text='
```


---

## RHEL-08-020026 — `account_password_pam_faillock_password_auth`

**Prompt:** On a RHEL 8 system, ensure that the PAM stack is configured to prevent brute-force attacks by locking out accounts after a certain number of failed login attempts. Specifically, configure the "password-auth" PAM configuration to include the pam_faillock module in the authentication section, ensuring it is present for pre-authentication checks to deny attempts after several failures. Write an idempotent bash remediation script to achieve this.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure pam_faillock preauth is configured in password-auth
# for RHEL 8 to lock out accounts after several failed login attempts.
#

set -euo pipefail

PAM_FILE="/etc/pam.d/password-auth"

# Ensure the target file exists
if [ ! -f "$PAM_FILE" ]; then
    echo "ERROR: $PAM_FILE does not exist. Aborting." >&2
    exit 1
fi

# The preauth line we want to guarantee is present.
PREAUTH_LINE="auth        required                                     pam_faillock.so preauth silent deny=5 unlock_time=900"

# Check whether a pam_faillock preauth entry already exists in the auth section.
if grep -Eq '^\s*auth\s+.*pam_faillock\.so\s+.*preauth' "$PAM_FILE"; then
    # Entry already present; nothing to do (idempotent).
    echo "pam_faillock preauth entry already present in $PAM_FILE. No changes made."
    exit 0
fi

# Create a timestamped backup before modifying.
BACKUP="${PAM_FILE}.bak.$(date +%Y%m%d%H%M%S)"
cp -p "$PAM_FILE" "$BACKUP"
echo "Backup created at $BACKUP"

# Insert the preauth line before the first 'auth' line so it performs
# pre-authentication checks before other auth modules.
if grep -Eq '^\s*auth\s' "$PAM_FILE"; then
    # Insert before the first auth line.
    awk -v ins="$PREAUTH_LINE" '
        BEGIN { done=0 }
        {
            if (!done && $0 ~ /^[[:space:]]*auth[[:space:]]/) {
                print ins
                done=1
            }
            print
        }
        END {
            if (!done) {
                print ins
            }
        }
    ' "$PAM_FILE" > "${PAM_FILE}.tmp"
else
    # No auth lines found; just append the line.
    cp "$PAM_FILE" "${PAM_FILE}.tmp"
    printf '%s\n' "$PREAUTH_LINE" >> "${PAM_FILE}.tmp"
fi

# Preserve ownership and permissions of the original file.
chown --reference="$PAM_FILE" "${PAM_FILE}.tmp"
chmod --reference="$PAM_FILE" "${PAM_FILE}.tmp"

# Replace the original file atomically.
mv "${PAM_FILE}.tmp" "$PAM_FILE"

echo "pam_faillock preauth entry added to $PAM_FILE."
exit 0
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

**Prompt:** On a RHEL 8 system, ensure that the PAM framework is configured to use the pam_faillock.so module in the system authentication service. This configuration is crucial to lock accounts following too many failed login attempts, effectively mitigating password guessing attacks. Write an idempotent bash remediation script to ensure that this module is properly invoked in the system authentication configuration, specifically at the pre-authentication phase.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Idempotent remediation to ensure pam_faillock.so is invoked at the
# pre-authentication phase in the system-auth PAM configuration on RHEL 8.
#

set -o pipefail

PAM_FILE="/etc/pam.d/system-auth"

if [ ! -f "$PAM_FILE" ]; then
    echo "ERROR: $PAM_FILE not found. Cannot continue." >&2
    exit 1
fi

# Backup the original file (timestamped) if not already backed up today.
BACKUP="${PAM_FILE}.bak.$(date +%Y%m%d)"
if [ ! -f "$BACKUP" ]; then
    cp -p "$PAM_FILE" "$BACKUP"
fi

# Check whether the pre-authentication faillock line already exists.
# The pre-auth line should be:
#   auth  required  pam_faillock.so preauth ...
if grep -Pq '^\s*auth\s+(required|requisite|\[[^]]+\])\s+pam_faillock\.so\s+.*preauth' "$PAM_FILE"; then
    echo "pam_faillock.so preauth already configured in $PAM_FILE."
    exit 0
fi

# Determine insertion point: pam_faillock preauth must be placed before the
# first pam_unix.so auth line.
TMP_FILE="$(mktemp)"

# Line to insert
PREAUTH_LINE="auth        required                                     pam_faillock.so preauth"

inserted=0
while IFS= read -r line || [ -n "$line" ]; do
    # Insert before the first pam_unix.so auth line.
    if [ "$inserted" -eq 0 ] && echo "$line" | grep -Pq '^\s*auth\s+.*\s+pam_unix\.so'; then
        printf '%s\n' "$PREAUTH_LINE" >> "$TMP_FILE"
        inserted=1
    fi
    printf '%s\n' "$line" >> "$TMP_FILE"
done < "$PAM_FILE"

# If no pam_unix.so auth line was found, append the preauth line at the end
# of the auth block (fall back to appending after the first auth line).
if [ "$inserted" -eq 0 ]; then
    rm -f "$TMP_FILE"
    TMP_FILE="$(mktemp)"
    while IFS= read -r line || [ -n "$line" ]; do
        printf '%s\n' "$line" >> "$TMP_FILE"
        if [ "$inserted" -eq 0 ] && echo "$line" | grep -Pq '^\s*auth\s'; then
            printf '%s\n' "$PREAUTH_LINE" >> "$TMP_FILE"
            inserted=1
        fi
    done < "$PAM_FILE"
fi

# If still not inserted (no auth lines at all), prepend it.
if [ "$inserted" -eq 0 ]; then
    printf '%s\n' "$PREAUTH_LINE" > "$TMP_FILE"
    cat "$PAM_FILE" >> "$TMP_FILE"
fi

# Apply the changes preserving ownership and permissions.
cat "$TMP_FILE" > "$PAM_FILE"
rm -f "$TMP_FILE"

echo "Configured pam_faillock.so preauth in $PAM_FILE."
exit 0
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

**Prompt:** On a RHEL 8 system, configure the PAM system so that any account lockouts resulting from excessive password failures are logged. This ensures that security personnel can review failed login attempts and identify potential unauthorized access attempts. Write an idempotent bash remediation script to securely log these lockout events, ensuring this logging configuration persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure PAM faillock lockout events are logged on RHEL 8.
#
# This script configures faillock (via /etc/security/faillock.conf) to enable
# audit logging of account lockout events, and ensures the pam_faillock
# module is present in the appropriate PAM stacks. It is idempotent and
# persists across reboots.

set -euo pipefail

FAILLOCK_CONF="/etc/security/faillock.conf"
PAM_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")

log() {
    echo "[remediate-faillock-logging] $*"
}

#------------------------------------------------------------------------------
# 1. Configure /etc/security/faillock.conf to enable audit logging.
#------------------------------------------------------------------------------
configure_faillock_conf() {
    if [[ ! -f "$FAILLOCK_CONF" ]]; then
        log "Creating $FAILLOCK_CONF"
        touch "$FAILLOCK_CONF"
        chown root:root "$FAILLOCK_CONF"
        chmod 0644 "$FAILLOCK_CONF"
    fi

    # The 'audit' directive causes faillock to log the user name that is denied
    # access due to too many authentication failures via the audit subsystem.
    if grep -Eq '^\s*audit\b' "$FAILLOCK_CONF"; then
        log "'audit' directive already present in $FAILLOCK_CONF"
    else
        log "Enabling 'audit' directive in $FAILLOCK_CONF"
        printf '\n# Log account lockout events for security review\naudit\n' >> "$FAILLOCK_CONF"
    fi

    # Ensure permissions are secure.
    chown root:root "$FAILLOCK_CONF"
    chmod 0644 "$FAILLOCK_CONF"
}

#------------------------------------------------------------------------------
# 2. Ensure pam_faillock is present in the PAM stacks with audit logging.
#    On RHEL 8, using authselect is the supported/idempotent method.
#------------------------------------------------------------------------------
configure_via_authselect() {
    # Enable the faillock feature via authselect if a profile is selected.
    if authselect current >/dev/null 2>&1; then
        log "authselect profile detected; enabling with-faillock feature"

        # enable-feature is idempotent; enabling an already-enabled feature is a no-op.
        authselect enable-feature with-faillock || true

        # Apply changes to the live configuration.
        authselect apply-changes -b 2>/dev/null || authselect apply-changes || true
        return 0
    fi

    return 1
}

#------------------------------------------------------------------------------
# 3. Fallback: directly ensure pam_faillock lines exist with 'audit' option
#    in the PAM files (used only if authselect is not managing the config).
#------------------------------------------------------------------------------
configure_pam_files_directly() {
    local file="$1"

    [[ -f "$file" ]] || { log "Skipping missing $file"; return 0; }

    # Ensure preauth line exists with audit option.
    if grep -Eq '^\s*auth\s+.*pam_faillock\.so\s+preauth' "$file"; then
        # Add 'audit' if not present on the preauth line.
        if ! grep -E '^\s*auth\s+.*pam_faillock\.so\s+preauth' "$file" | grep -q '\baudit\b'; then
            log "Adding 'audit' to existing preauth pam_faillock line in $file"
            sed -ri '/^\s*auth\s+.*pam_faillock\.so\s+preauth/ s/(pam_faillock\.so\s+preauth)/\1 audit/' "$file"
        else
            log "preauth pam_faillock already logs (audit) in $file"
        fi
    else
        log "Adding preauth pam_faillock (with audit) to $file"
        sed -ri '0,/^\s*auth\s+/ s//auth        required                                     pam_faillock.so preauth audit silent deny=3 unlock_time=900\n&/' "$file"
    fi

    # Ensure authfail line exists with audit option.
    if grep -Eq '^\s*auth\s+.*pam_faillock\.so\s+authfail' "$file"; then
        if ! grep -E '^\s*auth\s+.*pam_faillock\.so\s+authfail' "$file" | grep -q '\baudit\b'; then
            log "Adding 'audit' to existing authfail pam_faillock line in $file"
            sed -ri '/^\s*auth\s+.*pam_faillock\.so\s+authfail/ s/(pam_faillock\.so\s+authfail)/\1 audit/' "$file"
        else
            log "authfail pam_faillock already logs (audit) in $file"
        fi
    else
        log "Adding authfail pam_faillock (with audit) to $file"
        printf 'auth        [default=die]                                 pam_faillock.so authfail audit deny=3 unlock_time=900\n' >> "$file"
    fi

    # Ensure account line exists.
    if ! grep -Eq '^\s*account\s+.*pam_faillock\.so' "$file"; then
        log "Adding account pam_faillock to $file"
        printf 'account     required                                     pam_faillock.so\n' >> "$file"
    fi

    chown root:root "$file"
    chmod 0644 "$file"
}

#------------------------------------------------------------------------------
# Main
#------------------------------------------------------------------------------
main() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root." >&2
        exit 1
    fi

    configure_faillock_conf

    if configure_via_authselect; then
        log "PAM faillock configured/managed via authselect."
    else
        log "authselect not in use; configuring PAM files directly."
        for f in "${PAM_FILES[@]}"; do
            configure_pam_files_directly "$f"
        done
    fi

    log "Faillock lockout logging remediation complete."
}

main "$@"
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

**Prompt:** On a RHEL 8 system, configure the system to lock user accounts after 5 failed login attempts in order to mitigate the risk of unauthorized access from brute-force attacks. Write an idempotent bash remediation script that ensures this account lockout policy is correctly configured, utilizing any system-appropriate tools for managing PAM configuration to avoid manual errors, and ensure the policy is applied consistently across boots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation script: Lock user accounts after 5 failed login attempts on RHEL 8
# Uses authselect (system-appropriate tool) to manage PAM configuration idempotently.
#
set -euo pipefail

DENY_VALUE=5
FAILLOCK_CONF="/etc/security/faillock.conf"

# Ensure we are running as root
if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

# Ensure authselect is available
if ! command -v authselect >/dev/null 2>&1; then
    echo "ERROR: authselect is not installed. Installing..." >&2
    if command -v dnf >/dev/null 2>&1; then
        dnf install -y authselect
    elif command -v yum >/dev/null 2>&1; then
        yum install -y authselect
    else
        echo "ERROR: No supported package manager found to install authselect." >&2
        exit 1
    fi
fi

# Determine current authselect profile; if none is selected, select a sane default.
if ! authselect current >/dev/null 2>&1; then
    echo "No authselect profile currently selected. Selecting 'sssd' profile."
    authselect select sssd --force
fi

# Ensure the with-faillock feature is enabled (idempotent).
CURRENT_FEATURES="$(authselect current 2>/dev/null | grep -i 'with-faillock' || true)"
if [[ -z "$CURRENT_FEATURES" ]]; then
    echo "Enabling 'with-faillock' feature in authselect profile."
    authselect enable-feature with-faillock
else
    echo "'with-faillock' feature already enabled."
fi

# Apply the changes to generate the PAM configuration.
authselect apply-changes

# Ensure faillock.conf exists.
if [[ ! -f "$FAILLOCK_CONF" ]]; then
    touch "$FAILLOCK_CONF"
fi

# Idempotently set the 'deny' parameter in /etc/security/faillock.conf
if grep -Eq '^\s*deny\s*=' "$FAILLOCK_CONF"; then
    # Update existing (possibly commented) deny line
    sed -ri "s|^\s*#?\s*deny\s*=.*|deny = ${DENY_VALUE}|" "$FAILLOCK_CONF"
else
    echo "deny = ${DENY_VALUE}" >> "$FAILLOCK_CONF"
fi

# Verify the applied configuration
CONFIGURED_DENY="$(grep -E '^\s*deny\s*=' "$FAILLOCK_CONF" | tail -n1 | sed -E 's|^\s*deny\s*=\s*([0-9]+).*|\1|')"
if [[ "$CONFIGURED_DENY" == "$DENY_VALUE" ]]; then
    echo "SUCCESS: Account lockout policy set to deny after ${DENY_VALUE} failed attempts."
else
    echo "ERROR: Failed to verify deny = ${DENY_VALUE} in ${FAILLOCK_CONF}." >&2
    exit 1
fi

# Re-apply authselect changes to ensure consistency across boots
authselect apply-changes

echo "Account lockout configuration completed successfully."
exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_accounts_passwords_pam_faillock_deny='
```


---

## RHEL-08-020023 — `accounts_passwords_pam_faillock_deny_root`

**Prompt:** On a RHEL 8 system, configure the system-auth configuration such that the root account is locked after 3 consecutive failed login attempts. This reduces the vulnerability to brute-force attacks by limiting the number of attempts an unauthorized user can make to guess the root password. Write an idempotent bash remediation script that ensures this locking mechanism is in place using the appropriate pluggable authentication module, and make sure the rule is correctly enforced without manual file edit errors.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Idempotent remediation: lock the root account after 3 consecutive
# failed login attempts using pam_faillock on RHEL 8.
#
set -euo pipefail

PAM_FILES=(
    "/etc/pam.d/system-auth"
    "/etc/pam.d/password-auth"
)

FAILLOCK_CONF="/etc/security/faillock.conf"

# Desired parameters
DENY_VALUE=3
ROOT_OPTION="even_deny_root"

#-----------------------------------------------------------------------
# 1. Ensure /etc/security/faillock.conf contains the correct settings.
#    pam_faillock (RHEL 8.2+) reads its configuration from this file.
#-----------------------------------------------------------------------
ensure_conf_option() {
    local key="$1"
    local value="$2"
    local file="$3"

    # Create the file if missing
    [[ -f "$file" ]] || touch "$file"

    if [[ -n "$value" ]]; then
        # key = value style option
        if grep -Eq "^[[:space:]]*#?[[:space:]]*${key}[[:space:]]*=" "$file"; then
            sed -ri "s|^[[:space:]]*#?[[:space:]]*${key}[[:space:]]*=.*|${key} = ${value}|" "$file"
        else
            echo "${key} = ${value}" >> "$file"
        fi
    else
        # standalone boolean option (e.g. even_deny_root)
        if grep -Eq "^[[:space:]]*#?[[:space:]]*${key}[[:space:]]*$" "$file"; then
            sed -ri "s|^[[:space:]]*#?[[:space:]]*${key}[[:space:]]*$|${key}|" "$file"
        else
            echo "${key}" >> "$file"
        fi
    fi
}

if [[ -f "$FAILLOCK_CONF" ]] || rpm -q pam >/dev/null 2>&1; then
    ensure_conf_option "deny" "$DENY_VALUE" "$FAILLOCK_CONF"
    ensure_conf_option "$ROOT_OPTION" "" "$FAILLOCK_CONF"
fi

#-----------------------------------------------------------------------
# 2. Ensure pam_faillock is referenced in the PAM stacks.
#    We insert (idempotently) the required preauth/authfail/account lines.
#-----------------------------------------------------------------------
ensure_faillock_in_pam() {
    local file="$1"

    [[ -f "$file" ]] || return 0

    # Backup once
    if [[ ! -f "${file}.bak_faillock" ]]; then
        cp -a "$file" "${file}.bak_faillock"
    fi

    local tmp
    tmp="$(mktemp)"

    # --- auth preauth line ---
    if ! grep -Eq '^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_faillock\.so[[:space:]]+preauth' "$file"; then
        awk '
            !inserted && /^[[:space:]]*auth[[:space:]]/ {
                print "auth        required      pam_faillock.so preauth silent deny='"$DENY_VALUE"' '"$ROOT_OPTION"'";
                inserted=1
            }
            { print }
        ' "$file" > "$tmp" && cat "$tmp" > "$file"
    else
        # Update existing preauth line to enforce deny and even_deny_root
        sed -ri "s|^([[:space:]]*auth[[:space:]]+required[[:space:]]+pam_faillock\.so[[:space:]]+preauth).*|auth        required      pam_faillock.so preauth silent deny=${DENY_VALUE} ${ROOT_OPTION}|" "$file"
    fi

    # --- auth authfail line (after last pam_unix auth line) ---
    if ! grep -Eq '^[[:space:]]*auth[[:space:]]+\[default=die\][[:space:]]+pam_faillock\.so[[:space:]]+authfail' "$file"; then
        awk '
            /^[[:space:]]*auth[[:space:]]+sufficient[[:space:]]+pam_unix\.so/ {
                print;
                print "auth        [default=die] pam_faillock.so authfail deny='"$DENY_VALUE"' '"$ROOT_OPTION"'";
                added=1;
                next
            }
            { print }
            END {
                if (!added) {
                    print "auth        [default=die] pam_faillock.so authfail deny='"$DENY_VALUE"' '"$ROOT_OPTION"'"
                }
            }
        ' "$file" > "$tmp" && cat "$tmp" > "$file"
    else
        sed -ri "s|^([[:space:]]*auth[[:space:]]+\[default=die\][[:space:]]+pam_faillock\.so[[:space:]]+authfail).*|auth        [default=die] pam_faillock.so authfail deny=${DENY_VALUE} ${ROOT_OPTION}|" "$file"
    fi

    # --- account line ---
    if ! grep -Eq '^[[:space:]]*account[[:space:]]+required[[:space:]]+pam_faillock\.so' "$file"; then
        awk '
            !inserted && /^[[:space:]]*account[[:space:]]/ {
                print "account     required      pam_faillock.so";
                inserted=1
            }
            { print }
            END {
                if (!inserted) print "account     required      pam_faillock.so"
            }
        ' "$file" > "$tmp" && cat "$tmp" > "$file"
    fi

    rm -f "$tmp"
}

for f in "${PAM_FILES[@]}"; do
    ensure_faillock_in_pam "$f"
done

#-----------------------------------------------------------------------
# 3. Verify results
#-----------------------------------------------------------------------
echo "=== faillock.conf settings ==="
grep -E '^(deny|even_deny_root)' "$FAILLOCK_CONF" || true
echo
echo "=== pam_faillock entries ==="
for f in "${PAM_FILES[@]}"; do
    echo "--- $f ---"
    grep -E 'pam_faillock\.so' "$f" || true
done

echo
echo "Remediation complete: root will be locked after ${DENY_VALUE} consecutive failed attempts."
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

**Prompt:** On a RHEL 8 system, configure the authentication subsystem such that account lockouts due to multiple failed authentication attempts persist even after the system is rebooted. This change is crucial for mitigating password guessing and user enumeration attacks. Ensure that any tally directory storing the lockout data is not reset on reboot. Write an idempotent bash remediation script to achieve and verify this persisted lockout behavior using the relevant authentication management tools.

**Model-generated script:**
```bash
```bash
#!/usr/bin/env bash
#
# Remediation script: Ensure account lockouts due to failed authentication
# attempts persist across reboots on RHEL 8 (using faillock/authselect).
#
# The default faillock tally directory is /var/run/faillock which is a
# tmpfs and is cleared on reboot. To persist lockouts, we set a
# persistent 'dir' in /etc/security/faillock.conf pointing to a directory
# that survives reboot (e.g. /var/log/faillock).
#
set -euo pipefail

FAILLOCK_CONF="/etc/security/faillock.conf"
PERSIST_DIR="/var/log/faillock"
EXIT_CODE=0

echo "==> Starting persistent faillock remediation..."

#-----------------------------------------------------------------------
# 0. Sanity checks
#-----------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

if ! command -v authselect >/dev/null 2>&1; then
    echo "ERROR: authselect is not available on this system." >&2
    exit 1
fi

#-----------------------------------------------------------------------
# 1. Ensure faillock is enabled via authselect
#-----------------------------------------------------------------------
echo "==> Ensuring faillock feature is enabled via authselect..."

# Determine currently selected profile; if none, select the default sssd profile.
if ! authselect current >/dev/null 2>&1; then
    echo "    No authselect profile currently selected. Selecting sssd profile..."
    authselect select sssd --force
fi

# Enable the with-faillock feature (idempotent).
if authselect current 2>/dev/null | grep -qw "with-faillock"; then
    echo "    'with-faillock' feature already enabled."
else
    echo "    Enabling 'with-faillock' feature..."
    authselect enable-feature with-faillock
fi

# Apply the changes.
echo "==> Applying authselect changes..."
authselect apply-changes

#-----------------------------------------------------------------------
# 2. Create persistent tally directory
#-----------------------------------------------------------------------
echo "==> Ensuring persistent tally directory exists: ${PERSIST_DIR}"
if [[ ! -d "${PERSIST_DIR}" ]]; then
    mkdir -p "${PERSIST_DIR}"
    echo "    Created ${PERSIST_DIR}."
else
    echo "    ${PERSIST_DIR} already exists."
fi
# Secure permissions/ownership on the tally directory.
chown root:root "${PERSIST_DIR}"
chmod 0700 "${PERSIST_DIR}"

#-----------------------------------------------------------------------
# 3. Configure faillock.conf with a persistent 'dir'
#-----------------------------------------------------------------------
echo "==> Configuring persistent 'dir' in ${FAILLOCK_CONF}..."

# Ensure the config file exists.
if [[ ! -f "${FAILLOCK_CONF}" ]]; then
    touch "${FAILLOCK_CONF}"
    chmod 0644 "${FAILLOCK_CONF}"
fi

set_faillock_option() {
    local key="$1"
    local value="$2"
    local conf="$3"
    # Match commented or uncommented, with or without value.
    if grep -Eq "^[[:space:]]*#?[[:space:]]*${key}([[:space:]]*=.*)?[[:space:]]*$" "${conf}"; then
        # Replace existing (commented or not) entry.
        sed -ri "s|^[[:space:]]*#?[[:space:]]*${key}([[:space:]]*=.*)?[[:space:]]*$|${key} = ${value}|" "${conf}"
    else
        # Append new entry.
        printf '%s = %s\n' "${key}" "${value}" >> "${conf}"
    fi
}

# Persist tally directory.
set_faillock_option "dir" "${PERSIST_DIR}" "${FAILLOCK_CONF}"

# Ensure some sane lockout settings exist (idempotent). These support the
# overall lockout behavior; values are set only if not already present as
# uncommented directives.
ensure_option_present() {
    local key="$1"
    local value="$2"
    local conf="$3"
    if grep -Eq "^[[:space:]]*${key}([[:space:]]*=.*)?[[:space:]]*$" "${conf}"; then
        : # already actively set, leave as-is
    else
        set_faillock_option "${key}" "${value}" "${conf}"
    fi
}

ensure_option_present "deny" "3" "${FAILLOCK_CONF}"
ensure_option_present "unlock_time" "900" "${FAILLOCK_CONF}"
ensure_option_present "fail_interval" "900" "${FAILLOCK_CONF}"

#-----------------------------------------------------------------------
# 4. Verification
#-----------------------------------------------------------------------
echo "==> Verifying configuration..."

# 4a. Verify authselect feature.
if authselect current 2>/dev/null | grep -qw "with-faillock"; then
    echo "    [PASS] authselect 'with-faillock' feature is enabled."
else
    echo "    [FAIL] authselect 'with-faillock' feature is NOT enabled." >&2
    EXIT_CODE=1
fi

# 4b. Verify persistent dir directive.
if grep -Eq "^[[:space:]]*dir[[:space:]]*=[[:space:]]*${PERSIST_DIR}[[:space:]]*$" "${FAILLOCK_CONF}"; then
    echo "    [PASS] Persistent tally 'dir = ${PERSIST_DIR}' configured in ${FAILLOCK_CONF}."
else
    echo "    [FAIL] Persistent tally 'dir' not correctly set in ${FAILLOCK_CONF}." >&2
    EXIT_CODE=1
fi

# 4c. Verify the tally directory exists and is not on tmpfs (i.e. persists).
if [[ -d "${PERSIST_DIR}" ]]; then
    FSTYPE=$(stat -f -c '%T' "${PERSIST_DIR}" 2>/dev/null || echo "unknown")
    if [[ "${FSTYPE}" == "tmpfs" ]]; then
        echo "    [WARN] ${PERSIST_DIR} appears to be on tmpfs (${FSTYPE}); lockouts may not persist." >&2
        EXIT_CODE=1
    else
        echo "    [PASS] ${PERSIST_DIR} exists on persistent filesystem (${FSTYPE})."
    fi
else
    echo "    [FAIL] Persistent tally directory ${PERSIST_DIR} does not exist." >&2
    EXIT_CODE=1
fi

# 4d. Verify faillock references the persistent directory (best effort).
if command -v faillock >/dev/null 2>&1; then
    echo "    [INFO] Current faillock status (first lines):"
    faillock 2>/dev/null | head -n
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_accounts_passwords_pam_faillock_dir='
```


---

## RHEL-08-020013 — `accounts_passwords_pam_faillock_interval`

**Prompt:** On a RHEL 8 system, configure the system's authentication to lock accounts after consecutive failed login attempts within a specific time window. This reduces the risk of unauthorized access through password guessing. Write an idempotent bash remediation script to set the failed-login attempt interval to 900 seconds, ensuring this configuration is applied consistently across the system's authentication framework.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation script: Configure account lockout failed-login interval to 900 seconds
# on RHEL 8 using the pam_faillock configuration in /etc/security/faillock.conf.
#
set -o pipefail

FAILLOCK_CONF="/etc/security/faillock.conf"
KEY="fail_interval"
VALUE="900"

#############################################################################
# 1. Ensure /etc/security/faillock.conf has fail_interval = 900
#############################################################################
if [ ! -f "$FAILLOCK_CONF" ]; then
    touch "$FAILLOCK_CONF"
    chmod 0644 "$FAILLOCK_CONF"
fi

# Look for an active (uncommented) fail_interval line
if grep -Eq "^\s*${KEY}\s*=" "$FAILLOCK_CONF"; then
    # Update existing active setting if it differs
    if ! grep -Eq "^\s*${KEY}\s*=\s*${VALUE}\s*$" "$FAILLOCK_CONF"; then
        sed -ri "s|^\s*${KEY}\s*=.*$|${KEY} = ${VALUE}|" "$FAILLOCK_CONF"
    fi
elif grep -Eq "^\s*#\s*${KEY}\s*=" "$FAILLOCK_CONF"; then
    # Uncomment and set the commented default
    sed -ri "s|^\s*#\s*${KEY}\s*=.*$|${KEY} = ${VALUE}|" "$FAILLOCK_CONF"
else
    # Append a new setting
    echo "${KEY} = ${VALUE}" >> "$FAILLOCK_CONF"
fi

#############################################################################
# 2. Ensure pam_faillock is enabled in the PAM stack.
#    On RHEL 8, `authselect` manages PAM; enable the faillock feature so that
#    faillock.conf settings take effect. Fall back to direct PAM edits if
#    authselect is not in use.
#############################################################################
if command -v authselect >/dev/null 2>&1 && authselect current >/dev/null 2>&1; then
    # Enable faillock feature idempotently
    if ! authselect current | grep -q "with-faillock"; then
        authselect enable-feature with-faillock
    fi
    # Apply changes
    authselect apply-changes >/dev/null 2>&1
else
    # Direct PAM configuration fallback
    for PAMFILE in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
        [ -f "$PAMFILE" ] || continue

        # preauth line
        if ! grep -Eq "^\s*auth\s+required\s+pam_faillock\.so\s+preauth" "$PAMFILE"; then
            sed -ri "0,/^\s*auth\s+.*pam_unix\.so.*$/s//auth        required      pam_faillock.so preauth\n&/" "$PAMFILE"
        fi

        # authfail line
        if ! grep -Eq "^\s*auth\s+\[default=die\]\s+pam_faillock\.so\s+authfail" "$PAMFILE"; then
            sed -ri "/^\s*auth\s+.*pam_unix\.so.*$/a auth        [default=die]  pam_faillock.so authfail" "$PAMFILE"
        fi

        # account line
        if ! grep -Eq "^\s*account\s+required\s+pam_faillock\.so" "$PAMFILE"; then
            sed -ri "0,/^\s*account\s+.*pam_unix\.so.*$/s//account     required      pam_faillock.so\n&/" "$PAMFILE"
        fi
    done
fi

echo "faillock fail_interval configured to ${VALUE} seconds."
exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_accounts_passwords_pam_faillock_fail_interval='
```


---

## RHEL-08-020019 — `accounts_passwords_pam_faillock_silent`

**Prompt:** On a RHEL 8 system, configure the authentication subsystem to avoid showing detailed system messages upon unsuccessful login attempts which could be used to infer the existence of user accounts. Ensure that informative error messages are suppressed when there are failed login attempts by properly configuring the account lockout mechanisms using the relevant module entries. Avoid manual editing of PAM files; ensure changes are made using system tools that apply PAM configuration securely. Write an idempotent bash remediation script to achieve this setup.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Suppress informative login-failure messages that could be used
# to enumerate valid user accounts, by ensuring pam_faillock is configured
# with the "silent" option. Uses authselect (the supported system tool) so
# PAM files are not edited manually.
#
set -euo pipefail

FAILLOCK_CONF="/etc/security/faillock.conf"

log() { echo "[remediation] $*"; }

ensure_authselect() {
    if ! command -v authselect >/dev/null 2>&1; then
        log "authselect not found; installing..."
        if command -v dnf >/dev/null 2>&1; then
            dnf -y install authselect >/dev/null 2>&1 || {
                log "ERROR: failed to install authselect"; exit 1; }
        else
            log "ERROR: authselect is not available and cannot be installed"; exit 1
        fi
    fi
}

select_profile_if_needed() {
    # Determine currently selected profile. If none is selected, select a
    # sane default (sssd) with faillock enabled.
    if authselect current >/dev/null 2>&1; then
        log "authselect profile currently selected:"
        authselect current || true
    else
        log "No authselect profile selected; selecting 'sssd' with with-faillock."
        authselect select sssd with-faillock --force
    fi
}

enable_faillock_feature() {
    # Ensure the with-faillock feature is enabled for the current profile.
    if authselect current 2>/dev/null | grep -qw "with-faillock"; then
        log "with-faillock feature already enabled."
    else
        log "Enabling with-faillock feature."
        authselect enable-feature with-faillock
    fi
}

set_faillock_conf_option() {
    # Idempotently set/uncomment an option in /etc/security/faillock.conf.
    # Args: key [value]
    local key="$1"
    local value="${2:-}"
    local line

    if [ -n "$value" ]; then
        line="${key} = ${value}"
    else
        line="${key}"
    fi

    touch "$FAILLOCK_CONF"

    if grep -Eq "^[[:space:]]*#?[[:space:]]*${key}([[:space:]]|=|$)" "$FAILLOCK_CONF"; then
        # Replace the existing (possibly commented) line.
        sed -ri "s|^[[:space:]]*#?[[:space:]]*${key}([[:space:]]*=.*|[[:space:]]*)$|${line}|" "$FAILLOCK_CONF"
        # Ensure exactly the intended content on that line.
        sed -ri "s|^[[:space:]]*#?[[:space:]]*${key}([[:space:]]|=|$).*|${line}|" "$FAILLOCK_CONF"
    else
        echo "${line}" >> "$FAILLOCK_CONF"
    fi
}

configure_silent() {
    log "Configuring faillock.conf to suppress informative messages."
    # 'silent' suppresses informative messages to users on failed logins,
    # preventing account enumeration. Set reasonable lockout parameters too.
    set_faillock_conf_option "silent"
    set_faillock_conf_option "deny" "3"
    set_faillock_conf_option "unlock_time" "900"
    set_faillock_conf_option "fail_interval" "900"
}

apply_changes() {
    log "Applying authselect changes."
    authselect apply-changes -b --backup=faillock-silent-backup >/dev/null 2>&1 \
        || authselect apply-changes -b >/dev/null 2>&1 || true
}

verify() {
    log "Verification:"
    grep -E "^[[:space:]]*silent" "$FAILLOCK_CONF" >/dev/null 2>&1 \
        && log "  'silent' is set in $FAILLOCK_CONF" \
        || { log "  ERROR: 'silent' not set"; exit 1; }

    if authselect current 2>/dev/null | grep -qw "with-faillock"; then
        log "  with-faillock feature is active."
    else
        log "  WARNING: with-faillock feature not detected as active."
    fi
}

main() {
    ensure_authselect
    select_profile_if_needed
    enable_faillock_feature
    configure_silent
    apply_changes
    verify
    log "Remediation complete."
}

main "$@"
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

**Prompt:** On a RHEL 8 system, configure the PAM system to lock out user accounts for a period of 15 minutes after three consecutive failed login attempts to mitigate the risk of brute-force attacks. Ensure the configuration is persistent across reboots and applies uniformly to all local user accounts. Write an idempotent bash remediation script to achieve this security measure.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation script to lock user accounts for 15 minutes after 3
# consecutive failed login attempts on RHEL 8 using pam_faillock.
#
set -euo pipefail

DENY=3
UNLOCK_TIME=900   # 15 minutes in seconds
FAILLOCK_CONF="/etc/security/faillock.conf"
AUTH_FILE="/etc/pam.d/system-auth"
PASSWORD_FILE="/etc/pam.d/password-auth"

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

timestamp() { date +%Y%m%d%H%M%S; }

backup_file() {
    local f="$1"
    if [[ -f "$f" && ! -f "${f}.orig.bak" ]]; then
        cp -p "$f" "${f}.orig.bak"
    fi
}

#####################################################################
# 1. Configure /etc/security/faillock.conf (RHEL 8 supported method)
#####################################################################
configure_faillock_conf() {
    backup_file "$FAILLOCK_CONF"
    touch "$FAILLOCK_CONF"

    set_kv() {
        local key="$1" value="$2" file="$3"
        if grep -Eq "^[[:space:]]*#?[[:space:]]*${key}([[:space:]]*=.*)?$" "$file"; then
            sed -ri "s|^[[:space:]]*#?[[:space:]]*${key}([[:space:]]*=.*)?$|${key} = ${value}|" "$file"
        else
            printf '%s = %s\n' "$key" "$value" >> "$file"
        fi
    }

    set_bool() {
        local key="$1" file="$2"
        if grep -Eq "^[[:space:]]*#?[[:space:]]*${key}[[:space:]]*$" "$file"; then
            sed -ri "s|^[[:space:]]*#?[[:space:]]*${key}[[:space:]]*$|${key}|" "$file"
        else
            printf '%s\n' "$key" >> "$file"
        fi
    }

    set_kv "deny"        "$DENY"        "$FAILLOCK_CONF"
    set_kv "unlock_time" "$UNLOCK_TIME" "$FAILLOCK_CONF"
    set_kv "fail_interval" "900"        "$FAILLOCK_CONF"
    set_bool "even_deny_root" "$FAILLOCK_CONF"
}

#####################################################################
# 2. Ensure pam_faillock entries exist in PAM stacks
#####################################################################
configure_pam_file() {
    local file="$1"
    backup_file "$file"

    # Add preauth line before the first pam_unix.so auth line if absent
    if ! grep -Eq '^\s*auth\s+required\s+pam_faillock\.so\s+preauth' "$file"; then
        sed -ri '0,/^\s*auth\s+.*pam_unix\.so.*/{s//auth        required      pam_faillock.so preauth\n&/}' "$file"
    fi

    # Add authfail line after the first pam_unix.so auth line if absent
    if ! grep -Eq '^\s*auth\s+.*pam_faillock\.so\s+authfail' "$file"; then
        sed -ri '0,/^\s*auth\s+.*pam_unix\.so.*/{s//&\nauth        [default=die]  pam_faillock.so authfail/}' "$file"
    fi

    # Add account line if absent
    if ! grep -Eq '^\s*account\s+required\s+pam_faillock\.so' "$file"; then
        if grep -Eq '^\s*account\s+.*pam_unix\.so' "$file"; then
            sed -ri '0,/^\s*account\s+.*pam_unix\.so.*/{s//account     required      pam_faillock.so\n&/}' "$file"
        else
            printf 'account     required      pam_faillock.so\n' >> "$file"
        fi
    fi
}

#####################################################################
# Execute remediation
#####################################################################
configure_faillock_conf
configure_pam_file "$AUTH_FILE"
configure_pam_file "$PASSWORD_FILE"

echo "PAM faillock lockout policy applied:"
echo "  - deny=${DENY} failed attempts"
echo "  - unlock_time=${UNLOCK_TIME} seconds (15 minutes)"
echo "Configuration is persistent and applies to all local accounts."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_accounts_passwords_pam_faillock_unlock_time='
```


---

## RHEL-08-020130 — `accounts_password_pam_dcredit`

**Prompt:** On a RHEL 8 system, passwords currently are not required to contain any digits, which compromises their complexity and increases the risk of being cracked through guessing or brute-force attacks. Write an idempotent bash remediation script that configures the system to enforce that all user passwords contain at least one digit, making them more resistant to attacks. Ensure the change persists and applies to all future password changes.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure PAM enforces at least one digit in passwords (dcredit = -1)
# Target: RHEL 8 (pwquality)
#
set -euo pipefail

CONF_FILE="/etc/security/pwquality.conf"
PARAM="dcredit"
VALUE="-1"

# Ensure the configuration file exists
if [[ ! -f "$CONF_FILE" ]]; then
    touch "$CONF_FILE"
    chmod 0644 "$CONF_FILE"
fi

# Idempotently set dcredit = -1
if grep -Eq '^[[:space:]]*#?[[:space:]]*dcredit[[:space:]]*=' "$CONF_FILE"; then
    # Replace any existing (commented or uncommented) dcredit line
    sed -ri "s|^[[:space:]]*#?[[:space:]]*dcredit[[:space:]]*=.*|${PARAM} = ${VALUE}|" "$CONF_FILE"
else
    # Append the setting if it does not exist
    printf '%s = %s\n' "$PARAM" "$VALUE" >> "$CONF_FILE"
fi

# Verify the change
if grep -Eq "^[[:space:]]*${PARAM}[[:space:]]*=[[:space:]]*${VALUE}[[:space:]]*$" "$CONF_FILE"; then
    echo "Success: '${PARAM} = ${VALUE}' is set in ${CONF_FILE}. Passwords now require at least one digit."
else
    echo "Error: Failed to set '${PARAM} = ${VALUE}' in ${CONF_FILE}." >&2
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

**Prompt:** On a RHEL 8 system, configure the PAM subsystem to enforce strong password policies by ensuring that user passwords do not contain dictionary words. Specifically, ensure the PAM module responsible for password quality checks is configured to enable checks against dictionary words. Write an idempotent bash remediation script that implements this policy, ensuring the enforcement persists across system reconfigurations.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation script: Enforce dictionary word checks in password quality policy
# on RHEL 8 via pam_pwquality / pwquality.conf
#
# The 'dictcheck' option in pwquality controls whether passwords are checked
# against dictionary words. Setting dictcheck = 1 enables the check.
#
set -euo pipefail

PWQUALITY_CONF="/etc/security/pwquality.conf"
PWQUALITY_CONF_D="/etc/security/pwquality.conf.d"
PARAM="dictcheck"
VALUE="1"

# Ensure the main config file exists
if [[ ! -f "$PWQUALITY_CONF" ]]; then
    touch "$PWQUALITY_CONF"
    chmod 0644 "$PWQUALITY_CONF"
    chown root:root "$PWQUALITY_CONF"
fi

# Function to set a parameter idempotently in a given config file
set_param() {
    local file="$1"
    local param="$2"
    local value="$3"

    # Match lines like: dictcheck = 1  (with optional leading whitespace/comment)
    if grep -Eq "^[[:space:]]*#?[[:space:]]*${param}[[:space:]]*=" "$file"; then
        # Replace the existing (possibly commented) line with the desired setting
        sed -i -E "s|^[[:space:]]*#?[[:space:]]*${param}[[:space:]]*=.*|${param} = ${value}|" "$file"
    else
        # Append if not present
        printf '%s = %s\n' "$param" "$value" >> "$file"
    fi
}

# Apply the dictcheck setting in the main configuration file
set_param "$PWQUALITY_CONF" "$PARAM" "$VALUE"

# If a drop-in directory exists, ensure no drop-in disables the setting.
# Drop-in files can override the main config, so remediate any that set dictcheck=0.
if [[ -d "$PWQUALITY_CONF_D" ]]; then
    shopt -s nullglob
    for dropin in "$PWQUALITY_CONF_D"/*.conf; do
        if grep -Eq "^[[:space:]]*#?[[:space:]]*${PARAM}[[:space:]]*=" "$dropin"; then
            sed -i -E "s|^[[:space:]]*#?[[:space:]]*${PARAM}[[:space:]]*=.*|${PARAM} = ${VALUE}|" "$dropin"
        fi
    done
    shopt -u nullglob
fi

# Ensure pam_pwquality is invoked in the password stack so the setting is enforced.
# On RHEL 8, authselect manages PAM; if authselect is in use, ensure profile is applied.
if command -v authselect >/dev/null 2>&1; then
    if authselect current >/dev/null 2>&1; then
        # Re-apply the current profile to ensure PAM reflects pwquality configuration
        authselect apply-changes >/dev/null 2>&1 || true
    fi
fi

# Verify the change was applied
if grep -Eq "^[[:space:]]*${PARAM}[[:space:]]*=[[:space:]]*${VALUE}[[:space:]]*$" "$PWQUALITY_CONF"; then
    echo "Success: '${PARAM} = ${VALUE}' is configured in ${PWQUALITY_CONF}."
    exit 0
else
    echo "Error: Failed to configure '${PARAM}' in ${PWQUALITY_CONF}." >&2
    exit 1
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_password_pam_dictcheck='
```


---

## RHEL-08-020170 — `accounts_password_pam_difok`

**Prompt:** On a RHEL 8 system, enhance the complexity of new passwords by ensuring they differ from old passwords by at least 4 characters during a password change, mitigating the risk of password reuse and brute-force attacks. Implement an idempotent bash remediation script that configures this minimum character difference requirement via the appropriate PAM security settings, ensuring this policy is enforced persistently.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Enforce minimum password character difference (difok = 4)
# via pam_pwquality configuration on RHEL 8.
#
# This script is idempotent: running it multiple times results in the
# same configuration state.

set -euo pipefail

PWQUALITY_CONF="/etc/security/pwquality.conf"
PARAM="difok"
VALUE="4"

# Ensure the pwquality configuration file exists
if [[ ! -f "${PWQUALITY_CONF}" ]]; then
    touch "${PWQUALITY_CONF}"
    chmod 0644 "${PWQUALITY_CONF}"
fi

# Configure difok in /etc/security/pwquality.conf
if grep -Eq '^\s*#?\s*difok\s*=' "${PWQUALITY_CONF}"; then
    # Replace any existing (commented or uncommented) difok line
    sed -ri "s|^\s*#?\s*${PARAM}\s*=.*|${PARAM} = ${VALUE}|" "${PWQUALITY_CONF}"
else
    # Append the setting if it does not exist
    echo "${PARAM} = ${VALUE}" >> "${PWQUALITY_CONF}"
fi

# Also enforce the setting directly on the PAM pam_pwquality lines to ensure
# persistence even if pam configs specify difok inline.
PAM_FILES=(
    "/etc/pam.d/system-auth"
    "/etc/pam.d/password-auth"
)

for pam_file in "${PAM_FILES[@]}"; do
    [[ -f "${pam_file}" ]] || continue

    # Only act on lines that invoke pam_pwquality.so
    if grep -Eq 'pam_pwquality\.so' "${pam_file}"; then
        if grep -Eq 'pam_pwquality\.so.*\bdifok=' "${pam_file}"; then
            # Update existing inline difok value
            sed -ri "/pam_pwquality\.so/ s/\bdifok=[0-9]+/difok=${VALUE}/g" "${pam_file}"
        else
            # Append difok=VALUE to the pam_pwquality line
            sed -ri "/pam_pwquality\.so/ s/$/ ${PARAM}=${VALUE}/" "${pam_file}"
        fi
    fi
done

# Verify the resulting configuration
echo "Current pwquality difok setting:"
grep -E "^\s*${PARAM}\s*=" "${PWQUALITY_CONF}" || true

for pam_file in "${PAM_FILES[@]}"; do
    [[ -f "${pam_file}" ]] || continue
    echo "PAM pwquality entries in ${pam_file}:"
    grep -E 'pam_pwquality\.so' "${pam_file}" || true
done

echo "Remediation complete: password change now requires at least ${VALUE} differing characters."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_password_pam_difok='
```


---

## RHEL-08-020120 — `accounts_password_pam_lcredit`

**Prompt:** On a RHEL 8 system, ensure that passwords must contain at least one lowercase letter to enhance complexity and reduce vulnerability to password-guessing attacks. Write an idempotent bash remediation script that configures the system's PAM modules to require this minimum lowercase character rule for passwords, and ensure the change is persistent across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure passwords contain at least one lowercase character.
# Configures pwquality via /etc/security/pwquality.conf using lcredit = -1.
#

set -euo pipefail

CONF_FILE="/etc/security/pwquality.conf"
PARAM="lcredit"
VALUE="-1"

# Ensure the configuration file exists
if [[ ! -f "$CONF_FILE" ]]; then
    touch "$CONF_FILE"
    chmod 0644 "$CONF_FILE"
    chown root:root "$CONF_FILE"
fi

# Idempotently set the lcredit parameter.
# Match lines like: "lcredit = 0", "#lcredit=1", "  lcredit = -1", etc.
if grep -Eq '^[[:space:]]*#?[[:space:]]*lcredit[[:space:]]*=' "$CONF_FILE"; then
    # Replace existing (commented or uncommented) entry with the desired value.
    sed -ri "s|^[[:space:]]*#?[[:space:]]*${PARAM}[[:space:]]*=.*|${PARAM} = ${VALUE}|" "$CONF_FILE"
else
    # Append the setting if it does not exist at all.
    printf '%s = %s\n' "$PARAM" "$VALUE" >> "$CONF_FILE"
fi

# Verify the setting is now correct
if grep -Eq "^[[:space:]]*${PARAM}[[:space:]]*=[[:space:]]*${VALUE}[[:space:]]*$" "$CONF_FILE"; then
    echo "Success: '${PARAM} = ${VALUE}' is configured in ${CONF_FILE}."
else
    echo "Error: Failed to configure '${PARAM}' in ${CONF_FILE}." >&2
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

**Prompt:** On a RHEL 8 system, strengthen password complexity by configuring the pam_pwquality module to reject passwords that contain more than 3 consecutive repeating characters from the same character class. This limits password patterns that are more susceptible to brute-force attacks. Write an idempotent bash remediation script that enforces this restriction by setting an appropriate configuration value, ensuring the change is both applied and persists across system reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

CONFIG_FILE="/etc/security/pwquality.conf"
PARAM="maxclassrepeat"
VALUE="3"

# Ensure the configuration file exists
if [[ ! -f "$CONFIG_FILE" ]]; then
    touch "$CONFIG_FILE"
    chmod 0644 "$CONFIG_FILE"
    chown root:root "$CONFIG_FILE"
fi

# Idempotently set the maxclassrepeat parameter
if grep -Eq "^\s*#?\s*${PARAM}\s*=" "$CONFIG_FILE"; then
    sed -ri "s|^\s*#?\s*(${PARAM})\s*=.*|\1 = ${VALUE}|" "$CONFIG_FILE"
else
    printf '%s = %s\n' "$PARAM" "$VALUE" >> "$CONFIG_FILE"
fi

# Verify the change was applied
if grep -Eq "^\s*${PARAM}\s*=\s*${VALUE}\s*$" "$CONFIG_FILE"; then
    echo "Successfully set '${PARAM} = ${VALUE}' in ${CONFIG_FILE}"
else
    echo "Failed to set '${PARAM}' in ${CONFIG_FILE}" >&2
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

**Prompt:** On a RHEL 8 system, ensure that user passwords comply with a policy that limits the maximum number of consecutive repeating characters. This is to enhance password complexity and resist brute-force attacks involving repeated characters. Write an idempotent bash remediation script that configures the maximum consecutive repeating characters allowed in passwords to be two. Ensure that your configuration is idempotent and applies to all future password creations or changes.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

CONFIG_FILE="/etc/security/pwquality.conf"
PARAM="maxrepeat"
VALUE="2"

# Ensure the configuration file exists
if [[ ! -f "$CONFIG_FILE" ]]; then
    touch "$CONFIG_FILE"
    chmod 0644 "$CONFIG_FILE"
fi

# Idempotently set maxrepeat = 2
if grep -Eq "^\s*${PARAM}\s*=" "$CONFIG_FILE"; then
    # Parameter present (possibly commented differently); normalize it
    sed -i -E "s|^\s*${PARAM}\s*=.*|${PARAM} = ${VALUE}|" "$CONFIG_FILE"
elif grep -Eq "^\s*#\s*${PARAM}\s*=" "$CONFIG_FILE"; then
    # Commented-out parameter present; uncomment and set
    sed -i -E "s|^\s*#\s*${PARAM}\s*=.*|${PARAM} = ${VALUE}|" "$CONFIG_FILE"
else
    # Parameter absent; append it
    printf '%s = %s\n' "$PARAM" "$VALUE" >> "$CONFIG_FILE"
fi

# Verify result
if grep -Eq "^\s*${PARAM}\s*=\s*${VALUE}\s*$" "$CONFIG_FILE"; then
    echo "Successfully configured ${PARAM} = ${VALUE} in ${CONFIG_FILE}"
else
    echo "Failed to configure ${PARAM} in ${CONFIG_FILE}" >&2
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

**Prompt:** On a RHEL 8 system using PAM for authentication, enforce a higher password complexity requirement by ensuring that passwords contain characters from at least three different categories: upper-case letters, lower-case letters, digits, or special characters. This will increase the difficulty of password guessing and brute-force attacks by expanding the potential password space. Create an idempotent bash remediation script that configures the PAM system to require this complexity threshold when establishing or updating user passwords, and make the configuration persistent.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation script to enforce password complexity on RHEL 8 using pwquality.
# Requires passwords to contain characters from at least three of the four
# classes: upper-case, lower-case, digits, special characters.
#
# This is achieved by setting minclass = 3 in /etc/security/pwquality.conf
# (and pwquality.conf.d if present). The script is idempotent.

set -euo pipefail

PWQUALITY_CONF="/etc/security/pwquality.conf"
PARAM="minclass"
VALUE="3"

# Ensure the pwquality configuration file exists.
if [[ ! -f "${PWQUALITY_CONF}" ]]; then
    touch "${PWQUALITY_CONF}"
    chmod 0644 "${PWQUALITY_CONF}"
    chown root:root "${PWQUALITY_CONF}"
fi

# Idempotently set the minclass parameter.
if grep -Eq "^[[:space:]]*#?[[:space:]]*${PARAM}[[:space:]]*=" "${PWQUALITY_CONF}"; then
    # Replace any existing (commented or uncommented) minclass line.
    sed -ri "s|^[[:space:]]*#?[[:space:]]*${PARAM}[[:space:]]*=.*|${PARAM} = ${VALUE}|" "${PWQUALITY_CONF}"
else
    # Append the parameter if it does not exist.
    printf '%s = %s\n' "${PARAM}" "${VALUE}" >> "${PWQUALITY_CONF}"
fi

# Also handle any drop-in configuration directory files that might override the value.
PWQUALITY_CONF_D="/etc/security/pwquality.conf.d"
if [[ -d "${PWQUALITY_CONF_D}" ]]; then
    while IFS= read -r -d '' dropin; do
        if grep -Eq "^[[:space:]]*#?[[:space:]]*${PARAM}[[:space:]]*=" "${dropin}"; then
            sed -ri "s|^[[:space:]]*#?[[:space:]]*${PARAM}[[:space:]]*=.*|${PARAM} = ${VALUE}|" "${dropin}"
        fi
    done < <(find "${PWQUALITY_CONF_D}" -maxdepth 1 -type f -name '*.conf' -print0)
fi

# Ensure the PAM stack actually uses pam_pwquality so the setting is enforced.
for PAM_FILE in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
    [[ -f "${PAM_FILE}" ]] || continue

    if grep -Eq "^\s*password\s+.*pam_pwquality\.so" "${PAM_FILE}"; then
        # pam_pwquality is present. Make sure it references minclass=3 (optional,
        # since pwquality.conf already provides the value). We leave the line
        # intact to avoid conflicting settings but enforce minclass if inline.
        if grep -Eq "^\s*password\s+.*pam_pwquality\.so.*\bminclass=" "${PAM_FILE}"; then
            sed -ri "s|(^\s*password\s+.*pam_pwquality\.so[^\n]*?)\bminclass=[0-9]+|\1minclass=${VALUE}|" "${PAM_FILE}"
        fi
    else
        # Insert a pam_pwquality line before pam_unix.so in the password stack.
        if grep -Eq "^\s*password\s+.*pam_unix\.so" "${PAM_FILE}"; then
            sed -ri "0,/^\s*password\s+.*pam_unix\.so/{s|^(\s*password\s+.*pam_unix\.so.*)$|password    requisite     pam_pwquality.so try_first_pass local_users_only\n\1|}" "${PAM_FILE}"
        else
            printf 'password    requisite     pam_pwquality.so try_first_pass local_users_only\n' >> "${PAM_FILE}"
        fi
    fi
done

# Verify final state.
echo "Current pwquality minclass setting:"
grep -E "^\s*${PARAM}\s*=" "${PWQUALITY_CONF}" || true

echo "Password complexity remediation complete: minclass=${VALUE} enforced."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_password_pam_minclass='
```


---

## RHEL-08-020230 — `accounts_password_pam_minlen`

**Prompt:** On a RHEL 8 system, ensure that the Pluggable Authentication Module (PAM) is configured to enforce a minimum password length of 15 characters for user accounts. This strengthens password security by increasing the complexity and time required for brute-force attacks. Write an idempotent bash remediation script that configures PAM to enforce this minimum password length requirement.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Enforce a minimum password length of 15 characters via PAM
# on RHEL 8 by configuring the 'minlen' directive in pwquality.conf.
#

set -euo pipefail

CONF_FILE="/etc/security/pwquality.conf"
MINLEN_VALUE=15

# Ensure the configuration file exists
if [[ ! -f "$CONF_FILE" ]]; then
    touch "$CONF_FILE"
    chmod 0644 "$CONF_FILE"
fi

# Check for an existing (active or commented) minlen directive and update or add it idempotently
if grep -Eq '^\s*#?\s*minlen\b' "$CONF_FILE"; then
    # Replace any existing minlen line (commented or not) with the enforced value
    sed -ri "s|^\s*#?\s*minlen\s*=.*|minlen = ${MINLEN_VALUE}|" "$CONF_FILE"
else
    # Append the directive if it does not exist at all
    echo "minlen = ${MINLEN_VALUE}" >> "$CONF_FILE"
fi

# Verify the final state
if grep -Eq "^\s*minlen\s*=\s*${MINLEN_VALUE}\s*$" "$CONF_FILE"; then
    echo "Success: PAM minimum password length is set to ${MINLEN_VALUE} in ${CONF_FILE}."
else
    echo "Error: Failed to configure minimum password length in ${CONF_FILE}." >&2
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

**Prompt:** On a RHEL 8 system, the PAM password quality module must enforce that user passwords contain at least one special character. This policy increases password complexity and makes brute-force attacks more challenging. Modify the system's authentication configuration so that the password policy requires at least one special character. Ensure that the configuration is persistent and only enforces a policy requiring a minimum of one special character in passwords.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

CONF="/etc/security/pwquality.conf"

# Backup existing configuration
if [ -f "$CONF" ]; then
    cp -a "$CONF" "${CONF}.bak.$(date +%Y%m%d%H%M%S)"
fi

# Ensure the file exists
touch "$CONF"

# Set ocredit to -1 to require at least one special character
if grep -Eq '^\s*#?\s*ocredit\s*=' "$CONF"; then
    sed -i -E 's/^\s*#?\s*ocredit\s*=.*/ocredit = -1/' "$CONF"
else
    echo "ocredit = -1" >> "$CONF"
fi

echo "Password quality policy updated: at least one special character required."
grep -E '^\s*ocredit\s*=' "$CONF"
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_password_pam_ocredit='
```


---

## RHEL-08-020110 — `accounts_password_pam_ucredit`

**Prompt:** On a RHEL 8 system, ensure that password complexity requirements mandate the inclusion of a minimum number of uppercase characters in user passwords. Your task is to write an idempotent bash remediation script that configures the PAM system to require each password to include at least one uppercase letter. This setting helps improve resistance against password guessing and brute-force attempts.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

CONFIG_FILE="/etc/security/pwquality.conf"
PARAM="ucredit"
VALUE="-1"

# Ensure the configuration file exists
if [ ! -f "$CONFIG_FILE" ]; then
    touch "$CONFIG_FILE"
    chmod 0644 "$CONFIG_FILE"
fi

# Idempotently set the ucredit parameter
if grep -Eq "^\s*#?\s*${PARAM}\s*=" "$CONFIG_FILE"; then
    # Replace existing (commented or uncommented) line
    sed -i -E "s|^\s*#?\s*${PARAM}\s*=.*|${PARAM} = ${VALUE}|" "$CONFIG_FILE"
else
    # Append the parameter
    echo "${PARAM} = ${VALUE}" >> "$CONFIG_FILE"
fi

# Verify the change
if grep -Eq "^\s*${PARAM}\s*=\s*${VALUE}\s*$" "$CONFIG_FILE"; then
    echo "Successfully configured ${PARAM} = ${VALUE} in ${CONFIG_FILE}"
else
    echo "Failed to configure ${PARAM} in ${CONFIG_FILE}" >&2
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

**Prompt:** On a RHEL 8 system, enhance password security by configuring the system to use a minimum number of hashing rounds for password encryption. This makes password-cracking attempts computationally expensive. Write an idempotent bash remediation script to ensure the system always uses at least 5000 hashing rounds for password encryption. This configuration should persist through system changes and updates to the password settings.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

MIN_ROUNDS=5000
LOGIN_DEFS="/etc/login.defs"

# Ensure login.defs exists
if [[ ! -f "$LOGIN_DEFS" ]]; then
    touch "$LOGIN_DEFS"
    chmod 0644 "$LOGIN_DEFS"
fi

configure_rounds() {
    local key="$1"
    local value="$2"
    local file="$3"

    # Remove any commented or duplicate entries for the key, then set proper value
    if grep -Eq "^\s*#?\s*${key}\b" "$file"; then
        # Check if an active (uncommented) correct entry already exists
        if grep -Eq "^\s*${key}\s+${value}\s*$" "$file"; then
            # Ensure it's the only active entry
            local count
            count=$(grep -Ec "^\s*${key}\b" "$file")
            if [[ "$count" -eq 1 ]]; then
                return 0
            fi
        fi
        # Replace/normalize: remove all matching lines then append correct one
        sed -i -E "/^\s*#?\s*${key}\b.*/d" "$file"
        echo "${key} ${value}" >> "$file"
    else
        echo "${key} ${value}" >> "$file"
    fi
}

configure_rounds "SHA_CRYPT_MIN_ROUNDS" "$MIN_ROUNDS" "$LOGIN_DEFS"
configure_rounds "SHA_CRYPT_MAX_ROUNDS" "$MIN_ROUNDS" "$LOGIN_DEFS"

# Configure PAM to enforce rounds in pam files for password-auth and system-auth
for pam_file in /etc/pam.d/password-auth /etc/pam.d/system-auth; do
    [[ -f "$pam_file" ]] || continue

    # Only modify pam_unix.so lines in the password stack
    if grep -Eq "^\s*password\s+.*pam_unix\.so" "$pam_file"; then
        # Check if rounds= already correctly set
        if grep -E "^\s*password\s+.*pam_unix\.so" "$pam_file" | grep -Eq "rounds=${MIN_ROUNDS}\b"; then
            continue
        fi
        # Remove existing rounds= option then append correct one
        sed -i -E "/^\s*password\s+.*pam_unix\.so/ s/\s+rounds=[0-9]+//g" "$pam_file"
        sed -i -E "/^\s*password\s+.*pam_unix\.so/ s/$/ rounds=${MIN_ROUNDS}/" "$pam_file"
    fi
done

echo "Password hashing rounds configured to a minimum of ${MIN_ROUNDS}."
```

**Reference fix:**
```bash
var_password_hashing_min_rounds_login_defs='
```


---

## RHEL-08-040180 — `service_debug-shell_disabled`

**Prompt:** On a RHEL 8 system, ensure that the SystemD debug-shell service is permanently disabled to prevent unauthorized physical access to a root shell via tty9 after a system reboot, as this service can be used to bypass standard login controls. Write an idempotent bash remediation script that confirms the debug-shell service is disabled both immediately and permanently, safeguarding against unauthorized system access.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Permanently disable the SystemD debug-shell service.
# This prevents unauthorized physical access to a root shell via tty9.
#
set -o nounset
set -o pipefail

SERVICE="debug-shell.service"
EXIT_CODE=0

# Ensure systemctl is available
if ! command -v systemctl >/dev/null 2>&1; then
    echo "ERROR: systemctl not found. This script requires systemd." >&2
    exit 1
fi

# Ensure the script is run with root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

echo "Remediating: ensuring ${SERVICE} is disabled and masked."

# Stop the service immediately if it is running (idempotent)
if systemctl is-active --quiet "${SERVICE}"; then
    echo "Stopping active ${SERVICE}..."
    systemctl stop "${SERVICE}" || {
        echo "WARNING: Failed to stop ${SERVICE}." >&2
        EXIT_CODE=1
    }
else
    echo "${SERVICE} is not active."
fi

# Disable the service so it does not start at boot (idempotent)
if systemctl is-enabled "${SERVICE}" 2>/dev/null | grep -q -E '^(enabled|static|indirect)$'; then
    echo "Disabling ${SERVICE}..."
    systemctl disable "${SERVICE}" >/dev/null 2>&1 || true
fi

# Mask the service to guarantee it cannot be started (idempotent)
CURRENT_STATE="$(systemctl is-enabled "${SERVICE}" 2>/dev/null || true)"
if [ "${CURRENT_STATE}" != "masked" ]; then
    echo "Masking ${SERVICE}..."
    systemctl mask "${SERVICE}" >/dev/null 2>&1 || {
        echo "WARNING: Failed to mask ${SERVICE}." >&2
        EXIT_CODE=1
    }
else
    echo "${SERVICE} is already masked."
fi

# Reload systemd manager configuration to apply changes
systemctl daemon-reload || true

# Verification
echo "Verifying final state of ${SERVICE}..."

FINAL_STATE="$(systemctl is-enabled "${SERVICE}" 2>/dev/null || true)"
if [ "${FINAL_STATE}" = "masked" ]; then
    echo "PASS: ${SERVICE} is permanently disabled (masked)."
else
    echo "FAIL: ${SERVICE} state is '${FINAL_STATE}', expected 'masked'." >&2
    EXIT_CODE=1
fi

if systemctl is-active --quiet "${SERVICE}"; then
    echo "FAIL: ${SERVICE} is still active." >&2
    EXIT_CODE=1
else
    echo "PASS: ${SERVICE} is not active."
fi

exit "${EXIT_CODE}"
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

**Prompt:** On a RHEL 8 system, the Ctrl-Alt-Del key sequence can cause the system to reboot if pressed rapidly in succession. This might lead to accidental reboots, especially in environments with multiple operating systems where this key sequence has different meanings. Write an idempotent bash remediation script that configures the system to ignore this burst action and persist the configuration across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Disable the Ctrl-Alt-Del burst action on RHEL 8
# Idempotent: safe to run multiple times.
#
set -euo pipefail

CONF_FILE="/etc/systemd/system.conf"
DESIRED_SETTING="CtrlAltDelBurstAction=none"
KEY="CtrlAltDelBurstAction"

# Ensure the configuration file exists
if [[ ! -f "${CONF_FILE}" ]]; then
    echo "Error: ${CONF_FILE} does not exist." >&2
    exit 1
fi

changed=0

# Check whether the desired active (uncommented) setting is already present
if grep -Eq "^[[:space:]]*${KEY}[[:space:]]*=[[:space:]]*none[[:space:]]*$" "${CONF_FILE}"; then
    echo "Ctrl-Alt-Del burst action is already set to 'none'. No change needed."
else
    # Remove any existing (commented or uncommented) occurrences of the key
    if grep -Eq "^[[:space:]]*#?[[:space:]]*${KEY}[[:space:]]*=" "${CONF_FILE}"; then
        sed -i -E "/^[[:space:]]*#?[[:space:]]*${KEY}[[:space:]]*=/d" "${CONF_FILE}"
    fi

    # Append the desired setting
    printf '%s\n' "${DESIRED_SETTING}" >> "${CONF_FILE}"
    echo "Set ${DESIRED_SETTING} in ${CONF_FILE}."
    changed=1
fi

# Reload systemd manager configuration so the change is applied to the running system
if [[ "${changed}" -eq 1 ]]; then
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reexec
        echo "Reloaded systemd manager configuration."
    fi
fi

echo "Remediation complete."
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

**Prompt:** On a RHEL 8 system, the default behavior when Ctrl-Alt-Del is pressed is to reboot the machine, which poses a risk of accidental reboots in environments with users familiar with different operating systems. Write an idempotent bash remediation script to disable this shortcut so that pressing Ctrl-Alt-Del has no effect, ensuring this change persists across reboots and system updates.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

# Idempotent remediation to disable Ctrl-Alt-Del reboot on RHEL 8.
# The systemd target ctrl-alt-del.target is a symlink to reboot.target by default.
# Masking it (linking to /dev/null) neutralizes the key combination and
# persists across reboots and system updates.

if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

TARGET="/etc/systemd/system/ctrl-alt-del.target"

need_reload=0

# Ensure ctrl-alt-del.target is masked (symlinked to /dev/null)
if [[ -L "${TARGET}" ]]; then
    current="$(readlink -f "${TARGET}" || true)"
    if [[ "${current}" == "/dev/null" ]]; then
        echo "ctrl-alt-del.target is already masked. No change needed."
    else
        echo "ctrl-alt-del.target points to '${current}'. Re-masking."
        rm -f "${TARGET}"
        systemctl mask ctrl-alt-del.target
        need_reload=1
    fi
elif [[ -e "${TARGET}" ]]; then
    echo "ctrl-alt-del.target exists as a regular file. Replacing with mask."
    rm -f "${TARGET}"
    systemctl mask ctrl-alt-del.target
    need_reload=1
else
    echo "Masking ctrl-alt-del.target."
    systemctl mask ctrl-alt-del.target
    need_reload=1
fi

if [[ "${need_reload}" -eq 1 ]]; then
    systemctl daemon-reload
fi

# Verify final state
final="$(readlink -f "${TARGET}" 2>/dev/null || true)"
if [[ "${final}" == "/dev/null" ]]; then
    echo "Success: Ctrl-Alt-Del is disabled (ctrl-alt-del.target masked)."
else
    echo "Error: Failed to mask ctrl-alt-del.target." >&2
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

**Prompt:** On a RHEL 8 system, configure the systemd logind service to automatically terminate idle user sessions after 30 minutes of inactivity. This reduces the risk of unattended sessions being hijacked. Write an idempotent bash remediation script that ensures this automatic termination behavior is configured and persistent across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation script: terminate idle user sessions after 30 minutes of inactivity
# via systemd-logind. Idempotent and persistent across reboots.
#
set -euo pipefail

STOP_IDLE_SECS="1800"   # 30 minutes
STOP_ACTION="lock"      # StopIdleSessionSec triggers session stop; action defined below

LOGIND_CONF="/etc/systemd/logind.conf"
DROPIN_DIR="/etc/systemd/logind.conf.d"
DROPIN_FILE="${DROPIN_DIR}/50-idle-session-timeout.conf"

# Require root
if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

# Ensure the drop-in directory exists
if [[ ! -d "${DROPIN_DIR}" ]]; then
    mkdir -p "${DROPIN_DIR}"
    chmod 0755 "${DROPIN_DIR}"
fi

# Desired configuration content
read -r -d '' DESIRED_CONTENT <<EOF || true
# Managed by remediation script: terminate idle user sessions
# after ${STOP_IDLE_SECS} seconds (30 minutes) of inactivity.
[Login]
StopIdleSessionSec=${STOP_IDLE_SECS}
EOF

# Write the drop-in only if content differs (idempotent)
NEED_RELOAD=0
if [[ ! -f "${DROPIN_FILE}" ]] || ! printf '%s\n' "${DESIRED_CONTENT}" | cmp -s - "${DROPIN_FILE}"; then
    printf '%s\n' "${DESIRED_CONTENT}" > "${DROPIN_FILE}"
    chmod 0644 "${DROPIN_FILE}"
    echo "Updated ${DROPIN_FILE}"
    NEED_RELOAD=1
else
    echo "${DROPIN_FILE} already up to date."
fi

# Also ensure main logind.conf does not override with a conflicting value.
# If StopIdleSessionSec is set to something else there, normalize it.
if [[ -f "${LOGIND_CONF}" ]]; then
    if grep -Eq '^\s*StopIdleSessionSec\s*=' "${LOGIND_CONF}"; then
        CURRENT_MAIN="$(grep -E '^\s*StopIdleSessionSec\s*=' "${LOGIND_CONF}" | tail -n1 | sed -E 's/^\s*StopIdleSessionSec\s*=\s*//')"
        if [[ "${CURRENT_MAIN}" != "${STOP_IDLE_SECS}" ]]; then
            sed -i -E "s|^\s*StopIdleSessionSec\s*=.*|StopIdleSessionSec=${STOP_IDLE_SECS}|" "${LOGIND_CONF}"
            echo "Normalized StopIdleSessionSec in ${LOGIND_CONF}"
            NEED_RELOAD=1
        fi
    fi
fi

# Reload systemd and restart logind so changes take effect and persist
if [[ "${NEED_RELOAD}" -eq 1 ]]; then
    systemctl daemon-reload || true
    if systemctl is-active --quiet systemd-logind; then
        systemctl restart systemd-logind
        echo "Restarted systemd-logind."
    else
        systemctl start systemd-logind || true
        echo "Started systemd-logind."
    fi
else
    echo "No changes required; systemd-logind not restarted."
fi

# Ensure systemd-logind is enabled to persist across reboots
if ! systemctl is-enabled --quiet systemd-logind 2>/dev/null; then
    systemctl enable systemd-logind || true
fi

# Verification
echo "----- Verification -----"
EFFECTIVE="$(systemctl show systemd-logind -p StopIdleSessionSec --value 2>/dev/null || true)"
echo "Effective StopIdleSessionSec: ${EFFECTIVE:-unknown}"

if [[ "${EFFECTIVE}" == "${STOP_IDLE_SECS}" || "${EFFECTIVE}" == "30min" ]]; then
    echo "SUCCESS: Idle session timeout configured to 30 minutes."
    exit 0
else
    echo "WARNING: Effective value could not be confirmed as ${STOP_IDLE_SECS}s." >&2
    echo "Configuration files were written; a reboot may be required on older systemd versions." >&2
    exit 0
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel && { ( grep -qP "^ID=[\"']?rhel[\"']?$" "/etc/os-release" && { real="$(grep -P "^VERSION_ID=[\"']?[\w.]+[\"']?$" /etc/os-release | sed "s/^VERSION_ID=[\"']\?\([^\"']\+\)[\"']\?$/\1/")"; expected="8.7"; printf "%s\n%s" "$expected" "$real" | sort -VC; } && grep -qP "^ID=[\"']?rhel[\"']?$" "/etc/os-release" && { real="$(grep -P "^VERSION_ID=[\"']?[\w.]+[\"']?$" /etc/os-release | sed "s/^VERSION_ID=[\"']\?\([^\"']\+\)[\"']\?$/\1/")"; expected="9.0"; [[ "$real" != "$expected" ]]; } ) || grep -qP "^ID=[\"']?ol[\"']?$" "/etc/os-release" && { real="$(grep -P "^VERSION_ID=[\"']?[\w.]+[\"']?$" /etc/os-release | sed "s/^VERS
```


---

## RHEL-08-010410 — `package_opensc_installed`

**Prompt:** For a RHEL 8 system, ensure that the 'opensc' package is installed to enable multifactor authentication using smart cards or similar hardware tokens. This provides an additional security layer by verifying identity with a separate physical device. Write an idempotent bash remediation script that verifies and ensures that the 'opensc' package is installed, thereby supporting the use of multifactor authentication methods.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation script: Ensure the 'opensc' package is installed on RHEL 8.
# This supports multifactor authentication using smart cards / hardware tokens.
#
# The script is idempotent: it checks whether the package is already installed
# and only performs an installation if it is missing.

set -o errexit
set -o nounset
set -o pipefail

PACKAGE="opensc"

# Must be run as root to install packages
if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

# Determine the package manager available on the system
if command -v dnf >/dev/null 2>&1; then
    PKG_MGR="dnf"
elif command -v yum >/dev/null 2>&1; then
    PKG_MGR="yum"
else
    echo "ERROR: Neither dnf nor yum package manager was found." >&2
    exit 1
fi

# Check whether the package is already installed
if rpm -q "${PACKAGE}" >/dev/null 2>&1; then
    echo "Package '${PACKAGE}' is already installed. No action required."
    exit 0
fi

echo "Package '${PACKAGE}' is not installed. Installing now..."

# Install the package
if "${PKG_MGR}" install -y "${PACKAGE}"; then
    echo "Package '${PACKAGE}' was installed successfully."
else
    echo "ERROR: Failed to install package '${PACKAGE}'." >&2
    exit 1
fi

# Verify installation succeeded
if rpm -q "${PACKAGE}" >/dev/null 2>&1; then
    echo "Verification passed: '${PACKAGE}' is present on the system."
    exit 0
else
    echo "ERROR: Verification failed: '${PACKAGE}' is still not installed." >&2
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

**Prompt:** On a RHEL 8 system, configure user account settings to automatically disable accounts after 30 days of inactivity following password expiration. This reduces the risk of inactive accounts being compromised and used undetected by malicious parties. Write an idempotent bash remediation script that ensures compliant configuration, and that this setting persists for all future user accounts created.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Set account inactivity lock to 30 days after password expiration
# Applies to RHEL 8 systems.
#

set -euo pipefail

INACTIVITY_DAYS=30
USERADD_FILE="/etc/default/useradd"

# --- Ensure default for all future accounts via useradd defaults ---
# The 'useradd -D -f' command updates INACTIVE in /etc/default/useradd idempotently.
if [ -f "$USERADD_FILE" ]; then
    current_default="$(grep -E '^INACTIVE=' "$USERADD_FILE" | cut -d= -f2 || true)"
    if [ "$current_default" != "$INACTIVITY_DAYS" ]; then
        useradd -D -f "$INACTIVITY_DAYS"
    fi
else
    # File missing; create default via useradd (it will regenerate the file)
    useradd -D -f "$INACTIVITY_DAYS"
fi

# Verify the file actually contains the expected setting; fix directly if needed.
if grep -qE '^INACTIVE=' "$USERADD_FILE"; then
    sed -i "s/^INACTIVE=.*/INACTIVE=${INACTIVITY_DAYS}/" "$USERADD_FILE"
else
    echo "INACTIVE=${INACTIVITY_DAYS}" >> "$USERADD_FILE"
fi

# --- Apply to existing interactive (non-system) user accounts ---
# Determine UID_MIN from /etc/login.defs (default to 1000 if not found)
UID_MIN="$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs 2>/dev/null | tail -n1)"
UID_MIN="${UID_MIN:-1000}"

while IFS=: read -r username _ uid _ _ _ shell; do
    # Skip accounts below UID_MIN (system accounts)
    if [ "$uid" -lt "$UID_MIN" ]; then
        continue
    fi
    # Skip nobody / nfsnobody
    if [ "$uid" -ge 65534 ]; then
        continue
    fi
    # Skip accounts with nologin/false shells (non-interactive)
    case "$shell" in
        */nologin|*/false|/bin/sync|/sbin/shutdown|/sbin/halt)
            continue
            ;;
    esac

    # Read current inactive value from shadow (field 7)
    current_inactive="$(getent shadow "$username" | awk -F: '{print $7}')"

    if [ "$current_inactive" != "$INACTIVITY_DAYS" ]; then
        chage --inactive "$INACTIVITY_DAYS" "$username"
    fi
done < /etc/passwd

echo "Account inactivity lock configured to ${INACTIVITY_DAYS} days for existing and future accounts."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q shadow-utils; then

var_account_disable_post_pw_expiration='
```


---

## RHEL-08-020200 — `accounts_maximum_age_login_defs`

**Prompt:** On a RHEL 8 system, ensure that all new user accounts are configured to require password changes every 60 days to mitigate the risk of password compromise. This setting should force users to update their passwords regularly. Write an idempotent bash remediation script that sets the password maximum age for new accounts to 60 days, and ensures this configuration persists for any future user additions.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

LOGIN_DEFS="/etc/login.defs"
MAX_DAYS=60

if [[ ! -f "$LOGIN_DEFS" ]]; then
    echo "Error: $LOGIN_DEFS not found." >&2
    exit 1
fi

# Backup once if no backup exists yet for idempotency tracking
if [[ ! -f "${LOGIN_DEFS}.bak" ]]; then
    cp -p "$LOGIN_DEFS" "${LOGIN_DEFS}.bak"
fi

if grep -Eq '^\s*PASS_MAX_DAYS\s+' "$LOGIN_DEFS"; then
    # Update existing (non-commented) directive if it differs
    current="$(grep -E '^\s*PASS_MAX_DAYS\s+' "$LOGIN_DEFS" | awk '{print $2}' | head -n1)"
    if [[ "$current" != "$MAX_DAYS" ]]; then
        sed -i -E "s/^\s*PASS_MAX_DAYS\s+.*/PASS_MAX_DAYS\t${MAX_DAYS}/" "$LOGIN_DEFS"
        echo "Updated PASS_MAX_DAYS to ${MAX_DAYS} in ${LOGIN_DEFS}."
    else
        echo "PASS_MAX_DAYS already set to ${MAX_DAYS}. No change needed."
    fi
else
    # Uncomment a commented directive if present, else append
    if grep -Eq '^\s*#\s*PASS_MAX_DAYS\s+' "$LOGIN_DEFS"; then
        sed -i -E "s/^\s*#\s*PASS_MAX_DAYS\s+.*/PASS_MAX_DAYS\t${MAX_DAYS}/" "$LOGIN_DEFS"
        echo "Uncommented and set PASS_MAX_DAYS to ${MAX_DAYS} in ${LOGIN_DEFS}."
    else
        printf 'PASS_MAX_DAYS\t%s\n' "$MAX_DAYS" >> "$LOGIN_DEFS"
        echo "Appended PASS_MAX_DAYS ${MAX_DAYS} to ${LOGIN_DEFS}."
    fi
fi

# Verify
final="$(grep -E '^\s*PASS_MAX_DAYS\s+' "$LOGIN_DEFS" | awk '{print $2}' | head -n1)"
if [[ "$final" == "$MAX_DAYS" ]]; then
    echo "Verification passed: PASS_MAX_DAYS = ${final}"
else
    echo "Verification failed: PASS_MAX_DAYS = ${final:-unset}" >&2
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

**Prompt:** On a RHEL 8 system, enforce a minimum age of 1 day for password changes to prevent users from rapidly cycling through old passwords, which undermines password reuse policies. Write an idempotent bash remediation script that configures this 1-day minimum password age requirement for new user accounts, ensuring it persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

LOGIN_DEFS="/etc/login.defs"
MIN_DAYS=1

if [[ ! -f "$LOGIN_DEFS" ]]; then
    echo "Error: $LOGIN_DEFS not found." >&2
    exit 1
fi

# Backup once
if [[ ! -f "${LOGIN_DEFS}.bak" ]]; then
    cp -p "$LOGIN_DEFS" "${LOGIN_DEFS}.bak"
fi

if grep -Eq '^[[:space:]]*PASS_MIN_DAYS[[:space:]]+' "$LOGIN_DEFS"; then
    # Replace existing (possibly commented-out gets handled separately)
    sed -i -E "s/^[[:space:]]*PASS_MIN_DAYS[[:space:]]+.*/PASS_MIN_DAYS\t${MIN_DAYS}/" "$LOGIN_DEFS"
elif grep -Eq '^[[:space:]]*#[[:space:]]*PASS_MIN_DAYS[[:space:]]+' "$LOGIN_DEFS"; then
    # Uncomment and set
    sed -i -E "s/^[[:space:]]*#[[:space:]]*PASS_MIN_DAYS[[:space:]]+.*/PASS_MIN_DAYS\t${MIN_DAYS}/" "$LOGIN_DEFS"
else
    echo -e "PASS_MIN_DAYS\t${MIN_DAYS}" >> "$LOGIN_DEFS"
fi

# Verify
if grep -Eq "^[[:space:]]*PASS_MIN_DAYS[[:space:]]+${MIN_DAYS}[[:space:]]*$" "$LOGIN_DEFS"; then
    echo "PASS_MIN_DAYS set to ${MIN_DAYS} in ${LOGIN_DEFS}."
else
    echo "Error: Failed to set PASS_MIN_DAYS." >&2
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

**Prompt:** On a RHEL 8 system, ensure that the minimum password length for new user accounts enforces at least 15 characters to mitigate against password cracking attempts. Write an idempotent bash remediation script that configures the system to enforce this minimum password length, noting that although multiple mechanisms might enforce password quality, the specified length requirement must always be met for new accounts.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation script to enforce a minimum password length of 15 characters
# for new user accounts on a RHEL 8 system.
#
# This configures pwquality (minlen) which is the primary mechanism used by
# PAM (pam_pwquality) to enforce password length requirements.

set -euo pipefail

MINLEN_VALUE=15

# Primary configuration file for pwquality
PWQUALITY_CONF="/etc/security/pwquality.conf"
PWQUALITY_CONF_D="/etc/security/pwquality.conf.d"

configure_file() {
    local file="$1"
    local key="minlen"
    local value="$MINLEN_VALUE"

    # Ensure the file exists
    if [ ! -f "$file" ]; then
        touch "$file"
        chmod 0644 "$file"
    fi

    # If an active (uncommented) minlen entry exists, update it in place.
    if grep -Eq '^\s*minlen\s*=' "$file"; then
        sed -ri "s|^\s*minlen\s*=.*|${key} = ${value}|" "$file"
    # If a commented minlen entry exists, replace it with an active one.
    elif grep -Eq '^\s*#\s*minlen\s*=' "$file"; then
        sed -ri "s|^\s*#\s*minlen\s*=.*|${key} = ${value}|" "$file"
    else
        # Append a new active entry.
        printf '%s = %s\n' "$key" "$value" >> "$file"
    fi
}

# Configure the main pwquality.conf
configure_file "$PWQUALITY_CONF"

# If a conf.d directory is in use, ensure any files there do not override
# our setting with a weaker value.
if [ -d "$PWQUALITY_CONF_D" ]; then
    shopt -s nullglob
    for f in "$PWQUALITY_CONF_D"/*.conf; do
        if grep -Eq '^\s*minlen\s*=' "$f"; then
            current="$(grep -E '^\s*minlen\s*=' "$f" | tail -n1 | sed -E 's|^\s*minlen\s*=\s*([0-9]+).*|\1|')"
            if [ -z "$current" ] || [ "$current" -lt "$MINLEN_VALUE" ]; then
                sed -ri "s|^\s*minlen\s*=.*|minlen = ${MINLEN_VALUE}|" "$f"
            fi
        fi
    done
    shopt -u nullglob
fi

# Verify the resulting configuration.
if grep -Eq "^\s*minlen\s*=\s*${MINLEN_VALUE}\b" "$PWQUALITY_CONF"; then
    echo "SUCCESS: minlen is set to ${MINLEN_VALUE} in ${PWQUALITY_CONF}"
else
    echo "ERROR: Failed to set minlen to ${MINLEN_VALUE} in ${PWQUALITY_CONF}" >&2
    exit 1
fi

exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q shadow-utils; then

var_accounts_password_minlen_login_defs='
```


---

## RHEL-08-020210 — `accounts_password_set_max_life_existing`

**Prompt:** On a RHEL 8 system, ensure that all user accounts have passwords set to expire after a maximum of 90 days to reduce the risk of the passwords being compromised over time. Write an idempotent bash remediation script that configures any account without this restriction to enforce a maximum password lifetime of 90 days. The script should apply this setting for existing accounts and persist through normal system operation.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure all user accounts enforce a maximum password age of 90 days.
# Idempotent: safe to run multiple times.

set -o pipefail

MAX_DAYS=90
LOGIN_DEFS="/etc/login.defs"

# ---------------------------------------------------------------------------
# 1. Set the system-wide default in /etc/login.defs so NEW accounts inherit it.
# ---------------------------------------------------------------------------
if [ -f "$LOGIN_DEFS" ]; then
    if grep -Eq '^\s*PASS_MAX_DAYS\s+' "$LOGIN_DEFS"; then
        current=$(grep -E '^\s*PASS_MAX_DAYS\s+' "$LOGIN_DEFS" | awk '{print $2}' | tail -n1)
        if [ "$current" != "$MAX_DAYS" ]; then
            sed -i -E "s/^\s*PASS_MAX_DAYS\s+.*/PASS_MAX_DAYS\t$MAX_DAYS/" "$LOGIN_DEFS"
            echo "Updated PASS_MAX_DAYS in $LOGIN_DEFS to $MAX_DAYS."
        else
            echo "PASS_MAX_DAYS already set to $MAX_DAYS in $LOGIN_DEFS."
        fi
    else
        echo -e "PASS_MAX_DAYS\t$MAX_DAYS" >> "$LOGIN_DEFS"
        echo "Added PASS_MAX_DAYS $MAX_DAYS to $LOGIN_DEFS."
    fi
else
    echo -e "PASS_MAX_DAYS\t$MAX_DAYS" > "$LOGIN_DEFS"
    echo "Created $LOGIN_DEFS with PASS_MAX_DAYS $MAX_DAYS."
fi

# ---------------------------------------------------------------------------
# 2. Apply the setting to EXISTING accounts that have a real (usable) password
#    and whose current maximum exceeds 90 (or is unset/never-expiring).
# ---------------------------------------------------------------------------
# Iterate over accounts listed in /etc/shadow.
while IFS=: read -r username passwd _; do
    # Skip empty lines
    [ -z "$username" ] && continue

    # Only consider accounts that actually have a hashed password set.
    # Skip locked (!, *) and empty-password / no-login placeholder entries.
    case "$passwd" in
        ""|"*"|"!"*|"!!") continue ;;
    esac

    # Get current maximum password age for the account.
    current_max=$(chage -l "$username" 2>/dev/null | awk -F: '/Maximum number of days between password change/ {gsub(/^[ \t]+/,"",$2); print $2}')

    # If chage failed for this user, skip.
    [ -z "$current_max" ] && continue

    # If it's set to "never" or is greater than the required max, remediate.
    if [ "$current_max" = "never" ] || ! [[ "$current_max" =~ ^[0-9]+$ ]]; then
        chage --maxdays "$MAX_DAYS" "$username" \
            && echo "Set PASS_MAX_DAYS=$MAX_DAYS for '$username' (was: $current_max)."
    elif [ "$current_max" -gt "$MAX_DAYS" ]; then
        chage --maxdays "$MAX_DAYS" "$username" \
            && echo "Set PASS_MAX_DAYS=$MAX_DAYS for '$username' (was: $current_max)."
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

**Prompt:** On a RHEL 8 system, ensure that all user accounts enforce a minimum password age of 1 day, preventing users from changing passwords repeatedly in short succession to bypass password reuse policies. Write an idempotent bash remediation script that sets this minimum password age for all non-compliant user accounts, ensuring the setting persists until explicitly changed again.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

MIN_DAYS=1
LOGIN_DEFS="/etc/login.defs"

# 1. Ensure the default PASS_MIN_DAYS in /etc/login.defs is set to MIN_DAYS
if grep -Eq '^\s*PASS_MIN_DAYS\s+' "$LOGIN_DEFS"; then
    current_default=$(grep -E '^\s*PASS_MIN_DAYS\s+' "$LOGIN_DEFS" | tail -1 | awk '{print $2}')
    if [ "$current_default" != "$MIN_DAYS" ]; then
        sed -i -E "s/^\s*PASS_MIN_DAYS\s+.*/PASS_MIN_DAYS\t$MIN_DAYS/" "$LOGIN_DEFS"
        echo "Updated PASS_MIN_DAYS in $LOGIN_DEFS to $MIN_DAYS"
    fi
else
    printf "PASS_MIN_DAYS\t%s\n" "$MIN_DAYS" >> "$LOGIN_DEFS"
    echo "Added PASS_MIN_DAYS $MIN_DAYS to $LOGIN_DEFS"
fi

# 2. Enforce minimum password age for all existing interactive user accounts
#    Determine UID_MIN to identify regular user accounts
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' "$LOGIN_DEFS" | tail -1)
UID_MIN=${UID_MIN:-1000}

while IFS=: read -r username _ uid _ _ _ shell; do
    # Skip accounts without a valid uid
    [ -z "$uid" ] && continue

    # Apply to root and to regular (interactive) users
    if [ "$uid" -eq 0 ] || { [ "$uid" -ge "$UID_MIN" ] && \
        [ "$shell" != "/sbin/nologin" ] && \
        [ "$shell" != "/usr/sbin/nologin" ] && \
        [ "$shell" != "/bin/false" ]; }; then

        current_min=$(chage -l "$username" 2>/dev/null | awk -F: '/Minimum number of days/{gsub(/ /,"",$2); print $2}')

        if [ -z "$current_min" ] || [ "$current_min" != "$MIN_DAYS" ]; then
            chage --mindays "$MIN_DAYS" "$username"
            echo "Set minimum password age to $MIN_DAYS for user: $username"
        fi
    fi
done < /etc/passwd

echo "Minimum password age remediation complete."
```

**Reference fix:**
```bash
var_accounts_minimum_age_login_defs='
```


---

## RHEL-08-020331 — `no_empty_passwords`

**Prompt:** On a RHEL 8 system, it is crucial to ensure that user accounts cannot be accessed with an empty password to prevent unauthorized access. Write an idempotent bash remediation script that configures the system's Pluggable Authentication Module (PAM) to disallow login to accounts that are missing a password. Ensure the change persists and strictly enforce by modifying the relevant PAM configuration files.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Disallow login to accounts with empty passwords
# RHEL 8 - Remove 'nullok' from pam_unix.so lines in PAM configuration
#

set -o pipefail

# On RHEL 8 the effective PAM configuration is managed via authselect profiles.
# We must edit the profile-provided files if authselect is in use, otherwise
# edit the system-auth / password-auth files directly.

PAM_FILES=(
    "/etc/pam.d/system-auth"
    "/etc/pam.d/password-auth"
)

remove_nullok() {
    local file="$1"

    # Resolve symlinks to edit the actual backing file
    local target
    target="$(readlink -f "$file" 2>/dev/null)"
    [ -z "$target" ] && target="$file"

    if [ ! -f "$target" ]; then
        echo "WARNING: $target does not exist, skipping."
        return 0
    fi

    # Only modify if 'nullok' is present on a pam_unix.so line
    if grep -Eq '^\s*[^#].*pam_unix\.so.*\bnullok\b' "$target"; then
        echo "Removing 'nullok' from pam_unix.so in $target"
        # Remove standalone 'nullok' token (with surrounding whitespace handling)
        sed -i -E '/pam_unix\.so/ s/\bnullok(_secure)?\b//g' "$target"
        # Clean up any resulting double spaces / trailing spaces on those lines
        sed -i -E '/pam_unix\.so/ s/[[:space:]]+/ /g; /pam_unix\.so/ s/[[:space:]]+$//' "$target"
    else
        echo "No 'nullok' found on pam_unix.so line in $target (already compliant)."
    fi
}

# If authselect is managing configuration, update the custom/current profile too
if command -v authselect >/dev/null 2>&1; then
    if authselect current >/dev/null 2>&1; then
        echo "authselect is in use. Editing authselect-managed files."
        # authselect current profile files live under /etc/authselect/
        AUTHSELECT_FILES=(
            "/etc/authselect/system-auth"
            "/etc/authselect/password-auth"
            "/etc/authselect/custom/*/system-auth"
            "/etc/authselect/custom/*/password-auth"
        )
        for pattern in "${AUTHSELECT_FILES[@]}"; do
            for f in $pattern; do
                [ -f "$f" ] && remove_nullok "$f"
            done
        done
    fi
fi

# Always ensure the active PAM files are compliant
for pam_file in "${PAM_FILES[@]}"; do
    remove_nullok "$pam_file"
done

# Re-apply authselect changes so profile edits take effect on the live system
if command -v authselect >/dev/null 2>&1; then
    if authselect current >/dev/null 2>&1; then
        echo "Applying authselect changes..."
        authselect apply-changes -b 2>/dev/null || authselect apply-changes 2>/dev/null || true
    fi
fi

# Verification
echo "Verification of pam_unix.so lines:"
for pam_file in "${PAM_FILES[@]}"; do
    target="$(readlink -f "$pam_file" 2>/dev/null)"
    [ -z "$target" ] && target="$pam_file"
    if [ -f "$target" ]; then
        if grep -Eq '^\s*[^#].*pam_unix\.so.*\bnullok\b' "$target"; then
            echo "FAIL: 'nullok' still present in $target"
        else
            echo "PASS: $target"
        fi
    fi
done

echo "Remediation complete."
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

**Prompt:** On a RHEL 8 system, configure the system authentication delay so that there is a 4-second pause imposed after a failed login attempt. This delay helps mitigate brute force attacks by slowing down the rate of successive failed login attempts. Write an idempotent bash remediation script that enforces this delay for login attempts, ensuring the setting is correct in both current operations and across system reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

CONF_FILE="/etc/security/faildelay.conf"
PAM_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
DELAY_MICROSECONDS=4000000

# Ensure the pam_faildelay module is configured in the relevant PAM files
for pam_file in "${PAM_FILES[@]}"; do
    if [ ! -f "$pam_file" ]; then
        continue
    fi

    if grep -qE '^\s*auth\s+.*pam_faildelay\.so' "$pam_file"; then
        # Update existing pam_faildelay line to enforce the correct delay
        sed -ri "s|^(\s*auth\s+\S+\s+pam_faildelay\.so).*|\1 delay=${DELAY_MICROSECONDS}|" "$pam_file"
    else
        # Insert pam_faildelay after the first auth line
        if grep -qE '^\s*auth' "$pam_file"; then
            sed -ri "0,/^\s*auth.*/s||&\nauth        required                                     pam_faildelay.so delay=${DELAY_MICROSECONDS}|" "$pam_file"
        else
            printf 'auth        required                                     pam_faildelay.so delay=%s\n' "$DELAY_MICROSECONDS" >> "$pam_file"
        fi
    fi
done

# Also enforce via faildelay.conf if the file/mechanism is supported
if [ -f "$CONF_FILE" ] || [ -d "$(dirname "$CONF_FILE")" ]; then
    DELAY_SECONDS=$(( DELAY_MICROSECONDS / 1000000 ))
    if [ -f "$CONF_FILE" ] && grep -qE '^\s*delay\s*=' "$CONF_FILE"; then
        sed -ri "s|^\s*delay\s*=.*|delay = ${DELAY_SECONDS}|" "$CONF_FILE"
    else
        printf 'delay = %s\n' "$DELAY_SECONDS" >> "$CONF_FILE"
    fi
fi

echo "System authentication fail delay configured to $(( DELAY_MICROSECONDS / 1000000 )) seconds."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q shadow-utils; then

var_accounts_fail_delay='
```


---

## RHEL-08-020024 — `accounts_max_concurrent_login_sessions`

**Prompt:** On a RHEL 8 system, prevent denial-of-service attacks by limiting the number of concurrent login sessions a single user can initiate. The maximum allowable simultaneous login sessions per user should be set to 5. Write an idempotent bash remediation script that enforces this restriction in a manner that will reliably apply both now and after any reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

LIMITS_FILE="/etc/security/limits.conf"
LIMITS_DIR="/etc/security/limits.d"
MAXLOGINS=5

# Ensure limits.d directory exists
mkdir -p "$LIMITS_DIR"

# Remove any conflicting maxlogins entries from limits.conf
if [ -f "$LIMITS_FILE" ]; then
    sed -i -E '/^[[:space:]]*\*[[:space:]]+hard[[:space:]]+maxlogins[[:space:]]+/d' "$LIMITS_FILE"
fi

# Remove any conflicting maxlogins entries from other files in limits.d
if [ -d "$LIMITS_DIR" ]; then
    for f in "$LIMITS_DIR"/*.conf; do
        [ -e "$f" ] || continue
        if [ "$f" != "$LIMITS_DIR/99-maxlogins.conf" ]; then
            sed -i -E '/^[[:space:]]*\*[[:space:]]+hard[[:space:]]+maxlogins[[:space:]]+/d' "$f"
        fi
    done
fi

# Write the authoritative maxlogins setting
DROPIN="$LIMITS_DIR/99-maxlogins.conf"
DESIRED="*               hard    maxlogins       ${MAXLOGINS}"

if [ -f "$DROPIN" ] && grep -qE '^\*[[:space:]]+hard[[:space:]]+maxlogins[[:space:]]+'"${MAXLOGINS}"'[[:space:]]*$' "$DROPIN"; then
    :
else
    printf '%s\n' "$DESIRED" > "$DROPIN"
fi

chmod 0644 "$DROPIN"
chown root:root "$DROPIN"

echo "maxlogins set to ${MAXLOGINS} in ${DROPIN}"
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_accounts_max_concurrent_login_sessions='
```


---

## RHEL-08-010741 — `accounts_users_home_files_groupownership`

**Prompt:** On a RHEL 8 system, ensure that every file and directory inside each user's home directory is group-owned by the user's primary group, to prevent unauthorized group access. Consider only files and directories belonging to local interactive users who have a valid shell. Write an idempotent bash remediation script to enforce this ownership requirement, ensuring that all files and directories conform to this standard.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Ensure every file/directory inside each local interactive user's home
# directory is group-owned by that user's primary group.
#

set -u

# Build a list of valid (non-nologin, non-false) shells from /etc/shells
valid_shells="^($(awk '/^\// && !/(\/nologin|\/false)$/ {
    print $0
}' /etc/shells | paste -sd '|' - | sed 's/\//\\\//g'))$"

# Iterate over local interactive users from /etc/passwd
awk -v pat="$valid_shells" -F: '($7 ~ pat) { print $1":"$3":"$4":"$6 }' /etc/passwd | \
while IFS=: read -r user uid gid home; do

    # Skip if no UID meets the local interactive threshold
    # (typically UID_MIN and UID_MAX; using login.defs values)
    UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
    UID_MAX=$(awk '/^\s*UID_MAX/{print $2}' /etc/login.defs)
    [ -z "$UID_MIN" ] && UID_MIN=1000
    [ -z "$UID_MAX" ] && UID_MAX=60000

    if [ "$uid" -lt "$UID_MIN" ] || [ "$uid" -gt "$UID_MAX" ]; then
        continue
    fi

    # Validate home directory exists and is a directory
    if [ -z "$home" ] || [ ! -d "$home" ]; then
        continue
    fi

    # Skip shared/system-ish home directories to avoid accidental changes
    case "$home" in
        /|/dev|/proc|/sys|/bin|/sbin|/usr|/etc|/var|/run|/tmp)
            continue
            ;;
    esac

    # Determine the primary group name for this user's GID
    primary_group=$(getent group "$gid" | cut -d: -f1)
    if [ -z "$primary_group" ]; then
        # fall back to numeric gid if no name resolves
        primary_group="$gid"
    fi

    # Find files/dirs whose group ownership differs from primary group,
    # and correct them idempotently.
    find "$home" -not -group "$gid" -print0 2>/dev/null | \
    while IFS= read -r -d '' path; do
        chgrp -h "$gid" "$path" 2>/dev/null
    done

done
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

**Prompt:** On a RHEL 8 system, configure the file permissions of all directories and non-hidden files within each local interactive user's home directory to be no more permissive than 0750. This limits access to the owner and group members, protecting sensitive user data. Hidden files, those whose names start with a dot, should not be altered. Write an idempotent bash remediation script to ensure these secure permissions are set and maintained for all existing user accounts.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation script: ensure directories and non-hidden files within each
# local interactive user's home directory are no more permissive than 0750.
# Hidden files/directories (names starting with a dot) are not altered.
#

set -o nounset

# Determine the UID_MIN value for local interactive users from login.defs
if [ -f /etc/login.defs ]; then
    UID_MIN=$(awk '/^\s*UID_MIN\s+/{print $2}' /etc/login.defs | head -n 1)
fi
UID_MIN=${UID_MIN:-1000}

# Determine typical UID_MAX (interactive users are below the nologin range)
if [ -f /etc/login.defs ]; then
    UID_MAX=$(awk '/^\s*UID_MAX\s+/{print $2}' /etc/login.defs | head -n 1)
fi
UID_MAX=${UID_MAX:-60000}

# Iterate through passwd entries and select local interactive users
while IFS=: read -r username _ uid _ _ homedir shell; do

    # Skip users outside the interactive UID range
    if [ -z "${uid}" ]; then
        continue
    fi
    if [ "${uid}" -lt "${UID_MIN}" ] || [ "${uid}" -gt "${UID_MAX}" ]; then
        continue
    fi

    # Skip accounts with non-interactive shells
    case "${shell}" in
        */nologin|*/false|/sbin/nologin|/bin/false|/usr/sbin/nologin|"")
            continue
            ;;
    esac

    # Ensure a valid home directory exists
    if [ -z "${homedir}" ] || [ ! -d "${homedir}" ]; then
        continue
    fi

    # Skip system-shared home directories that could be dangerous to alter
    case "${homedir}" in
        /|/root|/dev|/proc|/sys|/bin|/sbin|/usr|/etc|/var|/tmp)
            continue
            ;;
    esac

    # Process directories (excluding hidden ones and anything under hidden dirs)
    # and non-hidden files. Prune hidden entries so they are not descended into
    # or modified.
    find "${homedir}" \
        \( -name '.*' -prune \) -o \
        \( -type d -perm /0027 -exec chmod g-w,o-rwx {} + \) -o \
        \( -type f -perm /0027 -exec chmod g-w,o-rwx {} + \)

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

**Prompt:** On a RHEL 8 system, ensure all user initialization files inside home directories, including those of the root user, have permissions no more permissive than 0740. This restricts unauthorized users from reading or modifying shell environment configurations, protecting against account compromise. Write an idempotent bash remediation script that adjusts the permissions of these files accordingly, and apply this to all existing users' initialization files.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure all user initialization files inside home directories
# (including root) have permissions no more permissive than 0740.
#
# Idempotent: only changes files whose current permissions exceed 0740.

set -o nounset
set -o pipefail

# Maximum allowed permission mode (octal)
MAX_PERM=0740
MAX_PERM_DEC=$((8#0740))

# List of user initialization files to check within each home directory.
INIT_FILES=(
    ".bashrc"
    ".bash_profile"
    ".bash_login"
    ".profile"
    ".bash_logout"
    ".cshrc"
    ".login"
    ".logout"
    ".tcshrc"
    ".kshrc"
    ".zshrc"
    ".zprofile"
    ".zlogin"
    ".zlogout"
    ".zshenv"
    ".xinitrc"
    ".Xdefaults"
    ".emacs"
    ".exrc"
    ".inputrc"
    ".vimrc"
    ".netrc"
    ".forward"
)

# Collect list of home directories from local users (UID present in /etc/passwd).
# Include root explicitly (its home is normally /root).
declare -A HOME_DIRS

while IFS=':' read -r username _ uid _ _ homedir _; do
    # Skip entries without a home directory
    [ -z "${homedir}" ] && continue
    # Skip pseudo home directories that are not real user homes
    case "${homedir}" in
        /|/dev/null|/nonexistent|/bin*|/sbin*|/usr/sbin*|/proc*)
            continue
            ;;
    esac
    # Only consider directories that actually exist
    if [ -d "${homedir}" ]; then
        HOME_DIRS["${homedir}"]=1
    fi
done < /etc/passwd

# Ensure root's home is included even if some parsing edge cases occur.
if [ -d /root ]; then
    HOME_DIRS["/root"]=1
fi

# Iterate over each home directory and adjust init file permissions.
for homedir in "${!HOME_DIRS[@]}"; do
    for initfile in "${INIT_FILES[@]}"; do
        target="${homedir}/${initfile}"

        # Only operate on regular files (not directories, symlinks, etc.).
        if [ -f "${target}" ] && [ ! -L "${target}" ]; then
            # Get current permission bits in octal.
            current_perm=$(stat -c '%a' "${target}" 2>/dev/null)
            [ -z "${current_perm}" ] && continue

            current_perm_dec=$((8#${current_perm}))

            # Compute the resulting permission by masking off any bits
            # that exceed 0740 (i.e., keep only bits allowed by MAX_PERM).
            new_perm_dec=$(( current_perm_dec & MAX_PERM_DEC ))

            if [ "${current_perm_dec}" -ne "${new_perm_dec}" ]; then
                new_perm_oct=$(printf '%04o' "${new_perm_dec}")
                chmod "${new_perm_oct}" "${target}" && \
                    echo "Adjusted permissions of ${target}: ${current_perm} -> ${new_perm_oct}"
            fi
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

**Prompt:** On a RHEL 8 system, ensure the default umask for all Bash shell users is configured to limit file permissions such that newly created files are not excessively permissive. The default umask should mask permissions to prevent unauthorized read, write, or execution by others. Write an idempotent bash remediation script to enforce a default umask value of 077 for all users under the Bash shell, ensuring the setting persists for new sessions.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation script: enforce a default umask of 077 for all Bash shell users
# Idempotent - safe to run multiple times.

set -euo pipefail

UMASK_VALUE="077"

# Files that affect Bash login/interactive session umask
BASHRC="/etc/bashrc"
PROFILE="/etc/profile"
PROFILE_D_FILE="/etc/profile.d/set_umask.sh"

# Function to remediate umask entries in a given file
remediate_file() {
    local file="$1"

    # Skip if file does not exist (we will not create /etc/bashrc or /etc/profile)
    if [ ! -f "$file" ]; then
        return 0
    fi

    # Backup the file once if not already backed up
    if [ ! -f "${file}.orig" ]; then
        cp -p "$file" "${file}.orig"
    fi

    # Replace any existing umask lines (that set a value) with the desired one.
    # Matches lines like:  umask 022 , umask 0022 , UMASK 077 (case-insensitive on keyword)
    if grep -Eiq '^[[:space:]]*umask[[:space:]]+[0-7]{3,4}' "$file"; then
        sed -ri "s/^([[:space:]]*)umask[[:space:]]+[0-7]{3,4}.*/\1umask ${UMASK_VALUE}/I" "$file"
    fi
}

# Remediate the standard system bash files
remediate_file "$BASHRC"
remediate_file "$PROFILE"

# Ensure a dedicated profile.d drop-in enforces the umask for all shells.
# This guarantees the setting persists for new sessions even if the main files
# did not previously contain a umask entry.
DESIRED_CONTENT="# Set default umask to ${UMASK_VALUE} for all users (security hardening)
umask ${UMASK_VALUE}"

if [ ! -f "$PROFILE_D_FILE" ] || [ "$(cat "$PROFILE_D_FILE" 2>/dev/null || true)" != "$DESIRED_CONTENT" ]; then
    printf '%s\n' "$DESIRED_CONTENT" > "$PROFILE_D_FILE"
fi

# Ensure proper permissions on the drop-in file
chmod 0644 "$PROFILE_D_FILE"
chown root:root "$PROFILE_D_FILE"

echo "Default umask successfully enforced to ${UMASK_VALUE} for all Bash shell users."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q bash; then

var_accounts_user_umask='
```


---

## RHEL-08-020353 — `accounts_umask_etc_csh_cshrc`

**Prompt:** On a RHEL 8 system, ensure that the default umask for users who use the C shell is set to prevent new files from having more permissive access than necessary, by setting it to the value of 077. This ensures new files are not group or world-readable, reducing the risk of unauthorized data exposure. Write an idempotent bash remediation script that configures the default umask for the C shell to be 077, and ensures this configuration persists for all user sessions.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

CSH_FILE="/etc/csh.cshrc"
UMASK_VALUE="077"

# Ensure the file exists
if [ ! -f "$CSH_FILE" ]; then
    touch "$CSH_FILE"
    chmod 0644 "$CSH_FILE"
fi

# Check for existing umask line(s) and normalize them
if grep -qE '^\s*umask\s+' "$CSH_FILE"; then
    # Replace any existing umask setting with the desired value
    sed -ri "s/^\s*umask\s+[0-7]+\s*$/umask ${UMASK_VALUE}/" "$CSH_FILE"
    # Verify the replacement resulted in the correct value; if not, append correct one
    if ! grep -qE "^umask\s+${UMASK_VALUE}\s*$" "$CSH_FILE"; then
        # Remove any lingering umask lines that don't match and append the correct one
        sed -ri '/^\s*umask\s+[0-7]+\s*$/d' "$CSH_FILE"
        echo "umask ${UMASK_VALUE}" >> "$CSH_FILE"
    fi
else
    echo "umask ${UMASK_VALUE}" >> "$CSH_FILE"
fi

# Final idempotency check
if grep -qE "^umask\s+${UMASK_VALUE}\s*$" "$CSH_FILE"; then
    echo "C shell default umask is correctly set to ${UMASK_VALUE} in ${CSH_FILE}."
else
    echo "Failed to set C shell default umask to ${UMASK_VALUE} in ${CSH_FILE}." >&2
    exit 1
fi
```

**Reference fix:**
```bash
var_accounts_user_umask='
```


---

## RHEL-08-020351 — `accounts_umask_etc_login_defs`

**Prompt:** On a RHEL 8 system, the umask setting in the login configuration defines the default permission mask for newly created files, impacting security by determining which permission bits are unset. Ensure that the default umask in the login settings is correctly configured such that newly created files do not allow write access to group and others, typically resulting in default permissions of 0755 for directories and 0644 for files. Write an idempotent bash remediation script that enforces this umask configuration to mitigate the risk of unauthorized access due to overly permissive file permissions.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation script: enforce default UMASK 022 in /etc/login.defs
# Ensures newly created files are 0644 and directories 0755
# (i.e., no write access for group and others).
#
# Idempotent: only makes changes when necessary.

set -euo pipefail

LOGIN_DEFS="/etc/login.defs"
DESIRED_UMASK="022"

# Ensure the login.defs file exists
if [[ ! -f "$LOGIN_DEFS" ]]; then
    echo "Creating $LOGIN_DEFS as it does not exist."
    touch "$LOGIN_DEFS"
    chmod 0644 "$LOGIN_DEFS"
    chown root:root "$LOGIN_DEFS"
fi

# Check current UMASK configuration (ignore commented lines)
current_line="$(grep -Ei '^[[:space:]]*UMASK[[:space:]]+' "$LOGIN_DEFS" || true)"

if [[ -n "$current_line" ]]; then
    current_value="$(echo "$current_line" | awk '{print $2}')"
    if [[ "$current_value" == "$DESIRED_UMASK" ]]; then
        echo "UMASK already correctly set to $DESIRED_UMASK in $LOGIN_DEFS. No change needed."
    else
        echo "Updating existing UMASK value ($current_value) to $DESIRED_UMASK in $LOGIN_DEFS."
        # Replace any active UMASK line(s) with the desired value
        sed -ri "s/^[[:space:]]*UMASK[[:space:]]+.*/UMASK           ${DESIRED_UMASK}/I" "$LOGIN_DEFS"
    fi
else
    echo "No active UMASK setting found. Adding UMASK $DESIRED_UMASK to $LOGIN_DEFS."
    # Remove any commented UMASK lines to avoid confusion, then append the setting
    printf 'UMASK           %s\n' "$DESIRED_UMASK" >> "$LOGIN_DEFS"
fi

# Verify the result
final_value="$(grep -Ei '^[[:space:]]*UMASK[[:space:]]+' "$LOGIN_DEFS" | awk '{print $2}' | head -n1 || true)"
if [[ "$final_value" == "$DESIRED_UMASK" ]]; then
    echo "Verification succeeded: UMASK is set to $DESIRED_UMASK in $LOGIN_DEFS."
    exit 0
else
    echo "ERROR: Verification failed. UMASK is '$final_value' instead of '$DESIRED_UMASK'." >&2
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

**Prompt:** On a RHEL 8 system, ensure that Kernel Page-Table Isolation (KPTI), a protective measure against the Meltdown vulnerability, is enabled by default for all current and future Linux kernel boot entries. Write an idempotent bash remediation script that adds the necessary parameter to all existing kernels and updates the default boot settings so KPTI remains enabled even after kernel updates or reinstallations.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure Kernel Page-Table Isolation (KPTI) is enabled by default
# for all current and future kernel boot entries on RHEL 8.
#
# The relevant kernel boot parameter is "pti=on".

set -euo pipefail

PARAM="pti=on"

# --- Ensure grubby is available ---
if ! command -v grubby >/dev/null 2>&1; then
    echo "ERROR: grubby is not installed. Install it with: yum install -y grubby" >&2
    exit 1
fi

# --- 1. Apply the parameter to all existing kernel boot entries ---
# grubby is idempotent for --update-kernel; running it again does not create
# duplicate arguments.
echo "Updating all existing kernel boot entries to include '${PARAM}'..."
grubby --update-kernel=ALL --args="${PARAM}"

# --- 2. Ensure the parameter is applied to future kernels ---
# Future kernels installed via 'yum'/'dnf' derive their command line from
# /etc/default/grub (GRUB_CMDLINE_LINUX). Add the parameter there idempotently.
GRUB_DEFAULT="/etc/default/grub"

if [[ -f "${GRUB_DEFAULT}" ]]; then
    if grep -q '^GRUB_CMDLINE_LINUX=' "${GRUB_DEFAULT}"; then
        # Extract the current value (strip surrounding quotes)
        current_line="$(grep '^GRUB_CMDLINE_LINUX=' "${GRUB_DEFAULT}")"
        current_value="${current_line#GRUB_CMDLINE_LINUX=}"
        current_value="${current_value%\"}"
        current_value="${current_value#\"}"

        # Only add if not already present
        if ! grep -qw "${PARAM}" <<<"${current_value}"; then
            if [[ -n "${current_value}" ]]; then
                new_value="${current_value} ${PARAM}"
            else
                new_value="${PARAM}"
            fi
            # Escape special characters for sed replacement
            escaped_new_value="$(printf '%s' "${new_value}" | sed -e 's/[\/&]/\\&/g')"
            sed -i "s/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX=\"${escaped_new_value}\"/" "${GRUB_DEFAULT}"
            echo "Added '${PARAM}' to GRUB_CMDLINE_LINUX in ${GRUB_DEFAULT}."
        else
            echo "'${PARAM}' already present in GRUB_CMDLINE_LINUX; no change needed."
        fi
    else
        # No GRUB_CMDLINE_LINUX line exists; add one.
        echo "GRUB_CMDLINE_LINUX=\"${PARAM}\"" >>"${GRUB_DEFAULT}"
        echo "Created GRUB_CMDLINE_LINUX with '${PARAM}' in ${GRUB_DEFAULT}."
    fi
else
    echo "WARNING: ${GRUB_DEFAULT} not found; skipping default grub config update." >&2
fi

# --- 3. Regenerate the GRUB configuration to persist the default settings ---
if [[ -d /sys/firmware/efi ]]; then
    GRUB_CFG="/boot/efi/EFI/redhat/grub.cfg"
else
    GRUB_CFG="/boot/grub2/grub.cfg"
fi

if [[ -f "${GRUB_CFG}" ]]; then
    echo "Regenerating GRUB configuration at ${GRUB_CFG}..."
    grub2-mkconfig -o "${GRUB_CFG}"
else
    echo "WARNING: GRUB config ${GRUB_CFG} not found; attempting default location." >&2
    if [[ -d /sys/firmware/efi ]]; then
        grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg || true
    else
        grub2-mkconfig -o /boot/grub2/grub.cfg || true
    fi
fi

echo "KPTI (pti=on) remediation complete. A reboot is required for changes to take effect."
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

**Prompt:** On a RHEL 8 system, virtual system calls (vsyscalls) are currently enabled, which can give attackers a vector for controlling the instruction pointer within the kernel. Ensure that vsyscalls are disabled across all current and future system boots by incorporating the appropriate kernel argument in the GRUB configuration. Write an idempotent bash remediation script that updates the necessary GRUB settings to disable vsyscalls, ensuring this setting persists through kernel updates and system reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Disable vsyscalls via kernel argument vsyscall=none
# Ensures persistence across current and future boots on RHEL 8.
#
set -euo pipefail

ARG="vsyscall=none"
GRUB_DEFAULT="/etc/default/grub"

# --- 1. Ensure the argument is present in /etc/default/grub (future kernels) ---

# Create the file if it does not exist
if [ ! -f "$GRUB_DEFAULT" ]; then
    touch "$GRUB_DEFAULT"
fi

if grep -q '^GRUB_CMDLINE_LINUX=' "$GRUB_DEFAULT"; then
    # Extract current value
    current_line="$(grep '^GRUB_CMDLINE_LINUX=' "$GRUB_DEFAULT")"
    if echo "$current_line" | grep -qw "vsyscall=none"; then
        echo "vsyscall=none already present in GRUB_CMDLINE_LINUX."
    else
        # Remove any existing vsyscall= setting, then append vsyscall=none
        # Work on the value inside the quotes
        value="$(sed -n 's/^GRUB_CMDLINE_LINUX="\(.*\)"$/\1/p' "$GRUB_DEFAULT")"
        # Strip any existing vsyscall= token
        value="$(echo "$value" | sed -E 's/\bvsyscall=[^ ]*//g' | tr -s ' ' | sed 's/^ //;s/ $//')"
        if [ -z "$value" ]; then
            newvalue="$ARG"
        else
            newvalue="$value $ARG"
        fi
        sed -i "s|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=\"$newvalue\"|" "$GRUB_DEFAULT"
        echo "Updated GRUB_CMDLINE_LINUX with vsyscall=none."
    fi
else
    echo "GRUB_CMDLINE_LINUX=\"$ARG\"" >> "$GRUB_DEFAULT"
    echo "Added GRUB_CMDLINE_LINUX with vsyscall=none."
fi

# --- 2. Apply to all existing kernel boot entries (current boots) ---

if command -v grubby >/dev/null 2>&1; then
    grubby --update-kernel=ALL --args="$ARG"
    echo "Applied vsyscall=none to all existing kernel entries via grubby."
    # Ensure new kernels inherit the argument
    grubby --update-kernel=DEFAULT --args="$ARG" >/dev/null 2>&1 || true
fi

# --- 3. Regenerate the GRUB configuration ---

if [ -d /sys/firmware/efi ]; then
    GRUB_CFG="/boot/efi/EFI/redhat/grub.cfg"
    if [ ! -f "$GRUB_CFG" ]; then
        # Fallback locations
        GRUB_CFG="$(find /boot/efi/EFI -name grub.cfg 2>/dev/null | head -n1 || true)"
        [ -z "$GRUB_CFG" ] && GRUB_CFG="/boot/efi/EFI/redhat/grub.cfg"
    fi
else
    GRUB_CFG="/boot/grub2/grub.cfg"
fi

if command -v grub2-mkconfig >/dev/null 2>&1; then
    grub2-mkconfig -o "$GRUB_CFG"
    echo "Regenerated GRUB configuration at $GRUB_CFG."
fi

echo "Remediation complete: vsyscalls disabled (vsyscall=none)."
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

**Prompt:** On a RHEL 8 system, ensure the Rsyslog service is configured to authenticate remote systems to which it off-loads audit logs. This is crucial for maintaining the integrity and confidentiality of audit records by preventing unauthorized access during transmission. Write an idempotent bash remediation script that configures Rsyslog to authenticate all remote logging communications using x509 certificates. This configuration should persist through reboots and should be applicable whether legacy syntax or RainerScript syntax is used in the Rsyslog configuration files.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure Rsyslog authenticates remote systems (off-loading audit
# logs) using x509 certificates. Idempotent and persistent across reboots.
#
set -u

RSYSLOG_CONF="/etc/rsyslog.conf"
CONF_D="/etc/rsyslog.d"
DROPIN="${CONF_D}/60-tls-auth.conf"

# Ensure the config directory exists
mkdir -p "${CONF_D}"

#
# Detect whether legacy syntax or RainerScript syntax is in use.
# RainerScript uses "action(...)" directives; legacy uses "*.* @@host" or
# "$ActionSendStreamDriver..." style directives.
#
uses_rainerscript=0
if grep -rEq '^\s*action\s*\(' "${RSYSLOG_CONF}" "${CONF_D}" 2>/dev/null; then
    uses_rainerscript=1
fi
if grep -rEiq 'StreamDriver\s*=' "${RSYSLOG_CONF}" "${CONF_D}" 2>/dev/null; then
    uses_rainerscript=1
fi

#
# Helper: set or replace a legacy-style directive in a given file.
# Args: <file> <directive-name> <full-line>
#
set_legacy_directive() {
    local file="$1"
    local key="$2"
    local line="$3"

    # Remove any existing (commented or active) occurrences of the directive
    if [ -f "${file}" ]; then
        sed -ri "/^\s*#?\s*${key}\b/d" "${file}"
    fi
    printf '%s\n' "${line}" >> "${file}"
}

if [ "${uses_rainerscript}" -eq 1 ]; then
    #
    # RainerScript / modern syntax configuration.
    # Enforce x509/name authentication on outbound TLS connections.
    #
    cat > "${DROPIN}" <<'EOF'
# Managed by remediation: authenticate remote systems via x509 certificates
global(
    DefaultNetstreamDriver="gtls"
    DefaultNetstreamDriverCAFile="/etc/pki/ca-trust/source/anchors/rsyslog-ca.pem"
    DefaultNetstreamDriverCertFile="/etc/pki/tls/certs/rsyslog-cert.pem"
    DefaultNetstreamDriverKeyFile="/etc/pki/tls/private/rsyslog-key.pem"
)

# Require x509 name-based authentication of remote peers
action(
    type="omfwd"
    StreamDriver="gtls"
    StreamDriverMode="1"
    StreamDriverAuthMode="x509/name"
)
EOF
else
    #
    # Legacy syntax configuration in the main rsyslog.conf.
    #
    set_legacy_directive "${RSYSLOG_CONF}" \
        "\\\$DefaultNetstreamDriver" \
        '$DefaultNetstreamDriver gtls'

    set_legacy_directive "${RSYSLOG_CONF}" \
        "\\\$DefaultNetstreamDriverCAFile" \
        '$DefaultNetstreamDriverCAFile /etc/pki/ca-trust/source/anchors/rsyslog-ca.pem'

    set_legacy_directive "${RSYSLOG_CONF}" \
        "\\\$DefaultNetstreamDriverCertFile" \
        '$DefaultNetstreamDriverCertFile /etc/pki/tls/certs/rsyslog-cert.pem'

    set_legacy_directive "${RSYSLOG_CONF}" \
        "\\\$DefaultNetstreamDriverKeyFile" \
        '$DefaultNetstreamDriverKeyFile /etc/pki/tls/private/rsyslog-key.pem'

    set_legacy_directive "${RSYSLOG_CONF}" \
        "\\\$ActionSendStreamDriverMode" \
        '$ActionSendStreamDriverMode 1'

    set_legacy_directive "${RSYSLOG_CONF}" \
        "\\\$ActionSendStreamDriverAuthMode" \
        '$ActionSendStreamDriverAuthMode x509/name'
fi

#
# Validate configuration syntax if possible (non-fatal).
#
if command -v rsyslogd >/dev/null 2>&1; then
    rsyslogd -N1 >/dev/null 2>&1 || true
fi

#
# Enable and restart the service so changes persist and take effect.
#
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable rsyslog >/dev/null 2>&1 || true
    systemctl restart rsyslog >/dev/null 2>&1 || true
fi

exit 0
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

**Prompt:** On a RHEL 8 system, configure the Rsyslog service to ensure that audit records are securely encrypted when off-loading logs to a remote server, protecting them from unauthorized access during transmission. Write an idempotent bash remediation script that configures Rsyslog to use encryption for off-loaded logs by setting the appropriate parameter to ensure encrypted transmission of logs.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure Rsyslog encrypts off-loaded audit records to a remote log server.
#
# This script configures the rsyslog gtls driver so that logs sent to a
# remote server are transmitted using TLS encryption.
#
set -o pipefail

CONFIG_FILE="/etc/rsyslog.conf"
DROPIN_DIR="/etc/rsyslog.d"
DROPIN_FILE="${DROPIN_DIR}/remote-tls.conf"

# The directive that enables TLS/encrypted transport for off-loaded logs.
PARAM_KEY="\$DefaultNetstreamDriver"
PARAM_VALUE="gtls"
DIRECTIVE="${PARAM_KEY} ${PARAM_VALUE}"

# Ensure the configuration directory exists
if [ ! -d "${DROPIN_DIR}" ]; then
    mkdir -p "${DROPIN_DIR}"
fi

# Function to escape a string for use in sed/grep patterns
escape_re() {
    printf '%s' "$1" | sed -e 's/[.[\*^$/]/\\&/g'
}

ESCAPED_KEY="$(escape_re "${PARAM_KEY}")"

# Search for an existing (uncommented) DefaultNetstreamDriver directive across
# rsyslog configuration files.
found_file=""
if [ -f "${CONFIG_FILE}" ]; then
    if grep -Eq "^[[:space:]]*${ESCAPED_KEY}[[:space:]]+" "${CONFIG_FILE}"; then
        found_file="${CONFIG_FILE}"
    fi
fi

if [ -z "${found_file}" ]; then
    for f in "${DROPIN_DIR}"/*.conf; do
        [ -e "$f" ] || continue
        if grep -Eq "^[[:space:]]*${ESCAPED_KEY}[[:space:]]+" "$f"; then
            found_file="$f"
            break
        fi
    done
fi

if [ -n "${found_file}" ]; then
    # A directive already exists; make it idempotent by ensuring the value is gtls.
    if grep -Eq "^[[:space:]]*${ESCAPED_KEY}[[:space:]]+${PARAM_VALUE}[[:space:]]*$" "${found_file}"; then
        echo "Rsyslog encryption driver already correctly configured in ${found_file}."
    else
        sed -i -E "s|^[[:space:]]*${ESCAPED_KEY}[[:space:]]+.*$|${DIRECTIVE}|" "${found_file}"
        echo "Updated ${PARAM_KEY} directive in ${found_file}."
    fi
else
    # No directive present; add it in a dedicated drop-in file.
    if [ -f "${DROPIN_FILE}" ] && grep -Eq "^[[:space:]]*${ESCAPED_KEY}[[:space:]]+${PARAM_VALUE}[[:space:]]*$" "${DROPIN_FILE}"; then
        echo "Rsyslog encryption driver already configured in ${DROPIN_FILE}."
    else
        {
            echo "# Ensure off-loaded logs are transmitted encrypted (TLS)"
            echo "${DIRECTIVE}"
        } >> "${DROPIN_FILE}"
        echo "Added ${PARAM_KEY} directive to ${DROPIN_FILE}."
    fi
fi

# Restart rsyslog to apply the change if the service is present and active.
if command -v systemctl >/dev/null 2>&1; then
    if systemctl list-unit-files 2>/dev/null | grep -q '^rsyslog\.service'; then
        systemctl restart rsyslog.service 2>/dev/null && \
            echo "rsyslog service restarted." || \
            echo "Warning: unable to restart rsyslog service."
    fi
fi

exit 0
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

**Prompt:** On a RHEL 8 system, ensure that rsyslog encrypts all audit logs before off-loading them to remote systems to protect the data from unauthorized access during transmission. Write an idempotent bash remediation script that configures rsyslog to utilize TLS via gnutls for secure communication when off-loading logs. This configuration must be verified as active, ensure it applies both immediately and persists across reboots.

**Model-generated script:**
```bash
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure rsyslog encrypts audit logs (via TLS/gnutls) before
# off-loading them to remote systems on RHEL 8.
#
# Idempotent: safe to run multiple times.
#
set -euo pipefail

RSYSLOG_CONF="/etc/rsyslog.conf"
RSYSLOG_D="/etc/rsyslog.d"
TLS_CONF="${RSYSLOG_D}/tls-encryption.conf"
CA_CERT="/etc/pki/tls/certs/rsyslog-ca.pem"
CLIENT_CERT="/etc/pki/tls/certs/rsyslog-cert.pem"
CLIENT_KEY="/etc/pki/tls/private/rsyslog-key.pem"
# Remote log server destination - adjust as needed for your environment
REMOTE_SERVER="logcollector.example.com"
REMOTE_PORT="6514"

echo "==> Starting rsyslog TLS remediation"

########################################
# 1. Ensure required packages installed
########################################
PKGS=(rsyslog rsyslog-gnutls gnutls-utils)
MISSING=()
for pkg in "${PKGS[@]}"; do
    if ! rpm -q "$pkg" >/dev/null 2>&1; then
        MISSING+=("$pkg")
    fi
done

if [ "${#MISSING[@]}" -gt 0 ]; then
    echo "==> Installing missing packages: ${MISSING[*]}"
    yum install -y "${MISSING[@]}"
else
    echo "==> All required packages already installed"
fi

########################################
# 2. Ensure TLS certificate material exists
########################################
mkdir -p /etc/pki/tls/certs /etc/pki/tls/private
chmod 0755 /etc/pki/tls/certs
chmod 0700 /etc/pki/tls/private

if [ ! -f "$CA_CERT" ]; then
    echo "WARNING: CA certificate not found at ${CA_CERT}."
    echo "         Provisioning a placeholder is not secure; please deploy your"
    echo "         organization's CA certificate to this path."
fi
if [ ! -f "$CLIENT_CERT" ]; then
    echo "WARNING: Client certificate not found at ${CLIENT_CERT}."
    echo "         Please deploy the rsyslog client certificate to this path."
fi
if [ ! -f "$CLIENT_KEY" ]; then
    echo "WARNING: Client key not found at ${CLIENT_KEY}."
    echo "         Please deploy the rsyslog client private key to this path."
fi

# Enforce secure perms on key if present
[ -f "$CLIENT_KEY" ] && chmod 0600 "$CLIENT_KEY" && chown root:root "$CLIENT_KEY"
[ -f "$CLIENT_CERT" ] && chmod 0644 "$CLIENT_CERT" && chown root:root "$CLIENT_CERT"
[ -f "$CA_CERT" ] && chmod 0644 "$CA_CERT" && chown root:root "$CA_CERT"

########################################
# 3. Ensure gnutls driver directives in main rsyslog.conf
########################################
declare -A GLOBAL_DIRECTIVES=(
    ["\$DefaultNetstreamDriver"]="gtls"
    ["\$DefaultNetstreamDriverCAFile"]="${CA_CERT}"
    ["\$DefaultNetstreamDriverCertFile"]="${CLIENT_CERT}"
    ["\$DefaultNetstreamDriverKeyFile"]="${CLIENT_KEY}"
)

if [ ! -f "$RSYSLOG_CONF" ]; then
    echo "ERROR: ${RSYSLOG_CONF} does not exist. Aborting."
    exit 1
fi

CHANGED=0
for key in "${!GLOBAL_DIRECTIVES[@]}"; do
    value="${GLOBAL_DIRECTIVES[$key]}"
    # Escape $ for grep/sed
    esc_key=$(printf '%s' "$key" | sed 's/[$]/\\$/g')
    if grep -Eq "^[[:space:]]*${esc_key}[[:space:]]" "$RSYSLOG_CONF"; then
        # Update in place if value differs
        if ! grep -Eq "^[[:space:]]*${esc_key}[[:space:]]+${value//\//\\/}[[:space:]]*$" "$RSYSLOG_CONF"; then
            sed -i -E "s|^[[:space:]]*${esc_key}[[:space:]].*$|${key} ${value}|" "$RSYSLOG_CONF"
            echo "==> Updated directive: ${key} ${value}"
            CHANGED=1
        fi
    else
        echo "${key} ${value}" >> "$RSYSLOG_CONF"
        echo "==> Added directive: ${key} ${value}"
        CHANGED=1
    fi
done

########################################
# 4. Write TLS off-loading config with encryption enforced
########################################
TMP_TLS="$(mktemp)"
cat > "$TMP_TLS" <<EOF
# Managed by remediation script - rsyslog TLS off-loading of audit logs
# Ensures all forwarded logs are encrypted using gnutls (TLS).

# Use gtls netstream driver with strict anonymous authentication disabled
\$DefaultNetstreamDriver gtls
\$DefaultNetstreamDriverCAFile ${CA_CERT}
\$DefaultNetstreamDriverCertFile ${CLIENT_CERT}
\$DefaultNetstreamDriverKeyFile ${CLIENT_KEY}

# TLS driver mode: 1 = TLS-only
\$ActionSendStreamDriverMode 1
# Require server certificate authentication (x509/name)
\$ActionSendStreamDriverAuthMode x509/name

# Forward all logs (including audit) encrypted via TLS to remote collector
*.* @@${REMOTE_SERVER}:${REMOTE_PORT}
EOF

if [ -f "$TLS_CONF" ] && cmp -s "$TMP_TLS" "$TLS_CONF"; then
    echo "==> TLS off-loading config already correct: ${TLS_CONF}"
    rm -f "$TMP_TLS"
else
    mv "$TMP_TLS" "$TLS_CONF"
    chmod 0644 "$TLS_CONF"
    chown root:root "$TLS_CONF"
    echo "==> Wrote TLS off-loading config: ${TLS_CONF}"
    CHANGED=1
fi

########################################
# 5. Validate rsyslog configuration syntax
########################################
echo "==> Validating rsyslog configuration"
if ! rsyslogd -N1 >/dev/null 2>&1; then
    echo "ERROR: rsyslog configuration validation failed:"
    rsyslogd -N1 || true
    exit 1
fi
echo "==> rsyslog configuration
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

**Prompt:** On a RHEL 8 system, ensure that the Rsyslog service is configured to log remote access events to identifiable logs. The logging configuration must match all security-related access activities from the following categories: authentication events and daemon events. These configurations should persist across service restarts and reboots. Write an idempotent bash remediation script that sets up the Rsyslog configuration to achieve this logging requirement, ensuring that remote access methods are monitored and logged correctly.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation script: Configure Rsyslog to log remote access events
# (authentication and daemon events) to identifiable log files.
# Idempotent: safe to run multiple times.
#
set -euo pipefail

RSYSLOG_CONF_DIR="/etc/rsyslog.d"
REMOTE_ACCESS_CONF="${RSYSLOG_CONF_DIR}/50-remote-access.conf"
AUTH_LOG="/var/log/secure"
DAEMON_LOG="/var/log/messages"

# Ensure this script is run as root
if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

# Ensure rsyslog package is installed
if ! rpm -q rsyslog >/dev/null 2>&1; then
    echo "Installing rsyslog package..."
    if command -v dnf >/dev/null 2>&1; then
        dnf install -y rsyslog
    else
        yum install -y rsyslog
    fi
fi

# Ensure the rsyslog drop-in directory exists
if [[ ! -d "${RSYSLOG_CONF_DIR}" ]]; then
    mkdir -p "${RSYSLOG_CONF_DIR}"
    chmod 0755 "${RSYSLOG_CONF_DIR}"
fi

# Desired configuration content
read -r -d '' DESIRED_CONF <<EOF || true
# Managed by remediation script - do not edit manually
# Log remote access security events to identifiable logs.
# Authentication events (auth, authpriv) -> ${AUTH_LOG}
# Daemon events (daemon) -> ${DAEMON_LOG}

auth.*;authpriv.*                                       ${AUTH_LOG}
daemon.*                                                ${DAEMON_LOG}
EOF

# Write configuration only if it differs (idempotent)
NEEDS_RESTART=0
if [[ -f "${REMOTE_ACCESS_CONF}" ]]; then
    if ! diff -q <(printf '%s\n' "${DESIRED_CONF}") "${REMOTE_ACCESS_CONF}" >/dev/null 2>&1; then
        printf '%s\n' "${DESIRED_CONF}" > "${REMOTE_ACCESS_CONF}"
        NEEDS_RESTART=1
    fi
else
    printf '%s\n' "${DESIRED_CONF}" > "${REMOTE_ACCESS_CONF}"
    NEEDS_RESTART=1
fi

# Set secure permissions on configuration file
chmod 0644 "${REMOTE_ACCESS_CONF}"
chown root:root "${REMOTE_ACCESS_CONF}"

# Ensure the log files exist with correct permissions
for logfile in "${AUTH_LOG}" "${DAEMON_LOG}"; do
    if [[ ! -f "${logfile}" ]]; then
        touch "${logfile}"
    fi
    chown root:root "${logfile}"
    chmod 0600 "${logfile}"
done

# Validate rsyslog configuration syntax
if command -v rsyslogd >/dev/null 2>&1; then
    if ! rsyslogd -N1 >/dev/null 2>&1; then
        echo "ERROR: rsyslog configuration validation failed." >&2
        rsyslogd -N1
        exit 1
    fi
fi

# Ensure rsyslog service is enabled to persist across reboots
if command -v systemctl >/dev/null 2>&1; then
    if ! systemctl is-enabled rsyslog >/dev/null 2>&1; then
        systemctl enable rsyslog
        NEEDS_RESTART=1
    fi

    # Restart/start rsyslog to apply configuration and persist across restarts
    if ! systemctl is-active rsyslog >/dev/null 2>&1; then
        systemctl start rsyslog
    elif [[ "${NEEDS_RESTART}" -eq 1 ]]; then
        systemctl restart rsyslog
    fi
else
    # Fallback for non-systemd environments
    if [[ "${NEEDS_RESTART}" -eq 1 ]]; then
        service rsyslog restart || service rsyslog start
    fi
fi

echo "Rsyslog remote access logging configuration applied successfully."
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

**Prompt:** For a RHEL 8 system, ensure that system log messages are sent to a designated remote log server to aid in centralized monitoring and forensic analysis. Write an idempotent bash remediation script that configures the system's logging service to forward logs to a remote server using TCP for reliable delivery. Ensure that this configuration persists across reboots and that the remote server's address can be resolved via DNS.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Idempotent remediation script to forward rsyslog messages to a remote
# log server over TCP on RHEL 8.
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
REMOTE_LOG_SERVER="${REMOTE_LOG_SERVER:-logserver.example.com}"
REMOTE_LOG_PORT="${REMOTE_LOG_PORT:-514}"
RSYSLOG_CONF_DIR="/etc/rsyslog.d"
FORWARD_CONF_FILE="${RSYSLOG_CONF_DIR}/00-remote-forward.conf"

# ---------------------------------------------------------------------------
# Ensure we are running as root
# ---------------------------------------------------------------------------
if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Ensure rsyslog is installed
# ---------------------------------------------------------------------------
if ! rpm -q rsyslog >/dev/null 2>&1; then
    echo "Installing rsyslog..."
    yum install -y rsyslog
fi

# ---------------------------------------------------------------------------
# Ensure the configuration directory exists
# ---------------------------------------------------------------------------
if [[ ! -d "${RSYSLOG_CONF_DIR}" ]]; then
    mkdir -p "${RSYSLOG_CONF_DIR}"
    chmod 0755 "${RSYSLOG_CONF_DIR}"
fi

# ---------------------------------------------------------------------------
# Build the desired configuration content
#   - "@@" prefix selects TCP transport (reliable delivery)
#   - Hostname (rather than IP) allows DNS resolution
#   - Disk-assisted queue provides resilience across restarts/outages
# ---------------------------------------------------------------------------
read -r -d '' DESIRED_CONFIG <<EOF || true
# Managed by remediation script - forward all logs to remote server over TCP
# Do not edit manually; changes may be overwritten.
\$ActionQueueType LinkedList
\$ActionQueueFileName remotefwd
\$ActionResumeRetryCount -1
\$ActionQueueSaveOnShutdown on
*.* @@${REMOTE_LOG_SERVER}:${REMOTE_LOG_PORT}
EOF

# ---------------------------------------------------------------------------
# Write configuration only if it differs (idempotency)
# ---------------------------------------------------------------------------
NEED_RESTART=0
if [[ -f "${FORWARD_CONF_FILE}" ]] && \
   printf '%s\n' "${DESIRED_CONFIG}" | cmp -s - "${FORWARD_CONF_FILE}"; then
    echo "Remote log forwarding already configured correctly. No changes made."
else
    echo "Writing remote log forwarding configuration to ${FORWARD_CONF_FILE}..."
    printf '%s\n' "${DESIRED_CONFIG}" > "${FORWARD_CONF_FILE}"
    chmod 0644 "${FORWARD_CONF_FILE}"
    chown root:root "${FORWARD_CONF_FILE}"
    NEED_RESTART=1
fi

# ---------------------------------------------------------------------------
# Validate rsyslog configuration before applying
# ---------------------------------------------------------------------------
if command -v rsyslogd >/dev/null 2>&1; then
    if ! rsyslogd -N1 >/dev/null 2>&1; then
        echo "ERROR: rsyslog configuration validation failed." >&2
        exit 1
    fi
fi

# ---------------------------------------------------------------------------
# Ensure rsyslog is enabled to persist across reboots
# ---------------------------------------------------------------------------
if ! systemctl is-enabled rsyslog >/dev/null 2>&1; then
    echo "Enabling rsyslog service..."
    systemctl enable rsyslog
    NEED_RESTART=1
fi

# ---------------------------------------------------------------------------
# Ensure rsyslog is running / restart to pick up new config
# ---------------------------------------------------------------------------
if ! systemctl is-active rsyslog >/dev/null 2>&1; then
    echo "Starting rsyslog service..."
    systemctl start rsyslog
elif [[ "${NEED_RESTART}" -eq 1 ]]; then
    echo "Restarting rsyslog service to apply changes..."
    systemctl restart rsyslog
fi

echo "Remote log forwarding to ${REMOTE_LOG_SERVER}:${REMOTE_LOG_PORT} (TCP) is configured."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

rsyslog_remote_loghost_address='
```


---

## RHEL-08-040261 — `sysctl_net_ipv6_conf_all_accept_ra`

**Prompt:** On a RHEL 8 system, disable the acceptance of IPv6 router advertisements on all network interfaces to prevent potential man-in-the-middle attacks facilitated by unauthorized router advertisements. Write an idempotent bash remediation script that enforces this configuration both at runtime and across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

SYSCTL_CONF_DIR="/etc/sysctl.d"
SYSCTL_CONF_FILE="${SYSCTL_CONF_DIR}/60-disable-ra.conf"

PARAMS=(
    "net.ipv6.conf.all.accept_ra"
    "net.ipv6.conf.default.accept_ra"
)

# Ensure the sysctl configuration directory exists
mkdir -p "${SYSCTL_CONF_DIR}"

# Create or update the persistent configuration file idempotently
tmpfile="$(mktemp)"
trap 'rm -f "${tmpfile}"' EXIT

# Preserve any unrelated lines from the existing file, dropping managed keys
if [[ -f "${SYSCTL_CONF_FILE}" ]]; then
    while IFS= read -r line; do
        skip=false
        for param in "${PARAMS[@]}"; do
            if [[ "${line}" =~ ^[[:space:]]*${param//./\\.}[[:space:]]*= ]]; then
                skip=true
                break
            fi
        done
        if [[ "${skip}" == false ]]; then
            printf '%s\n' "${line}" >> "${tmpfile}"
        fi
    done < "${SYSCTL_CONF_FILE}"
fi

# Append the managed parameters
for param in "${PARAMS[@]}"; do
    printf '%s = 0\n' "${param}" >> "${tmpfile}"
done

# Only replace the file if content differs (idempotency)
if [[ ! -f "${SYSCTL_CONF_FILE}" ]] || ! cmp -s "${tmpfile}" "${SYSCTL_CONF_FILE}"; then
    install -m 0644 "${tmpfile}" "${SYSCTL_CONF_FILE}"
    echo "Updated ${SYSCTL_CONF_FILE}"
else
    echo "${SYSCTL_CONF_FILE} already up to date"
fi

# Apply the persistent settings
for param in "${PARAMS[@]}"; do
    sysctl -w "${param}=0" >/dev/null
done

# Enforce at runtime on every current interface (including 'all' and 'default')
for iface_path in /proc/sys/net/ipv6/conf/*/accept_ra; do
    [[ -w "${iface_path}" ]] || continue
    current="$(cat "${iface_path}")"
    if [[ "${current}" != "0" ]]; then
        echo 0 > "${iface_path}"
    fi
done

# Reload sysctl settings to ensure consistency
sysctl --system >/dev/null 2>&1 || true

echo "IPv6 router advertisement acceptance disabled at runtime and persisted."
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

**Prompt:** On a RHEL 8 system, ensure that all IPv6 interfaces do not accept ICMP redirect messages, which can be used in man-in-the-middle attacks. Write an idempotent bash remediation script to configure the system so this setting is enforced at runtime and persists across reboots, disabling the acceptance of such redirects on all IPv6 interfaces.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

SYSCTL_PARAM="net.ipv6.conf.all.accept_redirects"
SYSCTL_VALUE="0"
SYSCTL_DEFAULT_PARAM="net.ipv6.conf.default.accept_redirects"
CONFIG_FILE="/etc/sysctl.d/99-disable-ipv6-redirects.conf"

# Remove the setting from any other sysctl configuration files to avoid conflicts
for f in /etc/sysctl.conf /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
    [ -f "$f" ] || continue
    [ "$f" = "$CONFIG_FILE" ] && continue
    if grep -Eq "^\s*${SYSCTL_PARAM}\s*=" "$f" 2>/dev/null; then
        sed -i -E "/^\s*${SYSCTL_PARAM//./\\.}\s*=/d" "$f"
    fi
    if grep -Eq "^\s*${SYSCTL_DEFAULT_PARAM}\s*=" "$f" 2>/dev/null; then
        sed -i -E "/^\s*${SYSCTL_DEFAULT_PARAM//./\\.}\s*=/d" "$f"
    fi
done

# Create/refresh the dedicated configuration file idempotently
TMP_FILE="$(mktemp)"
cat > "$TMP_FILE" <<EOF
${SYSCTL_PARAM} = ${SYSCTL_VALUE}
${SYSCTL_DEFAULT_PARAM} = ${SYSCTL_VALUE}
EOF

if [ ! -f "$CONFIG_FILE" ] || ! cmp -s "$TMP_FILE" "$CONFIG_FILE"; then
    mv "$TMP_FILE" "$CONFIG_FILE"
    chmod 0644 "$CONFIG_FILE"
else
    rm -f "$TMP_FILE"
fi

# Apply the setting at runtime for all and default, plus each existing interface
sysctl -w "${SYSCTL_PARAM}=${SYSCTL_VALUE}" >/dev/null
sysctl -w "${SYSCTL_DEFAULT_PARAM}=${SYSCTL_VALUE}" >/dev/null

if [ -d /proc/sys/net/ipv6/conf ]; then
    for iface_path in /proc/sys/net/ipv6/conf/*/accept_redirects; do
        [ -w "$iface_path" ] || continue
        echo "$SYSCTL_VALUE" > "$iface_path"
    done
fi

# Reload sysctl configuration to ensure persistence values are loaded
sysctl --system >/dev/null 2>&1 || true

echo "IPv6 ICMP redirect acceptance has been disabled and persisted."
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

**Prompt:** On a RHEL 8 system, when IPv6 forwarding is enabled and the system functions as a router, it currently allows acceptance of source-routed packets on all IPv6 interfaces, which can potentially bypass network security measures. Write an idempotent bash remediation script to ensure that the system does not accept source-routed packets on any IPv6 interfaces, applying the change immediately and ensuring it persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure the system does not accept IPv6 source-routed packets.
# Controls: net.ipv6.conf.all.accept_source_route
#           net.ipv6.conf.default.accept_source_route
#
set -euo pipefail

PARAMS=(
    "net.ipv6.conf.all.accept_source_route"
    "net.ipv6.conf.default.accept_source_route"
)
DESIRED_VALUE="0"
SYSCTL_DROPIN="/etc/sysctl.d/60-disable_ipv6_source_route.conf"

# Ensure the drop-in directory exists.
mkdir -p "$(dirname "${SYSCTL_DROPIN}")"

# --- Make the setting persistent ---------------------------------------------
# Remove any conflicting definitions from common sysctl config files.
SYSCTL_FILES=(
    "/etc/sysctl.conf"
    /etc/sysctl.d/*.conf
    /run/sysctl.d/*.conf
    /usr/lib/sysctl.d/*.conf
)

for param in "${PARAMS[@]}"; do
    escaped_param="${param//./\\.}"
    for file in "${SYSCTL_FILES[@]}"; do
        # Skip our own managed drop-in file and non-existent globs.
        [ -f "${file}" ] || continue
        [ "${file}" = "${SYSCTL_DROPIN}" ] && continue
        if grep -Eq "^[[:space:]]*${escaped_param}[[:space:]]*=" "${file}"; then
            sed -ri "/^[[:space:]]*${escaped_param}[[:space:]]*=/d" "${file}"
        fi
    done
done

# Write the managed drop-in file with the desired values (idempotently).
TMP_FILE="$(mktemp)"
{
    echo "# Managed by remediation script: disable IPv6 source-routed packets"
    for param in "${PARAMS[@]}"; do
        echo "${param} = ${DESIRED_VALUE}"
    done
} > "${TMP_FILE}"

if [ ! -f "${SYSCTL_DROPIN}" ] || ! cmp -s "${TMP_FILE}" "${SYSCTL_DROPIN}"; then
    install -m 0644 "${TMP_FILE}" "${SYSCTL_DROPIN}"
fi
rm -f "${TMP_FILE}"

# --- Apply the settings immediately -------------------------------------------
for param in "${PARAMS[@]}"; do
    # Only apply if the corresponding sysctl key exists (IPv6 enabled).
    key_path="/proc/sys/${param//.//}"
    if [ -f "${key_path}" ]; then
        current="$(sysctl -n "${param}" 2>/dev/null || echo "")"
        if [ "${current}" != "${DESIRED_VALUE}" ]; then
            sysctl -w "${param}=${DESIRED_VALUE}" >/dev/null
        fi
    fi
done

# Flush IPv6 route cache so the new setting takes effect on existing routes.
if [ -f /proc/sys/net/ipv6/route/flush ]; then
    sysctl -w net.ipv6.route.flush=1 >/dev/null 2>&1 || true
fi

echo "IPv6 source-routed packet acceptance has been disabled and persisted."
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

**Prompt:** On a RHEL 8 system, disable the IPv6 forwarding feature to prevent the system from routing IPv6 packets between network interfaces, as this is only appropriate for systems configured as routers. Write an idempotent bash remediation script that ensures IPv6 forwarding is disabled at runtime and the setting persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

SYSCTL_PARAM="net.ipv6.conf.all.forwarding"
SYSCTL_VALUE="0"
SYSCTL_CONF_DIR="/etc/sysctl.d"
SYSCTL_CONF_FILE="${SYSCTL_CONF_DIR}/60-disable-ipv6-forwarding.conf"

# Ensure the sysctl.d directory exists
mkdir -p "${SYSCTL_CONF_DIR}"

# Remove any conflicting entries for this parameter in common config files
for f in /etc/sysctl.conf ${SYSCTL_CONF_DIR}/*.conf; do
    [ -f "$f" ] || continue
    # Skip our own managed file
    if [ "$f" = "${SYSCTL_CONF_FILE}" ]; then
        continue
    fi
    if grep -Eq "^\s*${SYSCTL_PARAM}\s*=" "$f" 2>/dev/null; then
        sed -i -E "/^\s*${SYSCTL_PARAM}\s*=.*/d" "$f"
    fi
done

# Write the persistent configuration idempotently
DESIRED_LINE="${SYSCTL_PARAM} = ${SYSCTL_VALUE}"
if [ ! -f "${SYSCTL_CONF_FILE}" ] || ! grep -Eqx "\s*${SYSCTL_PARAM}\s*=\s*${SYSCTL_VALUE}\s*" "${SYSCTL_CONF_FILE}"; then
    printf '%s\n' "${DESIRED_LINE}" > "${SYSCTL_CONF_FILE}"
fi

# Apply the setting at runtime
sysctl -w "${SYSCTL_PARAM}=${SYSCTL_VALUE}" >/dev/null

# Also handle the default forwarding parameter to be thorough
DEFAULT_PARAM="net.ipv6.conf.default.forwarding"
if sysctl -a 2>/dev/null | grep -q "^${DEFAULT_PARAM}"; then
    sysctl -w "${DEFAULT_PARAM}=${SYSCTL_VALUE}" >/dev/null || true
fi

# Reload sysctl settings to ensure persistence takes effect
sysctl --system >/dev/null 2>&1 || true

# Verify runtime value
CURRENT_VALUE="$(sysctl -n "${SYSCTL_PARAM}" 2>/dev/null || echo "unknown")"
if [ "${CURRENT_VALUE}" = "${SYSCTL_VALUE}" ]; then
    echo "IPv6 forwarding is disabled (${SYSCTL_PARAM} = ${CURRENT_VALUE})."
    exit 0
else
    echo "Failed to set ${SYSCTL_PARAM} to ${SYSCTL_VALUE}; current value is ${CURRENT_VALUE}." >&2
    exit 1
fi
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

**Prompt:** On a RHEL 8 system, configure the OS to not accept IPv6 router advertisements by default on any interface. This measure helps mitigate man-in-the-middle attacks that can occur through malicious router advertisements. Write an idempotent bash remediation script that disables IPv6 router advertisement acceptance on all interfaces by default and ensures this setting is persistent across system reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PARAM="net.ipv6.conf.all.accept_ra"
VALUE="0"
CONF_FILE="/etc/sysctl.d/60-disable_ra.conf"

# Ensure the sysctl.d directory exists
mkdir -p /etc/sysctl.d

# Remove any existing conflicting settings for this parameter from common sysctl files
for f in /etc/sysctl.conf /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
    [ -f "$f" ] || continue
    [ "$f" = "$CONF_FILE" ] && continue
    if grep -Eq "^\s*${PARAM}\s*=" "$f" 2>/dev/null; then
        sed -i -E "/^\s*${PARAM}\s*=.*/d" "$f"
    fi
done

# Write the persistent setting idempotently
if [ -f "$CONF_FILE" ] && grep -Eq "^\s*${PARAM}\s*=\s*${VALUE}\s*$" "$CONF_FILE"; then
    :
else
    if [ -f "$CONF_FILE" ] && grep -Eq "^\s*${PARAM}\s*=" "$CONF_FILE"; then
        sed -i -E "s|^\s*${PARAM}\s*=.*|${PARAM} = ${VALUE}|" "$CONF_FILE"
    else
        echo "${PARAM} = ${VALUE}" >> "$CONF_FILE"
    fi
fi

# Apply the setting to the running system
sysctl -w "${PARAM}=${VALUE}"

# Flush the IPv6 route cache so the change takes effect immediately
sysctl -w net.ipv6.route.flush=1 2>/dev/null || true
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

**Prompt:** On a RHEL 8 system, prevent the system from accepting ICMPv6 redirect messages on all default IPv6 interfaces by configuring the relevant kernel parameter to reject such redirects. This change should mitigate the risk of man-in-the-middle attacks that exploit ICMP redirect messages. Write an idempotent bash remediation script that applies this setting both at runtime and ensures it persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PARAM="net.ipv6.conf.default.accept_redirects"
VALUE="0"
SYSCTL_DIR="/etc/sysctl.d"
CONF_FILE="${SYSCTL_DIR}/60-ipv6-default-accept-redirects.conf"

# Ensure the sysctl drop-in directory exists
mkdir -p "${SYSCTL_DIR}"

# Remove any conflicting definitions of this parameter from other sysctl files
for f in /etc/sysctl.conf ${SYSCTL_DIR}/*.conf /run/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
    [ -f "$f" ] || continue
    if [ "$f" = "${CONF_FILE}" ]; then
        continue
    fi
    if grep -Eq "^\s*${PARAM}\b" "$f"; then
        sed -i -E "\|^\s*${PARAM}\b|d" "$f"
    fi
done

# Write the persistent configuration idempotently
if [ ! -f "${CONF_FILE}" ] || ! grep -Eq "^\s*${PARAM}\s*=\s*${VALUE}\s*$" "${CONF_FILE}"; then
    printf '%s = %s\n' "${PARAM}" "${VALUE}" > "${CONF_FILE}"
fi

# Apply the setting at runtime
sysctl -w "${PARAM}=${VALUE}"

# Reload sysctl settings to ensure consistency
sysctl --system >/dev/null

# Verify
CURRENT="$(sysctl -n "${PARAM}")"
if [ "${CURRENT}" != "${VALUE}" ]; then
    echo "ERROR: Failed to set ${PARAM} to ${VALUE} (current: ${CURRENT})" >&2
    exit 1
fi

echo "Successfully set ${PARAM} = ${VALUE} (runtime and persistent)."
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

**Prompt:** On a RHEL 8 system, configure the network stack so that it does not accept source-routed packets on IPv6 interfaces by default. This setting helps prevent malicious entities from bypassing routing security measures. Write an idempotent bash remediation script that ensures the system is configured to reject source-routed packets for IPv6 at runtime and that this configuration persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

SYSCTL_PARAM="net.ipv6.conf.default.accept_source_route"
SYSCTL_VALUE="0"
SYSCTL_CONF="/etc/sysctl.d/60-disable-ipv6-source-route.conf"

# Ensure the persistent configuration file has the correct setting.
# Remove any conflicting definitions from other sysctl config files.
for f in /etc/sysctl.conf /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
    if [ -f "$f" ] && [ "$f" != "$SYSCTL_CONF" ]; then
        if grep -Eq "^\s*${SYSCTL_PARAM}\s*=" "$f"; then
            sed -i -E "/^\s*${SYSCTL_PARAM}\s*=.*/d" "$f"
        fi
    fi
done

# Create or update the dedicated configuration file idempotently.
if [ -f "$SYSCTL_CONF" ] && grep -Eq "^\s*${SYSCTL_PARAM}\s*=" "$SYSCTL_CONF"; then
    sed -i -E "s|^\s*${SYSCTL_PARAM}\s*=.*|${SYSCTL_PARAM} = ${SYSCTL_VALUE}|" "$SYSCTL_CONF"
else
    echo "${SYSCTL_PARAM} = ${SYSCTL_VALUE}" >> "$SYSCTL_CONF"
fi

# Apply the setting at runtime.
sysctl -w "${SYSCTL_PARAM}=${SYSCTL_VALUE}"

# Reload sysctl settings to ensure persistence configuration is active.
sysctl --system >/dev/null 2>&1 || true
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

**Prompt:** On a RHEL 8 system, IPv4 interfaces currently accept ICMP redirect messages, which can be exploited to alter routing tables and potentially enable man-in-the-middle attacks. Write an idempotent bash remediation script to disable acceptance of ICMP redirects on all IPv4 interfaces. Ensure this configuration is applied both at runtime and persistently across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PARAMS=("net.ipv4.conf.all.accept_redirects" "net.ipv4.conf.default.accept_redirects")
PERSIST_FILE="/etc/sysctl.d/99-disable-icmp-redirects.conf"

# Ensure the persistent config directory exists
mkdir -p /etc/sysctl.d

# Remove any conflicting existing settings in common sysctl config locations
for cfg in /etc/sysctl.conf /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
    [ -f "$cfg" ] || continue
    # Skip our own managed file
    [ "$cfg" = "$PERSIST_FILE" ] && continue
    for param in "${PARAMS[@]}"; do
        if grep -Eq "^\s*${param}\s*=" "$cfg"; then
            sed -i -E "/^\s*${param}\s*=.*/d" "$cfg"
        fi
    done
done

# Write the persistent configuration idempotently
{
    echo "# Managed by remediation script: disable ICMP redirect acceptance"
    for param in "${PARAMS[@]}"; do
        echo "${param} = 0"
    done
} > "${PERSIST_FILE}.tmp"

if [ ! -f "$PERSIST_FILE" ] || ! cmp -s "${PERSIST_FILE}.tmp" "$PERSIST_FILE"; then
    mv "${PERSIST_FILE}.tmp" "$PERSIST_FILE"
    chmod 0644 "$PERSIST_FILE"
else
    rm -f "${PERSIST_FILE}.tmp"
fi

# Apply the persistent settings from our file
sysctl -p "$PERSIST_FILE" >/dev/null

# Apply at runtime for all currently configured settings and existing interfaces
for param in "${PARAMS[@]}"; do
    sysctl -w "${param}=0" >/dev/null
done

# Ensure all existing per-interface entries are also set at runtime
for iface_path in /proc/sys/net/ipv4/conf/*/accept_redirects; do
    [ -f "$iface_path" ] || continue
    if [ "$(cat "$iface_path")" != "0" ]; then
        echo 0 > "$iface_path"
    fi
done

# Refresh route cache
sysctl -w net.ipv4.route.flush=1 >/dev/null 2>&1 || true

echo "ICMP redirect acceptance disabled at runtime and persistently."
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

**Prompt:** On a RHEL 8 system, ensure IPv4 packet forwarding is disabled across all network interfaces to prevent the system from inadvertently acting as a router. This configuration should be applied at runtime and persist across system reboots. Write an idempotent bash remediation script to achieve this.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

SYSCTL_KEY="net.ipv4.ip_forward"
SYSCTL_VALUE="0"
PERSIST_FILE="/etc/sysctl.d/99-disable-ipv4-forwarding.conf"

# Ensure persistent configuration file has the correct setting
if [[ -f "${PERSIST_FILE}" ]] && grep -Eq "^\s*${SYSCTL_KEY}\s*=" "${PERSIST_FILE}"; then
    sed -ri "s|^\s*${SYSCTL_KEY}\s*=.*|${SYSCTL_KEY} = ${SYSCTL_VALUE}|" "${PERSIST_FILE}"
else
    printf '%s = %s\n' "${SYSCTL_KEY}" "${SYSCTL_VALUE}" >> "${PERSIST_FILE}"
fi

# Remove any conflicting settings in other common sysctl locations
for f in /etc/sysctl.conf /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
    [[ -f "${f}" ]] || continue
    [[ "${f}" == "${PERSIST_FILE}" ]] && continue
    if grep -Eq "^\s*${SYSCTL_KEY}\s*=" "${f}" 2>/dev/null; then
        if grep -Eq "^\s*${SYSCTL_KEY}\s*=\s*${SYSCTL_VALUE}\s*$" "${f}"; then
            continue
        fi
        sed -ri "s|^(\s*${SYSCTL_KEY}\s*=.*)|# \1 (disabled by remediation)|" "${f}"
    fi
done

# Apply the persistent setting at runtime
sysctl -w "${SYSCTL_KEY}=${SYSCTL_VALUE}" >/dev/null

# Reload all sysctl settings to ensure precedence is correct
sysctl --system >/dev/null

# Flush route cache to apply immediately
sysctl -w net.ipv4.route.flush=1 >/dev/null 2>&1 || true

# Verify
CURRENT_VALUE="$(sysctl -n ${SYSCTL_KEY})"
if [[ "${CURRENT_VALUE}" == "${SYSCTL_VALUE}" ]]; then
    echo "IPv4 packet forwarding is disabled (${SYSCTL_KEY} = ${CURRENT_VALUE})."
    exit 0
else
    echo "Failed to disable IPv4 packet forwarding (${SYSCTL_KEY} = ${CURRENT_VALUE})." >&2
    exit 1
fi
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

**Prompt:** On a RHEL 8 system, to prevent unauthorized network redirects which might lead to man-in-the-middle attacks, ensure that the kernel does not accept ICMP redirect messages by default on IPv4 interfaces. Write an idempotent bash remediation script to disable accepting these redirects at runtime and ensure the setting persists after reboot.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PARAM="net.ipv4.conf.default.accept_redirects"
VALUE="0"
CONF_FILE="/etc/sysctl.d/99-icmp-redirect-hardening.conf"

# Ensure the sysctl.d directory exists
mkdir -p /etc/sysctl.d

# Remove any existing definitions of this parameter from common config locations
for f in /etc/sysctl.conf /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
    [ -f "$f" ] || continue
    if [ "$f" = "$CONF_FILE" ]; then
        continue
    fi
    if grep -Eq "^\s*${PARAM//./\\.}\s*=" "$f"; then
        sed -i -E "/^\s*${PARAM//./\\.}\s*=/d" "$f"
    fi
done

# Write the persistent setting idempotently
if [ -f "$CONF_FILE" ] && grep -Eq "^\s*${PARAM//./\\.}\s*=\s*${VALUE}\s*$" "$CONF_FILE"; then
    :
else
    if [ -f "$CONF_FILE" ] && grep -Eq "^\s*${PARAM//./\\.}\s*=" "$CONF_FILE"; then
        sed -i -E "s|^\s*${PARAM//./\\.}\s*=.*|${PARAM} = ${VALUE}|" "$CONF_FILE"
    else
        echo "${PARAM} = ${VALUE}" >> "$CONF_FILE"
    fi
fi

# Apply the setting at runtime
sysctl -w "${PARAM}=${VALUE}" >/dev/null

# Reload all sysctl settings to ensure consistency
sysctl --system >/dev/null

# Verify the runtime value
CURRENT="$(sysctl -n "${PARAM}")"
if [ "$CURRENT" = "$VALUE" ]; then
    echo "Successfully set ${PARAM} = ${VALUE} (runtime and persistent)."
else
    echo "Failed to set ${PARAM} to ${VALUE}. Current value: ${CURRENT}" >&2
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

**Prompt:** On a RHEL 8 system, source-routed packets on IPv4 interfaces can currently be accepted by default, which may allow network security measures to be circumvented. Write an idempotent bash remediation script to configure the system to reject source-routed packets on all IPv4 interfaces by default, ensuring the change is applied at runtime and persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PARAM="net.ipv4.conf.all.accept_source_route"
VALUE="0"
SYSCTL_DIR="/etc/sysctl.d"
CONF_FILE="${SYSCTL_DIR}/60-source-route-remediation.conf"

mkdir -p "${SYSCTL_DIR}"

# Remove any existing definitions of this parameter from common sysctl files
for f in /etc/sysctl.conf /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do
    [ -f "$f" ] || continue
    if [ "$f" = "${CONF_FILE}" ]; then
        continue
    fi
    if grep -Eq "^[[:space:]]*${PARAM//./\\.}[[:space:]]*=" "$f"; then
        sed -i -E "/^[[:space:]]*${PARAM//./\\.}[[:space:]]*=/d" "$f"
    fi
done

# Write the desired setting to our dedicated persistence file (idempotently)
if [ ! -f "${CONF_FILE}" ] || ! grep -Eq "^[[:space:]]*${PARAM//./\\.}[[:space:]]*=[[:space:]]*${VALUE}[[:space:]]*$" "${CONF_FILE}"; then
    printf '%s = %s\n' "${PARAM}" "${VALUE}" > "${CONF_FILE}"
fi

# Apply at runtime
sysctl -w "${PARAM}=${VALUE}" >/dev/null

# Reload all sysctl settings to ensure consistency
sysctl --system >/dev/null 2>&1 || true

# Verify
CURRENT="$(sysctl -n "${PARAM}")"
if [ "${CURRENT}" != "${VALUE}" ]; then
    echo "ERROR: Failed to set ${PARAM} to ${VALUE} (current: ${CURRENT})" >&2
    exit 1
fi

echo "Successfully configured ${PARAM} = ${VALUE} (runtime and persistent)."
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

**Prompt:** On a RHEL 8 system, to reduce vulnerability to certain network-based attacks and unauthorized network mapping, configure the system to ignore ICMP broadcast echo requests on all IPv4 interfaces. Write an idempotent bash remediation script that sets the system to ignore such requests at runtime and ensures the configuration persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PARAM="net.ipv4.icmp_echo_ignore_broadcasts"
VALUE="1"
CONF_FILE="/etc/sysctl.d/99-icmp-broadcast.conf"

# Ensure the persistent configuration directory exists
mkdir -p /etc/sysctl.d

# Remove any conflicting settings for this parameter from common sysctl files
for f in /etc/sysctl.conf /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
    [ -f "$f" ] || continue
    if [ "$f" = "$CONF_FILE" ]; then
        continue
    fi
    if grep -Eq "^[[:space:]]*${PARAM}[[:space:]]*=" "$f"; then
        sed -i -E "/^[[:space:]]*${PARAM}[[:space:]]*=.*/d" "$f"
    fi
done

# Write the desired setting idempotently to our managed file
if [ -f "$CONF_FILE" ] && grep -Eq "^[[:space:]]*${PARAM}[[:space:]]*=[[:space:]]*${VALUE}[[:space:]]*$" "$CONF_FILE"; then
    :
else
    if [ -f "$CONF_FILE" ] && grep -Eq "^[[:space:]]*${PARAM}[[:space:]]*=" "$CONF_FILE"; then
        sed -i -E "s|^[[:space:]]*${PARAM}[[:space:]]*=.*|${PARAM} = ${VALUE}|" "$CONF_FILE"
    else
        echo "${PARAM} = ${VALUE}" >> "$CONF_FILE"
    fi
fi

# Apply the setting at runtime
sysctl -w "${PARAM}=${VALUE}" >/dev/null

# Reload from persistent config to ensure consistency
sysctl --system >/dev/null

# Verify
CURRENT="$(sysctl -n "$PARAM")"
if [ "$CURRENT" = "$VALUE" ]; then
    echo "Success: ${PARAM} is set to ${VALUE}."
else
    echo "Error: ${PARAM} is ${CURRENT}, expected ${VALUE}." >&2
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

**Prompt:** On a RHEL 8 system, disable the ability to send ICMP redirect messages on all IPv4 network interfaces, as this reduces information leakage about network topology and is unnecessary on systems not acting as routers. Write an idempotent bash remediation script to ensure that this behavior is disabled both at runtime and across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

# Kernel parameters to disable sending ICMP redirects on all IPv4 interfaces
PARAM_ALL="net.ipv4.conf.all.send_redirects"
PARAM_DEFAULT="net.ipv4.conf.default.send_redirects"
VALUE="0"

SYSCTL_DIR="/etc/sysctl.d"
SYSCTL_FILE="${SYSCTL_DIR}/99-disable-send-redirects.conf"

mkdir -p "${SYSCTL_DIR}"

# Remove any conflicting settings for these parameters in other sysctl config files
for f in /etc/sysctl.conf /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
    [ -f "$f" ] || continue
    [ "$f" = "${SYSCTL_FILE}" ] && continue
    if grep -Eq "^\s*${PARAM_ALL//./\\.}\s*=" "$f" 2>/dev/null; then
        sed -i -E "\|^\s*${PARAM_ALL//./\\.}\s*=|d" "$f"
    fi
    if grep -Eq "^\s*${PARAM_DEFAULT//./\\.}\s*=" "$f" 2>/dev/null; then
        sed -i -E "\|^\s*${PARAM_DEFAULT//./\\.}\s*=|d" "$f"
    fi
done

# Write the desired configuration idempotently
cat > "${SYSCTL_FILE}" <<EOF
${PARAM_ALL} = ${VALUE}
${PARAM_DEFAULT} = ${VALUE}
EOF

chmod 0644 "${SYSCTL_FILE}"

# Apply the settings at runtime
sysctl -q -w "${PARAM_ALL}=${VALUE}"
sysctl -q -w "${PARAM_DEFAULT}=${VALUE}"

# Also apply to any existing per-interface settings
for iface_dir in /proc/sys/net/ipv4/conf/*/send_redirects; do
    [ -w "$iface_dir" ] || continue
    echo "${VALUE}" > "$iface_dir"
done

# Reload sysctl configuration to ensure consistency
sysctl -q --system || true

# Verification
runtime_all="$(sysctl -n ${PARAM_ALL})"
runtime_default="$(sysctl -n ${PARAM_DEFAULT})"

if [ "${runtime_all}" = "${VALUE}" ] && [ "${runtime_default}" = "${VALUE}" ]; then
    echo "ICMP redirect sending disabled successfully (runtime and persistent)."
else
    echo "ERROR: failed to disable ICMP redirect sending." >&2
    exit 1
fi
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

**Prompt:** On a RHEL 8 system, ensure that the system does not send ICMP redirect messages on all IPv4 interfaces by default, as doing so could expose internal network topology information that should remain private. Write an idempotent bash remediation script that configures the system to disable sending ICMP redirects both at runtime and across reboots, for the default configuration of all IPv4 interfaces.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

PARAM="net.ipv4.conf.default.send_redirects"
VALUE="0"
SYSCTL_CONF="/etc/sysctl.conf"
SYSCTL_DIR="/etc/sysctl.d"

# Remove any conflicting settings from sysctl.conf and drop-in files
if [ -f "$SYSCTL_CONF" ]; then
    sed -i -E "/^\s*${PARAM//./\\.}\s*=/d" "$SYSCTL_CONF"
fi

if [ -d "$SYSCTL_DIR" ]; then
    for f in "$SYSCTL_DIR"/*.conf; do
        [ -e "$f" ] || continue
        sed -i -E "/^\s*${PARAM//./\\.}\s*=/d" "$f"
    done
fi

# Set the persistent value in a dedicated drop-in file
DROPIN="${SYSCTL_DIR}/60-disable-send-redirects.conf"
mkdir -p "$SYSCTL_DIR"

if grep -qsE "^\s*${PARAM//./\\.}\s*=\s*${VALUE}\s*$" "$DROPIN"; then
    :
else
    sed -i -E "/^\s*${PARAM//./\\.}\s*=/d" "$DROPIN" 2>/dev/null || true
    echo "${PARAM} = ${VALUE}" >> "$DROPIN"
fi

# Apply the setting at runtime
sysctl -w "${PARAM}=${VALUE}" >/dev/null

# Reload sysctl settings to ensure consistency
sysctl -p "$DROPIN" >/dev/null 2>&1 || true
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

**Prompt:** On a RHEL 8 system, prevent the asynchronous transfer mode (ATM) kernel module from loading, to minimize exposure to possible security flaws in its implementation. Write an idempotent bash remediation script that ensures the ATM kernel module cannot be loaded, through any means, even indirectly, and that this configuration persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

MODULE="atm"
CONF_DIR="/etc/modprobe.d"
CONF_FILE="${CONF_DIR}/${MODULE}.conf"

# Ensure the modprobe configuration directory exists
mkdir -p "${CONF_DIR}"

# Desired configuration content
BLACKLIST_LINE="blacklist ${MODULE}"
INSTALL_LINE="install ${MODULE} /bin/false"

# Idempotently ensure the blacklist directive is present
if [ ! -f "${CONF_FILE}" ] || ! grep -qxF "${BLACKLIST_LINE}" "${CONF_FILE}"; then
    if ! grep -qxF "${BLACKLIST_LINE}" "${CONF_FILE}" 2>/dev/null; then
        echo "${BLACKLIST_LINE}" >> "${CONF_FILE}"
    fi
fi

# Idempotently ensure the install directive is present to prevent indirect loading
if ! grep -qxF "${INSTALL_LINE}" "${CONF_FILE}" 2>/dev/null; then
    echo "${INSTALL_LINE}" >> "${CONF_FILE}"
fi

# Set safe permissions on the configuration file
chmod 0644 "${CONF_FILE}"
chown root:root "${CONF_FILE}"

# Unload the module if it is currently loaded (best effort)
if lsmod | awk '{print $1}' | grep -qx "${MODULE}"; then
    rmmod "${MODULE}" 2>/dev/null || modprobe -r "${MODULE}" 2>/dev/null || true
fi

exit 0
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

**Prompt:** On a RHEL 8 system, eliminate the risk of exploiting vulnerabilities in the Controller Area Network (CAN) protocol by ensuring that the CAN kernel module is neither loaded nor available for use. Write an idempotent bash remediation script that prevents the CAN protocol module from ever loading on the system, including during boot, and ensures the change persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Disable the CAN kernel module on RHEL 8
# Ensures the "can" module is blacklisted and cannot be loaded.
#

set -o errexit
set -o nounset
set -o pipefail

MODULE_NAME="can"
CONF_DIR="/etc/modprobe.d"
CONF_FILE="${CONF_DIR}/${MODULE_NAME}.conf"

# Ensure the modprobe.d directory exists
if [ ! -d "${CONF_DIR}" ]; then
    mkdir -p "${CONF_DIR}"
fi

# Desired configuration lines
INSTALL_LINE="install ${MODULE_NAME} /bin/false"
BLACKLIST_LINE="blacklist ${MODULE_NAME}"

# Create or update the configuration file idempotently
NEED_WRITE=0

if [ ! -f "${CONF_FILE}" ]; then
    NEED_WRITE=1
else
    if ! grep -qxF "${INSTALL_LINE}" "${CONF_FILE}"; then
        NEED_WRITE=1
    fi
    if ! grep -qxF "${BLACKLIST_LINE}" "${CONF_FILE}"; then
        NEED_WRITE=1
    fi
fi

if [ "${NEED_WRITE}" -eq 1 ]; then
    {
        echo "${INSTALL_LINE}"
        echo "${BLACKLIST_LINE}"
    } > "${CONF_FILE}"
    chmod 0644 "${CONF_FILE}"
fi

# Unload the module if it is currently loaded
if lsmod | awk '{print $1}' | grep -qx "${MODULE_NAME}"; then
    modprobe -r "${MODULE_NAME}" 2>/dev/null || rmmod "${MODULE_NAME}" 2>/dev/null || true
fi

echo "CAN kernel module has been disabled and blacklisted."
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

**Prompt:** On a RHEL 8 system, the IEEE 1394 (FireWire) standard, which is not commonly used and could be exploited if present, should be disabled. Write an idempotent bash remediation script that prevents the firewire-core kernel module from loading, ensuring this configuration persists across reboots, thereby protecting the system against potential vulnerabilities.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

MODULE="firewire-core"
CONF_FILE="/etc/modprobe.d/${MODULE}.conf"

# Ensure modprobe.d directory exists
mkdir -p /etc/modprobe.d

# Desired configuration lines
INSTALL_LINE="install ${MODULE} /bin/true"
BLACKLIST_LINE="blacklist ${MODULE}"

# Create or update the configuration file idempotently
touch "${CONF_FILE}"

if ! grep -Eqx "install[[:space:]]+${MODULE}[[:space:]]+/bin/(true|false)" "${CONF_FILE}"; then
    echo "${INSTALL_LINE}" >> "${CONF_FILE}"
fi

if ! grep -Eqx "blacklist[[:space:]]+${MODULE}" "${CONF_FILE}"; then
    echo "${BLACKLIST_LINE}" >> "${CONF_FILE}"
fi

# Set safe permissions on the configuration file
chmod 0644 "${CONF_FILE}"
chown root:root "${CONF_FILE}"

# Unload the module if it is currently loaded
if lsmod | grep -q "^${MODULE//-/_}\b"; then
    rmmod "${MODULE}" 2>/dev/null || modprobe -r "${MODULE}" 2>/dev/null || true
fi

echo "FireWire (${MODULE}) module has been disabled and blacklisted."
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

**Prompt:** On a RHEL 8 system, the Stream Control Transmission Protocol (SCTP) is currently enabled, which could expose the system to vulnerabilities inherent to SCTP's implementation. Write an idempotent bash remediation script that prevents the SCTP kernel module from being loaded, effectively disabling SCTP support on the system, and ensure this configuration persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

CONF_FILE="/etc/modprobe.d/sctp.conf"
BLACKLIST_LINE="blacklist sctp"
INSTALL_LINE="install sctp /bin/true"

# Ensure the modprobe.d directory exists
mkdir -p /etc/modprobe.d

# Ensure the install directive is present (prevents module loading)
if ! grep -Eq "^\s*install\s+sctp\s+/bin/true\s*$" "$CONF_FILE" 2>/dev/null; then
    echo "$INSTALL_LINE" >> "$CONF_FILE"
fi

# Ensure the blacklist directive is present
if ! grep -Eq "^\s*blacklist\s+sctp\s*$" "$CONF_FILE" 2>/dev/null; then
    echo "$BLACKLIST_LINE" >> "$CONF_FILE"
fi

# Set safe permissions on the configuration file
chmod 0644 "$CONF_FILE"
chown root:root "$CONF_FILE"

# Unload the SCTP module if currently loaded and not in use
if lsmod | grep -Eq "^sctp\b"; then
    if modprobe -r sctp 2>/dev/null; then
        :
    else
        echo "Warning: sctp module is currently in use and could not be unloaded. It will remain disabled after reboot." >&2
    fi
fi

echo "SCTP module has been disabled and configuration persisted."
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

**Prompt:** On a RHEL 8 system, disable the Transparent Inter-Process Communication (TIPC) protocol to mitigate risks associated with potential vulnerabilities in its implementation. Write an idempotent bash remediation script that prevents the TIPC kernel module from being loaded on the system, ensuring that the change is idempotent and persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

MODULE="tipc"
CONF_FILE="/etc/modprobe.d/${MODULE}.conf"

# Ensure the modprobe.d directory exists
mkdir -p /etc/modprobe.d

# Desired configuration lines
INSTALL_LINE="install ${MODULE} /bin/false"
BLACKLIST_LINE="blacklist ${MODULE}"

# Create or update the configuration file idempotently
NEED_UPDATE=0

if [ ! -f "${CONF_FILE}" ]; then
    NEED_UPDATE=1
else
    if ! grep -qxF "${INSTALL_LINE}" "${CONF_FILE}"; then
        NEED_UPDATE=1
    fi
    if ! grep -qxF "${BLACKLIST_LINE}" "${CONF_FILE}"; then
        NEED_UPDATE=1
    fi
fi

if [ "${NEED_UPDATE}" -eq 1 ]; then
    {
        echo "${INSTALL_LINE}"
        echo "${BLACKLIST_LINE}"
    } > "${CONF_FILE}"
    chmod 0644 "${CONF_FILE}"
    echo "Updated ${CONF_FILE} to disable ${MODULE} module."
else
    echo "${CONF_FILE} already configured to disable ${MODULE} module."
fi

# Unload the module if it is currently loaded
if lsmod | grep -q "^${MODULE}\b"; then
    if modprobe -r "${MODULE}" 2>/dev/null; then
        echo "Unloaded currently loaded ${MODULE} module."
    else
        echo "Warning: could not unload ${MODULE} module (it may be in use)." >&2
    fi
else
    echo "${MODULE} module is not currently loaded."
fi

echo "TIPC module remediation complete."
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

**Prompt:** On a RHEL 8 system where Bluetooth functionality must be disabled to reduce attack surface and prevent unauthorized wireless connections, ensure the kernel does not load the Bluetooth module. Write an idempotent bash remediation script that blocks the loading of the Bluetooth module at system startup, ensuring this configuration persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Disable Bluetooth kernel module on RHEL 8
# Blocks loading of the 'bluetooth' module and ensures persistence.
#

set -euo pipefail

MODULE="bluetooth"
CONF_FILE="/etc/modprobe.d/${MODULE}.conf"
FALSE_BIN="/bin/false"

# Ensure the configuration directory exists
if [ ! -d /etc/modprobe.d ]; then
    mkdir -p /etc/modprobe.d
    chmod 0755 /etc/modprobe.d
fi

# Desired configuration lines
INSTALL_LINE="install ${MODULE} ${FALSE_BIN}"
BLACKLIST_LINE="blacklist ${MODULE}"

# Create the conf file if it doesn't exist
if [ ! -f "${CONF_FILE}" ]; then
    touch "${CONF_FILE}"
    chmod 0644 "${CONF_FILE}"
fi

# Idempotently ensure the install directive is present
if ! grep -Eq "^\s*install\s+${MODULE}\s+${FALSE_BIN}\s*$" "${CONF_FILE}"; then
    # Remove any existing install lines for this module to avoid duplicates/conflicts
    sed -i -E "/^\s*install\s+${MODULE}\s+/d" "${CONF_FILE}"
    echo "${INSTALL_LINE}" >> "${CONF_FILE}"
fi

# Idempotently ensure the blacklist directive is present
if ! grep -Eq "^\s*blacklist\s+${MODULE}\s*$" "${CONF_FILE}"; then
    echo "${BLACKLIST_LINE}" >> "${CONF_FILE}"
fi

# Unload the module now if it is currently loaded (best-effort)
if lsmod | awk '{print $1}' | grep -qx "${MODULE}"; then
    modprobe -r "${MODULE}" 2>/dev/null || rmmod "${MODULE}" 2>/dev/null || true
fi

echo "Bluetooth module load blocking configured in ${CONF_FILE}"
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

**Prompt:** On a RHEL 8 system, reduce the local attack surface by preventing the usage of the cramfs filesystem, which is not commonly utilized in most server environments. Write an idempotent bash remediation script to ensure that the cramfs kernel module cannot be loaded, making sure this configuration persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation script: disable the cramfs kernel module on RHEL 8
# Idempotent: safe to run multiple times.

set -o nounset
set -o pipefail

MODULE_NAME="cramfs"
CONF_DIR="/etc/modprobe.d"
CONF_FILE="${CONF_DIR}/${MODULE_NAME}.conf"

# Desired lines to enforce in the modprobe configuration file
INSTALL_LINE="install ${MODULE_NAME} /bin/true"
BLACKLIST_LINE="blacklist ${MODULE_NAME}"

# Ensure the modprobe.d directory exists
if [[ ! -d "${CONF_DIR}" ]]; then
    mkdir -p "${CONF_DIR}"
    chmod 0755 "${CONF_DIR}"
fi

# Ensure the configuration file exists
if [[ ! -f "${CONF_FILE}" ]]; then
    touch "${CONF_FILE}"
    chmod 0644 "${CONF_FILE}"
fi

# Ensure the 'install' directive is present (redirect loading to /bin/true)
if ! grep -Eq "^\s*install\s+${MODULE_NAME}\s+/bin/true\s*$" "${CONF_FILE}"; then
    # Remove any conflicting/incomplete install lines for this module first
    if grep -Eq "^\s*install\s+${MODULE_NAME}\b" "${CONF_FILE}"; then
        sed -i -E "/^\s*install\s+${MODULE_NAME}\b.*$/d" "${CONF_FILE}"
    fi
    echo "${INSTALL_LINE}" >> "${CONF_FILE}"
fi

# Ensure the 'blacklist' directive is present
if ! grep -Eq "^\s*blacklist\s+${MODULE_NAME}\s*$" "${CONF_FILE}"; then
    echo "${BLACKLIST_LINE}" >> "${CONF_FILE}"
fi

# Unload the module if it is currently loaded (only if not in use)
if lsmod | grep -Eq "^${MODULE_NAME}\b"; then
    if modprobe -r "${MODULE_NAME}" 2>/dev/null; then
        echo "Unloaded currently loaded module: ${MODULE_NAME}"
    else
        echo "Warning: unable to unload ${MODULE_NAME} (possibly in use). It will remain disabled after reboot." >&2
    fi
fi

echo "cramfs module has been disabled via ${CONF_FILE}"
exit 0
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

**Prompt:** On a RHEL 8 system, prevent automatic and manual loading of the USB storage driver to mitigate the risk of malicious software introduction via USB storage devices. Write an idempotent bash remediation script that disables both automatic and manual loading of the USB storage kernel module, ensuring this restriction persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

MODULE="usb-storage"
CONF_DIR="/etc/modprobe.d"
CONF_FILE="${CONF_DIR}/${MODULE}.conf"

mkdir -p "${CONF_DIR}"

# Line to disable manual loading (redirect modprobe to /bin/false)
INSTALL_LINE="install ${MODULE} /bin/false"
# Line to disable/blacklist automatic loading
BLACKLIST_LINE="blacklist ${MODULE}"

touch "${CONF_FILE}"

# Ensure the install line is present exactly once
if ! grep -qxF "${INSTALL_LINE}" "${CONF_FILE}"; then
    # Remove any existing install lines for this module to avoid duplicates/conflicts
    sed -i "\|^\s*install\s\+${MODULE}\s|d" "${CONF_FILE}"
    echo "${INSTALL_LINE}" >> "${CONF_FILE}"
fi

# Ensure the blacklist line is present exactly once
if ! grep -qxF "${BLACKLIST_LINE}" "${CONF_FILE}"; then
    sed -i "\|^\s*blacklist\s\+${MODULE}\s*$|d" "${CONF_FILE}"
    echo "${BLACKLIST_LINE}" >> "${CONF_FILE}"
fi

# Set safe permissions on the config file
chmod 0644 "${CONF_FILE}"
chown root:root "${CONF_FILE}"

# Attempt to unload the module now if it is currently loaded and not in use
if lsmod | grep -q "^${MODULE//-/_}\b"; then
    if rmmod "${MODULE//-/_}" 2>/dev/null; then
        :
    else
        echo "Warning: ${MODULE} is currently in use and could not be unloaded; it will remain disabled after reboot." >&2
    fi
fi

echo "USB storage driver loading has been disabled via ${CONF_FILE}."
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

**Prompt:** On a RHEL 8 system, ensure that the /boot partition is mounted with the 'nosuid' option to prevent users from executing set-user-identifier (SUID) or set-group-identifier (SGID) binaries from this partition. Write an idempotent bash remediation script that configures the system to mount /boot with the 'nosuid' option, ensuring this configuration persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

FSTAB="/etc/fstab"
MOUNT_POINT="/boot"

# Check if /boot exists as a mount point in fstab
if ! grep -qE "^\s*[^#].*\s+${MOUNT_POINT}\s+" "$FSTAB"; then
    echo "No ${MOUNT_POINT} entry found in ${FSTAB}. Nothing to remediate."
    exit 0
fi

# Backup fstab once
if [[ ! -f "${FSTAB}.bak.nosuid" ]]; then
    cp -p "$FSTAB" "${FSTAB}.bak.nosuid"
fi

# Process the /boot line in fstab
tmpfile="$(mktemp)"

awk -v mp="$MOUNT_POINT" '
function ltrim(s){ sub(/^[ \t]+/, "", s); return s }
{
    line = $0
    trimmed = ltrim(line)
    # Skip comments and blank lines
    if (trimmed ~ /^#/ || trimmed == "") {
        print line
        next
    }

    # Split into fields
    n = split(line, f, /[ \t]+/)
    # fstab fields: device mountpoint fstype options dump pass
    # Find the mount point (2nd field). Note leading whitespace may create empty f[1].
    # Re-split ignoring leading whitespace.
    m = split(trimmed, g, /[ \t]+/)

    if (m >= 4 && g[2] == mp) {
        opts = g[4]
        # Check if nosuid already present
        hasnosuid = 0
        cnt = split(opts, o, ",")
        for (i = 1; i <= cnt; i++) {
            if (o[i] == "nosuid") { hasnosuid = 1 }
        }
        if (!hasnosuid) {
            opts = opts ",nosuid"
        }

        # Rebuild the line
        out = g[1] " " g[2] " " g[3] " " opts
        for (i = 5; i <= m; i++) {
            out = out " " g[i]
        }
        print out
    } else {
        print line
    }
}
' "$FSTAB" > "$tmpfile"

# Apply changes only if different (idempotency)
if ! cmp -s "$tmpfile" "$FSTAB"; then
    cat "$tmpfile" > "$FSTAB"
    echo "Updated ${FSTAB}: added 'nosuid' to ${MOUNT_POINT}."
else
    echo "${MOUNT_POINT} already has 'nosuid' in ${FSTAB}. No changes needed."
fi

rm -f "$tmpfile"

# Remount /boot to apply immediately if currently mounted
if mountpoint -q "$MOUNT_POINT"; then
    if ! findmnt -no OPTIONS "$MOUNT_POINT" | tr ',' '\n' | grep -qx "nosuid"; then
        mount -o remount "$MOUNT_POINT"
        echo "Remounted ${MOUNT_POINT} with updated options."
    else
        echo "${MOUNT_POINT} is already mounted with 'nosuid'."
    fi
else
    echo "${MOUNT_POINT} is not currently mounted; configuration will apply on next mount/reboot."
fi

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

**Prompt:** On a RHEL 8 system, ensure the /dev/shm temporary filesystem is mounted with the nodev option to prevent device files from being created there. This enhances security by ensuring that only the root filesystem's /dev directory contains device files, reducing the risk of unauthorized devices being used in temporary directories. Write an idempotent bash remediation script to enforce the nodev setting for /dev/shm in both the current session and all future boot-ups.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

FSTAB="/etc/fstab"
MOUNT_POINT="/dev/shm"

# Ensure an fstab entry exists for /dev/shm with the nodev option.
if grep -qE '^\s*[^#].*\s+/dev/shm\s+' "$FSTAB"; then
    # Entry exists; ensure nodev is present in the options field (field 4).
    awk '
    {
        if ($0 ~ /^[[:space:]]*#/) { print; next }
        if (NF >= 4 && $2 == "/dev/shm") {
            n = split($4, opts, ",")
            has_nodev = 0
            for (i = 1; i <= n; i++) {
                if (opts[i] == "nodev") { has_nodev = 1 }
            }
            if (!has_nodev) {
                if ($4 == "defaults" || $4 == "") {
                    $4 = $4 ",nodev"
                } else {
                    $4 = $4 ",nodev"
                }
            }
            print
            next
        }
        print
    }
    ' OFS="\t" "$FSTAB" > "${FSTAB}.tmp"
    mv "${FSTAB}.tmp" "$FSTAB"
    chmod 644 "$FSTAB"
else
    # No entry exists; add one.
    printf 'tmpfs\t/dev/shm\ttmpfs\tdefaults,nodev\t0 0\n' >> "$FSTAB"
fi

# Apply the setting to the current session.
if mountpoint -q "$MOUNT_POINT"; then
    mount -o remount "$MOUNT_POINT"
else
    mount "$MOUNT_POINT"
fi

# Verify nodev is active in the current session.
if findmnt -kn -o OPTIONS "$MOUNT_POINT" | grep -qw nodev; then
    echo "nodev is enforced on $MOUNT_POINT (current session and fstab)."
else
    echo "ERROR: Failed to enforce nodev on $MOUNT_POINT" >&2
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

**Prompt:** On a RHEL 8 system, the /dev/shm directory, which is used for temporary storage, currently allows execution of binaries, creating a security risk as it can be exploited by users to run unauthorized executables. Write an idempotent bash remediation script to ensure that the /dev/shm directory is mounted with the "noexec" option, preventing execution of binaries from this directory. Ensure this configuration change is persistent across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

FSTAB="/etc/fstab"
MOUNT_POINT="/dev/shm"

# Backup fstab once
if [ ! -f "${FSTAB}.orig" ]; then
    cp -p "${FSTAB}" "${FSTAB}.orig"
fi

# Ensure /dev/shm has an entry in fstab with noexec (and other secure options)
if grep -qE "^\s*[^#].*\s+${MOUNT_POINT}\s+" "${FSTAB}"; then
    # Entry exists; process each matching line
    awk -v mp="${MOUNT_POINT}" '
    {
        if ($0 ~ "^[[:space:]]*[^#]" && $2 == mp) {
            # $4 is the options field
            n = split($4, opts, ",")
            has_noexec = 0
            for (i = 1; i <= n; i++) {
                if (opts[i] == "noexec") has_noexec = 1
            }
            if (has_noexec == 0) {
                $4 = $4 ",noexec"
            }
            print $1"\t"$2"\t"$3"\t"$4"\t"$5"\t"$6
        } else {
            print $0
        }
    }' "${FSTAB}" > "${FSTAB}.tmp"
    mv "${FSTAB}.tmp" "${FSTAB}"
    chmod 644 "${FSTAB}"
else
    # No entry; add a secure one
    printf 'tmpfs\t%s\ttmpfs\tdefaults,nodev,nosuid,noexec\t0 0\n' "${MOUNT_POINT}" >> "${FSTAB}"
fi

# Apply the mount options now (idempotent remount)
if mountpoint -q "${MOUNT_POINT}"; then
    current_opts="$(findmnt -no OPTIONS "${MOUNT_POINT}")"
    if ! printf '%s' "${current_opts}" | grep -qw "noexec"; then
        mount -o remount "${MOUNT_POINT}"
    fi
else
    mount "${MOUNT_POINT}"
fi

# Verify
if findmnt -no OPTIONS "${MOUNT_POINT}" | grep -qw "noexec"; then
    echo "SUCCESS: ${MOUNT_POINT} is mounted with noexec and persistent in ${FSTAB}."
else
    echo "ERROR: Failed to apply noexec on ${MOUNT_POINT}." >&2
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

**Prompt:** On a RHEL 8 system, ensure that the temporary filesystem mounted at /dev/shm does not allow setuid or setgid binaries to be executed, which mitigates the risk of privilege escalation through such executables. Write an idempotent bash remediation script that enforces the 'nosuid' option for the /dev/shm mount point and ensures this configuration persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

MOUNT_POINT="/dev/shm"
REQUIRED_OPTION="nosuid"
FSTAB="/etc/fstab"

# Ensure fstab has an entry for /dev/shm with nosuid option

if grep -qE "^\s*[^#].*\s+${MOUNT_POINT}\s+" "$FSTAB"; then
    # An entry exists; make sure nosuid is present in the options field (field 4)
    awk -v mp="$MOUNT_POINT" -v opt="$REQUIRED_OPTION" '
    BEGIN { OFS="\t" }
    {
        if ($0 ~ /^[[:space:]]*#/ || NF < 4) {
            print $0
            next
        }
        if ($2 == mp) {
            n = split($4, opts, ",")
            found = 0
            for (i = 1; i <= n; i++) {
                if (opts[i] == opt) { found = 1; break }
            }
            if (!found) {
                if ($4 == "defaults" || $4 == "" ) {
                    $4 = $4 "," opt
                } else {
                    $4 = $4 "," opt
                }
            }
        }
        print $0
    }' "$FSTAB" > "${FSTAB}.tmp"
    mv "${FSTAB}.tmp" "$FSTAB"
    chmod 0644 "$FSTAB"
else
    # No entry exists; add a proper tmpfs entry for /dev/shm
    printf "tmpfs\t%s\ttmpfs\tdefaults,%s\t0 0\n" "$MOUNT_POINT" "$REQUIRED_OPTION" >> "$FSTAB"
fi

# Apply the option to the currently mounted filesystem
if mount | grep -qE "\s${MOUNT_POINT}\s"; then
    current_opts=$(findmnt -no OPTIONS "$MOUNT_POINT" 2>/dev/null || echo "")
    if ! echo "$current_opts" | tr ',' '\n' | grep -qx "$REQUIRED_OPTION"; then
        mount -o remount,"$REQUIRED_OPTION" "$MOUNT_POINT"
    fi
else
    mount "$MOUNT_POINT" 2>/dev/null || mount -t tmpfs -o "defaults,$REQUIRED_OPTION" tmpfs "$MOUNT_POINT"
fi

# Verify
if findmnt -no OPTIONS "$MOUNT_POINT" | tr ',' '\n' | grep -qx "$REQUIRED_OPTION"; then
    echo "Success: ${REQUIRED_OPTION} is enforced on ${MOUNT_POINT}."
else
    echo "Error: failed to enforce ${REQUIRED_OPTION} on ${MOUNT_POINT}." >&2
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

**Prompt:** On a RHEL 8 system, ensure that non-root local partitions are mounted with the 'nodev' option to prevent files on these partitions from being interpreted as device files. This limits where device files can appear, typically restricting them to the /dev directory on the root filesystem, thereby reducing risks associated with unauthorized device file creation. Write an idempotent bash remediation script that updates the system configuration so that all eligible non-root partitions are mounted with the 'nodev' option, and ensure this configuration persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure non-root local partitions are mounted with 'nodev'.
# Idempotent: safe to run multiple times.
#

set -o pipefail

FSTAB="/etc/fstab"
BACKUP="${FSTAB}.bak.$(date +%Y%m%d%H%M%S)"

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

if [[ ! -f "$FSTAB" ]]; then
    echo "ERROR: $FSTAB not found." >&2
    exit 1
fi

# Pseudo/virtual filesystem types that should be skipped.
SKIP_FSTYPES=" proc sysfs tmpfs devtmpfs devpts securityfs cgroup cgroup2 pstore bpf tracefs debugfs mqueue hugetlbfs configfs fusectl autofs rpc_pipefs nsfs binfmt_misc none swap efivarfs "

changed=0
cp -p "$FSTAB" "$BACKUP"

tmpfile="$(mktemp)"

while IFS= read -r line || [[ -n "$line" ]]; do
    # Preserve comments and blank lines as-is.
    trimmed="${line#"${line%%[![:space:]]*}"}"
    if [[ -z "$trimmed" || "$trimmed" == \#* ]]; then
        printf '%s\n' "$line" >> "$tmpfile"
        continue
    fi

    # Parse fstab fields.
    read -r fs_spec fs_file fs_vfstype fs_mntopts fs_dump fs_pass rest <<< "$line"

    # If we cannot parse enough fields, leave the line untouched.
    if [[ -z "$fs_spec" || -z "$fs_file" || -z "$fs_vfstype" || -z "$fs_mntopts" ]]; then
        printf '%s\n' "$line" >> "$tmpfile"
        continue
    fi

    # Skip the root filesystem.
    if [[ "$fs_file" == "/" ]]; then
        printf '%s\n' "$line" >> "$tmpfile"
        continue
    fi

    # Skip swap and pseudo/virtual filesystems.
    if [[ "$SKIP_FSTYPES" == *" $fs_vfstype "* ]]; then
        printf '%s\n' "$line" >> "$tmpfile"
        continue
    fi

    # Only handle local real filesystems (skip network mounts).
    case "$fs_vfstype" in
        nfs|nfs4|cifs|smbfs|ceph|glusterfs|fuse.*|sshfs)
            printf '%s\n' "$line" >> "$tmpfile"
            continue
            ;;
    esac

    # Check if 'nodev' is already present as a distinct option.
    if [[ ",$fs_mntopts," == *",nodev,"* ]]; then
        printf '%s\n' "$line" >> "$tmpfile"
        continue
    fi

    # Add 'nodev' to the options.
    if [[ "$fs_mntopts" == "defaults" || -n "$fs_mntopts" ]]; then
        new_mntopts="${fs_mntopts},nodev"
    else
        new_mntopts="defaults,nodev"
    fi

    # Rebuild the line preserving trailing fields.
    if [[ -n "$rest" ]]; then
        new_line="$fs_spec $fs_file $fs_vfstype $new_mntopts $fs_dump $fs_pass $rest"
    else
        new_line="$fs_spec $fs_file $fs_vfstype $new_mntopts ${fs_dump:-0} ${fs_pass:-0}"
    fi

    printf '%s\n' "$new_line" >> "$tmpfile"
    echo "Updated $fs_file: added 'nodev' option."
    changed=1

done < "$FSTAB"

if [[ "$changed" -eq 1 ]]; then
    # Preserve ownership and permissions.
    cat "$tmpfile" > "$FSTAB"
    rm -f "$tmpfile"
    echo "fstab updated. Backup saved to $BACKUP."

    # Attempt to remount affected filesystems now so change takes effect.
    while IFS= read -r line || [[ -n "$line" ]]; do
        trimmed="${line#"${line%%[![:space:]]*}"}"
        [[ -z "$trimmed" || "$trimmed" == \#* ]] && continue
        read -r fs_spec fs_file fs_vfstype fs_mntopts _ <<< "$line"
        [[ "$fs_file" == "/" ]] && continue
        [[ ",$fs_mntopts," != *",nodev,"* ]] && continue
        if mountpoint -q "$fs_file" 2>/dev/null; then
            if mount -o remount "$fs_file" 2>/dev/null; then
                echo "Remounted $fs_file with updated options."
            else
                echo "WARNING: Could not remount $fs_file live; change will apply on next reboot." >&2
            fi
        fi
    done < "$FSTAB"
else
    rm -f "$tmpfile"
    # No changes needed; remove the redundant backup.
    rm -f "$BACKUP"
    echo "No changes required. All eligible non-root partitions already use 'nodev'."
fi

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

**Prompt:** On a RHEL 8 system containing a camera, ensure the uvcvideo kernel module is disabled to prevent unintended camera use which can lead to data leaks and privacy issues. Write an idempotent bash remediation script that disables this module, making sure this change persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

MODULE="uvcvideo"
CONF_FILE="/etc/modprobe.d/${MODULE}.conf"

# Ensure the modprobe.d directory exists
mkdir -p /etc/modprobe.d

# Desired configuration content
DESIRED_CONTENT="install ${MODULE} /bin/true
blacklist ${MODULE}"

# Write configuration idempotently
if [[ ! -f "${CONF_FILE}" ]] || [[ "$(cat "${CONF_FILE}")" != "${DESIRED_CONTENT}" ]]; then
    printf '%s\n' "${DESIRED_CONTENT}" > "${CONF_FILE}"
    chmod 0644 "${CONF_FILE}"
fi

# Unload the module if currently loaded
if lsmod | awk '{print $1}' | grep -qx "${MODULE}"; then
    modprobe -r "${MODULE}" || rmmod "${MODULE}" || true
fi

exit 0
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

**Prompt:** On a RHEL 8 system, prevent the generation and storage of core dumps, which can contain sensitive data and present a security risk if accessed by unauthorized users. Write an idempotent bash remediation script that immediately disables core dump creation and ensures this setting persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

# Must run as root
if [[ "$(id -u)" -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

#############################################
# 1. Disable core dumps via limits.conf
#############################################
LIMITS_DIR="/etc/security/limits.d"
LIMITS_FILE="${LIMITS_DIR}/99-disable-coredumps.conf"

mkdir -p "$LIMITS_DIR"

DESIRED_LIMITS=$'* hard core 0\n* soft core 0'

if [[ ! -f "$LIMITS_FILE" ]] || [[ "$(cat "$LIMITS_FILE")" != "$DESIRED_LIMITS" ]]; then
    printf '%s\n' "$DESIRED_LIMITS" > "$LIMITS_FILE"
    chmod 0644 "$LIMITS_FILE"
    echo "Updated ${LIMITS_FILE}"
else
    echo "${LIMITS_FILE} already configured."
fi

#############################################
# 2. Disable setuid core dumps via sysctl
#############################################
SYSCTL_FILE="/etc/sysctl.d/99-disable-coredumps.conf"
SYSCTL_SETTING="fs.suid_dumpable = 0"

if [[ ! -f "$SYSCTL_FILE" ]] || ! grep -qxF "$SYSCTL_SETTING" "$SYSCTL_FILE"; then
    # Rebuild file to contain only the desired setting
    printf '%s\n' "$SYSCTL_SETTING" > "$SYSCTL_FILE"
    chmod 0644 "$SYSCTL_FILE"
    echo "Updated ${SYSCTL_FILE}"
else
    echo "${SYSCTL_FILE} already configured."
fi

# Apply sysctl setting immediately
sysctl -w fs.suid_dumpable=0 >/dev/null
# Reload from config to ensure persistence values loaded
sysctl --system >/dev/null 2>&1 || true

#############################################
# 3. Disable systemd-coredump handling
#############################################
COREDUMP_CONF_DIR="/etc/systemd/coredump.conf.d"
COREDUMP_CONF="${COREDUMP_CONF_DIR}/disable.conf"

mkdir -p "$COREDUMP_CONF_DIR"

DESIRED_COREDUMP=$'[Coredump]\nStorage=none\nProcessSizeMax=0'

if [[ ! -f "$COREDUMP_CONF" ]] || [[ "$(cat "$COREDUMP_CONF")" != "$DESIRED_COREDUMP" ]]; then
    printf '%s\n' "$DESIRED_COREDUMP" > "$COREDUMP_CONF"
    chmod 0644 "$COREDUMP_CONF"
    echo "Updated ${COREDUMP_CONF}"
else
    echo "${COREDUMP_CONF} already configured."
fi

#############################################
# 4. Mask systemd-coredump socket/service
#############################################
if systemctl list-unit-files 2>/dev/null | grep -q '^systemd-coredump.socket'; then
    if [[ "$(systemctl is-enabled systemd-coredump.socket 2>/dev/null || true)" != "masked" ]]; then
        systemctl mask systemd-coredump.socket >/dev/null 2>&1 || true
        echo "Masked systemd-coredump.socket"
    else
        echo "systemd-coredump.socket already masked."
    fi
fi

# Reload systemd to pick up coredump.conf changes
systemctl daemon-reload >/dev/null 2>&1 || true

#############################################
# 5. Apply core limit to current shell/session
#############################################
ulimit -S -c 0 2>/dev/null || true
ulimit -H -c 0 2>/dev/null || true

echo "Core dump remediation complete."
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

**Prompt:** Unprivileged users on a RHEL 8 system currently have access to the kernel message buffer, which can leak sensitive information about kernel memory addresses. Write an idempotent bash remediation script that configures the system to restrict this access so that only privileged users can read the kernel message buffer. Ensure this restriction is enforced both at runtime and across system reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Restrict access to the kernel message buffer (dmesg)
# by setting kernel.dmesg_restrict = 1
#
# Enforces the setting at runtime and persistently across reboots.

set -euo pipefail

SYSCTL_PARAM="kernel.dmesg_restrict"
SYSCTL_VALUE="1"
CONFIG_FILE="/etc/sysctl.d/99-dmesg-restrict.conf"

# --- Apply the persistent configuration idempotently ---

# Remove any conflicting/duplicate definitions from common sysctl locations
# so the value we set is authoritative.
for f in /etc/sysctl.conf /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
    [ -f "$f" ] || continue
    # Skip our own managed file
    if [ "$f" = "$CONFIG_FILE" ]; then
        continue
    fi
    if grep -Eq "^[[:space:]]*${SYSCTL_PARAM}[[:space:]]*=" "$f" 2>/dev/null; then
        sed -i -E "\#^[[:space:]]*${SYSCTL_PARAM}[[:space:]]*=#d" "$f"
    fi
done

# Write our managed configuration file with the desired setting
mkdir -p "$(dirname "$CONFIG_FILE")"
if [ ! -f "$CONFIG_FILE" ] || ! grep -Eq "^[[:space:]]*${SYSCTL_PARAM}[[:space:]]*=[[:space:]]*${SYSCTL_VALUE}[[:space:]]*$" "$CONFIG_FILE"; then
    printf '%s = %s\n' "$SYSCTL_PARAM" "$SYSCTL_VALUE" > "$CONFIG_FILE"
    chmod 0644 "$CONFIG_FILE"
fi

# --- Apply the setting at runtime ---

# Load the setting from our config file (persistent + immediate)
if command -v sysctl >/dev/null 2>&1; then
    sysctl -w "${SYSCTL_PARAM}=${SYSCTL_VALUE}" >/dev/null
    # Reload from files to ensure system-wide consistency
    sysctl --system >/dev/null 2>&1 || true
else
    echo "$SYSCTL_VALUE" > "/proc/sys/${SYSCTL_PARAM//.//}"
fi

# --- Verify ---
CURRENT_VALUE="$(sysctl -n "$SYSCTL_PARAM" 2>/dev/null || cat "/proc/sys/${SYSCTL_PARAM//.//}")"
if [ "$CURRENT_VALUE" = "$SYSCTL_VALUE" ]; then
    echo "Success: ${SYSCTL_PARAM} is set to ${CURRENT_VALUE} (runtime and persistent)."
    exit 0
else
    echo "Error: ${SYSCTL_PARAM} is ${CURRENT_VALUE}, expected ${SYSCTL_VALUE}." >&2
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

**Prompt:** On a RHEL 8 system, enhance security by preventing any new kernel image from being loaded into memory after the system is running, which mitigates risks of unauthorized kernel replacement through kexec. Write an idempotent bash remediation script to disable kernel image loading at runtime and ensure this setting persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

SYSCTL_PARAM="kernel.kexec_load_disabled"
SYSCTL_VALUE="1"
SYSCTL_FILE="/etc/sysctl.d/99-kexec-hardening.conf"

# Ensure the persistent sysctl configuration is present and correct
if [ -f "$SYSCTL_FILE" ]; then
    # Remove any existing definitions of the parameter to avoid duplicates
    sed -i "\|^\s*${SYSCTL_PARAM}\s*=|d" "$SYSCTL_FILE"
fi

# Remove the setting from other common sysctl locations to prevent overrides
for f in /etc/sysctl.conf /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
    [ -e "$f" ] || continue
    [ "$f" = "$SYSCTL_FILE" ] && continue
    if grep -Eq "^\s*${SYSCTL_PARAM}\s*=" "$f" 2>/dev/null; then
        sed -i "\|^\s*${SYSCTL_PARAM}\s*=|d" "$f"
    fi
done

# Add the correct setting to the dedicated hardening file
echo "${SYSCTL_PARAM} = ${SYSCTL_VALUE}" >> "$SYSCTL_FILE"
chmod 0644 "$SYSCTL_FILE"

# Apply the setting at runtime
CURRENT_VALUE="$(sysctl -n "$SYSCTL_PARAM" 2>/dev/null || echo "")"
if [ "$CURRENT_VALUE" != "$SYSCTL_VALUE" ]; then
    sysctl -w "${SYSCTL_PARAM}=${SYSCTL_VALUE}" >/dev/null
fi

# Reload sysctl settings from the file to ensure consistency
sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1 || true

# Verify the runtime value
FINAL_VALUE="$(sysctl -n "$SYSCTL_PARAM" 2>/dev/null || echo "")"
if [ "$FINAL_VALUE" = "$SYSCTL_VALUE" ]; then
    echo "kernel.kexec_load_disabled is set to ${SYSCTL_VALUE} and persisted in ${SYSCTL_FILE}"
else
    echo "Failed to set ${SYSCTL_PARAM} to ${SYSCTL_VALUE} (current: ${FINAL_VALUE})" >&2
    exit 1
fi
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

**Prompt:** On a RHEL 8 system, unprivileged users are currently able to perform kernel profiling, which can inadvertently expose sensitive information about kernel operations. Write an idempotent bash remediation script to restrict kernel profiling such that only privileged users can access this capability. Ensure this restriction is enforced immediately and persists after reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Restrict kernel profiling to privileged users only.
# Sets kernel.perf_event_paranoid = 2 immediately and persistently.
#
set -euo pipefail

SYSCTL_KEY="kernel.perf_event_paranoid"
SYSCTL_VAL="2"
CONF_DIR="/etc/sysctl.d"
CONF_FILE="${CONF_DIR}/99-perf-event-paranoid.conf"

# Ensure we are running as root
if [[ "$(id -u)" -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# Ensure the sysctl.d directory exists
mkdir -p "${CONF_DIR}"

# Remove any conflicting settings for this key from other sysctl config files
for f in /etc/sysctl.conf /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
    [[ -f "${f}" ]] || continue
    [[ "${f}" == "${CONF_FILE}" ]] && continue
    if grep -Eq "^[[:space:]]*${SYSCTL_KEY//./\\.}[[:space:]]*=" "${f}"; then
        sed -i -E "/^[[:space:]]*${SYSCTL_KEY//./\\.}[[:space:]]*=/d" "${f}"
    fi
done

# Write the desired setting idempotently
DESIRED_LINE="${SYSCTL_KEY} = ${SYSCTL_VAL}"
if [[ ! -f "${CONF_FILE}" ]] || ! grep -Eq "^[[:space:]]*${SYSCTL_KEY//./\\.}[[:space:]]*=[[:space:]]*${SYSCTL_VAL}[[:space:]]*$" "${CONF_FILE}"; then
    printf '%s\n' "${DESIRED_LINE}" > "${CONF_FILE}"
    chmod 0644 "${CONF_FILE}"
fi

# Apply the setting immediately
sysctl -w "${SYSCTL_KEY}=${SYSCTL_VAL}" >/dev/null

# Reload all sysctl settings to ensure persistence config is coherent
sysctl --system >/dev/null 2>&1 || true

# Verify
CURRENT_VAL="$(sysctl -n "${SYSCTL_KEY}")"
if [[ "${CURRENT_VAL}" == "${SYSCTL_VAL}" ]]; then
    echo "Success: ${SYSCTL_KEY} is set to ${CURRENT_VAL}."
else
    echo "Error: ${SYSCTL_KEY} is ${CURRENT_VAL}, expected ${SYSCTL_VAL}." >&2
    exit 1
fi
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

**Prompt:** On a RHEL 8 system, unprivileged processes currently have the ability to use the network bpf() syscall, which may leak information about the kernel's state and compromise security. Write an idempotent bash remediation script that disables access to the network bpf() syscall for unprivileged processes at runtime, ensuring the setting is also persistent across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

SYSCTL_KEY="kernel.unprivileged_bpf_disabled"
SYSCTL_VALUE="1"
SYSCTL_DIR="/etc/sysctl.d"
CONFIG_FILE="${SYSCTL_DIR}/99-bpf-harden.conf"

mkdir -p "${SYSCTL_DIR}"

# Remove any conflicting definitions of the key from common sysctl config locations
for f in /etc/sysctl.conf ${SYSCTL_DIR}/*.conf /run/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
    [ -f "$f" ] || continue
    if [ "$f" = "$CONFIG_FILE" ]; then
        continue
    fi
    if grep -Eq "^\s*${SYSCTL_KEY}\b" "$f" 2>/dev/null; then
        sed -i -E "/^\s*${SYSCTL_KEY}\b/d" "$f"
    fi
done

# Write the persistent setting idempotently
if [ -f "${CONFIG_FILE}" ] && grep -Eq "^\s*${SYSCTL_KEY}\s*=\s*${SYSCTL_VALUE}\s*$" "${CONFIG_FILE}"; then
    :
else
    if [ -f "${CONFIG_FILE}" ] && grep -Eq "^\s*${SYSCTL_KEY}\b" "${CONFIG_FILE}"; then
        sed -i -E "s|^\s*${SYSCTL_KEY}\b.*|${SYSCTL_KEY} = ${SYSCTL_VALUE}|" "${CONFIG_FILE}"
    else
        printf '%s = %s\n' "${SYSCTL_KEY}" "${SYSCTL_VALUE}" >> "${CONFIG_FILE}"
    fi
fi

# Apply the setting at runtime
sysctl -w "${SYSCTL_KEY}=${SYSCTL_VALUE}" >/dev/null

# Reload sysctl settings from files to ensure consistency
sysctl --system >/dev/null 2>&1 || sysctl -p "${CONFIG_FILE}" >/dev/null 2>&1 || true

# Verify
CURRENT_VALUE="$(sysctl -n "${SYSCTL_KEY}" 2>/dev/null || echo "")"
if [ "${CURRENT_VALUE}" = "${SYSCTL_VALUE}" ]; then
    echo "Success: ${SYSCTL_KEY} is set to ${CURRENT_VALUE}"
else
    echo "Error: failed to set ${SYSCTL_KEY} (current value: '${CURRENT_VALUE}')" >&2
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

**Prompt:** On a RHEL 8 system, limit the "ptrace" capability so that processes can only examine or control their direct descendants, reducing the risk of sensitive data being extracted by malicious software through unauthorized process tracing. Write an idempotent bash remediation script that restricts ptrace operations to descendant processes at runtime and ensures this restriction persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

SYSCTL_KEY="kernel.yama.ptrace_scope"
SYSCTL_VALUE="1"
SYSCTL_CONF_DIR="/etc/sysctl.d"
SYSCTL_CONF_FILE="${SYSCTL_CONF_DIR}/10-ptrace-scope.conf"

echo "Ensuring Yama LSM is available..."
if [ ! -e /proc/sys/kernel/yama/ptrace_scope ]; then
    echo "ERROR: /proc/sys/kernel/yama/ptrace_scope not present. Yama LSM may not be enabled in the kernel." >&2
    exit 1
fi

echo "Removing conflicting sysctl settings from other config files..."
mapfile -t conflicting_files < <(grep -rlsE "^[[:space:]]*${SYSCTL_KEY}[[:space:]]*=" \
    /etc/sysctl.conf /etc/sysctl.d /run/sysctl.d /usr/lib/sysctl.d /usr/local/lib/sysctl.d 2>/dev/null || true)

for f in "${conflicting_files[@]}"; do
    if [ "${f}" != "${SYSCTL_CONF_FILE}" ]; then
        echo "  Cleaning ${SYSCTL_KEY} from ${f}"
        sed -i -E "/^[[:space:]]*${SYSCTL_KEY}[[:space:]]*=/d" "${f}"
    fi
done

echo "Ensuring persistent sysctl configuration in ${SYSCTL_CONF_FILE}..."
mkdir -p "${SYSCTL_CONF_DIR}"

DESIRED_LINE="${SYSCTL_KEY} = ${SYSCTL_VALUE}"

if [ -f "${SYSCTL_CONF_FILE}" ] && grep -qE "^[[:space:]]*${SYSCTL_KEY}[[:space:]]*=" "${SYSCTL_CONF_FILE}"; then
    sed -i -E "s|^[[:space:]]*${SYSCTL_KEY}[[:space:]]*=.*|${DESIRED_LINE}|" "${SYSCTL_CONF_FILE}"
else
    echo "${DESIRED_LINE}" >> "${SYSCTL_CONF_FILE}"
fi

echo "Applying sysctl setting at runtime..."
sysctl -w "${SYSCTL_KEY}=${SYSCTL_VALUE}" >/dev/null
sysctl --system >/dev/null 2>&1 || true

CURRENT_VALUE="$(cat /proc/sys/kernel/yama/ptrace_scope)"
if [ "${CURRENT_VALUE}" != "${SYSCTL_VALUE}" ]; then
    echo "ERROR: Failed to set ${SYSCTL_KEY} to ${SYSCTL_VALUE} (current: ${CURRENT_VALUE})." >&2
    exit 1
fi

echo "Success: ${SYSCTL_KEY} = ${CURRENT_VALUE} (ptrace restricted to descendant processes)."
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

**Prompt:** On a RHEL 8 system, enhance the security of the BPF just-in-time (JIT) compiler by ensuring it randomizes kernel addresses in BPF programs and does not expose JIT addresses in /proc/kallsyms. Write an idempotent bash remediation script to secure the BPF JIT compiler, ensuring this configuration is applied at runtime and remains effective after reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation script to harden the BPF JIT compiler on RHEL 8.
#
# This enables JIT hardening (net.core.bpf_jit_harden) which:
#   - Randomizes kernel addresses embedded in BPF programs (blinding constants)
#   - Prevents exposure of JIT addresses in /proc/kallsyms
#
# Value 2 applies hardening for all users (privileged and unprivileged).
#
set -euo pipefail

SYSCTL_KEY="net.core.bpf_jit_harden"
SYSCTL_VALUE="2"
SYSCTL_DIR="/etc/sysctl.d"
SYSCTL_CONF="${SYSCTL_DIR}/99-bpf-jit-harden.conf"

if [[ ${EUID} -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

# Ensure the sysctl.d directory exists.
mkdir -p "${SYSCTL_DIR}"

# --- Persist configuration for reboots ---

# Remove any conflicting/duplicate settings from other sysctl config files.
for f in /etc/sysctl.conf /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
    [[ -f "${f}" ]] || continue
    # Skip our own managed file.
    [[ "${f}" == "${SYSCTL_CONF}" ]] && continue
    if grep -Eq "^[[:space:]]*${SYSCTL_KEY}[[:space:]]*=" "${f}" 2>/dev/null; then
        sed -ri "/^[[:space:]]*${SYSCTL_KEY}[[:space:]]*=/d" "${f}"
    fi
done

# Write our managed configuration file idempotently.
DESIRED_LINE="${SYSCTL_KEY} = ${SYSCTL_VALUE}"
if [[ ! -f "${SYSCTL_CONF}" ]] || ! grep -Eq "^[[:space:]]*${SYSCTL_KEY}[[:space:]]*=[[:space:]]*${SYSCTL_VALUE}[[:space:]]*$" "${SYSCTL_CONF}"; then
    printf '# Managed by BPF JIT hardening remediation script\n%s\n' "${DESIRED_LINE}" > "${SYSCTL_CONF}"
    chmod 0644 "${SYSCTL_CONF}"
fi

# --- Apply configuration at runtime ---

# Reload the setting from our config file so it takes effect immediately.
if command -v sysctl >/dev/null 2>&1; then
    sysctl -q -w "${SYSCTL_KEY}=${SYSCTL_VALUE}" || true
    sysctl -q -p "${SYSCTL_CONF}" || true
fi

# --- Verification ---

CURRENT_VALUE="$(sysctl -n "${SYSCTL_KEY}" 2>/dev/null || echo 'unavailable')"
if [[ "${CURRENT_VALUE}" == "${SYSCTL_VALUE}" ]]; then
    echo "SUCCESS: ${SYSCTL_KEY} is set to ${CURRENT_VALUE} (runtime) and persisted in ${SYSCTL_CONF}."
else
    echo "WARNING: ${SYSCTL_KEY} runtime value is '${CURRENT_VALUE}', expected '${SYSCTL_VALUE}'." >&2
    echo "Configuration has been persisted in ${SYSCTL_CONF} and will apply after reboot." >&2
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

**Prompt:** On a RHEL 8 system, restrict the use of user namespaces by setting the maximum allowed user namespaces to zero. This minimizes attack vectors by preventing unnecessary functionalities that are primarily used in container environments. Write an idempotent bash remediation script that enforces this setting, ensuring it is applied at runtime and persists across reboots. Do not implement this restriction if the system requires user namespaces for container workflows, where a non-zero value is needed.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Set user.max_user_namespaces = 0
# Idempotent: applies runtime setting and persists across reboots.
#

set -euo pipefail

SYSCTL_PARAM="user.max_user_namespaces"
SYSCTL_VALUE="0"
SYSCTL_CONF="/etc/sysctl.d/99-user_max_user_namespaces.conf"

# If the system requires user namespaces (a non-zero value is already
# configured for container workflows), do not enforce the restriction.
requires_userns=false

# Check any persisted configuration files for a non-zero value.
declare -a sysctl_files=(
    /run/sysctl.d/*.conf
    /etc/sysctl.d/*.conf
    /usr/local/lib/sysctl.d/*.conf
    /usr/lib/sysctl.d/*.conf
    /lib/sysctl.d/*.conf
    /etc/sysctl.conf
)

for f in "${sysctl_files[@]}"; do
    [ -f "$f" ] || continue
    # Skip our own managed file when scanning for external overrides.
    [ "$f" = "$SYSCTL_CONF" ] && continue
    while IFS= read -r line; do
        # Strip comments and whitespace
        key=$(printf '%s' "$line" | sed -e 's/#.*//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
        case "$key" in
            "$SYSCTL_PARAM"*=*)
                val=$(printf '%s' "$key" | cut -d= -f2- | tr -d '[:space:]')
                if [ -n "$val" ] && [ "$val" != "0" ]; then
                    requires_userns=true
                fi
                ;;
        esac
    done < "$f"
done

if [ "$requires_userns" = true ]; then
    echo "System configuration indicates user namespaces are required (non-zero value present)."
    echo "Skipping restriction of ${SYSCTL_PARAM}."
    exit 0
fi

# Persist the setting.
mkdir -p "$(dirname "$SYSCTL_CONF")"

desired_line="${SYSCTL_PARAM} = ${SYSCTL_VALUE}"

if [ -f "$SYSCTL_CONF" ]; then
    if grep -Eq "^[[:space:]]*${SYSCTL_PARAM}[[:space:]]*=" "$SYSCTL_CONF"; then
        # Update existing entry idempotently.
        sed -i -E "s|^[[:space:]]*${SYSCTL_PARAM}[[:space:]]*=.*|${desired_line}|" "$SYSCTL_CONF"
    else
        printf '%s\n' "$desired_line" >> "$SYSCTL_CONF"
    fi
else
    printf '%s\n' "$desired_line" > "$SYSCTL_CONF"
fi

# Apply at runtime.
sysctl -w "${SYSCTL_PARAM}=${SYSCTL_VALUE}" >/dev/null

# Reload from the managed file to ensure consistency.
sysctl -p "$SYSCTL_CONF" >/dev/null 2>&1 || true

# Verify runtime value.
current_value=$(sysctl -n "$SYSCTL_PARAM" 2>/dev/null || echo "unset")
if [ "$current_value" = "$SYSCTL_VALUE" ]; then
    echo "Successfully set ${SYSCTL_PARAM} = ${SYSCTL_VALUE} (runtime and persistent)."
else
    echo "Failed to set ${SYSCTL_PARAM}. Current runtime value: ${current_value}" >&2
    exit 1
fi
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

**Prompt:** On a RHEL 8 system, disable the acquisition, saving, and processing of core dumps which may contain sensitive data and are primarily useful for developers. Ensure that the mechanism responsible for handling core dumps is deactivated and remains inactive across reboots. Write an idempotent bash remediation script to achieve this state.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

SERVICE="systemd-coredump.socket"

# Mask the systemd-coredump socket to disable core dump handling
if systemctl list-unit-files | grep -q "^${SERVICE}"; then
    if [ "$(systemctl is-enabled "${SERVICE}" 2>/dev/null || true)" != "masked" ]; then
        systemctl mask "${SERVICE}"
    fi
    if systemctl is-active --quiet "${SERVICE}" 2>/dev/null; then
        systemctl stop "${SERVICE}"
    fi
fi

# Ensure coredump storage and processing are disabled in coredump.conf
COREDUMP_CONF="/etc/systemd/coredump.conf"

if [ ! -f "${COREDUMP_CONF}" ]; then
    mkdir -p /etc/systemd
    printf '[Coredump]\n' > "${COREDUMP_CONF}"
fi

# Ensure [Coredump] section exists
if ! grep -q '^\[Coredump\]' "${COREDUMP_CONF}"; then
    printf '\n[Coredump]\n' >> "${COREDUMP_CONF}"
fi

set_coredump_option() {
    local key="$1"
    local value="$2"
    if grep -qiE "^\s*#?\s*${key}\s*=" "${COREDUMP_CONF}"; then
        sed -i -E "s|^\s*#?\s*${key}\s*=.*|${key}=${value}|I" "${COREDUMP_CONF}"
    else
        sed -i "/^\[Coredump\]/a ${key}=${value}" "${COREDUMP_CONF}"
    fi
}

set_coredump_option "Storage" "none"
set_coredump_option "ProcessSizeMax" "0"

# Configure sysctl to disable setuid core dumps and set core pattern
SYSCTL_CONF="/etc/sysctl.d/99-coredump.conf"
mkdir -p /etc/sysctl.d

update_sysctl_line() {
    local key="$1"
    local value="$2"
    if [ -f "${SYSCTL_CONF}" ] && grep -qE "^\s*${key}\s*=" "${SYSCTL_CONF}"; then
        sed -i -E "s|^\s*${key}\s*=.*|${key} = ${value}|" "${SYSCTL_CONF}"
    else
        echo "${key} = ${value}" >> "${SYSCTL_CONF}"
    fi
}

update_sysctl_line "kernel.core_pattern" "|/bin/false"
update_sysctl_line "fs.suid_dumpable" "0"

sysctl -w kernel.core_pattern="|/bin/false" >/dev/null
sysctl -w fs.suid_dumpable=0 >/dev/null

# Disable core dumps via limits.conf
LIMITS_CONF="/etc/security/limits.d/99-coredump.conf"
mkdir -p /etc/security/limits.d

if [ ! -f "${LIMITS_CONF}" ] || ! grep -qE '^\s*\*\s+hard\s+core\s+0' "${LIMITS_CONF}"; then
    {
        echo "* hard core 0"
        echo "* soft core 0"
    } > "${LIMITS_CONF}"
fi

# Reload systemd configuration
systemctl daemon-reload

echo "Core dump handling has been disabled."
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

**Prompt:** On a RHEL 8 system, configure the core dump handling to disable the generation of backtraces for core dumps. This reduces the potential exposure of sensitive data found in core dumps while still allowing system logging. Write an idempotent bash remediation script that sets the system to prevent the creation of backtraces from core dumps, ensuring this configuration is persistent across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Disable backtrace generation for core dumps on RHEL 8
# Sets ProcessSizeMax=0 in /etc/systemd/coredump.conf under the [Coredump] section
# This prevents systemd-coredump from creating backtraces while still allowing logging.

set -euo pipefail

CONF_FILE="/etc/systemd/coredump.conf"
SECTION="Coredump"
KEY="ProcessSizeMax"
VALUE="0"

# Ensure the configuration file exists
if [[ ! -f "$CONF_FILE" ]]; then
    printf '[%s]\n' "$SECTION" > "$CONF_FILE"
fi

# Ensure the [Coredump] section exists
if ! grep -qE "^\s*\[${SECTION}\]" "$CONF_FILE"; then
    printf '\n[%s]\n' "$SECTION" >> "$CONF_FILE"
fi

# Check if the key exists (commented or uncommented) and set it correctly
if grep -qE "^\s*#?\s*${KEY}\s*=" "$CONF_FILE"; then
    # Replace the existing (possibly commented) line with the desired value
    sed -i -E "s|^\s*#?\s*${KEY}\s*=.*|${KEY}=${VALUE}|" "$CONF_FILE"
else
    # Insert the key right after the [Coredump] section header
    sed -i -E "/^\s*\[${SECTION}\]/a ${KEY}=${VALUE}" "$CONF_FILE"
fi

# Verify the setting is correctly applied (idempotent check)
if grep -qE "^\s*${KEY}\s*=\s*${VALUE}\s*$" "$CONF_FILE"; then
    echo "Configuration verified: ${KEY}=${VALUE} in ${CONF_FILE}"
else
    echo "ERROR: Failed to set ${KEY}=${VALUE} in ${CONF_FILE}" >&2
    exit 1
fi

# Reload systemd to apply the coredump configuration change
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

echo "Core dump backtrace generation has been disabled and made persistent."
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

**Prompt:** On a RHEL 8 system, disable the storing of core dumps to minimize the risk of sensitive information exposure and align with security best practices for production environments. Write an idempotent bash remediation script that configures the system so that core dumps are not stored by default, ensuring that this setting persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation script to disable core dumps on RHEL 8
# Idempotent: safe to run multiple times.
#
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

########################################
# 1. Disable core dumps via limits.conf
########################################
LIMITS_DIR="/etc/security/limits.d"
LIMITS_FILE="${LIMITS_DIR}/99-disable-coredumps.conf"

mkdir -p "${LIMITS_DIR}"

desired_limits="$(cat <<'EOF'
# Managed by remediation script: disable core dumps
* hard core 0
* soft core 0
EOF
)"

if [[ ! -f "${LIMITS_FILE}" ]] || [[ "$(cat "${LIMITS_FILE}")" != "${desired_limits}" ]]; then
    printf '%s\n' "${desired_limits}" > "${LIMITS_FILE}"
    chmod 0644 "${LIMITS_FILE}"
    echo "Updated ${LIMITS_FILE}"
else
    echo "${LIMITS_FILE} already configured."
fi

########################################
# 2. Disable setuid core dumps via sysctl
########################################
SYSCTL_DIR="/etc/sysctl.d"
SYSCTL_FILE="${SYSCTL_DIR}/99-disable-coredumps.conf"

mkdir -p "${SYSCTL_DIR}"

desired_sysctl="$(cat <<'EOF'
# Managed by remediation script: disable core dumps
fs.suid_dumpable = 0
kernel.core_pattern = |/bin/false
EOF
)"

if [[ ! -f "${SYSCTL_FILE}" ]] || [[ "$(cat "${SYSCTL_FILE}")" != "${desired_sysctl}" ]]; then
    printf '%s\n' "${desired_sysctl}" > "${SYSCTL_FILE}"
    chmod 0644 "${SYSCTL_FILE}"
    echo "Updated ${SYSCTL_FILE}"
else
    echo "${SYSCTL_FILE} already configured."
fi

# Apply sysctl settings immediately
sysctl -w fs.suid_dumpable=0 >/dev/null
sysctl -w kernel.core_pattern="|/bin/false" >/dev/null

########################################
# 3. Configure systemd coredump handling
########################################
COREDUMP_DIR="/etc/systemd/coredump.conf.d"
COREDUMP_FILE="${COREDUMP_DIR}/99-disable-coredumps.conf"

mkdir -p "${COREDUMP_DIR}"

desired_coredump="$(cat <<'EOF'
# Managed by remediation script: disable core dumps
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
)"

if [[ ! -f "${COREDUMP_FILE}" ]] || [[ "$(cat "${COREDUMP_FILE}")" != "${desired_coredump}" ]]; then
    printf '%s\n' "${desired_coredump}" > "${COREDUMP_FILE}"
    chmod 0644 "${COREDUMP_FILE}"
    echo "Updated ${COREDUMP_FILE}"
else
    echo "${COREDUMP_FILE} already configured."
fi

########################################
# 4. Reload systemd to apply coredump config
########################################
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    # Mask systemd-coredump socket/service if present to prevent capture
    if systemctl list-unit-files | grep -q '^systemd-coredump\.socket'; then
        systemctl mask systemd-coredump.socket >/dev/null 2>&1 || true
    fi
fi

echo "Core dump storage has been disabled and will persist across reboots."
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

**Prompt:** On a RHEL 8 system, ensure that core dumps are disabled for all users across the system to prevent exposure of sensitive information in memory, which could be extracted from core dump files. Write an idempotent bash remediation script that implements this policy by utilizing the system-wide limits configuration.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

LIMITS_FILE="/etc/security/limits.conf"
LIMITS_DIR="/etc/security/limits.d"
DROPIN="${LIMITS_DIR}/50-disable-coredumps.conf"

# Ensure limits.d directory exists
if [[ ! -d "$LIMITS_DIR" ]]; then
    mkdir -p "$LIMITS_DIR"
    chmod 0755 "$LIMITS_DIR"
fi

# Remove any existing core dump limit lines from main limits.conf to avoid conflicts
if [[ -f "$LIMITS_FILE" ]]; then
    if grep -Eq '^[[:space:]]*\*[[:space:]]+(hard|soft)[[:space:]]+core' "$LIMITS_FILE"; then
        sed -i -E '/^[[:space:]]*\*[[:space:]]+(hard|soft)[[:space:]]+core[[:space:]]/d' "$LIMITS_FILE"
    fi
fi

# Create/refresh the drop-in file with hard limit of 0 for all users
DESIRED_CONTENT="* hard core 0"

if [[ ! -f "$DROPIN" ]] || ! grep -Eq '^[[:space:]]*\*[[:space:]]+hard[[:space:]]+core[[:space:]]+0[[:space:]]*$' "$DROPIN"; then
    printf '%s\n' "$DESIRED_CONTENT" > "$DROPIN"
    chmod 0644 "$DROPIN"
fi

# Ensure systemd coredump is also disabled system-wide
SYSTEMD_COREDUMP_CONF="/etc/systemd/coredump.conf"
if [[ -f "$SYSTEMD_COREDUMP_CONF" ]]; then
    if grep -Eq '^[[:space:]]*Storage[[:space:]]*=' "$SYSTEMD_COREDUMP_CONF"; then
        sed -i -E 's|^[[:space:]]*Storage[[:space:]]*=.*|Storage=none|' "$SYSTEMD_COREDUMP_CONF"
    else
        if grep -Eq '^\[Coredump\]' "$SYSTEMD_COREDUMP_CONF"; then
            sed -i '/^\[Coredump\]/a Storage=none' "$SYSTEMD_COREDUMP_CONF"
        else
            printf '[Coredump]\nStorage=none\n' >> "$SYSTEMD_COREDUMP_CONF"
        fi
    fi

    if grep -Eq '^[[:space:]]*ProcessSizeMax[[:space:]]*=' "$SYSTEMD_COREDUMP_CONF"; then
        sed -i -E 's|^[[:space:]]*ProcessSizeMax[[:space:]]*=.*|ProcessSizeMax=0|' "$SYSTEMD_COREDUMP_CONF"
    else
        if grep -Eq '^\[Coredump\]' "$SYSTEMD_COREDUMP_CONF"; then
            sed -i '/^\[Coredump\]/a ProcessSizeMax=0' "$SYSTEMD_COREDUMP_CONF"
        else
            printf '[Coredump]\nProcessSizeMax=0\n' >> "$SYSTEMD_COREDUMP_CONF"
        fi
    fi
else
    printf '[Coredump]\nStorage=none\nProcessSizeMax=0\n' > "$SYSTEMD_COREDUMP_CONF"
    chmod 0644 "$SYSTEMD_COREDUMP_CONF"
fi

# Set sysctl to prevent setuid programs from dumping core
SYSCTL_DROPIN="/etc/sysctl.d/50-coredump.conf"
if [[ ! -f "$SYSCTL_DROPIN" ]] || ! grep -Eq '^[[:space:]]*fs\.suid_dumpable[[:space:]]*=[[:space:]]*0[[:space:]]*$' "$SYSCTL_DROPIN"; then
    printf 'fs.suid_dumpable = 0\n' > "$SYSCTL_DROPIN"
    chmod 0644 "$SYSCTL_DROPIN"
fi

# Apply sysctl setting immediately (idempotent)
sysctl -w fs.suid_dumpable=0 >/dev/null 2>&1 || true

# Reload systemd if coredump config changed
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

echo "Core dumps have been disabled system-wide."
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

**Prompt:** On a RHEL 8 system, the current configuration may not adequately utilize Address Space Layout Randomization (ASLR), increasing vulnerability to certain types of exploitation attempts. To protect against these types of attacks, configure the system to enable full randomization of virtual address space layout. Write an idempotent bash remediation script that ensures this randomization is both activated immediately and maintained across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Enable full Address Space Layout Randomization (ASLR)
# Sets kernel.randomize_va_space = 2 immediately and persistently.
#
set -euo pipefail

PARAM="kernel.randomize_va_space"
VALUE="2"
DROPIN_DIR="/etc/sysctl.d"
DROPIN_FILE="${DROPIN_DIR}/99-aslr.conf"

# Ensure the sysctl drop-in directory exists
if [ ! -d "${DROPIN_DIR}" ]; then
    mkdir -p "${DROPIN_DIR}"
fi

# Remove any conflicting settings from common sysctl configuration files
for f in /etc/sysctl.conf /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
    [ -f "${f}" ] || continue
    # Skip our own managed drop-in file
    if [ "${f}" = "${DROPIN_FILE}" ]; then
        continue
    fi
    if grep -Eq "^[[:space:]]*${PARAM}[[:space:]]*=" "${f}"; then
        sed -i -E "/^[[:space:]]*${PARAM}[[:space:]]*=/d" "${f}"
    fi
done

# Write (or update) the managed drop-in file idempotently
DESIRED_LINE="${PARAM} = ${VALUE}"
if [ ! -f "${DROPIN_FILE}" ] || ! grep -Eq "^[[:space:]]*${PARAM}[[:space:]]*=[[:space:]]*${VALUE}[[:space:]]*$" "${DROPIN_FILE}"; then
    printf '%s\n' "${DESIRED_LINE}" > "${DROPIN_FILE}"
    chmod 0644 "${DROPIN_FILE}"
fi

# Apply the setting immediately
sysctl -w "${PARAM}=${VALUE}" >/dev/null

# Reload sysctl settings to ensure consistency (best-effort)
sysctl --system >/dev/null 2>&1 || true

# Verify the runtime value
CURRENT="$(sysctl -n "${PARAM}")"
if [ "${CURRENT}" != "${VALUE}" ]; then
    echo "ERROR: Failed to set ${PARAM} to ${VALUE} (current: ${CURRENT})" >&2
    exit 1
fi

echo "SUCCESS: ${PARAM} is set to ${VALUE} (full ASLR enabled and persistent)."
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

**Prompt:** On a RHEL 8 system, ensure that the kernel is configured to poison free memory pages, providing an additional security measure against use-after-free vulnerabilities. Develop an idempotent bash remediation script that appends the necessary kernel command line argument to enable page allocator poisoning, ensuring it is applied both to the current and any future kernel entries in the boot loader configuration, and persists this setting across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Enable page allocator poisoning (page_poison=1) on RHEL 8
# Idempotently ensures the kernel command line argument is applied to the
# current kernel entry, all future kernel entries, and persists across reboots.

set -o pipefail

ARG="page_poison=1"

# Ensure we are running as root
if [[ "$(id -u)" -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

#
# 1. Persist the setting for all future kernel entries via /etc/default/grub
#
GRUB_DEFAULT="/etc/default/grub"

if [[ -f "$GRUB_DEFAULT" ]]; then
    if grep -q '^GRUB_CMDLINE_LINUX=' "$GRUB_DEFAULT"; then
        # Extract current value of GRUB_CMDLINE_LINUX
        current_line="$(grep '^GRUB_CMDLINE_LINUX=' "$GRUB_DEFAULT")"
        if echo "$current_line" | grep -qw "$ARG"; then
            echo "GRUB_CMDLINE_LINUX already contains '$ARG'. No change to $GRUB_DEFAULT."
        else
            # Append the argument inside the existing quotes
            sed -i "s/^\(GRUB_CMDLINE_LINUX=\"[^\"]*\)\"/\1 $ARG\"/" "$GRUB_DEFAULT"
            # Clean up any accidental leading space inside quotes (empty original value)
            sed -i "s/^\(GRUB_CMDLINE_LINUX=\"\) $ARG\"/\1$ARG\"/" "$GRUB_DEFAULT"
            echo "Added '$ARG' to GRUB_CMDLINE_LINUX in $GRUB_DEFAULT."
        fi
    else
        echo "GRUB_CMDLINE_LINUX=\"$ARG\"" >> "$GRUB_DEFAULT"
        echo "Created GRUB_CMDLINE_LINUX with '$ARG' in $GRUB_DEFAULT."
    fi
else
    echo "GRUB_CMDLINE_LINUX=\"$ARG\"" > "$GRUB_DEFAULT"
    echo "Created $GRUB_DEFAULT with '$ARG'."
fi

#
# 2. Apply the setting to current and existing kernel entries via grubby
#
if command -v grubby >/dev/null 2>&1; then
    # Update all existing boot entries
    grubby --update-kernel=ALL --args="$ARG"
    echo "Applied '$ARG' to all existing kernel entries via grubby."
else
    echo "grubby not found; skipping per-entry update." >&2
fi

#
# 3. Regenerate the GRUB2 configuration to ensure persistence
#
if [[ -d /sys/firmware/efi ]]; then
    GRUB_CFG="/boot/efi/EFI/redhat/grub.cfg"
else
    GRUB_CFG="/boot/grub2/grub.cfg"
fi

if command -v grub2-mkconfig >/dev/null 2>&1; then
    if [[ -f "$GRUB_CFG" ]] || [[ -d "$(dirname "$GRUB_CFG")" ]]; then
        grub2-mkconfig -o "$GRUB_CFG"
        echo "Regenerated GRUB configuration at $GRUB_CFG."
    else
        # Fallback to default path
        grub2-mkconfig -o /boot/grub2/grub.cfg
        echo "Regenerated GRUB configuration at /boot/grub2/grub.cfg."
    fi
else
    echo "grub2-mkconfig not found; skipping config regeneration." >&2
fi

echo "Page allocator poisoning ('$ARG') remediation complete."
echo "A reboot is required for the setting to take effect."
exit 0
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

**Prompt:** On a RHEL 8 system, ensure the kernel is configured to enable memory poisoning for the SLUB or SLAB allocator, which writes specific values to memory areas when they are freed and when allocated, preventing use-after-free and other vulnerabilities. Write an idempotent bash remediation script that configures this poisoning behavior by modifying the GRUB 2 bootloader settings so that it persists across reboots and applies to all installed kernels. The result should enhance system security by detecting and mitigating memory-related vulnerabilities inherently.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation script: enable SLUB/SLAB memory poisoning via GRUB2
# Parameter: slub_debug=P
# This script is idempotent and applies to all installed kernels.

set -euo pipefail

PARAM="slub_debug=P"
GRUB_DEFAULT="/etc/default/grub"

# Ensure we are running as root
if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# --- 1. Update /etc/default/grub so new kernels inherit the setting ---
if [[ ! -f "${GRUB_DEFAULT}" ]]; then
    echo "Creating ${GRUB_DEFAULT}"
    touch "${GRUB_DEFAULT}"
fi

if grep -q '^GRUB_CMDLINE_LINUX=' "${GRUB_DEFAULT}"; then
    # Check if slub_debug is already present (with any value)
    current_line="$(grep '^GRUB_CMDLINE_LINUX=' "${GRUB_DEFAULT}")"

    if echo "${current_line}" | grep -qw 'slub_debug=P'; then
        echo "slub_debug=P already present in ${GRUB_DEFAULT}"
    elif echo "${current_line}" | grep -q 'slub_debug='; then
        # Replace any existing slub_debug value with P
        sed -i -E 's/slub_debug=[^"[:space:]]*/slub_debug=P/' "${GRUB_DEFAULT}"
        echo "Updated existing slub_debug value to P in ${GRUB_DEFAULT}"
    else
        # Append the parameter inside the existing quotes
        sed -i -E 's/^(GRUB_CMDLINE_LINUX=")(.*)(")/\1\2 slub_debug=P\3/' "${GRUB_DEFAULT}"
        # Clean up potential double spaces
        sed -i -E 's/GRUB_CMDLINE_LINUX="[[:space:]]+/GRUB_CMDLINE_LINUX="/' "${GRUB_DEFAULT}"
        echo "Added slub_debug=P to GRUB_CMDLINE_LINUX in ${GRUB_DEFAULT}"
    fi
else
    echo "GRUB_CMDLINE_LINUX=\"${PARAM}\"" >> "${GRUB_DEFAULT}"
    echo "Created GRUB_CMDLINE_LINUX with slub_debug=P in ${GRUB_DEFAULT}"
fi

# --- 2. Apply to all installed kernels using grubby ---
if command -v grubby >/dev/null 2>&1; then
    # Update all kernel entries
    grubby --update-kernel=ALL --args="${PARAM}" >/dev/null 2>&1 || true
    echo "Applied ${PARAM} to all installed kernels via grubby"
fi

# --- 3. Regenerate the GRUB2 configuration ---
# Determine the correct grub config location (BIOS vs UEFI)
if [[ -d /sys/firmware/efi ]]; then
    GRUB_CFG="/boot/efi/EFI/redhat/grub.cfg"
    if [[ ! -f "${GRUB_CFG}" ]]; then
        # Fallback: try to locate the efi grub.cfg dynamically
        GRUB_CFG="$(find /boot/efi/EFI -name grub.cfg 2>/dev/null | head -n1 || true)"
    fi
else
    GRUB_CFG="/boot/grub2/grub.cfg"
fi

if [[ -n "${GRUB_CFG:-}" ]]; then
    grub2-mkconfig -o "${GRUB_CFG}"
    echo "Regenerated GRUB configuration at ${GRUB_CFG}"
else
    echo "Warning: Could not determine GRUB configuration file location." >&2
fi

echo "Memory poisoning (slub_debug=P) configuration complete. Reboot required to take effect."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel && { rpm --quiet -q grub2-common; }; then

var_slub_debug_options='
```


---

## RHEL-08-010670 — `service_kdump_disabled`

**Prompt:** In a RHEL 8 environment, the kdump service is running, which can lead to potential security issues by exposing sensitive system state in core dumps, and risk system instability by using excessive disk space. Write an idempotent bash remediation script to permanently disable the kdump service, ensuring it remains inactive even after a reboot.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation script: Permanently disable the kdump service on RHEL 8
# This script is idempotent and safe to run multiple times.

set -euo pipefail

SERVICE="kdump.service"
GRUB_DEFAULT="/etc/default/grub"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

# Ensure the script is run as root
if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

# 1. Stop the kdump service if it is currently running
if systemctl is-active --quiet "${SERVICE}"; then
    log "Stopping ${SERVICE}..."
    systemctl stop "${SERVICE}"
else
    log "${SERVICE} is not active. No stop needed."
fi

# 2. Disable the kdump service so it does not start on boot
if systemctl is-enabled --quiet "${SERVICE}" 2>/dev/null; then
    log "Disabling ${SERVICE}..."
    systemctl disable "${SERVICE}"
else
    log "${SERVICE} is already disabled or not installed."
fi

# 3. Mask the service to prevent it from being started by any means
if [[ "$(systemctl is-enabled "${SERVICE}" 2>/dev/null || true)" != "masked" ]]; then
    log "Masking ${SERVICE}..."
    systemctl mask "${SERVICE}" || true
else
    log "${SERVICE} is already masked."
fi

# 4. Ensure kernel is configured with crashkernel=no to disable memory reservation
if [[ -f "${GRUB_DEFAULT}" ]]; then
    if grep -q '^GRUB_CMDLINE_LINUX=' "${GRUB_DEFAULT}"; then
        current_line="$(grep '^GRUB_CMDLINE_LINUX=' "${GRUB_DEFAULT}")"

        # Remove any existing crashkernel= entries
        new_line="$(echo "${current_line}" | sed -E 's/crashkernel=[^"[:space:]]*//g')"

        # Add crashkernel=no if not present
        if ! echo "${new_line}" | grep -q 'crashkernel=no'; then
            # Insert crashkernel=no before the closing quote
            new_line="$(echo "${new_line}" | sed -E 's/"[[:space:]]*$/ crashkernel=no"/')"
        fi

        # Normalize extra spaces
        new_line="$(echo "${new_line}" | sed -E 's/[[:space:]]+/ /g; s/ "/"/g; s/=" /="/g')"

        if [[ "${current_line}" != "${new_line}" ]]; then
            log "Updating GRUB_CMDLINE_LINUX to disable crashkernel..."
            cp -a "${GRUB_DEFAULT}" "${GRUB_DEFAULT}.bak.$(date +%Y%m%d%H%M%S)"
            sed -i "s|^GRUB_CMDLINE_LINUX=.*|${new_line}|" "${GRUB_DEFAULT}"

            # Regenerate GRUB config
            if [[ -d /sys/firmware/efi ]]; then
                GRUB_CFG="/boot/efi/EFI/redhat/grub.cfg"
            else
                GRUB_CFG="/boot/grub2/grub.cfg"
            fi
            log "Regenerating GRUB configuration at ${GRUB_CFG}..."
            grub2-mkconfig -o "${GRUB_CFG}"
        else
            log "GRUB already configured with crashkernel disabled. No change needed."
        fi
    else
        log "GRUB_CMDLINE_LINUX not found in ${GRUB_DEFAULT}. Skipping GRUB modification."
    fi
else
    log "${GRUB_DEFAULT} not found. Skipping GRUB modification."
fi

log "kdump has been permanently disabled."
log "Note: A reboot may be required for crashkernel changes to fully take effect."

exit 0
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

**Prompt:** On a RHEL 8 system, ensure that application whitelisting is enforced by having the File Access Policy Daemon (fapolicyd) installed and active. Write an idempotent bash remediation script that checks for the presence and active status of fapolicyd, installing and starting it if necessary, and ensuring it stays enabled across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation script: enforce application whitelisting via fapolicyd
# Ensures fapolicyd is installed, enabled, and active (idempotent).

set -o pipefail

PACKAGE="fapolicyd"
SERVICE="fapolicyd.service"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

# Must run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

# 1. Ensure the fapolicyd package is installed
if rpm -q "${PACKAGE}" >/dev/null 2>&1; then
    log "Package '${PACKAGE}' is already installed."
else
    log "Package '${PACKAGE}' not installed. Installing..."
    if command -v dnf >/dev/null 2>&1; then
        dnf install -y "${PACKAGE}"
    elif command -v yum >/dev/null 2>&1; then
        yum install -y "${PACKAGE}"
    else
        echo "ERROR: Neither dnf nor yum found; cannot install ${PACKAGE}." >&2
        exit 1
    fi

    if ! rpm -q "${PACKAGE}" >/dev/null 2>&1; then
        echo "ERROR: Failed to install ${PACKAGE}." >&2
        exit 1
    fi
    log "Package '${PACKAGE}' installed successfully."
fi

# 2. Ensure the service is enabled to start at boot
if systemctl is-enabled "${SERVICE}" >/dev/null 2>&1; then
    log "Service '${SERVICE}' is already enabled."
else
    log "Enabling service '${SERVICE}'..."
    systemctl enable "${SERVICE}"
    if ! systemctl is-enabled "${SERVICE}" >/dev/null 2>&1; then
        echo "ERROR: Failed to enable ${SERVICE}." >&2
        exit 1
    fi
    log "Service '${SERVICE}' enabled."
fi

# 3. Ensure the service is active (running)
if systemctl is-active "${SERVICE}" >/dev/null 2>&1; then
    log "Service '${SERVICE}' is already active."
else
    log "Starting service '${SERVICE}'..."
    systemctl start "${SERVICE}"
    if ! systemctl is-active "${SERVICE}" >/dev/null 2>&1; then
        echo "ERROR: Failed to start ${SERVICE}." >&2
        systemctl status "${SERVICE}" --no-pager || true
        exit 1
    fi
    log "Service '${SERVICE}' started."
fi

log "fapolicyd is installed, enabled, and active. Application whitelisting is enforced."
exit 0
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

**Prompt:** On a RHEL 8 system, ensure the File Access Policy Daemon (fapolicyd) is enabled and will start automatically at boot. This service is crucial for implementing application whitelisting to manage file access rights. Write an idempotent bash remediation script that enables and ensures this service is configured to run at start-up persistently.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation script: Ensure fapolicyd (File Access Policy Daemon) is
# installed, enabled, and running persistently at boot on RHEL 8.
# This script is idempotent and safe to run multiple times.

set -o pipefail

SERVICE_NAME="fapolicyd"
PACKAGE_NAME="fapolicyd"

# Ensure we are running as root
if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

# Verify systemctl is available
if ! command -v systemctl >/dev/null 2>&1; then
    echo "ERROR: systemctl not found. This script requires a systemd-based system." >&2
    exit 1
fi

# Ensure the fapolicyd package is installed
if ! rpm -q "${PACKAGE_NAME}" >/dev/null 2>&1; then
    echo "Package '${PACKAGE_NAME}' is not installed. Installing..."
    if command -v dnf >/dev/null 2>&1; then
        dnf install -y "${PACKAGE_NAME}" || {
            echo "ERROR: Failed to install ${PACKAGE_NAME}." >&2
            exit 1
        }
    elif command -v yum >/dev/null 2>&1; then
        yum install -y "${PACKAGE_NAME}" || {
            echo "ERROR: Failed to install ${PACKAGE_NAME}." >&2
            exit 1
        }
    else
        echo "ERROR: No supported package manager (dnf/yum) found." >&2
        exit 1
    fi
else
    echo "Package '${PACKAGE_NAME}' is already installed."
fi

# Enable the service to start at boot (idempotent)
if systemctl is-enabled "${SERVICE_NAME}" >/dev/null 2>&1; then
    echo "Service '${SERVICE_NAME}' is already enabled at boot."
else
    echo "Enabling service '${SERVICE_NAME}' to start at boot..."
    systemctl enable "${SERVICE_NAME}" || {
        echo "ERROR: Failed to enable ${SERVICE_NAME}." >&2
        exit 1
    }
fi

# Ensure the service is currently running (idempotent)
if systemctl is-active "${SERVICE_NAME}" >/dev/null 2>&1; then
    echo "Service '${SERVICE_NAME}' is already active/running."
else
    echo "Starting service '${SERVICE_NAME}'..."
    systemctl start "${SERVICE_NAME}" || {
        echo "ERROR: Failed to start ${SERVICE_NAME}." >&2
        exit 1
    }
fi

# Final verification
if systemctl is-enabled "${SERVICE_NAME}" >/dev/null 2>&1 && \
   systemctl is-active "${SERVICE_NAME}" >/dev/null 2>&1; then
    echo "SUCCESS: '${SERVICE_NAME}' is enabled and running."
    exit 0
else
    echo "ERROR: '${SERVICE_NAME}' is not properly enabled and/or running." >&2
    exit 1
fi
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

**Prompt:** On a RHEL 8 system, configure the Fapolicy module to implement a deny-all, permit-by-exception policy to control software execution. This means no software execution is allowed by default unless explicitly whitelisted. This enhances security by ensuring only vetted programs run, reducing potential vulnerabilities. Write an idempotent bash remediation script to configure this restrictive execution policy that persists across reboots, ensuring only authorized software is executable while preventing unauthorized program execution.

**Model-generated script:**
```bash
```bash
#!/usr/bin/env bash
#
# Remediation script: Configure fapolicyd to implement a
# deny-all, permit-by-exception software execution policy on RHEL 8.
#
# Idempotent: safe to run multiple times.

set -euo pipefail

LOG() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

#-----------------------------------------------------------------------
# 1. Ensure fapolicyd package is installed
#-----------------------------------------------------------------------
if ! rpm -q fapolicyd >/dev/null 2>&1; then
    LOG "Installing fapolicyd package..."
    if command -v dnf >/dev/null 2>&1; then
        dnf install -y fapolicyd
    else
        yum install -y fapolicyd
    fi
else
    LOG "fapolicyd package already installed."
fi

#-----------------------------------------------------------------------
# 2. Configure fapolicyd main configuration
#    Set permissive = 0 to enforce the policy.
#-----------------------------------------------------------------------
FAPOLICYD_CONF="/etc/fapolicyd/fapolicyd.conf"

if [[ -f "${FAPOLICYD_CONF}" ]]; then
    LOG "Ensuring fapolicyd is in enforcing mode (permissive = 0)..."
    if grep -Eq '^\s*permissive\s*=' "${FAPOLICYD_CONF}"; then
        sed -ri 's/^\s*permissive\s*=.*/permissive = 0/' "${FAPOLICYD_CONF}"
    else
        echo "permissive = 0" >> "${FAPOLICYD_CONF}"
    fi
else
    LOG "WARNING: ${FAPOLICYD_CONF} not found; creating minimal config."
    mkdir -p /etc/fapolicyd
    cat > "${FAPOLICYD_CONF}" <<'EOF'
permissive = 0
nice_val = 14
q_size = 800
uid = fapolicyd
gid = fapolicyd
do_stat_report = 1
detailed_report = 1
db_max_size = 40
subj_cache_size = 1549
obj_cache_size = 8191
watch_fs = ext2,ext3,ext4,tmpfs,xfs,vfat
trust = rpmdb,file
integrity = none
syslog_format = rule,dec,perm,auid,pid,exe,:,path,ftype,trust
EOF
fi

#-----------------------------------------------------------------------
# 3. Configure the deny-all, permit-by-exception rule set.
#    On RHEL 8, rules live in /etc/fapolicyd/rules.d/ (newer) or
#    /etc/fapolicyd/fapolicyd.rules (older). We handle both.
#-----------------------------------------------------------------------
RULES_DIR="/etc/fapolicyd/rules.d"
LEGACY_RULES="/etc/fapolicyd/fapolicyd.rules"

# The final catch-all deny rule that enforces "deny by default".
DENY_ALL_RULE="deny_audit perm=any all : all"

if [[ -d "${RULES_DIR}" ]]; then
    LOG "Using rules.d directory-based configuration."

    # Ensure default distributed rules exist (permit trusted / known).
    # If the directory is empty, populate with vendor defaults if available.
    if ! ls "${RULES_DIR}"/*.rules >/dev/null 2>&1; then
        if [[ -f /usr/share/fapolicyd/sample-rules/README-rules ]]; then
            LOG "Populating rules.d from sample rules..."
            cp -n /usr/share/fapolicyd/sample-rules/*.rules "${RULES_DIR}/" 2>/dev/null || true
        fi
    fi

    # Create the final deny-all rule with a high-numbered filename
    # so it is evaluated last (permit-by-exception).
    DENY_FILE="${RULES_DIR}/99-deny-all.rules"
    if [[ ! -f "${DENY_FILE}" ]] || ! grep -Fxq "${DENY_ALL_RULE}" "${DENY_FILE}"; then
        LOG "Installing deny-all catch-all rule at ${DENY_FILE}..."
        echo "${DENY_ALL_RULE}" > "${DENY_FILE}"
        chmod 0644 "${DENY_FILE}"
    else
        LOG "Deny-all catch-all rule already present."
    fi

    # Compile the rules into the working rule file used by the daemon.
    if command -v fagenrules >/dev/null 2>&1; then
        LOG "Regenerating compiled rules with fagenrules..."
        fagenrules --load || fagenrules || true
    fi

else
    LOG "Using legacy single-file rule configuration."
    touch "${LEGACY_RULES}"

    # Ensure the deny-all rule is the last line in the file.
    # Remove any existing occurrence first, then append.
    if grep -Fxq "${DENY_ALL_RULE}" "${LEGACY_RULES}"; then
        # Ensure it is the last rule by removing and re-adding.
        grep -Fxv "${DENY_ALL_RULE}" "${LEGACY_RULES}" > "${LEGACY_RULES}.tmp" || true
        mv "${LEGACY_RULES}.tmp" "${LEGACY_RULES}"
    fi
    LOG "Appending deny-all catch-all rule to ${LEGACY_RULES}..."
    echo "${DENY_ALL_RULE}" >> "${LEGACY_RULES}"
    chmod 0644 "${LEGACY_RULES}"
fi

#-----------------------------------------------------------------------
# 4. Update the trust database so all installed (vetted) software
#    from the RPM database is whitelisted (permit-by-exception).
#-----------------------------------------------------------------------
if command -v fapolicyd-cli >/dev/null 2>&1; then
    LOG "Updating fapolicyd trust database..."
    fapolicyd-cli --update || true
fi

#-----------------------------------------------------------------------
# 5. Enable and (re)start the service so the policy persists across reboots.
#-----------------------------------------------------------------------
LOG "Enabling fapolicyd service to persist across reboots..."
systemctl enable fapolicyd >/dev/null 2>&1 || true

LOG "Restarting fapolicyd service to apply policy..."
systemctl restart fapolicyd

# Give the daemon a moment to initialize.
sleep 2

#-----------------------------------------------------------------------
# 6. Verify the service is active and enabled.
#-----------------------------------------------------------------------
if systemctl is-enabled fapolicyd >/dev/null 2>&1; then
    LOG "fapolicyd is enabled (will start on boot)."
else
    LOG "WARNING: fapolicyd is not enabled."
fi

if systemctl is-active fapolicyd >/d
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

**Prompt:** Ensure that the 'mailx' package is installed and available on a RHEL 8 system, facilitating the sending of emails for important system notifications and alerts. Write an idempotent bash remediation script that installs this package if it is not already present, ensuring persistence across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation script: Ensure the 'mailx' package is installed on RHEL 8
# This script is idempotent: it only installs the package if it is missing.
#

set -o errexit
set -o nounset
set -o pipefail

PACKAGE="mailx"

# Ensure the script is run with root privileges
if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

# Determine the available package manager (dnf preferred on RHEL 8)
if command -v dnf >/dev/null 2>&1; then
    PKG_MGR="dnf"
elif command -v yum >/dev/null 2>&1; then
    PKG_MGR="yum"
else
    echo "ERROR: Neither dnf nor yum package managers found." >&2
    exit 1
fi

# Check if the package is already installed (idempotency check)
if rpm -q "${PACKAGE}" >/dev/null 2>&1; then
    echo "Package '${PACKAGE}' is already installed. No action required."
    exit 0
fi

echo "Package '${PACKAGE}' is not installed. Installing now using ${PKG_MGR}..."

# Install the package; RPM-installed packages persist across reboots by design
if "${PKG_MGR}" install -y "${PACKAGE}"; then
    echo "Package '${PACKAGE}' installed successfully."
else
    echo "ERROR: Failed to install package '${PACKAGE}'." >&2
    exit 1
fi

# Verify installation succeeded
if rpm -q "${PACKAGE}" >/dev/null 2>&1; then
    echo "Verification passed: '${PACKAGE}' is present on the system."
    exit 0
else
    echo "ERROR: Verification failed: '${PACKAGE}' is still not installed." >&2
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

**Prompt:** Ensure that the Postfix mail server is installed on a RHEL 8 system to facilitate the ability to send emails, which can be used to notify administrators about system events or issues. Write an idempotent bash remediation script to verify that the Postfix package is installed, and install it if it is not already present, ensuring the capability is available and persists through system reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Idempotent remediation script to ensure Postfix is installed and enabled
# on a RHEL 8 system so the host can send mail (e.g. admin notifications).
#

set -o pipefail

PACKAGE="postfix"
SERVICE="postfix"

# Must run as root to install packages and manage services.
if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

# Determine which package manager is available.
if command -v dnf >/dev/null 2>&1; then
    PKG_MGR="dnf"
elif command -v yum >/dev/null 2>&1; then
    PKG_MGR="yum"
else
    echo "ERROR: Neither dnf nor yum is available on this system." >&2
    exit 1
fi

# 1. Ensure the Postfix package is installed.
if rpm -q "${PACKAGE}" >/dev/null 2>&1; then
    echo "Postfix package is already installed. No action needed."
else
    echo "Postfix package is not installed. Installing now..."
    if ! "${PKG_MGR}" install -y "${PACKAGE}"; then
        echo "ERROR: Failed to install ${PACKAGE}." >&2
        exit 1
    fi
    echo "Postfix package installed successfully."
fi

# 2. Ensure the Postfix service is enabled so it persists across reboots.
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-enabled "${SERVICE}" >/dev/null 2>&1; then
        echo "Postfix service is already enabled."
    else
        echo "Enabling Postfix service to persist through reboots..."
        if ! systemctl enable "${SERVICE}" >/dev/null 2>&1; then
            echo "ERROR: Failed to enable ${SERVICE} service." >&2
            exit 1
        fi
        echo "Postfix service enabled."
    fi

    # 3. Ensure the Postfix service is currently running.
    if systemctl is-active "${SERVICE}" >/dev/null 2>&1; then
        echo "Postfix service is already running."
    else
        echo "Starting Postfix service..."
        if ! systemctl start "${SERVICE}" >/dev/null 2>&1; then
            echo "ERROR: Failed to start ${SERVICE} service." >&2
            exit 1
        fi
        echo "Postfix service started."
    fi
else
    echo "WARNING: systemctl not found; unable to manage the Postfix service." >&2
fi

echo "Remediation complete: Postfix is installed, enabled, and running."
exit 0
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

**Prompt:** On a RHEL 8 system, the chrony time synchronization service should be configured to operate strictly in a client mode, preventing it from opening any network ports for server operations. This minimizes attack vectors by ensuring the daemon does not inadvertently act as a time server. Write an idempotent bash remediation script that configures chrony to not act as a server, and ensures this configuration remains effective across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Configure chrony to operate strictly in client mode.
# Ensures the chrony daemon does not open network ports for server operations
# by setting "port 0" in the chrony configuration.
#

set -o pipefail

# Directive we want to enforce
DIRECTIVE_KEY="port"
DIRECTIVE_VALUE="0"
DIRECTIVE_LINE="port 0"

# Candidate configuration files/locations
MAIN_CONF="/etc/chrony.conf"
DROPIN_DIR="/etc/chrony.d"

# Determine the target configuration file.
# Prefer the main config if it exists; otherwise fall back sensibly.
if [ -f "$MAIN_CONF" ]; then
    TARGET_CONF="$MAIN_CONF"
elif [ -d "$DROPIN_DIR" ]; then
    TARGET_CONF="${DROPIN_DIR}/99-client-only.conf"
else
    TARGET_CONF="$MAIN_CONF"
fi

# Helper: does a given file already contain an active "port 0" directive?
has_active_port_zero() {
    local file="$1"
    [ -f "$file" ] || return 1
    grep -Eq "^[[:space:]]*${DIRECTIVE_KEY}[[:space:]]+${DIRECTIVE_VALUE}([[:space:]]|$)" "$file"
}

# Helper: does a given file contain any active "port" directive (non-zero)?
has_any_active_port() {
    local file="$1"
    [ -f "$file" ] || return 1
    grep -Eq "^[[:space:]]*${DIRECTIVE_KEY}[[:space:]]+" "$file"
}

CHANGED=0

# 1) Check every relevant config file for a conflicting active "port" directive
#    and comment those lines out (unless it's already "port 0").
scan_files=()
[ -f "$MAIN_CONF" ] && scan_files+=("$MAIN_CONF")
if [ -d "$DROPIN_DIR" ]; then
    while IFS= read -r -d '' f; do
        scan_files+=("$f")
    done < <(find "$DROPIN_DIR" -maxdepth 1 -type f -name '*.conf' -print0 2>/dev/null)
fi

ALREADY_SET=0
for f in "${scan_files[@]}"; do
    if has_active_port_zero "$f"; then
        ALREADY_SET=1
        continue
    fi
    if has_any_active_port "$f"; then
        # Comment out any active non-zero port directives to avoid conflict
        tmp="$(mktemp)"
        sed -E "s/^([[:space:]]*)(${DIRECTIVE_KEY}[[:space:]]+.*)$/\1# \2  # commented by client-only remediation/" "$f" > "$tmp"
        if ! cmp -s "$f" "$tmp"; then
            cat "$tmp" > "$f"
            CHANGED=1
        fi
        rm -f "$tmp"
    fi
done

# 2) Ensure the "port 0" directive is present in the target config.
if [ "$ALREADY_SET" -eq 0 ] && ! has_active_port_zero "$TARGET_CONF"; then
    # Create the drop-in directory if we are targeting it
    case "$TARGET_CONF" in
        "$DROPIN_DIR"/*)
            mkdir -p "$DROPIN_DIR"
            ;;
    esac
    printf '\n# Restrict chrony to client-only mode (no server ports)\n%s\n' "$DIRECTIVE_LINE" >> "$TARGET_CONF"
    CHANGED=1
fi

# 3) Restart chrony so the change takes effect immediately (persists across reboots
#    since it is written to configuration).
if [ "$CHANGED" -eq 1 ]; then
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-enabled chronyd >/dev/null 2>&1 || systemctl is-active chronyd >/dev/null 2>&1; then
            systemctl restart chronyd 2>/dev/null || true
        fi
    fi
    echo "chrony configured for client-only mode (port 0)."
else
    echo "chrony already configured for client-only mode; no changes made."
fi

exit 0
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

**Prompt:** On a RHEL 8 system, ensure that the chrony daemon is not exposed to the network for management operations by disabling its ability to listen for management connections. Write an idempotent bash remediation script that configures the chrony service to not listen on any network port for management, making the change persist across service restarts.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

CHRONY_CONF="/etc/chrony.conf"

if [[ ! -f "$CHRONY_CONF" ]]; then
    echo "Error: $CHRONY_CONF not found." >&2
    exit 1
fi

# Ensure the file ends with a newline so appends are clean
if [[ -n "$(tail -c1 "$CHRONY_CONF")" ]]; then
    echo "" >> "$CHRONY_CONF"
fi

# Remove any existing (possibly incorrect) cmdport directives
sed -i '/^[[:space:]]*cmdport[[:space:]]/d;/^[[:space:]]*cmdport$/d' "$CHRONY_CONF"

# Add the correct directive to disable management port
if ! grep -Eq '^[[:space:]]*cmdport[[:space:]]+0[[:space:]]*$' "$CHRONY_CONF"; then
    echo "cmdport 0" >> "$CHRONY_CONF"
fi

# Restart chrony to apply changes if the service exists and is active
if systemctl list-unit-files 2>/dev/null | grep -q '^chronyd\.service'; then
    if systemctl is-active --quiet chronyd; then
        systemctl restart chronyd
    fi
fi

echo "chrony management port disabled (cmdport 0) in $CHRONY_CONF"
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

**Prompt:** On a RHEL 8 system, ensure the time synchronization service periodically polls time servers to maintain accurate system time, which is crucial for event correlation and forensic analyses. Configure the time service to use a maxpoll interval of 10, ensuring this setting persists across reboots. The configuration must apply to all relevant server, pool, and peer entries in the time service configuration files. Write an idempotent bash remediation script that enforces this maxpoll setting for time synchronization services used on the system.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Enforce maxpoll=10 on all server/pool/peer entries in chrony (or ntp)
# time synchronization configuration files. Idempotent remediation.
#

set -u

MAXPOLL_VALUE=10

# Candidate configuration files/directories to search
CONFIG_CANDIDATES=(
    "/etc/chrony.conf"
    "/etc/chrony/chrony.conf"
    "/etc/ntp.conf"
)

CONFIG_DIRS=(
    "/etc/chrony.d"
    "/etc/chrony/conf.d"
    "/etc/chrony/sources.d"
    "/etc/ntp.d"
)

# Build the list of files to process
declare -a FILES=()

for f in "${CONFIG_CANDIDATES[@]}"; do
    [ -f "$f" ] && FILES+=("$f")
done

for d in "${CONFIG_DIRS[@]}"; do
    if [ -d "$d" ]; then
        while IFS= read -r -d '' file; do
            FILES+=("$file")
        done < <(find "$d" -maxdepth 1 -type f \( -name '*.conf' -o -name '*.sources' \) -print0 2>/dev/null)
    fi
done

if [ "${#FILES[@]}" -eq 0 ]; then
    echo "No chrony/ntp configuration files found. Nothing to remediate."
    exit 0
fi

remediate_file() {
    local file="$1"
    local tmp
    tmp="$(mktemp)" || return 1
    local changed=0

    while IFS= read -r line || [ -n "$line" ]; do
        # Determine the first non-whitespace token
        local trimmed keyword
        trimmed="$(printf '%s' "$line" | sed -e 's/^[[:space:]]*//')"
        keyword="$(printf '%s' "$trimmed" | awk '{print $1}')"

        case "$keyword" in
            server|pool|peer)
                if printf '%s' "$line" | grep -Eq '(^|[[:space:]])maxpoll([[:space:]]|$)'; then
                    # Replace the existing maxpoll value
                    newline="$(printf '%s' "$line" | sed -E "s/([[:space:]])maxpoll[[:space:]]+[0-9]+/\1maxpoll ${MAXPOLL_VALUE}/g")"
                else
                    # Append maxpoll setting, preserving trailing content
                    newline="$(printf '%s' "$line" | sed -E "s/[[:space:]]*$//") maxpoll ${MAXPOLL_VALUE}"
                fi
                if [ "$newline" != "$line" ]; then
                    changed=1
                fi
                printf '%s\n' "$newline" >> "$tmp"
                ;;
            *)
                printf '%s\n' "$line" >> "$tmp"
                ;;
        esac
    done < "$file"

    if [ "$changed" -eq 1 ]; then
        # Preserve permissions/ownership
        local perms owner
        perms="$(stat -c '%a' "$file" 2>/dev/null)"
        owner="$(stat -c '%U:%G' "$file" 2>/dev/null)"
        cat "$tmp" > "$file"
        [ -n "$perms" ] && chmod "$perms" "$file"
        [ -n "$owner" ] && chown "$owner" "$file"
        echo "Updated maxpoll settings in: $file"
    else
        echo "No changes needed in: $file"
    fi

    rm -f "$tmp"
    return "$changed"
}

any_change=0
for file in "${FILES[@]}"; do
    remediate_file "$file"
    if [ "$?" -eq 1 ]; then
        any_change=1
    fi
done

# Restart the appropriate time service if a change was made
if [ "$any_change" -eq 1 ]; then
    if systemctl list-unit-files 2>/dev/null | grep -q '^chronyd\.service'; then
        if systemctl is-active --quiet chronyd; then
            systemctl restart chronyd && echo "Restarted chronyd."
        fi
    elif systemctl list-unit-files 2>/dev/null | grep -q '^ntpd\.service'; then
        if systemctl is-active --quiet ntpd; then
            systemctl restart ntpd && echo "Restarted ntpd."
        fi
    fi
fi

echo "maxpoll ${MAXPOLL_VALUE} enforcement complete."
exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel && { ( rpm --quiet -q chrony || rpm --quiet -q ntp ); }; then

var_time_service_set_maxpoll='
```


---

## RHEL-08-010200 — `sshd_set_keepalive`

**Prompt:** On a RHEL 8 system running SSH server, ensure that idle SSH sessions are disconnected immediately upon reaching the timeout interval defined by the client alive interval. This restricts the SSH server to send 0 keepalive messages before timing out a session, enforcing strict adherence to timeout policies. Write an idempotent bash remediation script to set the SSH server so that the session times out exactly when the client alive interval is reached without sending additional keepalive messages.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
PARAM="ClientAliveCountMax"
VALUE="0"

# Ensure the config file exists
if [[ ! -f "$SSHD_CONFIG" ]]; then
    echo "Error: $SSHD_CONFIG does not exist." >&2
    exit 1
fi

# Backup the original file once
if [[ ! -f "${SSHD_CONFIG}.bak" ]]; then
    cp -p "$SSHD_CONFIG" "${SSHD_CONFIG}.bak"
fi

# Check if a correct, active (uncommented) directive already exists
if grep -Eiq "^\s*${PARAM}\s+${VALUE}\s*$" "$SSHD_CONFIG"; then
    echo "${PARAM} is already set to ${VALUE}. No changes needed."
else
    # Remove any existing (commented or uncommented) ClientAliveCountMax lines
    sed -ri "/^\s*#?\s*${PARAM}\b/d" "$SSHD_CONFIG"

    # Append the correct directive
    echo "${PARAM} ${VALUE}" >> "$SSHD_CONFIG"
    echo "Set ${PARAM} to ${VALUE} in ${SSHD_CONFIG}."
fi

# Validate the sshd configuration
if sshd -t; then
    echo "sshd configuration is valid."
    # Restart/reload the SSH service to apply changes
    if systemctl is-active --quiet sshd; then
        systemctl reload sshd || systemctl restart sshd
        echo "sshd service reloaded."
    else
        echo "sshd service is not active; skipping reload."
    fi
else
    echo "Error: sshd configuration test failed. Restoring backup." >&2
    cp -p "${SSHD_CONFIG}.bak" "$SSHD_CONFIG"
    exit 1
fi
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

var_sshd_set_keepalive='
```


---

## RHEL-08-010201 — `sshd_set_idle_timeout`

**Prompt:** On a RHEL 8 system, configure SSH so that any SSH client will be logged out if it becomes unresponsive for more than 10 minutes. This reduces the risk of unauthorized session hijacking. Write an idempotent bash remediation script to ensure that this network responsiveness timeout is set appropriately, making sure it is enforced for new connections and persists through server restarts.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"

# Desired values: ClientAliveInterval 600, ClientAliveCountMax 0
# 600 seconds = 10 minutes of unresponsiveness before logout.
CAI_KEY="ClientAliveInterval"
CAI_VAL="600"
CACM_KEY="ClientAliveCountMax"
CACM_VAL="0"

# Backup once
if [[ ! -f "${SSHD_CONFIG}.bak" ]]; then
    cp -p "${SSHD_CONFIG}" "${SSHD_CONFIG}.bak"
fi

set_sshd_option() {
    local key="$1"
    local val="$2"
    local file="$3"

    # Match the directive whether commented or active, at start of line
    if grep -qiE "^[[:space:]]*#?[[:space:]]*${key}[[:space:]]+" "${file}"; then
        # Replace the first occurrence, remove any others to keep it clean
        sed -i -E "0,/^[[:space:]]*#?[[:space:]]*${key}[[:space:]]+.*/s//${key} ${val}/I" "${file}"
        # Comment out any additional duplicate active lines
        awk -v key="${key}" -v val="${val}" '
            BEGIN { IGNORECASE=1; seen=0 }
            {
                line=$0
                if (line ~ "^[[:space:]]*"key"[[:space:]]+") {
                    if (seen==0) { print key" "val; seen=1 }
                    else { print "# "line }
                } else {
                    print line
                }
            }
        ' "${file}" > "${file}.tmp" && mv "${file}.tmp" "${file}"
    else
        printf '%s %s\n' "${key}" "${val}" >> "${file}"
    fi
}

set_sshd_option "${CAI_KEY}" "${CAI_VAL}" "${SSHD_CONFIG}"
set_sshd_option "${CACM_KEY}" "${CACM_VAL}" "${SSHD_CONFIG}"

# Restore permissions/context
chmod 0600 "${SSHD_CONFIG}"
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F "${SSHD_CONFIG}" || true
fi

# Validate configuration
if command -v sshd >/dev/null 2>&1; then
    sshd -t
fi

# Restart/reload sshd so new connections use the settings and it persists
SERVICE=""
if systemctl list-unit-files 2>/dev/null | grep -q '^sshd\.service'; then
    SERVICE="sshd"
elif systemctl list-unit-files 2>/dev/null | grep -q '^ssh\.service'; then
    SERVICE="ssh"
fi

if [[ -n "${SERVICE}" ]]; then
    systemctl enable "${SERVICE}" >/dev/null 2>&1 || true
    if systemctl is-active --quiet "${SERVICE}"; then
        systemctl reload "${SERVICE}" 2>/dev/null || systemctl restart "${SERVICE}"
    else
        systemctl restart "${SERVICE}"
    fi
fi

echo "SSH client alive timeout configured: ${CAI_KEY} ${CAI_VAL}, ${CACM_KEY} ${CACM_VAL}"
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

sshd_idle_timeout_value='
```


---

## RHEL-08-020330 — `sshd_disable_empty_passwords`

**Prompt:** On a RHEL 8 system, ensure that the SSH server is configured to disallow login using accounts with empty passwords, which improves security by requiring valid credentials for remote access. Write an idempotent bash remediation script that explicitly sets this configuration, ensuring that the restriction is enforced for all SSH sessions and remains effective across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
PARAM="PermitEmptyPasswords"
VALUE="no"

# Ensure the sshd_config file exists
if [[ ! -f "$SSHD_CONFIG" ]]; then
    echo "Error: $SSHD_CONFIG not found." >&2
    exit 1
fi

# Remove any existing (commented or uncommented) PermitEmptyPasswords lines
# that do not match the desired setting, then ensure the correct one is present.
if grep -qiE '^\s*#?\s*PermitEmptyPasswords\b' "$SSHD_CONFIG"; then
    # Replace the first occurrence with the correct value and comment out others
    sed -i -E "s|^\s*#?\s*PermitEmptyPasswords\b.*|${PARAM} ${VALUE}|I" "$SSHD_CONFIG"

    # Ensure only one active directive remains (deduplicate)
    # Keep the first, comment out subsequent duplicates
    awk -v param="$PARAM" '
        BEGIN { seen = 0 }
        {
            if ($0 ~ "^[[:space:]]*"param"[[:space:]]") {
                if (seen == 0) {
                    print
                    seen = 1
                } else {
                    print "# " $0
                }
            } else {
                print
            }
        }
    ' "$SSHD_CONFIG" > "${SSHD_CONFIG}.tmp"
    mv "${SSHD_CONFIG}.tmp" "$SSHD_CONFIG"
else
    # No directive present; append it
    printf '%s %s\n' "$PARAM" "$VALUE" >> "$SSHD_CONFIG"
fi

# Set secure permissions on sshd_config
chown root:root "$SSHD_CONFIG"
chmod 0600 "$SSHD_CONFIG"

# Validate configuration before applying
if command -v sshd >/dev/null 2>&1; then
    if ! sshd -t; then
        echo "Error: sshd configuration test failed." >&2
        exit 1
    fi
fi

# Reload/restart sshd to apply changes if the service is active
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet sshd; then
        systemctl reload sshd 2>/dev/null || systemctl restart sshd
    elif systemctl is-enabled --quiet sshd 2>/dev/null; then
        systemctl restart sshd
    fi
fi

echo "SSH configuration enforced: ${PARAM} ${VALUE}"
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

**Prompt:** On a RHEL 8 system, reduce the attack surface of the SSH server by ensuring that GSSAPI authentication is disabled, as it might expose the system to unnecessary risks if not required. Write an idempotent bash remediation script that explicitly disables GSSAPI authentication in the SSH server's configuration, ensuring compliance persists across SSH server restarts.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Disable SSH GSSAPI Authentication on RHEL 8
# Ensures "GSSAPIAuthentication no" is set in the effective sshd configuration.
#
set -euo pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
DROPIN_DIR="/etc/ssh/sshd_config.d"
PARAM="GSSAPIAuthentication"
VALUE="no"

# Regex helpers (case-insensitive parameter match, ignoring leading whitespace/comments)
GREP_PATTERN='^[[:space:]]*'"${PARAM}"'[[:space:]]'
SET_LINE="${PARAM} ${VALUE}"

remediate_file() {
    local file="$1"
    # Only act on regular, readable files
    [ -f "$file" ] || return 0

    if grep -qiE "${GREP_PATTERN}" "$file"; then
        # Replace any existing (commented or uncommented) directive lines with the desired value.
        # Handles leading whitespace and comment markers.
        sed -ri "s/^[[:space:]]*#?[[:space:]]*${PARAM}[[:space:]].*/${SET_LINE}/I" "$file"
    fi
}

# Ensure the main config file exists
if [ ! -f "$SSHD_CONFIG" ]; then
    echo "ERROR: ${SSHD_CONFIG} not found." >&2
    exit 1
fi

# Fix any occurrences in drop-in files that could override the main config
if [ -d "$DROPIN_DIR" ]; then
    while IFS= read -r -d '' dropin; do
        remediate_file "$dropin"
    done < <(find "$DROPIN_DIR" -maxdepth 1 -type f -name '*.conf' -print0)
fi

# Remediate the main config file
if grep -qiE "${GREP_PATTERN}" "$SSHD_CONFIG"; then
    remediate_file "$SSHD_CONFIG"
else
    # Directive not present at all: append the correct setting
    printf '\n%s\n' "${SET_LINE}" >> "$SSHD_CONFIG"
fi

# Verify the effective setting via sshd if available; fall back to grep verification
verify_ok=0
if command -v sshd >/dev/null 2>&1; then
    if sshd -T 2>/dev/null | grep -qi "^gssapiauthentication ${VALUE}$"; then
        verify_ok=1
    fi
fi

if [ "$verify_ok" -ne 1 ]; then
    if grep -qiE '^[[:space:]]*'"${PARAM}"'[[:space:]]+'"${VALUE}"'[[:space:]]*$' "$SSHD_CONFIG"; then
        verify_ok=1
    fi
fi

if [ "$verify_ok" -ne 1 ]; then
    echo "ERROR: Failed to verify ${PARAM} ${VALUE}." >&2
    exit 1
fi

# Reload the SSH server so the change persists across restarts and takes effect now
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet sshd 2>/dev/null; then
        systemctl reload sshd 2>/dev/null || systemctl restart sshd 2>/dev/null || true
    elif systemctl is-active --quiet ssh 2>/dev/null; then
        systemctl reload ssh 2>/dev/null || systemctl restart ssh 2>/dev/null || true
    fi
fi

echo "SUCCESS: ${PARAM} is set to ${VALUE}."
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

**Prompt:** On a RHEL 8 system, ensure that the SSH server does not permit Kerberos authentication, which might inadvertently allow SSH to use unnecessary remote authentication methods if enabled elsewhere. Write an idempotent bash remediation script to explicitly disable Kerberos authentication in the SSH server's configuration, ensuring the change takes effect for new connections.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
DIRECTIVE="KerberosAuthentication"
VALUE="no"

if [[ ! -f "$SSHD_CONFIG" ]]; then
    echo "Error: $SSHD_CONFIG not found." >&2
    exit 1
fi

# Backup once per run if a change is needed
NEEDS_CHANGE=0

# Check if a correct, active (non-commented) directive already exists
if grep -Eq "^[[:space:]]*${DIRECTIVE}[[:space:]]+${VALUE}[[:space:]]*$" "$SSHD_CONFIG"; then
    # Ensure there are no other conflicting active directives
    ACTIVE_COUNT=$(grep -Eic "^[[:space:]]*${DIRECTIVE}[[:space:]]+" "$SSHD_CONFIG" || true)
    CORRECT_COUNT=$(grep -Eic "^[[:space:]]*${DIRECTIVE}[[:space:]]+${VALUE}[[:space:]]*$" "$SSHD_CONFIG" || true)
    if [[ "$ACTIVE_COUNT" -eq 1 && "$CORRECT_COUNT" -eq 1 ]]; then
        echo "Directive already correctly set. No changes needed."
    else
        NEEDS_CHANGE=1
    fi
else
    NEEDS_CHANGE=1
fi

if [[ "$NEEDS_CHANGE" -eq 1 ]]; then
    cp -a "$SSHD_CONFIG" "${SSHD_CONFIG}.bak.$(date +%Y%m%d%H%M%S)"

    # Comment out any existing active directives to avoid conflicts
    sed -ri "s/^[[:space:]]*(${DIRECTIVE}[[:space:]]+.*)$/# \1/I" "$SSHD_CONFIG"

    # Append the desired directive
    printf '%s %s\n' "$DIRECTIVE" "$VALUE" >> "$SSHD_CONFIG"

    echo "Set '${DIRECTIVE} ${VALUE}' in $SSHD_CONFIG."
fi

# Validate configuration syntax before reloading
if command -v sshd >/dev/null 2>&1; then
    sshd -t
fi

# Reload the SSH service so the change applies to new connections
if [[ "$NEEDS_CHANGE" -eq 1 ]]; then
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active --quiet sshd; then
            systemctl reload sshd || systemctl restart sshd
            echo "Reloaded sshd service."
        else
            echo "sshd service not active; configuration will apply on next start."
        fi
    fi
fi

echo "Remediation complete."
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

**Prompt:** On a RHEL 8 system, the SSH server currently allows direct remote login as the root user, potentially exposing the system to unauthorized remote access attempts. To enhance security and enforce individual accountability, configure the SSH server to disallow all remote root logins. Write an idempotent bash remediation script to ensure this setting is enforced, persisting across SSH server restarts.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
PARAM="PermitRootLogin"
VALUE="no"

# Ensure the config file exists
if [[ ! -f "$SSHD_CONFIG" ]]; then
    echo "Error: $SSHD_CONFIG does not exist." >&2
    exit 1
fi

# Backup the original config once
if [[ ! -f "${SSHD_CONFIG}.bak" ]]; then
    cp -p "$SSHD_CONFIG" "${SSHD_CONFIG}.bak"
fi

# Check if a correct, active (uncommented) setting already exists
if grep -Eiq "^\s*${PARAM}\s+${VALUE}\s*$" "$SSHD_CONFIG"; then
    echo "${PARAM} is already set to ${VALUE}. No changes needed."
else
    # Remove any existing (commented or uncommented) PermitRootLogin lines
    sed -i -E "/^\s*#?\s*${PARAM}\s+.*/d" "$SSHD_CONFIG"

    # Append the enforced setting
    echo "${PARAM} ${VALUE}" >> "$SSHD_CONFIG"
    echo "${PARAM} set to ${VALUE}."
fi

# Validate the sshd configuration before restarting
if command -v sshd >/dev/null 2>&1; then
    if ! sshd -t; then
        echo "Error: sshd configuration test failed. Restoring backup." >&2
        cp -p "${SSHD_CONFIG}.bak" "$SSHD_CONFIG"
        exit 1
    fi
fi

# Restart the SSH service to apply changes
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet sshd; then
        systemctl restart sshd
        echo "sshd service restarted."
    else
        echo "sshd service not active; configuration will apply on next start."
    fi
else
    service sshd restart || true
fi

echo "Remediation complete: remote root login is disabled."
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

**Prompt:** On a RHEL 8 system, configure the SSH server to ignore the user's known hosts file to ensure SSH connections require authentication as configured, providing additional security against misconfigurations that might otherwise allow unintended access. Write an idempotent bash remediation script that configures the SSH server to ignore the user's known hosts file, ensuring the change is effective for all future SSH connections and persistent across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
PARAM="IgnoreUserKnownHosts"
VALUE="yes"

# Ensure the sshd_config file exists
if [[ ! -f "$SSHD_CONFIG" ]]; then
    echo "Error: $SSHD_CONFIG does not exist." >&2
    exit 1
fi

# Backup the original file once
if [[ ! -f "${SSHD_CONFIG}.bak" ]]; then
    cp -p "$SSHD_CONFIG" "${SSHD_CONFIG}.bak"
fi

# Remove any existing (commented or uncommented) directive lines for the parameter
# that are not already set correctly, then add the correct one.
if grep -qiE "^\s*${PARAM}\b" "$SSHD_CONFIG"; then
    # Replace the first active occurrence, comment out any others
    sed -i -E "s|^\s*${PARAM}\b.*|${PARAM} ${VALUE}|I" "$SSHD_CONFIG"
    # Deduplicate: keep only first matching line, comment out subsequent duplicates
    awk -v param="$PARAM" '
        BEGIN { IGNORECASE=1; seen=0 }
        {
            line=$0
            if (line ~ "^[[:space:]]*"param"[[:space:]]") {
                if (seen==0) { print line; seen=1 }
                else { print "# duplicate removed: " line }
            } else {
                print line
            }
        }
    ' "$SSHD_CONFIG" > "${SSHD_CONFIG}.tmp"
    mv "${SSHD_CONFIG}.tmp" "$SSHD_CONFIG"
else
    printf '\n%s %s\n' "$PARAM" "$VALUE" >> "$SSHD_CONFIG"
fi

# Set proper permissions
chmod 0600 "$SSHD_CONFIG"
chown root:root "$SSHD_CONFIG"

# Validate configuration
if command -v sshd >/dev/null 2>&1; then
    if ! sshd -t; then
        echo "Error: sshd configuration test failed. Restoring backup." >&2
        cp -p "${SSHD_CONFIG}.bak" "$SSHD_CONFIG"
        exit 1
    fi
fi

# Reload/restart sshd to apply changes
if systemctl is-active --quiet sshd 2>/dev/null || systemctl is-enabled --quiet sshd 2>/dev/null; then
    systemctl restart sshd
elif systemctl is-active --quiet ssh 2>/dev/null || systemctl is-enabled --quiet ssh 2>/dev/null; then
    systemctl restart ssh
fi

echo "SSH server configured with '${PARAM} ${VALUE}'."
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

**Prompt:** On a RHEL 8 system, ensure that the SSH server does not allow X11 forwarding unless explicitly required, to reduce the risk of compromising remote X11 servers through the SSH connection. Write an idempotent bash remediation script that disables SSH X11 forwarding for new sessions by configuring the server appropriately, ensuring the setting persists across reboots if applicable.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Disable SSH X11 Forwarding on RHEL 8
# Ensures 'X11Forwarding no' is set in the SSH server configuration.
#

set -euo pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_CONFIG_DIR="/etc/ssh/sshd_config.d"
DIRECTIVE="X11Forwarding"
VALUE="no"

# Ensure main config file exists
if [[ ! -f "$SSHD_CONFIG" ]]; then
    echo "ERROR: $SSHD_CONFIG not found." >&2
    exit 1
fi

# Backup the main config once (timestamped)
backup_file="${SSHD_CONFIG}.bak.$(date +%Y%m%d%H%M%S)"
cp -p "$SSHD_CONFIG" "$backup_file"

# Function to normalize any existing (possibly commented or misconfigured) entries
# in a given file to the desired setting.
normalize_file() {
    local file="$1"
    [[ -f "$file" ]] || return 0

    # Remove any existing X11Forwarding lines (commented or not, any case, any leading whitespace)
    sed -ri "/^[[:space:]]*#?[[:space:]]*${DIRECTIVE}[[:space:]]+.*$/Id" "$file"
}

# Check for override files in sshd_config.d that might re-enable X11Forwarding.
# These files are included by the main config and can override settings.
if [[ -d "$SSHD_CONFIG_DIR" ]]; then
    shopt -s nullglob
    for f in "$SSHD_CONFIG_DIR"/*.conf; do
        if grep -Eiq "^[[:space:]]*${DIRECTIVE}[[:space:]]+" "$f"; then
            cp -p "$f" "${f}.bak.$(date +%Y%m%d%H%M%S)"
            normalize_file "$f"
        fi
    done
    shopt -u nullglob
fi

# Normalize and set the directive in the main config file.
normalize_file "$SSHD_CONFIG"

# Append the correct directive to the main config file.
echo "${DIRECTIVE} ${VALUE}" >> "$SSHD_CONFIG"

# Validate the SSH configuration before restarting.
if command -v sshd >/dev/null 2>&1; then
    if ! sshd -t; then
        echo "ERROR: sshd configuration test failed. Restoring backup." >&2
        cp -p "$backup_file" "$SSHD_CONFIG"
        exit 1
    fi
fi

# Reload/restart the SSH service so the change takes effect for new sessions.
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet sshd 2>/dev/null; then
        systemctl reload sshd || systemctl restart sshd
    elif systemctl is-active --quiet ssh 2>/dev/null; then
        systemctl reload ssh || systemctl restart ssh
    fi
fi

echo "SSH X11 forwarding has been disabled (${DIRECTIVE} ${VALUE})."
exit 0
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

**Prompt:** On a RHEL 8 system, SSH allows users to specify environment variables that may override intended access controls, posing a security risk. Ensure the SSH server configuration explicitly disallows the use of user-specified environment variables during session initiation. Write an idempotent bash remediation script that enforces this restriction in the SSH server configuration to prevent any such overrides for new sessions.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
PARAM="PermitUserEnvironment"
VALUE="no"

# Ensure the config file exists
if [[ ! -f "$SSHD_CONFIG" ]]; then
    echo "Error: $SSHD_CONFIG does not exist." >&2
    exit 1
fi

# Backup the original file once
if [[ ! -f "${SSHD_CONFIG}.bak" ]]; then
    cp -p "$SSHD_CONFIG" "${SSHD_CONFIG}.bak"
fi

# Remove any existing (commented or active) PermitUserEnvironment lines
# to avoid duplicates and ensure the correct value is enforced.
sed -ri "/^\s*#?\s*${PARAM}\b/d" "$SSHD_CONFIG"

# Append the enforced setting
echo "${PARAM} ${VALUE}" >> "$SSHD_CONFIG"

# Validate the sshd configuration syntax
if sshd -t 2>/dev/null; then
    echo "SSH configuration validated successfully."
else
    echo "Warning: sshd -t reported issues. Restoring backup." >&2
    cp -p "${SSHD_CONFIG}.bak" "$SSHD_CONFIG"
    exit 1
fi

# Reload/restart sshd to apply changes if service is active
if systemctl is-active --quiet sshd; then
    systemctl restart sshd
    echo "sshd service restarted."
elif systemctl is-active --quiet ssh; then
    systemctl restart ssh
    echo "ssh service restarted."
else
    echo "SSH service not active; configuration will apply on next start."
fi

echo "Enforced: ${PARAM} ${VALUE}"
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

**Prompt:** On a RHEL 8 system, ensure the SSH server enforces rigorous permission checks on user-specific SSH configuration files to prevent unauthorized logins due to improper file permissions. Write an idempotent bash remediation script to explicitly enable strict mode checking in the SSH configuration, ensuring the system verifies secure file permissions before accepting login requests.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
PARAM="StrictModes"
VALUE="yes"

# Ensure the config file exists
if [[ ! -f "$SSHD_CONFIG" ]]; then
    echo "Error: $SSHD_CONFIG does not exist." >&2
    exit 1
fi

# Back up the original config once
BACKUP="${SSHD_CONFIG}.bak.$(date +%Y%m%d%H%M%S)"

# Check for an active (uncommented) StrictModes directive
if grep -Eiq '^\s*StrictModes\s+' "$SSHD_CONFIG"; then
    # Extract current value (last matching active directive)
    current_value="$(grep -Ei '^\s*StrictModes\s+' "$SSHD_CONFIG" | tail -n1 | awk '{print $2}')"
    if [[ "${current_value,,}" == "${VALUE,,}" ]]; then
        echo "StrictModes already set to '$VALUE'. No changes needed."
    else
        cp -p "$SSHD_CONFIG" "$BACKUP"
        # Replace all active StrictModes directives with the desired value
        sed -ri "s|^\s*StrictModes\s+.*$|${PARAM} ${VALUE}|I" "$SSHD_CONFIG"
        echo "Updated StrictModes to '$VALUE'. Backup at $BACKUP."
    fi
else
    cp -p "$SSHD_CONFIG" "$BACKUP"
    # Check if there are commented occurrences to replace instead of appending duplicates
    if grep -Eiq '^\s*#\s*StrictModes\s+' "$SSHD_CONFIG"; then
        sed -ri "0,/^\s*#\s*StrictModes\s+.*$/s||${PARAM} ${VALUE}|I" "$SSHD_CONFIG"
        echo "Enabled StrictModes (replaced commented directive). Backup at $BACKUP."
    else
        printf '\n%s %s\n' "$PARAM" "$VALUE" >> "$SSHD_CONFIG"
        echo "Appended StrictModes '$VALUE' to $SSHD_CONFIG. Backup at $BACKUP."
    fi
fi

# Validate the sshd configuration syntax
if command -v sshd >/dev/null 2>&1; then
    if sshd -t; then
        echo "sshd configuration syntax is valid."
        # Reload/restart sshd to apply changes if the service is active
        if command -v systemctl >/dev/null 2>&1; then
            if systemctl is-active --quiet sshd; then
                systemctl reload sshd || systemctl restart sshd
                echo "sshd service reloaded."
            else
                echo "sshd service is not active; skipping reload."
            fi
        fi
    else
        echo "Error: sshd configuration test failed. Review $SSHD_CONFIG." >&2
        exit 1
    fi
else
    echo "Warning: sshd binary not found; skipping syntax validation and reload." >&2
fi
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

**Prompt:** On a RHEL 8 system, configure the SSH server to display a consistent warning message to users before they authenticate. This message should be sourced from the system-wide banner file, thereby promoting policy awareness and supporting potential legal measures against unauthorized access. Write an idempotent bash remediation script that ensures the SSH server always displays this pre-authentication warning banner, and that the setting persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure SSH server displays a pre-authentication warning banner
# sourced from the system-wide banner file (/etc/issue.net).
#
# This script is idempotent and ensures the setting persists across reboots.

set -euo pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
BANNER_FILE="/etc/issue.net"
DESIRED_VALUE="/etc/issue.net"

# --- Ensure the banner file exists with a sensible warning message ---
if [[ ! -f "${BANNER_FILE}" ]]; then
    cat > "${BANNER_FILE}" <<'EOF'
WARNING: Unauthorized access to this system is prohibited.
This system is for the use of authorized users only. Individuals using this
computer system without authority, or in excess of their authority, are
subject to having all of their activities on this system monitored and
recorded by system personnel. Anyone using this system expressly consents
to such monitoring and is advised that if such monitoring reveals possible
evidence of criminal activity, system personnel may provide the evidence
of such monitoring to law enforcement officials.
EOF
    chmod 0644 "${BANNER_FILE}"
    chown root:root "${BANNER_FILE}"
fi

# --- Ensure sshd_config exists ---
if [[ ! -f "${SSHD_CONFIG}" ]]; then
    echo "Error: ${SSHD_CONFIG} not found." >&2
    exit 1
fi

# --- Configure the Banner directive idempotently ---
# Match any active or commented Banner line (case-insensitive), and normalize it.
if grep -qiE '^\s*#?\s*Banner\b' "${SSHD_CONFIG}"; then
    # Replace all existing Banner lines with the correct directive.
    sed -ri "s|^\s*#?\s*[Bb]anner\b.*$|Banner ${DESIRED_VALUE}|" "${SSHD_CONFIG}"
    # Collapse potential duplicates: keep only the first Banner line.
    awk -v val="Banner ${DESIRED_VALUE}" '
        /^Banner / {
            if (!seen) { print val; seen=1 }
            next
        }
        { print }
    ' "${SSHD_CONFIG}" > "${SSHD_CONFIG}.tmp"
    mv "${SSHD_CONFIG}.tmp" "${SSHD_CONFIG}"
else
    # No Banner directive present; append it.
    printf '\nBanner %s\n' "${DESIRED_VALUE}" >> "${SSHD_CONFIG}"
fi

chmod 0600 "${SSHD_CONFIG}"
chown root:root "${SSHD_CONFIG}"

# --- Validate the sshd configuration before reloading ---
if command -v sshd >/dev/null 2>&1; then
    if ! sshd -t; then
        echo "Error: sshd configuration test failed. Not restarting service." >&2
        exit 1
    fi
fi

# --- Reload/restart the SSH service so the change takes effect ---
if command -v systemctl >/dev/null 2>&1; then
    if systemctl list-unit-files | grep -qE '^sshd\.service'; then
        systemctl enable sshd >/dev/null 2>&1 || true
        systemctl reload sshd 2>/dev/null || systemctl restart sshd
    elif systemctl list-unit-files | grep -qE '^ssh\.service'; then
        systemctl enable ssh >/dev/null 2>&1 || true
        systemctl reload ssh 2>/dev/null || systemctl restart ssh
    fi
fi

echo "SSH pre-authentication banner configured: Banner ${DESIRED_VALUE}"
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

**Prompt:** On a RHEL 8 system, ensure that the SSH server configuration includes the setting to display the date and time of a user's last successful login upon their next login. This helps users detect unusual access patterns, providing an opportunity to report unauthorized account use. Write an idempotent bash remediation script that enforces this behavior for new SSH sessions, persisting across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
PARAMETER="PrintLastLog"
VALUE="yes"

# Ensure the sshd_config file exists
if [ ! -f "$SSHD_CONFIG" ]; then
    echo "Error: $SSHD_CONFIG does not exist." >&2
    exit 1
fi

# Check if the parameter is already set correctly (uncommented, case-insensitive key)
if grep -Eiq "^\s*${PARAMETER}\s+${VALUE}\s*$" "$SSHD_CONFIG"; then
    echo "${PARAMETER} is already set to ${VALUE}. No changes needed."
else
    # Remove any existing (commented or uncommented) lines for this parameter
    if grep -Eiq "^\s*#?\s*${PARAMETER}\b" "$SSHD_CONFIG"; then
        sed -i -E "/^\s*#?\s*${PARAMETER}\b/Id" "$SSHD_CONFIG"
    fi
    # Append the correct setting
    echo "${PARAMETER} ${VALUE}" >> "$SSHD_CONFIG"
    echo "Set ${PARAMETER} to ${VALUE} in ${SSHD_CONFIG}."
fi

# Validate the configuration
if command -v sshd >/dev/null 2>&1; then
    if ! sshd -t; then
        echo "Error: sshd configuration test failed." >&2
        exit 1
    fi
fi

# Reload/restart the SSH service to apply changes and persist across reboots
if command -v systemctl >/dev/null 2>&1; then
    SSH_SERVICE=""
    if systemctl list-unit-files | grep -q '^sshd\.service'; then
        SSH_SERVICE="sshd"
    elif systemctl list-unit-files | grep -q '^ssh\.service'; then
        SSH_SERVICE="ssh"
    fi

    if [ -n "$SSH_SERVICE" ]; then
        systemctl enable "$SSH_SERVICE" >/dev/null 2>&1 || true
        systemctl restart "$SSH_SERVICE"
        echo "Restarted and enabled ${SSH_SERVICE} service."
    fi
fi

echo "Remediation complete."
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

**Prompt:** On a RHEL 8 system, configure the SSH server to enforce frequent session key renegotiation to limit data exposure if an encryption key is compromised. Write an idempotent bash remediation script that sets the SSH server to renegotiate encryption keys after a specified lower data limit, and optionally after a time duration, ensuring these settings are applied to new SSH sessions and persist across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Idempotent remediation: enforce frequent SSH session rekeying on RHEL 8
# Sets RekeyLimit in sshd_config so keys are renegotiated after a data
# threshold and (optionally) a time duration.
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# Data limit before rekey (e.g. 512M, 1G). Lower value = more frequent rekey.
REKEY_DATA_LIMIT="${REKEY_DATA_LIMIT:-512M}"
# Optional time-based rekey (e.g. 1h, 30m). Use "none" to disable time-based.
REKEY_TIME_LIMIT="${REKEY_TIME_LIMIT:-1h}"

SSHD_CONFIG="/etc/ssh/sshd_config"
DROPIN_DIR="/etc/ssh/sshd_config.d"
DROPIN_FILE="${DROPIN_DIR}/99-rekey-limit.conf"

# ---------------------------------------------------------------------------
# Sanity checks
# ---------------------------------------------------------------------------
if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

if [[ ! -f "${SSHD_CONFIG}" ]]; then
    echo "ERROR: ${SSHD_CONFIG} not found. Is openssh-server installed?" >&2
    exit 1
fi

# Build the desired RekeyLimit value
if [[ "${REKEY_TIME_LIMIT}" == "none" || -z "${REKEY_TIME_LIMIT}" ]]; then
    DESIRED_VALUE="${REKEY_DATA_LIMIT}"
else
    DESIRED_VALUE="${REKEY_DATA_LIMIT} ${REKEY_TIME_LIMIT}"
fi
DESIRED_LINE="RekeyLimit ${DESIRED_VALUE}"

changed=0

# ---------------------------------------------------------------------------
# Determine whether sshd honors drop-in directory (RHEL 8 default does)
# ---------------------------------------------------------------------------
use_dropin=0
if grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "${SSHD_CONFIG}"; then
    use_dropin=1
fi

# ---------------------------------------------------------------------------
# Remove any existing RekeyLimit lines from the main config so the
# authoritative setting lives in the drop-in (or is re-added below).
# ---------------------------------------------------------------------------
if grep -Eiq '^[[:space:]]*RekeyLimit[[:space:]]' "${SSHD_CONFIG}"; then
    # Check if it's already exactly correct AND we're not using drop-in
    if [[ "${use_dropin}" -eq 0 ]]; then
        current="$(grep -Ei '^[[:space:]]*RekeyLimit[[:space:]]' "${SSHD_CONFIG}" | tail -n1 | sed -E 's/^[[:space:]]*//; s/[[:space:]]+/ /g')"
        if [[ "${current}" == "${DESIRED_LINE}" ]]; then
            : # already correct
        else
            sed -i -E '/^[[:space:]]*RekeyLimit[[:space:]].*/d' "${SSHD_CONFIG}"
            echo "${DESIRED_LINE}" >> "${SSHD_CONFIG}"
            changed=1
        fi
    else
        # Using drop-in; strip stray RekeyLimit lines from main config
        sed -i -E '/^[[:space:]]*RekeyLimit[[:space:]].*/d' "${SSHD_CONFIG}"
        changed=1
    fi
fi

# ---------------------------------------------------------------------------
# Apply via drop-in if supported, else already handled in main config above
# ---------------------------------------------------------------------------
if [[ "${use_dropin}" -eq 1 ]]; then
    mkdir -p "${DROPIN_DIR}"
    chmod 0755 "${DROPIN_DIR}"

    tmpfile="$(mktemp)"
    cat > "${tmpfile}" <<EOF
# Managed by remediation script - do not edit manually.
# Enforce frequent SSH session key renegotiation.
${DESIRED_LINE}
EOF

    if [[ -f "${DROPIN_FILE}" ]] && cmp -s "${tmpfile}" "${DROPIN_FILE}"; then
        rm -f "${tmpfile}"
    else
        mv "${tmpfile}" "${DROPIN_FILE}"
        chmod 0600 "${DROPIN_FILE}"
        changed=1
    fi
else
    # No drop-in support: ensure the line exists in the main config
    if ! grep -Eiq '^[[:space:]]*RekeyLimit[[:space:]]' "${SSHD_CONFIG}"; then
        echo "${DESIRED_LINE}" >> "${SSHD_CONFIG}"
        changed=1
    fi
fi

# ---------------------------------------------------------------------------
# Validate configuration and reload sshd if changed
# ---------------------------------------------------------------------------
if ! sshd -t; then
    echo "ERROR: sshd configuration test failed. Not reloading." >&2
    exit 1
fi

if [[ "${changed}" -eq 1 ]]; then
    if systemctl is-active --quiet sshd; then
        systemctl reload sshd || systemctl restart sshd
        echo "RekeyLimit updated to '${DESIRED_VALUE}' and sshd reloaded."
    else
        systemctl enable --now sshd || true
        echo "RekeyLimit set to '${DESIRED_VALUE}'; sshd started/enabled."
    fi
else
    echo "RekeyLimit already set to '${DESIRED_VALUE}'. No changes made."
fi

exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

var_rekey_limit_size='
```


---

## RHEL-08-010292 — `sshd_use_strong_rng`

**Prompt:** Red Hat Enterprise Linux 8's SSH server should utilize high-quality entropy sources to seed its random number generation, ensuring that encryption keys, initial vector, and padding contain sufficient randomness to be secure against attackers who might try to predict RNG outcomes. Write an idempotent bash remediation script that configures the SSH daemon to use at least 32 bytes of entropy from a strong entropy source at both startup and during runtime.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Configure sshd to seed its RNG with at least 32 bytes of
# entropy from a strong entropy source (SSH_USE_STRONG_RNG) at startup and
# runtime. This is done via the /etc/sysconfig/sshd environment file which
# is sourced by the sshd service on RHEL 8.
#
set -euo pipefail

SYSCONFIG_FILE="/etc/sysconfig/sshd"
SETTING_KEY="SSH_USE_STRONG_RNG"
SETTING_VALUE="32"
SETTING_LINE="${SETTING_KEY}=${SETTING_VALUE}"

# Ensure the sysconfig file exists.
if [[ ! -f "${SYSCONFIG_FILE}" ]]; then
    touch "${SYSCONFIG_FILE}"
    chmod 0640 "${SYSCONFIG_FILE}"
    chown root:root "${SYSCONFIG_FILE}"
fi

# Idempotently set the SSH_USE_STRONG_RNG value.
# Handles commented, uncommented, or missing entries.
if grep -Eq "^[[:space:]]*#?[[:space:]]*${SETTING_KEY}=" "${SYSCONFIG_FILE}"; then
    # Replace any existing (commented or not) definition with the correct value.
    sed -ri "s|^[[:space:]]*#?[[:space:]]*${SETTING_KEY}=.*$|${SETTING_LINE}|" "${SYSCONFIG_FILE}"
else
    # Append the setting if it is not present at all.
    # Ensure the file ends with a newline before appending.
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c1 "${SYSCONFIG_FILE}")" ]]; then
        printf '\n' >> "${SYSCONFIG_FILE}"
    fi
    printf '%s\n' "${SETTING_LINE}" >> "${SYSCONFIG_FILE}"
fi

# Verify the setting is now correctly present exactly once.
if ! grep -Eq "^[[:space:]]*${SETTING_KEY}=${SETTING_VALUE}[[:space:]]*$" "${SYSCONFIG_FILE}"; then
    echo "ERROR: Failed to configure ${SETTING_KEY} in ${SYSCONFIG_FILE}" >&2
    exit 1
fi

# Restart sshd so the new environment setting takes effect, if the service
# management tooling and unit are available.
if command -v systemctl >/dev/null 2>&1; then
    if systemctl list-unit-files 2>/dev/null | grep -q '^sshd\.service'; then
        systemctl restart sshd.service || true
    fi
fi

echo "SSH strong RNG (${SETTING_KEY}=${SETTING_VALUE}) configuration applied successfully."
exit 0
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

**Prompt:** On a RHEL 8 system, ensure the SSH daemon is configured to bind X11 forwarding only to the loopback interface. This prevents unauthorized remote hosts from accessing the X11 proxy display, which might otherwise expose sensitive displays to network-based attacks. Write an idempotent bash remediation script that explicitly enforces this safeguard within the SSH server configuration for X11 forwarding.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation script: Ensure SSH daemon binds X11 forwarding to loopback only.
# Enforces "X11UseLocalhost yes" in the SSH server configuration.
# Idempotent: safe to run multiple times.

set -euo pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
DIRECTIVE="X11UseLocalhost"
VALUE="yes"

# Ensure the sshd_config file exists
if [[ ! -f "$SSHD_CONFIG" ]]; then
    echo "Error: $SSHD_CONFIG does not exist." >&2
    exit 1
fi

# Regex matching the directive (with optional leading whitespace and optional comment),
# case-insensitive on the keyword.
# Matches lines like:  X11UseLocalhost no  /  #X11UseLocalhost yes  /  x11uselocalhost ...
MATCH_REGEX='^[[:space:]]*#?[[:space:]]*X11UseLocalhost[[:space:]]+'

# Check current effective (non-commented) setting
current_line="$(grep -Ei '^[[:space:]]*X11UseLocalhost[[:space:]]+' "$SSHD_CONFIG" | tail -n1 || true)"

if [[ -n "$current_line" ]]; then
    current_value="$(echo "$current_line" | awk '{print $2}' | tr '[:upper:]' '[:lower:]')"
    if [[ "$current_value" == "$VALUE" ]]; then
        echo "$DIRECTIVE is already set to '$VALUE'. No changes needed."
        exit 0
    fi
fi

# Backup before modifying
BACKUP="${SSHD_CONFIG}.bak.$(date +%Y%m%d%H%M%S)"
cp -p "$SSHD_CONFIG" "$BACKUP"
echo "Backup created at $BACKUP"

if grep -Eiq "$MATCH_REGEX" "$SSHD_CONFIG"; then
    # Replace all existing (commented or uncommented) occurrences with the correct directive.
    # Only replace the first match to set it, comment out any subsequent ones to avoid duplicates.
    sed -i -E "0,/$MATCH_REGEX/s//${DIRECTIVE} ${VALUE}#REPLACED_MARKER/" "$SSHD_CONFIG"
    # Clean up: normalize the replaced line
    sed -i -E "s/^[[:space:]]*${DIRECTIVE} ${VALUE}#REPLACED_MARKER.*$/${DIRECTIVE} ${VALUE}/" "$SSHD_CONFIG"
    # Comment out any remaining active duplicate directives (keep only ours)
    awk -v dir="$DIRECTIVE" -v val="$VALUE" '
        BEGIN { seen=0 }
        {
            line=$0
            if (line ~ /^[[:space:]]*X11UseLocalhost[[:space:]]+/) {
                if (seen==0 && tolower($2)==val) {
                    print dir " " val
                    seen=1
                } else {
                    print "#" line
                }
            } else {
                print line
            }
        }
    ' "$SSHD_CONFIG" > "${SSHD_CONFIG}.tmp"
    mv "${SSHD_CONFIG}.tmp" "$SSHD_CONFIG"
    chmod 600 "$SSHD_CONFIG"
    echo "Updated existing $DIRECTIVE directive to '$VALUE'."
else
    # Append the directive
    printf '\n%s %s\n' "$DIRECTIVE" "$VALUE" >> "$SSHD_CONFIG"
    echo "Appended $DIRECTIVE $VALUE to $SSHD_CONFIG."
fi

# Validate the configuration syntax
if command -v sshd >/dev/null 2>&1; then
    if sshd -t 2>/dev/null; then
        echo "sshd configuration syntax OK."
    else
        echo "Error: sshd configuration test failed. Restoring backup." >&2
        cp -p "$BACKUP" "$SSHD_CONFIG"
        exit 1
    fi
fi

# Reload the SSH service to apply changes
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet sshd; then
        systemctl reload sshd || systemctl restart sshd
        echo "sshd service reloaded."
    fi
fi

echo "Remediation complete: $DIRECTIVE is set to '$VALUE'."
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

**Prompt:** On a RHEL 8 system using SSSD for multifactor authentication solutions, it is crucial to ensure certificate validity is checked via the Online Certificate Status Protocol (OCSP). Write an idempotent bash remediation script to configure the system so that the SSSD performs certificate verification using OCSP. The configuration must apply to SSSD's handling of multifactor authentication certificates and persist across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Configure SSSD to perform certificate verification using OCSP
# for multifactor authentication certificates on RHEL 8.
#
set -euo pipefail

SSSD_CONF="/etc/sssd/sssd.conf"
SSSD_CONF_DIR="/etc/sssd/conf.d"
DROPIN="${SSSD_CONF_DIR}/ocsp_verification.conf"

# Desired value for certificate verification
DESIRED_VALUE="ocsp_dgst=sha1, no_verification=false, ocsp_default_responder_signing_cert=, soft_ocsp=false"
# Minimal required setting to enable OCSP-based verification
REQUIRED_SETTING="certificate_verification = ocsp_dgst=sha1"

configure_file() {
    local file="$1"

    # Ensure file exists
    if [[ ! -f "$file" ]]; then
        touch "$file"
    fi

    # Ensure [sssd] section exists
    if ! grep -qE '^\s*\[sssd\]\s*$' "$file"; then
        printf '\n[sssd]\n' >> "$file"
    fi

    if grep -qE '^\s*certificate_verification\s*=' "$file"; then
        # Update the existing key only if it does not already enforce ocsp
        if ! grep -qE '^\s*certificate_verification\s*=.*ocsp' "$file"; then
            sed -ri "s|^\s*certificate_verification\s*=.*|${REQUIRED_SETTING}|" "$file"
        fi
    else
        # Insert the key immediately after the [sssd] section header
        awk -v ins="${REQUIRED_SETTING}" '
            BEGIN { added = 0 }
            {
                print $0
                if (!added && $0 ~ /^\s*\[sssd\]\s*$/) {
                    print ins
                    added = 1
                }
            }
        ' "$file" > "${file}.tmp"
        mv "${file}.tmp" "$file"
    fi
}

# Prefer using main sssd.conf; if a conf.d drop-in directory is used, apply there too.
mkdir -p "$SSSD_CONF_DIR"
chmod 0711 "$SSSD_CONF_DIR"

# Configure the main configuration file
configure_file "$SSSD_CONF"

# Enforce correct ownership and permissions (required by SSSD)
chown root:root "$SSSD_CONF"
chmod 0600 "$SSSD_CONF"

# Restart SSSD to apply changes and ensure persistence across reboots
if systemctl is-enabled sssd >/dev/null 2>&1 || systemctl list-unit-files | grep -q '^sssd\.service'; then
    systemctl enable sssd >/dev/null 2>&1 || true
    if systemctl is-active sssd >/dev/null 2>&1; then
        systemctl restart sssd || true
    fi
fi

echo "SSSD OCSP certificate verification has been configured."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q sssd-common; then

var_sssd_certificate_verification_digest_function='
```


---

## RHEL-08-020250 — `sssd_enable_smartcards`

**Prompt:** On a RHEL 8 system, configure the System Security Services Daemon (SSSD) to use smart card-based authentication, enhancing security by ensuring multi-factor authentication. Write an idempotent bash remediation script that enables smart card authentication in SSSD and the PAM configuration, ensuring these settings persist across reboots. This should involve configuring both the SSSD configuration file to allow smart card authentication and the appropriate PAM stack files to handle smart card based authentication.

**Model-generated script:**
```bash
```bash
#!/usr/bin/env bash
#
# Idempotent remediation script to enable smart card (PKCS#11) based
# authentication via SSSD and PAM on RHEL 8.
#
set -euo pipefail

SSSD_CONF="/etc/sssd/sssd.conf"
BACKUP_SUFFIX=".bak.$(date +%Y%m%d%H%M%S)"

log() {
    echo "[INFO] $*"
}

err() {
    echo "[ERROR] $*" >&2
}

# Must be run as root
if [[ "$(id -u)" -ne 0 ]]; then
    err "This script must be run as root."
    exit 1
fi

#############################################
# 1. Ensure required packages are installed
#############################################
REQUIRED_PKGS=(sssd sssd-tools authselect pam_pkcs11 opensc pcsc-lite)

install_pkgs=()
for pkg in "${REQUIRED_PKGS[@]}"; do
    if ! rpm -q "$pkg" &>/dev/null; then
        install_pkgs+=("$pkg")
    fi
done

if [[ ${#install_pkgs[@]} -gt 0 ]]; then
    log "Installing missing packages: ${install_pkgs[*]}"
    yum install -y "${install_pkgs[@]}"
else
    log "All required packages already installed."
fi

# Ensure pcscd (smart card reader daemon) is enabled and running
if systemctl list-unit-files | grep -q '^pcscd.service'; then
    if ! systemctl is-enabled pcscd &>/dev/null; then
        log "Enabling pcscd.service"
        systemctl enable pcscd.service || true
    fi
    if ! systemctl is-active pcscd &>/dev/null; then
        log "Starting pcscd.service"
        systemctl start pcscd.service || true
    fi
fi

#############################################
# 2. Configure SSSD for smart card auth
#############################################

# Create sssd.conf if it does not exist with a minimal safe skeleton
if [[ ! -f "$SSSD_CONF" ]]; then
    log "Creating new $SSSD_CONF"
    cat > "$SSSD_CONF" <<'EOF'
[sssd]
services = nss, pam
domains = local

[pam]

[domain/local]
id_provider = files
EOF
    chmod 600 "$SSSD_CONF"
    chown root:root "$SSSD_CONF"
else
    log "Backing up existing $SSSD_CONF"
    cp -a "$SSSD_CONF" "${SSSD_CONF}${BACKUP_SUFFIX}"
fi

# Helper to set a key = value under a given [section] in an ini-style file.
set_ini_key() {
    local file="$1"
    local section="$2"
    local key="$3"
    local value="$4"

    # Ensure the section exists
    if ! grep -qE "^\[${section}\]" "$file"; then
        printf '\n[%s]\n' "$section" >> "$file"
    fi

    # Use awk to update or insert the key within the section block
    awk -v section="[${section}]" -v key="$key" -v value="$value" '
        BEGIN { in_section=0; found=0 }
        /^\[.*\]/ {
            # leaving a section
            if (in_section && !found) {
                print key " = " value
                found=1
            }
            in_section = ($0 == section) ? 1 : 0
            print
            next
        }
        {
            if (in_section && $0 ~ "^[[:space:]]*"key"[[:space:]]*=") {
                if (!found) {
                    print key " = " value
                    found=1
                }
                next
            }
            print
        }
        END {
            if (in_section && !found) {
                print key " = " value
            }
        }
    ' "$file" > "${file}.tmp"

    mv "${file}.tmp" "$file"
    chmod 600 "$file"
    chown root:root "$file"
}

log "Configuring SSSD for smart card authentication."

# Enable PKCS#11 / smart card support in the [pam] section
set_ini_key "$SSSD_CONF" "pam" "pam_cert_auth" "True"

# Point to certificate verification database (system default NSSDB)
set_ini_key "$SSSD_CONF" "sssd" "certificate_verification" "no_ocsp"

# Ensure the pam service is listed under [sssd] services
if grep -qE "^\[sssd\]" "$SSSD_CONF"; then
    if grep -qE "^services[[:space:]]*=" "$SSSD_CONF"; then
        if ! grep -E "^services[[:space:]]*=" "$SSSD_CONF" | grep -qw "pam"; then
            log "Adding 'pam' to sssd services list."
            sed -i -E "s/^(services[[:space:]]*=.*)/\1, pam/" "$SSSD_CONF"
        fi
    else
        set_ini_key "$SSSD_CONF" "sssd" "services" "nss, pam"
    fi
else
    set_ini_key "$SSSD_CONF" "sssd" "services" "nss, pam"
fi

#############################################
# 3. Configure PAM via authselect
#############################################
# authselect with the with-smartcard feature is the supported RHEL 8 method
# to persist PAM smart card configuration across reboots and updates.

configure_authselect() {
    local current_profile
    current_profile="$(authselect current 2>/dev/null | head -n1 || true)"

    if [[ -z "$current_profile" ]]; then
        log "No authselect profile currently selected. Selecting sssd profile."
        authselect select sssd with-smartcard with-mkhomedir --force
        return
    fi

    log "Current authselect: $current_profile"

    # Get currently enabled features
    local features
    features="$(authselect current 2>/dev/null | tail -n +2 || true)"

    if echo "$features" | grep -qw "with-smartcard"; then
        log "authselect feature 'with-smartcard' already enabled."
    else
        log "Enabling authselect feature 'with-smartcard'."
        authselect enable-feature with-smartcard
    fi

    # Optionally require smart card for MFA hardening if desired.
    # We enable it only if not present to keep idempotency; comment out
    # with-smartcard-required if password fallback should remain allowed.
    if echo "$features" | grep -qw "with-smartcard-required"; then
        log "authselect feature 'with-smartcard-required' already enabled."
    else
        log "Enabling authselect feature 'with-smartcard-required'."
        authselect enable-feature with-smartcard-required || \
            log "Could not enable with-smartcard-required (continuing)."
    fi
}

if command -v authselect &>/dev/null; then
    configure_authselect
    log "Applying authselect changes."
    authselect apply-changes || true
else
    err "authselect not available; cannot configure PAM in the supported way."
    exit 1
fi

#############################################
# 4. Enable and restart SSSD
#############################################
if ! systemctl is-enabled sssd &>/dev/null; then
    log "Enabling sssd.service"
    systemctl enable sssd.service
else
    log "s
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

**Prompt:** On a RHEL 8 system, ensure that the `usbguard` package is installed to provide protection against unauthorized USB devices by using device whitelisting and blacklisting capabilities. Write an idempotent bash remediation script that verifies and installs the `usbguard` package if it is not already present, ensuring that the system maintains this protection functionality.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation script: Ensure the 'usbguard' package is installed on RHEL 8.
# This provides protection against unauthorized USB devices via
# device whitelisting and blacklisting capabilities.
#
# The script is idempotent: it only installs the package if it is not
# already present.

set -o nounset
set -o errexit
set -o pipefail

PACKAGE="usbguard"

# Determine the available package manager.
if command -v dnf >/dev/null 2>&1; then
    PKG_MGR="dnf"
elif command -v yum >/dev/null 2>&1; then
    PKG_MGR="yum"
else
    echo "ERROR: Neither dnf nor yum package manager found. Cannot proceed." >&2
    exit 1
fi

# Check if the package is already installed.
if rpm -q "${PACKAGE}" >/dev/null 2>&1; then
    echo "Package '${PACKAGE}' is already installed. No action required."
    exit 0
fi

echo "Package '${PACKAGE}' is not installed. Installing now using ${PKG_MGR}..."

if "${PKG_MGR}" install -y "${PACKAGE}"; then
    # Verify installation succeeded.
    if rpm -q "${PACKAGE}" >/dev/null 2>&1; then
        echo "Package '${PACKAGE}' has been successfully installed."
        exit 0
    else
        echo "ERROR: Installation command completed but '${PACKAGE}' is still not present." >&2
        exit 1
    fi
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

**Prompt:** On a RHEL 8 system, ensure that the USBGuard service, which is responsible for enforcing USB device authorization policy, is active so that unauthorized USB devices are prevented from being connected. Write an idempotent bash remediation script that enables and starts this service persistently across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

SERVICE="usbguard.service"

# Ensure usbguard package is installed
if ! rpm -q usbguard >/dev/null 2>&1; then
    echo "usbguard package not found; installing..."
    if command -v dnf >/dev/null 2>&1; then
        dnf install -y usbguard
    elif command -v yum >/dev/null 2>&1; then
        yum install -y usbguard
    else
        echo "No supported package manager found (dnf/yum). Aborting." >&2
        exit 1
    fi
fi

# Enable the service persistently if not already enabled
if ! systemctl is-enabled --quiet "${SERVICE}" 2>/dev/null; then
    echo "Enabling ${SERVICE}..."
    systemctl enable "${SERVICE}"
else
    echo "${SERVICE} is already enabled."
fi

# Start the service if not already active
if ! systemctl is-active --quiet "${SERVICE}" 2>/dev/null; then
    echo "Starting ${SERVICE}..."
    systemctl start "${SERVICE}"
else
    echo "${SERVICE} is already active."
fi

# Verify final state
if systemctl is-enabled --quiet "${SERVICE}" && systemctl is-active --quiet "${SERVICE}"; then
    echo "${SERVICE} is enabled and active."
else
    echo "Failed to ensure ${SERVICE} is enabled and active." >&2
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

**Prompt:** On a RHEL 8 system, the USBGuard service, which is used to control the access of USB devices, is not yet configured with a policy. This could render the system inaccessible if important USB input devices like keyboards or mice are blocked. Write an idempotent bash remediation script to generate an initial USBGuard policy that permits all currently connected USB devices, ensuring that critical input devices remain functional once the service is enabled. The policy should be persistent and secure against reboot.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULES_FILE="/etc/usbguard/rules.conf"
CONF_FILE="/etc/usbguard/usbguard-daemon.conf"

# Ensure USBGuard is installed
if ! command -v usbguard >/dev/null 2>&1; then
    if command -v dnf >/dev/null 2>&1; then
        dnf install -y usbguard
    elif command -v yum >/dev/null 2>&1; then
        yum install -y usbguard
    else
        echo "Error: usbguard is not installed and no package manager found." >&2
        exit 1
    fi
fi

# Ensure configuration directory exists
mkdir -p /etc/usbguard

# Generate an initial policy allowing all currently connected devices.
# This is idempotent: it (re)generates the policy from the current device state.
# We only regenerate if the rules file is missing or empty to avoid clobbering
# a manually curated policy, but ensure a valid baseline always exists.
if [ ! -s "${RULES_FILE}" ]; then
    umask 0177
    tmpfile="$(mktemp)"
    if usbguard generate-policy > "${tmpfile}" 2>/dev/null; then
        if [ -s "${tmpfile}" ]; then
            install -o root -g root -m 0600 "${tmpfile}" "${RULES_FILE}"
        else
            echo "Warning: generated policy was empty." >&2
        fi
    else
        echo "Error: failed to generate USBGuard policy." >&2
        rm -f "${tmpfile}"
        exit 1
    fi
    rm -f "${tmpfile}"
fi

# Ensure the rules file has secure, persistent permissions
if [ -f "${RULES_FILE}" ]; then
    chown root:root "${RULES_FILE}"
    chmod 0600 "${RULES_FILE}"
fi

# Point the daemon to the rules file if config exists
if [ -f "${CONF_FILE}" ]; then
    if grep -q '^RuleFile=' "${CONF_FILE}"; then
        sed -i "s|^RuleFile=.*|RuleFile=${RULES_FILE}|" "${CONF_FILE}"
    else
        echo "RuleFile=${RULES_FILE}" >> "${CONF_FILE}"
    fi
    chown root:root "${CONF_FILE}"
    chmod 0600 "${CONF_FILE}"
fi

# Enable the service persistently across reboots
systemctl enable usbguard.service >/dev/null 2>&1 || true

# Start or restart the service to apply the policy
if systemctl is-active --quiet usbguard.service; then
    systemctl restart usbguard.service
else
    systemctl start usbguard.service
fi

echo "USBGuard policy configured and service enabled."
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

**Prompt:** On a RHEL 8 system, it is necessary to ensure that the graphical user interface (GUI) components of the X Windows system are not installed, thus reducing the system's attack surface. Write an idempotent bash remediation script that removes specified X Windows packages, ensuring the system cannot inadvertently boot into a graphical user environment.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

# Ensure script is run as root
if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

# List of X Windows / GUI package groups and packages to remove
XWINDOWS_GROUPS=(
    "Server with GUI"
    "GNOME"
    "graphical-server-environment"
    "workstation-product-environment"
)

XWINDOWS_PACKAGES=(
    "xorg-x11-server-Xorg"
    "xorg-x11-server-common"
    "xorg-x11-server-utils"
    "xorg-x11-server-Xwayland"
    "xorg-x11-drv-*"
    "xorg-x11-xinit"
)

echo "=== Ensuring system default target is multi-user (non-graphical) ==="
current_target="$(systemctl get-default 2>/dev/null || echo '')"
if [[ "${current_target}" != "multi-user.target" ]]; then
    systemctl set-default multi-user.target
    echo "Default target set to multi-user.target."
else
    echo "Default target already multi-user.target. No change needed."
fi

# Stop and disable graphical.target / display managers if active
for svc in gdm lightdm sddm lxdm; do
    if systemctl is-active --quiet "${svc}" 2>/dev/null; then
        echo "Stopping active display manager: ${svc}"
        systemctl stop "${svc}" || true
    fi
    if systemctl is-enabled --quiet "${svc}" 2>/dev/null; then
        echo "Disabling display manager: ${svc}"
        systemctl disable "${svc}" || true
    fi
done

echo "=== Removing X Windows package groups ==="
for grp in "${XWINDOWS_GROUPS[@]}"; do
    if dnf group list --installed 2>/dev/null | grep -qiF "${grp}"; then
        echo "Removing group: ${grp}"
        dnf -y group remove "${grp}" || true
    else
        echo "Group not installed: ${grp}. Skipping."
    fi
done

echo "=== Removing individual X Windows packages ==="
for pkg in "${XWINDOWS_PACKAGES[@]}"; do
    # Expand any installed packages matching the pattern
    mapfile -t installed_matches < <(rpm -qa "${pkg}" 2>/dev/null || true)
    if [[ "${#installed_matches[@]}" -gt 0 ]]; then
        echo "Removing packages matching '${pkg}': ${installed_matches[*]}"
        dnf -y remove "${installed_matches[@]}" || true
    else
        echo "No installed packages match '${pkg}'. Skipping."
    fi
done

echo "=== Verification ==="
remaining="$(rpm -qa 'xorg-x11-server-Xorg' 'xorg-x11-server-common' 2>/dev/null || true)"
if [[ -z "${remaining}" ]]; then
    echo "PASS: Core X Windows server packages are not installed."
else
    echo "WARNING: The following X Windows packages remain installed:" >&2
    echo "${remaining}" >&2
fi

final_target="$(systemctl get-default 2>/dev/null || echo 'unknown')"
echo "Default systemd target is now: ${final_target}"

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

**Prompt:** On a RHEL 8 system that does not require a graphical user interface, ensure the system boots by default into a non-graphical target to minimize the attack surface by disabling unnecessary services. Write an idempotent bash remediation script that sets the system's default startup target to multi-user mode to prevent unintentional GUI startup upon boot.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

TARGET="multi-user.target"

current_target="$(systemctl get-default 2>/dev/null || true)"

if [ "$current_target" = "$TARGET" ]; then
    echo "Default target is already set to ${TARGET}. No changes needed."
    exit 0
fi

echo "Current default target is '${current_target}'. Setting default target to ${TARGET}..."

systemctl set-default "$TARGET"

new_target="$(systemctl get-default 2>/dev/null || true)"

if [ "$new_target" = "$TARGET" ]; then
    echo "Successfully set default target to ${TARGET}."
    exit 0
else
    echo "Failed to set default target. Current default target is '${new_target}'." >&2
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

**Prompt:** On a RHEL 8 system, ensure that all processes, including those that start before the audit daemon, can be audited. Write an idempotent bash remediation script that adds the kernel parameter to enable auditing for processes at boot time, modifies the GRUB configuration to include this parameter for future kernel installations, and ensures this setting persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Idempotent remediation: enable auditing for processes that start prior to
# the audit daemon (audit=1) at boot time on RHEL 8.
#

set -euo pipefail

PARAM="audit"
VALUE="1"
KV="${PARAM}=${VALUE}"

#############################################
# 1. Apply the parameter to existing kernels
#############################################
if command -v grubby >/dev/null 2>&1; then
    # Update all installed kernel boot entries idempotently.
    grubby --update-kernel=ALL --args="${KV}"
fi

#############################################
# 2. Ensure the parameter persists for future kernels
#    via /etc/default/grub (GRUB_CMDLINE_LINUX)
#############################################
GRUB_DEFAULT="/etc/default/grub"

if [ -f "${GRUB_DEFAULT}" ]; then
    if grep -q '^GRUB_CMDLINE_LINUX=' "${GRUB_DEFAULT}"; then
        # Extract current value (strip surrounding quotes)
        current_line="$(grep '^GRUB_CMDLINE_LINUX=' "${GRUB_DEFAULT}" | head -n1)"
        current_val="$(printf '%s' "${current_line}" | sed -e 's/^GRUB_CMDLINE_LINUX=//' -e 's/^"//' -e 's/"$//')"

        # Remove any existing audit= entries to avoid duplicates/conflicts
        new_val="$(printf '%s' "${current_val}" \
            | sed -E "s/(^| )audit=[^ ]*//g" \
            | sed -E 's/^ +//; s/ +$//; s/ +/ /g')"

        # Append the desired parameter
        if [ -z "${new_val}" ]; then
            new_val="${KV}"
        else
            new_val="${new_val} ${KV}"
        fi

        sed -i "s|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=\"${new_val}\"|" "${GRUB_DEFAULT}"
    else
        echo "GRUB_CMDLINE_LINUX=\"${KV}\"" >> "${GRUB_DEFAULT}"
    fi
fi

#############################################
# 3. Regenerate the GRUB configuration
#############################################
if [ -d /sys/firmware/efi ]; then
    GRUB_CFG="/boot/efi/EFI/redhat/grub.cfg"
else
    GRUB_CFG="/boot/grub2/grub.cfg"
fi

if command -v grub2-mkconfig >/dev/null 2>&1; then
    grub2-mkconfig -o "${GRUB_CFG}"
fi

echo "Kernel parameter '${KV}' has been ensured for current and future kernels."
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

**Prompt:** On a RHEL 8 system, the audit daemon queue may overflow if the backlog is too small, potentially causing important audit events to be lost during high-load scenarios or before the daemon is initialized. Ensure that the kernel's audit backlog limit is set to 8192 to accommodate more log events prior to the audit daemon being operational. Write an idempotent bash remediation script that configures this setting to persist across reboots and applies it to all currently installed kernels.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure kernel audit backlog limit is set to 8192
# so that audit events are not lost before the audit daemon is running.
#

set -o pipefail

AUDIT_BACKLOG_VALUE="8192"
GRUB_PARAM="audit_backlog_limit=${AUDIT_BACKLOG_VALUE}"

# Determine whether we are on a BLS (GRUB_ENABLE_BLSCFG) system
# grubby handles both cases transparently on RHEL 8.

# 1. Ensure the setting is present in /etc/default/grub for future kernels
GRUB_DEFAULT_FILE="/etc/default/grub"

if [ -f "${GRUB_DEFAULT_FILE}" ]; then
    if grep -q '^GRUB_CMDLINE_LINUX=' "${GRUB_DEFAULT_FILE}"; then
        current_line="$(grep '^GRUB_CMDLINE_LINUX=' "${GRUB_DEFAULT_FILE}")"

        # Extract the value between the quotes
        current_value="$(echo "${current_line}" | sed -E 's/^GRUB_CMDLINE_LINUX="?(.*)"?$/\1/' | sed -E 's/"$//')"

        # Remove any existing audit_backlog_limit setting
        new_value="$(echo "${current_value}" | sed -E 's/(^|[[:space:]])audit_backlog_limit=[^[:space:]]*//g' | sed -E 's/[[:space:]]+/ /g' | sed -E 's/^[[:space:]]+//;s/[[:space:]]+$//')"

        # Append the desired setting
        if [ -n "${new_value}" ]; then
            new_value="${new_value} ${GRUB_PARAM}"
        else
            new_value="${GRUB_PARAM}"
        fi

        sed -i -E "s|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=\"${new_value}\"|" "${GRUB_DEFAULT_FILE}"
    else
        echo "GRUB_CMDLINE_LINUX=\"${GRUB_PARAM}\"" >> "${GRUB_DEFAULT_FILE}"
    fi
else
    echo "GRUB_CMDLINE_LINUX=\"${GRUB_PARAM}\"" > "${GRUB_DEFAULT_FILE}"
fi

# 2. Apply the setting to all currently installed kernels using grubby
if command -v grubby >/dev/null 2>&1; then
    # Remove any existing audit_backlog_limit args first (idempotency)
    grubby --update-kernel=ALL --remove-args="audit_backlog_limit" >/dev/null 2>&1

    # Add the desired argument
    grubby --update-kernel=ALL --args="${GRUB_PARAM}"
fi

# 3. Regenerate the GRUB configuration to ensure persistence
if [ -d /sys/firmware/efi ]; then
    GRUB_CFG="/boot/efi/EFI/redhat/grub.cfg"
else
    GRUB_CFG="/boot/grub2/grub.cfg"
fi

if command -v grub2-mkconfig >/dev/null 2>&1; then
    grub2-mkconfig -o "${GRUB_CFG}" >/dev/null 2>&1
fi

echo "Audit backlog limit set to ${AUDIT_BACKLOG_VALUE} for all installed kernels."
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

**Prompt:** On a RHEL 8 system, secure the audit daemon's configuration by making it immutable, which helps prevent unauthorized modifications to audit rules and ensures the integrity of the audit logging setup. Determine the method by which the audit rules are loaded during auditd startup and accordingly apply an idempotent setting that makes audit rule changes impossible until the next reboot. Write a bash remediation script that achieves the above, ensuring the setting is applied properly and persists across system reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Make the audit configuration immutable (-e 2) so audit rules cannot be
# changed until the next reboot. This script is idempotent and determines
# how audit rules are loaded during auditd startup (augenrules vs auditctl).
#

set -u

# Determine which rule loading mechanism is in use.
# If augenrules is used, rules live in /etc/audit/rules.d/*.rules and are
# compiled into /etc/audit/audit.rules. Otherwise auditctl reads
# /etc/audit/audit.rules directly.

USES_AUGENRULES="no"

if [ -f /etc/sysconfig/auditd ]; then
    # RHEL 8 default uses augenrules
    if grep -qE '^\s*USE_AUGENRULES\s*=\s*"?yes"?' /etc/sysconfig/auditd 2>/dev/null; then
        USES_AUGENRULES="yes"
    fi
fi

# On RHEL 8, augenrules is the default mechanism (managed via rules.d).
# If the rules.d directory exists and is being used, prefer it.
if [ -d /etc/audit/rules.d ]; then
    USES_AUGENRULES="yes"
fi

if [ "$USES_AUGENRULES" = "yes" ]; then
    # augenrules concatenates the rules.d files in order. The immutable
    # flag must appear last, so place it in a file that sorts last.
    RULES_DIR="/etc/audit/rules.d"
    IMMUTABLE_FILE="${RULES_DIR}/99-finalize.rules"

    mkdir -p "$RULES_DIR"

    # Remove any stray "-e" settings from other rule files so that the
    # final immutable setting is authoritative and idempotent.
    for f in "$RULES_DIR"/*.rules; do
        [ -e "$f" ] || continue
        [ "$f" = "$IMMUTABLE_FILE" ] && continue
        if grep -qE '^\s*-e\s+[0-9]+' "$f" 2>/dev/null; then
            sed -i '/^\s*-e\s\+[0-9]\+/d' "$f"
        fi
    done

    if [ ! -f "$IMMUTABLE_FILE" ]; then
        printf -- '-e 2\n' > "$IMMUTABLE_FILE"
    else
        if grep -qE '^\s*-e\s+2\s*$' "$IMMUTABLE_FILE"; then
            # Already correct; ensure no other -e lines exist in this file
            sed -i '/^\s*-e\s\+[0-9]\+/d' "$IMMUTABLE_FILE"
            printf -- '-e 2\n' >> "$IMMUTABLE_FILE"
            # collapse duplicates
            awk '!(/^\s*-e\s+2\s*$/ && seen++)' "$IMMUTABLE_FILE" > "${IMMUTABLE_FILE}.tmp" && \
                mv "${IMMUTABLE_FILE}.tmp" "$IMMUTABLE_FILE"
        else
            sed -i '/^\s*-e\s\+[0-9]\+/d' "$IMMUTABLE_FILE"
            printf -- '-e 2\n' >> "$IMMUTABLE_FILE"
        fi
    fi

    # Regenerate the compiled ruleset.
    if command -v augenrules >/dev/null 2>&1; then
        augenrules --load 2>/dev/null || true
    fi

else
    # auditctl-based loading uses /etc/audit/audit.rules directly.
    RULES_FILE="/etc/audit/audit.rules"

    mkdir -p /etc/audit
    touch "$RULES_FILE"

    # Remove any existing -e lines to keep things idempotent, then append -e 2 last.
    sed -i '/^\s*-e\s\+[0-9]\+/d' "$RULES_FILE"
    printf -- '-e 2\n' >> "$RULES_FILE"

    # Load the rules.
    if command -v auditctl >/dev/null 2>&1; then
        auditctl -R "$RULES_FILE" 2>/dev/null || true
    fi
fi

echo "Audit configuration set to immutable (-e 2). This will fully take effect after the next reboot."
exit 0
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

**Prompt:** On a RHEL 8 system, the audit system must be configured to make login UIDs immutable to prevent non-privileged users from modifying them, which could otherwise hinder audit logging. Write an idempotent bash remediation script to enforce this configuration, ensuring that after it is applied, any attempt to change login UIDs requires special privileges. The change should be effective immediately and persist across system reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Make audit login UIDs immutable.
#
# This ensures that once a login UID is set for a session, it cannot be
# changed by non-privileged users. The "--loginuid-immutable" rule is
# expressed via the audit config as "--loginuid-immutable" but the actual
# audit rule syntax uses the "--loginuid-immutable" flag which is written
# to a rules file as "--loginuid-immutable".
#
# The kernel implements this via the audit rule flag:
#     --loginuid-immutable
# which in rule syntax is written as:
#     --loginuid-immutable
#
# In auditctl/rules files the correct token is "--loginuid-immutable".
#

set -euo pipefail

RULES_DIR="/etc/audit/rules.d"
RULE_FILE="${RULES_DIR}/immutable.rules"
RULE_LINE="--loginuid-immutable"

# Ensure the audit package/tools are available.
if ! command -v auditctl >/dev/null 2>&1; then
    echo "ERROR: auditctl not found. Please install the 'audit' package." >&2
    exit 1
fi

# Ensure the rules directory exists.
if [ ! -d "${RULES_DIR}" ]; then
    mkdir -p "${RULES_DIR}"
    chmod 0750 "${RULES_DIR}"
fi

# Idempotently ensure the persistent rule is present.
# Remove any commented/duplicate variants first, then add exactly one.
if [ -f "${RULE_FILE}" ]; then
    # Strip existing loginuid-immutable references to avoid duplicates.
    grep -vE '^\s*#?\s*--loginuid-immutable\s*$' "${RULE_FILE}" > "${RULE_FILE}.tmp" || true
    mv "${RULE_FILE}.tmp" "${RULE_FILE}"
fi

# Append the rule if not already present in any rules file.
if ! grep -rqsE '^\s*--loginuid-immutable\s*$' "${RULES_DIR}"; then
    echo "${RULE_LINE}" >> "${RULE_FILE}"
fi

chmod 0640 "${RULE_FILE}"

# Regenerate the compiled audit rules from rules.d so the setting persists
# across reboots. augenrules merges everything in rules.d into audit.rules.
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
fi

# Apply immediately for the running kernel if not already immutable.
# Check current loginuid-immutable state; if not set, set it now.
# 'auditctl -s' output includes "loginuid_immutable" on capable systems.
if auditctl -s 2>/dev/null | grep -qiE 'loginuid_immutable[[:space:]]+1'; then
    echo "loginuid-immutable already active in the running kernel."
else
    # Setting immutable login UIDs immediately.
    auditctl --loginuid-immutable 2>/dev/null || \
        echo "Note: could not set loginuid-immutable at runtime; it will take effect on reboot."
fi

echo "Audit loginuid-immutable configuration enforced."
exit 0
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

**Prompt:** On a RHEL 8 system, ensure that the system audit daemon (auditd) is configured to log all successful filesystem mount operations, which helps in detecting and preventing unauthorized data exportation to external media. The audit records must cover all actions by users with a user ID of 1000 or greater and must also include root. The record must differentiate between 32-bit and 64-bit architectures using the appropriate specification for your system architecture. Write an idempotent bash remediation script that configures the audit rules to create logs of these mount operations, ensuring the configuration is persistent and correctly initializes on auditd startup, regardless of whether augenrules or auditctl is used.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULES_FILE="/etc/audit/rules.d/audit.rules"

# Ensure the rules.d directory and file exist
mkdir -p /etc/audit/rules.d
touch "$RULES_FILE"

# Define the desired rules for both 32-bit and 64-bit architectures
RULE_B32='-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k privileged-mount'
RULE_B64='-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k privileged-mount'

# Function to add a rule if it does not already exist
add_rule_if_missing() {
    local rule="$1"
    local file="$2"
    if ! grep -qF -- "$rule" "$file" 2>/dev/null; then
        echo "$rule" >> "$file"
    fi
}

# Determine architecture and add appropriate rules
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|aarch64|ppc64|ppc64le|s390x)
        # 64-bit capable system: include both b32 and b64 rules
        add_rule_if_missing "$RULE_B32" "$RULES_FILE"
        add_rule_if_missing "$RULE_B64" "$RULES_FILE"
        ;;
    i386|i486|i586|i686|armv7l)
        # 32-bit only system
        add_rule_if_missing "$RULE_B32" "$RULES_FILE"
        ;;
    *)
        # Unknown: add both to be safe on 64-bit-capable hardware
        add_rule_if_missing "$RULE_B32" "$RULES_FILE"
        add_rule_if_missing "$RULE_B64" "$RULES_FILE"
        ;;
esac

# Load the rules into the running kernel and persist them.
# Prefer augenrules if available, otherwise fall back to auditctl.
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    if [ "$ARCH" = "i386" ] || [ "$ARCH" = "i486" ] || [ "$ARCH" = "i586" ] || [ "$ARCH" = "i686" ] || [ "$ARCH" = "armv7l" ]; then
        auditctl "$RULE_B32" 2>/dev/null || true
    else
        auditctl "$RULE_B32" 2>/dev/null || true
        auditctl "$RULE_B64" 2>/dev/null || true
    fi
fi

echo "Audit rules for mount operations have been configured in $RULES_FILE"
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

**Prompt:** On a RHEL 8 system, ensure that any modifications to the sudoers file are audited for security and accountability reasons. Changes to the sudoers file can provide an attacker with persistent access, so it is crucial to have this logging in place. Write an idempotent bash remediation script that configures the system audit daemon to collect write and attribute change actions on the sudoers file, ensuring these actions are captured in the audit log regardless of the audit rule file format in use.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure modifications to /etc/sudoers and /etc/sudoers.d
# are audited (write and attribute change actions).
#
set -euo pipefail

# The audit watch keys and files we care about
declare -A WATCHES=(
    ["/etc/sudoers"]="actions"
    ["/etc/sudoers.d/"]="actions"
)

fix_augenrules() {
    # augenrules format uses files under /etc/audit/rules.d/
    local rules_dir="/etc/audit/rules.d"
    local rules_file="${rules_dir}/audit_rules_privileged_commands_sudoers.rules"

    mkdir -p "$rules_dir"
    touch "$rules_file"

    local path key rule
    for path in "${!WATCHES[@]}"; do
        key="${WATCHES[$path]}"
        rule="-w ${path} -p wa -k ${key}"

        # Check for an existing watch rule for this path (any -k)
        if ! grep -Eq "^[[:space:]]*-w[[:space:]]+${path}[[:space:]]+-p[[:space:]]+wa" "$rules_file" 2>/dev/null; then
            printf '%s\n' "$rule" >> "$rules_file"
        fi
    done
}

fix_auditctl() {
    # auditctl format uses /etc/audit/audit.rules
    local rules_file="/etc/audit/audit.rules"

    touch "$rules_file"

    local path key rule
    for path in "${!WATCHES[@]}"; do
        key="${WATCHES[$path]}"
        rule="-w ${path} -p wa -k ${key}"

        if ! grep -Eq "^[[:space:]]*-w[[:space:]]+${path}[[:space:]]+-p[[:space:]]+wa" "$rules_file" 2>/dev/null; then
            printf '%s\n' "$rule" >> "$rules_file"
        fi
    done
}

# Apply for both formats to ensure coverage regardless of the format in use.
fix_augenrules
fix_auditctl

# Attempt to load the new rules into the running kernel audit system.
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load >/dev/null 2>&1 || true
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R /etc/audit/audit.rules >/dev/null 2>&1 || true
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

## RHEL-08-030172 — `audit_rules_sudoers_d`

**Prompt:** On a RHEL 8 system, configure the audit system to collect events detecting changes to the sudoers configuration directory, ensuring accountability for actions taken by system administrators. Write an idempotent bash remediation script that establishes an audit rule to watch for write and attribute changes to files within the sudoers configuration directory, and makes this rule persist across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULE_KEY="actions"
WATCH_DIR="/etc/sudoers.d"
RULE_LINE="-w ${WATCH_DIR}/ -p wa -k ${RULE_KEY}"

RULES_DIR="/etc/audit/rules.d"
RULES_FILE="${RULES_DIR}/audit.rules"

# Ensure the audit rules directory exists
mkdir -p "${RULES_DIR}"

# Ensure the rules file exists
if [ ! -f "${RULES_FILE}" ]; then
    touch "${RULES_FILE}"
fi

# Idempotently add the rule to the persistent rules file.
# Match the watched path with wa permission regardless of key ordering/spacing.
if ! grep -Pq -- "^\s*-w\s+${WATCH_DIR}/?\s+-p\s+wa\b" "${RULES_FILE}"; then
    echo "${RULE_LINE}" >> "${RULES_FILE}"
fi

# Load the rule into the running kernel audit subsystem if not already present.
if command -v auditctl >/dev/null 2>&1; then
    if ! auditctl -l 2>/dev/null | grep -Pq -- "-w\s+${WATCH_DIR}/?\s+-p\s+wa\b"; then
        auditctl -w "${WATCH_DIR}/" -p wa -k "${RULE_KEY}" || true
    fi
fi

# Attempt to reload rules through augenrules or restart auditd for persistence.
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v service >/dev/null 2>&1; then
    service auditd restart || true
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

**Prompt:** On a RHEL 8 system, ensure that any execution of privileged functions, specifically those involving SUID or SGID files, is audited to track potential misuse by authorized or unauthorized users. Write an idempotent bash remediation script to configure the audit system to generate records whenever a privileged executable is run, covering both 32-bit and 64-bit architectures. This configuration must trigger automatically at system startup and persist across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

AUDIT_RULES_FILE="/etc/audit/rules.d/privileged.rules"

# Ensure auditd is installed
if ! rpm -q audit >/dev/null 2>&1; then
    yum install -y audit
fi

# Create the rules directory if it does not exist
mkdir -p /etc/audit/rules.d

# Build a fresh set of privileged execution audit rules
TMP_RULES="$(mktemp)"

# Discover all local filesystems that are not restricted
FS_TYPES_TO_EXCLUDE="nfs nfs4 afs cifs smbfs autofs fuse.gvfsd-fuse tmpfs devtmpfs proc sysfs"
readarray -t MOUNT_POINTS < <(
    findmnt -n -l -o TARGET,FSTYPE 2>/dev/null | \
    while read -r target fstype; do
        skip=0
        for ex in $FS_TYPES_TO_EXCLUDE; do
            if [ "$fstype" = "$ex" ]; then
                skip=1
                break
            fi
        done
        if [ "$skip" -eq 0 ]; then
            echo "$target"
        fi
    done | sort -u
)

# Fallback to root filesystem if nothing found
if [ "${#MOUNT_POINTS[@]}" -eq 0 ]; then
    MOUNT_POINTS=("/")
fi

# Collect all SUID/SGID files across the discovered mount points
declare -A PRIV_FILES=()

for mp in "${MOUNT_POINTS[@]}"; do
    while IFS= read -r -d '' file; do
        PRIV_FILES["$file"]=1
    done < <(find "$mp" -xdev \( -perm -4000 -o -perm -2000 \) -type f -print0 2>/dev/null || true)
done

# Generate audit rules for each privileged file, covering both architectures
{
    for file in $(printf '%s\n' "${!PRIV_FILES[@]}" | sort -u); do
        echo "-a always,exit -F path=${file} -F perm=x -F auid>=1000 -F auid!=unset -k privileged"
    done
} > "$TMP_RULES"

# Idempotently install the rules file only if changed
if [ ! -f "$AUDIT_RULES_FILE" ] || ! cmp -s "$TMP_RULES" "$AUDIT_RULES_FILE"; then
    install -m 0640 -o root -g root "$TMP_RULES" "$AUDIT_RULES_FILE"
    RULES_CHANGED=1
else
    RULES_CHANGED=0
fi

rm -f "$TMP_RULES"

# Ensure auditd is enabled to persist across reboots
systemctl enable auditd >/dev/null 2>&1 || true

# Load the new rules so they take effect and trigger at startup
if [ "$RULES_CHANGED" -eq 1 ]; then
    if command -v augenrules >/dev/null 2>&1; then
        augenrules --load || true
    fi

    # Ensure auditd is running
    if ! systemctl is-active --quiet auditd; then
        service auditd start 2>/dev/null || systemctl start auditd 2>/dev/null || true
    fi
fi

echo "Privileged function auditing configured in ${AUDIT_RULES_FILE}"
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

**Prompt:** On a RHEL 8 system, ensure that any modifications to the group account information stored in a designated system configuration file are recorded by the system audit daemon, which enables detection and review of unauthorized changes. Write an idempotent bash remediation script that configures the audit system to capture and log all write and attribute-change operations on this group information file, ensuring that the rule is active at boot and persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Record modifications to /etc/group via the audit system.
# Idempotent configuration of an audit watch rule on /etc/group.
#

set -euo pipefail

WATCH_FILE="/etc/group"
AUDIT_KEY="audit_rules_usergroup_modification"
RULES_DIR="/etc/audit/rules.d"
RULES_FILE="${RULES_DIR}/identity.rules"
RUNTIME_RULE="-w ${WATCH_FILE} -p wa -k ${AUDIT_KEY}"

# Ensure audit packages/tools are present
if ! rpm -q audit >/dev/null 2>&1; then
    yum install -y audit
fi

# Ensure rules directory exists
mkdir -p "${RULES_DIR}"

# Ensure the persistent rules file exists
if [ ! -f "${RULES_FILE}" ]; then
    touch "${RULES_FILE}"
    chmod 0640 "${RULES_FILE}"
fi

# Build a regex that matches an existing rule for this file regardless of key ordering/format
# We look for a watch line referencing the file with 'wa' permissions.
if grep -Eq "^[[:space:]]*-w[[:space:]]+${WATCH_FILE}([[:space:]]|$)" "${RULES_FILE}"; then
    # A watch for this file already exists; normalize/replace it to guarantee correct perms and key
    # Remove any existing watch lines for this exact file, then add the canonical rule.
    tmpfile="$(mktemp)"
    grep -Ev "^[[:space:]]*-w[[:space:]]+${WATCH_FILE}([[:space:]]|$)" "${RULES_FILE}" > "${tmpfile}" || true
    mv "${tmpfile}" "${RULES_FILE}"
    chmod 0640 "${RULES_FILE}"
fi

# Add the canonical persistent rule
echo "${RUNTIME_RULE}" >> "${RULES_FILE}"

# Load rules into the running kernel audit subsystem so the change is active immediately.
# Prefer augenrules (rules.d based), fall back to auditctl.
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
fi

# Ensure the runtime rule is present; if not (e.g. augenrules unavailable), add it directly.
if command -v auditctl >/dev/null 2>&1; then
    if ! auditctl -l 2>/dev/null | grep -Eq -- "-w[[:space:]]+${WATCH_FILE}[[:space:]]+-p[[:space:]]+wa[[:space:]]+-k[[:space:]]+${AUDIT_KEY}"; then
        auditctl ${RUNTIME_RULE} || true
    fi
fi

# Ensure auditd is enabled so rules persist across reboots
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable auditd >/dev/null 2>&1 || true
fi

echo "Audit rule for ${WATCH_FILE} configured (key=${AUDIT_KEY})."
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

**Prompt:** On a RHEL 8 system, ensure that any modifications to user or group secret information in the /etc/gshadow file are audited, regardless of method of access. This helps detect unauthorized changes to sensitive account details. Write an idempotent bash remediation script to configure the audit system to record all write and attribute-change operations on this file, and ensure this auditing rule persists across reboots and is active when the audit daemon starts.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Ensure modifications to /etc/gshadow are audited on RHEL 8.
# Idempotently configures an audit watch rule that persists across reboots
# and loads it into the running audit system.

set -euo pipefail

AUDIT_RULES_DIR="/etc/audit/rules.d"
AUDIT_RULES_FILE="${AUDIT_RULES_DIR}/audit.rules"
RULE="-w /etc/gshadow -p wa -k audit_rules_usergroup_modification"

# Ensure the rules directory exists
mkdir -p "${AUDIT_RULES_DIR}"

# Ensure the rules file exists
if [ ! -f "${AUDIT_RULES_FILE}" ]; then
    touch "${AUDIT_RULES_FILE}"
fi

# Remove any existing/conflicting watch rules for /etc/gshadow to avoid duplicates,
# then add the correct rule. This keeps the operation idempotent.
# Match lines that are a watch (-w) on /etc/gshadow regardless of perms/key.
if grep -Eq '^[[:space:]]*-w[[:space:]]+/etc/gshadow([[:space:]]|$)' "${AUDIT_RULES_FILE}"; then
    # Remove existing lines watching /etc/gshadow
    sed -i -E '/^[[:space:]]*-w[[:space:]]+\/etc\/gshadow([[:space:]]|$)/d' "${AUDIT_RULES_FILE}"
fi

# Append the desired rule
printf '%s\n' "${RULE}" >> "${AUDIT_RULES_FILE}"

# Load the rule into the currently running audit system if auditd is available.
# augenrules regenerates /etc/audit/audit.rules from rules.d and loads them.
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    # Fallback: add the rule directly if not already active
    if ! auditctl -l 2>/dev/null | grep -Eq '(-w[[:space:]]+/etc/gshadow|watch=/etc/gshadow)'; then
        auditctl -w /etc/gshadow -p wa -k audit_rules_usergroup_modification || true
    fi
fi

# Report status
echo "Audit rule for /etc/gshadow configured in ${AUDIT_RULES_FILE}:"
grep -E '^[[:space:]]*-w[[:space:]]+/etc/gshadow' "${AUDIT_RULES_FILE}"
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

**Prompt:** On a RHEL 8 system, ensure that any modifications to the account security file, which could indicate changes to stored password history, are logged by the audit system. This is important for detecting unauthorized changes to user authentication mechanisms. Write an idempotent bash remediation script that configures the audit system to capture and persistently log all write and attribute changes to this critical file, helping administrators track unauthorized account changes.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure auditing of modifications to /etc/security/opasswd
# (the account security file storing password history).
#
# Idempotent: only adds the rule if it is not already present.

set -euo pipefail

RULES_DIR="/etc/audit/rules.d"
RULES_FILE="${RULES_DIR}/audit.rules"
KEY="audit_rules_usergroup_modification"
WATCH_FILE="/etc/security/opasswd"

# The audit rule we want to ensure is present.
AUDIT_RULE="-w ${WATCH_FILE} -p wa -k ${KEY}"

# Ensure the rules directory exists.
mkdir -p "${RULES_DIR}"

# Ensure the persistent rules file exists.
if [ ! -f "${RULES_FILE}" ]; then
    touch "${RULES_FILE}"
    chmod 0640 "${RULES_FILE}"
fi

# Add the rule to the persistent rules file if it is not already present.
# Match on the file path and the -p wa flags to remain idempotent even if
# an existing rule uses a slightly different formatting.
if ! grep -Pq -- "^\s*-w\s+${WATCH_FILE}\s+-p\s+wa\s+-k\s+\S+" "${RULES_FILE}"; then
    printf '%s\n' "${AUDIT_RULE}" >> "${RULES_FILE}"
fi

# Also ensure the rule is present in the running audit configuration.
# Load rules if auditctl is available.
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load >/dev/null 2>&1 || true
elif command -v auditctl >/dev/null 2>&1; then
    if ! auditctl -l 2>/dev/null | grep -Pq -- "-w\s+${WATCH_FILE}\s+-p\s+wa"; then
        auditctl ${AUDIT_RULE} >/dev/null 2>&1 || true
    fi
fi

echo "Audit rule for ${WATCH_FILE} ensured in ${RULES_FILE}."
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

**Prompt:** On a RHEL 8 system, modify the auditing configuration to ensure that any changes to the /etc/passwd file, which can affect user or group information, are recorded. This includes writing to or attribute changes of the file. Write an idempotent bash remediation script that ensures auditd records these events persistently with an appropriate key for identification.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

AUDIT_RULES_DIR="/etc/audit/rules.d"
RULE_FILE="${AUDIT_RULES_DIR}/audit.rules"
KEY="audit_rules_usergroup_modification"
FILE_PATH="/etc/passwd"
RULE_LINE="-w ${FILE_PATH} -p wa -k ${KEY}"

# Ensure the rules directory exists
mkdir -p "${AUDIT_RULES_DIR}"

# Ensure the rule file exists
if [ ! -f "${RULE_FILE}" ]; then
    touch "${RULE_FILE}"
fi

# Remove any existing (possibly malformed) watch rules for the file to avoid duplicates
# then add the correct one, keeping the operation idempotent.
found=0
while IFS= read -r line; do
    # Match a watch rule for /etc/passwd regardless of exact spacing/options
    if echo "${line}" | grep -Eq "^-w[[:space:]]+${FILE_PATH}([[:space:]]|$)"; then
        found=1
    fi
done < "${RULE_FILE}"

if [ "${found}" -eq 0 ]; then
    echo "${RULE_LINE}" >> "${RULE_FILE}"
else
    # Verify the existing rule matches the desired one exactly; if not, normalize it.
    if ! grep -Fxq "${RULE_LINE}" "${RULE_FILE}"; then
        # Remove existing watch lines for the file and append the correct rule
        tmpfile="$(mktemp)"
        grep -Ev "^-w[[:space:]]+${FILE_PATH}([[:space:]]|$)" "${RULE_FILE}" > "${tmpfile}" || true
        echo "${RULE_LINE}" >> "${tmpfile}"
        cat "${tmpfile}" > "${RULE_FILE}"
        rm -f "${tmpfile}"
    fi
fi

# Load the new rules if auditd tools are available
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    auditctl "${RULE_LINE}" 2>/dev/null || true
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

**Prompt:** On a RHEL 8 system, ensure that any modifications to the /etc/shadow file are audited to help detect unauthorized changes to user and group information. Assume the default configuration using the 'augenrules' tool for audit rule management. Write an idempotent bash remediation script that configures the audit system to log write and attribute changes to the /etc/shadow file, ensuring that this configuration persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Audit modifications to /etc/shadow on RHEL 8 using augenrules.
#

set -euo pipefail

AUDIT_RULES_DIR="/etc/audit/rules.d"
RULE_FILE="${AUDIT_RULES_DIR}/audit_rules_for_ospp.rules"
WATCHED_FILE="/etc/shadow"
KEY="audit_rules_for_ospp"

# Ensure the audit rules directory exists
mkdir -p "${AUDIT_RULES_DIR}"

# Ensure the rules file exists
touch "${RULE_FILE}"

# Desired audit rule for write and attribute changes to /etc/shadow
DESIRED_RULE="-w ${WATCHED_FILE} -p wa -k ${KEY}"

# Idempotently add the rule if it does not already exist.
# Match any existing watch rule for /etc/shadow with -p wa regardless of key.
if ! grep -Eq "^[[:space:]]*-w[[:space:]]+${WATCHED_FILE}([[:space:]].*)?-p[[:space:]]+wa" "${RULE_FILE}" 2>/dev/null; then
    # Remove any stale/partial watch rules for /etc/shadow to avoid duplicates
    if grep -Eq "^[[:space:]]*-w[[:space:]]+${WATCHED_FILE}([[:space:]]|$)" "${RULE_FILE}" 2>/dev/null; then
        sed -i -E "\|^[[:space:]]*-w[[:space:]]+${WATCHED_FILE}([[:space:]]|$)|d" "${RULE_FILE}"
    fi
    echo "${DESIRED_RULE}" >> "${RULE_FILE}"
fi

# Load the new audit rules using augenrules
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
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

## RHEL-08-030490 — `audit_rules_dac_modification_chmod`

**Prompt:** On a RHEL 8 system, configure the audit daemon to log all events where file permissions are modified using the chmod command, specifically for sessions created by non-system users (users with a non-zero UID). This ensures changes in file discretionary access controls (DAC) are recorded for security monitoring. The solution should account for both 32-bit and 64-bit architectures if applicable and ensure these audit rules are persistent across reboots. Provide an idempotent bash remediation script to achieve this logging configuration.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation script: configure auditd to log all chmod-based DAC permission
# changes for non-system users (UID >= 1000), for both 32-bit and 64-bit
# architectures, persistently across reboots.

set -euo pipefail

RULES_FILE="/etc/audit/rules.d/perm_mod.rules"
AUDIT_DIR="/etc/audit/rules.d"

# Ensure the audit rules directory exists
if [ ! -d "$AUDIT_DIR" ]; then
    mkdir -p "$AUDIT_DIR"
fi

# Ensure the rules file exists
if [ ! -f "$RULES_FILE" ]; then
    touch "$RULES_FILE"
fi

# Determine the minimum UID for non-system (regular) users
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs 2>/dev/null || true)
if [ -z "${UID_MIN:-}" ]; then
    UID_MIN=1000
fi

# Detect architecture support
ARCHES=()
case "$(uname -m)" in
    x86_64|aarch64|ppc64|ppc64le|s390x)
        ARCHES=("b32" "b64")
        ;;
    i386|i486|i586|i686|armv7l)
        ARCHES=("b32")
        ;;
    *)
        # Fall back to attempting both; auditctl will ignore unsupported ones
        ARCHES=("b32" "b64")
        ;;
esac

# Build the desired rule lines
declare -a DESIRED_RULES=()
for arch in "${ARCHES[@]}"; do
    DESIRED_RULES+=("-a always,exit -F arch=${arch} -S chmod -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod")
done

# Idempotently add each rule if not already present
for rule in "${DESIRED_RULES[@]}"; do
    # Match on the significant parts (arch and syscall) to avoid duplicates
    arch=$(echo "$rule" | grep -oP 'arch=\K\S+')
    if ! grep -Eq -- "-a[[:space:]]+always,exit.*arch=${arch}.*-S[[:space:]]+chmod.*perm_mod" "$RULES_FILE"; then
        echo "$rule" >> "$RULES_FILE"
    fi
done

# Load the new rules into the running kernel and make persistent
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        case "$line" in
            \#*) continue ;;
        esac
        # shellcheck disable=SC2086
        auditctl $line 2>/dev/null || true
    done < "$RULES_FILE"
fi

# Restart auditd if it is running to ensure rules take effect
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet auditd 2>/dev/null; then
        service auditd restart 2>/dev/null || systemctl restart auditd 2>/dev/null || true
    fi
fi

echo "Audit rules for chmod DAC modifications configured in ${RULES_FILE}"
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

**Prompt:** On a RHEL 8 system, ensure that any modifications to file ownership are audited to detect unauthorized attempts to alter discretionary access controls (DAC), which could precede unauthorized access attempts. Write an idempotent bash remediation script that configures the audit system to log all "chown" operations by users with an audit user ID (auid) of 1000 or higher, excluding unset auids, for both 32-bit and 64-bit system architectures. The changes must take effect at every system startup.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

AUDIT_RULES_FILE="/etc/audit/rules.d/audit.rules"

# Ensure the rules directory and file exist
mkdir -p /etc/audit/rules.d
touch "$AUDIT_RULES_FILE"

# Define the audit rules for chown (64-bit and 32-bit)
RULE_B64="-a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=unset -F key=perm_mod"
RULE_B32="-a always,exit -F arch=b32 -S chown -F auid>=1000 -F auid!=unset -F key=perm_mod"

# Function to add a rule if not already present (idempotent)
add_rule() {
    local rule="$1"
    local arch_pattern="$2"

    # Check if an equivalent rule already exists (matching arch and chown syscall)
    if ! grep -Eq "^-a always,exit -F arch=${arch_pattern}.*-S[[:space:]]+chown([[:space:]]|,).*auid>=1000" "$AUDIT_RULES_FILE" 2>/dev/null \
       && ! grep -Fxq "$rule" "$AUDIT_RULES_FILE" 2>/dev/null; then
        echo "$rule" >> "$AUDIT_RULES_FILE"
    fi
}

add_rule "$RULE_B64" "b64"
add_rule "$RULE_B32" "b32"

# Load the new rules into the running audit system
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "$AUDIT_RULES_FILE" || true
fi

# Ensure auditd is enabled to apply rules at every startup
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
	SYSCALL="chown"
	KEY="perm_mod"
	SYSCALL_GROUPING="chown fchown fchownat lchown"

	# Perform the remediation for both possible 
```


---

## RHEL-08-030490 — `audit_rules_dac_modification_fchmod`

**Prompt:** On a RHEL 8 system, ensure that the audit logging service is configured to record all events where the discretionary access controls (DAC) of files are modified using the 'fchmod' syscall. This applies to all users with an audit user ID (auid) of 1000 or above, excluding unset values, across both 32-bit and 64-bit architectures on a 64-bit system. These audit rules should be consistently applied at startup and persist across reboots. Write an idempotent bash remediation script to configure the audit system accordingly.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULES_FILE="/etc/audit/rules.d/perm_mod.rules"

# Ensure auditd package is installed
if ! rpm -q audit >/dev/null 2>&1; then
    yum install -y audit
fi

# Ensure the rules file exists
touch "$RULES_FILE"

# Define the required audit rules
RULE_64='-a always,exit -F arch=b64 -S fchmod -F auid>=1000 -F auid!=unset -F key=perm_mod'
RULE_32='-a always,exit -F arch=b32 -S fchmod -F auid>=1000 -F auid!=unset -F key=perm_mod'

# Function to add a rule if it does not already exist (idempotent)
add_rule() {
    local rule="$1"
    local arch="$2"
    # Remove any existing fchmod rule for this architecture to avoid duplicates/inconsistencies
    if grep -Eq "^\s*-a\s+always,exit\s+.*-F\s+arch=${arch}\b.*\bfchmod\b" "$RULES_FILE"; then
        # Check if the exact rule already exists
        if ! grep -Fxq "$rule" "$RULES_FILE"; then
            # Remove the old matching lines
            sed -i -E "/^\s*-a\s+always,exit\s+.*-F\s+arch=${arch}\b.*\bfchmod\b/d" "$RULES_FILE"
            echo "$rule" >> "$RULES_FILE"
        fi
    else
        echo "$rule" >> "$RULES_FILE"
    fi
}

add_rule "$RULE_64" "b64"
add_rule "$RULE_32" "b32"

# Load the new rules if auditd is running
if systemctl is-active --quiet auditd 2>/dev/null || pgrep -x auditd >/dev/null 2>&1; then
    if command -v augenrules >/dev/null 2>&1; then
        augenrules --load || true
    else
        auditctl -R "$RULES_FILE" || true
    fi
fi

echo "Audit rules for fchmod DAC modifications have been configured."
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

**Prompt:** On a RHEL 8 system, configure the audit daemon to record all attempts to change file permissions using the 'fchmodat' system call. Ensure the audit covers all users with a user ID of 1000 or greater, excluding the unset user ID, for both 32-bit and, if applicable, 64-bit architectures of the kernel. This ensures the tracking of potential unauthorized permission changes, which helps identify conditions that might allow unauthorized data access. Write an idempotent bash remediation script to enforce this auditing configuration so that it is active at runtime and persists after reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULES_FILE="/etc/audit/rules.d/perm_mod.rules"

# Ensure the audit package is installed
if ! rpm -q audit >/dev/null 2>&1; then
    yum install -y audit
fi

# Ensure the rules directory exists
mkdir -p /etc/audit/rules.d
touch "$RULES_FILE"

# Determine architectures
declare -a ARCHES=("b32")
if [ "$(uname -m)" = "x86_64" ] || [ "$(uname -m)" = "aarch64" ] || [ "$(getconf LONG_BIT 2>/dev/null)" = "64" ]; then
    ARCHES+=("b64")
fi

for ARCH in "${ARCHES[@]}"; do
    RULE="-a always,exit -F arch=${ARCH} -S fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod"
    if ! grep -qF -- "-S fchmodat" "$RULES_FILE" 2>/dev/null | grep -q "arch=${ARCH}"; then
        :
    fi
    # Idempotently add the rule if not already present
    if ! grep -Eq -- "-a[[:space:]]+always,exit[[:space:]]+-F[[:space:]]+arch=${ARCH}.*-S[[:space:]]+fchmodat.*auid>=1000.*auid!=unset" "$RULES_FILE"; then
        echo "$RULE" >> "$RULES_FILE"
    fi
done

# Load the rules at runtime
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
else
    auditctl -R "$RULES_FILE" || true
fi

# Ensure auditd is enabled and running
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable auditd 2>/dev/null || true
    if systemctl is-active auditd >/dev/null 2>&1; then
        service auditd restart 2>/dev/null || systemctl restart auditd 2>/dev/null || true
    else
        systemctl start auditd 2>/dev/null || service auditd start 2>/dev/null || true
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

**Prompt:** On a RHEL 8 system, ensure that all instances of system calls that modify file ownership via the 'fchown' operation are audited for both 32-bit and 64-bit architectures, for users with an authenticated UID of 1000 or higher. The audit rule should ensure no actions by unset UIDs are missed, and it should be tagged with the key 'perm_mod'. Your task is to write an idempotent bash script that adds these audit rules such that they persist across reboots and are automatically loaded by the audit daemon at startup.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

AUDIT_RULES_FILE="/etc/audit/rules.d/perm_mod.rules"

RULE_64="-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=unset -F key=perm_mod"
RULE_32="-a always,exit -F arch=b32 -S fchown -F auid>=1000 -F auid!=unset -F key=perm_mod"

touch "$AUDIT_RULES_FILE"
chmod 0640 "$AUDIT_RULES_FILE"

add_rule_if_missing() {
    local rule="$1"
    if ! grep -Fxq "$rule" "$AUDIT_RULES_FILE"; then
        echo "$rule" >> "$AUDIT_RULES_FILE"
    fi
}

add_rule_if_missing "$RULE_64"
add_rule_if_missing "$RULE_32"

if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "$AUDIT_RULES_FILE" || true
fi

echo "Audit rules for fchown (perm_mod) have been configured."
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

**Prompt:** On a RHEL 8 system, ensure that all modifications to file permissions, specifically via the 'fchownat' syscall, are recorded in the audit logs. This should apply to all users with a user ID of 1000 or higher and not using the unset user ID. Both 32-bit and, if applicable, 64-bit architectures should be audited. The configuration must persist across reboots and should be set up to work with the default audit rules mechanism in place, whether it is 'augenrules' or 'auditctl'. Write an idempotent bash remediation script to achieve this for systems using both 32-bit and 64-bit architectures.

**Model-generated script:**
```bash
#!/usr/bin/env bash

# Determine which audit rules mechanism is in use
if [ -f /etc/audit/rules.d/audit.rules ] && grep -q '^\s*-D' /etc/audit/rules.d/audit.rules 2>/dev/null; then
    :
fi

# Determine if augenrules or auditctl is in use
if systemctl is-enabled auditd 2>/dev/null | grep -q enabled || [ -d /etc/audit/rules.d ]; then
    :
fi

# Detect the tool used
GROUP="perm_mod"

if grep -q 'augenrules' /usr/lib/systemd/system/auditd.service 2>/dev/null || \
   [ -d /etc/audit/rules.d ]; then
    RULES_FILE="/etc/audit/rules.d/${GROUP}.rules"
    USE_AUGENRULES=true
else
    RULES_FILE="/etc/audit/audit.rules"
    USE_AUGENRULES=false
fi

# Ensure the rules.d directory exists if using augenrules
if [ "$USE_AUGENRULES" = true ]; then
    mkdir -p /etc/audit/rules.d
fi

# Determine architectures
ARCHS=()
if [ "$(uname -m)" = "x86_64" ] || [ "$(uname -m)" = "aarch64" ] || [ "$(uname -m)" = "ppc64le" ] || [ "$(uname -m)" = "s390x" ]; then
    ARCHS+=("b32" "b64")
else
    ARCHS+=("b32")
fi

# Build the rules
declare -a RULES
for arch in "${ARCHS[@]}"; do
    RULES+=("-a always,exit -F arch=${arch} -S fchownat -F auid>=1000 -F auid!=unset -F key=${GROUP}")
done

# Function to ensure a rule exists in a file (idempotent)
ensure_rule() {
    local file="$1"
    local rule="$2"

    # Create file if it doesn't exist
    if [ ! -f "$file" ]; then
        touch "$file"
    fi

    # Normalize whitespace of the target rule for comparison
    local normalized_rule
    normalized_rule=$(echo "$rule" | tr -s ' ')

    # Check if an equivalent rule (matching fchownat + arch + auid) already exists
    local arch
    arch=$(echo "$rule" | grep -oP 'arch=\K[^ ]+')

    if grep -E -- "^-a always,exit.*-F arch=${arch}.*-S ([^ ]+,)*fchownat(,[^ ]+)*.*-F auid>=1000.*-F auid!=unset" "$file" >/dev/null 2>&1; then
        # Already present
        return 0
    fi

    # Append the rule
    echo "$rule" >> "$file"
}

for rule in "${RULES[@]}"; do
    ensure_rule "$RULES_FILE" "$rule"
done

# Reload audit rules
if [ "$USE_AUGENRULES" = true ]; then
    if command -v augenrules >/dev/null 2>&1; then
        augenrules --load >/dev/null 2>&1 || true
    fi
else
    if command -v auditctl >/dev/null 2>&1; then
        auditctl -R "$RULES_FILE" >/dev/null 2>&1 || true
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

**Prompt:** On a RHEL 8 system, ensure that any modifications to a file's extended attributes by either user-level or root actions are audited. This helps in identifying unauthorized access control changes. Write an idempotent bash remediation script that adds rules to audit the use of the "fremovexattr" syscall for all user IDs, including root, on both 32-bit and 64-bit architectures, if applicable. The script must ensure these audit rules persist through reboots whether the audit system is using augenrules or auditctl to load rules.

**Model-generated script:**
```bash
#!/usr/bin/env bash

# Determine the architecture(s) present on this system.
declare -a ARCHS=("b32")
if [[ "$(uname -m)" == "x86_64" || "$(uname -m)" == "aarch64" ]]; then
    ARCHS=("b32" "b64")
fi

# Build the list of audit rules we need for fremovexattr.
declare -a RULES
for ARCH in "${ARCHS[@]}"; do
    RULES+=("-a always,exit -F arch=${ARCH} -S fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod")
    RULES+=("-a always,exit -F arch=${ARCH} -S fremovexattr -F auid=0 -F key=perm_mod")
done

#############################################################
# Function: add a rule to a given file if not already present
#############################################################
add_rule_to_file() {
    local rule="$1"
    local file="$2"

    # Normalize whitespace for comparison
    local norm_rule
    norm_rule="$(echo "$rule" | sed -e 's/[[:space:]]\+/ /g' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"

    local found=0
    if [[ -f "$file" ]]; then
        while IFS= read -r line; do
            local norm_line
            norm_line="$(echo "$line" | sed -e 's/[[:space:]]\+/ /g' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
            if [[ "$norm_line" == "$norm_rule" ]]; then
                found=1
                break
            fi
        done < "$file"
    fi

    if [[ "$found" -eq 0 ]]; then
        echo "$rule" >> "$file"
    fi
}

#############################################################
# Handle augenrules layout
#############################################################
AUGEN_FILE="/etc/audit/rules.d/audit.rules"
PERM_FILE="/etc/audit/rules.d/perm_mod.rules"

if [[ -d /etc/audit/rules.d ]]; then
    # Use a dedicated rules file for clarity/idempotency
    touch "$PERM_FILE"
    chmod 0640 "$PERM_FILE"
    for rule in "${RULES[@]}"; do
        # Only add if not present in any rules.d file
        already=0
        norm_rule="$(echo "$rule" | sed -e 's/[[:space:]]\+/ /g' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
        for f in /etc/audit/rules.d/*.rules; do
            [[ -e "$f" ]] || continue
            while IFS= read -r line; do
                norm_line="$(echo "$line" | sed -e 's/[[:space:]]\+/ /g' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
                if [[ "$norm_line" == "$norm_rule" ]]; then
                    already=1
                    break
                fi
            done < "$f"
            [[ "$already" -eq 1 ]] && break
        done
        if [[ "$already" -eq 0 ]]; then
            echo "$rule" >> "$PERM_FILE"
        fi
    done
fi

#############################################################
# Handle auditctl layout (/etc/audit/audit.rules)
#############################################################
AUDITCTL_FILE="/etc/audit/audit.rules"
if [[ -f "$AUDITCTL_FILE" ]]; then
    for rule in "${RULES[@]}"; do
        add_rule_to_file "$rule" "$AUDITCTL_FILE"
    done
fi

#############################################################
# Attempt to reload the rules
#############################################################
if command -v augenrules >/dev/null 2>&1 && [[ -d /etc/audit/rules.d ]]; then
    augenrules --load >/dev/null 2>&1 || true
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "$AUDITCTL_FILE" >/dev/null 2>&1 || true
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
	SYSCALL="fremovexattr"
	KEY="perm_mod"
	SYSCALL_GROUPING="fremovexattr lremovexattr removexattr fsetxattr lsetxattr setxattr"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
```


---

## RHEL-08-030200 — `audit_rules_dac_modification_fsetxattr`

**Prompt:** On a RHEL 8 system, configure the audit system to record all events that involve Discretionary Access Control (DAC) modifications specifically when file extended attributes are set via 'fsetxattr'. Ensure that audit rules capture these events for all users with UID of 1000 or higher, excluding 'unset' users, and also for the root user, on both 32-bit and 64-bit architectures as applicable. Write an idempotent bash remediation script that implements these audit rules ensuring they persist across reboots and apply correctly based on the system's architecture.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Configure auditd rules to record DAC modifications via fsetxattr.
# Idempotent remediation script for RHEL 8.

set -euo pipefail

RULES_DIR="/etc/audit/rules.d"
RULES_FILE="${RULES_DIR}/dac_modification.rules"

# Ensure the audit rules directory exists
mkdir -p "${RULES_DIR}"

# Determine architecture(s)
ARCH_BITS="$(getconf LONG_BIT 2>/dev/null || echo 64)"

# Build the set of desired rules
declare -a DESIRED_RULES=()

# 64-bit architecture rules (only if system is 64-bit)
if [ "${ARCH_BITS}" = "64" ]; then
    DESIRED_RULES+=("-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod")
    DESIRED_RULES+=("-a always,exit -F arch=b64 -S fsetxattr -F auid=0 -F key=perm_mod")
fi

# 32-bit architecture rules (always applicable)
DESIRED_RULES+=("-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod")
DESIRED_RULES+=("-a always,exit -F arch=b32 -S fsetxattr -F auid=0 -F key=perm_mod")

# Create the rules file if it does not exist
if [ ! -f "${RULES_FILE}" ]; then
    touch "${RULES_FILE}"
    chmod 0640 "${RULES_FILE}"
fi

# Idempotently ensure each desired rule is present
for rule in "${DESIRED_RULES[@]}"; do
    if ! grep -qF -- "${rule}" "${RULES_FILE}" 2>/dev/null; then
        echo "${rule}" >> "${RULES_FILE}"
    fi
done

# Ensure correct permissions on the rules file
chmod 0640 "${RULES_FILE}"

# Load the new rules into the running kernel audit configuration
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    for rule in "${DESIRED_RULES[@]}"; do
        auditctl ${rule} 2>/dev/null || true
    done
fi

echo "Audit rules for fsetxattr DAC modifications have been configured in ${RULES_FILE}."
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

**Prompt:** On a RHEL 8 system, configure the audit system to track all events modifying discretionary access controls (DAC) through the use of the `lchown` syscall, to detect potential misuse or unauthorized attempts to alter file ownership. Ensure audit rules are applied to capture these events for users with an Audit User ID (AUID) of 1000 or higher, excluding unset AUIDs. If the system architecture is 64-bit, both 32-bit and 64-bit syscall architectures must be covered. Write an idempotent bash remediation script that adds and applies these audit rules persistently on system startup.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Configure auditd to track lchown syscall (DAC modification) events
# for AUID >= 1000, excluding unset AUIDs (4294967295).
# Idempotent remediation script for RHEL 8.

set -euo pipefail

RULES_FILE="/etc/audit/rules.d/perm_mod.rules"

# Ensure the rules directory exists
mkdir -p /etc/audit/rules.d

# Detect architecture
ARCH_BITS="$(getconf LONG_BIT 2>/dev/null || echo 32)"

# Build the list of rules we need
declare -a NEEDED_RULES=()

if [ "${ARCH_BITS}" = "64" ]; then
    NEEDED_RULES+=("-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=unset -F key=perm_mod")
    NEEDED_RULES+=("-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=unset -F key=perm_mod")
else
    NEEDED_RULES+=("-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=unset -F key=perm_mod")
fi

# Ensure the rules file exists
touch "${RULES_FILE}"

# Function to normalize a rule for comparison (collapse whitespace)
normalize() {
    echo "$1" | sed -e 's/[[:space:]]\+/ /g' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

# Add each needed rule if not already present (idempotent)
for rule in "${NEEDED_RULES[@]}"; do
    norm_rule="$(normalize "${rule}")"
    found=0
    while IFS= read -r line; do
        # Skip comments and blank lines
        case "${line}" in
            \#*|"") continue ;;
        esac
        norm_line="$(normalize "${line}")"
        if [ "${norm_line}" = "${norm_rule}" ]; then
            found=1
            break
        fi
    done < "${RULES_FILE}"

    if [ "${found}" -eq 0 ]; then
        echo "${rule}" >> "${RULES_FILE}"
    fi
done

# Apply the rules to the running audit system
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    for rule in "${NEEDED_RULES[@]}"; do
        # shellcheck disable=SC2086
        auditctl ${rule} 2>/dev/null || true
    done
fi

echo "Audit rules for lchown (DAC modification) have been configured and applied."
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

**Prompt:** On a RHEL 8 system, ensure that any changes to the system's discretionary access controls (DAC) are auditable, specifically tracking the removal of extended file attributes using the lremovexattr syscall. Write an idempotent bash remediation script that configures the audit daemon to capture these events for all users, including root, with appropriate audit rules. The rules must support both 32-bit and 64-bit architectures, log events for user IDs 1000 and above, and must persist across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure auditing of DAC changes via lremovexattr syscall
# Applies to RHEL 8, supporting both 32-bit and 64-bit architectures.
#

set -euo pipefail

AUDIT_RULES_DIR="/etc/audit/rules.d"
AUDIT_RULES_FILE="${AUDIT_RULES_DIR}/perm_mod.rules"

# Ensure the audit package is installed
if ! rpm -q audit >/dev/null 2>&1; then
    echo "The 'audit' package is not installed. Installing..."
    yum install -y audit
fi

# Ensure the rules directory exists
if [ ! -d "${AUDIT_RULES_DIR}" ]; then
    mkdir -p "${AUDIT_RULES_DIR}"
    chmod 0750 "${AUDIT_RULES_DIR}"
fi

# Ensure the rules file exists
if [ ! -f "${AUDIT_RULES_FILE}" ]; then
    touch "${AUDIT_RULES_FILE}"
    chmod 0640 "${AUDIT_RULES_FILE}"
fi

# Define required audit rules for both architectures
RULE_B64="-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod"
RULE_B32="-a always,exit -F arch=b32 -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod"

# Idempotently add the 64-bit rule
if ! grep -qE -- '^-a[[:space:]]+always,exit[[:space:]]+-F[[:space:]]+arch=b64([[:space:]].*)?-S[[:space:]]+lremovexattr' "${AUDIT_RULES_FILE}" 2>/dev/null; then
    echo "${RULE_B64}" >> "${AUDIT_RULES_FILE}"
    echo "Added 64-bit lremovexattr audit rule."
else
    echo "64-bit lremovexattr audit rule already present."
fi

# Idempotently add the 32-bit rule
if ! grep -qE -- '^-a[[:space:]]+always,exit[[:space:]]+-F[[:space:]]+arch=b32([[:space:]].*)?-S[[:space:]]+lremovexattr' "${AUDIT_RULES_FILE}" 2>/dev/null; then
    echo "${RULE_B32}" >> "${AUDIT_RULES_FILE}"
    echo "Added 32-bit lremovexattr audit rule."
else
    echo "32-bit lremovexattr audit rule already present."
fi

# Load the new rules into the running audit system
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
else
    echo "augenrules not found; attempting service reload."
fi

# Ensure auditd is enabled and running so rules persist and are active
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable auditd >/dev/null 2>&1 || true
    if ! systemctl is-active --quiet auditd; then
        service auditd start 2>/dev/null || systemctl start auditd 2>/dev/null || true
    fi
fi

echo "Remediation complete: lremovexattr DAC audit rules configured."
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

**Prompt:** On a RHEL 8 system, configure the audit daemon to record events that modify file permissions through the lsetxattr system call. The audit records should include both user and root actions, capturing attempts to change file attributes that may indicate unauthorized access attempts. Write an idempotent bash remediation script that adds these audit rules to capture 32-bit and, if applicable, 64-bit architecture calls, ensuring they persist across reboots and are applied consistently whether using augenrules or auditctl for rule management.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Record events that modify file attributes via lsetxattr
# Adds audit rules for 32-bit and 64-bit architectures, persistent and
# consistent for both augenrules and auditctl rule management.
#

set -u

# Determine machine architecture bitness
ARCH_BITS="$(getconf LONG_BIT 2>/dev/null)"

# Rule fragments for the lsetxattr syscall
declare -a RULES_64=(
    "-a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod"
    "-a always,exit -F arch=b64 -S lsetxattr -F auid=0 -F key=perm_mod"
)

declare -a RULES_32=(
    "-a always,exit -F arch=b32 -S lsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod"
    "-a always,exit -F arch=b32 -S lsetxattr -F auid=0 -F key=perm_mod"
)

# Build the full list of rules to apply based on architecture
declare -a ALL_RULES=()
if [ "$ARCH_BITS" = "64" ]; then
    ALL_RULES+=("${RULES_64[@]}")
fi
ALL_RULES+=("${RULES_32[@]}")

# --- Persist rules for augenrules (/etc/audit/rules.d/*.rules) ---
RULES_D_DIR="/etc/audit/rules.d"
RULES_D_FILE="${RULES_D_DIR}/perm_mod.rules"

mkdir -p "$RULES_D_DIR"
touch "$RULES_D_FILE"

for rule in "${ALL_RULES[@]}"; do
    # Idempotent: only add if an exact matching line is not present
    if ! grep -qF -- "$rule" "$RULES_D_FILE"; then
        printf '%s\n' "$rule" >> "$RULES_D_FILE"
    fi
done

# --- Persist rules for auditctl (/etc/audit/audit.rules) ---
AUDIT_RULES_FILE="/etc/audit/audit.rules"

if [ -f "$AUDIT_RULES_FILE" ]; then
    for rule in "${ALL_RULES[@]}"; do
        if ! grep -qF -- "$rule" "$AUDIT_RULES_FILE"; then
            printf '%s\n' "$rule" >> "$AUDIT_RULES_FILE"
        fi
    done
fi

# --- Load rules into the running kernel via auditctl ---
if command -v auditctl >/dev/null 2>&1; then
    # Get currently loaded rules once
    CURRENT_RULES="$(auditctl -l 2>/dev/null)"
    for rule in "${ALL_RULES[@]}"; do
        # auditctl -l normalizes output; check for the syscall+arch+auid signature.
        # Attempt to add; auditctl will reject duplicates harmlessly.
        if ! printf '%s\n' "$CURRENT_RULES" | grep -q "lsetxattr"; then
            auditctl $rule >/dev/null 2>&1 || true
        else
            # Rule with lsetxattr already present; still attempt idempotent add
            auditctl $rule >/dev/null 2>&1 || true
        fi
    done
fi

# --- Reload persistent rules if augenrules is available ---
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load >/dev/null 2>&1 || true
fi

echo "Audit rules for lsetxattr (perm_mod) have been configured."
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

**Prompt:** On a RHEL 8 system, configure the audit framework to log every action that removes extended attributes from files, as this indicates a change to discretionary access controls (DACs). Ensure this captures both root and non-root user actions. For non-root, all users with IDs >= 1000 and a defined user ID should be audited. This setup must apply at startup and must account for both 32-bit and 64-bit architectures. Write an idempotent bash remediation script that establishes and persists these rules, so the audit system logs all relevant attempts to alter these controls.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULES_FILE="/etc/audit/rules.d/audit.rules"

# Ensure the rules directory and file exist
mkdir -p /etc/audit/rules.d
touch "$RULES_FILE"

# Define the desired audit rules for removexattr / lremovexattr / fremovexattr
declare -a RULES=(
"-a always,exit -F arch=b32 -S removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod"
"-a always,exit -F arch=b32 -S removexattr,lremovexattr,fremovexattr -F auid=0 -F key=perm_mod"
"-a always,exit -F arch=b64 -S removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod"
"-a always,exit -F arch=b64 -S removexattr,lremovexattr,fremovexattr -F auid=0 -F key=perm_mod"
)

# Add each rule if not already present (idempotent)
for rule in "${RULES[@]}"; do
    if ! grep -qF -- "$rule" "$RULES_FILE"; then
        echo "$rule" >> "$RULES_FILE"
    fi
done

# Load the new rules into the running audit system if possible
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    for rule in "${RULES[@]}"; do
        auditctl $rule || true
    done
fi

# Ensure auditd is enabled to apply rules at startup
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable auditd 2>/dev/null || true
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

**Prompt:** On a RHEL 8 system, configure the audit subsystem to capture all events that modify a file's discretionary access controls (DAC) using the setxattr system call. This auditing should cover both 32-bit and 64-bit architectures, if applicable, and capture such events for all users, including root, who have an audit user ID (auid) of 1000 or greater, as well as for the root user (auid 0) specifically. Ensure these audit rules are persisting across reboots regardless of whether the system uses augenrules or auditctl to manage rules. Write an idempotent bash remediation script to implement these audit rules.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

# Determine architectures
ARCHES=()
if [[ "$(uname -m)" == "x86_64" || "$(uname -m)" == "aarch64" || "$(uname -m)" == "ppc64le" || "$(uname -m)" == "s390x" ]]; then
    ARCHES+=("b64" "b32")
else
    ARCHES+=("b32")
fi

RULES_FILE="/etc/audit/rules.d/perm_mod.rules"

# Build the list of desired rules
declare -a DESIRED_RULES=()
for ARCH in "${ARCHES[@]}"; do
    DESIRED_RULES+=("-a always,exit -F arch=${ARCH} -S setxattr -F auid>=1000 -F auid!=unset -F key=perm_mod")
    DESIRED_RULES+=("-a always,exit -F arch=${ARCH} -S setxattr -F auid=0 -F key=perm_mod")
done

# Ensure rules.d directory exists
mkdir -p /etc/audit/rules.d

# Ensure the rules file exists
touch "$RULES_FILE"

# Add each desired rule idempotently to the persistent rules file
for RULE in "${DESIRED_RULES[@]}"; do
    # Normalize whitespace for matching
    if ! grep -qxF "$RULE" "$RULES_FILE"; then
        # Check for equivalent rule using -k instead of -F key=
        ALT_RULE="${RULE/-F key=perm_mod/-k perm_mod}"
        if ! grep -qxF "$ALT_RULE" "$RULES_FILE"; then
            echo "$RULE" >> "$RULES_FILE"
        fi
    fi
done

# Also load rules into the running kernel via auditctl if available
if command -v auditctl >/dev/null 2>&1; then
    for RULE in "${DESIRED_RULES[@]}"; do
        # Check if the rule (or its equivalent) is already loaded
        LOADED="$(auditctl -l 2>/dev/null || true)"
        # Extract syscall/arch/auid fields for matching
        if ! echo "$LOADED" | grep -qF "$RULE"; then
            # Attempt to add; ignore failures for immutable configs
            auditctl $RULE 2>/dev/null || true
        fi
    done
fi

# If augenrules is present, regenerate the compiled rules
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load 2>/dev/null || true
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

**Prompt:** On a RHEL 8 system, ensure that any attempt to execute the `chacl` command is recorded by the system audit mechanism. This includes any execution by both regular users and the root user. Write an idempotent bash remediation script to configure the audit system to generate an audit record for each `chacl` run attempt, without being affected by whether the audit system uses `augenrules` or `auditctl`. This configuration should persist across daemon restarts and reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

# Determine the audit rule string for chacl
AUDIT_RULE="-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_mod"

# Determine which backend is in use
if grep -qE '^\s*augenrules' /etc/audit/rules.d/*.rules /etc/audit/auditd.conf 2>/dev/null; then
    :
fi

# Prefer augenrules approach; check which tool is active
if systemctl is-active --quiet auditd 2>/dev/null || true; then
    :
fi

# Decide whether augenrules is used
USE_AUGENRULES=false
if command -v augenrules >/dev/null 2>&1; then
    if [ -d /etc/audit/rules.d ]; then
        USE_AUGENRULES=true
    fi
fi

if [ "$USE_AUGENRULES" = true ]; then
    RULE_FILE="/etc/audit/rules.d/audit.rules"
    # Ensure the directory exists
    mkdir -p /etc/audit/rules.d

    # Remove any existing chacl rule to avoid duplicates, then add the correct one
    if [ -f "$RULE_FILE" ]; then
        grep -v -- '-F path=/usr/bin/chacl' "$RULE_FILE" > "${RULE_FILE}.tmp" || true
        mv "${RULE_FILE}.tmp" "$RULE_FILE"
    fi

    # Add rule if not present
    if ! grep -qF -- "$AUDIT_RULE" "$RULE_FILE" 2>/dev/null; then
        echo "$AUDIT_RULE" >> "$RULE_FILE"
    fi
else
    RULE_FILE="/etc/audit/audit.rules"

    # Remove any existing chacl rule to avoid duplicates
    if [ -f "$RULE_FILE" ]; then
        grep -v -- '-F path=/usr/bin/chacl' "$RULE_FILE" > "${RULE_FILE}.tmp" || true
        mv "${RULE_FILE}.tmp" "$RULE_FILE"
    fi

    # Add rule if not present
    if ! grep -qF -- "$AUDIT_RULE" "$RULE_FILE" 2>/dev/null; then
        echo "$AUDIT_RULE" >> "$RULE_FILE"
    fi
fi

# Reload audit rules to apply immediately
if command -v augenrules >/dev/null 2>&1 && [ "$USE_AUGENRULES" = true ]; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    auditctl "$AUDIT_RULE" 2>/dev/null || true
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

**Prompt:** On a RHEL 8 system, ensure that the use of the setfacl command is always audited for all users, including root, to maintain comprehensive security logging. This aids in establishing an audit trail for incidents involving permission changes. Write an idempotent bash remediation script that configures the audit daemon to record every execution attempt of the setfacl command, ensuring the settings are enforced at runtime and persist across system reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure execution of setfacl command is audited for all users
# (including root) on a RHEL 8 system.
#
# This configures auditd persistent rules and loads them at runtime.

set -euo pipefail

AUDIT_RULES_DIR="/etc/audit/rules.d"
RULE_FILE="${AUDIT_RULES_DIR}/privileged-setfacl.rules"
SETFACL_PATH="/usr/bin/setfacl"

# Determine architecture list; add both b32 and b64 rules where appropriate.
UNAME_M="$(uname -m)"

# Build the list of rules based on architecture.
declare -a RULES=()

if [[ "${UNAME_M}" == "x86_64" || "${UNAME_M}" == "aarch64" || "${UNAME_M}" == "ppc64le" || "${UNAME_M}" == "s390x" ]]; then
    # 64-bit systems: add both b64 and b32 rules for completeness.
    RULES+=("-a always,exit -F path=${SETFACL_PATH} -F perm=x -F auid>=1000 -F auid!=unset -F key=perm_mod")
    RULES+=("-a always,exit -F path=${SETFACL_PATH} -F perm=x -F auid=0 -F key=perm_mod")
else
    # 32-bit systems
    RULES+=("-a always,exit -F path=${SETFACL_PATH} -F perm=x -F auid>=1000 -F auid!=unset -F key=perm_mod")
    RULES+=("-a always,exit -F path=${SETFACL_PATH} -F perm=x -F auid=0 -F key=perm_mod")
fi

# Ensure the audit rules directory exists.
mkdir -p "${AUDIT_RULES_DIR}"

# Write the rules file idempotently.
{
    echo "## Auditing rules for the setfacl command"
    for r in "${RULES[@]}"; do
        echo "${r}"
    done
} > "${RULE_FILE}.tmp"

# Only replace the file if it differs (keeps idempotency clean).
if [[ ! -f "${RULE_FILE}" ]] || ! cmp -s "${RULE_FILE}.tmp" "${RULE_FILE}"; then
    mv -f "${RULE_FILE}.tmp" "${RULE_FILE}"
    chmod 0640 "${RULE_FILE}"
    RULES_CHANGED=1
else
    rm -f "${RULE_FILE}.tmp"
    RULES_CHANGED=0
fi

# Load the rules into the running kernel audit system so they take effect
# immediately at runtime (in addition to persisting across reboots).
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    for r in "${RULES[@]}"; do
        # auditctl uses the same syntax; add rule if not already present.
        auditctl ${r} 2>/dev/null || true
    done
fi

# If auditd is in immutable mode (-e 2), a reboot may be required for
# runtime enforcement. Inform accordingly, but rules will persist.
if command -v auditctl >/dev/null 2>&1; then
    if auditctl -s 2>/dev/null | grep -qw 'enabled 2'; then
        echo "NOTE: auditd is in immutable mode (enabled 2). A reboot is required for the new rules to take effect at runtime."
    fi
fi

echo "setfacl auditing configuration applied. Rules file: ${RULE_FILE}"
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

**Prompt:** On a RHEL 8 system, configure the audit daemon to record any execution attempts of the 'chcon' command by both normal users and root. It serves as a security measure to detect misuse of this privileged command, which if misused, can lead to unauthorized changes to SELinux context of files. Your task is to write an idempotent bash remediation script that ensures audit records are being generated for each use of chcon to capture such attempts, making certain they are applied consistently at both audit start and during ongoing operations. The audit must record the attempt specifically when triggered by users with an authenticated user ID (AUDIT_USR) greater than or equal to 1000, excluding unset & kernel logins.

**Model-generated script:**
```bash
#!/usr/bin/env bash

set -euo pipefail

RULES_FILE="/etc/audit/rules.d/privileged.rules"

# Determine UID_MIN from login.defs (fallback to 1000)
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs 2>/dev/null || true)
if [ -z "${UID_MIN:-}" ]; then
    UID_MIN=1000
fi

# The two required audit rules (b64 and b32)
RULE_B64="-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=${UID_MIN} -F auid!=unset -F key=privileged"
RULE_B32="-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=${UID_MIN} -F auid!=unset -F key=privileged"

# Ensure rules directory exists
mkdir -p /etc/audit/rules.d
touch "$RULES_FILE"

# Add architecture-specific rules idempotently
add_rule() {
    local arch="$1"
    local rule="-a always,exit -F arch=${arch} -F path=/usr/bin/chcon -F perm=x -F auid>=${UID_MIN} -F auid!=unset -F key=privileged"
    # Remove any existing chcon privileged rule for this arch to avoid duplicates/staleness
    if ! grep -qF -- "$rule" "$RULES_FILE"; then
        echo "$rule" >> "$RULES_FILE"
    fi
}

# Clean up any prior chcon privileged rules to keep file consistent
grep -v -E 'path=/usr/bin/chcon.*key=privileged' "$RULES_FILE" > "${RULES_FILE}.tmp" || true
mv "${RULES_FILE}.tmp" "$RULES_FILE"

# Determine supported architectures
if [ "$(uname -m)" = "x86_64" ] || [ "$(getconf LONG_BIT 2>/dev/null)" = "64" ]; then
    add_rule "b64"
    add_rule "b32"
else
    add_rule "b32"
fi

# Apply rules to the running audit system
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        auditctl $line || true
    done < "$RULES_FILE"
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

**Prompt:** On a RHEL 8 system, ensure that any execution attempt of the 'semanage' command by any user, including root, is recorded by the audit system. The goal is to monitor and audit the use of this privileged command to detect potential misuse or unauthorized access attempts. Write an idempotent bash remediation script that configures the audit system to log every execution attempt of the 'semanage' command and ensure this logging is in effect at all times, persisting across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

SEMANAGE_PATH="/usr/sbin/semanage"
AUDIT_RULES_DIR="/etc/audit/rules.d"
RULE_FILE="${AUDIT_RULES_DIR}/privileged.rules"

# Ensure the audit rules directory exists
if [ ! -d "${AUDIT_RULES_DIR}" ]; then
    mkdir -p "${AUDIT_RULES_DIR}"
fi

# Ensure the rule file exists
touch "${RULE_FILE}"

# Determine architecture-specific handling.
# The semanage command should be audited on both 32-bit and 64-bit systems.
declare -a ARCH_LIST=()
if [ "$(uname -m)" = "x86_64" ] || [ "$(uname -m)" = "aarch64" ]; then
    ARCH_LIST=("b32" "b64")
else
    ARCH_LIST=("b32")
fi

# The desired audit rule for semanage
KEY="privileged"

for ARCH in "${ARCH_LIST[@]}"; do
    RULE="-a always,exit -F arch=${ARCH} -F path=${SEMANAGE_PATH} -F perm=x -F auid>=1000 -F auid!=unset -k ${KEY}"
    # Check if a matching rule (path + arch) already exists in the file
    if ! grep -Eq -- "-F path=${SEMANAGE_PATH}(\s|$).*-F arch=${ARCH}" "${RULE_FILE}" 2>/dev/null && \
       ! grep -Eq -- "-F arch=${ARCH}(\s|$).*-F path=${SEMANAGE_PATH}" "${RULE_FILE}" 2>/dev/null; then
        echo "${RULE}" >> "${RULE_FILE}"
    fi
done

# Load the new rules into the running kernel audit system if possible
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    for ARCH in "${ARCH_LIST[@]}"; do
        auditctl -a always,exit -F arch=${ARCH} -F path=${SEMANAGE_PATH} -F perm=x -F auid>=1000 -F auid!=unset -k ${KEY} 2>/dev/null || true
    done
fi

# If auditd is in immutable mode, changes require a reboot; notify accordingly.
if command -v auditctl >/dev/null 2>&1; then
    if auditctl -s 2>/dev/null | grep -q "enabled 2"; then
        echo "Audit system is in immutable mode (enabled 2). A reboot is required for rule changes to take effect."
    fi
fi

# Ensure auditd service is enabled so rules persist across reboots
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable auditd >/dev/null 2>&1 || true
fi

echo "semanage execution auditing has been configured."
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

**Prompt:** On a RHEL 8 system, ensure that every attempt to execute the 'setfiles' command is logged by the audit system. This is crucial to detect and investigate potential misuse of the command, which could indicate insider threats or compromised accounts. Write an idempotent bash remediation script that configures the audit daemon to record all execution attempts of 'setfiles', capturing them for both normal users and the root user, and ensuring that these audit settings are applied persistently.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure all execution attempts of the 'setfiles' command are audited.
#

set -euo pipefail

AUDIT_RULES_DIR="/etc/audit/rules.d"
RULE_FILE="${AUDIT_RULES_DIR}/privileged.rules"
BINARY="/usr/sbin/setfiles"

# Ensure the audit package/tools are present
if ! rpm -q audit >/dev/null 2>&1; then
    yum install -y audit
fi

# Ensure rules directory exists
mkdir -p "${AUDIT_RULES_DIR}"

# Determine architecture-specific rules to add
ARCH_LIST=()
case "$(uname -m)" in
    x86_64|aarch64|ppc64|ppc64le|s390x)
        ARCH_LIST=("b32" "b64")
        ;;
    i686|i386|armv7l)
        ARCH_LIST=("b32")
        ;;
    *)
        ARCH_LIST=("b32" "b64")
        ;;
esac

# Build the audit rules
declare -a RULES=()
for arch in "${ARCH_LIST[@]}"; do
    RULES+=("-a always,exit -F arch=${arch} -F path=${BINARY} -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged-setfiles")
done

# Ensure the rule file exists
touch "${RULE_FILE}"

# Add each rule idempotently
for rule in "${RULES[@]}"; do
    if ! grep -qF -- "-F path=${BINARY} -F perm=x" "${RULE_FILE}" 2>/dev/null | grep -q "$(echo "${rule}" | grep -o 'arch=[^ ]*')"; then
        :
    fi
    # More robust idempotent check: match arch and path together
    arch_token=$(echo "${rule}" | grep -o 'arch=[^ ]*')
    if ! grep -F -- "-F path=${BINARY} -F perm=x" "${RULE_FILE}" 2>/dev/null | grep -qF -- "${arch_token}"; then
        echo "${rule}" >> "${RULE_FILE}"
    fi
done

# Set proper permissions on the rule file
chmod 0640 "${RULE_FILE}"
chown root:root "${RULE_FILE}"

# Load the new rules into the running audit system persistently
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
fi

# Attempt to reload audit daemon rules
if command -v auditctl >/dev/null 2>&1; then
    auditctl -R "${RULE_FILE}" 2>/dev/null || true
fi

# Restart auditd through service manager if possible (auditd can't be restarted via systemctl directly on RHEL)
if command -v service >/dev/null 2>&1; then
    service auditd restart 2>/dev/null || true
else
    systemctl kill --signal=SIGHUP auditd 2>/dev/null || true
fi

echo "Audit rules for 'setfiles' have been configured in ${RULE_FILE}."
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

**Prompt:** On a RHEL 8 system, ensure any attempt by a user to run the 'setsebool' command is logged for audit purposes. This logging must capture the execution by all non-system users and always trigger an audit event when the command is executed, providing a security measure to monitor misuse and potential attacks. Write an idempotent bash remediation script to configure the audit system such that attempts to execute 'setsebool' are recorded, ensuring the configuration persists across system reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure execution of 'setsebool' command is audited for all
# non-system users (UID >= 1000) on a RHEL 8 system.
#
set -euo pipefail

RULES_DIR="/etc/audit/rules.d"
RULES_FILE="${RULES_DIR}/privileged.rules"
AUDIT_BIN="/usr/sbin/setsebool"
KEY="privileged-priv_change"

# Determine the minimum UID for non-system (regular) users
if [ -f /etc/login.defs ]; then
    UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
fi
UID_MIN="${UID_MIN:-1000}"

# Ensure the audit package is installed
if ! rpm -q audit >/dev/null 2>&1; then
    yum install -y audit
fi

# Ensure the rules directory exists
mkdir -p "${RULES_DIR}"
touch "${RULES_FILE}"

# Build the desired audit rules (both 64-bit and 32-bit architectures)
declare -a DESIRED_RULES=(
    "-a always,exit -F path=${AUDIT_BIN} -F perm=x -F auid>=${UID_MIN} -F auid!=unset -F key=${KEY}"
)

# Add each rule idempotently
for RULE in "${DESIRED_RULES[@]}"; do
    # Remove any existing rule for this binary path to avoid duplicates/mismatches
    if grep -Eq "path=${AUDIT_BIN}([[:space:]]|$)" "${RULES_FILE}"; then
        # Only remove lines referencing this exact binary path
        sed -i "\|path=${AUDIT_BIN}[[:space:]]|d" "${RULES_FILE}"
        sed -i "\|path=${AUDIT_BIN}\$|d" "${RULES_FILE}"
    fi
done

# Append the desired rule(s) freshly
for RULE in "${DESIRED_RULES[@]}"; do
    if ! grep -Fxq "${RULE}" "${RULES_FILE}"; then
        echo "${RULE}" >> "${RULES_FILE}"
    fi
done

# Set safe permissions on the rules file
chmod 0640 "${RULES_FILE}"
chown root:root "${RULES_FILE}"

# Reload the audit rules to make them effective now and persist across reboots
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
else
    auditctl -R "${RULES_FILE}" || true
fi

# If auditd is running under systemd and requires a restart to apply
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet auditd; then
        # augenrules --load is preferred; a service restart is only needed
        # if auditd is in immutable mode. Attempt a graceful reload/restart.
        service auditd restart 2>/dev/null || systemctl restart auditd 2>/dev/null || true
    fi
fi

echo "Audit rule for ${AUDIT_BIN} has been configured successfully."
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

**Prompt:** On a RHEL 8 system, ensure that the auditd service collects events related to file deletions to maintain a comprehensive audit trail. Specifically, configure the audit rules to capture all file rename operations performed by processes with a user ID of 1000 or higher, excluding those unset, and set a key for these events as 'delete'. This configuration will help detect unauthorized or malicious file deletions, such as logs, and aid in forensic analysis. Write an idempotent bash remediation script that applies these audit rules persistently across reboots, accounting for both potential audit rule management methods.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure auditd collects file deletion (rename) events
# for processes with UID >= 1000 (excluding unset -1), keyed as 'delete'.
#

set -o pipefail

# Determine architecture-specific rules that need to be present.
# We cover both 32-bit and 64-bit syscalls for rename operations.
declare -a AUDIT_RULES

# Detect if system supports 64-bit (b64) syscalls.
if [[ "$(uname -m)" == "x86_64" || "$(uname -m)" == "aarch64" || "$(uname -m)" == "ppc64le" || "$(uname -m)" == "s390x" ]]; then
    AUDIT_RULES+=("-a always,exit -F arch=b32 -S rename,unlink,unlinkat,renameat -F auid>=1000 -F auid!=unset -F key=delete")
    AUDIT_RULES+=("-a always,exit -F arch=b64 -S rename,unlink,unlinkat,renameat -F auid>=1000 -F auid!=unset -F key=delete")
else
    AUDIT_RULES+=("-a always,exit -F arch=b32 -S rename,unlink,unlinkat,renameat -F auid>=1000 -F auid!=unset -F key=delete")
fi

# Function to normalize a rule for comparison (collapse whitespace).
normalize_rule() {
    echo "$1" | tr -s '[:space:]' ' ' | sed 's/^ *//;s/ *$//'
}

########################################################################
# Method 1: augenrules (rules under /etc/audit/rules.d/*.rules)
########################################################################
RULES_D_DIR="/etc/audit/rules.d"
TARGET_RULE_FILE="${RULES_D_DIR}/delete.rules"

if [[ -d "$RULES_D_DIR" ]] || command -v augenrules >/dev/null 2>&1; then
    mkdir -p "$RULES_D_DIR"

    for RULE in "${AUDIT_RULES[@]}"; do
        NORM_RULE="$(normalize_rule "$RULE")"
        FOUND=0

        # Search all existing rule files for an equivalent rule.
        while IFS= read -r -d '' file; do
            while IFS= read -r line; do
                [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
                if [[ "$(normalize_rule "$line")" == "$NORM_RULE" ]]; then
                    FOUND=1
                    break
                fi
            done < "$file"
            [[ "$FOUND" -eq 1 ]] && break
        done < <(find "$RULES_D_DIR" -maxdepth 1 -type f -name '*.rules' -print0 2>/dev/null)

        if [[ "$FOUND" -eq 0 ]]; then
            echo "$RULE" >> "$TARGET_RULE_FILE"
        fi
    done

    # Load the rules if augenrules is available.
    if command -v augenrules >/dev/null 2>&1; then
        augenrules --load >/dev/null 2>&1
    fi
fi

########################################################################
# Method 2: auditctl direct file (/etc/audit/audit.rules)
########################################################################
AUDIT_RULES_FILE="/etc/audit/audit.rules"

if [[ -f "$AUDIT_RULES_FILE" ]]; then
    for RULE in "${AUDIT_RULES[@]}"; do
        NORM_RULE="$(normalize_rule "$RULE")"
        FOUND=0

        while IFS= read -r line; do
            [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
            if [[ "$(normalize_rule "$line")" == "$NORM_RULE" ]]; then
                FOUND=1
                break
            fi
        done < "$AUDIT_RULES_FILE"

        if [[ "$FOUND" -eq 0 ]]; then
            echo "$RULE" >> "$AUDIT_RULES_FILE"
        fi
    done
fi

########################################################################
# Load rules into the running kernel (idempotent).
########################################################################
if command -v auditctl >/dev/null 2>&1; then
    for RULE in "${AUDIT_RULES[@]}"; do
        # Check if the rule is already loaded.
        NORM_RULE="$(normalize_rule "$RULE")"
        LOADED=0
        while IFS= read -r line; do
            if [[ "$(normalize_rule "$line")" == "$NORM_RULE" ]]; then
                LOADED=1
                break
            fi
        done < <(auditctl -l 2>/dev/null)

        if [[ "$LOADED" -eq 0 ]]; then
            # shellcheck disable=SC2086
            auditctl $RULE >/dev/null 2>&1
        fi
    done
fi

echo "Audit rules for file deletion (key=delete) have been applied."
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

**Prompt:** On a RHEL 8 system, configure the audit daemon to record every file deletion event, specifically ones performed using the renameat system call, for all non-system users (UID >= 1000). Non-system users should not include those with unset user identifiers. This ensures a comprehensive audit trail to trace deletions, aid in troubleshooting, and detect attempts to erase log files. Write an idempotent bash remediation script that ensures this audit rule is present and persists across reboots, regardless of whether the system uses augenrules or auditctl for audit rule initialization.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: audit every file deletion via renameat for non-system users
# (UID >= 1000, excluding unset -1 audit UID).
#
# This script is idempotent and supports both augenrules and auditctl
# rule loading tools.

set -euo pipefail

# Determine the correct architecture(s) to build rules for.
# Detect whether the system supports both 32-bit and 64-bit syscalls.
declare -a ARCHS
if [ "$(getconf LONG_BIT)" = "64" ]; then
    ARCHS=("b32" "b64")
else
    ARCHS=("b32")
fi

# Build the audit rule content for each architecture.
build_rules() {
    local rules=""
    for arch in "${ARCHS[@]}"; do
        rules+="-a always,exit -F arch=${arch} -S renameat -F auid>=1000 -F auid!=unset -F key=delete"$'\n'
    done
    printf '%s' "$rules"
}

RULE_CONTENT="$(build_rules)"

# ---------------------------------------------------------------------------
# Handle augenrules (persistent rule files in /etc/audit/rules.d/)
# ---------------------------------------------------------------------------
RULES_D="/etc/audit/rules.d"
RULES_FILE="${RULES_D}/delete.rules"

mkdir -p "$RULES_D"

# Ensure each required rule line is present in some file under rules.d.
# We use a canonical file and normalize/deduplicate the desired rule.
while IFS= read -r line; do
    [ -z "$line" ] && continue

    # Check if the exact rule already exists in any rules.d file.
    found=0
    if [ -d "$RULES_D" ]; then
        while IFS= read -r existing_file; do
            if grep -Fxq -- "$line" "$existing_file" 2>/dev/null; then
                found=1
                break
            fi
        done < <(find "$RULES_D" -maxdepth 1 -type f -name '*.rules' 2>/dev/null)
    fi

    if [ "$found" -eq 0 ]; then
        printf '%s\n' "$line" >> "$RULES_FILE"
    fi
done <<< "$RULE_CONTENT"

# ---------------------------------------------------------------------------
# Handle auditctl (persistent rules in /etc/audit/audit.rules)
# ---------------------------------------------------------------------------
AUDIT_RULES="/etc/audit/audit.rules"

if [ -f "$AUDIT_RULES" ] || command -v auditctl >/dev/null 2>&1; then
    touch "$AUDIT_RULES"
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        if ! grep -Fxq -- "$line" "$AUDIT_RULES" 2>/dev/null; then
            printf '%s\n' "$line" >> "$AUDIT_RULES"
        fi
    done <<< "$RULE_CONTENT"
fi

# ---------------------------------------------------------------------------
# Load rules into the running kernel audit subsystem (best effort).
# ---------------------------------------------------------------------------
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load >/dev/null 2>&1 || true
elif command -v auditctl >/dev/null 2>&1; then
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        # Only add if not already present in the running config.
        if ! auditctl -l 2>/dev/null | grep -Fq -- "-S renameat"; then
            # shellcheck disable=SC2086
            auditctl $line >/dev/null 2>&1 || true
        fi
    done <<< "$RULE_CONTENT"
fi

echo "Audit rule for renameat deletion events (UID>=1000) has been configured."
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

**Prompt:** On a RHEL 8 system, ensure that all file deletion events carried out by users, including root, are being audited by the audit daemon. This includes tracking the use of the "rmdir" syscall by users with a user ID (UID) of 1000 and above, as well as by the root account. Write an idempotent bash remediation script to enforce auditing of these events and ensure the configuration is persistent across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULES_FILE="/etc/audit/rules.d/audit.rules"

# Ensure the rules directory and file exist
mkdir -p /etc/audit/rules.d
touch "$RULES_FILE"

# Define the audit rules for file deletion events via rmdir syscall
declare -a RULES=(
    "-a always,exit -F arch=b32 -S rmdir -F auid>=1000 -F auid!=unset -F key=delete"
    "-a always,exit -F arch=b64 -S rmdir -F auid>=1000 -F auid!=unset -F key=delete"
    "-a always,exit -F arch=b32 -S rmdir -F auid=0 -F key=delete"
    "-a always,exit -F arch=b64 -S rmdir -F auid=0 -F key=delete"
)

# Add each rule if it is not already present (idempotent)
for RULE in "${RULES[@]}"; do
    if ! grep -qF -- "$RULE" "$RULES_FILE"; then
        echo "$RULE" >> "$RULES_FILE"
    fi
done

# Load the new rules
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
else
    auditctl -R "$RULES_FILE" || true
fi

echo "Audit rules for rmdir file deletion events have been configured."
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

**Prompt:** On a RHEL 8 system, ensure that the audit daemon is configured to collect file deletion events performed by non-system users. This involves capturing these events using the appropriate system architecture (either b32 or b64). Write an idempotent bash remediation script that configures the audit system to record file deletion attempts (unlink) by users with an auid of 1000 or greater and that are not unset. The configuration should persist across system reboots and align with default audit rule reading using augenrules.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULES_FILE="/etc/audit/rules.d/delete.rules"

# Determine system architecture support
if [ "$(uname -m)" = "x86_64" ] || [ "$(uname -m)" = "aarch64" ] || [ "$(uname -m)" = "ppc64le" ] || [ "$(uname -m)" = "s390x" ]; then
    ARCHES=("b32" "b64")
else
    ARCHES=("b32")
fi

# Ensure rules directory exists
mkdir -p /etc/audit/rules.d

# Ensure the rules file exists
touch "$RULES_FILE"

for ARCH in "${ARCHES[@]}"; do
    RULE="-a always,exit -F arch=${ARCH} -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=unset -F key=delete"
    # Check if an equivalent rule already exists (matching arch and delete key with unlink)
    if ! grep -qE -- "^-a always,exit -F arch=${ARCH} .*-S unlink.*-F auid>=1000 -F auid!=unset -F key=delete" "$RULES_FILE"; then
        echo "$RULE" >> "$RULES_FILE"
    fi
done

# Load the rules using augenrules if the daemon is present
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
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

**Prompt:** On a RHEL 8 system, ensure that the audit subsystem records all file deletions initiated by users to create an audit trail, which helps in troubleshooting and potentially detecting malicious activity. Specifically, configure the audit daemon to capture unlinkat system calls for all users with a user ID of 1000 and above, ensuring the settings apply to both 32-bit and 64-bit architectures as needed. Write an idempotent bash remediation script to apply these auditing rules so that they persist across service restarts and system reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation script: Record file deletions (unlinkat) by users with UID >= 1000
# Idempotent: safe to run multiple times.
#

set -euo pipefail

RULES_FILE="/etc/audit/rules.d/delete.rules"

# Ensure the audit rules directory exists
mkdir -p /etc/audit/rules.d

# Detect architectures present on the system
declare -a ARCHES=()
if [ "$(uname -m)" = "x86_64" ] || [ "$(uname -m)" = "aarch64" ] || [ "$(uname -m)" = "ppc64le" ] || [ "$(uname -m)" = "s390x" ]; then
    ARCHES+=("b64")
    ARCHES+=("b32")
else
    ARCHES+=("b32")
fi

# Build the desired rules
declare -a DESIRED_RULES=()
for arch in "${ARCHES[@]}"; do
    DESIRED_RULES+=("-a always,exit -F arch=${arch} -S unlinkat -F auid>=1000 -F auid!=unset -F key=delete")
done

# Create the rules file if it does not exist
touch "$RULES_FILE"

# Add each desired rule if not already present (idempotent)
for rule in "${DESIRED_RULES[@]}"; do
    # Match on the essential fields to avoid duplicates regardless of ordering/spacing
    arch_field=$(echo "$rule" | grep -oE 'arch=b[0-9]+')
    if ! grep -Eq "unlinkat" "$RULES_FILE" 2>/dev/null || \
       ! grep -Eq -- "-S unlinkat" "$RULES_FILE" 2>/dev/null || \
       ! grep -Eq -- "$arch_field" "$RULES_FILE" 2>/dev/null || \
       ! grep -E -- "-S unlinkat" "$RULES_FILE" 2>/dev/null | grep -q -- "$arch_field"; then
        # Only add if the exact combination (arch + unlinkat) is missing
        if ! grep -E -- "-S unlinkat" "$RULES_FILE" 2>/dev/null | grep -q -- "$arch_field"; then
            echo "$rule" >> "$RULES_FILE"
        fi
    fi
done

# Load rules into the running audit system to make them active immediately
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    for rule in "${DESIRED_RULES[@]}"; do
        auditctl $rule 2>/dev/null || true
    done
fi

# Ensure auditd is enabled and running so rules persist and are active
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable auditd 2>/dev/null || true
    if systemctl is-active --quiet auditd; then
        # auditd cannot be restarted with systemctl on RHEL; use service reload
        service auditd restart 2>/dev/null || systemctl restart auditd 2>/dev/null || true
    else
        systemctl start auditd 2>/dev/null || service auditd start 2>/dev/null || true
    fi
fi

echo "Audit rules for unlinkat (UID >= 1000) have been applied."
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

**Prompt:** On a RHEL 8 system, ensure that all unsuccessful attempts to create files using the `creat` system call are recorded for users with user IDs 1000 or higher, excluding system accounts, to detect potential unauthorized access attempts. This auditing must apply to both 32-bit and 64-bit architectures if the system supports them. Write an idempotent bash remediation script that configures the audit subsystem to capture and log such events, ensuring the new audit rules persist across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULES_FILE="/etc/audit/rules.d/access.rules"

# Ensure audit package is present
if ! rpm -q audit &>/dev/null; then
    yum install -y audit
fi

# Ensure the rules directory exists
mkdir -p /etc/audit/rules.d
touch "$RULES_FILE"

# Determine if the system supports 64-bit
ARCH_BITS=""
if [ "$(getconf LONG_BIT)" = "64" ]; then
    ARCH_BITS="b64 b32"
else
    ARCH_BITS="b32"
fi

# Build the desired rules for the creat syscall with EACCES and EPERM errors
declare -a DESIRED_RULES=()
for arch in $ARCH_BITS; do
    DESIRED_RULES+=("-a always,exit -F arch=${arch} -S creat -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access")
    DESIRED_RULES+=("-a always,exit -F arch=${arch} -S creat -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access")
done

# Add each rule idempotently
for rule in "${DESIRED_RULES[@]}"; do
    if ! grep -qF -- "$rule" "$RULES_FILE"; then
        echo "$rule" >> "$RULES_FILE"
    fi
done

# Load the new rules
if command -v augenrules &>/dev/null; then
    augenrules --load
else
    auditctl -R "$RULES_FILE" || true
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

**Prompt:** On a RHEL 8 system, ensure the audit system collects all unsuccessful attempts to use the 'ftruncate' system call as these attempts might indicate malicious activity. For users with a user ID of 1000 or higher, configure the audit subsystem to log any 'ftruncate' calls that result in access errors, both -EACCES and -EPERM, with separate audit keys. This configuration must account for both 32-bit and 64-bit architectures and persist across reboots. Write an idempotent bash remediation script that correctly sets up these audit rules.

**Model-generated script:**
```bash
#!/usr/bin/env bash

set -euo pipefail

RULES_FILE="/etc/audit/rules.d/audit.rules"

# Ensure the audit rules directory and file exist
mkdir -p /etc/audit/rules.d
touch "$RULES_FILE"

# Define the required audit rules
declare -a REQUIRED_RULES=(
"-a always,exit -F arch=b32 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access"
"-a always,exit -F arch=b32 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access"
"-a always,exit -F arch=b64 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access"
"-a always,exit -F arch=b64 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access"
)

# Function to check if an equivalent rule already exists (order-independent for the key fields)
rule_exists() {
    local arch="$1"
    local exitcode="$2"
    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// }" ]] && continue
        # Must be an ftruncate rule with the correct arch and exit code
        if echo "$line" | grep -qw -- "-S ftruncate" \
            && echo "$line" | grep -qw -- "arch=${arch}" \
            && echo "$line" | grep -qw -- "exit=${exitcode}" \
            && echo "$line" | grep -qw -- "auid>=1000" \
            && echo "$line" | grep -qw -- "-k access"; then
            return 0
        fi
    done < "$RULES_FILE"
    return 1
}

# Add missing rules
add_rule() {
    local arch="$1"
    local exitcode="$2"
    local rule="$3"
    if ! rule_exists "$arch" "$exitcode"; then
        echo "$rule" >> "$RULES_FILE"
    fi
}

add_rule "b32" "-EACCES" "-a always,exit -F arch=b32 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access"
add_rule "b32" "-EPERM"  "-a always,exit -F arch=b32 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access"
add_rule "b64" "-EACCES" "-a always,exit -F arch=b64 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access"
add_rule "b64" "-EPERM"  "-a always,exit -F arch=b64 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access"

# Load the new rules into the running audit system
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    for rule in "${REQUIRED_RULES[@]}"; do
        auditctl $rule 2>/dev/null || true
    done
fi

echo "Audit rules for ftruncate configured successfully."
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

**Prompt:** On a RHEL 8 system, ensure the auditing system captures unauthorized file access attempts using the 'open' syscall. This is crucial for detecting potential malicious activity or system compromises. Write an idempotent bash remediation script that configures the audit daemon to log all unsuccessful file access attempts (both EPERM and EACCES errors) by users with IDs 1000 or higher, on both 32-bit and 64-bit architectures, ensuring this auditing persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

AUDIT_RULES_DIR="/etc/audit/rules.d"
RULES_FILE="${AUDIT_RULES_DIR}/access.rules"

# Ensure the audit rules directory exists
mkdir -p "${AUDIT_RULES_DIR}"

# Define the required audit rules for unsuccessful 'open' syscall attempts
declare -a REQUIRED_RULES=(
"-a always,exit -F arch=b32 -S open -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access"
"-a always,exit -F arch=b32 -S open -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access"
"-a always,exit -F arch=b64 -S open -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access"
"-a always,exit -F arch=b64 -S open -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access"
)

# Create the rules file if it does not exist
touch "${RULES_FILE}"
chmod 0640 "${RULES_FILE}"

# Idempotently add each rule if not already present
for rule in "${REQUIRED_RULES[@]}"; do
    # Match on the essential parameters regardless of ordering/spacing
    arch=$(echo "$rule" | grep -oP 'arch=b\d+')
    exit_code=$(echo "$rule" | grep -oP 'exit=-E[A-Z]+')

    if ! grep -Eq -- "-S[[:space:]]+open" "${RULES_FILE}" 2>/dev/null || \
       ! grep -Eq -- "${arch}.*-S[[:space:]]+open.*${exit_code}|${arch}.*${exit_code}.*-S[[:space:]]+open|-S[[:space:]]+open.*${arch}.*${exit_code}" "${RULES_FILE}" 2>/dev/null; then
        # Verify this specific arch+exit combination is missing
        if ! grep -E -- "${arch}" "${RULES_FILE}" 2>/dev/null | grep -E -- "${exit_code}" | grep -Eq -- "-S[[:space:]]+open"; then
            echo "${rule}" >> "${RULES_FILE}"
        fi
    fi
done

# Load the new rules into the running audit system
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    for rule in "${REQUIRED_RULES[@]}"; do
        auditctl ${rule} 2>/dev/null || true
    done
fi

# Ensure auditd is enabled and running so rules persist across reboots
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable auditd 2>/dev/null || true
    if ! systemctl is-active --quiet auditd; then
        service auditd restart 2>/dev/null || systemctl restart auditd 2>/dev/null || true
    fi
fi

echo "Audit rules for unsuccessful 'open' syscall attempts have been configured."
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

**Prompt:** On a RHEL 8 system, configure the audit system to log all unauthorized file access attempts using the 'open_by_handle_at' system call by users with an audit user ID (auid) of 1000 or greater, excluding cases where the auid is unset. This includes unsuccessful attempts that result in specific error codes indicating access denial. Your idempotent bash remediation script should work for both 32-bit and 64-bit architectures, ensure persistent configuration across reboots, and target instances where the 'augenrules' program is in use to load audit rules during daemon startup.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Configure auditd to log unauthorized access attempts via open_by_handle_at
# for auid>=1000 (excluding unset auid), covering EACCES and EPERM errors.
# Idempotent, works for augenrules (rules.d).

set -o pipefail

RULES_FILE="/etc/audit/rules.d/access.rules"

# Ensure the rules.d directory exists
mkdir -p /etc/audit/rules.d

# Determine architecture support
declare -a ARCHES
if [ "$(uname -m)" = "x86_64" ] || [ "$(uname -m)" = "aarch64" ] || [ "$(uname -m)" = "ppc64le" ] || [ "$(uname -m)" = "s390x" ]; then
    ARCHES=("b32" "b64")
else
    ARCHES=("b32")
fi

# Build the desired rules
declare -a DESIRED_RULES
for ARCH in "${ARCHES[@]}"; do
    DESIRED_RULES+=("-a always,exit -F arch=${ARCH} -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access")
    DESIRED_RULES+=("-a always,exit -F arch=${ARCH} -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access")
done

# Create the rules file if it does not exist
touch "$RULES_FILE"

# Add each desired rule if not already present (idempotent)
for RULE in "${DESIRED_RULES[@]}"; do
    # Escape special regex characters for a fixed-string search
    if ! grep -qF -- "$RULE" "$RULE_CHECK_FILE" 2>/dev/null && ! grep -qF -- "$RULE" "$RULES_FILE"; then
        echo "$RULE" >> "$RULES_FILE"
    fi
done

# Load the rules if augenrules is present
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load >/dev/null 2>&1 || true
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

**Prompt:** On a RHEL 8 system, ensure that any unsuccessful attempts to open files using the 'openat' system call are audited, as these could signal malicious activity. This involves setting audit rules for both 32-bit and 64-bit architectures to track unauthorized access attempts for all users with UID 1000 or higher, except for unset UIDs, and capture events where operations result in 'Permission denied' or 'Access denied' errors. Write an idempotent bash remediation script that configures these audit rules to be enforced persistently across system reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash

# Remediation script to audit unsuccessful 'openat' system call attempts
# for both 32-bit and 64-bit architectures on RHEL 8.

set -euo pipefail

AUDIT_RULES_DIR="/etc/audit/rules.d"
AUDIT_RULES_FILE="${AUDIT_RULES_DIR}/audit.rules"
TARGET_FILE="${AUDIT_RULES_DIR}/access.rules"

# Ensure the audit rules directory exists
mkdir -p "${AUDIT_RULES_DIR}"

# Define the required rules
declare -a REQUIRED_RULES=(
    "-a always,exit -F arch=b32 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access"
    "-a always,exit -F arch=b32 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access"
    "-a always,exit -F arch=b64 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access"
    "-a always,exit -F arch=b64 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access"
)

# Ensure the target rules file exists
touch "${TARGET_FILE}"

# Add each required rule if not already present (idempotent)
for RULE in "${REQUIRED_RULES[@]}"; do
    # Build a grep pattern that matches the rule regardless of duplicate whitespace
    if ! grep -Pq -- "^\s*-a\s+always,exit\s+-F\s+arch=$(echo "${RULE}" | grep -oP 'arch=\K\w+')\s+-S\s+openat\s+-F\s+exit=$(echo "${RULE}" | grep -oP 'exit=\K[-A-Z]+')\s+-F\s+auid>=1000\s+-F\s+auid!=unset\s+-k\s+access\s*$" "${TARGET_FILE}" 2>/dev/null; then
        echo "${RULE}" >> "${TARGET_FILE}"
    fi
done

# Remove any duplicate lines from the target file to keep it clean
if [ -f "${TARGET_FILE}" ]; then
    awk '!seen[$0]++' "${TARGET_FILE}" > "${TARGET_FILE}.tmp" && mv "${TARGET_FILE}.tmp" "${TARGET_FILE}"
fi

# Set secure permissions on the rules file
chmod 0640 "${TARGET_FILE}"

# Load the new rules to enforce them and ensure persistence across reboots
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    for RULE in "${REQUIRED_RULES[@]}"; do
        auditctl ${RULE} 2>/dev/null || true
    done
fi

echo "Audit rules for unsuccessful 'openat' attempts have been configured."
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

**Prompt:** On a RHEL 8 system, configure the audit subsystem to log all unsuccessful attempts by non-system users to use the 'truncate' system call, which may indicate malicious activity. The auditing should include both 32-bit and 64-bit architectures if applicable. Write an idempotent bash remediation script to ensure these audit rules are enforced, and verify they persist across reboots and daemon restarts.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure unsuccessful truncate attempts by non-system users are audited.
# Idempotent: safe to run multiple times.
#
set -euo pipefail

RULES_FILE="/etc/audit/rules.d/50-truncate.rules"
AUDITCTL="/sbin/auditctl"
AUGENRULES="/sbin/augenrules"

# Determine UID_MIN (start of non-system users) from login.defs, default 1000.
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs 2>/dev/null | head -n1)
if [[ -z "${UID_MIN:-}" ]]; then
    UID_MIN=1000
fi

# Detect supported architectures.
ARCHS=()
# 64-bit is present on x86_64 / aarch64 etc.
if [[ "$(uname -m)" == "x86_64" || "$(uname -m)" == "aarch64" || "$(uname -m)" == "ppc64le" || "$(uname -m)" == "s390x" ]]; then
    ARCHS+=("b64")
    # 32-bit compat typically available on x86_64
    if [[ "$(uname -m)" == "x86_64" ]]; then
        ARCHS+=("b32")
    fi
else
    # Assume 32-bit only system.
    ARCHS+=("b32")
fi

# Build the desired rule set.
declare -a DESIRED_RULES=()
for arch in "${ARCHS[@]}"; do
    DESIRED_RULES+=("-a always,exit -F arch=${arch} -S truncate,ftruncate -F exit=-EACCES -F auid>=${UID_MIN} -F auid!=unset -k perm_mod")
    DESIRED_RULES+=("-a always,exit -F arch=${arch} -S truncate,ftruncate -F exit=-EPERM -F auid>=${UID_MIN} -F auid!=unset -k perm_mod")
done

# Ensure rules.d directory exists.
mkdir -p /etc/audit/rules.d

# Write the rules file idempotently.
TMPFILE="$(mktemp)"
{
    echo "## Audit unsuccessful truncate/ftruncate attempts by non-system users"
    for rule in "${DESIRED_RULES[@]}"; do
        echo "$rule"
    done
} > "$TMPFILE"

if [[ ! -f "$RULES_FILE" ]] || ! cmp -s "$TMPFILE" "$RULES_FILE"; then
    install -m 0640 "$TMPFILE" "$RULES_FILE"
    echo "Updated ${RULES_FILE}"
else
    echo "${RULES_FILE} already up to date"
fi
rm -f "$TMPFILE"

# Load rules into the running kernel (persist across daemon restarts via rules.d).
if command -v "$AUGENRULES" >/dev/null 2>&1; then
    "$AUGENRULES" --load >/dev/null 2>&1 || true
fi

# Ensure the running configuration has our rules; add any missing live rules.
if command -v "$AUDITCTL" >/dev/null 2>&1; then
    CURRENT="$("$AUDITCTL" -l 2>/dev/null || true)"
    for rule in "${DESIRED_RULES[@]}"; do
        # Normalize comparison by checking key components.
        if ! echo "$CURRENT" | grep -q "truncate"; then
            "$AUDITCTL" $rule >/dev/null 2>&1 || true
        fi
    done
fi

# Verify persistence: rules file exists and augenrules can regenerate.
if [[ -f "$RULES_FILE" ]]; then
    echo "Persistent audit rules present in ${RULES_FILE}:"
    grep -v '^\s*#' "$RULES_FILE" | grep -v '^\s*$' || true
fi

# Report currently loaded matching rules.
if command -v "$AUDITCTL" >/dev/null 2>&1; then
    echo "Currently loaded truncate audit rules:"
    "$AUDITCTL" -l 2>/dev/null | grep -i truncate || echo "  (none loaded; a reboot or 'augenrules --load' may be required)"
fi

echo "Remediation complete."
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

**Prompt:** On a RHEL 8 system, configure the audit subsystem to record any occurrence of kernel module unloading via the 'delete_module' syscall. This audit rule should apply to users with a user ID of 1000 or higher, excluding unset user IDs, using the appropriate architecture setting for your system. The rule must persist so ‘auditd’ enforces it on reboot, regardless of whether your system uses 'augenrules' or 'auditctl' for loading audit rules. Write an idempotent bash remediation script to achieve this.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

# Determine architecture bits for the syscall rule
if [ "$(getconf LONG_BIT)" = "32" ]; then
    ARCHS="b32"
else
    ARCHS="b32 b64"
fi

# Build the audit rule(s)
build_rules() {
    local rules=""
    for arch in $ARCHS; do
        rules="${rules}-a always,exit -F arch=${arch} -S delete_module -F auid>=1000 -F auid!=unset -F key=modules"$'\n'
    done
    printf '%s' "$rules"
}

RULES_CONTENT="$(build_rules)"

########################################
# Handle augenrules-style config
########################################
AUGEN_DIR="/etc/audit/rules.d"
AUGEN_FILE="${AUGEN_DIR}/modules.rules"

mkdir -p "$AUGEN_DIR"

# Remove any existing delete_module rules from all rules.d files to avoid duplicates
if ls "${AUGEN_DIR}"/*.rules >/dev/null 2>&1; then
    for f in "${AUGEN_DIR}"/*.rules; do
        if grep -q "delete_module" "$f" 2>/dev/null; then
            sed -i '/-S[[:space:]].*delete_module\|delete_module/d' "$f"
        fi
    done
fi

# Ensure our rules are present in the dedicated file (idempotent)
touch "$AUGEN_FILE"
# Remove any stale delete_module lines from our file first
sed -i '/delete_module/d' "$AUGEN_FILE"

while IFS= read -r line; do
    [ -z "$line" ] && continue
    if ! grep -qF -- "$line" "$AUGEN_FILE"; then
        printf '%s\n' "$line" >> "$AUGEN_FILE"
    fi
done <<< "$RULES_CONTENT"

########################################
# Handle auditctl-style config
########################################
AUDITCTL_FILE="/etc/audit/audit.rules"

if [ -f "$AUDITCTL_FILE" ]; then
    # Remove existing delete_module lines to avoid duplicates
    sed -i '/delete_module/d' "$AUDITCTL_FILE"

    while IFS= read -r line; do
        [ -z "$line" ] && continue
        if ! grep -qF -- "$line" "$AUDITCTL_FILE"; then
            printf '%s\n' "$line" >> "$AUDITCTL_FILE"
        fi
    done <<< "$RULES_CONTENT"
fi

########################################
# Load rules into the running kernel
########################################
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        auditctl $line 2>/dev/null || true
    done <<< "$RULES_CONTENT"
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

## RHEL-08-030360 — `audit_rules_kernel_module_loading_finit`

**Prompt:** On a RHEL 8 system, ensure the `auditd` daemon collects audit records for all actions involving the loading and unloading of kernel modules via the `finit_module` system call. This information is critical for detecting potential unauthorized changes to the kernel's behavior. Write an idempotent bash remediation script that configures `auditd` to capture these events for users with a non-system account (UID >= 1000), and ensures these audit rules are enforced on reboot.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULES_FILE="/etc/audit/rules.d/50-kernel_modules.rules"
KEY="modules"

# Determine architecture(s) to cover
declare -a ARCHES=()
case "$(uname -m)" in
    x86_64|aarch64|ppc64|ppc64le|s390x)
        ARCHES=(b64 b32)
        ;;
    *)
        ARCHES=(b32)
        ;;
esac

# Build the desired rule lines
declare -a DESIRED_RULES=()
for arch in "${ARCHES[@]}"; do
    DESIRED_RULES+=("-a always,exit -F arch=${arch} -S finit_module -F auid>=1000 -F auid!=unset -k ${KEY}")
done

# Ensure the rules directory exists
mkdir -p /etc/audit/rules.d

# Create the file if it does not exist
if [[ ! -f "$RULES_FILE" ]]; then
    touch "$RULES_FILE"
fi

# Add each desired rule if not already present (idempotent)
for rule in "${DESIRED_RULES[@]}"; do
    if ! grep -Fxq -- "$rule" "$RULES_FILE"; then
        echo "$rule" >> "$RULES_FILE"
    fi
done

# Set safe permissions on the rules file
chmod 0640 "$RULES_FILE"
chown root:root "$RULES_FILE"

# Load the rules into the running audit system
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    for rule in "${DESIRED_RULES[@]}"; do
        # shellcheck disable=SC2086
        auditctl $rule 2>/dev/null || true
    done
fi

echo "auditd rules for finit_module have been configured in ${RULES_FILE}."
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

**Prompt:** On a RHEL 8 system, ensure that any loading of kernel modules is audited to capture potentially malicious code introduction into the kernel space. Audit rule(s) must log all invocations of the system call that initiates the loading of a kernel module, distinguishing events by user ID to exclude system services (auid>=1000 and auid!=unset). Write an idempotent bash remediation script that configures the audit system to persistently log these events for both 32-bit (b32) and 64-bit (b64) architectures.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULES_FILE="/etc/audit/rules.d/50-kernel_modules_loading.rules"

# Desired audit rules
RULE_B32="-a always,exit -F arch=b32 -S init_module -F auid>=1000 -F auid!=unset -k modules"
RULE_B64="-a always,exit -F arch=b64 -S init_module -F auid>=1000 -F auid!=unset -k modules"

# Ensure the rules directory exists
mkdir -p /etc/audit/rules.d

# Create the rules file if it does not exist
touch "$RULES_FILE"

# Add b32 rule if not already present
if ! grep -qF -- "$RULE_B32" "$RULES_FILE"; then
    echo "$RULE_B32" >> "$RULES_FILE"
fi

# Add b64 rule if not already present
if ! grep -qF -- "$RULE_B64" "$RULES_FILE"; then
    echo "$RULE_B64" >> "$RULES_FILE"
fi

# Load the rules into the running audit system
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    auditctl "$RULE_B32" || true
    auditctl "$RULE_B64" || true
fi
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

**Prompt:** On a RHEL 8 system, configure the audit daemon to monitor and log attempts to manually edit files related to logon and logout events, which may indicate malicious activity such as an intruder trying to erase traces of an attack. Write an idempotent bash remediation script that ensures any manual edits to these sensitive files are captured and logged, regardless of whether the audit daemon uses the augenrules program or the auditctl utility. The script must persist this configuration across system reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Configure auditd to monitor manual edits to logon/logout related files.
# Idempotent remediation supporting both augenrules and auditctl backends.

set -o pipefail

# The audit rules we want to ensure are present.
# Monitoring session/login tracking files.
AUDIT_RULES=(
    "-w /var/log/lastlog -p wa -k logins"
    "-w /var/run/faillock -p wa -k logins"
)

# Determine which backend auditd uses.
if grep -qE '^\s*ExecStartPost\s*=.*augenrules' /usr/lib/systemd/system/auditd.service 2>/dev/null; then
    USE_AUGENRULES=1
else
    USE_AUGENRULES=0
fi

# Files for persistence.
RULES_D_FILE="/etc/audit/rules.d/logins.rules"
AUDIT_RULES_FILE="/etc/audit/audit.rules"

ensure_rule_in_file() {
    local rule="$1"
    local file="$2"

    # Create directory/file if needed.
    local dir
    dir="$(dirname "$file")"
    [ -d "$dir" ] || mkdir -p "$dir"
    [ -f "$file" ] || touch "$file"

    # Add rule if not already present (exact match, ignoring surrounding whitespace).
    if ! grep -qxF "$rule" "$file"; then
        # Remove any partial/duplicate lines matching the same key path to keep it clean.
        printf '%s\n' "$rule" >> "$file"
    fi
}

if [ "$USE_AUGENRULES" -eq 1 ]; then
    TARGET_FILE="$RULES_D_FILE"
else
    TARGET_FILE="$AUDIT_RULES_FILE"
fi

for rule in "${AUDIT_RULES[@]}"; do
    ensure_rule_in_file "$rule" "$TARGET_FILE"
done

# Set proper permissions on the rules file.
chmod 0640 "$TARGET_FILE" 2>/dev/null || true

# Load the rules into the running kernel audit system.
if command -v augenrules >/dev/null 2>&1 && [ "$USE_AUGENRULES" -eq 1 ]; then
    augenrules --load >/dev/null 2>&1 || true
elif command -v auditctl >/dev/null 2>&1; then
    for rule in "${AUDIT_RULES[@]}"; do
        # Only add if not already loaded.
        if ! auditctl -l 2>/dev/null | grep -qF "$(echo "$rule" | sed 's/^-w //; s/ -p.*//')"; then
            auditctl $rule >/dev/null 2>&1 || true
        fi
    done
fi

exit 0
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

**Prompt:** On a RHEL 8 system, enhance the security logging by ensuring that any attempts to manually alter login and logout event records, particularly involving files storing logon events, are audited. This helps in identifying potentially nefarious activity by capturing attempts to delete logs or evidence. Write an idempotent bash remediation script to ensure the audit system tracks write and attribute change attempts on files related to storing logon events, and persistently configures this monitoring across reboots, irrespective of the audit rule loading mechanism.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Audit attempts to alter logon/logout event records
# Monitors write and attribute change access to files storing logon events:
#   /var/log/lastlog  and  /var/run/faillock
#

set -o pipefail

# Determine the correct group id filter based on running kernel arch
# (not strictly needed for these rules, but keep the standard structure)

# Files/dirs storing logon events and their watch keys
declare -A WATCHES
WATCHES["/var/log/lastlog"]="logins"
WATCHES["/var/run/faillock"]="logins"

# ---------------------------------------------------------------------------
# Part 1: Persistent rules for augenrules (/etc/audit/rules.d/*.rules)
# ---------------------------------------------------------------------------

RULES_D_FILE="/etc/audit/rules.d/logins.rules"

fix_rules_file() {
    local file="$1"
    local path="$2"
    local key="$3"
    local rule="-w ${path} -p wa -k ${key}"

    # Create the file if it does not exist
    if [ ! -e "$file" ]; then
        touch "$file"
        chmod 0640 "$file"
    fi

    # Idempotent check: is there already a rule watching this path with wa?
    if ! grep -Pq -- "^\s*-w\s+${path}\s+-p\s+wa\s+-k\s+\S+\s*$" "$file"; then
        # Remove any incomplete/incorrect watch on this path first
        sed -i "\#^\s*-w\s\+${path}\s#d" "$file"
        echo "$rule" >> "$file"
    fi
}

# ---------------------------------------------------------------------------
# Part 2: Live/loaded rules for auditctl (/etc/audit/audit.rules)
# ---------------------------------------------------------------------------

AUDITCTL_FILE="/etc/audit/audit.rules"

fix_auditctl_file() {
    local file="$1"
    local path="$2"
    local key="$3"
    local rule="-w ${path} -p wa -k ${key}"

    if [ ! -e "$file" ]; then
        touch "$file"
        chmod 0640 "$file"
    fi

    if ! grep -Pq -- "^\s*-w\s+${path}\s+-p\s+wa\s+-k\s+\S+\s*$" "$file"; then
        sed -i "\#^\s*-w\s\+${path}\s#d" "$file"
        echo "$rule" >> "$file"
    fi
}

# ---------------------------------------------------------------------------
# Apply for each monitored path
# ---------------------------------------------------------------------------

for path in "${!WATCHES[@]}"; do
    key="${WATCHES[$path]}"
    fix_rules_file "$RULES_D_FILE" "$path" "$key"
    fix_auditctl_file "$AUDITCTL_FILE" "$path" "$key"
done

# ---------------------------------------------------------------------------
# Part 3: Load the rules into the running kernel audit system
# ---------------------------------------------------------------------------

if command -v augenrules >/dev/null 2>&1; then
    augenrules --load >/dev/null 2>&1 || true
elif command -v auditctl >/dev/null 2>&1; then
    for path in "${!WATCHES[@]}"; do
        key="${WATCHES[$path]}"
        auditctl -w "$path" -p wa -k "$key" >/dev/null 2>&1 || true
    done
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

**Prompt:** On a RHEL 8 system, configure the system audit daemon to collect audit records for the execution of all privileged commands, specifically focusing on the use of the kmod command. The audit system must be set to capture command execution for all non-root users (with user IDs 1000 or higher) while excluding system accounts. Ensure the configuration is compatible with the use of augenrules or auditctl and persists across reboots. Write an idempotent bash remediation script to achieve this.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure auditd collects execution of the kmod privileged command
# for all non-root users (UID >= 1000), excluding system accounts.
#
# Compatible with both augenrules (/etc/audit/rules.d/*.rules) and
# auditctl (/etc/audit/audit.rules).

set -euo pipefail

# Path to the kmod binary
KMOD_PATH="/usr/bin/kmod"

# Determine the minimum UID for non-system (login) users
if [ -f /etc/login.defs ]; then
    UID_MIN=$(awk '/^\s*UID_MIN\s+/{print $2; exit}' /etc/login.defs)
fi
# Fall back to 1000 if UID_MIN could not be determined
if [ -z "${UID_MIN:-}" ]; then
    UID_MIN=1000
fi

# The audit rule to enforce
AUDIT_RULE="-a always,exit -F path=${KMOD_PATH} -F perm=x -F auid>=${UID_MIN} -F auid!=unset -F key=privileged"

# Regex used to detect an existing (possibly slightly different) rule for kmod
# so we can avoid duplicates and update as needed.
match_line() {
    # Matches any always,exit rule referencing the kmod path
    grep -Eq "^-a[[:space:]]+always,exit.*-F[[:space:]]+path=${KMOD_PATH}([[:space:]]|$)" "$1" 2>/dev/null
}

#
# 1) Handle the augenrules layout (/etc/audit/rules.d/)
#
RULES_D_DIR="/etc/audit/rules.d"
RULES_D_FILE="${RULES_D_DIR}/privileged.rules"

if [ -d "${RULES_D_DIR}" ]; then
    # Remove any existing kmod rule lines across all *.rules files in rules.d
    for f in "${RULES_D_DIR}"/*.rules; do
        [ -e "$f" ] || continue
        if match_line "$f"; then
            sed -i -E "\|^-a[[:space:]]+always,exit.*-F[[:space:]]+path=${KMOD_PATH}([[:space:]]\|\$)|d" "$f"
        fi
    done

    # Ensure the target rules file exists
    if [ ! -e "${RULES_D_FILE}" ]; then
        touch "${RULES_D_FILE}"
        chmod 0640 "${RULES_D_FILE}"
    fi

    # Add the correct rule if it is not already present
    if ! grep -Fxq "${AUDIT_RULE}" "${RULES_D_FILE}"; then
        echo "${AUDIT_RULE}" >> "${RULES_D_FILE}"
    fi
fi

#
# 2) Handle the auditctl layout (/etc/audit/audit.rules)
#
AUDIT_RULES_FILE="/etc/audit/audit.rules"

if [ -e "${AUDIT_RULES_FILE}" ]; then
    # Remove existing kmod rule lines to avoid duplicates
    if match_line "${AUDIT_RULES_FILE}"; then
        sed -i -E "\|^-a[[:space:]]+always,exit.*-F[[:space:]]+path=${KMOD_PATH}([[:space:]]\|\$)|d" "${AUDIT_RULES_FILE}"
    fi

    # Add the correct rule if it is not already present
    if ! grep -Fxq "${AUDIT_RULE}" "${AUDIT_RULES_FILE}"; then
        echo "${AUDIT_RULE}" >> "${AUDIT_RULES_FILE}"
    fi
fi

#
# 3) Load the new rules into the running kernel where possible
#
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load >/dev/null 2>&1 || true
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "${AUDIT_RULES_FILE}" >/dev/null 2>&1 || true
fi

echo "Audit rule for ${KMOD_PATH} (auid>=${UID_MIN}) configured successfully."
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

**Prompt:** On a RHEL 8 system, ensure that the audit daemon is set up to collect audit records whenever any user (other than system accounts) or root executes privileged commands using the postdrop utility. This setup is important to detect potential misuse of privileges and to monitor for insider threats or privilege-escalation attacks. Write an idempotent bash remediation script that ensures audit records are collected for the execution of the postdrop command, persisting across reboots. Confirm compliance using either default augenrules or an alternative auditctl-based configuration, ensuring the audit rule targets executions with effective user IDs greater than or equal to 1000 and not unset.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

# Determine the correct architecture-independent rule for postdrop
# postdrop is typically located at /usr/sbin/postdrop
POSTDROP_PATH="/usr/sbin/postdrop"
if [ ! -e "$POSTDROP_PATH" ]; then
    # Try to locate it if not in default location
    ALT_PATH="$(command -v postdrop 2>/dev/null || true)"
    if [ -n "$ALT_PATH" ]; then
        POSTDROP_PATH="$ALT_PATH"
    fi
fi

RULE="-a always,exit -F path=${POSTDROP_PATH} -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged"

# Determine whether the system uses augenrules or auditctl
if [ -x /sbin/augenrules ] || command -v augenrules >/dev/null 2>&1; then
    # augenrules-based configuration
    RULES_DIR="/etc/audit/rules.d"
    RULES_FILE="${RULES_DIR}/privileged.rules"
    mkdir -p "$RULES_DIR"

    # Remove any existing postdrop rules to avoid duplicates
    if [ -f "$RULES_FILE" ]; then
        grep -v -- "-F path=${POSTDROP_PATH}" "$RULES_FILE" > "${RULES_FILE}.tmp" 2>/dev/null || true
        mv "${RULES_FILE}.tmp" "$RULES_FILE"
    fi

    # Also clean up any postdrop rules in other rule files
    for f in "${RULES_DIR}"/*.rules; do
        [ -e "$f" ] || continue
        [ "$f" = "$RULES_FILE" ] && continue
        if grep -q -- "-F path=${POSTDROP_PATH}" "$f" 2>/dev/null; then
            grep -v -- "-F path=${POSTDROP_PATH}" "$f" > "${f}.tmp" 2>/dev/null || true
            mv "${f}.tmp" "$f"
        fi
    done

    # Add the rule
    echo "$RULE" >> "$RULES_FILE"

    # Regenerate audit rules
    if command -v augenrules >/dev/null 2>&1; then
        augenrules --load || true
    fi
else
    # auditctl-based configuration
    RULES_FILE="/etc/audit/audit.rules"

    if [ -f "$RULES_FILE" ]; then
        grep -v -- "-F path=${POSTDROP_PATH}" "$RULES_FILE" > "${RULES_FILE}.tmp" 2>/dev/null || true
        mv "${RULES_FILE}.tmp" "$RULES_FILE"
    fi

    echo "$RULE" >> "$RULES_FILE"

    # Load the rule into the running kernel if auditctl available
    if command -v auditctl >/dev/null 2>&1; then
        auditctl "$RULE" 2>/dev/null || true
    fi
fi

echo "Audit rule for postdrop privileged command execution has been configured."
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

**Prompt:** On a RHEL 8 system, ensure that the system audit daemon is configured to collect audit logs for the execution of the privileged command `postqueue` by all users (except for system users) and the root user. This is to detect and mitigate potential misuse of privileged functions. Write an idempotent bash remediation script that establishes proper audit rules so that events involving the execution of this tool are recorded in audit logs, regardless of whether the audit daemon is configured to use augenrules or auditctl.

**Model-generated script:**
```bash
#!/usr/bin/env bash

# Remediation script to configure auditd to collect execution of the
# privileged command "postqueue" on RHEL 8.

set -euo pipefail

# Determine the path of the postqueue binary. Fall back to the common path.
PQ_PATH=""
for candidate in /usr/sbin/postqueue /sbin/postqueue /usr/bin/postqueue /bin/postqueue; do
    if [ -e "$candidate" ]; then
        PQ_PATH="$candidate"
        break
    fi
done

if [ -z "$PQ_PATH" ]; then
    # Default expected location for postqueue on RHEL systems.
    PQ_PATH="/usr/sbin/postqueue"
fi

# Determine the minimum UID for non-system (regular) users.
if [ -f /etc/login.defs ]; then
    UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs | tail -n 1)
fi
if [ -z "${UID_MIN:-}" ]; then
    UID_MIN=1000
fi

# The audit rule line to enforce.
AUDIT_RULE="-a always,exit -F path=${PQ_PATH} -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k privileged"

##############################################################################
# Handle augenrules (rules stored under /etc/audit/rules.d/)
##############################################################################
RULES_D_FILE="/etc/audit/rules.d/privileged.rules"

mkdir -p /etc/audit/rules.d

# Remove any existing rule referencing this path to avoid duplicates/stale rules.
if [ -f "$RULES_D_FILE" ]; then
    grep -v -E -- "-F[[:space:]]+path=${PQ_PATH}([[:space:]]|$)" "$RULES_D_FILE" > "${RULES_D_FILE}.tmp" 2>/dev/null || true
    mv "${RULES_D_FILE}.tmp" "$RULES_D_FILE"
fi

# Also clean up matching rules in any other rules.d file to keep things consistent.
for f in /etc/audit/rules.d/*.rules; do
    [ -e "$f" ] || continue
    [ "$f" = "$RULES_D_FILE" ] && continue
    if grep -q -E -- "-F[[:space:]]+path=${PQ_PATH}([[:space:]]|$)" "$f" 2>/dev/null; then
        grep -v -E -- "-F[[:space:]]+path=${PQ_PATH}([[:space:]]|$)" "$f" > "${f}.tmp" 2>/dev/null || true
        mv "${f}.tmp" "$f"
    fi
done

# Append the correct rule.
echo "$AUDIT_RULE" >> "$RULES_D_FILE"

##############################################################################
# Handle auditctl (rules stored in /etc/audit/audit.rules)
##############################################################################
AUDITCTL_FILE="/etc/audit/audit.rules"

if [ -f "$AUDITCTL_FILE" ]; then
    grep -v -E -- "-F[[:space:]]+path=${PQ_PATH}([[:space:]]|$)" "$AUDITCTL_FILE" > "${AUDITCTL_FILE}.tmp" 2>/dev/null || true
    mv "${AUDITCTL_FILE}.tmp" "$AUDITCTL_FILE"
else
    touch "$AUDITCTL_FILE"
fi

echo "$AUDIT_RULE" >> "$AUDITCTL_FILE"

##############################################################################
# Reload audit rules
##############################################################################
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "$AUDITCTL_FILE" || true
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

**Prompt:** On a RHEL 8 system, ensure the audit subsystem captures every attempt to execute the ssh-agent command by any user, including root. This is to help establish accountability and facilitate forensic analysis in case of a security incident. Write an idempotent bash remediation script that configures the audit system to record ssh-agent executions, ensuring the rule remains persistent across reboots and effective regardless of whether the system uses augenrules or auditctl for audit rule management.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

# Determine the correct architecture-specific rule(s)
# ssh-agent is a privileged command; audit every execution.

# Path to the ssh-agent binary
SSH_AGENT_PATH="/usr/bin/ssh-agent"

if [ ! -e "$SSH_AGENT_PATH" ]; then
    # Attempt to locate it if not at the default path
    if command -v ssh-agent >/dev/null 2>&1; then
        SSH_AGENT_PATH="$(command -v ssh-agent)"
    fi
fi

# The audit rule to enforce
AUDIT_RULE="-a always,exit -F path=${SSH_AGENT_PATH} -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged-ssh"

##############################################
# Configure persistent rules (augenrules)
##############################################
RULES_DIR="/etc/audit/rules.d"
RULES_FILE="${RULES_DIR}/privileged.rules"

mkdir -p "$RULES_DIR"
touch "$RULES_FILE"

# Remove any pre-existing ssh-agent rules to keep it idempotent,
# then append the desired rule.
if grep -qE -- "-F path=${SSH_AGENT_PATH}[[:space:]]" "$RULES_FILE" 2>/dev/null; then
    # Rebuild file without existing ssh-agent rule lines
    grep -vE -- "-F path=${SSH_AGENT_PATH}[[:space:]]" "$RULES_FILE" > "${RULES_FILE}.tmp"
    mv "${RULES_FILE}.tmp" "$RULES_FILE"
fi

if ! grep -qF -- "$AUDIT_RULE" "$RULES_FILE" 2>/dev/null; then
    echo "$AUDIT_RULE" >> "$RULES_FILE"
fi

##############################################
# Configure auditctl-based setups as well
##############################################
AUDITCTL_FILE="/etc/audit/audit.rules"

if [ -f "$AUDITCTL_FILE" ]; then
    if grep -qE -- "-F path=${SSH_AGENT_PATH}[[:space:]]" "$AUDITCTL_FILE" 2>/dev/null; then
        grep -vE -- "-F path=${SSH_AGENT_PATH}[[:space:]]" "$AUDITCTL_FILE" > "${AUDITCTL_FILE}.tmp"
        mv "${AUDITCTL_FILE}.tmp" "$AUDITCTL_FILE"
    fi
    if ! grep -qF -- "$AUDIT_RULE" "$AUDITCTL_FILE" 2>/dev/null; then
        echo "$AUDIT_RULE" >> "$AUDITCTL_FILE"
    fi
fi

##############################################
# Load the rules into the running kernel
##############################################
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    # Load the rule directly if augenrules is not available
    auditctl "$AUDIT_RULE" 2>/dev/null || true
fi

echo "Audit rule for ssh-agent execution has been configured."
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

**Prompt:** On a RHEL 8 system, ensure that the audit system is configured to log the execution of the SSH helper command `ssh-keysign`, as its misuse poses security risks. The audit system should be set to capture execution attempts by any real user ID greater than or equal to 1000, excluding cases where the user ID is unset. The capture should persist across system reboots, regardless of whether the audit system is configured with augenrules or auditctl for rule persistence. Write an idempotent bash remediation script to configure these auditing requirements for `ssh-keysign`.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

# Determine the correct auid unset value based on architecture bit width
# The audit rule for ssh-keysign privileged command execution

AUDIT_RULE='-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged'

# Function to check if the rule already exists in a file (ignoring key differences)
rule_present() {
    local file="$1"
    grep -Pq -- '^\s*-a\s+always,exit\s+-F\s+path=/usr/libexec/openssh/ssh-keysign\s+-F\s+perm=x\s+-F\s+auid>=1000\s+-F\s+auid!=unset\s+(-F\s+key=\S+|-k\s+\S+)\s*$' "$file" 2>/dev/null
}

# --- Handle augenrules persistence ---
if command -v augenrules >/dev/null 2>&1 || [ -d /etc/audit/rules.d ]; then
    RULES_DIR="/etc/audit/rules.d"
    mkdir -p "$RULES_DIR"
    PRIV_FILE="$RULES_DIR/privileged.rules"

    # Remove any existing matching lines to avoid duplicates
    if [ -f "$PRIV_FILE" ]; then
        # Search all rules.d files for existing entries and remove them
        found_file=""
        for f in "$RULES_DIR"/*.rules; do
            [ -e "$f" ] || continue
            if rule_present "$f"; then
                found_file="$f"
                break
            fi
        done
        if [ -z "$found_file" ]; then
            printf '%s\n' "$AUDIT_RULE" >> "$PRIV_FILE"
        fi
    else
        printf '%s\n' "$AUDIT_RULE" >> "$PRIV_FILE"
    fi

    # Re-scan in case PRIV_FILE didn't exist before
    already=0
    for f in "$RULES_DIR"/*.rules; do
        [ -e "$f" ] || continue
        if rule_present "$f"; then
            already=1
            break
        fi
    done
    if [ "$already" -eq 0 ]; then
        printf '%s\n' "$AUDIT_RULE" >> "$PRIV_FILE"
    fi
fi

# --- Handle auditctl persistence (/etc/audit/audit.rules) ---
AUDITCTL_FILE="/etc/audit/audit.rules"
if [ -f "$AUDITCTL_FILE" ] || [ -d /etc/audit ]; then
    mkdir -p /etc/audit
    if ! rule_present "$AUDITCTL_FILE"; then
        printf '%s\n' "$AUDIT_RULE" >> "$AUDITCTL_FILE"
    fi
fi

# --- Load the rule into the running audit system (best effort) ---
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load >/dev/null 2>&1 || true
elif command -v auditctl >/dev/null 2>&1; then
    auditctl "$AUDIT_RULE" >/dev/null 2>&1 || true
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

**Prompt:** On a RHEL 8 system, configure the audit daemon to capture and log all execution attempts of the privileged command 'unix_update' when executed by users with an audit user ID (auid) of 1000 or higher, excluding any unset auids. This is to monitor for misuse of privileged commands and ensure compliance with organizational security policies. The auditing must persist across reboots using the default audit rules mechanism for the system. Write an idempotent bash remediation script to configure this auditing requirement.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULES_DIR="/etc/audit/rules.d"
RULES_FILE="${RULES_DIR}/privileged.rules"

# Locate the unix_update binary
UNIX_UPDATE_PATH=""
for candidate in /usr/sbin/unix_update /sbin/unix_update /usr/bin/unix_update /bin/unix_update; do
    if [ -f "$candidate" ]; then
        UNIX_UPDATE_PATH="$candidate"
        break
    fi
done

# Fallback to a common default path if not found
if [ -z "$UNIX_UPDATE_PATH" ]; then
    UNIX_UPDATE_PATH="/usr/sbin/unix_update"
fi

mkdir -p "$RULES_DIR"
touch "$RULES_FILE"

AUDIT_RULE="-a always,exit -F path=${UNIX_UPDATE_PATH} -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update"

# Remove any pre-existing rules for unix_update to keep idempotent
if grep -q "path=.*unix_update" "$RULES_FILE" 2>/dev/null; then
    grep -v "path=.*unix_update" "$RULES_FILE" > "${RULES_FILE}.tmp" || true
    mv "${RULES_FILE}.tmp" "$RULES_FILE"
fi

# Add the desired rule if not already present
if ! grep -Fxq "$AUDIT_RULE" "$RULES_FILE"; then
    echo "$AUDIT_RULE" >> "$RULES_FILE"
fi

# Load the rules into the running kernel
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "$RULES_FILE" || true
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

**Prompt:** On a RHEL 8 system, ensure that executions of the 'usermod' command by any user, except for system accounts, are auditable, providing a trail that can warn of potential misuse of privileged functions. Assume the default configuration using the augenrules program; make sure the audit rules persist across reboots. Write an idempotent bash remediation script that ensures this audit rule is in place to capture such invocations by non-system accounts and tag the records with an easily identifiable key.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

RULE_FILE="/etc/audit/rules.d/privileged.rules"
AUDIT_RULE="-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=unset -k privileged-usermod"

# Ensure the rules directory exists
mkdir -p /etc/audit/rules.d

# Ensure the rule file exists
touch "$RULE_FILE"

# Add the rule idempotently (match on the path and key to avoid duplicates)
if ! grep -Pq -- '^\s*-a\s+always,exit\s+.*-F\s+path=/usr/sbin/usermod\s+.*-k\s+privileged-usermod\s*$' "$RULE_FILE"; then
    echo "$AUDIT_RULE" >> "$RULE_FILE"
fi

# Load the new rules using augenrules if auditd is available
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
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

**Prompt:** On a RHEL 8 system, configure the audit daemon to switch the system to single-user mode if a disk error occurs that prevents audit logs from being written, ensuring sever disk issues are addressed immediately, even at the expense of availability. This minimizes the risk of losing critical audit records. Write an idempotent bash remediation script that sets this behavior as the fallback action on disk error for the audit daemon, ensuring the configuration persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

CONFIG_FILE="/etc/audit/auditd.conf"
PARAM="disk_error_action"
VALUE="single"

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Error: $CONFIG_FILE does not exist. Is auditd installed?" >&2
    exit 1
fi

if grep -qiE "^\s*${PARAM}\s*=" "$CONFIG_FILE"; then
    sed -i -E "s|^\s*${PARAM}\s*=.*|${PARAM} = ${VALUE}|I" "$CONFIG_FILE"
else
    printf '%s = %s\n' "$PARAM" "$VALUE" >> "$CONFIG_FILE"
fi

if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
fi

if systemctl is-active --quiet auditd 2>/dev/null; then
    service auditd reload 2>/dev/null || systemctl kill --signal=HUP auditd 2>/dev/null || true
fi

echo "Configured ${PARAM} = ${VALUE} in ${CONFIG_FILE}"
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

var_auditd_disk_error_action='
```


---

## RHEL-08-030060 — `auditd_data_disk_full_action`

**Prompt:** On a RHEL 8 system, configure the audit logging daemon (auditd) to take corrective action and switch the system to single-user mode when the disk space dedicated for audit logs fills up. This helps ensure no audit logs are lost due to lack of disk space. Write an idempotent bash remediation script that sets this behavior in the auditd configuration file, ensuring the change persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

AUDITD_CONF="/etc/audit/auditd.conf"
PARAM="disk_full_action"
VALUE="single"

# Ensure the configuration file exists
if [ ! -f "$AUDITD_CONF" ]; then
    touch "$AUDITD_CONF"
    chmod 0640 "$AUDITD_CONF"
fi

# Idempotently set the parameter
if grep -qiE "^\s*${PARAM}\s*=" "$AUDITD_CONF"; then
    # Replace existing line (case-insensitive on key), preserving nothing else on that line
    sed -i -E "s|^\s*${PARAM}\s*=.*|${PARAM} = ${VALUE}|I" "$AUDITD_CONF"
else
    # Append the parameter
    printf '%s = %s\n' "$PARAM" "$VALUE" >> "$AUDITD_CONF"
fi

# Verify the change
if grep -qiE "^\s*${PARAM}\s*=\s*${VALUE}\s*$" "$AUDITD_CONF"; then
    echo "Successfully set '${PARAM} = ${VALUE}' in ${AUDITD_CONF}"
else
    echo "Failed to set '${PARAM}' in ${AUDITD_CONF}" >&2
    exit 1
fi

# Reload auditd configuration so the change takes effect (persists via config file across reboots)
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load >/dev/null 2>&1 || true
fi

if command -v service >/dev/null 2>&1; then
    service auditd reload >/dev/null 2>&1 || true
elif command -v systemctl >/dev/null 2>&1; then
    # auditd cannot be reliably reloaded via systemctl on RHEL; attempt kill -HUP
    if pgrep -x auditd >/dev/null 2>&1; then
        pkill -HUP -x auditd >/dev/null 2>&1 || true
    fi
fi

exit 0
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

var_auditd_disk_full_action='
```


---

## RHEL-08-030731 — `auditd_data_retention_space_left_action`

**Prompt:** On a RHEL 8 system, configure the system audit daemon to send an email alert when available disk space for audit logs becomes critically low. This ensures administrators are promptly informed of the issue, allowing them to take corrective action before system operation is impacted. Write an idempotent bash remediation script that sets the action taken by the audit daemon to 'email' when low disk space is detected, and ensure this configuration persists across service restarts.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

AUDITD_CONF="/etc/audit/auditd.conf"
PARAMETER="space_left_action"
VALUE="email"

# Ensure the auditd configuration file exists
if [ ! -f "$AUDITD_CONF" ]; then
    echo "Error: $AUDITD_CONF does not exist. Is auditd installed?" >&2
    exit 1
fi

# Idempotently set space_left_action to email
if grep -Eq "^\s*${PARAMETER}\s*=" "$AUDITD_CONF"; then
    # Parameter present, update it if not already correct
    current_value="$(grep -E "^\s*${PARAMETER}\s*=" "$AUDITD_CONF" | tail -n1 | sed -E "s/^\s*${PARAMETER}\s*=\s*//" | tr -d '[:space:]')"
    if [ "$current_value" != "$VALUE" ]; then
        sed -i -E "s|^\s*${PARAMETER}\s*=.*|${PARAMETER} = ${VALUE}|" "$AUDITD_CONF"
        echo "Updated ${PARAMETER} to ${VALUE} in ${AUDITD_CONF}."
        changed=1
    else
        echo "${PARAMETER} is already set to ${VALUE}. No change needed."
        changed=0
    fi
else
    # Parameter not present, append it
    printf '%s = %s\n' "$PARAMETER" "$VALUE" >> "$AUDITD_CONF"
    echo "Added ${PARAMETER} = ${VALUE} to ${AUDITD_CONF}."
    changed=1
fi

# Reload/restart auditd so the configuration persists and is applied
if [ "${changed:-0}" -eq 1 ]; then
    if command -v augenrules >/dev/null 2>&1; then
        augenrules --load >/dev/null 2>&1 || true
    fi
    # Prefer service command since systemctl restart of auditd is restricted
    if command -v service >/dev/null 2>&1; then
        service auditd restart >/dev/null 2>&1 || systemctl restart auditd >/dev/null 2>&1 || true
    else
        systemctl restart auditd >/dev/null 2>&1 || true
    fi
    echo "auditd configuration reloaded."
fi

echo "Configuration complete: ${PARAMETER} = ${VALUE}"
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

var_auditd_space_left_action='
```


---

## RHEL-08-030730 — `auditd_data_retention_space_left_percentage`

**Prompt:** To ensure audit logs are not lost due to lack of disk space and administrators are warned early, configure the audit daemon on a RHEL 8 system to generate notifications when available disk space for audit logs falls to 25% or less. Write an idempotent bash remediation script that configures the auditd service with this threshold, ensuring the change is persistent across service restarts and reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

AUDITD_CONF="/etc/audit/auditd.conf"
PARAM="space_left"
VALUE="25%"

if [[ ! -f "$AUDITD_CONF" ]]; then
    echo "Error: $AUDITD_CONF not found. Is auditd installed?" >&2
    exit 1
fi

# Idempotently set space_left to 25%
if grep -Eq '^\s*space_left\s*=' "$AUDITD_CONF"; then
    sed -ri "s|^\s*${PARAM}\s*=.*|${PARAM} = ${VALUE}|" "$AUDITD_CONF"
else
    echo "${PARAM} = ${VALUE}" >> "$AUDITD_CONF"
fi

# Ensure space_left_action notifies administrators (email is a common early-warning action)
if grep -Eq '^\s*space_left_action\s*=' "$AUDITD_CONF"; then
    CURRENT_ACTION=$(grep -Ei '^\s*space_left_action\s*=' "$AUDITD_CONF" | tail -n1 | cut -d= -f2 | tr -d ' ')
    if ! echo "$CURRENT_ACTION" | grep -Eiq '^(email|exec|syslog)$'; then
        sed -ri "s|^\s*space_left_action\s*=.*|space_left_action = SYSLOG|" "$AUDITD_CONF"
    fi
else
    echo "space_left_action = SYSLOG" >> "$AUDITD_CONF"
fi

# Verify configuration
echo "Current audit disk space warning configuration:"
grep -Ei '^\s*(space_left|space_left_action)\s*=' "$AUDITD_CONF"

# Reload auditd to apply changes persistently
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load >/dev/null 2>&1 || true
fi

if command -v service >/dev/null 2>&1; then
    service auditd reload 2>/dev/null || systemctl kill --signal=HUP auditd 2>/dev/null || true
else
    systemctl kill --signal=HUP auditd 2>/dev/null || true
fi

echo "auditd configured to warn when free audit log space falls to 25% or less."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

var_auditd_space_left_percentage='
```


---

## RHEL-08-030062 — `auditd_name_format`

**Prompt:** On a RHEL 8 system, the Audit daemon must distinguish audit logs from multiple computers by including a unique identifier as the computer node name in its events. Write an idempotent bash remediation script to configure the Audit daemon so that each audit log entry includes this unique identifier for the system, ensuring clear differentiation in distributed environments. This configuration should persist across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure auditd includes a unique computer node name in audit events.
# This is controlled by the "name_format" and "name" options in /etc/audit/auditd.conf.
# Setting name_format to "hostname" makes each audit event include the system's
# node name, allowing differentiation of logs from multiple computers.

set -euo pipefail

AUDITD_CONF="/etc/audit/auditd.conf"

# Ensure the configuration file exists
if [ ! -f "$AUDITD_CONF" ]; then
    echo "Error: $AUDITD_CONF does not exist. Is auditd installed?" >&2
    exit 1
fi

# Desired setting
KEY="name_format"
VALUE="hostname"

# Idempotently set the name_format directive
if grep -qiE "^\s*${KEY}\s*=" "$AUDITD_CONF"; then
    # Replace existing (possibly commented differently) uncommented directive
    sed -i -E "s|^\s*${KEY}\s*=.*|${KEY} = ${VALUE}|I" "$AUDITD_CONF"
else
    # Append the directive if it does not exist
    echo "${KEY} = ${VALUE}" >> "$AUDITD_CONF"
fi

# Verify the change
if ! grep -qiE "^\s*${KEY}\s*=\s*${VALUE}\s*$" "$AUDITD_CONF"; then
    echo "Error: Failed to set ${KEY} = ${VALUE} in $AUDITD_CONF" >&2
    exit 1
fi

echo "Configured '${KEY} = ${VALUE}' in $AUDITD_CONF"

# Reload the audit daemon configuration so the change takes effect.
# auditd must be reloaded via service management; systemctl reload may not
# apply auditd.conf changes, so use the recommended method if available.
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
fi

if command -v service >/dev/null 2>&1; then
    # 'service auditd reload' is the supported way to reload auditd on RHEL
    service auditd reload 2>/dev/null || systemctl reload auditd 2>/dev/null || \
        systemctl restart auditd 2>/dev/null || true
else
    systemctl reload auditd 2>/dev/null || systemctl restart auditd 2>/dev/null || true
fi

echo "Audit daemon configuration applied. Changes persist across reboots."
```

**Reference fix:**
```bash
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

var_auditd_name_format='
```


---

## RHEL-08-030610 — `file_permissions_etc_audit_rulesd`

**Prompt:** On a RHEL 8 system, the audit rule files located within a specific directory currently have permissions that may allow unauthorized personnel to alter them, risking audit integrity. Write an idempotent bash remediation script to ensure these audit rule files are only readable and writable by the owner, and not accessible by group or others. The script must ensure changes are persistent, effectively protecting the audit configuration from unauthorized changes.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure audit rule files in /etc/audit/rules.d are only
# readable/writable by owner (mode 0600), removing group/other access.
# Idempotent: safe to run multiple times.

set -o pipefail

AUDIT_RULES_DIR="/etc/audit/rules.d"

# Ensure the directory exists before proceeding.
if [ ! -d "$AUDIT_RULES_DIR" ]; then
    echo "Directory $AUDIT_RULES_DIR does not exist. Nothing to remediate."
    exit 0
fi

# Find all audit rule files (typically *.rules) and any regular files in the
# directory, then enforce 0600 permissions only where needed (idempotent).
while IFS= read -r -d '' file; do
    current_mode="$(stat -c '%a' "$file" 2>/dev/null)"
    if [ "$current_mode" != "600" ]; then
        chmod u=rw,g=,o= "$file"
        echo "Updated permissions on $file (was $current_mode, now 600)."
    else
        echo "Permissions already correct on $file (600)."
    fi
done < <(find "$AUDIT_RULES_DIR" -maxdepth 1 -type f -print0)

exit 0
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
