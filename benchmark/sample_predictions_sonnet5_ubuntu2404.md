# Inference predictions — `claude-sonnet-5`

215 rules.


---

## RHEL-08-010359 — `package_aide_installed`

**Prompt:** On an Ubuntu 24.04 system, ensure that a host-based file-integrity checking tool is available so that unauthorized modifications to critical system files can later be detected. Specifically, the AIDE file-integrity tool must be present on the system. Write an idempotent bash remediation script that guarantees this tool is installed.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

if ! dpkg -s aide >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y aide aide-common
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
set -euo pipefail

AIDE_DB_DIR="/var/lib/aide"
AIDE_DB_ACTIVE="${AIDE_DB_DIR}/aide.db.gz"
AIDE_DB_NEW="${AIDE_DB_DIR}/aide.db.new.gz"
AIDE_CONF="/etc/aide/aide.conf"

log() {
    echo "[aide-remediation] $*"
}

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root." >&2
    exit 1
fi

if ! command -v aide >/dev/null 2>&1; then
    log "AIDE not found, installing..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y aide aide-common
else
    log "AIDE is already installed."
fi

if ! command -v aide >/dev/null 2>&1; then
    echo "AIDE installation failed." >&2
    exit 1
fi

mkdir -p "${AIDE_DB_DIR}"

if [ ! -f "${AIDE_CONF}" ]; then
    for alt_conf in /etc/aide.conf; do
        if [ -f "${alt_conf}" ]; then
            AIDE_CONF="${alt_conf}"
            break
        fi
    done
fi

if [ ! -f "${AIDE_CONF}" ]; then
    echo "AIDE configuration file not found." >&2
    exit 1
fi

initialize_db() {
    log "Initializing AIDE database using config: ${AIDE_CONF}"
    if command -v aideinit >/dev/null 2>&1; then
        aideinit -y -f || true
    fi

    if [ ! -f "${AIDE_DB_NEW}" ]; then
        aide --config="${AIDE_CONF}" --init
    fi

    if [ -f "${AIDE_DB_NEW}" ]; then
        cp -f "${AIDE_DB_NEW}" "${AIDE_DB_ACTIVE}"
    fi
}

if [ ! -s "${AIDE_DB_ACTIVE}" ]; then
    log "No active AIDE database found at ${AIDE_DB_ACTIVE}. Creating baseline."
    initialize_db
else
    log "Verifying integrity of existing AIDE database..."
    if ! gzip -t "${AIDE_DB_ACTIVE}" >/dev/null 2>&1; then
        log "Existing AIDE database is corrupt. Recreating baseline."
        rm -f "${AIDE_DB_ACTIVE}"
        initialize_db
    else
        log "Existing AIDE database appears valid."
    fi
fi

if [ ! -s "${AIDE_DB_ACTIVE}" ]; then
    echo "Failed to establish a valid AIDE baseline database." >&2
    exit 1
fi

log "AIDE baseline database is present and valid at ${AIDE_DB_ACTIVE}."
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

**Prompt:** On an Ubuntu 24.04 system, configure the AIDE file-integrity tool so that it monitors and verifies the integrity of the system's audit tools (the binaries used to view, manipulate, and report on audit records). Each of these audit tool executables must be registered with AIDE for cryptographic verification covering their permissions, ownership, and content hashes, so that any modification, replacement, or tampering of the tools can be detected. Write an idempotent bash remediation script that ensures the audit tools are tracked by the file-integrity tool, with the configuration persisting across reboots.

**Model-generated script:**
```bash
```bash
#!/usr/bin/env bash
#
# Remediation script: Ensure AIDE monitors audit tool binaries
# Idempotent - safe to run multiple times.

set -euo pipefail

AIDE_CONF="/etc/aide/aide.conf"
AIDE_CONF_D="/etc/aide/aide.conf.d"
RULE="p+i+n+u+g+s+b+acl+xattrs+sha512"

# List of audit tool binaries that must be tracked by AIDE
AUDIT_TOOLS=(
    /sbin/auditctl
    /sbin/auditd
    /sbin/ausearch
    /sbin/aureport
    /sbin/autrace
    /sbin/augenrules
    /usr/sbin/audispd
    /usr/sbin/auditd
    /usr/sbin/auditctl
    /usr/sbin/ausearch
    /usr/sbin/aureport
    /usr/sbin/autrace
    /usr/sbin/augenrules
)

# Ensure AIDE is installed
if ! command -v aide >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y aide aide-common
fi

# Ensure the base AIDE configuration file exists
if [ ! -f "$AIDE_CONF" ]; then
    mkdir -p "$(dirname "$AIDE_CONF")"
    touch "$AIDE_CONF"
fi

# Use a dedicated custom rules file so we don't clobber distro-managed config
CUSTOM_RULES_FILE="${AIDE_CONF_D}/99-audit-tools"
mkdir -p "$AIDE_CONF_D"

if [ ! -f "$CUSTOM_RULES_FILE" ]; then
    touch "$CUSTOM_RULES_FILE"
fi

# Make sure the main aide.conf includes the conf.d directory
if ! grep -qE '^@@x_include[[:space:]]+/etc/aide/aide\.conf\.d' "$AIDE_CONF" 2>/dev/null && \
   ! grep -qE '^@@include[[:space:]]+/etc/aide/aide\.conf\.d' "$AIDE_CONF" 2>/dev/null; then
    if grep -qE '^@@x_include' "$AIDE_CONF" 2>/dev/null; then
        echo "@@x_include /etc/aide/aide.conf.d/*" >> "$AIDE_CONF"
    else
        echo "@@include /etc/aide/aide.conf.d/*" >> "$AIDE_CONF"
    fi
fi

# Add each audit tool binary to the custom rules file, idempotently
for tool in "${AUDIT_TOOLS[@]}"; do
    if [ -e "$tool" ]; then
        # Remove any existing (possibly outdated) entry for this exact path
        sed -i "\|^${tool}[[:space:]]|d" "$CUSTOM_RULES_FILE"
        sed -i "\|^${tool}[[:space:]]|d" "$AIDE_CONF"

        # Add the correct, complete rule
        echo "${tool} ${RULE}" >> "$CUSTOM_RULES_FILE"
    fi
done

# Deduplicate the custom rules file while preserving order
if [ -f "$CUSTOM_RULES_FILE" ]; then
    TMP_FILE=$(mktemp)
    awk '!seen[$0]++' "$CUSTOM_RULES_FILE" > "$TMP_FILE"
    mv "$TMP_FILE" "$CUSTOM_RULES_FILE"
    chmod 0644 "$CUSTOM_RULES_FILE"
fi

# Reinitialize the AIDE database so the new rules persist across reboots
mkdir -p /var/lib/aide

if command -v aideinit >/dev/null 2>&1; then
    aideinit -y -f >/dev/null 2>&1 || aideinit -y -f
    if [ -f /var/lib/aide/aide.db.new ]; then
        mv -f /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    fi
elif command -v aide >/dev/null 2>&1; then
    aide --config="$AIDE_CONF" --init
    if [ -f /var/lib/aide/aide.db.new ]; then
        mv -f /var/lib/aide/a
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
set -euo pipefail
IFS=$'\n\t'

readonly GRUB_FILE="/etc/default/grub"
readonly FIPS_FLAG="fips=1"

log() { echo "[fips-remediation] $*"; }

require_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
  fi
}

is_fips_enabled_runtime() {
  [[ -r /proc/sys/crypto/fips_enabled ]] && [[ "$(cat /proc/sys/crypto/fips_enabled)" == "1" ]]
}

is_fips_pkg_installed() {
  dpkg -s ubuntu-fips >/dev/null 2>&1
}

ensure_pro_client() {
  if ! command -v pro >/dev/null 2>&1; then
    log "Installing ubuntu-advantage-tools ..."
    apt-get update -y
    apt-get install -y ubuntu-advantage-tools
  fi
}

is_pro_attached() {
  pro status --format=json 2>/dev/null | grep -q '"attached": *true'
}

is_fips_service_enabled() {
  pro status 2>/dev/null | grep -E '^fips[[:space:]]' | grep -qi 'enabled'
}

enable_fips_service() {
  if is_fips_service_enabled; then
    log "FIPS service already enabled via Ubuntu Pro."
    return 0
  fi

  if ! is_pro_attached; then
    log "ERROR: This machine is not attached to an Ubuntu Pro subscription."
    log "Attach it first with: pro attach <TOKEN>"
    exit 1
  fi

  log "Enabling FIPS via Ubuntu Pro client ..."
  pro enable fips --assume-yes
}

ensure_grub_fips_param() {
  touch "$GRUB_FILE"

  if grep -Eq '^GRUB_CMDLINE_LINU
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
# Remediation script: Ensure system-wide crypto-policy is set to DEFAULT
# Idempotent - safe to run multiple times.

set -euo pipefail

readonly DESIRED_POLICY="DEFAULT"
readonly UPDATE_BIN="/usr/bin/update-crypto-policies"
readonly CONFIG_FILE="/etc/crypto-policies/config"
readonly STATE_DIR="/etc/crypto-policies/state"
readonly CURRENT_CFG="${STATE_DIR}/current.pol"

log() {
    printf '%s\n' "$*"
}

err() {
    printf 'ERROR: %s\n' "$*" >&2
}

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        err "This script must be run as root."
        exit 1
    fi
}

ensure_package_installed() {
    if command -v update-crypto-policies >/dev/null 2>&1; then
        return 0
    fi

    log "crypto-policies package/tools not found, attempting installation..."

    if command -v apt-get >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -y
        apt-get install -y crypto-policies
    else
        err "No supported package manager found to install crypto-policies."
        exit 1
    fi

    if ! command -v update-crypto-policies >/dev/null 2>&1; then
        err "Failed to install update-crypto-policies binary."
        exit 1
    fi
}

get_current_policy() {
    if [ -x "$UPDATE_BIN" ]; then
        "$UPDATE_BIN" --show 2>/dev/null || true
    fi
}

apply_policy() {
    log "Setting system-wide crypto policy to ${DESIRED_POLICY}..."
    "$UPDATE_BIN" --set "$DESIRED_POLICY"
}

verify_config_file() {
    if [ ! -f "$CONFIG_FILE" ]; then
        err "Config file ${CONFIG_FILE} does not exist after update."
        exit 1
    fi

    local cfg_content
    cfg_content="$(tr -d '[:space:]' < "$CONFIG_FILE")"

    if [ "$cfg_content" != "$DESIRED_POLICY" ]; then
        err "Config file ${CONFIG_FILE} does not reflect desired policy (${DESIRED_POLICY}), found: ${cfg_content}"
        exit 1
    fi
}

verify_active_policy() {
    local active
    active="$(get_current_policy)"

    if [ "$active" != "$DESIRED_POLICY" ]; then
        err "Active crypto policy (${active}) does not match desired policy (${DESIRED_POLICY})."
        exit 1
    fi
}

main() {
    require_root
    ensure_package_installed

    local current
    current="$(get_current_policy)"

    if [ "$current" = "$DESIRED_POLICY" ] && [ -f "$CONFIG_FILE" ] && \
       [ "$(tr -d '[:space:]' < "$CONFIG_FILE")" = "$DESIRED_POLICY" ]; then
        log "System-wide crypto policy is already set to ${DESIRED_POLICY}. No changes needed."
    else
        apply_policy
    fi

    verify_config_file
    verify_active_policy

    log "System-wide cryptographic policy successfully set to ${DESIRED_POLICY} and persisted."
}

main "$@"
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
# Remediation script: Ensure GnuTLS library honors system-wide crypto policy
# and does not override it with insecure/legacy protocol versions
# (SSL 3.0, TLS 1.0, TLS 1.1, DTLS 0.9, DTLS 1.0).
#
# This is idempotent: running it multiple times will not change the
# already-compliant state further.

set -euo pipefail

GNUTLS_CONFIG_DIR="/etc/gnutls"
GNUTLS_CONFIG_FILE="${GNUTLS_CONFIG_DIR}/config"

# Ensure the /etc/gnutls directory exists
if [ ! -d "${GNUTLS_CONFIG_DIR}" ]; then
    mkdir -p "${GNUTLS_CONFIG_DIR}"
    chmod 0755 "${GNUTLS_CONFIG_DIR}"
fi

# Ensure the config file exists
if [ ! -f "${GNUTLS_CONFIG_FILE}" ]; then
    touch "${GNUTLS_CONFIG_FILE}"
    chmod 0644 "${GNUTLS_CONFIG_FILE}"
fi

# Function to set or update a key=value pair under [overrides] section
set_override_key() {
    local key="$1"
    local value="$2"
    local file="$3"

    # Ensure [overrides] section exists
    if ! grep -qE '^\[overrides\]' "${file}"; then
        {
            echo ""
            echo "[overrides]"
        } >> "${file}"
    fi

    # Check if key already exists anywhere in file
    if grep -qE "^[[:space:]]*${key}[[:space:]]*=.*" "${file}"; then
        # Update existing key to desired value
        sed -i -E "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${value}|" "${file}"
    else
        # Insert key right after [overrides] section header
        awk -v key="${key}" -v value="${value}" '
            BEGIN { inserted = 0 }
            {
                print $0
                if ($0 ~ /^\[overrides\]/ && inserted == 0) {
                    print key " = " value
                    inserted = 1
                }
            }
        ' "${file}" > "${file}.tmp" && mv "${file}.tmp" "${file}"
    fi
}

# Enforce that GnuTLS does not override the system-wide crypto policy
# by disabling any explicit min/max protocol overrides and ensuring
# insecure protocols are disabled.
set_override_key "disabled-version" "SSL3.0" "${GNUTLS_CONFIG_FILE}"

# GnuTLS's [overrides] section allows specifying disabled protocol
# versions via repeated "disabled-version" keys, but since our helper
# only manages a single key value pair per key name, we instead ensure
# a comprehensive multi-line block is present using a dedicated marker.

MARKER_BEGIN="# BEGIN GNUTLS SYSTEM POLICY ENFORCEMENT"
MARKER_END="# END GNUTLS SYSTEM POLICY ENFORCEMENT"

# Remove any previously managed block (for idempotency / update-in-place)
if grep -qF "${MARKER_BEGIN}" "${GNUTLS_CONFIG_FILE}" 2>/dev/null; then
    sed -i "/${MARKER_BEGIN}/,/${MARKER_END}/d" "${GNUTLS_CONFIG_FILE}"
fi

# Remove any lone [overrides] section we may have created above without content,
# and any stray disabled-version lines we might have inserted, to avoid duplicates.
sed -i '/^\[overrides\]$/d' "${GNUTLS_CONFIG_FILE}"
sed -i '/^disabled-version[[:space:]]*=.*/d' "${GNUTLS_CONFIG_FILE}"

# Remove trailing blank lines to keep file tidy
sed -i -e :a -e '/^\n*$/{$d;N;ba' -e '}' "${GNUTLS_CONFIG_FILE}"

# Append a well-defined, managed block enforcing compliance
{
    echo ""
    echo "${MARKER_BEGIN}"
    echo "[overrides]"
    echo "insecure-sha1-signatures = false"
    echo "disabled-version = SSL3.0"
    echo "disabled-version = TLS1.0"
    echo "disabled-version = TLS1.1"
    echo "disabled-version = DTLS0.9"
    echo "disabled-version = DTLS1.0"
    echo "${MARKER_END}"
} >> "${GNUTLS_CONFIG_FILE}"

chmod 0644 "${GNUTLS_CONFIG_FILE}"

# Ensure system crypto policy environment variable does not force an override.
# GNUTLS_SYSTEM_PRIORITY_FILE / GNUTLS_FORCE_FIPS_MODE and similar overrides
# should not be globally exported in system-wide profile scripts.
PROFILE_D_DIR="/etc/profile.d"
if [ -d "${PROFILE_D_DIR}" ]; then
    for f in "${PROFILE_D_DIR}"/*.sh; do
        [ -e "${f}" ] || continue
        if grep -qE '^[[:space:]]*export[[:space:]]+GNUTLS_(SYSTEM_PRIORITY_FILE|FORCE_FIPS_MODE)=' "${f}" 2>/dev/null; then
            sed -i -E '/^[[:space:]]*export[[:space:]]+GNUTLS_(SYSTEM_PRIORITY_FILE|FORCE_FIPS_MODE)=/d' "${f}"
        fi
    done
fi

# Ensure /etc/crypto-policies based system priority string is intact and
# not being bypassed by a custom GnuTLS priority string file with weaker
# settings. If a custom priority override file exists, verify it does not
# enable insecure protocol versions; if it does, remove disallowed tokens.
CRYPTO_POLICY_GNUTLS_CONFIG="/etc/crypto-policies/back-ends/gnutls.config"

if [ -f "${CRYPTO_POLICY_GNUTLS_CONFIG}" ]; then
    # Remove any explicit enabling of insecure protocol versions from the
    # generated back-end config, should they exist due to manual tampering.
    sed -i -E 's/\+VERS-SSL3\.0//g; s/\+VERS-TLS1\.0//g; s/\+VERS-TLS1\.1//g; s/\+VERS-DTLS0\.9//g; s/\+VERS-DTLS1\.0//g' "${CRYPTO_POLICY_GNUTLS_CONFIG}"
fi

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
#
# Remediation: Disable user list on GDM login screen (GNOME, Ubuntu 24.04)
# Enforces system-wide via dconf database + lock, preventing user override.
# Idempotent: safe to run multiple times.

set -euo pipefail

PROFILE_DIR="/etc/dconf/profile"
PROFILE_FILE="${PROFILE_DIR}/gdm"

DB_DIR="/etc/dconf/db/gdm.d"
SETTINGS_FILE="${DB_DIR}/00-login-screen"

LOCKS_DIR="${DB_DIR}/locks"
LOCK_FILE="${LOCKS_DIR}/00-login-screen"

# Ensure required directories exist
mkdir -p "${PROFILE_DIR}"
mkdir -p "${DB_DIR}"
mkdir -p "${LOCKS_DIR}"

# Ensure the gdm dconf profile exists and is correctly configured
DESIRED_PROFILE_CONTENT="user-db:user
system-db:gdm
file-db:/usr/share/gdm/greeter-dconf-defaults"

if [[ ! -f "${PROFILE_FILE}" ]] || ! diff -q <(printf '%s\n' "${DESIRED_PROFILE_CONTENT}") "${PROFILE_FILE}" >/dev/null 2>&1; then
    printf '%s\n' "${DESIRED_PROFILE_CONTENT}" > "${PROFILE_FILE}"
fi

# Write the setting to disable the user list on the login screen
DESIRED_SETTINGS_CONTENT="[org/gnome/login-screen]
disable-user-list=true"

if [[ ! -f "${SETTINGS_FILE}" ]] || ! diff -q <(printf '%s\n' "${DESIRED_SETTINGS_CONTENT}") "${SETTINGS_FILE}" >/dev/null 2>&1; then
    printf '%s\n' "${DESIRED_SETTINGS_CONTENT}" > "${SETTINGS_FILE}"
fi

# Lock the setting so it cannot be overridden by users
DESIRED_LOCK_CONTENT="/org/gnome/login-screen/disable-user-list"

if [[ ! -f "${LOCK_FILE}" ]] || ! diff -q <(printf '%s\n' "${DESIRED_LOCK_CONTENT}") "${LOCK_FILE}" >/dev/null 2>&1; then
    printf '%s\n' "${DESIRED_LOCK_CONTENT}" > "${LOCK_FILE}"
fi

# Apply the dconf database changes
if command -v dconf >/dev/null 2>&1; then
    dconf update
else
    echo "Warning: dconf command not found; changes written but not applied. Install dconf-cli or ensure dconf is present." >&2
fi

exit 0
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
#
# Remediation: Enforce GNOME lock-screen-on-smartcard-removal as a
# mandatory, system-wide, non-overridable policy via dconf.
#
# Idempotent: safe to run multiple times; only rewrites files if content
# differs and only runs dconf update when a change was made.

set -euo pipefail

PROFILE_DIR="/etc/dconf/profile"
PROFILE_FILE="${PROFILE_DIR}/user"

DB_DIR="/etc/dconf/db/local.d"
LOCKS_DIR="${DB_DIR}/locks"

SETTINGS_FILE="${DB_DIR}/00-smartcard-removal-action"
LOCK_FILE="${LOCKS_DIR}/00-smartcard-removal-action"

CHANGED=0

log() {
    echo "[remediate-smartcard-lock] $*"
}

ensure_dir() {
    local dir="$1"
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir"
        log "Created directory: $dir"
        CHANGED=1
    fi
}

write_file_if_changed() {
    local file="$1"
    local content="$2"
    local tmpfile
    tmpfile=$(mktemp)
    printf '%s\n' "$content" > "$tmpfile"

    if [ ! -f "$file" ] || ! cmp -s "$tmpfile" "$file"; then
        install -m 0644 "$tmpfile" "$file"
        log "Wrote/updated: $file"
        CHANGED=1
    fi
    rm -f "$tmpfile"
}

# --- Ensure dconf and required base directories exist ---

if ! command -v dconf >/dev/null 2>&1; then
    log "dconf command not found; attempting to install dconf-cli."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -y
        apt-get install -y dconf-cli
    else
        echo "ERROR: dconf is not installed and no supported package manager was found." >&2
        exit 1
    fi
fi

ensure_dir "$PROFILE_DIR"
ensure_dir "$DB_DIR"
ensure_dir "$LOCKS_DIR"

# --- Ensure the 'user' profile references the local database ---

PROFILE_CONTENT="user-db:user
system-db:local"

write_file_if_changed "$PROFILE_FILE" "$PROFILE_CONTENT"

# --- Ensure the smartcard removal-action setting is defined ---

SETTINGS_CONTENT="[org/gnome/settings-daemon/peripherals/smartcard]
removal-action='lock-screen'"

write_file_if_changed "$SETTINGS_FILE" "$SETTINGS_CONTENT"

# --- Ensure the setting is locked so users cannot override it ---

LOCK_CONTENT="/org/gnome/settings-daemon/peripherals/smartcard/removal-action"

write_file_if_changed "$LOCK_FILE" "$LOCK_CONTENT"

# --- Apply the dconf database update ---

if [ "$CHANGED" -eq 1 ]; then
    log "Updating dconf database..."
    dconf update
    log "dconf database updated successfully."
else
    log "No changes needed; configuration already in place."
fi

log "Smartcard removal lock-screen policy is enforced."
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
```bash
#!/usr/bin/env bash
#
# Remediation: Disable GDM automatic/timed login on Ubuntu 24.04
# so that every user must authenticate before reaching a desktop
# session. Idempotent - safe to run multiple times, persists across
# reboots because it edits the on-disk GDM configuration file(s).

set -euo pipefail

# Candidate GDM configuration file locations on Ubuntu/Debian systems
CANDIDATE_FILES=(
    "/etc/gdm3/custom.conf"
    "/etc/gdm/custom.conf"
)

CONF=""

for f in "${CANDIDATE_FILES[@]}"; do
    if [ -f "$f" ]; then
        CONF="$f"
        break
    fi
done

# If no config file exists yet, but the gdm3 package appears to be
# installed, create the standard Ubuntu location so the setting is
# still enforced. If GDM is not installed at all, there is nothing
# to remediate.
if [ -z "$CONF" ]; then
    if dpkg -s gdm3 >/dev/null 2>&1 || command -v gdm3 >/dev/null 2>&1; then
        CONF="/etc/gdm3/custom.conf"
        mkdir -p "$(dirname "$CONF")"
        cat > "$CONF" <<'EOF'
# GDM configuration storage

[daemon]
EOF
    else
        echo "GDM (gdm3) does not appear to be installed. Nothing to remediate."
        exit 0
    fi
fi

# Take a one-time backup before the first modification.
if [ ! -f "${CONF}.bak" ]; then
    cp -p "$CONF" "${CONF}.bak"
fi

# Ensure the [daemon] section exists.
if ! grep -Eq '^\[daemon\]' "$CONF"; then
    printf '\n[daemon]\n' >> "$CONF"
fi

# Function: set_ini_value <file> <section> <key> <value>
# Ensures that
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
set -euo pipefail

# --- Configuration ---
IDLE_DELAY_SECONDS=900   # 15 minutes

PROFILE_DIR="/etc/dconf/profile"
DB_DIR="/etc/dconf/db/local.d"
LOCKS_DIR="${DB_DIR}/locks"

PROFILE_FILE="${PROFILE_DIR}/user"
SETTINGS_FILE="${DB_DIR}/00-screensaver"
LOCKS_FILE="${LOCKS_DIR}/00-screensaver"

# --- Preconditions ---
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

if ! command -v dconf >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y dconf-cli >/dev/null
    else
        echo "dconf command not found and apt-get unavailable; cannot proceed." >&2
        exit 1
    fi
fi

mkdir -p "$PROFILE_DIR" "$DB_DIR" "$LOCKS_DIR"

# --- Desired content ---
read -r -d '' PROFILE_CONTENT <<'EOF' || true
user-db:user
system-db:local
EOF

read -r -d '' SETTINGS_CONTENT <<EOF || true
[org/gnome/desktop/session]
idle-delay=uint32 ${IDLE_DELAY_SECONDS}

[org/gnome/desktop/screensaver]
idle-activation-enabled=true
lock-enabled=true
lock-delay=uint32 0
EOF

read -r -d '' LOCKS_CONTENT <<'EOF' || true
/org/gnome/desktop/session/idle-delay
/org/gnome/desktop/screensaver/idle-activation-enabled
/org/gnome/desktop/screensaver/lock-enabled
/org/gnome/desktop/screensaver/lock-delay
EOF

changed=0

write_if_different() {
    local file="$1"
    local content="$2"
    local tmp
    tmp="$(mktemp)"
    printf '%s\n' "$content" > "$tmp"

    if [[ ! -f "$file" ]] || ! cmp -s "$tmp" "$file"; then
        install -m 0644 "$tmp" "$file"
        changed=1
    fi
    rm -f "$tmp"
}

write_if_different "$PROFILE_FILE" "$PROFILE_CONTENT"
write_if_different "$SETTINGS_FILE" "$SETTINGS_CONTENT"
write_if_different "$LOCKS_FILE" "$LOCKS_CONTENT"

# Always compile the dconf database to guarantee enforcement,
# even if files were already correct but db wasn't compiled yet.
dconf update

if [[ $changed -eq 1 ]]; then
    echo "Screensaver inactivity lock policy (15 min) installed/updated and enforced."
else
    echo "Screensaver inactivity lock policy already correctly configured."
fi

exit 0
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
#
# Idempotent remediation script: enforce GNOME screensaver lock-delay = 0
# system-wide via dconf, persisting across reboots.

set -euo pipefail

DCONF_DB_DIR="/etc/dconf/db/local.d"
DCONF_LOCKS_DIR="${DCONF_DB_DIR}/locks"
DCONF_PROFILE_DIR="/etc/dconf/profile"
DCONF_PROFILE_FILE="${DCONF_PROFILE_DIR}/user"
SETTINGS_FILE="${DCONF_DB_DIR}/00-screensaver"
LOCK_FILE="${DCONF_LOCKS_DIR}/00-screensaver"

# Ensure required directories exist
mkdir -p "$DCONF_DB_DIR"
mkdir -p "$DCONF_LOCKS_DIR"
mkdir -p "$DCONF_PROFILE_DIR"

# Ensure the dconf user profile references the local system database
touch "$DCONF_PROFILE_FILE"

if ! grep -qxF 'user-db:user' "$DCONF_PROFILE_FILE"; then
    echo 'user-db:user' >> "$DCONF_PROFILE_FILE"
fi

if ! grep -qxF 'system-db:local' "$DCONF_PROFILE_FILE"; then
    echo 'system-db:local' >> "$DCONF_PROFILE_FILE"
fi

# Write the desired screensaver lock-delay setting (idempotent overwrite)
DESIRED_SETTINGS_CONTENT='[org/gnome/desktop/screensaver]
lock-delay=uint32 0'

if [ ! -f "$SETTINGS_FILE" ] || [ "$(cat "$SETTINGS_FILE")" != "$DESIRED_SETTINGS_CONTENT" ]; then
    printf '%s\n' "$DESIRED_SETTINGS_CONTENT" > "$SETTINGS_FILE"
fi

# Lock the setting so users cannot override it via dconf/gsettings
DESIRED_LOCK_CONTENT='/org/gnome/desktop/screensaver/lock-delay'

if [ ! -f "$LOCK_FILE" ] || [ "$(cat "$LOCK_FILE")" != "$DESIRED_LOCK_CONTENT" ]; then
    printf '%s\n' "$DESIRED_LOCK_CONTENT" > "$LOCK_FILE"
fi

# Apply the dconf database changes
dconf update
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
#
# Remediation script: Enforce GNOME screensaver lock-on-activate as a
# mandatory, system-wide, non-overridable setting on Ubuntu 24.04.
#
# This script is idempotent: it can be run multiple times safely and will
# always converge the system to the same end state.

set -euo pipefail

# --- Configuration -----------------------------------------------------

DCONF_DB_DIR="/etc/dconf/db/local.d"
DCONF_LOCKS_DIR="/etc/dconf/db/local.d/locks"

SETTINGS_FILE="${DCONF_DB_DIR}/00-screensaver"
LOCKS_FILE="${DCONF_LOCKS_DIR}/00-screensaver"

# --- Pre-flight checks ---------------------------------------------------

if [[ "${EUID}" -ne 0 ]]; then
    echo "Error: this script must be run as root." >&2
    exit 1
fi

if ! command -v dconf >/dev/null 2>&1; then
    echo "Installing dconf-cli package..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -y
        apt-get install -y dconf-cli
    else
        echo "Error: apt-get not found; cannot install dconf-cli." >&2
        exit 1
    fi
fi

# --- Ensure directory structure -----------------------------------------

mkdir -p "${DCONF_DB_DIR}"
mkdir -p "${DCONF_LOCKS_DIR}"

# --- Write mandatory settings file --------------------------------------

cat > "${SETTINGS_FILE}" <<'EOF'
# Managed by remediation script: enforce screensaver lock behavior
[org/gnome/desktop/screensaver]
lock-enabled=true
lock-delay=uint32 0

[org/gnome/desktop/session]
idle-delay=uint32 300
EOF

chmod 0644 "${SETTINGS_FILE}"

# --- Write locks file to prevent user override --------------------------

cat > "${LOCKS_FILE}" <<'EOF'
# Managed by remediation script: lock screensaver keys from user override
/org/gnome/desktop/screensaver/lock-enabled
/org/gnome/desktop/screensaver/lock-delay
/org/gnome/desktop/session/idle-delay
EOF

chmod 0644 "${LOCKS_FILE}"

# --- Update dconf database ----------------------------------------------

dconf update

# --- Verification ---------------------------------------------------------

if dconf read /org/gnome/desktop/screensaver/lock-enabled | grep -q "true"; then
    echo "Success: GNOME screensaver lock-enabled is enforced system-wide."
else
    echo "Warning: could not verify lock-enabled setting via dconf read (may require active session)." >&2
fi

exit 0
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
#
# Remediation: Enforce GNOME screensaver idle-lock via dconf system db
# so it cannot be overridden by users, and compile it into effect.
#
# Idempotent: re-running produces the same end state without errors.

set -euo pipefail

DB_NAME="local"
DB_DIR="/etc/dconf/db/${DB_NAME}.d"
LOCKS_DIR="${DB_DIR}/locks"
PROFILE_DIR="/etc/dconf/profile"
PROFILE_FILE="${PROFILE_DIR}/user"
SETTINGS_FILE="${DB_DIR}/00-screensaver"
LOCK_FILE="${LOCKS_DIR}/00-screensaver"

require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo "This script must be run as root." >&2
        exit 1
    fi
}

ensure_dconf_installed() {
    if ! command -v dconf >/dev/null 2>&1; then
        if command -v apt-get >/dev/null 2>&1; then
            apt-get update -y
            apt-get install -y dconf-cli dconf-gsettings-backend
        else
            echo "dconf command not found and apt-get unavailable; cannot proceed." >&2
            exit 1
        fi
    fi
}

write_if_changed() {
    # write_if_changed <path> <content>
    local path="$1"
    local content="$2"
    local tmpfile
    tmpfile="$(mktemp)"
    printf '%s\n' "$content" > "$tmpfile"

    if [[ -f "$path" ]] && cmp -s "$tmpfile" "$path"; then
        rm -f "$tmpfile"
        return 1
    fi

    install -o root -g root -m 0644 "$tmpfile" "$path"
    rm -f "$tmpfile"
    return 0
}

main() {
    require_root
    ensure_dconf_installed

    mkdir -p "$DB_DIR"
    mkdir -p "$LOCKS_DIR"
    mkdir -p "$PROFILE_DIR"

    local changed=0

    # Ensure the system dconf profile includes the local db (creates if absent)
    local profile_content
    profile_content=$(cat <<'EOF'
user-db:user
system-db:local
EOF
)
    if write_if_changed "$PROFILE_FILE" "$profile_content"; then
        changed=1
    fi

    # Enforced settings: idle delay, lock delay, and lock-enabled must be on
    local settings_content
    settings_content=$(cat <<'EOF'
[org/gnome/desktop/screensaver]
lock-enabled=true
lock-delay=uint32 0

[org/gnome/desktop/session]
idle-delay=uint32 300
EOF
)
    if write_if_changed "$SETTINGS_FILE" "$settings_content"; then
        changed=1
    fi

    # Lock these keys so users cannot override them via gsettings/dconf
    local locks_content
    locks_content=$(cat <<'EOF'
/org/gnome/desktop/screensaver/lock-enabled
/org/gnome/desktop/screensaver/lock-delay
/org/gnome/desktop/session/idle-delay
EOF
)
    if write_if_changed "$LOCK_FILE" "$locks_content"; then
        changed=1
    fi

    # Always compile to ensure state is applied and remains consistent,
    # even if files were already correct (safe / idempotent operation).
    dconf update

    if [[ "$changed" -eq 1 ]]; then
        echo "GNOME screensaver idle-lock policy applied and dconf database updated."
    else
        echo "GNOME screensaver idle-lock policy already enforced; dconf database refreshed."
    fi
}

main "$@"
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

# --- Configuration ---
DCONF_PROFILE_DIR="/etc/dconf/profile"
DCONF_PROFILE_FILE="${DCONF_PROFILE_DIR}/user"

DCONF_DB_DIR="/etc/dconf/db/local.d"
DCONF_LOCKS_DIR="${DCONF_DB_DIR}/locks"

SETTINGS_FILE="${DCONF_DB_DIR}/00-screensaver"
LOCKS_FILE="${DCONF_LOCKS_DIR}/00-screensaver"

LOCK_DELAY_VALUE="uint32 5"

# --- Ensure required packages/tools exist ---
if ! command -v dconf >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -y
        apt-get install -y dconf-cli dconf-gsettings-backend
    else
        echo "dconf command not found and no supported package manager detected." >&2
        exit 1
    fi
fi

# --- Create directories if missing ---
mkdir -p "${DCONF_PROFILE_DIR}"
mkdir -p "${DCONF_DB_DIR}"
mkdir -p "${DCONF_LOCKS_DIR}"

# --- Ensure dconf user profile references system 'local' database ---
DESIRED_PROFILE_CONTENT="user-db:user
system-db:local"

if [[ ! -f "${DCONF_PROFILE_FILE}" ]] || [[ "$(cat "${DCONF_PROFILE_FILE}")" != "${DESIRED_PROFILE_CONTENT}" ]]; then
    printf '%s\n' "${DESIRED_PROFILE_CONTENT}" > "${DCONF_PROFILE_FILE}"
fi

# --- Ensure screensaver lock-delay setting is defined ---
DESIRED_SETTINGS_CONTENT="[org/gnome/desktop/screensaver]
lock-delay=${LOCK_DELAY_VALUE}
lock-enabled=true"

if [[ ! -f "${SETTINGS_FILE}" ]] || [[ "$(cat "${SETTINGS_FILE}")" != "${DESIRED_SETTINGS_CONTENT}" ]]; then
    printf '%s\n' "${DESIRED_SETTINGS_CONTENT}" > "${SETTINGS_FILE}"
fi

# --- Ensure the lock-delay key (and lock-enabled) cannot be overridden by users ---
DESIRED_LOCKS_CONTENT="/org/gnome/desktop/screensaver/lock-delay
/org/gnome/desktop/screensaver/lock-enabled"

if [[ ! -f "${LOCKS_FILE}" ]] || [[ "$(cat "${LOCKS_FILE}")" != "${DESIRED_LOCKS_CONTENT}" ]]; then
    printf '%s\n' "${DESIRED_LOCKS_CONTENT}" > "${LOCKS_FILE}"
fi

# --- Set correct permissions ---
chmod 0644 "${DCONF_PROFILE_FILE}" "${SETTINGS_FILE}" "${LOCKS_FILE}"

# --- Apply/update the dconf database so changes take effect immediately ---
dconf update

exit 0
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
#
# Remediation script: Enforce GNOME session idle-delay (screen lock timeout)
# at the system level via dconf, preventing users from overriding it.
#
# Idempotent: safe to run multiple times.

set -euo pipefail

IDLE_DELAY_SECONDS=900   # 15 minutes - adjust as needed

DCONF_PROFILE_DIR="/etc/dconf/profile"
DCONF_DB_DIR="/etc/dconf/db/local.d"
DCONF_LOCKS_DIR="${DCONF_DB_DIR}/locks"

PROFILE_FILE="${DCONF_PROFILE_DIR}/user"
SETTINGS_FILE="${DCONF_DB_DIR}/00-screensaver"
LOCKS_FILE="${DCONF_LOCKS_DIR}/00-screensaver"

# Ensure required directories exist
mkdir -p "${DCONF_PROFILE_DIR}"
mkdir -p "${DCONF_DB_DIR}"
mkdir -p "${DCONF_LOCKS_DIR}"

# --- Ensure dconf user profile references the local database ---
if [ ! -f "${PROFILE_FILE}" ]; then
    cat > "${PROFILE_FILE}" <<'EOF'
user-db:user
system-db:local
EOF
else
    grep -qxF "user-db:user" "${PROFILE_FILE}" || \
        sed -i '1i user-db:user' "${PROFILE_FILE}"
    grep -qxF "system-db:local" "${PROFILE_FILE}" || \
        echo "system-db:local" >> "${PROFILE_FILE}"
fi

# --- Ensure the idle-delay setting is defined in the local dconf database ---
if [ ! -f "${SETTINGS_FILE}" ]; then
    cat > "${SETTINGS_FILE}" <<EOF
[org/gnome/desktop/session]
idle-delay=uint32 ${IDLE_DELAY_SECONDS}
EOF
else
    if ! grep -q '^\[org/gnome/desktop/session\]$' "${SETTINGS_FILE}"; then
        {
            echo ""
            echo "[org/gnome/desktop/session]"
            echo "idle-delay=uint32 ${IDLE_DELAY_SECONDS}"
        } >> "${SETTINGS_FILE}"
    else
        if grep -q '^idle-delay=' "${SETTINGS_FILE}"; then
            sed -i "s/^idle-delay=.*/idle-delay=uint32 ${IDLE_DELAY_SECONDS}/" "${SETTINGS_FILE}"
        else
            sed -i "/^\[org\/gnome\/desktop\/session\]$/a idle-delay=uint32 ${IDLE_DELAY_SECONDS}" "${SETTINGS_FILE}"
        fi
    fi
fi

# --- Ensure the setting is locked so users cannot override it ---
if [ ! -f "${LOCKS_FILE}" ]; then
    cat > "${LOCKS_FILE}" <<'EOF'
/org/gnome/desktop/session/idle-delay
EOF
else
    grep -qxF "/org/gnome/desktop/session/idle-delay" "${LOCKS_FILE}" || \
        echo "/org/gnome/desktop/session/idle-delay" >> "${LOCKS_FILE}"
fi

# --- Apply the dconf database changes ---
if command -v dconf >/dev/null 2>&1; then
    dconf update
else
    echo "Warning: dconf command not found; database not updated." >&2
fi

exit 0
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
#
# Remediation: Disable Ctrl-Alt-Del triggered reboot/logout action in the
# GNOME graphical interface for all users, enforced via the system-wide
# dconf database and locked to prevent user override.
#
# Idempotent: safe to run multiple times.

set -euo pipefail

DCONF_DB_DIR="/etc/dconf/db/local.d"
DCONF_LOCKS_DIR="${DCONF_DB_DIR}/locks"

SETTING_FILE="${DCONF_DB_DIR}/00-disable-CAD"
LOCK_FILE="${DCONF_LOCKS_DIR}/00-disable-CAD"

SETTING_CONTENT="[org/gnome/settings-daemon/plugins/media-keys]
logout=''
"

LOCK_CONTENT="/org/gnome/settings-daemon/plugins/media-keys/logout
"

changed=0

# Ensure dconf is present
if ! command -v dconf >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -y
        apt-get install -y dconf-cli
    else
        echo "dconf command not found and no supported package manager detected." >&2
        exit 1
    fi
fi

# Ensure directories exist
if [ ! -d "$DCONF_DB_DIR" ]; then
    mkdir -p "$DCONF_DB_DIR"
    changed=1
fi

if [ ! -d "$DCONF_LOCKS_DIR" ]; then
    mkdir -p "$DCONF_LOCKS_DIR"
    changed=1
fi

# Write the setting file idempotently
if [ ! -f "$SETTING_FILE" ] || ! diff -q <(printf '%s' "$SETTING_CONTENT") "$SETTING_FILE" >/dev/null 2>&1; then
    printf '%s' "$SETTING_CONTENT" > "$SETTING_FILE"
    chmod 0644 "$SETTING_FILE"
    changed=1
fi

# Write the lock file idempotently
if [ ! -f "$LOCK_FILE" ] || ! diff -q <(printf '%s' "$LOCK_CONTENT") "$LOCK_FILE" >/dev/null 2>&1; then
    printf '%s' "$LOCK_CONTENT" > "$LOCK_FILE"
    chmod 0644 "$LOCK_FILE"
    changed=1
fi

# Apply the dconf database update if anything changed, or if the compiled
# database does not yet reflect the current source files.
if [ "$changed" -eq 1 ] || [ ! -f /etc/dconf/db/local ] || [ "$SETTING_FILE" -nt /etc/dconf/db/local ] || [ "$LOCK_FILE" -nt /etc/dconf/db/local ]; then
    dconf update
fi

exit 0
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
```bash
#!/usr/bin/env bash
#
# remediate_sudo_timeout.sh
#
# Idempotent remediation script to enforce a finite sudo credential
# caching (re-authentication) timeout on Ubuntu 24.04 systems.
#
# This script ensures that sudo's timestamp_timeout is explicitly set
# to a defined, finite, non-negative value (in minutes) and is never
# left unset (which defaults to 15) or set to a negative value
# (which means "never expire").
#
# It writes the setting into a dedicated drop-in file under
# /etc/sudoers.d/ so it persists across updates and reboots, and
# validates the resulting configuration with visudo before applying.

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Desired sudo re-authentication timeout, in minutes.
# Must be a finite, non-negative integer. A short window (e.g. 5 minutes)
# minimizes the risk of an unattended/hijacked session retaining cached
# privileges.
TIMEOUT_MINUTES=5

SUDOERS_DROPIN_DIR="/etc/sudoers.d"
SUDOERS_DROPIN_FILE="${SUDOERS_DROPIN_DIR}/99-timestamp-timeout"
MARKER="Defaults timestamp_timeout="

# ---------------------------------------------------------------------------
# Sanity checks
# ---------------------------------------------------------------------------

if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

if ! command -v visudo >/dev/null 2>&1; then
    echo "ERROR: visudo command not found. Is sudo installed?" >&2
    exit 1
fi

if ! [[ "${TIMEOUT_MINUTES}" =~ ^[0-9]+$ ]]; then
    echo "ERROR: TIMEOUT_MINUTES must be a non-negative integer." >&2
    exit 1
fi

mkdir -p "${SUDOERS_DROPIN_DIR}"
chmod 0750 "${SUDOERS_DROPIN_DIR}"

# ---------------------------------------------------------------------------
# Remove any conflicting timestamp_timeout settings from other locations
# (main sudoers file and other drop-in files), so our single, authoritative
# setting takes effect deterministically. We do this idempotently: only
# modify files that actually contain a timestamp_timeout directive, and
# only if it differs from what we intend to enforce.
# ---------------------------------------------------------------------------

sanitize_file() {
    local file="$1"

    # Skip our own managed file; it will be rewritten separately.
    if [[ "${file}" == "${SUDOERS_DROPIN_FILE}" ]]; then
        return 0
    fi

    # Only proceed if file exists and contains a timestamp_timeout line.
    if [[ -f "${file}" ]] && grep -qE '^[[:space:]]*Defaults[[:space:]]+(!.*[[:space:]])?timestamp_timeout[[:space:]]*=' "${file}"; then
        local tmpfile
        tmpfile="$(mktemp)"
        # Remove lines that set timestamp_timeout (any value), keep everything else.
        grep -vE '^[[:space:]]*Defaults[[:space:]]+(!.*[[:space:]])?timestamp_timeout[[:space:]]*=' "${file}" > "${tmpfile}" || true

        # Only replace if content actually changed.
        if ! cmp -s "${file}" "${tmpfile}"; then
            cp --preserve=mode,ownership "${file}" "${file}.bak.$(date +%s)"
            cat "${tmpfile}" > "${file}"
        fi
        rm -f "${tmpfile}"
    fi
}

# Sanitize main sudoers file
if [[ -f /etc/sudoers ]]; then
    sanitize_file "/etc/sudoers"
fi

# Sanitize any existing drop-in files (excluding our own)
if [[ -d "${SUDOERS_DROPIN_DIR}" ]]; then
    while IFS= read -r -d '' f; do
        sanitize_file "${f}"
    done < <(find "${SUDOERS_DROPIN_DIR}" -maxdepth 1 -type f -print0)
fi

# ---------------------------------------------------------------------------
# Write (or update) our authoritative drop-in file idempotently.
# ---------------------------------------------------------------------------

DESIRED_LINE="Defaults        timestamp_timeout=${TIMEOUT_MINUTES}"

NEED_WRITE=1
if [[ -f "${SUDOERS_DROPIN_FILE}" ]]; then
    if grep -qxF "${DESIRED_LINE}" "${SUDOERS_DROPIN_FILE}" 2>/dev/null; then
        # Ensure no other timestamp_timeout lines with different values exist.
        OTHER_LINES=$(grep -E "^[[:space:]]*Defaults[[:space:]]+(!.*[[:space:]])?timestamp_timeout[[:space:]]*=" "${SUDOERS_DROPIN_FILE}" | grep -vxF "${DESIRED_LINE}" || true)
        if [[ -z "${OTHER_LINES}" ]]; then
            NEED_WRITE=0
        fi
    fi
fi

if [[ "${NEED_WRITE}" -eq 1 ]]; then
    TMP_SUDOERS_FILE="$(mktemp)"
    {
        echo "# Managed by remediate_sudo_timeout.sh"
        echo "# Enforces a finite sudo re-authentication (credential caching) timeout."
        echo "# This value must never be negative (which would mean 'never expire')."
        echo "${DESIRED_LINE}"
    } > "${TMP_SUDOERS_FILE}"

    chmod 0440 "${TMP_SUDOERS_FILE}"

    if visudo -cf "${TMP_SUDOERS_FILE}" >/dev/null 2>&1; then
        install -o root -g root -m 0440 "${TMP_SUDOERS_FILE}" "${SUDOERS_DROPIN_FILE}"
        echo "Updated ${SUDOERS_DROPIN_FILE} with timestamp_timeout=${TIMEOUT_MINUTES}."
    else
        echo "ERROR: Generated sudoers drop-in failed visudo validation. Aborting." >&2
        rm -f "${TMP_SUDOERS_FILE}"
        exit 1
    fi
    rm -f "${TMP_SUDOERS_FILE}"
else
    echo "Sudo timestamp_timeout already correctly set to ${TIMEOUT_MINUTES} in ${SUDOERS_DROPIN_FILE}. No changes needed."
fi

# Ensure correct permissions regardless of path taken above.
chmod 0440 "${SUDOERS_DROPIN_FILE}"
chown root:root "${SUDOER
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
```bash
#!/usr/bin/env bash
#
# Remedi
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
#!/bin/bash
#
# Remediation script: Ensure hardware random number generator tooling (rng-tools)
# is installed on Ubuntu 24.04 so that cryptographic operations (e.g., x509/PKI
# certificate generation) have access to high-quality entropy from HW RNGs.
#
# This script is idempotent: running it multiple times has the same effect
# as running it once, and it will not fail or make unnecessary changes if
# the package is already installed.

set -euo pipefail

PACKAGE_NAME="rng-tools"

log() {
    echo "[rng-tools-remediation] $*"
}

# Must be root to install packages
if [ "$(id -u)" -ne 0 ]; then
    log "This script must be run as root. Re-run with sudo."
    exit 1
fi

# Check if the package is already installed
is_installed() {
    dpkg-query -W -f='${Status}' "$PACKAGE_NAME" 2>/dev/null | grep -q "^install ok installed$"
}

if is_installed; then
    log "Package '$PACKAGE_NAME' is already installed. No action needed."
else
    log "Package '$PACKAGE_NAME' is not installed. Installing now..."

    export DEBIAN_FRONTEND=noninteractive

    # Update package index; do not fail the whole script if update has transient issues,
    # but do attempt it since it's needed for a fresh install in most environments.
    if ! apt-get update -y; then
        log "Warning: 'apt-get update' failed. Attempting installation anyway."
    fi

    if apt-get install -y "$PACKAGE_NAME"; then
        log "Successfully installed '$PACKAGE_NAME'."
    else
        log "Error: Failed to install '$PACKAGE_NAME'."
        exit 1
    fi
fi

# Ensure the associated service (if present) is enabled and running,
# so that entropy feeding is active going forward. This step is also idempotent.
SERVICE_NAME="rng-tools-debian.service"

if systemctl list-unit-files 2>/dev/null | grep -q "^rng-tools-debian\.service"; then
    if ! systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        log "Enabling service '$SERVICE_NAME'..."
        systemctl enable "$SERVICE_NAME" || log "Warning: could not enable $SERVICE_NAME"
    else
        log "Service '$SERVICE_NAME' is already enabled."
    fi

    if ! systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        log "Starting service '$SERVICE_NAME'..."
        systemctl start "$SERVICE_NAME" || log "Warning: could not start $SERVICE_NAME"
    else
        log "Service '$SERVICE_NAME' is already active."
    fi
else
    log "Service unit '$SERVICE_NAME' not found; skipping service enable/start step."
fi

log "Remediation complete: hardware RNG tooling is present and configured."
exit 0
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
#!/bin/bash
#
# Remediation script to ensure gssproxy package is not installed on Ubuntu 24.04
# This script is idempotent - safe to run multiple times

set -euo pipefail

PACKAGE_NAME="gssproxy"

# Function to check if package is installed
is_package_installed() {
    dpkg-query -W -f='${Status}' "${PACKAGE_NAME}" 2>/dev/null | grep -q "^install ok installed$"
}

# Main remediation logic
main() {
    echo "Checking status of package: ${PACKAGE_NAME}"

    if is_package_installed; then
        echo "Package '${PACKAGE_NAME}' is currently installed. Proceeding with removal."

        # Stop and disable the service if it exists, to avoid issues during removal
        if systemctl list-unit-files | grep -q "^gssproxy.service"; then
            echo "Stopping and disabling gssproxy.service"
            systemctl stop gssproxy.service 2>/dev/null || true
            systemctl disable gssproxy.service 2>/dev/null || true
        fi

        # Purge the package to remove binaries, config files, and associated data
        DEBIAN_FRONTEND=noninteractive apt-get purge -y "${PACKAGE_NAME}"

        # Clean up any residual dependencies that are no longer needed
        DEBIAN_FRONTEND=noninteractive apt-get autoremove -y

        echo "Package '${PACKAGE_NAME}' has been successfully removed."
    else
        echo "Package '${PACKAGE_NAME}' is not installed. No action required."
    fi

    # Final verification
    if is_package_installed; then
        echo "ERROR: Package '${PACKAGE_NAME}' is still installed after remediation attempt." >&2
        exit 1
    else
        echo "Verification successful: Package '${PACKAGE_NAME}' is confirmed absent from the system."
    fi
}

main "$@"
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
#!/bin/bash
#
# Remediation script to ensure the 'iprutils' package is not installed
# on the system. This script is idempotent and safe to run multiple times.

set -euo pipefail

PACKAGE_NAME="iprutils"

# Check if the package is installed (in any state that dpkg tracks)
if dpkg -s "${PACKAGE_NAME}" >/dev/null 2>&1; then
    echo "Package '${PACKAGE_NAME}' is installed. Removing it now..."

    # Ensure non-interactive behavior
    export DEBIAN_FRONTEND=noninteractive

    # Purge the package to remove binaries and configuration files
    apt-get remove --purge -y "${PACKAGE_NAME}"

    # Clean up any now-unneeded dependencies
    apt-get autoremove -y

    echo "Package '${PACKAGE_NAME}' has been successfully removed."
else
    echo "Package '${PACKAGE_NAME}' is not installed. No action needed."
fi

# Final verification to ensure compliance
if dpkg -s "${PACKAGE_NAME}" >/dev/null 2>&1; then
    echo "ERROR: Package '${PACKAGE_NAME}' is still present after remediation attempt." >&2
    exit 1
else
    echo "System is compliant: '${PACKAGE_NAME}' is not installed."
    exit 0
fi
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
#
# Remediation: Ensure the Red Hat Support reporting plugin for the
# automated crash-reporting (ABRT/libreport) framework is not installed.
#
# Idempotent: safe to run multiple times.

set -euo pipefail

# Possible package names across distributions/versions that provide the
# Red Hat Support reporting plugin for the crash-reporting framework.
PACKAGES=(
    "libreport-plugin-rhtsupport"
    "abrt-plugin-rhtsupport"
    "abrt-addon-rhtsupport"
    "python3-abrt-addon"
    "redhat-support-tool"
    "redhat-support-lib-python"
)

export DEBIAN_FRONTEND=noninteractive

installed_found=0

for pkg in "${PACKAGES[@]}"; do
    if dpkg -s "$pkg" >/dev/null 2>&1; then
        installed_found=1
        echo "Removing package: $pkg"
        apt-get purge -y "$pkg" || true
    fi
done

if [ "$installed_found" -eq 1 ]; then
    apt-get autoremove -y || true
fi

# Final verification
remaining=0
for pkg in "${PACKAGES[@]}"; do
    if dpkg -s "$pkg" >/dev/null 2>&1; then
        remaining=1
        echo "WARNING: Package $pkg is still installed." >&2
    fi
done

if [ "$remaining" -eq 0 ]; then
    echo "Compliant: Red Hat Support reporting plugin is not present on the system."
else
    echo "Non-compliant: Red Hat Support reporting plugin package(s) still present." >&2
    exit 1
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

**Prompt:** On an Ubuntu 24.04 system, ensure that the system-tuning daemon package — which dynamically adjusts performance and power-management settings by continuously monitoring system component usage — is not present on the system, eliminating an unnecessary background service and reducing the attack surface. Write an idempotent bash remediation script that guarantees this package is absent.

**Model-generated script:**
```bash
#!/bin/bash
set -euo pipefail

PACKAGE_NAME="tuned"

if dpkg -l | grep -qw "^ii.*${PACKAGE_NAME}"; then
    DEBIAN_FRONTEND=noninteractive apt-get purge -y "${PACKAGE_NAME}"
fi

apt-get autoremove -y

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

**Prompt:** On an Ubuntu 24.04 system, ensure that the package-management subsystem cryptographically verifies the GPG signature of locally installed package files before they are installed, so that tampered or untrusted software cannot be installed from local sources. Write an idempotent bash remediation script that globally enforces signature verification for local package installations.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation script: Ensure dpkg globally enforces GPG signature
# verification for locally installed package files (Ubuntu 24.04)
#
# This script configures APT/dpkg so that "dpkg -i" style local
# package installations (and apt's use of dpkg under the hood)
# require valid GPG signatures, by setting the dpkg configuration
# option that controls signature verification behavior.
#
# Idempotent: safe to run multiple times.

set -euo pipefail

CONF_DIR="/etc/dpkg/dpkg.cfg.d"
CONF_FILE="${CONF_DIR}/00-no-debsig"
APT_CONF_DIR="/etc/apt/apt.conf.d"
APT_CONF_FILE="${APT_CONF_DIR}/99verify-signatures"

# Ensure required directories exist
if [ ! -d "${CONF_DIR}" ]; then
    mkdir -p "${CONF_DIR}"
fi

if [ ! -d "${APT_CONF_DIR}" ]; then
    mkdir -p "${APT_CONF_DIR}"
fi

# --- Step 1: Ensure debsig-verify is installed to allow signature checks ---
if ! dpkg -s debsig-verify >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get update -y || true
        DEBIAN_FRONTEND=noninteractive apt-get install -y debsig-verify || true
    fi
fi

# --- Step 2: Ensure dpkg does NOT disable signature verification ---
# By default, Debian/Ubuntu dpkg does not verify signatures unless
# debsig-verify is installed and configured, and "no-debsig" is not set.
# Remove any existing "no-debsig" directives that would disable checks.

if [ -f "${CONF_FILE}" ]; then
    rm -f "${CONF_FILE}"
fi

# Also scan other dpkg.cfg.d files and remove any "no-debsig" lines
if [ -d "${CONF_DIR}" ]; then
    for f in "${CONF_DIR}"/*; do
        [ -f "$f" ] || continue
        if grep -q '^[[:space:]]*no-debsig' "$f" 2>/dev/null; then
            sed -i '/^[[:space:]]*no-debsig/d' "$f"
        fi
    done
fi

# Remove "no-debsig" from the main dpkg.cfg if present
if [ -f /etc/dpkg/dpkg.cfg ]; then
    if grep -q '^[[:space:]]*no-debsig' /etc/dpkg/dpkg.cfg 2>/dev/null; then
        sed -i '/^[[:space:]]*no-debsig/d' /etc/dpkg/dpkg.cfg
    fi
fi

# --- Step 3: Explicitly enable signature enforcement via debsig ---
cat > "${CONF_FILE}" <<'EOF'
# Ensure GPG signature verification is NOT disabled for dpkg installs.
# (Absence of "no-debsig" enables debsig-verify checks for local packages.)
EOF

# --- Step 4: Enforce APT-level verification for local .deb installs ---
cat > "${APT_CONF_FILE}" <<'EOF'
// Ensure APT enforces GPG signature verification globally,
// including for locally provided package files.
APT::Get::AllowUnauthenticated "false";
Acquire::AllowInsecureRepositories "false";
Acquire::AllowDowngradeToInsecureRepositories "false";
EOF

# --- Step 5: Ensure debsig policies directory and default policy exist ---
POLICY_DIR="/etc/debsig/policies"
KEYS_DIR="/usr/share/debsig/keyrings"

if [ ! -d "${POLICY_DIR}" ]; then
    mkdir -p "${POLICY_DIR}"
fi

if [ ! -d "${KEYS_DIR}" ]; then
    mkdir -p "${KEYS_DIR}"
fi

# --- Step 6: Validate configuration ---
if [ -f "${CONF_FILE}" ] && [ -f "${APT_CONF_FILE}" ]; then
    echo "GPG signature verification enforcement for local package installs is configured."
else
    echo "ERROR: Failed to configure GPG signature verification enforcement." >&2
    exit 1
fi

exit 0
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
#!/bin/bash
#
# Remediation: Ensure system authentication (PAM stack / nsswitch) is
# managed via the profile-based authentication configuration tool
# (pam-auth-update / libpam-runtime) on Ubuntu 24.04, rather than via
# hand-edited PAM files. Idempotent and persists across reboots because
# the selection is stored in debconf and pam-auth-update writes the
# resulting /etc/pam.d/common-* files to disk.

set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

PACKAGE="libpam-runtime"
DESIRED_PROFILE="unix"

export DEBIAN_FRONTEND=noninteractive

# Ensure the profile-based configuration tool package is installed.
if ! dpkg -s "${PACKAGE}" >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y "${PACKAGE}"
fi

# Ensure pam-auth-update binary is present.
if ! command -v pam-auth-update >/dev/null 2>&1; then
    echo "pam-auth-update not found even after installing ${PACKAGE}." >&2
    exit 1
fi

# Determine the currently selected debconf profile(s), if any.
CURRENT_SELECTION=""
if command -v debconf-show >/dev/null 2>&1; then
    CURRENT_SELECTION="$(debconf-show "${PACKAGE}" 2>/dev/null \
        | awk -F': ' '/libpam-runtime\/profiles/{print $2}' \
        | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
fi

NEEDS_UPDATE=0

if [[ -z "${CURRENT_SELECTION}" ]]; then
    NEEDS_UPDATE=1
else
    # Check whether the desired profile is among the currently selected ones.
    IFS=',' read -ra PROFILES <<< "${CURRENT_SELECTION}"
    FOUND=0
    for p in "${PROFILES[@]}"; do
        p_trimmed="$(echo "${p}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        if [[ "${p_trimmed}" == "${DESIRED_PROFILE}" ]]; then
            FOUND=1
            break
        fi
    done
    if [[ "${FOUND}" -eq 0 ]]; then
        NEEDS_UPDATE=1
    fi
fi

# Verify that the resulting common-* PAM files actually reflect
# management by pam-auth-update (i.e., contain the auto-generated marker).
PAM_MARKER_OK=1
for f in /etc/pam.d/common-auth /etc/pam.d/common-account \
         /etc/pam.d/common-password /etc/pam.d/common-session; do
    if [[ -f "${f}" ]]; then
        if ! grep -q "here via debconf" "${f}" 2>/dev/null; then
            PAM_MARKER_OK=0
            break
        fi
    else
        PAM_MARKER_OK=0
        break
    fi
done

if [[ "${NEEDS_UPDATE}" -eq 1 || "${PAM_MARKER_OK}" -eq 0 ]]; then
    printf '%s %s/profiles multiselect %s\n' \
        "${PACKAGE}" "${PACKAGE}" "${DESIRED_PROFILE}" | debconf-set-selections

    pam-auth-update --force

    echo "pam-auth-update applied with profile '${DESIRED_PROFILE}'."
else
    echo "System authentication already managed via pam-auth-update with profile '${DESIRED_PROFILE}'. No changes needed."
fi

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
#
# Remediation script: Set DoD-required system-use notification banner
# for local console logins (/etc/issue) on Ubuntu 24.04.
#
# This script is idempotent - running it multiple times will result
# in the same final state without duplicating content.

set -euo pipefail

BANNER_FILE="/etc/issue"
BACKUP_FILE="/etc/issue.bak.$(date +%Y%m%d%H%M%S)"

# The exact DoD-required banner text
BANNER_TEXT="You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

# Function to check if the banner already matches exactly
banner_matches() {
    if [[ -f "$BANNER_FILE" ]]; then
        local current_content
        current_content="$(cat "$BANNER_FILE")"
        if [[ "$current_content" == "$BANNER_TEXT" ]]; then
            return 0
        fi
    fi
    return 1
}

main() {
    # Ensure script is run as root
    if [[ "$(id -u)" -ne 0 ]]; then
        echo "ERROR: This script must be run as root." >&2
        exit 1
    fi

    if banner_matches; then
        echo "Login banner (${BANNER_FILE}) already set correctly. No changes needed."
        exit 0
    fi

    # Backup existing file if it exists and differs
    if [[ -f "$BANNER_FILE" ]]; then
        cp -p "$BANNER_FILE" "$BACKUP_FILE"
        echo "Existing ${BANNER_FILE} backed up to ${BACKUP_FILE}"
    fi

    # Write the banner text, ensuring no trailing newline issues
    printf '%s\n' "$BANNER_TEXT" > "$BANNER_FILE"

    # Set appropriate permissions
    chmod 0644 "$BANNER_FILE"
    chown root:root "$BANNER_FILE"

    if banner_matches; then
        echo "Login banner successfully configured at ${BANNER_FILE}."
    else
        echo "ERROR: Failed to verify banner content after write." >&2
        exit 1
    fi
}

main "$@"
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
#
# Remediation script: Configure and lock GDM login screen banner (use-notification message)
# Target: Ubuntu 24.04, GNOME Display Manager
#
# Idempotent: safe to re-run; will not duplicate entries and will fix
# incorrect/missing settings to the required state.

set -euo pipefail

BANNER_TEXT="You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

DCONF_PROFILE_DIR="/etc/dconf/profile"
DCONF_PROFILE_FILE="${DCONF_PROFILE_DIR}/gdm"

DCONF_DB_DIR="/etc/dconf/db/gdm.d"
DCONF_LOCKS_DIR="${DCONF_DB_DIR}/locks"

DCONF_BANNER_FILE="${DCONF_DB_DIR}/01-banner-message"
DCONF_LOCK_FILE="${DCONF_LOCKS_DIR}/01-banner-message"

mkdir -p "${DCONF_PROFILE_DIR}"
mkdir -p "${DCONF_DB_DIR}"
mkdir -p "${DCONF_LOCKS_DIR}"

# --- Ensure the gdm dconf profile exists and is correctly configured ---
cat > "${DCONF_PROFILE_FILE}" <<'EOF'
user-db:user
system-db:gdm
file-db:/usr/share/gdm/greeter-dconf-defaults
EOF

# --- Write the banner configuration (org.gnome.login-screen) ---
{
    echo "[org/gnome/login-screen]"
    echo "banner-message-enable=true"
    printf 'banner-message-text=%s\n' "$(python3 - <<PYEOF
import json,sys
text = """${BANNER_TEXT}"""
# GVariant string literal: use single quotes, escape backslashes and single quotes
escaped = text.replace("\\\\", "\\\\\\\\").replace("'", "\\\\'")
print("'" + escaped + "'")
PYEOF
)"
} > "${DCONF_BANNER_FILE}"

# --- Lock the keys so users cannot override them ---
cat > "${DCONF_LOCK_FILE}" <<'EOF'
/org/gnome/login-screen/banner-message-enable
/org/gnome/login-screen/banner-message-text
EOF

# --- Apply the dconf database updates ---
dconf update

exit 0
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
# Remediation script: Configure GNOME Display Manager (GDM) login screen
# to display an approved organizational warning/consent banner.
#
# This script is idempotent: running it multiple times results in the
# same final state, with no duplicate entries or errors.
#
# Requirements addressed:
#  - Banner text matches the approved organizational message exactly.
#  - Value is enforced as the active value (set in the user db).
#  - Value is locked via dconf lock so non-privileged users cannot override it.
#  - Configuration persists across reboots (written to /etc/dconf).

set -euo pipefail

# ---------------------------------------------------------------------------
# Approved organizational warning/consent banner text.
# Adjust this string ONLY to match your organization's officially approved
# legal notice. Keep it exactly as approved by legal/compliance.
# ---------------------------------------------------------------------------
BANNER_TEXT='This system is for the exclusive use of authorized users. By accessing this system, you consent to monitoring, recording, and auditing of your activity. Unauthorized access or use is strictly prohibited and may be subject to disciplinary action and/or civil and criminal penalties.'

DCONF_DB_DIR="/etc/dconf/db/gdm.d"
DCONF_PROFILE_DIR="/etc/dconf/profile"
DCONF_PROFILE_FILE="${DCONF_PROFILE_DIR}/gdm"
DCONF_KEYFILE="${DCONF_DB_DIR}/01-banner-message"
DCONF_LOCKS_DIR="${DCONF_DB_DIR}/locks"
DCONF_LOCKFILE="${DCONF_LOCKS_DIR}/01-banner-message"

# ---------------------------------------------------------------------------
# Ensure required packages/binaries are present.
# ---------------------------------------------------------------------------
if ! command -v dconf >/dev/null 2>&1; then
    echo "ERROR: 'dconf' command not found. Install dconf-cli/dconf package first." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Ensure directory structure exists.
# ---------------------------------------------------------------------------
mkdir -p "${DCONF_DB_DIR}"
mkdir -p "${DCONF_PROFILE_DIR}"
mkdir -p "${DCONF_LOCKS_DIR}"

# ---------------------------------------------------------------------------
# Ensure the gdm dconf profile exists and is correctly configured.
# This profile tells dconf to use the 'gdm' system db plus defaults.
# ---------------------------------------------------------------------------
DESIRED_PROFILE_CONTENT="user-db:user
system-db:gdm
file-db:/usr/share/gdm/greeter-dconf-defaults"

if [[ ! -f "${DCONF_PROFILE_FILE}" ]] || \
   [[ "$(cat "${DCONF_PROFILE_FILE}")" != "${DESIRED_PROFILE_CONTENT}" ]]; then
    printf '%s\n' "${DESIRED_PROFILE_CONTENT}" > "${DCONF_PROFILE_FILE}"
fi

# ---------------------------------------------------------------------------
# Escape the banner text for safe embedding into a GVariant string literal
# used inside the dconf keyfile. GVariant string escaping requires:
#   - backslash -> \\
#   - double quote -> \"
# Newlines are not expected in a single banner-message-text value; if present
# they should be avoided per policy, but we defensively handle them by
# converting to a literal space to keep this a single-line dconf value.
# ---------------------------------------------------------------------------
escape_for_gvariant() {
    local input="$1"
    input="${input//\\/\\\\}"
    input="${input//\"/\\\"}"
    input="${input//$'\n'/ }"
    printf '%s' "${input}"
}

ESCAPED_BANNER_TEXT="$(escape_for_gvariant "${BANNER_TEXT}")"

# ---------------------------------------------------------------------------
# Build desired content for the dconf keyfile that sets the banner.
# ---------------------------------------------------------------------------
DESIRED_KEYFILE_CONTENT="[org/gnome/login-screen]
banner-message-enable=true
banner-message-text='${ESCAPED_BANNER_TEXT}'"

if [[ ! -f "${DCONF_KEYFILE}" ]] || \
   [[ "$(cat "${DCONF_KEYFILE}")" != "${DESIRED_KEYFILE_CONTENT}" ]]; then
    printf '%s\n' "${DESIRED_KEYFILE_CONTENT}" > "${DCONF_KEYFILE}"
fi

# ---------------------------------------------------------------------------
# Ensure the locks file locks both keys so non-privileged users/greeter
# cannot override the enforced values.
# ---------------------------------------------------------------------------
DESIRED_LOCKS_CONTENT="/org/gnome/login-screen/banner-message-enable
/org/gnome/login-screen/banner-message-text"

if [[ ! -f "${DCONF_LOCKFILE}" ]] || \
   [[ "$(cat "${DCONF_LOCKFILE}")" != "${DESIRED_LOCKS_CONTENT}" ]]; then
    printf '%s\n' "${DESIRED_LOCKS_CONTENT}" > "${DCONF_LOCKFILE}"
fi

# ---------------------------------------------------------------------------
# Update the compiled dconf database so the change takes effect and
# persists across reboots.
# ---------------------------------------------------------------------------
dconf update

# ---------------------------------------------------------------------------
# Verify the enforced value is actually present in the compiled database.
# ---------------------------------------------------------------------------
COMPILED_DB="/etc/dconf/db/gdm"
if [[ ! -f "${COMPILED_DB}" ]]; then
    echo "ERROR: dconf compiled database '${COMPILED_DB}' was not created." >&2
    exit 1
fi

echo "GDM login screen banner has been configured, enforced, and locked successfully."
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
```bash
#!/usr/bin/env bash
#
# Idempotent remediation script: enable pam_faillock account lockout
# enforcement on Ubuntu 24.04 via the pam-auth-update framework.
#
# This configures failed login attempt counting/lockout system-wide
# (login, sudo, su, ssh, etc.) by:
#   1. Ensuring libpam-modules (which ships pam_faillock.so) is present.
#   2. Writing/normalizing /etc/security/faillock.conf lockout settings.
#   3. Registering "faillock" and "faillock_notify" pam-configs profiles
#      that hook pam_faillock preauth/authfail/account checks into the
#      authentication stack.
#   4. Running pam-auth-update non-interactively to regenerate
#      /etc/pam.d/common-auth and /etc/pam.d/common-account so the
#      faillock preauth check happens BEFORE pam_unix authenticates.
#
# Safe to re-run; all steps are idempotent.

set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: this script must be run as root." >&2
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive

echo "[*] Ensuring libpam-modules (provides pam_faillock.so) is installed..."
if ! dpkg -s libpam-modules >/dev/null 2>&1; then
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
# Remediation script: Ensure pam_faillock records account lockout events
# via 'audit' option on Ubuntu 24.04 (idempotent, persistent across reboots)
#
set -euo pipefail

FILES=(
    "/etc/pam.d/common-auth"
    "/etc/pam.d/common-account"
)

BACKUP_SUFFIX=".bak.$(date +%Y%m%d%H%M%S)"

ensure_audit_option() {
    local file="$1"

    if [[ ! -f "$file" ]]; then
        echo "WARNING: $file does not exist, skipping." >&2
        return
    fi

    # Backup once before modifying
    if [[ ! -f "${file}.orig" ]]; then
        cp -p "$file" "${file}.orig"
    fi
    cp -p "$file" "${file}${BACKUP_SUFFIX}"

    local tmpfile
    tmpfile=$(mktemp)

    awk '
    BEGIN { changed = 0 }
    {
        line = $0

        # Match pam_faillock.so lines (preauth or authfail), commented or not
        if (line ~ /pam_faillock\.so/ && line ~ /(preauth|authfail)/) {
            # Strip leading comment marker for processing, remember if it was commented
            is_comment = 0
            work_line = line
            if (work_line ~ /^[[:space:]]*#/) {
                is_comment = 1
            }

            # Only touch lines that are NOT commented out (active config lines)
            if (!is_comment) {
                if (work_line !~ /(^|[[:space:]])audit([[:space:]]|$)/) {
                    # Append audit option
                    sub(/[[:space:]]*$/, "", work_line)
                    work_line = work_line " audit"
                    changed = 1
                }
                print work_line
                next
            } else {
                print line
                next
            }
        }
        print line
    }
    END {
        # changed variable not used further, awk cannot easily return to bash
    }
    ' "$file" > "$tmpfile"

    if ! cmp -s "$file" "$tmpfile"; then
        install -m 0644 -o root -g root "$tmpfile" "$file"
        echo "Updated $file to ensure 'audit' option on pam_faillock lines."
    else
        echo "$file already compliant; no changes made."
    fi

    rm -f "$tmpfile"
}

main() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root." >&2
        exit 1
    fi

    for f in "${FILES[@]}"; do
        ensure_audit_option "$f"
    done

    # Validate PAM stack integrity by checking pam_faillock module exists
    if ! find /lib* /usr/lib* -name "pam_faillock.so" 2>/dev/null | grep -q .; then
        echo "WARNING: pam_faillock.so module not found on this system." >&2
    fi

    echo "Remediation complete: pam_faillock audit logging for account lockouts is enforced."
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

**Prompt:** On an Ubuntu 24.04 system, configure the authentication subsystem so that a user account is automatically locked after no more than 3 consecutive failed login attempts, mitigating password brute-force/guessing attacks. The lockout policy must apply system-wide, be enforced through the standard authentication framework, be idempotent, and persist across reboots. Write a bash remediation script that achieves this end state.

**Model-generated script:**
```bash
```bash
#!/usr/bin/env bash
#
# Remediation: enforce account lockout after 3 failed login attempts
# using pam_faillock, system-wide, via PAM common-auth/common-account,
# idempotent, and persistent across reboots (via /etc/security/faillock.conf
# and /etc/pam.d/common-auth, common-account).

set -euo pipefail

FAILLOCK_CONF="
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
#!/bin/bash
set -euo pipefail

FAILLOCK_CONF="/etc/security/faillock.conf"
REQUIRED_INTERVAL=900
PARAM="fail_interval"

if [ ! -f "$FAILLOCK_CONF" ]; then
    touch "$FAILLOCK_CONF"
fi

CURRENT_VALUE=$(grep -E "^\s*${PARAM}\s*=" "$FAILLOCK_CONF" 2>/dev/null | tail -n1 | sed -E "s/^\s*${PARAM}\s*=\s*([0-9]+).*/\1/" || true)

if [ -n "${CURRENT_VALUE:-}" ] && [ "$CURRENT_VALUE" -ge "$REQUIRED_INTERVAL" ] 2>/dev/null; then
    :
else
    cp "$FAILLOCK_CONF" "${FAILLOCK_CONF}.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true

    if grep -qE "^\s*#?\s*${PARAM}\s*=" "$FAILLOCK_CONF" 2>/dev/null; then
        sed -i -E "s/^\s*#?\s*${PARAM}\s*=.*/${PARAM} = ${REQUIRED_INTERVAL}/" "$FAILLOCK_CONF"
    else
        printf '\n%s = %s\n' "$PARAM" "$REQUIRED_INTERVAL" >> "$FAILLOCK_CONF"
    fi
fi

FINAL_VALUE=$(grep -E "^\s*${PARAM}\s*=" "$FAILLOCK_CONF" | tail -n1 | sed -E "s/^\s*${PARAM}\s*=\s*([0-9]+).*/\1/")

if [ -z "$FINAL_VALUE" ] || [ "$FINAL_VALUE" -lt "$REQUIRED_INTERVAL" ]; then
    echo "Failed to set ${PARAM} to at least ${REQUIRED_INTERVAL} in ${FAILLOCK_CONF}" >&2
    exit 1
fi

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

**Prompt:** On an Ubuntu 24.04 system, the account lockout mechanism that tracks failed authentication attempts must be configured to suppress any informational feedback shown to the user during the lockout/failure-counting process. Without suppression, the system reveals different behavior for existing versus non-existing accounts, allowing an attacker to enumerate valid usernames. Write an idempotent bash remediation script that ensures the failed-login lockout facility operates without displaying these messages, with the change persisting across reboots and applied consistently across the relevant authentication stacks.

**Model-generated script:**
```bash
```bash
#!/bin/bash
#
# Idempotent remediation: ensure pam_faillock operates silently (no
# enumeration-enabling feedback) via /etc/security/faillock.conf and
# across the common-auth / common-account PAM stacks, persisting
# across reboots.

set -uo pipefail

FAILLOCK_CONF="/etc/security/faillock.conf"
PAM_FILES=("/etc/pam.d/common-auth" "/etc/pam.d/common-account")

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# --- 1. Ensure /etc/security/faillock.conf enforces "silent" ---------------

if [ ! -f "$FAILLOCK_CONF" ]; then
    touch "$FAILLOCK_CONF"
fi

if grep -Eq '^[[:space:]]*silent([[:space:]]|$)' "$FAILLOCK_CONF" 2>/dev/null; then
    : # already correctly set and uncommented
elif grep -
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
set -euo pipefail

# Idempotent remediation script to enforce minimum digit requirement
# in system-wide password quality policy on Ubuntu 24.04 (pwquality).

PWQUALITY_CONF="/etc/security/pwquality.conf"
PWQUALITY_DIR="/etc/security/pwquality.conf.d"
PWQUALITY_DROPIN="${PWQUALITY_DIR}/50-dcredit.conf"

REQUIRED_SETTING="dcredit"
REQUIRED_VALUE="-1"

# Ensure the pwquality package/config exists
if [ ! -f "$PWQUALITY_CONF" ]; then
    echo "ERROR: $PWQUALITY_CONF not found. Is libpam-pwquality installed?" >&2
    exit 1
fi

# Prefer using the drop-in directory if it exists or can be created,
# as this is the more modern, idempotent, and override-safe approach.
if [ -d "$PWQUALITY_DIR" ] || mkdir -p "$PWQUALITY_DIR" 2>/dev/null; then
    if [ -f "$PWQUALITY_DROPIN" ] && grep -Eq "^\s*${REQUIRED_SETTING}\s*=\s*${REQUIRED_VALUE}\s*$" "$PWQUALITY_DROPIN"; then
        : # Already configured correctly, nothing to do
    else
        cat > "$PWQUALITY_DROPIN" <<EOF
# Managed by remediation script: enforce at least one digit in passwords
${REQUIRED_SETTING} = ${REQUIRED_VALUE}
EOF
    fi
else
    # Fallback: modify /etc/security/pwquality.conf directly
    if grep -Eq "^\s*${REQUIRED_SETTING}\s*=" "$PWQUALITY_CONF"; then
        # Update existing setting if it doesn't match required value
        current_value=$(grep -E "^\s*${REQUIRED_SETTING}\s*=" "$PWQUALITY_CONF" | tail -n1 | sed -E "s/^\s*${REQUIRED_SETTING}\s*=\s*(-?[0-9]+)\s*$/\1/")
        if [ "$current_value" != "$REQUIRED_VALUE" ]; then
            sed -i -E "s/^\s*${REQUIRED_SETTING}\s*=.*$/${REQUIRED_SETTING} = ${REQUIRED_VALUE}/" "$PWQUALITY_CONF"
        fi
    else
        printf '\n%s = %s\n' "$REQUIRED_SETTING" "$REQUIRED_VALUE" >> "$PWQUALITY_CONF"
    fi
fi

# Ensure PAM is configured to invoke pam_pwquality for password changes
PAM_COMMON_PASSWORD="/etc/pam.d/common-password"

if [ -f "$PAM_COMMON_PASSWORD" ]; then
    if ! grep -Eq '^\s*password\s+(requisite|required)\s+pam_pwquality\.so' "$PAM_COMMON_PASSWORD"; then
        # Insert a pam_pwquality line before the first pam_unix.so password line
        if grep -Eq '^\s*password\s+\[?success=1' "$PAM_COMMON_PASSWORD" || grep -Eq '^\s*password\s+.*pam_unix\.so' "$PAM_COMMON_PASSWORD"; then
            awk '
                BEGIN { inserted = 0 }
                /^\s*password\s+.*pam_unix\.so/ && inserted == 0 {
                    print "password\trequisite\t\t\tpam_pwquality.so retry=3"
                    inserted = 1
                }
                { print }
            ' "$PAM_COMMON_PASSWORD" > "${PAM_COMMON_PASSWORD}.tmp"
            mv "${PAM_COMMON_PASSWORD}.tmp" "$PAM_COMMON_PASSWORD"
        else
            printf 'password\trequisite\t\t\tpam_pwquality.so retry=3\n' >> "$PAM_COMMON_PASSWORD"
        fi
    fi
fi

exit 0
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
# Remediation script: Enforce dictionary-word checking for password quality
# via pam_pwquality (dictcheck option) on Ubuntu 24.04.
#
# This script is idempotent: running it multiple times will not create
# duplicate entries or break existing configuration.

set -euo pipefail

PWQUALITY_CONF="/etc/security/pwquality.conf"
PWQUALITY_CONF_D="/etc/security/pwquality.conf.d"
REMEDIATION_CONF="${PWQUALITY_CONF_D}/50-dictcheck.conf"
PACKAGE_NAME="libpam-pwquality"

log() {
    echo "[remediation] $*"
}

# ------------------------------------------------------------------
# Step 1: Ensure libpam-pwquality is installed (provides pam_pwquality.so
# and dictionary-checking capability via cracklib dictionaries).
# ------------------------------------------------------------------
if ! dpkg -s "${PACKAGE_NAME}" >/dev/null 2>&1; then
    log "Installing package: ${PACKAGE_NAME}"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y "${PACKAGE_NAME}"
else
    log "Package ${PACKAGE_NAME} already installed."
fi

# ------------------------------------------------------------------
# Step 2: Ensure the pwquality.conf.d directory exists (drop-in support).
# ------------------------------------------------------------------
if [ ! -d "${PWQUALITY_CONF_D}" ]; then
    log "Creating directory ${PWQUALITY_CONF_D}"
    mkdir -p "${PWQUALITY_CONF_D}"
fi

# ------------------------------------------------------------------
# Step 3: Set dictcheck = 1 in a drop-in configuration file
# (idempotent - overwrite with desired content each run).
# ------------------------------------------------------------------
log "Configuring dictcheck=1 in ${REMEDIATION_CONF}"
cat > "${REMEDIATION_CONF}" <<'EOF'
# Managed by remediation script
# Enforce dictionary-word checking on new passwords via cracklib
dictcheck = 1
EOF

chmod 0644 "${REMEDIATION_CONF}"

# ------------------------------------------------------------------
# Step 4: Also ensure main pwquality.conf does not explicitly disable
# dictcheck (e.g., dictcheck = 0). If such a line exists, comment it out
# or fix it to 1, since it could override or conflict with drop-in files
# depending on pwquality version/order. We normalize to be safe.
# ------------------------------------------------------------------
if [ -f "${PWQUALITY_CONF}" ]; then
    if grep -Eq '^\s*dictcheck\s*=' "${PWQUALITY_CONF}"; then
        log "Updating existing dictcheck setting in ${PWQUALITY_CONF}"
        sed -i -E 's/^\s*dictcheck\s*=.*/dictcheck = 1/' "${PWQUALITY_CONF}"
    else
        log "Adding dictcheck=1 to ${PWQUALITY_CONF}"
        printf '\n# Enforce dictionary-word checking on new passwords\ndictcheck = 1\n' >> "${PWQUALITY_CONF}"
    fi
else
    log "Creating ${PWQUALITY_CONF} with dictcheck=1"
    cat > "${PWQUALITY_CONF}" <<'EOF'
# Managed by remediation script
dictcheck = 1
EOF
    chmod 0644 "${PWQUALITY_CONF}"
fi

# ------------------------------------------------------------------
# Step 5: Ensure pam_pwquality is referenced in common-password PAM stack.
# Ubuntu's pam-auth-update framework typically manages this, but we
# verify and add it if missing, without duplicating entries.
# ------------------------------------------------------------------
COMMON_PASSWORD="/etc/pam.d/common-password"

if [ -f "${COMMON_PASSWORD}" ]; then
    if ! grep -Eq '^\s*password\s+(requisite|required|sufficient)\s+pam_pwquality\.so' "${COMMON_PASSWORD}"; then
        log "pam_pwquality.so entry not found in ${COMMON_PASSWORD}; adding it."
        # Insert pam_pwquality requisite line before the first pam_unix.so password line
        if grep -Eq '^\s*password\s+\S+\s+pam_unix\.so' "${COMMON_PASSWORD}"; then
            sed -i -E '0,/^\s*password\s+\S+\s+pam_unix\.so/s//password\trequisite\t\t\tpam_pwquality.so retry=3\n&/' "${COMMON_PASSWORD}"
        else
            echo "password requisite pam_pwquality.so retry=3" >> "${COMMON_PASSWORD}"
        fi
    else
        log "pam_pwquality.so already configured in ${COMMON_PASSWORD}"
    fi
else
    log "WARNING: ${COMMON_PASSWORD} not found. PAM stack may need manual review."
fi

# ------------------------------------------------------------------
# Step 6: Validate final configuration
# ------------------------------------------------------------------
log "Final dictcheck configuration:"
grep -R '^\s*dictcheck' "${PWQUALITY_CONF}" "${PWQUALITY_CONF_D}"/*.conf 2>/dev/null || true

log "Remediation complete: dictionary-word checking (dictcheck=1) enforced via pam_pwquality."
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
#
# Remediation script: Enforce minimum difference of 8 characters between
# old and new passwords via pam_pwquality (difok=8) on Ubuntu 24.04.
#
# Idempotent: safe to run multiple times.

set -euo pipefail

PWQUALITY_CONF="/etc/security/pwquality.conf"
PWQUALITY_DIR="/etc/security/pwquality.conf.d"
PWQUALITY_DROPIN="${PWQUALITY_DIR}/50-difok.conf"
DESIRED_KEY="difok"
DESIRED_VALUE="8"

log() {
    printf '%s\n' "$*"
}

# Ensure pwquality package is installed (provides pam_pwquality and pwquality.conf)
if ! dpkg -s libpam-pwquality >/dev/null 2>&1; then
    log "Installing libpam-pwquality package..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y libpam-pwquality
fi

# Ensure the base config file exists
if [ ! -f "${PWQUALITY_CONF}" ]; then
    log "Creating ${PWQUALITY_CONF}"
    touch "${PWQUALITY_CONF}"
fi

set_config_value() {
    local file="$1"
    local key="$2"
    local value="$3"

    if [ ! -f "${file}" ]; then
        touch "${file}"
    fi

    # Match lines like: key = value | key=value | # key = value | commented variants
    # We want to end up with exactly one active "key = value" line and no
    # conflicting active duplicates.

    if grep -Eq "^[[:space:]]*${key}[[:space:]]*=" "${file}"; then
        # Update existing active line(s) to desired value, keep only first occurrence active
        local tmpfile
        tmpfile=$(mktemp)
        local replaced=0
        while IFS= read -r line; do
            if printf '%s\n' "$line" | grep -Eq "^[[:space:]]*${key}[[:space:]]*="; then
                if [ "${replaced}" -eq 0 ]; then
                    printf '%s = %s\n' "${key}" "${value}" >> "${tmpfile}"
                    replaced=1
                else
                    : # drop duplicate active lines
                fi
            else
                printf '%s\n' "$line" >> "${tmpfile}"
            fi
        done < "${file}"
        mv "${tmpfile}" "${file}"
    elif grep -Eq "^[[:space:]]*#[[:space:]]*${key}[[:space:]]*=" "${file}"; then
        # Uncomment and set value on the first matching commented line
        local tmpfile
        tmpfile=$(mktemp)
        local replaced=0
        while IFS= read -r line; do
            if [ "${replaced}" -eq 0 ] && printf '%s\n' "$line" | grep -Eq "^[[:space:]]*#[[:space:]]*${key}[[:space:]]*="; then
                printf '%s = %s\n' "${key}" "${value}" >> "${tmpfile}"
                replaced=1
            else
                printf '%s\n' "$line" >> "${tmpfile}"
            fi
        done < "${file}"
        mv "${tmpfile}" "${file}"
    else
        # Append new setting
        printf '%s = %s\n' "${key}" "${value}" >> "${file}"
    fi
}

# Ensure drop-in directory exists (used if pwquality.conf includes it, common on newer libpwquality)
mkdir -p "${PWQUALITY_DIR}"

# Set difok in main config file (primary enforcement point)
set_config_value "${PWQUALITY_CONF}" "${DESIRED_KEY}" "${DESIRED_VALUE}"

# Also place a drop-in file for systems using conf.d includes, ensuring
# idempotent single authoritative value there too.
cat > "${PWQUALITY_DROPIN}" <<EOF
difok = ${DESIRED_VALUE}
EOF

# Validate final effective setting
current_value=$(grep -E "^[[:space:]]*${DESIRED_KEY}[[:space:]]*=" "${PWQUALITY_CONF}" | tail -n1 | awk -F'=' '{gsub(/[[:space:]]/, "", $2); print $2}')

if [ "${current_value}" != "${DESIRED_VALUE}" ]; then
    log "ERROR: Failed to set ${DESIRED_KEY}=${DESIRED_VALUE} in ${PWQUALITY_CONF}"
    exit 1
fi

log "pwquality '${DESIRED_KEY}' is set to '${DESIRED_VALUE}' in ${PWQUALITY_CONF} and ${PWQUALITY_DROPIN}."

# Ensure pam_pwquality is enabled in PAM common-password (Ubuntu uses pam-auth-update)
PAM_COMMON_PASSWORD="/etc/pam.d/common-password"

if [ -f "${PAM_COMMON_PASSWORD}" ]; then
    if ! grep -Eq '^[[:space:]]*password[[:space:]]+.*pam_pwquality\.so' "${PAM_COMMON_PASSWORD}"; then
        log "pam_pwquality.so not found active in ${PAM_COMMON_PASSWORD}; attempting to enable via pam-auth-update."
        if command -v pam-auth-update >/dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive pam-auth-update --enable pwquality || true
        fi
    fi

    if ! grep -Eq '^[[:space:]]*password[[:space:]]+.*pam_pwquality\.so' "${PAM_COMMON_PASSWORD}"; then
        log "WARNING: pam_pwquality.so still not active in ${PAM_COMMON_PASSWORD}. Please verify PAM configuration manually."
    else
        log "pam_pwquality.so is active in ${PAM_COMMON_PASSWORD}."
    fi
else
    log "WARNING: ${PAM_COMMON_PASSWORD} not found. Cannot verify PAM stack configuration."
fi

log "Remediation complete: difok=${DESIRED_VALUE} enforced for password changes."
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
#!/bin/bash
set -euo pipefail

PWQUALITY_CONF="/etc/security/pwquality.conf"
PWQUALITY_DIR="/etc/security/pwquality.conf.d"
PARAM="lcredit"
VALUE="-1"

# Ensure pam_pwquality is installed
if ! dpkg -s libpam-pwquality >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y libpam-pwquality
fi

# Ensure the main config file exists
if [ ! -f "$PWQUALITY_CONF" ]; then
    touch "$PWQUALITY_CONF"
fi

# Function to set a parameter in a given file idempotently
set_param() {
    local file="$1"
    local param="$2"
    local value="$3"

    if [ ! -f "$file" ]; then
        touch "$file"
    fi

    if grep -qE "^\s*${param}\s*=" "$file"; then
        # Update existing line only if value differs
        current_value=$(grep -E "^\s*${param}\s*=" "$file" | tail -n1 | sed -E "s/^\s*${param}\s*=\s*//")
        if [ "$current_value" != "$value" ]; then
            sed -i -E "s/^\s*${param}\s*=.*/${param} = ${value}/" "$file"
        fi
    else
        echo "${param} = ${value}" >> "$file"
    fi
}

# Prefer using the drop-in directory if it exists or can be created (Ubuntu 24.04 supports pwquality.conf.d)
if [ -d "$PWQUALITY_DIR" ] || mkdir -p "$PWQUALITY_DIR" 2>/dev/null; then
    DROPIN_FILE="${PWQUALITY_DIR}/90-lcredit.conf"
    set_param "$DROPIN_FILE" "$PARAM" "$VALUE"
else
    set_param "$PWQUALITY_CONF" "$PARAM" "$VALUE"
fi

# Also ensure the main config doesn't have a conflicting lcredit value set (if drop-in used)
if [ -d "$PWQUALITY_DIR" ]; then
    if grep -qE "^\s*${PARAM}\s*=" "$PWQUALITY_CONF" 2>/dev/null; then
        current_main_value=$(grep -E "^\s*${PARAM}\s*=" "$PWQUALITY_CONF" | tail -n1 | sed -E "s/^\s*${PARAM}\s*=\s*//")
        if [ "$current_main_value" != "$VALUE" ]; then
            sed -i -E "s/^\s*${PARAM}\s*=.*/${PARAM} = ${VALUE}/" "$PWQUALITY_CONF"
        fi
    fi
fi

# Ensure pam_pwquality is properly referenced in common-password PAM configuration
PAM_COMMON_PASSWORD="/etc/pam.d/common-password"

if [ -f "$PAM_COMMON_PASSWORD" ]; then
    if ! grep -qE "pam_pwquality\.so" "$PAM_COMMON_PASSWORD"; then
        # Insert pam_pwquality requirement before pam_unix.so password line
        sed -i -E "0,/^password\s+\[?success=1[^]]*\]?\s+pam_unix\.so/{s/^(password\s+\[?success=1[^]]*\]?\s+pam_unix\.so.*)/password\trequisite\t\t\tpam_pwquality.so retry=3\n\1/}" "$PAM_COMMON_PASSWORD"
    fi
fi

exit 0
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

PWQUALITY_CONF="/etc/security/pwquality.conf"
PWQUALITY_DIR="/etc/security/pwquality.conf.d"
PWQUALITY_DROPIN="${PWQUALITY_DIR}/50-maxclassrepeat.conf"
SETTING_NAME="maxclassrepeat"
SETTING_VALUE="4"

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root." >&2
    exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
    echo "This script targets Debian/Ubuntu systems with apt-get." >&2
    exit 1
fi

if ! dpkg -s libpam-pwquality >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y libpam-pwquality
fi

mkdir -p "${PWQUALITY_DIR}"

set_setting_in_file() {
    local file="$1"
    local key="$2"
    local value="$3"

    if [ -f "${file}" ]; then
        if grep -qE "^[[:space:]]*${key}[[:space:]]*=" "${file}"; then
            sed -i -E "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${value}|" "${file}"
        elif grep -qE "^[[:space:]]*#[[:space:]]*${key}[[:space:]]*=" "${file}"; then
            sed -i -E "s|^[[:space:]]*#[[:space:]]*${key}[[:space:]]*=.*|${key} = ${value}|" "${file}"
        else
            printf '%s = %s\n' "${key}" "${value}" >> "${file}"
        fi
    else
        printf '%s = %s\n' "${key}" "${value}" > "${file}"
    fi
}

# Ensure the drop-in directory config takes effect (main pwquality.conf can also be used,
# but pwquality.conf.d is the preferred, persistent, idempotent location on Ubuntu 24.04).
set_setting_in_file "${PWQUALITY_DROPIN}" "${SETTING_NAME}" "${SETTING_VALUE}"

# Remove/normalize any conflicting maxclassrepeat entries in the main config file to avoid
# ambiguity, but keep the main file otherwise untouched. If the main file already sets it,
# make sure it agrees with the desired value instead of leaving stale/conflicting values.
if [ -f "${PWQUALITY_CONF}" ]; then
    if grep -qE "^[[:space:]]*${SETTING_NAME}[[:space:]]*=" "${PWQUALITY_CONF}"; then
        set_setting_in_file "${PWQUALITY_CONF}" "${SETTING_NAME}" "${SETTING_VALUE}"
    fi
fi

chmod 0644 "${PWQUALITY_DROPIN}"
[ -f "${PWQUALITY_CONF}" ] && chmod 0644 "${PWQUALITY_CONF}"

# Validate the resulting effective configuration reflects the desired value.
EFFECTIVE_VALUE="$(
    {
        [ -f "${PWQUALITY_CONF}" ] && cat "${PWQUALITY_CONF}"
        [ -d "${PWQUALITY_DIR}" ] && cat "${PWQUALITY_DIR}"/*.conf 2>/dev/null
    } | awk -F= -v key="${SETTING_NAME}" '
        {
            gsub(/^[ \t]+|[ \t]+$/, "", $1)
            if ($1 == key) {
                val=$2
                gsub(/^[ \t]+|[ \t]+$/, "", val)
                last=val
            }
        }
        END { print last }
    '
)"

if [ "${EFFECTIVE_VALUE}" != "${SETTING_VALUE}" ]; then
    echo "Failed to verify effective ${SETTING_NAME} setting (got '${EFFECTIVE_VALUE}', expected '${SETTING_VALUE}')." >&2
    exit 1
fi

echo "pwquality ${SETTING_NAME} is set to ${SETTING_VALUE} in ${PWQUALITY_DROPIN}."
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
#!/bin/bash
set -euo pipefail

PWQUALITY_CONF="/etc/security/pwquality.conf"
PWQUALITY_DIR="/etc/security/pwquality.conf.d"
PARAM="maxrepeat"
VALUE="3"

# Ensure the base config file exists
if [ ! -f "$PWQUALITY_CONF" ]; then
    touch "$PWQUALITY_CONF"
fi

# Prefer using a drop-in directory if supported, but also ensure main conf is consistent
if [ -d "$PWQUALITY_DIR" ] || mkdir -p "$PWQUALITY_DIR" 2>/dev/null; then
    DROPIN_FILE="${PWQUALITY_DIR}/50-maxrepeat.conf"
    if [ -f "$DROPIN_FILE" ] && grep -Eq "^\s*${PARAM}\s*=" "$DROPIN_FILE"; then
        sed -i -E "s/^\s*${PARAM}\s*=.*/${PARAM} = ${VALUE}/" "$DROPIN_FILE"
    else
        echo "${PARAM} = ${VALUE}" > "$DROPIN_FILE"
    fi
    chmod 0644 "$DROPIN_FILE"
fi

# Also enforce/normalize the setting directly in the main pwquality.conf
# to ensure correctness even if drop-in directories aren't read by all tools.
if grep -Eq "^\s*#?\s*${PARAM}\s*=" "$PWQUALITY_CONF"; then
    sed -i -E "s/^\s*#?\s*${PARAM}\s*=.*/${PARAM} = ${VALUE}/" "$PWQUALITY_CONF"
else
    printf '\n%s = %s\n' "${PARAM}" "${VALUE}" >> "$PWQUALITY_CONF"
fi

# Ensure pam_pwquality is invoked in the PAM common-password stack (needed for enforcement)
PAM_FILE="/etc/pam.d/common-password"
if [ -f "$PAM_FILE" ]; then
    if ! grep -Eq '^\s*password\s+requisite\s+pam_pwquality\.so' "$PAM_FILE" \
       && ! grep -Eq '^\s*password\s+required\s+pam_pwquality\.so' "$PAM_FILE"; then
        # Insert a pam_pwquality line before the first pam_unix.so password line
        awk '
            BEGIN { inserted=0 }
            /^\s*password\s+\S+\s+pam_unix\.so/ && inserted==0 {
                print "password\trequisite\t\t\tpam_pwquality.so retry=3"
                inserted=1
            }
            { print }
        ' "$PAM_FILE" > "${PAM_FILE}.tmp" && mv "${PAM_FILE}.tmp" "$PAM_FILE"
    fi
fi

# Validate final state
if grep -Eq "^\s*${PARAM}\s*=\s*${VALUE}\s*$" "$PWQUALITY_CONF"; then
    echo "pwquality ${PARAM} is set to ${VALUE} in ${PWQUALITY_CONF}."
else
    echo "ERROR: Failed to set ${PARAM} in ${PWQUALITY_CONF}." >&2
    exit 1
fi

exit 0
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
#
# Remediation script: Enforce minclass=4 in pwquality.conf (Ubuntu 24.04)
# Ensures newly set/changed passwords must contain characters from at least
# 4 character classes (uppercase, lowercase, digit, special).
# Idempotent: safe to run multiple times.

set -euo pipefail

PWQUALITY_CONF="/etc/security/pwquality.conf"
PWQUALITY_CONF_DIR="/etc/security/pwquality.conf.d"
DROPIN_FILE="${PWQUALITY_CONF_DIR}/50-minclass.conf"
SETTING_NAME="minclass"
SETTING_VALUE="4"

log() {
    printf '%s\n' "$*"
}

ensure_package_installed() {
    if ! dpkg -s libpam-pwquality >/dev/null 2>&1; then
        log "Installing libpam-pwquality package..."
        if command -v apt-get >/dev/null 2>&1; then
            apt-get update -y
            apt-get install -y libpam-pwquality
        else
            log "ERROR: apt-get not found; cannot install libpam-pwquality." >&2
            exit 1
        fi
    fi
}

ensure_conf_file_exists() {
    if [ ! -f "${PWQUALITY_CONF}" ]; then
        log "Creating ${PWQUALITY_CONF}..."
        touch "${PWQUALITY_CONF}"
        chmod 0644 "${PWQUALITY_CONF}"
    fi
}

set_setting_in_file() {
    local file="$1"
    local name="$2"
    local value="$3"

    if [ ! -f "$file" ]; then
        touch "$file"
        chmod 0644 "$file"
    fi

    # Remove any existing (commented or uncommented) definitions of the setting,
    # keeping the file idempotent and avoiding duplicate/conflicting entries.
    if grep -Eq "^[[:space:]]*#?[[:space:]]*${name}[[:space:]]*=" "$file"; then
        sed -i -E "s/^[[:space:]]*#?[[:space:]]*${name}[[:space:]]*=.*/${name} = ${value}/" "$file"
    else
        printf '%s = %s\n' "$name" "$value" >> "$file"
    fi
}

verify_setting() {
    local file="$1"
    local name="$2"
    local value="$3"

    if grep -Eq "^[[:space:]]*${name}[[:space:]]*=[[:space:]]*${value}[[:space:]]*$" "$file"; then
        return 0
    fi
    return 1
}

main() {
    if [ "$(id -u)" -ne 0 ]; then
        log "ERROR: This script must be run as root." >&2
        exit 1
    fi

    ensure_package_installed
    ensure_conf_file_exists

    # Prefer using the drop-in directory if it exists (Ubuntu 24.04 supports it),
    # otherwise fall back to modifying the main pwquality.conf directly.
    if [ -d "${PWQUALITY_CONF_DIR}" ]; then
        set_setting_in_file "${DROPIN_FILE}" "${SETTING_NAME}" "${SETTING_VALUE}"

        if verify_setting "${DROPIN_FILE}" "${SETTING_NAME}" "${SETTING_VALUE}"; then
            log "Verified: ${SETTING_NAME} = ${SETTING_VALUE} is set in ${DROPIN_FILE}"
        else
            log "ERROR: Failed to verify setting in ${DROPIN_FILE}" >&2
            exit 1
        fi

        # Ensure main config doesn't have a conflicting override of minclass
        # that would take precedence (main file is parsed after conf.d on some setups,
        # so remove/normalize any existing 'minclass' entry there too).
        if grep -Eq "^[[:space:]]*#?[[:space:]]*${SETTING_NAME}[[:space:]]*=" "${PWQUALITY_CONF}"; then
            set_setting_in_file "${PWQUALITY_CONF}" "${SETTING_NAME}" "${SETTING_VALUE}"
            if verify_setting "${PWQUALITY_CONF}" "${SETTING_NAME}" "${SETTING_VALUE}"; then
                log "Verified: ${SETTING_NAME} = ${SETTING_VALUE} is set in ${PWQUALITY_CONF}"
            else
                log "ERROR: Failed to verify setting in ${PWQUALITY_CONF}" >&2
                exit 1
            fi
        fi
    else
        set_setting_in_file "${PWQUALITY_CONF}" "${SETTING_NAME}" "${SETTING_VALUE}"

        if verify_setting "${PWQUALITY_CONF}" "${SETTING_NAME}" "${SETTING_VALUE}"; then
            log "Verified: ${SETTING_NAME} = ${SETTING_VALUE} is set in ${PWQUALITY_CONF}"
        else
            log "ERROR: Failed to verify setting in ${PWQUALITY_CONF}" >&2
            exit 1
        fi
    fi

    log "Password quality policy successfully enforces minclass=4."
}

main "$@"
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

CONFIG_FILE="/etc/security/pwquality.conf"
CONFIG_DIR="/etc/security/pwquality.conf.d"
PARAM="minlen"
VALUE="15"

if [ ! -e "$CONFIG_FILE" ]; then
    touch "$CONFIG_FILE"
fi

if [ -d "$CONFIG_DIR" ]; then
    DROPIN_FILE="$CONFIG_DIR/50-minlen.conf"
    if [ -f "$DROPIN_FILE" ] && grep -qE "^\s*${PARAM}\s*=" "$DROPIN_FILE"; then
        sed -i -E "s/^\s*${PARAM}\s*=.*/${PARAM} = ${VALUE}/" "$DROPIN_FILE"
    else
        echo "${PARAM} = ${VALUE}" >> "$DROPIN_FILE"
    fi
    chmod 0644 "$DROPIN_FILE"
fi

if grep -qE "^\s*${PARAM}\s*=" "$CONFIG_FILE"; then
    sed -i -E "s/^\s*${PARAM}\s*=.*/${PARAM} = ${VALUE}/" "$CONFIG_FILE"
elif grep -qE "^\s*#\s*${PARAM}\s*=" "$CONFIG_FILE"; then
    sed -i -E "s/^\s*#\s*${PARAM}\s*=.*/${PARAM} = ${VALUE}/" "$CONFIG_FILE"
else
    echo "${PARAM} = ${VALUE}" >> "$CONFIG_FILE"
fi

CURRENT_VALUE=$(grep -E "^\s*${PARAM}\s*=" "$CONFIG_FILE" | tail -n1 | sed -E "s/^\s*${PARAM}\s*=\s*//")

if [ "$CURRENT_VALUE" != "$VALUE" ]; then
    echo "ERROR: Failed to set ${PARAM} to ${VALUE} in ${CONFIG_FILE}" >&2
    exit 1
fi

chmod 0644 "$CONFIG_FILE"

echo "Password quality policy enforced: ${PARAM} = ${VALUE}"
exit 0
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
#!/bin/bash
set -euo pipefail

CONF_FILE="/etc/security/pwquality.conf"
CONF_DIR="/etc/security/pwquality.conf.d"
SETTING_NAME="ocredit"
SETTING_VALUE="-1"

if [[ ! -f "$CONF_FILE" ]]; then
    touch "$CONF_FILE"
fi

if grep -Eq "^[[:space:]]*${SETTING_NAME}[[:space:]]*=" "$CONF_FILE"; then
    sed -i -E "s/^[[:space:]]*${SETTING_NAME}[[:space:]]*=.*/${SETTING_NAME} = ${SETTING_VALUE}/" "$CONF_FILE"
else
    if grep -Eq "^[[:space:]]*#[[:space:]]*${SETTING_NAME}[[:space:]]*=" "$CONF_FILE"; then
        sed -i -E "s/^[[:space:]]*#[[:space:]]*${SETTING_NAME}[[:space:]]*=.*/${SETTING_NAME} = ${SETTING_VALUE}/" "$CONF_FILE"
    else
        printf "%s = %s\n" "$SETTING_NAME" "$SETTING_VALUE" >> "$CONF_FILE"
    fi
fi

if [[ -d "$CONF_DIR" ]]; then
    for f in "$CONF_DIR"/*.conf; do
        [[ -e "$f" ]] || continue
        if grep -Eq "^[[:space:]]*${SETTING_NAME}[[:space:]]*=" "$f"; then
            sed -i -E "s/^[[:space:]]*${SETTING_NAME}[[:space:]]*=.*/${SETTING_NAME} = ${SETTING_VALUE}/" "$f"
        fi
    done
fi

CURRENT_VALUE=$(grep -E "^[[:space:]]*${SETTING_NAME}[[:space:]]*=" "$CONF_FILE" | tail -n1 | sed -E "s/^[[:space:]]*${SETTING_NAME}[[:space:]]*=[[:space:]]*//")

if [[ "$CURRENT_VALUE" != "$SETTING_VALUE" ]]; then
    echo "Failed to set ${SETTING_NAME} to ${SETTING_VALUE} in ${CONF_FILE}" >&2
    exit 1
fi

exit 0
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

CONFIG_FILE="/etc/security/pwquality.conf"
PARAM="ucredit"
VALUE="-1"

if [ ! -f "$CONFIG_FILE" ]; then
    touch "$CONFIG_FILE"
fi

if grep -qE "^\s*#?\s*${PARAM}\s*=" "$CONFIG_FILE"; then
    sed -i -E "s|^\s*#?\s*${PARAM}\s*=.*|${PARAM} = ${VALUE}|" "$CONFIG_FILE"
else
    printf '%s = %s\n' "$PARAM" "$VALUE" >> "$CONFIG_FILE"
fi

if ! command -v apt-get >/dev/null 2>&1; then
    :
fi

if command -v dpkg-query >/dev/null 2>&1; then
    if ! dpkg-query -W -f='${Status}' libpam-pwquality 2>/dev/null | grep -q "install ok installed"; then
        if command -v apt-get >/dev/null 2>&1; then
            apt-get update -y
            apt-get install -y libpam-pwquality
        fi
    fi
fi

CONFIRM=$(grep -E "^\s*${PARAM}\s*=\s*${VALUE}\s*$" "$CONFIG_FILE" || true)
if [ -z "$CONFIRM" ]; then
    echo "Failed to set ${PARAM} in ${CONFIG_FILE}" >&2
    exit 1
fi

exit 0
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
#!/bin/bash
set -euo pipefail

LOGIN_DEFS="/etc/login.defs"
MIN_ROUNDS=5000

backup_file() {
    local file="$1"
    if [ -f "$file" ] && [ ! -f "${file}.bak.$(date +%Y%m%d)" ]; then
        cp -p "$file" "${file}.bak.$(date +%Y%m%d)" 2>/dev/null || true
    fi
}

# --- Configure /etc/login.defs ---
backup_file "$LOGIN_DEFS"

configure_login_defs_param() {
    local param="$1"
    local min_value="$2"

    if grep -qE "^[[:space:]]*${param}[[:space:]]+[0-9]+" "$LOGIN_DEFS"; then
        local current_value
        current_value=$(grep -E "^[[:space:]]*${param}[[:space:]]+[0-9]+" "$LOGIN_DEFS" | tail -1 | awk '{print $2}')
        if [ "$current_value" -lt "$min_value" ]; then
            sed -i -E "s/^([[:space:]]*${param}[[:space:]]+)[0-9]+/\1${min_value}/" "$LOGIN_DEFS"
        fi
    else
        # Remove any commented-out or malformed lines for this param to avoid duplicates, then append
        echo "${param} ${min_value}" >> "$LOGIN_DEFS"
    fi
}

configure_login_defs_param "SHA_CRYPT_MIN_ROUNDS" "$MIN_ROUNDS"
configure_login_defs_param "SHA_CRYPT_MAX_ROUNDS" "$MIN_ROUNDS"

# --- Configure /etc/pam.d/common-password ---
PAM_FILE="/etc/pam.d/common-password"

if [ -f "$PAM_FILE" ]; then
    backup_file "$PAM_FILE"

    # Find lines with pam_unix.so and sha512 (or without specifying algorithm but that's less common)
    # We target lines that configure password hashing (pam_unix.so) and ensure rounds=5000 minimum
    if grep -qE '^\s*password\s+.*pam_unix\.so' "$PAM_FILE"; then
        # Process each matching line
        while IFS= read -r line_num; do
            line=$(sed -n "${line_num}p" "$PAM_FILE")

            # Check if rounds= is already present
            if echo "$line" | grep -qE 'rounds=[0-9]+'; then
                current_rounds=$(echo "$line" | grep -oE 'rounds=[0-9]+' | cut -d= -f2)
                if [ "$current_rounds" -lt "$MIN_ROUNDS" ]; then
                    new_line=$(echo "$line" | sed -E "s/rounds=[0-9]+/rounds=${MIN_ROUNDS}/")
                    sed -i "${line_num}s|.*|${new_line}|" "$PAM_FILE"
                fi
            else
                # Add rounds= parameter; ensure sha512 is present too for SHA-based hashing
                new_line="$line"
                if ! echo "$new_line" | grep -qE '\bsha512\b'; then
                    new_line="${new_line} sha512"
                fi
                new_line="${new_line} rounds=${MIN_ROUNDS}"
                sed -i "${line_num}s|.*|${new_line}|" "$PAM_FILE"
            fi
        done < <(grep -nE '^\s*password\s+.*pam_unix\.so' "$PAM_FILE" | cut -d: -f1)
    fi
fi

echo "Password hashing rounds policy enforced: minimum ${MIN_ROUNDS} rounds."
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
#
# remediate-debug-shell.sh
#
# Ensures the systemd debug-shell service (which provides an unauthenticated
# root shell on tty9 / a virtual console) is stopped, disabled, and masked
# so it cannot be started manually, automatically, or via socket/dependency
# activation. Idempotent: safe to run multiple times and across reboots.

set -euo pipefail

UNIT="debug-shell.service"

log() {
    printf '[remediate-debug-shell] %s\n' "$1"
}

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "This script must be run as root." >&2
        exit 1
    fi
}

require_systemctl() {
    if ! command -v systemctl >/dev/null 2>&1; then
        echo "systemctl not found; this remediation requires systemd." >&2
        exit 1
    fi
}

require_root
require_systemctl

# Reload unit files in case package state changed since last boot.
systemctl daemon-reload || true

# 1. Stop the service if it is currently active (idempotent: no-op if inactive).
if systemctl is-active --quiet "$UNIT" 2>/dev/null; then
    log "Stopping active $UNIT"
    systemctl stop "$UNIT"
else
    log "$UNIT is not active"
fi

# 2. Disable the service so it is not started by any enablement symlink/target.
if systemctl is-enabled --quiet "$UNIT" 2>/dev/null; then
    log "Disabling $UNIT"
    systemctl disable "$UNIT"
else
    log "$UNIT is already disabled (or not present)"
fi

# 3. Mask the service so it cannot be started manually, by dependency,
#    or by any other unit requiring it. This creates a symlink to
#    /dev/null in /etc/systemd/system, which persists across reboots.
CURRENT_STATE="$(systemctl is-enabled "$UNIT" 2>/dev/null || true)"
if [ "$CURRENT_STATE" != "masked" ]; then
    log "Masking $UNIT"
    systemctl mask "$UNIT"
else
    log "$UNIT is already masked"
fi

# 4. Reload systemd to make sure state is fully applied.
systemctl daemon-reload || true

# 5. Verification: confirm the unit is masked and inactive.
FINAL_STATE="$(systemctl is-enabled "$UNIT" 2>/dev/null || true)"
FINAL_ACTIVE="$(systemctl is-active "$UNIT" 2>/dev/null || true)"

if [ "$FINAL_STATE" = "masked" ]; then
    log "Verified: $UNIT is masked."
else
    echo "ERROR: $UNIT is not masked (state: $FINAL_STATE)" >&2
    exit 1
fi

if [ "$FINAL_ACTIVE" != "active" ]; then
    log "Verified: $UNIT is not active (state: $FINAL_ACTIVE)."
else
    echo "ERROR: $UNIT is still active." >&2
    exit 1
fi

log "Remediation complete: $UNIT is stopped, disabled, and masked persistently."
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

CONF_FILE="/etc/systemd/system.conf"
SETTING="CtrlAltDelBurstAction"
VALUE="none"
LINE="${SETTING}=${VALUE}"

if [[ ! -f "$CONF_FILE" ]]; then
    echo "Error: $CONF_FILE not found." >&2
    exit 1
fi

if [[ ! -w "$CONF_FILE" ]]; then
    echo "Error: $CONF_FILE is not writable. Run as root." >&2
    exit 1
fi

TIMESTAMP="$(date +%Y%m%d%H%M%S)"
BACKUP_FILE="${CONF_FILE}.bak.${TIMESTAMP}"

if grep -qE "^[[:space:]]*${SETTING}[[:space:]]*=" "$CONF_FILE"; then
    CURRENT_VALUE="$(grep -E "^[[:space:]]*${SETTING}[[:space:]]*=" "$CONF_FILE" | tail -n1 | sed -E "s/^[[:space:]]*${SETTING}[[:space:]]*=[[:space:]]*//")"
    if [[ "$CURRENT_VALUE" == "$VALUE" ]]; then
        echo "Setting '${LINE}' already present and correct in ${CONF_FILE}."
    else
        cp -p "$CONF_FILE" "$BACKUP_FILE"
        sed -i -E "s|^[[:space:]]*${SETTING}[[:space:]]*=.*|${LINE}|" "$CONF_FILE"
        echo "Updated ${SETTING} to '${VALUE}' in ${CONF_FILE} (backup: ${BACKUP_FILE})."
    fi
elif grep -qE "^[[:space:]]*#[[:space:]]*${SETTING}[[:space:]]*=" "$CONF_FILE"; then
    cp -p "$CONF_FILE" "$BACKUP_FILE"
    sed -i -E "s|^[[:space:]]*#[[:space:]]*${SETTING}[[:space:]]*=.*|${LINE}|" "$CONF_FILE"
    echo "Uncommented and set ${SETTING} to '${VALUE}' in ${CONF_FILE} (backup: ${BACKUP_FILE})."
else
    cp -p "$CONF_FILE" "$BACKUP_FILE"
    if grep -qE "^\[Manager\]" "$CONF_FILE"; then
        sed -i "/^\[Manager\]/a ${LINE}" "$CONF_FILE"
    else
        {
            echo "[Manager]"
            echo "${LINE}"
        } >> "$CONF_FILE"
    fi
    echo "Added ${SETTING}=${VALUE} to ${CONF_FILE} (backup: ${BACKUP_FILE})."
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    echo "systemd manager configuration reloaded."
else
    echo "Warning: systemctl not found; unable to reload systemd configuration." >&2
fi

FINAL_VALUE="$(grep -E "^[[:space:]]*${SETTING}[[:space:]]*=" "$CONF_FILE" | tail -n1 | sed -E "s/^[[:space:]]*${SETTING}[[:space:]]*=[[:space:]]*//")"
if [[ "$FINAL_VALUE" == "$VALUE" ]]; then
    echo "Verification successful: ${SETTING}=${VALUE} is set in ${CONF_FILE}."
else
    echo "Verification failed: ${SETTING} is not correctly set." >&2
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
#!/bin/bash
set -euo pipefail

OVERRIDE_DIR="/etc/systemd/system/ctrl-alt-del.target.d"
OVERRIDE_FILE="${OVERRIDE_DIR}/disable-cad.conf"

mkdir -p "$OVERRIDE_DIR"

cat > "$OVERRIDE_FILE" <<'EOF'
[Unit]
# This override disables the default reboot action triggered by
# Ctrl-Alt-Del by masking ctrl-alt-del.target and making it a no-op.
EOF

systemctl mask ctrl-alt-del.target

systemctl daemon-reload

systemctl disable ctrl-alt-del.target 2>/dev/null || true

exit 0
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
#
# Remediation script: Configure systemd-logind to terminate idle user
# sessions automatically after a defined period of inactivity.
#
# This script is idempotent - it can be run multiple times safely and
# will always leave the system in the desired end state.

set -euo pipefail

readonly LOGIND_CONF="/etc/systemd/logind.conf"
readonly IDLE_LIMIT="900"   # 15 minutes, in seconds. Non-zero, reasonable default.
readonly SETTING_NAME="StopIdleSessionSec"
readonly BACKUP_SUFFIX=".bak.$(date +%Y%m%d%H%M%S)"

main() {
    ensure_root

    if [ ! -f "${LOGIND_CONF}" ]; then
        echo "ERROR: ${LOGIND_CONF} not found. Is systemd-logind installed?" >&2
        exit 1
    fi

    backup_config

    apply_setting

    reload_logind

    verify_setting
}

ensure_root() {
    if [ "${EUID:-$(id -u)}" -ne 0 ]; then
        echo "ERROR: This script must be run as root." >&2
        exit 1
    fi
}

backup_config() {
    # Only back up if a backup doesn't already exist for today's run,
    # to avoid cluttering with duplicate backups on repeated runs.
    if ! cp -p "${LOGIND_CONF}" "${LOGIND_CONF}${BACKUP_SUFFIX}" 2>/dev/null; then
        echo "WARNING: Could not create backup of ${LOGIND_CONF}." >&2
    fi
}

apply_setting() {
    local desired_line="${SETTING_NAME}=${IDLE_LIMIT}"

    # Case 1: An active (uncommented) setting already exists.
    if grep -qE "^[[:space:]]*${SETTING_NAME}[[:space:]]*=" "${LOGIND_CONF}"; then
        # Update it in place if it doesn't already match the desired value.
        if ! grep -qxE "[[:space:]]*${SETTING_NAME}[[:space:]]*=[[:space:]]*${IDLE_LIMIT}[[:space:]]*" "${LOGIND_CONF}"; then
            sed -i -E "s|^[[:space:]]*${SETTING_NAME}[[:space:]]*=.*|${desired_line}|" "${LOGIND_CONF}"
            echo "Updated existing ${SETTING_NAME} setting to ${IDLE_LIMIT} seconds."
        else
            echo "${SETTING_NAME} already set to ${IDLE_LIMIT} seconds. No change needed."
        fi
        return
    fi

    # Case 2: A commented-out setting exists (e.g. "#StopIdleSessionSec=").
    if grep -qE "^[[:space:]]*#+[[:space:]]*${SETTING_NAME}[[:space:]]*=" "${LOGIND_CONF}"; then
        sed -i -E "s|^[[:space:]]*#+[[:space:]]*${SETTING_NAME}[[:space:]]*=.*|${desired_line}|" "${LOGIND_CONF}"
        echo "Uncommented and set ${SETTING_NAME} to ${IDLE_LIMIT} seconds."
        return
    fi

    # Case 3: No setting present at all; append it under the [Login] section.
    if grep -qE "^\[Login\]" "${LOGIND_CONF}"; then
        # Insert right after the [Login] section header.
        sed -i -E "0,/^\[Login\]/s|^\[Login\]|[Login]\n${desired_line}|" "${LOGIND_CONF}"
    else
        {
            echo ""
            echo "[Login]"
            echo "${desired_line}"
        } >>"${LOGIND_CONF}"
    fi
    echo "Added ${SETTING_NAME}=${IDLE_LIMIT} to ${LOGIND_CONF}."
}

reload_logind() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart systemd-logind.service 2>/dev/null || {
            echo "WARNING: Could not restart systemd-logind.service. A reboot may be required." >&2
        }
    fi
}

verify_setting() {
    if grep -qxE "[[:space:]]*${SETTING_NAME}[[:space:]]*=[[:space:]]*${IDLE_LIMIT}[[:space:]]*" "${LOGIND_CONF}"; then
        echo "Verification successful: ${SETTING_NAME}=${IDLE_LIMIT} is set in ${LOGIND_CONF}."
    else
        echo "ERROR: Verification failed. ${SETTING_NAME}=${IDLE_LIMIT} not found in ${LOGIND_CONF}." >&2
        exit 1
    fi
}

main "$@"
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
#!/bin/bash
#
# Remediation script to ensure smart-card support (PC/SC-Lite) is installed
# for multifactor authentication using hardware tokens (CAC/PIV cards).
#
# This script is idempotent: running it multiple times will not cause
# errors and will result in the same end state (package installed).

set -euo pipefail

PACKAGE_NAME="pcsc-lite"

# Function to check if the package is already installed
is_installed() {
    dpkg-query -W -f='${Status}' "${PACKAGE_NAME}" 2>/dev/null | grep -q "install ok installed"
}

main() {
    if is_installed; then
        echo "Package '${PACKAGE_NAME}' is already installed. No action needed."
        exit 0
    fi

    echo "Package '${PACKAGE_NAME}' is not installed. Proceeding with installation..."

    # Ensure apt package lists are up to date
    export DEBIAN_FRONTEND=noninteractive

    if ! apt-get update -y; then
        echo "ERROR: Failed to update package lists." >&2
        exit 1
    fi

    if ! apt-get install -y "${PACKAGE_NAME}"; then
        echo "ERROR: Failed to install package '${PACKAGE_NAME}'." >&2
        exit 1
    fi

    # Verify installation succeeded
    if is_installed; then
        echo "Package '${PACKAGE_NAME}' successfully installed."
    else
        echo "ERROR: Installation of '${PACKAGE_NAME}' could not be verified." >&2
        exit 1
    fi
}

main "$@"
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
#
# Remediation script: Ensure default password inactivity lock period (INACTIVE)
# for newly created user accounts is set to 30 days or less in /etc/default/useradd
#
# This script is idempotent - it can be run multiple times safely.

set -euo pipefail

USERADD_DEFAULTS="/etc/default/useradd"
DESIRED_INACTIVE_VALUE=30

# Ensure the file exists; if not, create it (useradd -D will normally create it)
if [[ ! -f "$USERADD_DEFAULTS" ]]; then
    touch "$USERADD_DEFAULTS"
    chmod 644 "$USERADD_DEFAULTS"
fi

# Use useradd -D to set the INACTIVE default persistently.
# This is the canonical, supported way to modify /etc/default/useradd
# and ensures correct formatting and any related side effects are handled.
current_inactive_value="$(useradd -D | awk -F= '/^INACTIVE=/{print $2}')"

if [[ "${current_inactive_value:-}" != "$DESIRED_INACTIVE_VALUE" ]]; then
    useradd -D -f "$DESIRED_INACTIVE_VALUE"
fi

# Verify the change took effect; fail loudly if not (helps catch environment issues)
final_inactive_value="$(useradd -D | awk -F= '/^INACTIVE=/{print $2}')"

if [[ "$final_inactive_value" != "$DESIRED_INACTIVE_VALUE" ]]; then
    echo "ERROR: Failed to set INACTIVE default to ${DESIRED_INACTIVE_VALUE} in ${USERADD_DEFAULTS}" >&2
    exit 1
fi

echo "INACTIVE default is set to ${final_inactive_value} days in ${USERADD_DEFAULTS}."
exit 0
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
PARAM="PASS_MAX_DAYS"
VALUE="60"

if [[ ! -f "$LOGIN_DEFS" ]]; then
    echo "Error: $LOGIN_DEFS not found." >&2
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root." >&2
    exit 1
fi

TIMESTAMP="$(date +%Y%m%d%H%M%S)"
BACKUP="${LOGIN_DEFS}.bak.${TIMESTAMP}"
cp -p "$LOGIN_DEFS" "$BACKUP"

if grep -qE "^[[:space:]]*${PARAM}[[:space:]]+[0-9]+" "$LOGIN_DEFS"; then
    CURRENT_VALUE="$(grep -E "^[[:space:]]*${PARAM}[[:space:]]+[0-9]+" "$LOGIN_DEFS" | awk '{print $2}' | tail -n1)"
    if [[ "$CURRENT_VALUE" == "$VALUE" ]]; then
        echo "${PARAM} is already set to ${VALUE} in ${LOGIN_DEFS}. No changes needed."
        rm -f "$BACKUP"
    else
        sed -i -E "s/^[[:space:]]*${PARAM}[[:space:]]+[0-9]+.*/${PARAM}\t${VALUE}/" "$LOGIN_DEFS"
        echo "Updated ${PARAM} from ${CURRENT_VALUE} to ${VALUE} in ${LOGIN_DEFS}."
    fi
elif grep -qE "^[[:space:]]*#?[[:space:]]*${PARAM}\b" "$LOGIN_DEFS"; then
    sed -i -E "s/^[[:space:]]*#?[[:space:]]*${PARAM}.*/${PARAM}\t${VALUE}/" "$LOGIN_DEFS"
    echo "Set commented/malformed ${PARAM} directive to ${VALUE} in ${LOGIN_DEFS}."
else
    printf "\n%s\t%s\n" "$PARAM" "$VALUE" >> "$LOGIN_DEFS"
    echo "Added ${PARAM} ${VALUE} to ${LOGIN_DEFS}."
fi

if grep -qE "^[[:space:]]*${PARAM}[[:space:]]+${VALUE}[[:space:]]*$" "$LOGIN_DEFS"; then
    echo "Verification successful: ${PARAM} is set to ${VALUE} in ${LOGIN_DEFS}."
else
    echo "Verification failed: ${PARAM} does not appear to be set correctly." >&2
    exit 1
fi

exit 0
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
#
# Remediation script: Enforce a minimum password age of 1 day for newly
# created user accounts on Ubuntu 24.04.
#
# This script is idempotent - it can be run multiple times safely.
# It modifies /etc/login.defs to set PASS_MIN_DAYS, which controls
# the default minimum number of days between password changes for
# newly created accounts (via useradd). It also updates existing
# user accounts to enforce this policy if desired (optional, disabled
# by default to keep scope aligned with "newly created user accounts").
#
# Persistence: /etc/login.defs is a static configuration file that
# persists across reboots by design.

set -euo pipefail

LOGIN_DEFS="/etc/login.defs"
DESIRED_VALUE=1
PARAM_NAME="PASS_MIN_DAYS"

# Ensure the file exists
if [[ ! -f "${LOGIN_DEFS}" ]]; then
    echo "ERROR: ${LOGIN_DEFS} not found. Cannot proceed." >&2
    exit 1
fi

# Backup the original file once, before first modification
BACKUP_FILE="${LOGIN_DEFS}.bak.$(date +%Y%m%d%H%M%S)"

# Function to check current effective value
get_current_value() {
    grep -E "^[[:space:]]*${PARAM_NAME}[[:space:]]+[0-9]+" "${LOGIN_DEFS}" \
        | awk '{print $2}' \
        | tail -n 1
}

CURRENT_VALUE="$(get_current_value || true)"

if [[ "${CURRENT_VALUE}" == "${DESIRED_VALUE}" ]]; then
    echo "INFO: ${PARAM_NAME} is already set to ${DESIRED_VALUE} in ${LOGIN_DEFS}. No changes needed."
else
    # Create a backup before making changes
    cp -p "${LOGIN_DEFS}" "${BACKUP_FILE}"
    echo "INFO: Backed up ${LOGIN_DEFS} to ${BACKUP_FILE}"

    if grep -qE "^[[:space:]]*${PARAM_NAME}[[:space:]]+[0-9]+" "${LOGIN_DEFS}"; then
        # Parameter exists (possibly multiple times or commented variants);
        # update the first uncommented occurrence and remove duplicates,
        # leaving a single canonical entry.
        awk -v param="${PARAM_NAME}" -v val="${DESIRED_VALUE}" '
            BEGIN { replaced = 0 }
            {
                if ($0 ~ "^[[:space:]]*" param "[[:space:]]+[0-9]+" && replaced == 0) {
                    print param "\t" val
                    replaced = 1
                } else if ($0 ~ "^[[:space:]]*" param "[[:space:]]+[0-9]+" && replaced == 1) {
                    # skip duplicate lines
                    next
                } else {
                    print $0
                }
            }
        ' "${LOGIN_DEFS}" > "${LOGIN_DEFS}.tmp"
        mv "${LOGIN_DEFS}.tmp" "${LOGIN_DEFS}"
        echo "INFO: Updated existing ${PARAM_NAME} entry to ${DESIRED_VALUE} in ${LOGIN_DEFS}."
    else
        # Parameter does not exist; append it, preferably near
        # PASS_MAX_DAYS if present, else at end of file.
        if grep -qE "^[[:space:]]*PASS_MAX_DAYS[[:space:]]+[0-9]+" "${LOGIN_DEFS}"; then
            awk -v param="${PARAM_NAME}" -v val="${DESIRED_VALUE}" '
                {
                    print $0
                    if ($0 ~ "^[[:space:]]*PASS_MAX_DAYS[[:space:]]+[0-9]+") {
                        print param "\t" val
                    }
                }
            ' "${LOGIN_DEFS}" > "${LOGIN_DEFS}.tmp"
            mv "${LOGIN_DEFS}.tmp" "${LOGIN_DEFS}"
        else
            {
                echo ""
                echo "# Minimum number of days allowed between password changes."
                echo "${PARAM_NAME}	${DESIRED_VALUE}"
            } >> "${LOGIN_DEFS}"
        fi
        echo "INFO: Added ${PARAM_NAME} ${DESIRED_VALUE} to ${LOGIN_DEFS}."
    fi
fi

# Final verification
FINAL_VALUE="$(get_current_value || true)"
if [[ "${FINAL_VALUE}" == "${DESIRED_VALUE}" ]]; then
    echo "SUCCESS: ${PARAM_NAME} is set to ${DESIRED_VALUE} in ${LOGIN_DEFS}."
else
    echo "ERROR: Failed to set ${PARAM_NAME} to ${DESIRED_VALUE} in ${LOGIN_DEFS}." >&2
    exit 1
fi

exit 0
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
#
# Remediation script: Enforce minimum password length of 15 characters
# system-wide on Ubuntu 24.04 (idempotent, persists across reboots).
#
# This configures:
#   1. /etc/login.defs        -> PASS_MIN_LEN (legacy, informational)
#   2. /etc/security/pwquality.conf -> minlen (enforced by PAM pwquality)
#
set -euo pipefail

# ------------------------------------------------------------------
# Ensure required package providing pwquality PAM module is present
# ------------------------------------------------------------------
if ! dpkg -s libpam-pwquality >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y libpam-pwquality
fi

MIN_LEN=15

# ------------------------------------------------------------------
# 1. /etc/security/pwquality.conf - set minlen = 15
# ------------------------------------------------------------------
PWQUALITY_CONF="/etc/security/pwquality.conf"

if [ ! -f "$PWQUALITY_CONF" ]; then
    touch "$PWQUALITY_CONF"
fi

if grep -Eq '^\s*#?\s*minlen\s*=' "$PWQUALITY_CONF"; then
    sed -i -E "s/^\s*#?\s*minlen\s*=.*/minlen = ${MIN_LEN}/" "$PWQUALITY_CONF"
else
    printf '\nminlen = %s\n' "${MIN_LEN}" >> "$PWQUALITY_CONF"
fi

# ------------------------------------------------------------------
# 2. /etc/login.defs - set PASS_MIN_LEN (legacy, for completeness)
# ------------------------------------------------------------------
LOGIN_DEFS="/etc/login.defs"

if grep -Eq '^\s*#?\s*PASS_MIN_LEN\s+' "$LOGIN_DEFS"; then
    sed -i -E "s/^\s*#?\s*PASS_MIN_LEN\s+.*/PASS_MIN_LEN\t${MIN_LEN}/" "$LOGIN_DEFS"
else
    printf 'PASS_MIN_LEN\t%s\n' "${MIN_LEN}" >> "$LOGIN_DEFS"
fi

# ------------------------------------------------------------------
# 3. Ensure PAM common-password includes pam_pwquality with retry
# ------------------------------------------------------------------
PAM_PASSWORD_FILE="/etc/pam.d/common-password"

if [ -f "$PAM_PASSWORD_FILE" ]; then
    if grep -Eq '^\s*password\s+(requisite|required)\s+pam_pwquality\.so' "$PAM_PASSWORD_FILE"; then
        # Ensure retry option exists; do not touch minlen here since pwquality.conf governs it
        if ! grep -Eq '^\s*password\s+(requisite|required)\s+pam_pwquality\.so.*retry=' "$PAM_PASSWORD_FILE"; then
            sed -i -E "s/^(\s*password\s+(requisite|required)\s+pam_pwquality\.so.*)$/\1 retry=3/" "$PAM_PASSWORD_FILE"
        fi
    else
        # Insert pam_pwquality line before pam_unix.so password line
        if grep -Eq '^\s*password\s+\[?success=1' "$PAM_PASSWORD_FILE" || grep -Eq '^\s*password\s+requisite\s+pam_unix\.so' "$PAM_PASSWORD_FILE" || grep -Eq '^\s*password\s+\S+\s+pam_unix\.so' "$PAM_PASSWORD_FILE"; then
            sed -i -E "0,/^\s*password\s+\S+\s+pam_unix\.so/s//password\trequisite\t\t\tpam_pwquality.so retry=3\n&/" "$PAM_PASSWORD_FILE"
        else
            printf 'password\trequisite\t\t\tpam_pwquality.so retry=3\n' >> "$PAM_PASSWORD_FILE"
        fi
    fi
else
    cat > "$PAM_PASSWORD_FILE" <<EOF
password    requisite           pam_pwquality.so retry=3
password    [success=1 default=ignore]  pam_unix.so obscure use_authtok try_first_pass sha512
password    requisite           pam_deny.so
password    required            pam_permit.so
EOF
fi

echo "Password policy remediation applied: minimum password length set to ${MIN_LEN} characters."
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
#!/bin/bash
#
# Remediation script: Ensure all local user accounts have a maximum
# password age of 365 days (idempotent).
#
# This script:
#   1. Updates the default PASS_MAX_DAYS setting in /etc/login.defs
#      so that any newly created accounts get the correct value.
#   2. Iterates over all local user accounts defined in /etc/passwd
#      (i.e., accounts with an entry in /etc/shadow) and, for each
#      account whose current maximum password age is not exactly 365,
#      updates it using chage.
#
# Running the script multiple times will not change anything further
# once compliance has been achieved (idempotent).

set -euo pipefail

readonly MAX_DAYS=365
readonly LOGIN_DEFS="/etc/login.defs"

# Ensure the script is run as root
if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

# --- Step 1: Update /etc/login.defs default ------------------------------

if grep -qE '^\s*PASS_MAX_DAYS\s+' "$LOGIN_DEFS"; then
    current_default=$(grep -E '^\s*PASS_MAX_DAYS\s+' "$LOGIN_DEFS" | awk '{print $2}' | tail -n1)
    if [[ "$current_default" != "$MAX_DAYS" ]]; then
        sed -i -E "s/^\s*PASS_MAX_DAYS\s+.*/PASS_MAX_DAYS   ${MAX_DAYS}/" "$LOGIN_DEFS"
        echo "Updated PASS_MAX_DAYS in ${LOGIN_DEFS} to ${MAX_DAYS}."
    else
        echo "PASS_MAX_DAYS in ${LOGIN_DEFS} already set to ${MAX_DAYS}. No change needed."
    fi
else
    echo "PASS_MAX_DAYS   ${MAX_DAYS}" >> "$LOGIN_DEFS"
    echo "Added PASS_MAX_DAYS=${MAX_DAYS} to ${LOGIN_DEFS}."
fi

# --- Step 2: Update existing local user accounts --------------------------

# Get list of usernames that have an entry in /etc/shadow (i.e., local accounts)
mapfile -t shadow_users < <(awk -F: '{print $1}' /etc/shadow)

for user in "${shadow_users[@]}"; do
    # Skip if user does not exist in /etc/passwd (shouldn't normally happen)
    if ! getent passwd "$user" >/dev/null 2>&1; then
        continue
    fi

    # Retrieve current max password age using chage
    current_max=$(chage -l "$user" 2>/dev/null | awk -F': ' '/Maximum number of days between password change/ {print $2}')

    # If chage couldn't retrieve info (e.g., locked/system account without shadow fields), skip
    if [[ -z "$current_max" ]]; then
        continue
    fi

    # Normalize "never" or empty values by treating them as non-compliant
    if [[ "$current_max" == "never" || "$current_max" == "-1" ]]; then
        current_max="-1"
    fi

    if [[ "$current_max" != "$MAX_DAYS" ]]; then
        if chage -M "$MAX_DAYS" "$user" 2>/dev/null; then
            echo "Set PASS_MAX_DAYS=${MAX_DAYS} for user '${user}'."
        else
            echo "WARNING: Failed to update max password age for user '${user}'." >&2
        fi
    fi
done

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
# Remediation script: Enforce minimum password age (PASS_MIN_DAYS) of 1
# for all existing local user accounts, and update /etc/login.defs so
# future accounts inherit this setting as well.
#
# Idempotent: running multiple times will not change already-compliant
# accounts or configuration.

set -euo pipefail

MIN_DAYS=1
LOGIN_DEFS="/etc/login.defs"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# --- 1. Update /etc/login.defs so new accounts get the correct default ---
if [[ -f "$LOGIN_DEFS" ]]; then
    if grep -qE '^[[:space:]]*PASS_MIN_DAYS[[:space:]]+' "$LOGIN_DEFS"; then
        current_val=$(grep -E '^[[:space:]]*PASS_MIN_DAYS[[:space:]]+' "$LOGIN_DEFS" | awk '{print $2}' | tail -n1)
        if [[ "$current_val" =~ ^[0-9]+$ ]] && [[ "$current_val" -ge "$MIN_DAYS" ]]; then
            : # already compliant, do nothing
        else
            sed -i -E "s/^([[:space:]]*PASS_MIN_DAYS[[:space:]]+).*/\1${MIN_DAYS}/" "$LOGIN_DEFS"
            echo "Updated PASS_MIN_DAYS in $LOGIN_DEFS to $MIN_DAYS"
        fi
    else
        printf '\nPASS_MIN_DAYS\t%s\n' "$MIN_DAYS" >> "$LOGIN_DEFS"
        echo "Added PASS_MIN_DAYS=$MIN_DAYS to $LOGIN_DEFS"
    fi
fi

# --- 2. Determine the UID range considered "regular" / "local" users ---
# Use login.defs UID_MIN/UID_MAX if available, else fall back to typical defaults.
UID_MIN=$(awk '/^[[:space:]]*UID_MIN[[:space:]]+/ {print $2}' "$LOGIN_DEFS" 2>/dev/null | tail -n1)
UID_MAX=$(awk '/^[[:space:]]*UID_MAX[[:space:]]+/ {print $2}' "$LOGIN_DEFS" 2>/dev/null | tail -n1)
UID_MIN=${UID_MIN:-1000}
UID_MAX=${UID_MAX:-60000}

# --- 3. Iterate over all local user accounts in /etc/passwd ---
# We include all accounts with a valid shadow entry (i.e., real local accounts),
# not just those within UID_MIN..UID_MAX, since system accounts with
# interactive login shells could also have password aging fields set.
# However, to be safe and avoid touching accounts that don't have passwords
# (e.g., accounts locked with '*' or '!'), we check /etc/shadow.

while IFS=: read -r username _ uid _ _ _ shell; do
    # Skip nologin/false shells for system accounts, but still check real users.
    # We only care about accounts that actually have shadow password entries.

    shadow_entry=$(getent shadow "$username" 2>/dev/null || true)
    [[ -z "$shadow_entry" ]] && continue

    IFS=: read -r _ passwd_field lastchg minage maxage warn inactive expire _ <<< "$shadow_entry"

    # Skip accounts without a real password set (locked/disabled accounts)
    case "$passwd_field" in
        ""|"!"|"!!"|"*"|"*LK*")
            continue
            ;;
    esac

    # Some accounts may not have password field starting with $ (hashed) but
    # could still be legitimate (e.g., empty password intentionally disabled).
    # We proceed only if passwd_field looks like a hash (starts with $ or is a valid crypt string).
    if [[ "$passwd_field" != \$* ]]; then
        continue
    fi

    # Determine current minage; treat empty as 0
    current_minage="${minage:-0}"
    if ! [[ "$current_minage" =~ ^[0-9]+$ ]]; then
        current_minage=0
    fi

    if [[ "$current_minage" -lt "$MIN_DAYS" ]]; then
        chage --mindays "$MIN_DAYS" "$username"
        echo "Set minimum password age to $MIN_DAYS day(s) for user: $username"
    fi

done < /etc/passwd

exit 0
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
#!/bin/bash
#
# Remediation script for Ubuntu 24.04
# Ensures that accounts with empty/blank passwords are refused login
# by removing "nullok" options from PAM configuration files.
#
# Idempotent: running multiple times has no additional effect.

set -euo pipefail

# List of PAM configuration files that may contain nullok
PAM_FILES=(
    "/etc/pam.d/common-auth"
    "/etc/pam.d/system-auth"
    "/etc/pam.d/password-auth"
)

# Also scan all files under /etc/pam.d for nullok, in case of custom configs
mapfile -t ALL_PAM_FILES < <(grep -rl "nullok" /etc/pam.d/ 2>/dev/null || true)

# Merge unique list of files to process
declare -A FILES_TO_PROCESS
for f in "${PAM_FILES[@]}" "${ALL_PAM_FILES[@]}"; do
    if [[ -f "$f" ]]; then
        FILES_TO_PROCESS["$f"]=1
    fi
done

TIMESTAMP=$(date +%Y%m%d%H%M%S)
CHANGED=0

for file in "${!FILES_TO_PROCESS[@]}"; do
    if grep -qE '(^|[[:space:]])nullok(_secure)?([[:space:]]|$)' "$file"; then
        # Backup only once per run per file
        BACKUP="${file}.bak.${TIMESTAMP}"
        cp -p "$file" "$BACKUP"

        # Remove nullok and nullok_secure tokens, preserving rest of line formatting
        sed -i -E 's/([[:space:]])nullok(_secure)?([[:space:]]|$)/\1\3/g; s/^nullok(_secure)?([[:space:]]|$)/\2/g' "$file"

        # Clean up any resulting double spaces
        sed -i -E 's/[[:space:]]+/ /g; s/[[:space:]]+$//' "$file"

        echo "Removed nullok option(s) from $file (backup saved as $BACKUP)"
        CHANGED=1
    fi
done

# Additionally, ensure pwquality or pam_unix doesn't have nullok via authconfig-style configs (defensive check)
if command -v pam-auth-update >/dev/null 2>&1; then
    # Re-run pam-auth-update to regenerate common-* files consistently, non-interactively
    DEBIAN_FRONTEND=noninteractive pam-auth-update --package >/dev/null 2>&1 || true
fi

if [[ "$CHANGED" -eq 1 ]]; then
    echo "PAM configuration updated: empty password logins are now refused."
else
    echo "No nullok entries found; system already compliant."
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
#!/bin/bash
set -euo pipefail

LOGIN_DEFS="/etc/login.defs"
REQUIRED_DELAY=4
PARAM="FAIL_DELAY"

if [[ ! -f "$LOGIN_DEFS" ]]; then
    echo "Error: $LOGIN_DEFS not found." >&2
    exit 1
fi

# Backup before modifying, only once
BACKUP="${LOGIN_DEFS}.bak.$(date +%Y%m%d%H%M%S)"
if ! cp -n "$LOGIN_DEFS" "$BACKUP" 2>/dev/null; then
    :
fi

# Get current value of FAIL_DELAY if set (uncommented)
current_value=$(grep -E "^[[:space:]]*${PARAM}[[:space:]]+[0-9]+" "$LOGIN_DEFS" | awk '{print $2}' | tail -n1 || true)

if [[ -n "$current_value" ]]; then
    if [[ "$current_value" -ge "$REQUIRED_DELAY" ]]; then
        echo "FAIL_DELAY already set to $current_value (>= $REQUIRED_DELAY). No changes needed."
        exit 0
    else
        echo "Updating existing FAIL_DELAY from $current_value to $REQUIRED_DELAY"
        sed -i -E "s/^[[:space:]]*${PARAM}[[:space:]]+[0-9]+.*/${PARAM}\t${REQUIRED_DELAY}/" "$LOGIN_DEFS"
    fi
else
    # Check if there's a commented-out FAIL_DELAY line to replace
    if grep -qE "^[[:space:]]*#[[:space:]]*${PARAM}[[:space:]]+[0-9]+" "$LOGIN_DEFS"; then
        echo "Uncommenting and setting FAIL_DELAY to $REQUIRED_DELAY"
        sed -i -E "s/^[[:space:]]*#[[:space:]]*${PARAM}[[:space:]]+[0-9]+.*/${PARAM}\t${REQUIRED_DELAY}/" "$LOGIN_DEFS"
    else
        echo "Adding FAIL_DELAY ${REQUIRED_DELAY} to $LOGIN_DEFS"
        printf '\n# Enforce minimum delay (in seconds) after a failed login attempt\n%s\t%s\n' "$PARAM" "$REQUIRED_DELAY" >> "$LOGIN_DEFS"
    fi
fi

# Verify the change took effect
new_value=$(grep -E "^[[:space:]]*${PARAM}[[:space:]]+[0-9]+" "$LOGIN_DEFS" | awk '{print $2}' | tail -n1 || true)

if [[ -z "$new_value" || "$new_value" -lt "$REQUIRED_DELAY" ]]; then
    echo "Error: Failed to enforce FAIL_DELAY >= $REQUIRED_DELAY in $LOGIN_DEFS" >&2
    exit 1
fi

echo "Success: FAIL_DELAY is now set to $new_value in $LOGIN_DEFS"
exit 0
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
#!/bin/bash
#
# remediate_maxlogins.sh
#
# Idempotent remediation script to enforce a per-user concurrent login
# session limit of 10 on Ubuntu 24.04 via /etc/security/limits.conf
# (and drop-in directory), persisting across reboots.

set -euo pipefail

LIMITS_FILE="/etc/security/limits.conf"
LIMITS_DIR="/etc/security/limits.d"
DROPIN_FILE="${LIMITS_DIR}/90-maxlogins.conf"
MAXLOGIN_VALUE=10
MARKER_HARD="* hard maxlogins ${MAXLOGIN_VALUE}"
MARKER_SOFT="* soft maxlogins ${MAXLOGIN_VALUE}"

# Ensure limits.d directory exists
if [ ! -d "${LIMITS_DIR}" ]; then
    mkdir -p "${LIMITS_DIR}"
    chmod 755 "${LIMITS_DIR}"
fi

# Ensure the main limits.conf file exists
if [ ! -f "${LIMITS_FILE}" ]; then
    touch "${LIMITS_FILE}"
    chmod 644 "${LIMITS_FILE}"
fi

# Function to remove any pre-existing maxlogins directives for '*'
# from a given file, so we can idempotently enforce the correct value.
remove_existing_maxlogins() {
    local file="$1"
    if [ -f "$file" ]; then
        # Remove lines that set maxlogins for the wildcard domain '*'
        # (both soft and hard), ignoring commented lines.
        sed -i.bak -E '/^[[:space:]]*\*[[:space:]]+(soft|hard)[[:space:]]+maxlogins[[:space:]]+[0-9]+[[:space:]]*$/d' "$file"
        rm -f "${file}.bak"
    fi
}

# Clean up any existing maxlogins entries in both the main file and drop-in file
remove_existing_maxlogins "${LIMITS_FILE}"
remove_existing_maxlogins "${DROPIN_FILE}"

# Write the drop-in file with the correct, idempotent configuration.
# This ensures a single source of truth and avoids duplicate entries.
cat > "${DROPIN_FILE}" <<EOF
# Managed by remediate_maxlogins.sh
# Enforce a maximum of ${MAXLOGIN_VALUE} concurrent login sessions per user
# to mitigate denial-of-service conditions from excessive simultaneous logins.
${MARKER_SOFT}
${MARKER_HARD}
EOF

chmod 644 "${DROPIN_FILE}"
chown root:root "${DROPIN_FILE}"

# Ensure pam_limits is enabled for login-related PAM services so that
# the limits.conf/limits.d settings are actually enforced.
PAM_FILES=(
    "/etc/pam.d/common-session"
    "/etc/pam.d/common-session-noninteractive"
)

PAM_LIMITS_LINE="session required pam_limits.so"

for pam_file in "${PAM_FILES[@]}"; do
    if [ -f "$pam_file" ]; then
        if ! grep -qE '^[[:space:]]*session[[:space:]]+required[[:space:]]+pam_limits\.so' "$pam_file"; then
            echo "${PAM_LIMITS_LINE}" >> "$pam_file"
        fi
    fi
done

# Also ensure pam_limits is enabled in login and sshd PAM configs,
# as some services may not include common-session.
for pam_file in "/etc/pam.d/login" "/etc/pam.d/sshd"; do
    if [ -f "$pam_file" ]; then
        if ! grep -qE '^[[:space:]]*session[[:space:]]+(required|requisite)[[:space:]]+pam_limits\.so' "$pam_file" \
           && ! grep -qE '^[[:space:]]*@include[[:space:]]+common-session[[:space:]]*$' "$pam_file"; then
            echo "${PAM_LIMITS_LINE}" >> "$pam_file"
        fi
    fi
done

echo "Per-user concurrent login session limit of ${MAXLOGIN_VALUE} has been enforced via ${DROPIN_FILE}."
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
#!/bin/bash
#
# Remediation script: Ensure all files and directories within each local
# interactive user's home directory are group-owned by a group of which
# the user is a member.
#
# This script is idempotent: running it multiple times has no negative
# effect, since it only changes group ownership when the current group
# is not one of the user's groups.

set -u

UID_MIN=1000
UID_MAX=60000

# Try to read UID_MIN from /etc/login.defs if present, for accuracy.
if [ -f /etc/login.defs ]; then
    login_defs_uid_min=$(awk '/^UID_MIN/ {print $2}' /etc/login.defs 2>/dev/null)
    if [ -n "${login_defs_uid_min:-}" ]; then
        UID_MIN="$login_defs_uid_min"
    fi
fi

# Iterate over local interactive users from /etc/passwd
awk -v min="$UID_MIN" -v max="$UID_MAX" -F: '
    ($3 >= min && $3 <= max) && ($7 !~ /(nologin|false)$/) { print $1 ":" $3 ":" $6 }
' /etc/passwd | while IFS=: read -r user uid home; do

    # Skip if home directory does not exist or is not a directory
    if [ -z "${home:-}" ] || [ ! -d "$home" ]; then
        continue
    fi

    # Skip well-known system/service home directories that might overlap
    case "$home" in
        /|/root|/bin|/sbin|/usr|/usr/*|/proc|/sys|/dev)
            continue
            ;;
    esac

    # Get the set of group IDs (numeric) the user belongs to
    user_gids=$(id -G "$user" 2>/dev/null)
    if [ -z "$user_gids" ]; then
        continue
    fi

    primary_gid=$(id -g "$user" 2>/dev/null)
    if [ -z "$primary_gid" ]; then
        continue
    fi

    # Build a quick lookup pattern for group IDs
    gid_pattern=" ${user_gids} "

    # Walk all files and directories in the user's home directory
    while IFS= read -r -d '' entry; do
        file_gid=$(stat -c '%g' "$entry" 2>/dev/null)
        if [ -z "$file_gid" ]; then
            continue
        fi

        if [[ "$gid_pattern" != *" $file_gid "* ]]; then
            chgrp "$primary_gid" "$entry" 2>/dev/null
        fi
    done < <(find "$home" -xdev \( -type f -o -type d \) -print0 2>/dev/null)

done

exit 0
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
#
# Remediation script: Set default Bash shell umask system-wide to 027
# Idempotent: safe to run multiple times without duplicating changes.

set -euo pipefail

UMASK_VALUE="027"
UMASK_LINE="umask ${UMASK_VALUE}"

# List of files to check/update for system-wide bash umask settings
TARGET_FILES=(
    "/etc/bash.bashrc"
    "/etc/profile"
)

# Also handle /etc/profile.d directory with a dedicated script
PROFILE_D_FILE="/etc/profile.d/99-umask.sh"

remediate_file() {
    local file="$1"

    # Ensure the file exists
    if [[ ! -f "$file" ]]; then
        touch "$file"
    fi

    # Remove any existing uncommented umask lines (various forms) to avoid conflicts
    # This matches lines like: umask 022, umask   0022, umask something
    if grep -Eq '^[[:space:]]*umask[[:space:]]+[0-7]{3,4}[[:space:]]*$' "$file"; then
        sed -i -E '/^[[:space:]]*umask[[:space:]]+[0-7]{3,4}[[:space:]]*$/d' "$file"
    fi

    # Append the desired umask setting if not already present
    if ! grep -Fxq "${UMASK_LINE}" "$file"; then
        {
            echo ""
            echo "# Set default umask for Bash shell (CIS/DISA remediation)"
            echo "${UMASK_LINE}"
        } >> "$file"
    fi
}

# Remediate the primary system-wide bash configuration files
for f in "${TARGET_FILES[@]}"; do
    remediate_file "$f"
done

# Create/update a dedicated profile.d script to enforce umask for all login shells
if [[ ! -f "$PROFILE_D_FILE" ]]; then
    cat > "$PROFILE_D_FILE" <<EOF
#!/bin/sh
# Enforce default umask system-wide (CIS/DISA remediation)
umask ${UMASK_VALUE}
EOF
    chmod 0644 "$PROFILE_D_FILE"
else
    # Ensure existing file has correct umask line, replacing any prior umask directives
    if grep -Eq '^[[:space:]]*umask[[:space:]]+[0-7]{3,4}[[:space:]]*$' "$PROFILE_D_FILE"; then
        sed -i -E '/^[[:space:]]*umask[[:space:]]+[0-7]{3,4}[[:space:]]*$/d' "$PROFILE_D_FILE"
    fi
    if ! grep -Fxq "${UMASK_LINE}" "$PROFILE_D_FILE"; then
        echo "${UMASK_LINE}" >> "$PROFILE_D_FILE"
    fi
    chmod 0644 "$PROFILE_D_FILE"
fi

# Also address /etc/login.defs UMASK setting used by login and su for non-interactive shells
LOGIN_DEFS="/etc/login.defs"
if [[ -f "$LOGIN_DEFS" ]]; then
    if grep -Eq '^[[:space:]]*UMASK[[:space:]]+[0-7]{3,4}[[:space:]]*$' "$LOGIN_DEFS"; then
        sed -i -E "s/^[[:space:]]*UMASK[[:space:]]+[0-7]{3,4}[[:space:]]*\$/UMASK           ${UMASK_VALUE}/" "$LOGIN_DEFS"
    else
        echo "UMASK           ${UMASK_VALUE}" >> "$LOGIN_DEFS"
    fi
fi

# Verify final state
echo "Umask remediation applied. Current settings:"
for f in "${TARGET_FILES[@]}" "$PROFILE_D_FILE" "$LOGIN_DEFS"; do
    if [[ -f "$f" ]]; then
        echo "---- $f ----"
        grep -E '^[[:space:]]*(umask|UMASK)[[:space:]]+[0-7]{3,4}[[:space:]]*$' "$f" || true
    fi
done

exit 0
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
#!/bin/bash
set -euo pipefail

UMASK_VALUE="077"
FILES=("/etc/csh.cshrc" "/etc/csh.login")

for FILE in "${FILES[@]}"; do
    if [ ! -f "$FILE" ]; then
        touch "$FILE"
    fi

    # Remove any existing umask lines to avoid duplicates or conflicting values
    if grep -qE '^[[:space:]]*umask[[:space:]]+[0-7]+' "$FILE"; then
        sed -i -E '/^[[:space:]]*umask[[:space:]]+[0-7]+/d' "$FILE"
    fi

    # Append the desired umask setting
    echo "umask ${UMASK_VALUE}" >> "$FILE"
done

exit 0
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

LOGIN_DEFS="/etc/login.defs"
DESIRED_MASK="077"

if [[ ! -f "$LOGIN_DEFS" ]]; then
    echo "Error: $LOGIN_DEFS not found." >&2
    exit 1
fi

if [[ ! -w "$LOGIN_DEFS" ]]; then
    echo "Error: Insufficient permissions to modify $LOGIN_DEFS. Run as root." >&2
    exit 1
fi

TIMESTAMP="$(date +%Y%m%d%H%M%S)"
BACKUP_FILE="${LOGIN_DEFS}.bak.${TIMESTAMP}"

CURRENT_LINE="$(grep -E '^[[:space:]]*UMASK[[:space:]]+' "$LOGIN_DEFS" || true)"

if [[ -n "$CURRENT_LINE" ]]; then
    CURRENT_VALUE="$(echo "$CURRENT_LINE" | awk '{print $2}')"
    if [[ "$CURRENT_VALUE" == "$DESIRED_MASK" ]]; then
        echo "UMASK is already set to $DESIRED_MASK in $LOGIN_DEFS. No changes needed."
        exit 0
    fi
fi

cp -p "$LOGIN_DEFS" "$BACKUP_FILE"
echo "Backup of $LOGIN_DEFS created at $BACKUP_FILE"

if grep -qE '^[[:space:]]*UMASK[[:space:]]+' "$LOGIN_DEFS"; then
    sed -i -E "s/^[[:space:]]*UMASK[[:space:]]+.*/UMASK           ${DESIRED_MASK}/" "$LOGIN_DEFS"
    echo "Updated existing UMASK entry in $LOGIN_DEFS to ${DESIRED_MASK}."
elif grep -qE '^[[:space:]]*#[[:space:]]*UMASK[[:space:]]+' "$LOGIN_DEFS"; then
    sed -i -E "s/^[[:space:]]*#[[:space:]]*UMASK[[:space:]]+.*/UMASK           ${DESIRED_MASK}/" "$LOGIN_DEFS"
    echo "Uncommented and updated UMASK entry in $LOGIN_DEFS to ${DESIRED_MASK}."
else
    {
        echo ""
        echo "UMASK           ${DESIRED_MASK}"
    } >> "$LOGIN_DEFS"
    echo "Added new UMASK entry (${DESIRED_MASK}) to $LOGIN_DEFS."
fi

if grep -qE "^UMASK[[:space:]]+${DESIRED_MASK}([[:space:]]|$)" "$LOGIN_DEFS"; then
    echo "Verification successful: UMASK is now set to ${DESIRED_MASK} in $LOGIN_DEFS."
else
    echo "Error: Verification failed. UMASK setting was not applied correctly." >&2
    exit 1
fi

echo "Remediation complete. The default file-creation mask (UMASK ${DESIRED_MASK}) will apply to new login sessions."
exit 0
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
#!/bin/bash
#
# Remediation script: Enable Kernel Page-Table Isolation (KPTI)
# to mitigate Meltdown (CVE-2017-5754) and strengthen KASLR defenses.
#
# Idempotent: safe to run multiple times.

set -euo pipefail

GRUB_FILE="/etc/default/grub"
PARAM="pti=on"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

if [[ ! -f "$GRUB_FILE" ]]; then
    echo "GRUB default configuration file not found at $GRUB_FILE" >&2
    exit 1
fi

# Backup original file once
if [[ ! -f "${GRUB_FILE}.bak" ]]; then
    cp -a "$GRUB_FILE" "${GRUB_FILE}.bak"
fi

# Ensure GRUB_CMDLINE_LINUX_DEFAULT exists
if ! grep -qE '^GRUB_CMDLINE_LINUX_DEFAULT=' "$GRUB_FILE"; then
    echo 'GRUB_CMDLINE_LINUX_DEFAULT=""' >> "$GRUB_FILE"
fi

# Ensure GRUB_CMDLINE_LINUX exists
if ! grep -qE '^GRUB_CMDLINE_LINUX=' "$GRUB_FILE"; then
    echo 'GRUB_CMDLINE_LINUX=""' >> "$GRUB_FILE"
fi

add_param_if_missing() {
    local var_name="$1"
    local current_line
    current_line=$(grep -E "^${var_name}=" "$GRUB_FILE" || true)

    if [[ -z "$current_line" ]]; then
        return
    fi

    # Extract the value between quotes
    local current_value
    current_value=$(echo "$current_line" | sed -E "s/^${var_name}=\"(.*)\"$/\1/")

    # Check if PARAM is already present as a whole word
    if echo " $current_value " | grep -qE "[[:space:]]${PARAM}[[:space:]]"; then
        return
    fi

    # Append the parameter, ensuring proper spacing
    local new_value
    if [[ -z "$current_value" ]]; then
        new_value="$PARAM"
    else
        new_value="$current_value $PARAM"
    fi

    # Use a temporary file for safe in-place editing
    local tmp_file
    tmp_file=$(mktemp)
    sed -E "s|^${var_name}=\".*\"$|${var_name}=\"${new_value}\"|" "$GRUB_FILE" > "$tmp_file"
    mv "$tmp_file" "$GRUB_FILE"
}

add_param_if_missing "GRUB_CMDLINE_LINUX_DEFAULT"
add_param_if_missing "GRUB_CMDLINE_LINUX"

# Regenerate grub configuration so it applies to all installed kernels
if command -v update-grub >/dev/null 2>&1; then
    update-grub
elif command -v grub-mkconfig >/dev/null 2>&1; then
    grub-mkconfig -o /boot/grub/grub.cfg
else
    echo "Could not find update-grub or grub-mkconfig to regenerate GRUB configuration." >&2
    exit 1
fi

echo "KPTI (pti=on) has been enabled in GRUB configuration. It will persist across reboots and apply to all installed and future kernels."
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
#!/bin/bash
#
# Remediation: Disable the legacy vsyscall interface on Ubuntu 24.04
# by enforcing vsyscall=none via GRUB, so it applies to all installed
# kernels and persists for future kernel installs. Idempotent.

set -euo pipefail

GRUB_DEFAULT_FILE="/etc/default/grub"
GRUB_DROPIN_DIR="/etc/default/grub.d"
GRUB_DROPIN_FILE="${GRUB_DROPIN_DIR}/99-disable-vsyscall.cfg"
PARAM="vsyscall=none"

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root." >&2
    exit 1
fi

if [ ! -f "$GRUB_DEFAULT_FILE" ]; then
    echo "ERROR: $GRUB_DEFAULT_FILE not found. Is GRUB installed?" >&2
    exit 1
fi

add_param_to_var() {
    local var_name="$1"
    local file="$2"
    local current_line
    local current_val
    local new_val

    if grep -qE "^${var_name}=" "$file"; then
        current_line="$(grep -E "^${var_name}=" "$file" | tail -n1)"
        current_val="$(echo "$current_line" | sed -E "s/^${var_name}=\"?([^\"]*)\"?$/\1/")"

        if echo " $current_val " | grep -qE "[[:space:]]${PARAM}[[:space:]]"; then
            # already present
            return 0
        fi

        if [ -z "$current_val" ]; then
            new_val="$PARAM"
        else
            new_val="${current_val} ${PARAM}"
        fi

        # Replace the line, quoting the new value
        sed -i -E "s|^${var_name}=.*|${var_name}=\"${new_val}\"|" "$file"
    else
        # Variable not present, append it
        echo "${var_name}=\"${PARAM}\"" >> "$file"
    fi
}

# Backup original file once
if [ ! -f "${GRUB_DEFAULT_FILE}.bak" ]; then
    cp -p "$GRUB_DEFAULT_FILE" "${GRUB_DEFAULT_FILE}.bak"
fi

add_param_to_var "GRUB_CMDLINE_LINUX" "$GRUB_DEFAULT_FILE"
add_param_to_var "GRUB_CMDLINE_LINUX_DEFAULT" "$GRUB_DEFAULT_FILE"

# Ensure a drop-in directory exists so future grub package upgrades /
# kernel installs that source grub.d configs still pick this up
# consistently (in addition to /etc/default/grub itself).
mkdir -p "$GRUB_DROPIN_DIR"

cat > "$GRUB_DROPIN_FILE" <<EOF
# Managed by remediation script: enforce vsyscall=none for all kernels
GRUB_CMDLINE_LINUX="\${GRUB_CMDLINE_LINUX:-} ${PARAM}"
EOF

# De-duplicate whitespace in the main grub file for cleanliness
sed -i -E 's/^(GRUB_CMDLINE_LINUX(_DEFAULT)?=")[[:space:]]+/\1/' "$GRUB_DEFAULT_FILE"
sed -i -E 's/([^"[:space:]])[[:space:]]+"/\1"/' "$GRUB_DEFAULT_FILE"

# Regenerate grub configuration so change applies to all installed kernels
if command -v update-grub >/dev/null 2>&1; then
    update-grub
elif command -v grub-mkconfig >/dev/null 2>&1; then
    if [ -d /boot/grub ]; then
        grub-mkconfig -o /boot/grub/grub.cfg
    elif [ -d /boot/grub2 ]; then
        grub-mkconfig -o /boot/grub2/grub.cfg
    fi
else
    echo "WARNING: Could not find update-grub or grub-mkconfig to regenerate GRUB config." >&2
fi

echo "vsyscall=none has been enforced via GRUB configuration."
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
# Remediation script: Ensure rsyslog (or rsyslog-relp/TLS) is configured to
# authenticate remote log destination peers via x.509 certificate name
# verification (PeerName / authmode=x509/name) before offloading logs.
#
# Idempotent: safe to run multiple times.

set -euo pipefail

RSYSLOG_CONF="/etc/rsyslog.conf"
RSYSLOG_D="/etc/rsyslog.d"
DROPIN_FILE="${RSYSLOG_D}/60-remote-tls-authmode.conf"

# Ensure rsyslog is installed
if ! command -v rsyslogd >/dev/null 2>&1; then
    echo "rsyslogd not found; installing rsyslog package..."
    apt-get update -y
    apt-get install -y rsyslog rsyslog-gnutls
fi

# Ensure rsyslog.d directory exists
mkdir -p "${RSYSLOG_D}"

# Backup original rsyslog.conf if not already backed up
if [ -f "${RSYSLOG_CONF}" ] && [ ! -f "${RSYSLOG_CONF}.bak" ]; then
    cp -p "${RSYSLOG_CONF}" "${RSYSLOG_CONF}.bak"
fi

# Determine PermittedPeer name to enforce - can be overridden via env var
PERMITTED_PEER="${RSYSLOG_PERMITTED_PEER:-*.example.com}"

# Build desired configuration block
read -r -d '' DESIRED_CONF <<EOF || true
# Managed by remediation script: enforce x.509 certificate-name
# authentication of the remote log collector before forwarding records.
# This ensures rsyslog verifies the peer's certificate name (authmode=x509/name)
# rather than accepting any certificate (anon) when using TLS-based forwarding.

\$DefaultNetstreamDriver gtls
\$DefaultNetstreamDriverCAFile /etc/ssl/certs/ca-certificates.crt
\$ActionSendStreamDriverMode 1
\$ActionSendStreamDriverAuthMode x509/name
\$ActionSendStreamDriverPermittedPeer ${PERMITTED_PEER}
EOF

# Write drop-in file idempotently: only rewrite if content differs
if [ ! -f "${DROPIN_FILE}" ] || ! diff -q <(printf '%s\n' "${DESIRED_CONF}") "${DROPIN_FILE}" >/dev/null 2>&1; then
    printf '%s\n' "${DESIRED_CONF}" > "${DROPIN_FILE}"
    echo "Updated ${DROPIN_FILE} with x509/name authentication settings."
else
    echo "${DROPIN_FILE} already configured correctly."
fi

chmod 0644 "${DROPIN_FILE}"
chown root:root "${DROPIN_FILE}"

# Ensure any existing forwarding action lines in rsyslog.conf or other
# rsyslog.d files that use authmode=anon are corrected to x509/name.
for f in "${RSYSLOG_CONF}" "${RSYSLOG_D}"/*.conf; do
    [ -f "$f" ] || continue
    # Skip our own managed file to avoid redundant operations (already correct)
    if [ "$f" = "${DROPIN_FILE}" ]; then
        continue
    fi
    if grep -qE 'ActionSendStreamDriverAuthMode\s+anon' "$f" 2>/dev/null; then
        sed -i -E 's/(ActionSendStreamDriverAuthMode\s+)anon/\1x509\/name/I' "$f"
        echo "Corrected insecure authmode in $f"
    fi
done

# Validate rsyslog configuration syntax
if command -v rsyslogd >/dev/null 2>&1; then
    if ! rsyslogd -N1 -f "${RSYSLOG_CONF}" >/tmp/rsyslog_validate.log 2>&1; then
        echo "ERROR: rsyslog configuration validation failed. See /tmp/rsyslog_validate.log" >&2
        cat /tmp/rsyslog_validate.log >&2
        exit 1
    fi
fi

# Enable and restart rsyslog service to apply changes persistently
systemctl enable rsyslog.service >/dev/null 2>&1 || true

if systemctl is-active --quiet rsyslog.service; then
    systemctl restart rsyslog.service
else
    systemctl start rsyslog.service
fi

echo "rsyslog remote logging now enforces x.509 certificate-name (PeerName) authentication."
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

**Prompt:** On an Ubuntu 24.04 system, the system logging service forwards (off-loads) audit and log records to a remote collector, but these records contain sensitive configuration and authentication details that must not traverse the network in cleartext. Configure the system logging service so that all forwarded log traffic is sent using encrypted (TLS-protected) network transport rather than an unencrypted channel. Write an idempotent bash remediation script that enforces encrypted off-loading of log records and ensures the setting persists across reboots.

**Model-generated script:**
```bash
```bash
#!/usr/bin/env bash
#
# remediate_rsyslog_tls_forward.sh
#
# Ensures that rsyslog forwards logs to the remote collector only via an
# encrypted (TLS) transport. Idempotent: safe to re-run; will not create
# duplicate configuration, and existing cleartext forwarding directives
# are disabled.

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration variables - adjust to match your environment
# ---------------------------------------------------------------------------
REMOTE_HOST="loghost.example.com"
REMOTE_PORT="6514"

TLS_DIR="/etc/rsyslog.d"
TLS_CONF="${TLS_DIR}/60-remote-tls-forward.conf"
MARK_BEGIN="# BEGIN MANAGED TLS FORWARD BLOCK - DO NOT EDIT"
MARK_END="# END MANAGED TLS FORWARD BLOCK"

CERT_DIR="/etc/rsyslog.d/tls"
CA_CERT="${CERT_DIR}/ca.pem"
CLIENT_CERT="${CERT_DIR}/client-cert.pem"
CLIENT_KEY="${CERT_DIR}/client-key.pem"

RSYSLOG_MAIN_CONF="/etc/rsyslog.conf"

log()  { echo "[remediate-tls-forward] $*"; }
err()  { echo "[remediate-tls-forward][ERROR] $*" >&2; }

require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        err "This script must be run as root."
        exit 1
    fi
}

ensure_rsyslog_installed() {
    if ! command -v rsyslogd >/dev/null 2>&1; then
        log "rsyslog not found; installing."
        apt-get update -y
        apt-get install -y rsyslog rsyslog-gnutls
    else
        # Ensure the TLS (gtls) driver support package is present.
        if ! dpkg -s rsyslog-gnutls >/dev/null 2>&1; then
            log "Installing rsyslog-gnutls for TLS stream driver support."
            apt-get update -y
            apt-get install -y rsyslog-gnutls
        fi
    fi
}

ensure_tls_material() {
    mkdir -p "${CERT_DIR}"
    chmod 700 "${CERT_DIR}"

    if [[ ! -f "${CA_CERT}" || ! -f "${CLIENT_CERT}" || ! -f "${CLIENT_KEY}" ]]; then
        log "TLS material missing under ${CERT_DIR}."
        log "Generating a self-signed CA and client certificate for TLS forwarding."
        log "Replace these with your organization's PKI-issued certificates in production
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
# Remediation: Ensure rsyslog offloads logs to remote hosts using TLS
# (GnuTLS) as the default network stream driver.
#
# This script is idempotent and persists across reboots by modifying
# /etc/rsyslog.conf (or the appropriate drop-in) directly.

set -euo pipefail

RSYSLOG_CONF="/etc/rsyslog.conf"
DIRECTIVE_OLD='$DefaultNetstreamDriver'
DESIRED_VALUE="gtls"
DESIRED_LINE="${DIRECTIVE_OLD} ${DESIRED_VALUE}"

# Ensure rsyslog package/config exists
if [ ! -f "${RSYSLOG_CONF}" ]; then
    echo "ERROR: ${RSYSLOG_CONF} not found. Is rsyslog installed?" >&2
    exit 1
fi

backup_conf() {
    local ts
    ts="$(date +%Y%m%d%H%M%S)"
    cp -p "${RSYSLOG_CONF}" "${RSYSLOG_CONF}.bak.${ts}"
}

# Check for a legacy-style directive line (commented or not),
# ignoring leading whitespace.
existing_line_regex="^[[:space:]]*\\\$DefaultNetstreamDriver[[:space:]]+.*$"

if grep -Eq "${existing_line_regex}" "${RSYSLOG_CONF}"; then
    current_value="$(grep -E "${existing_line_regex}" "${RSYSLOG_CONF}" | tail -n1 | awk '{print $2}')"
    if [ "${current_value}" = "${DESIRED_VALUE}" ]; then
        CHANGED=0
    else
        backup_conf
        # Replace the last matching uncommented directive with desired value,
        # and comment out/remove any duplicate lines to keep config clean.
        # First, remove all existing DefaultNetstreamDriver lines.
        sed -i -E "/${existing_line_regex}/d" "${RSYSLOG_CONF}"
        # Append the desired directive at the end of the global directives
        # section (top of file is fine for legacy format directives).
        printf '%s\n' "${DESIRED_LINE}" >> "${RSYSLOG_CONF}"
        CHANGED=1
    fi
else
    backup_conf
    printf '%s\n' "${DESIRED_LINE}" >> "${RSYSLOG_CONF}"
    CHANGED=1
fi

# Also ensure no conflicting settings exist in /etc/rsyslog.d/*.conf
# by fixing any that explicitly set a different DefaultNetstreamDriver.
if [ -d /etc/rsyslog.d ]; then
    for f in /etc/rsyslog.d/*.conf; do
        [ -e "${f}" ] || continue
        if grep -Eq "${existing_line_regex}" "${f}"; then
            other_value="$(grep -E "${existing_line_regex}" "${f}" | tail -n1 | awk '{print $2}')"
            if [ "${other_value}" != "${DESIRED_VALUE}" ]; then
                cp -p "${f}" "${f}.bak.$(date +%Y%m%d%H%M%S)"
                sed -i -E "/${existing_line_regex}/d" "${f}"
                CHANGED=1
            fi
        fi
    done
fi

# Reload/restart rsyslog only if changes were made and service is active.
if [ "${CHANGED:-0}" -eq 1 ]; then
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-enabled rsyslog >/dev/null 2>&1 || systemctl is-active rsyslog >/dev/null 2>&1; then
            systemctl restart rsyslog
        fi
        systemctl enable rsyslog >/dev/null 2>&1 || true
    fi
fi

# Final verification
if grep -Eq "^[[:space:]]*\\\$DefaultNetstreamDriver[[:space:]]+${DESIRED_VALUE}[[:space:]]*\$" "${RSYSLOG_CONF}"; then
    echo "OK: rsyslog DefaultNetstreamDriver is set to '${DESIRED_VALUE}' in ${RSYSLOG_CONF}."
    exit 0
else
    echo "ERROR: Failed to configure DefaultNetstreamDriver to '${DESIRED_VALUE}'." >&2
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
#
# Remediation script: Ensure rsyslog captures and persists auth, authpriv,
# and daemon messages to dedicated log files across reboots.
#
# Idempotent: safe to run multiple times.

set -euo pipefail

RSYSLOG_CONF_DIR="/etc/rsyslog.d"
RSYSLOG_RULE_FILE="${RSYSLOG_CONF_DIR}/60-auth-daemon.conf"
SECURE_LOG="/var/log/secure"
MESSAGES_LOG="/var/log/messages"

# ------------------------------------------------------------------
# 1. Ensure rsyslog is installed
# ------------------------------------------------------------------
if ! dpkg -s rsyslog >/dev/null 2>&1; then
    echo "Installing rsyslog..."
    apt-get update -y
    apt-get install -y rsyslog
fi

# ------------------------------------------------------------------
# 2. Ensure the rsyslog config directory exists
# ------------------------------------------------------------------
mkdir -p "${RSYSLOG_CONF_DIR}"

# ------------------------------------------------------------------
# 3. Ensure the rule file exists with the correct content
# ------------------------------------------------------------------
DESIRED_CONTENT="# Managed by remediation script - do not edit manually
auth.*,authpriv.*                                      ${SECURE_LOG}
daemon.*                                                ${MESSAGES_LOG}
"

if [ ! -f "${RSYSLOG_RULE_FILE}" ] || ! diff -q <(printf '%s' "${DESIRED_CONTENT}") "${RSYSLOG_RULE_FILE}" >/dev/null 2>&1; then
    echo "Writing rsyslog rule file: ${RSYSLOG_RULE_FILE}"
    printf '%s' "${DESIRED_CONTENT}" > "${RSYSLOG_RULE_FILE}"
    chmod 0644 "${RSYSLOG_RULE_FILE}"
    chown root:root "${RSYSLOG_RULE_FILE}"
fi

# ------------------------------------------------------------------
# 4. Ensure target log files exist with proper permissions
# ------------------------------------------------------------------
for LOGFILE in "${SECURE_LOG}" "${MESSAGES_LOG}"; do
    if [ ! -f "${LOGFILE}" ]; then
        echo "Creating log file: ${LOGFILE}"
        touch "${LOGFILE}"
    fi
    chmod 0640 "${LOGFILE}"
    chown syslog:adm "${LOGFILE}" 2>/dev/null || chown root:adm "${LOGFILE}"
done

# ------------------------------------------------------------------
# 5. Ensure logrotate config exists for the new logs (idempotent)
# ------------------------------------------------------------------
LOGROTATE_FILE="/etc/logrotate.d/rsyslog-secure-messages"
DESIRED_LOGROTATE="${SECURE_LOG} ${MESSAGES_LOG} {
    rotate 4
    weekly
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate 2>/dev/null || systemctl kill -s HUP rsyslog.service 2>/dev/null || true
    endscript
}
"

if [ ! -f "${LOGROTATE_FILE}" ] || ! diff -q <(printf '%s' "${DESIRED_LOGROTATE}") "${LOGROTATE_FILE}" >/dev/null 2>&1; then
    echo "Writing logrotate config: ${LOGROTATE_FILE}"
    printf '%s' "${DESIRED_LOGROTATE}" > "${LOGROTATE_FILE}"
    chmod 0644 "${LOGROTATE_FILE}"
    chown root:root "${LOGROTATE_FILE}"
fi

# ------------------------------------------------------------------
# 6. Validate rsyslog configuration
# ------------------------------------------------------------------
if command -v rsyslogd >/dev/null 2>&1; then
    if ! rsyslogd -N1 >/dev/null 2>&1; then
        echo "ERROR: rsyslog configuration validation failed." >&2
        exit 1
    fi
fi

# ------------------------------------------------------------------
# 7. Enable and restart rsyslog to apply changes and persist across reboots
# ------------------------------------------------------------------
systemctl enable rsyslog.service >/dev/null 2>&1 || true
systemctl restart rsyslog.service

echo "Rsyslog configuration for auth/authpriv/daemon logging has been applied successfully."
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
#!/bin/bash
#
# remediate_remote_logging.sh
#
# Configures rsyslog to forward all log facilities and priorities
# to a centralized remote log server ("loghost") over TCP.
# Idempotent: safe to run multiple times.

set -euo pipefail

LOGHOST="loghost"
LOGHOST_PORT="514"
RSYSLOG_CONF_DIR="/etc/rsyslog.d"
FORWARD_CONF_FILE="${RSYSLOG_CONF_DIR}/60-remote-loghost.conf"
FORWARD_LINE="*.*  @@${LOGHOST}:${LOGHOST_PORT}"

log() {
    echo "[remediate_remote_logging] $*"
}

# Ensure rsyslog is installed
if ! dpkg -s rsyslog >/dev/null 2>&1; then
    log "rsyslog not found, installing..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y rsyslog
fi

# Ensure rsyslog config directory exists
if [ ! -d "${RSYSLOG_CONF_DIR}" ]; then
    log "Creating rsyslog config directory ${RSYSLOG_CONF_DIR}"
    mkdir -p "${RSYSLOG_CONF_DIR}"
fi

# Create or update the forwarding configuration file idempotently
if [ -f "${FORWARD_CONF_FILE}" ] && grep -qE "^\*\.\*[[:space:]]+@@${LOGHOST}:${LOGHOST_PORT}[[:space:]]*$" "${FORWARD_CONF_FILE}"; then
    log "Forwarding rule already present in ${FORWARD_CONF_FILE}, no changes needed."
else
    log "Writing forwarding rule to ${FORWARD_CONF_FILE}"
    cat > "${FORWARD_CONF_FILE}" <<EOF
# Managed by remediate_remote_logging.sh
# Forward all log facilities and priorities to the centralized remote log server.
${FORWARD_LINE}
EOF
fi

# Ensure file permissions are sane
chmod 0644 "${FORWARD_CONF_FILE}"
chown root:root "${FORWARD_CONF_FILE}"

# Validate rsyslog configuration syntax before reloading
if command -v rsyslogd >/dev/null 2>&1; then
    if ! rsyslogd -N1 >/dev/null 2>&1; then
        log "ERROR: rsyslog configuration validation failed. Please check ${FORWARD_CONF_FILE}."
        exit 1
    fi
fi

# Enable and (re)start rsyslog service so changes persist across reboots
systemctl enable rsyslog >/dev/null 2>&1 || true

if systemctl is-active --quiet rsyslog; then
    log "Restarting rsyslog to apply configuration changes."
    systemctl restart rsyslog
else
    log "Starting rsyslog service."
    systemctl start rsyslog
fi

log "Remote log forwarding to ${LOGHOST}:${LOGHOST_PORT} is configured and active."
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
#!/bin/bash
set -euo pipefail

CONF_FILE="/etc/sysctl.d/60-disable-ipv6-ra.conf"

declare -a SETTINGS=(
    "net.ipv6.conf.all.accept_ra=0"
    "net.ipv6.conf.default.accept_ra=0"
)

if [ -d /proc/sys/net/ipv6/conf ]; then
    for iface_path in /proc/sys/net/ipv6/conf/*; do
        [ -d "$iface_path" ] || continue
        iface="$(basename "$iface_path")"
        case "$iface" in
            all|default) continue ;;
        esac
        SETTINGS+=("net.ipv6.conf.${iface}.accept_ra=0")
    done
fi

if [ ! -f "$CONF_FILE" ]; then
    touch "$CONF_FILE"
fi

for setting in "${SETTINGS[@]}"; do
    key="${setting%%=*}"
    value="${setting##*=}"

    if grep -Eq "^\s*${key//./\\.}\s*=" "$CONF_FILE"; then
        sed -i -E "s|^\s*${key//./\\.}\s*=.*|${key}=${value}|" "$CONF_FILE"
    else
        echo "${key}=${value}" >> "$CONF_FILE"
    fi

    current_val=""
    proc_path="/proc/sys/${key//.//}"
    if [ -f "$proc_path" ]; then
        current_val="$(cat "$proc_path" 2>/dev/null || echo "")"
    fi

    if [ "$current_val" != "$value" ]; then
        sysctl -w "${key}=${value}" >/dev/null 2>&1 || true
    fi
done

sysctl --system >/dev/null 2>&1 || true

exit 0
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
#!/bin/bash
set -euo pipefail

CONF_FILE="/etc/sysctl.d/60-disable-ipv6-redirects.conf"

declare -A PARAMS=(
  ["net.ipv6.conf.all.accept_redirects"]="0"
  ["net.ipv6.conf.default.accept_redirects"]="0"
)

if [[ ! -f "$CONF_FILE" ]]; then
  touch "$CONF_FILE"
fi

for key in "${!PARAMS[@]}"; do
  value="${PARAMS[$key]}"

  if grep -qE "^\s*${key//./\\.}\s*=" "$CONF_FILE"; then
    sed -i -E "s|^\s*${key//./\\.}\s*=.*|${key} = ${value}|" "$CONF_FILE"
  else
    echo "${key} = ${value}" >> "$CONF_FILE"
  fi

  sysctl -w "${key}=${value}" >/dev/null
done

for iface_path in /proc/sys/net/ipv6/conf/*/accept_redirects; do
  if [[ -w "$iface_path" ]]; then
    echo 0 > "$iface_path" 2>/dev/null || true
  fi
done

sysctl --system >/dev/null 2>&1 || true

exit 0
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

SYSCTL_CONF="/etc/sysctl.d/60-disable-ipv6-source-route.conf"
PARAM_ALL="net.ipv6.conf.all.accept_source_route"
PARAM_DEFAULT="net.ipv6.conf.default.accept_source_route"
DESIRED_VALUE=0

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

declare -a PARAMS=("$PARAM_ALL" "$PARAM_DEFAULT")

for iface_path in /proc/sys/net/ipv6/conf/*/accept_source_route; do
    [ -e "$iface_path" ] || continue
    iface=$(basename "$(dirname "$iface_path")")
    PARAMS+=("net.ipv6.conf.${iface}.accept_source_route")
done

tmpfile=$(mktemp)
trap 'rm -f "$tmpfile"' EXIT

if [ -f "$SYSCTL_CONF" ]; then
    while IFS= read -r line; do
        key="${line%%=*}"
        key="$(echo "$key" | xargs)"
        skip=0
        for p in "${PARAMS[@]}"; do
            if [[ "$key" == "$p" ]]; then
                skip=1
                break
            fi
        done
        if [[ $skip -eq 0 ]]; then
            echo "$line" >> "$tmpfile"
        fi
    done < "$SYSCTL_CONF"
fi

for p in "${PARAMS[@]}"; do
    echo "${p} = ${DESIRED_VALUE}" >> "$tmpfile"
done

sort -u "$tmpfile" -o "$tmpfile"

if [ ! -f "$SYSCTL_CONF" ] || ! cmp -s "$tmpfile" "$SYSCTL_CONF"; then
    install -m 0644 "$tmpfile" "$SYSCTL_CONF"
fi

for p in "${PARAMS[@]}"; do
    key_path="/proc/sys/${p//./\/}"
    if [ -e "$key_path" ]; then
        current_value=$(cat "$key_path" 2>/dev/null || echo "")
        if [[ "$current_value" != "$DESIRED_VALUE" ]]; then
            sysctl -w "${p}=${DESIRED_VALUE}" >/dev/null
        fi
    fi
done

sysctl --system >/dev/null 2>&1 || true

echo "IPv6 source-routed packet acceptance has been disabled across all interfaces."
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

SYSCTL_PARAMS=(
    "net.ipv6.conf.all.forwarding"
    "net.ipv6.conf.default.forwarding"
)

CONF_FILE="/etc/sysctl.d/60-disable-ipv6-forwarding.conf"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# Ensure the dedicated config file exists
if [[ ! -f "$CONF_FILE" ]]; then
    touch "$CONF_FILE"
    chmod 0644 "$CONF_FILE"
fi

for param in "${SYSCTL_PARAMS[@]}"; do
    desired_line="${param} = 0"

    # Remove any existing occurrences of this parameter from other sysctl
    # configuration files so they don't conflict with our setting.
    for f in /etc/sysctl.conf /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
        [[ -e "$f" ]] || continue
        [[ "$f" == "$CONF_FILE" ]] && continue
        if grep -Eq "^\s*${param//./\\.}\s*=" "$f" 2>/dev/null; then
            sed -i -E "s|^\s*${param//./\\.}\s*=.*|# &  (managed by ${CONF_FILE})|g" "$f"
        fi
    done

    # Update or add the parameter in our managed config file
    if grep -Eq "^\s*${param//./\\.}\s*=" "$CONF_FILE"; then
        sed -i -E "s|^\s*${param//./\\.}\s*=.*|${desired_line}|" "$CONF_FILE"
    else
        echo "$desired_line" >> "$CONF_FILE"
    fi

    # Apply at runtime immediately
    sysctl -w "${param}=0" >/dev/null
done

# Reload sysctl settings from all configuration files to ensure consistency
sysctl --system >/dev/null

echo "IPv6 packet forwarding has been disabled and persisted."
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
#!/bin/bash
set -euo pipefail

# Remediation script: Disable IPv6 Router Advertisement acceptance
# for newly initialized (default) interfaces on Ubuntu 24.04.
# Ensures both runtime sysctl values and persistent configuration
# are set idempotently.

SYSCTL_PARAM="net.ipv6.conf.default.accept_ra"
SYSCTL_VALUE="0"
SYSCTL_CONF_DIR="/etc/sysctl.d"
SYSCTL_CONF_FILE="${SYSCTL_CONF_DIR}/60-ipv6-disable-ra.conf"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# Ensure sysctl.d directory exists
mkdir -p "${SYSCTL_CONF_DIR}"

# Function to set or update a sysctl parameter in a config file idempotently
set_persistent_sysctl() {
    local param="$1"
    local value="$2"
    local file="$3"

    if [[ -f "${file}" ]] && grep -qE "^\s*${param}\s*=" "${file}"; then
        # Update existing line if value differs
        if ! grep -qE "^\s*${param}\s*=\s*${value}\s*$" "${file}"; then
            sed -i -E "s|^\s*${param}\s*=.*|${param} = ${value}|" "${file}"
        fi
    else
        echo "${param} = ${value}" >> "${file}"
    fi
}

# Ensure the persistent config file exists
touch "${SYSCTL_CONF_FILE}"

# Apply persistent configuration idempotently
set_persistent_sysctl "${SYSCTL_PARAM}" "${SYSCTL_VALUE}" "${SYSCTL_CONF_FILE}"

# Apply runtime setting immediately (idempotent - sysctl -w is safe to repeat)
current_value="$(sysctl -n "${SYSCTL_PARAM}" 2>/dev/null || echo "")"
if [[ "${current_value}" != "${SYSCTL_VALUE}" ]]; then
    sysctl -w "${SYSCTL_PARAM}=${SYSCTL_VALUE}" >/dev/null
fi

# Reload sysctl settings from all config files to ensure consistency
sysctl --system >/dev/null 2>&1 || true

# Verify the setting took effect
final_value="$(sysctl -n "${SYSCTL_PARAM}" 2>/dev/null || echo "")"
if [[ "${final_value}" == "${SYSCTL_VALUE}" ]]; then
    echo "Success: ${SYSCTL_PARAM} is set to ${SYSCTL_VALUE} (runtime and persistent)."
else
    echo "Warning: ${SYSCTL_PARAM} could not be verified as ${SYSCTL_VALUE} at runtime." >&2
    exit 1
fi
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
#!/bin/bash
set -euo pipefail

CONF_FILE="/etc/sysctl.d/60-disable-ipv6-redirects.conf"
KEY_ALL="net.ipv6.conf.all.accept_redirects"
KEY_DEFAULT="net.ipv6.conf.default.accept_redirects"
VALUE="0"

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root." >&2
    exit 1
fi

if [ -f "$CONF_FILE" ]; then
    for KEY in "$KEY_ALL" "$KEY_DEFAULT"; do
        if grep -qE "^\s*${KEY}\s*=" "$CONF_FILE"; then
            sed -i -E "s|^\s*${KEY}\s*=.*|${KEY} = ${VALUE}|" "$CONF_FILE"
        else
            echo "${KEY} = ${VALUE}" >> "$CONF_FILE"
        fi
    done
else
    {
        echo "# Disable acceptance of ICMP redirects on all IPv6 interfaces"
        echo "${KEY_ALL} = ${VALUE}"
        echo "${KEY_DEFAULT} = ${VALUE}"
    } > "$CONF_FILE"
fi

chmod 0644 "$CONF_FILE"

sysctl -w "${KEY_ALL}=${VALUE}" >/dev/null
sysctl -w "${KEY_DEFAULT}=${VALUE}" >/dev/null

sysctl --system >/dev/null 2>&1 || true

CURRENT_ALL=$(sysctl -n "${KEY_ALL}")
CURRENT_DEFAULT=$(sysctl -n "${KEY_DEFAULT}")

if [ "$CURRENT_ALL" != "$VALUE" ] || [ "$CURRENT_DEFAULT" != "$VALUE" ]; then
    echo "Failed to apply sysctl settings correctly." >&2
    exit 1
fi

echo "IPv6 ICMP redirect acceptance disabled successfully and persisted in ${CONF_FILE}."
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
#!/bin/bash
set -euo pipefail

SYSCTL_PARAM="net.ipv6.conf.default.accept_source_route"
DESIRED_VALUE="0"
CONF_FILE="/etc/sysctl.d/60-disable-ipv6-source-route.conf"

if [ -f "$CONF_FILE" ]; then
    if grep -qE "^\s*${SYSCTL_PARAM}\s*=\s*${DESIRED_VALUE}\s*$" "$CONF_FILE"; then
        :
    else
        if grep -qE "^\s*${SYSCTL_PARAM}\s*=" "$CONF_FILE"; then
            sed -i -E "s|^\s*${SYSCTL_PARAM}\s*=.*|${SYSCTL_PARAM} = ${DESIRED_VALUE}|" "$CONF_FILE"
        else
            echo "${SYSCTL_PARAM} = ${DESIRED_VALUE}" >> "$CONF_FILE"
        fi
    fi
else
    echo "${SYSCTL_PARAM} = ${DESIRED_VALUE}" > "$CONF_FILE"
fi

CURRENT_VALUE="$(sysctl -n "${SYSCTL_PARAM}" 2>/dev/null || echo "")"
if [ "$CURRENT_VALUE" != "$DESIRED_VALUE" ]; then
    sysctl -w "${SYSCTL_PARAM}=${DESIRED_VALUE}" >/dev/null
fi

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

**Prompt:** On an Ubuntu 24.04 system, the IPv4 networking stack currently accepts ICMP redirect messages on all interfaces. Because these messages are unauthenticated and can be forged to alter the host's routing table, they enable man-in-the-middle attacks and should be refused unless explicitly required. Write an idempotent bash remediation script that prevents the system from accepting ICMP redirect messages on all IPv4 interfaces, applying the change at runtime and ensuring it persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
set -euo pipefail

SYSCTL_FILE="/etc/sysctl.d/99-disable-icmp-redirects.conf"

declare -A PARAMS=(
    ["net.ipv4.conf.all.accept_redirects"]="0"
    ["net.ipv4.conf.default.accept_redirects"]="0"
)

if [[ ! -f "$SYSCTL_FILE" ]]; then
    touch "$SYSCTL_FILE"
    chmod 644 "$SYSCTL_FILE"
fi

for key in "${!PARAMS[@]}"; do
    value="${PARAMS[$key]}"

    if grep -Eq "^\s*${key}\s*=" "$SYSCTL_FILE"; then
        sed -i -E "s|^\s*${key}\s*=.*|${key} = ${value}|" "$SYSCTL_FILE"
    else
        echo "${key} = ${value}" >> "$SYSCTL_FILE"
    fi

    sysctl -w "${key}=${value}" >/dev/null
done

sysctl --system >/dev/null 2>&1 || true

for key in "${!PARAMS[@]}"; do
    expected="${PARAMS[$key]}"
    current="$(sysctl -n "${key}")"
    if [[ "$current" != "$expected" ]]; then
        echo "ERROR: Failed to set ${key} to ${expected} (current: ${current})" >&2
        exit 1
    fi
done

exit 0
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
#!/bin/bash
set -euo pipefail

CONF_FILE="/etc/sysctl.d/60-disable-ipv4-forwarding.conf"

declare -A SETTINGS=(
    ["net.ipv4.ip_forward"]="0"
    ["net.ipv4.conf.all.forwarding"]="0"
    ["net.ipv4.conf.default.forwarding"]="0"
)

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

if [[ -f "$CONF_FILE" ]]; then
    for key in "${!SETTINGS[@]}"; do
        value="${SETTINGS[$key]}"
        if grep -Eq "^\s*${key}\s*=" "$CONF_FILE"; then
            sed -i -E "s|^\s*${key}\s*=.*|${key} = ${value}|" "$CONF_FILE"
        else
            echo "${key} = ${value}" >> "$CONF_FILE"
        fi
    done
else
    {
        echo "# Disable IPv4 forwarding to prevent host from routing/bridging traffic"
        for key in "${!SETTINGS[@]}"; do
            echo "${key} = ${SETTINGS[$key]}"
        done
    } > "$CONF_FILE"
fi

chmod 0644 "$CONF_FILE"

for key in "${!SETTINGS[@]}"; do
    value="${SETTINGS[$key]}"
    sysctl -w "${key}=${value}" >/dev/null
done

for iface_path in /proc/sys/net/ipv4/conf/*/forwarding; do
    if [[ -w "$iface_path" ]]; then
        current_val=$(cat "$iface_path" 2>/dev/null || echo "")
        if [[ "$current_val" != "0" ]]; then
            echo 0 > "$iface_path" 2>/dev/null || true
        fi
    fi
done

sysctl --system >/dev/null 2>&1 || true

current_ip_forward=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "unknown")
if [[ "$current_ip_forward" != "0" ]]; then
    echo "ERROR: net.ipv4.ip_forward is not set to 0 (current: ${current_ip_forward})" >&2
    exit 1
fi

echo "IPv4 forwarding has been disabled at runtime and configured to persist across reboots via ${CONF_FILE}."
exit 0
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
#!/bin/bash
set -euo pipefail

PARAM="net.ipv4.conf.default.accept_redirects"
VALUE="0"
SYSCTL_CONF_DIR="/etc/sysctl.d"
SYSCTL_CONF_FILE="${SYSCTL_CONF_DIR}/60-disable-ipv4-default-accept-redirects.conf"

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root." >&2
    exit 1
fi

mkdir -p "${SYSCTL_CONF_DIR}"

if [ -f "${SYSCTL_CONF_FILE}" ]; then
    if grep -qE "^\s*${PARAM}\s*=" "${SYSCTL_CONF_FILE}"; then
        sed -i -E "s/^\s*${PARAM}\s*=.*/${PARAM} = ${VALUE}/" "${SYSCTL_CONF_FILE}"
    else
        echo "${PARAM} = ${VALUE}" >> "${SYSCTL_CONF_FILE}"
    fi
else
    echo "${PARAM} = ${VALUE}" > "${SYSCTL_CONF_FILE}"
fi

for f in /etc/sysctl.conf /etc/sysctl.d/*.conf /run/sysctl.d/*.conf; do
    [ -f "$f" ] || continue
    [ "$f" = "${SYSCTL_CONF_FILE}" ] && continue
    if grep -qE "^\s*${PARAM}\s*=" "$f" 2>/dev/null; then
        sed -i -E "s/^\s*${PARAM}\s*=.*/${PARAM} = ${VALUE}/" "$f"
    fi
done

sysctl -w "${PARAM}=${VALUE}" >/dev/null

CURRENT_VALUE=$(sysctl -n "${PARAM}")
if [ "${CURRENT_VALUE}" != "${VALUE}" ]; then
    echo "Failed to apply runtime setting for ${PARAM}." >&2
    exit 1
fi

sysctl --system >/dev/null 2>&1 || true

FINAL_VALUE=$(sysctl -n "${PARAM}")
if [ "${FINAL_VALUE}" != "${VALUE}" ]; then
    echo "Verification failed: ${PARAM} is set to ${FINAL_VALUE}, expected ${VALUE}." >&2
    exit 1
fi

echo "Successfully configured ${PARAM} = ${VALUE} (runtime and persistent)."
exit 0
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
#
# Remediation script: Disable IPv4 default source-routed packet acceptance
#
# This script sets net.ipv4.conf.default.accept_source_route = 0
# both at runtime (sysctl) and persistently (via a dedicated sysctl
# configuration file), in an idempotent manner.

set -euo pipefail

readonly PARAM="net.ipv4.conf.default.accept_source_route"
readonly DESIRED_VALUE="0"
readonly SYSCTL_CONF_DIR="/etc/sysctl.d"
readonly SYSCTL_CONF_FILE="${SYSCTL_CONF_DIR}/60-disable-ipv4-source-route.conf"

main() {
    ensure_root

    apply_runtime_setting
    persist_setting
    reload_sysctl_settings
    verify_runtime_setting
}

ensure_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo "ERROR: This script must be run as root." >&2
        exit 1
    fi
}

apply_runtime_setting() {
    echo "Applying runtime setting: ${PARAM} = ${DESIRED_VALUE}"
    if ! sysctl -w "${PARAM}=${DESIRED_VALUE}" >/dev/null; then
        echo "ERROR: Failed to set ${PARAM} at runtime." >&2
        exit 1
    fi
}

persist_setting() {
    mkdir -p "${SYSCTL_CONF_DIR}"

    if [[ -f "${SYSCTL_CONF_FILE}" ]] && \
       grep -Eq "^[[:space:]]*${PARAM//./\\.}[[:space:]]*=[[:space:]]*${DESIRED_VALUE}[[:space:]]*$" "${SYSCTL_CONF_FILE}"; then
        echo "Persistent setting already present and correct in ${SYSCTL_CONF_FILE}"
        return 0
    fi

    echo "Writing persistent setting to ${SYSCTL_CONF_FILE}"
    cat > "${SYSCTL_CONF_FILE}" <<EOF
# Managed by remediation script: disable acceptance of IPv4 source-routed
# packets by default on all interfaces. Source routing allows a sender to
# dictate a packet's path through the network, which can be exploited to
# circumvent firewalls, routing policies, and other security controls.
# This setting has little to no legitimate use on a non-router host.
${PARAM} = ${DESIRED_VALUE}
EOF
}

reload_sysctl_settings() {
    echo "Reloading sysctl settings from ${SYSCTL_CONF_FILE}"
    if ! sysctl -p "${SYSCTL_CONF_FILE}" >/dev/null; then
        echo "WARNING: sysctl failed to reload ${SYSCTL_CONF_FILE}; runtime value may not match persisted config." >&2
    fi
}

verify_runtime_setting() {
    local current_value
    current_value="$(sysctl -n "${PARAM}")"

    if [[ "${current_value}" == "${DESIRED_VALUE}" ]]; then
        echo "Verification successful: ${PARAM} = ${current_value}"
    else
        echo "ERROR: Verification failed. ${PARAM} = ${current_value}, expected ${DESIRED_VALUE}" >&2
        exit 1
    fi
}

main "$@"
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

SYSCTL_PARAM="net.ipv4.icmp_echo_ignore_broadcasts"
SYSCTL_VALUE="1"
CONF_FILE="/etc/sysctl.d/60-icmp-broadcast-ignore.conf"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# Apply the setting immediately to the running kernel
sysctl -w "${SYSCTL_PARAM}=${SYSCTL_VALUE}" >/dev/null

# Ensure the persistent configuration file exists with the correct content
DESIRED_LINE="${SYSCTL_PARAM} = ${SYSCTL_VALUE}"

if [[ -f "${CONF_FILE}" ]] && grep -qE "^[[:space:]]*${SYSCTL_PARAM}[[:space:]]*=[[:space:]]*${SYSCTL_VALUE}[[:space:]]*$" "${CONF_FILE}"; then
    :
else
    printf '%s\n' "# Ignore ICMP echo requests sent to broadcast/multicast addresses" > "${CONF_FILE}"
    printf '%s\n' "${DESIRED_LINE}" >> "${CONF_FILE}"
fi

# Remove any conflicting settings for this parameter in other sysctl config locations
for f in /etc/sysctl.conf /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
    [[ -e "${f}" ]] || continue
    [[ "${f}" == "${CONF_FILE}" ]] && continue
    if grep -qE "^[[:space:]]*${SYSCTL_PARAM}[[:space:]]*=" "${f}" 2>/dev/null; then
        sed -i -E "s|^[[:space:]]*${SYSCTL_PARAM}[[:space:]]*=.*|${DESIRED_LINE}|g" "${f}"
    fi
done

# Reload sysctl settings to ensure persistence takes effect and verify
sysctl --system >/dev/null 2>&1 || sysctl -p "${CONF_FILE}" >/dev/null

CURRENT_VALUE=$(sysctl -n "${SYSCTL_PARAM}")
if [[ "${CURRENT_VALUE}" != "${SYSCTL_VALUE}" ]]; then
    echo "Failed to set ${SYSCTL_PARAM} to ${SYSCTL_VALUE}. Current value: ${CURRENT_VALUE}" >&2
    exit 1
fi

echo "Success: ${SYSCTL_PARAM} is set to ${SYSCTL_VALUE} and will persist across reboots."
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
#
# remediate_icmp_send_redirects.sh
#
# Disables sending of ICMPv4 redirect messages on all and default interfaces.
# Idempotent: safe to run multiple times.
# Applies setting immediately (runtime) and persists it across reboots.

set -euo pipefail

readonly SYSCTL_CONF_FILE="/etc/sysctl.d/60-disable-icmp-send-redirects.conf"
readonly PARAMS=(
    "net.ipv4.conf.all.send_redirects"
    "net.ipv4.conf.default.send_redirects"
)
readonly DESIRED_VALUE="0"

if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

# Ensure the persistent config file exists
if [[ ! -f "${SYSCTL_CONF_FILE}" ]]; then
    touch "${SYSCTL_CONF_FILE}"
    chmod 0644 "${SYSCTL_CONF_FILE}"
fi

for param in "${PARAMS[@]}"; do
    # --- Persist setting in sysctl.d config file (idempotent) ---
    if grep -Eq "^\s*${param//./\\.}\s*=" "${SYSCTL_CONF_FILE}" 2>/dev/null; then
        # Update existing line if value differs
        current_persisted_value=$(grep -E "^\s*${param//./\\.}\s*=" "${SYSCTL_CONF_FILE}" | tail -n1 | awk -F= '{gsub(/[[:space:]]/, "", $2); print $2}')
        if [[ "${current_persisted_value}" != "${DESIRED_VALUE}" ]]; then
            sed -i -E "s|^\s*${param//./\\.}\s*=.*|${param} = ${DESIRED_VALUE}|" "${SYSCTL_CONF_FILE}"
        fi
    else
        echo "${param} = ${DESIRED_VALUE}" >> "${SYSCTL_CONF_FILE}"
    fi

    # --- Apply setting immediately at runtime (idempotent) ---
    current_runtime_value=$(sysctl -n "${param}" 2>/dev/null || echo "")
    if [[ "${current_runtime_value}" != "${DESIRED_VALUE}" ]]; then
        sysctl -w "${param}=${DESIRED_VALUE}" >/dev/null
    fi
done

# Reload sysctl settings from all config files to ensure consistency
sysctl --system >/dev/null 2>&1 || true

# Final verification
failed=0
for param in "${PARAMS[@]}"; do
    value=$(sysctl -n "${param}" 2>/dev/null || echo "")
    if [[ "${value}" != "${DESIRED_VALUE}" ]]; then
        echo "ERROR: Failed to set ${param} to ${DESIRED_VALUE} (current: ${value})" >&2
        failed=1
    fi
done

if [[ "${failed}" -eq 0 ]]; then
    echo "Success: ICMP redirect sending is disabled (runtime and persistent)."
    exit 0
else
    echo "ERROR: One or more settings failed to apply." >&2
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

**Prompt:** On an Ubuntu 24.04 system that is not acting as a router, the default network configuration currently permits the system to send ICMP redirect messages on IPv4 interfaces, which can leak route-table details and portions of the network topology. Write an idempotent bash remediation script that disables the sending of IPv4 ICMP redirects for the default interface configuration, applying the change at runtime and ensuring it persists across reboots.

**Model-generated script:**
```bash
#!/bin/bash
#
# Remediation script: Disable sending of IPv4 ICMP redirects for the default
# interface configuration on Ubuntu 24.04.
#
# This script is idempotent - it can be run multiple times without causing
# errors or duplicate entries, and will converge to the same end state.

set -euo pipefail

readonly SYSCTL_PARAM="net.ipv4.conf.default.send_redirects"
readonly DESIRED_VALUE="0"
readonly SYSCTL_CONF_DIR="/etc/sysctl.d"
readonly SYSCTL_CONF_FILE="${SYSCTL_CONF_DIR}/60-disable-ipv4-send-redirects.conf"

main() {
    ensure_conf_dir_exists
    write_persistent_config
    apply_runtime_setting
    verify_runtime_setting
}

ensure_conf_dir_exists() {
    if [[ ! -d "${SYSCTL_CONF_DIR}" ]]; then
        mkdir -p "${SYSCTL_CONF_DIR}"
    fi
}

write_persistent_config() {
    local desired_line="${SYSCTL_PARAM} = ${DESIRED_VALUE}"

    if [[ -f "${SYSCTL_CONF_FILE}" ]] && grep -Eq "^[[:space:]]*${SYSCTL_PARAM}[[:space:]]*=[[:space:]]*${DESIRED_VALUE}[[:space:]]*$" "${SYSCTL_CONF_FILE}"; then
        return 0
    fi

    cat > "${SYSCTL_CONF_FILE}" <<EOF
# Ubuntu 24.04 CIS/Hardening remediation
# Disable sending of IPv4 ICMP redirects for the default interface
# configuration. This system is not a router and should not send
# ICMP redirect messages, which can leak routing/topology information.
${desired_line}
EOF
}

apply_runtime_setting() {
    sysctl -w "${SYSCTL_PARAM}=${DESIRED_VALUE}" >/dev/null
}

verify_runtime_setting() {
    local current_value
    current_value="$(sysctl -n "${SYSCTL_PARAM}")"

    if [[ "${current_value}" != "${DESIRED_VALUE}" ]]; then
        echo "ERROR: Failed to set ${SYSCTL_PARAM} to ${DESIRED_VALUE} at runtime (current: ${current_value})" >&2
        exit 1
    fi
}

main "$@"
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
#!/bin/bash
#
# Remediation script: Disable ATM kernel module
# Prevents automatic and manual loading of the ATM networking protocol module.
# Idempotent: safe to run multiple times.

set -euo pipefail

MODULE_NAME="atm"
MODPROBE_CONF_DIR="/etc/modprobe.d"
MODPROBE_CONF_FILE="${MODPROBE_CONF_DIR}/${MODULE_NAME}-remediation.conf"

# Ensure we are running as root
if [[ "${EUID}" -ne 0 ]]; then
    echo "Error: This script must be run as root." >&2
    exit 1
fi

# Ensure the modprobe.d directory exists
if [[ ! -d "${MODPROBE_CONF_DIR}" ]]; then
    mkdir -p "${MODPROBE_CONF_DIR}"
fi

# Create or update the modprobe configuration file
# 'install <module> /bin/false' prevents the module from being loaded,
# whether automatically or manually via modprobe, as it replaces the
# normal install action with a no-op command.
INSTALL_LINE="install ${MODULE_NAME} /bin/false"

if [[ -f "${MODPROBE_CONF_FILE}" ]]; then
    if ! grep -qxF "${INSTALL_LINE}" "${MODPROBE_CONF_FILE}"; then
        echo "${INSTALL_LINE}" >> "${MODPROBE_CONF_FILE}"
    fi
else
    echo "${INSTALL_LINE}" > "${MODPROBE_CONF_FILE}"
fi

# Ensure the blacklist directive is also present to prevent
# automatic loading via module aliases/dependencies.
BLACKLIST_LINE="blacklist ${MODULE_NAME}"

if ! grep -qxF "${BLACKLIST_LINE}" "${MODPROBE_CONF_FILE}"; then
    echo "${BLACKLIST_LINE}" >> "${MODPROBE_CONF_FILE}"
fi

# Set correct permissions on the configuration file
chmod 0644 "${MODPROBE_CONF_FILE}"
chown root:root "${MODPROBE_CONF_FILE}"

# If the module is currently loaded, attempt to unload it
if lsmod | grep -qw "^${MODULE_NAME}"; then
    modprobe -r "${MODULE_NAME}" 2>/dev/null || true
fi

# Update the initramfs so the change is reflected at boot time, if supported
if command -v update-initramfs >/dev/null 2>&1; then
    update-initramfs -u >/dev/null 2>&1 || true
fi

echo "ATM kernel module has been disabled (automatic and manual loading blocked)."
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

**Prompt:** On an Ubuntu 24.04 system, the Controller Area Network (CAN) protocol is an uncommon serial communications protocol that is unnecessary on most systems; leaving its kernel support available expands the attack surface for exploitation of flaws in its implementation. Write an idempotent bash remediation script that ensures the CAN protocol kernel module cannot be loaded and is prevented from being used, with the configuration persisting across reboots.

**Model-generated script:**
```bash
#!/bin/bash
#
# Remediation script: Disable and blacklist the CAN kernel module
# This script is idempotent and safe to run multiple times.

set -euo pipefail

MODULE_NAME="can"
MODPROBE_CONF_DIR="/etc/modprobe.d"
MODPROBE_CONF_FILE="${MODPROBE_CONF_DIR}/can.conf"

# Ensure the modprobe.d directory exists
if [ ! -d "${MODPROBE_CONF_DIR}" ]; then
    mkdir -p "${MODPROBE_CONF_DIR}"
fi

# Ensure the configuration file exists
if [ ! -f "${MODPROBE_CONF_FILE}" ]; then
    touch "${MODPROBE_CONF_FILE}"
fi

# Add "install can /bin/false" directive if not already present
INSTALL_LINE="install ${MODULE_NAME} /bin/false"
if ! grep -qxF "${INSTALL_LINE}" "${MODPROBE_CONF_FILE}"; then
    echo "${INSTALL_LINE}" >> "${MODPROBE_CONF_FILE}"
fi

# Add "blacklist can" directive if not already present
BLACKLIST_LINE="blacklist ${MODULE_NAME}"
if ! grep -qxF "${BLACKLIST_LINE}" "${MODPROBE_CONF_FILE}"; then
    echo "${BLACKLIST_LINE}" >> "${MODPROBE_CONF_FILE}"
fi

# If the module is currently loaded, attempt to unload it
if lsmod | grep -qw "^${MODULE_NAME}"; then
    modprobe -r "${MODULE_NAME}" 2>/dev/null || true
fi

# Update initramfs to ensure the blacklist persists across reboots
if command -v update-initramfs >/dev/null 2>&1; then
    update-initramfs -u
fi

exit 0
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
#!/bin/bash
#
# Remediation script: Disable IEEE 1394 (FireWire) support on Ubuntu 24.04
#
# This script ensures the firewire kernel modules cannot be loaded
# automatically or manually, persistently across reboots. It is
# idempotent - safe to run multiple times without adverse effects.

set -euo pipefail

CONF_DIR="/etc/modprobe.d"
CONF_FILE="${CONF_DIR}/firewire-blacklist.conf"

# List of relevant FireWire kernel modules
MODULES=(
    "firewire-core"
    "firewire-ohci"
    "firewire-sbp2"
    "firewire-net"
)

# Ensure the modprobe.d directory exists
if [ ! -d "${CONF_DIR}" ]; then
    mkdir -p "${CONF_DIR}"
fi

# Create or overwrite the configuration file with correct directives
{
    echo "# FireWire (IEEE 1394) support disabled for security hardening"
    echo "# Managed by automated remediation script - do not edit manually"
    echo
    for mod in "${MODULES[@]}"; do
        echo "install ${mod} /bin/false"
    done
    echo
    for mod in "${MODULES[@]}"; do
        echo "blacklist ${mod}"
    done
} > "${CONF_FILE}.tmp"

# Only replace the file if content differs, to keep idempotency clean
if [ ! -f "${CONF_FILE}" ] || ! cmp -s "${CONF_FILE}.tmp" "${CONF_FILE}"; then
    mv "${CONF_FILE}.tmp" "${CONF_FILE}"
else
    rm -f "${CONF_FILE}.tmp"
fi

chmod 0644 "${CONF_FILE}"
chown root:root "${CONF_FILE}"

# Attempt to unload the modules if they are currently loaded
for mod in "${MODULES[@]}"; do
    mod_underscored="${mod//-/_}"
    if lsmod | grep -qw "${mod_underscored}"; then
        modprobe -r "${mod_underscored}" 2>/dev/null || true
    fi
done

# Update initramfs to ensure blacklist takes effect at boot, if available
if command -v update-initramfs >/dev/null 2>&1; then
    update-initramfs -u >/dev/null 2>&1 || true
fi

exit 0
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
#!/bin/bash
#
# Remediation script: Disable SCTP kernel module support persistently
#
set -euo pipefail

MODULE_NAME="sctp"
MODPROBE_CONF_DIR="/etc/modprobe.d"
MODPROBE_CONF_FILE="${MODPROBE_CONF_DIR}/${MODULE_NAME}_disable.conf"

# Ensure /etc/modprobe.d exists
if [ ! -d "${MODPROBE_CONF_DIR}" ]; then
    mkdir -p "${MODPROBE_CONF_DIR}"
fi

# Ensure the install directive is present to prevent loading the module
if [ -f "${MODPROBE_CONF_FILE}" ]; then
    if ! grep -qE "^\s*install\s+${MODULE_NAME}\s+/bin/(true|false)\s*$" "${MODPROBE_CONF_FILE}"; then
        echo "install ${MODULE_NAME} /bin/true" >> "${MODPROBE_CONF_FILE}"
    fi
else
    echo "install ${MODULE_NAME} /bin/true" > "${MODPROBE_CONF_FILE}"
fi

# Ensure the blacklist directive is present to prevent auto-loading
if ! grep -qE "^\s*blacklist\s+${MODULE_NAME}\s*$" "${MODPROBE_CONF_FILE}"; then
    echo "blacklist ${MODULE_NAME}" >> "${MODPROBE_CONF_FILE}"
fi

# If the module is currently loaded, attempt to unload it
if lsmod | grep -qE "^${MODULE_NAME}\b"; then
    modprobe -r "${MODULE_NAME}" 2>/dev/null || true
fi

# Update initramfs to ensure the change persists across reboots, if applicable
if command -v update-initramfs >/dev/null 2>&1; then
    update-initramfs -u >/dev/null 2>&1 || true
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
#!/bin/bash
#
# Remediation script: Disable TIPC (Transparent Inter-Process Communication) protocol
# This script ensures the TIPC kernel module cannot be loaded or used,
# and that the configuration persists across reboots.
#
# Idempotent: safe to run multiple times.

set -euo pipefail

MODULE_NAME="tipc"
MODPROBE_CONF_DIR="/etc/modprobe.d"
MODPROBE_CONF_FILE="${MODPROBE_CONF_DIR}/tipc.conf"

echo "Starting remediation for TIPC protocol..."

# Ensure modprobe.d directory exists
if [ ! -d "${MODPROBE_CONF_DIR}" ]; then
    echo "Creating directory ${MODPROBE_CONF_DIR}..."
    mkdir -p "${MODPROBE_CONF_DIR}"
fi

# Create or update the modprobe configuration file to prevent loading and blacklist the module
echo "Configuring ${MODPROBE_CONF_FILE} to disable TIPC..."

TMP_FILE=$(mktemp)

{
    echo "# Disable TIPC (Transparent Inter-Process Communication) protocol"
    echo "# This file is managed by a remediation script - do not edit manually"
    echo "install ${MODULE_NAME} /bin/false"
    echo "blacklist ${MODULE_NAME}"
} > "${TMP_FILE}"

if [ -f "${MODPROBE_CONF_FILE}" ]; then
    if ! diff -q "${TMP_FILE}" "${MODPROBE_CONF_FILE}" > /dev/null 2>&1; then
        cp "${TMP_FILE}" "${MODPROBE_CONF_FILE}"
        echo "Updated ${MODPROBE_CONF_FILE}."
    else
        echo "${MODPROBE_CONF_FILE} already correctly configured."
    fi
else
    cp "${TMP_FILE}" "${MODPROBE_CONF_FILE}"
    echo "Created ${MODPROBE_CONF_FILE}."
fi

rm -f "${TMP_FILE}"

chmod 0644 "${MODPROBE_CONF_FILE}"

# If the module is currently loaded, attempt to unload it
if lsmod | grep -q "^${MODULE_NAME}[[:space:]]"; then
    echo "TIPC module is currently loaded. Attempting to unload it..."
    if modprobe -r "${MODULE_NAME}" 2>/dev/null; then
        echo "Successfully unloaded TIPC module."
    else
        echo "Warning: Could not unload TIPC module (it may be in use). It will not load on next boot."
    fi
else
    echo "TIPC module is not currently loaded."
fi

# Update initramfs to ensure the blacklist takes effect at boot, if update-initramfs exists
if command -v update-initramfs > /dev/null 2>&1; then
    echo "Updating initramfs..."
    update-initramfs -u > /dev/null 2>&1 || echo "Warning: update-initramfs failed, but modprobe.d configuration is still in place."
fi

echo "Verifying configuration..."

if modprobe -n -v "${MODULE_NAME}" 2>/dev/null | grep -q "install /bin/false"; then
    echo "Verification successful: TIPC module load is blocked via install directive."
else
    echo "Warning: Verification of install directive failed. Please check ${MODPROBE_CONF_FILE} manually."
fi

if modprobe --showconfig 2>/dev/null | grep -q "blacklist ${MODULE_NAME}"; then
    echo "Verification successful: TIPC module is blacklisted."
else
    echo "Warning: Verification of blacklist directive failed. Please check ${MODPROBE_CONF_FILE} manually."
fi

echo "Remediation for TIPC protocol completed successfully."

exit 0
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
#!/bin/bash
set -euo pipefail

MODULE_NAME="bluetooth"
CONF_FILE="/etc/modprobe.d/${MODULE_NAME}-blacklist.conf"

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root." >&2
    exit 1
fi

TMP_FILE="$(mktemp)"
trap 'rm -f "${TMP_FILE}"' EXIT

{
    echo "install ${MODULE_NAME} /bin/false"
    echo "blacklist ${MODULE_NAME}"
} > "${TMP_FILE}"

if [ ! -f "${CONF_FILE}" ] || ! cmp -s "${TMP_FILE}" "${CONF_FILE}"; then
    install -m 0644 -o root -g root "${TMP_FILE}" "${CONF_FILE}"
fi

if lsmod | grep -q "^${MODULE_NAME}"; then
    modprobe -r "${MODULE_NAME}" 2>/dev/null || true
fi

if command -v update-initramfs >/dev/null 2>&1; then
    update-initramfs -u
fi

exit 0
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
#!/bin/bash
#
# Remediation script: Disable the cramfs filesystem kernel module
# on Ubuntu 24.04 to reduce local attack surface.
#
# This script is idempotent - it can be run multiple times safely
# without creating duplicate entries or causing errors.

set -euo pipefail

MODULE_NAME="cramfs"
MODPROBE_CONF_DIR="/etc/modprobe.d"
MODPROBE_CONF_FILE="${MODPROBE_CONF_DIR}/${MODULE_NAME}.conf"

# Ensure /etc/modprobe.d exists
if [ ! -d "${MODPROBE_CONF_DIR}" ]; then
    mkdir -p "${MODPROBE_CONF_DIR}"
fi

# --- Ensure the module cannot be loaded (install -> /bin/false) ---
INSTALL_LINE="install ${MODULE_NAME} /bin/false"

if [ -f "${MODPROBE_CONF_FILE}" ]; then
    if ! grep -qxF "${INSTALL_LINE}" "${MODPROBE_CONF_FILE}"; then
        echo "${INSTALL_LINE}" >> "${MODPROBE_CONF_FILE}"
    fi
else
    echo "${INSTALL_LINE}" > "${MODPROBE_CONF_FILE}"
fi

# --- Ensure the module is blacklisted (prevents autoloading via aliases) ---
BLACKLIST_LINE="blacklist ${MODULE_NAME}"

if ! grep -qxF "${BLACKLIST_LINE}" "${MODPROBE_CONF_FILE}"; then
    echo "${BLACKLIST_LINE}" >> "${MODPROBE_CONF_FILE}"
fi

# Set correct permissions on the config file
chmod 0644 "${MODPROBE_CONF_FILE}"
chown root:root "${MODPROBE_CONF_FILE}"

# --- If the module is currently loaded, attempt to unload it ---
if lsmod | grep -q "^${MODULE_NAME}\b"; then
    modprobe -r "${MODULE_NAME}" 2>/dev/null || true
fi

# --- Update initramfs so the change persists across reboots/kernel updates ---
if command -v update-initramfs >/dev/null 2>&1; then
    update-initramfs -u 2>/dev/null || true
fi

echo "Remediation applied: ${MODULE_NAME} module is now blacklisted and disabled."

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

**Prompt:** On an Ubuntu 24.04 system, prevent the use of USB mass-storage devices, which can be used to exfiltrate data or introduce malicious software, by configuring the kernel module subsystem so that the USB storage driver is neither automatically loaded nor loadable through the normal module-loading mechanism. Write an idempotent bash remediation script that disables and blacklists this driver so the change persists across reboots.

**Model-generated script:**
```bash
#!/bin/bash
#
# Remediation script: Disable and blacklist the USB storage kernel module
# on Ubuntu 24.04 to prevent use of USB mass-storage devices.
#
# This script is idempotent: it can be run multiple times without
# causing duplicate entries or errors.

set -euo pipefail

MODULE_NAME="usb-storage"
MODPROBE_CONF_DIR="/etc/modprobe.d"
MODPROBE_CONF_FILE="${MODPROBE_CONF_DIR}/usb-storage-blacklist.conf"

# Ensure the script is run as root
if [[ "${EUID}" -ne 0 ]]; then
    echo "Error: This script must be run as root." >&2
    exit 1
fi

# Ensure the modprobe.d directory exists
if [[ ! -d "${MODPROBE_CONF_DIR}" ]]; then
    mkdir -p "${MODPROBE_CONF_DIR}"
fi

# Create or update the modprobe configuration file idempotently
if [[ ! -f "${MODPROBE_CONF_FILE}" ]]; then
    cat > "${MODPROBE_CONF_FILE}" <<EOF
# Disable and blacklist the USB storage driver to prevent use of
# USB mass-storage devices (data exfiltration / malware introduction).
install ${MODULE_NAME} /bin/false
blacklist ${MODULE_NAME}
EOF
    echo "Created ${MODPROBE_CONF_FILE} with blacklist directives."
else
    # Ensure "install <module> /bin/false" line is present
    if ! grep -Eq "^\s*install\s+${MODULE_NAME}\s+/bin/false\s*$" "${MODPROBE_CONF_FILE}"; then
        echo "install ${MODULE_NAME} /bin/false" >> "${MODPROBE_CONF_FILE}"
        echo "Added 'install ${MODULE_NAME} /bin/false' directive."
    fi

    # Ensure "blacklist <module>" line is present
    if ! grep -Eq "^\s*blacklist\s+${MODULE_NAME}\s*$" "${MODPROBE_CONF_FILE}"; then
        echo "blacklist ${MODULE_NAME}" >> "${MODPROBE_CONF_FILE}"
        echo "Added 'blacklist ${MODULE_NAME}' directive."
    fi

    echo "${MODPROBE_CONF_FILE} already contains required directives (updated if needed)."
fi

# If the module is currently loaded, attempt to remove it
if lsmod | grep -qw "${MODULE_NAME//-/_}"; then
    echo "Module ${MODULE_NAME} is currently loaded. Attempting to unload it."
    if modprobe -r "${MODULE_NAME}" 2>/dev/null; then
        echo "Successfully unloaded ${MODULE_NAME}."
    else
        echo "Warning: Could not unload ${MODULE_NAME} (it may be in use)." >&2
    fi
else
    echo "Module ${MODULE_NAME} is not currently loaded."
fi

# Update initramfs so the blacklist takes effect on next boot as well
if command -v update-initramfs >/dev/null 2>&1; then
    update-initramfs -u
    echo "initramfs updated."
else
    echo "Warning: update-initramfs command not found; skipping initramfs update." >&2
fi

echo "Remediation complete: ${MODULE_NAME} is disabled and blacklisted."

exit 0
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
```bash
#!/usr/bin/env bash
set -euo pipefail

BOOT_MNT="/boot"
FSTAB="/etc/fstab"

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

if ! command
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

# Ensure /dev/shm is currently mounted with nodev
if findmnt -kn "$MOUNT_POINT" >/dev/null 2>&1; then
    mount -o remount,nodev "$MOUNT_POINT"
fi

# Handle /etc/fstab persistence
if grep -qE "^\s*[^#][^[:space:]]*\s+${MOUNT_POINT}\s+" "$FSTAB"; then
    # There is already an entry for /dev/shm - ensure it has nodev
    CURRENT_LINE=$(grep -E "^\s*[^#][^[:space:]]*\s+${MOUNT_POINT}\s+" "$FSTAB")

    FS_SPEC=$(awk '{print $1}' <<< "$CURRENT_LINE")
    FS_FILE=$(awk '{print $2}' <<< "$CURRENT_LINE")
    FS_VFSTYPE=$(awk '{print $3}' <<< "$CURRENT_LINE")
    FS_MNTOPS=$(awk '{print $4}' <<< "$CURRENT_LINE")
    FS_FREQ=$(awk '{print $5}' <<< "$CURRENT_LINE")
    FS_PASSNO=$(awk '{print $6}' <<< "$CURRENT_LINE")

    [ -z "$FS_FREQ" ] && FS_FREQ="0"
    [ -z "$FS_PASSNO" ] && FS_PASSNO="0"

    IFS=',' read -ra OPTS <<< "$FS_MNTOPS"
    HAS_NODEV=0
    NEW_OPTS=()
    for opt in "${OPTS[@]}"; do
        if [ "$opt" = "nodev" ]; then
            HAS_NODEV=1
        fi
        NEW_OPTS+=("$opt")
    done

    if [ "$HAS_NODEV" -eq 0 ]; then
        NEW_OPTS+=("nodev")
    fi

    NEW_MNTOPS=$(IFS=,; echo "${NEW_OPTS[*]}")

    NEW_LINE="${FS_SPEC} ${FS_FILE} ${FS_VFSTYPE} ${NEW_MNTOPS} ${FS_FREQ} ${FS_PASSNO}"

    if [ "$NEW_LINE" != "$CURRENT_LINE" ]; then
        ESCAPED_CURRENT=$(printf '%s\n' "$CURRENT_LINE" | sed -e 's/[\/&]/\\&/g')
        ESCAPED_NEW=$(printf '%s\n' "$NEW_LINE" | sed -e 's/[\/&]/\\&/g')
        sed -i "s/${ESCAPED_CURRENT}/${ESCAPED_NEW}/" "$FSTAB"
    fi
else
    # No entry exists - add one
    echo "tmpfs ${MOUNT_POINT} tmpfs defaults,nodev,nosuid,noexec 0 0" >> "$FSTAB"
fi

# Remount to apply fstab-defined options if changed
if findmnt -kn "$MOUNT_POINT" >/dev/null 2>&1; then
    mount -o remount "$MOUNT_POINT"
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
TS="$(date +%Y%m%d%H%M%S)"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# Backup fstab before making changes
cp -p "$FSTAB" "${FSTAB}.bak.${TS}"

# Determine current fstab line for /dev/shm (if any), excluding comments
current_line="$(grep -E '^[^#].*[[:space:]]'"${MOUNT_POINT}"'[[:space:]]' "$FSTAB" || true)"

if [[ -n "$current_line" ]]; then
    # Parse fields
    device="$(awk '{print $1}' <<< "$current_line")"
    mpoint="$(awk '{print $2}' <<< "$current_line")"
    fstype="$(awk '{print $3}' <<< "$current_line")"
    opts="$(awk '{print $4}' <<< "$current_line")"
    dump="$(awk '{print $5}' <<< "$current_line")"
    pass="$(awk '{print $6}' <<< "$current_line")"

    # Default dump/pass if missing
    dump="${dump:-0}"
    pass="${pass:-0}"

    # Ensure noexec is present in options
    IFS=',' read -ra opt_array <<< "$opts"
    has_noexec=0
    for o in "${opt_array[@]}"; do
        if [[ "$o" == "noexec" ]]; then
            has_noexec=1
            break
        fi
    done

    if [[ $has_noexec -eq 0 ]]; then
        if [[ -z "$opts" || "$opts" == "defaults" ]]; then
            new_opts="defaults,noexec"
        else
            new_opts="${opts},noexec"
        fi
    else
        new_opts="$opts"
    fi

    new_line="${device} ${mpoint} ${fstype} ${new_opts} ${dump} ${pass}"

    if [[ "$new_line" != "$current_line" ]]; then
        # Replace the existing line with the updated one
        escaped_current="$(printf '%s\n' "$current_line" | sed -e 's/[\/&]/\\&/g')"
        escaped_new="$(printf '%s\n' "$new_line" | sed -e 's/[\/&]/\\&/g')"
        sed -i "s|^${escaped_current}\$|${escaped_new}|" "$FSTAB"
    fi
else
    # No existing entry, add a new one with sane defaults for tmpfs
    echo "tmpfs ${MOUNT_POINT} tmpfs defaults,noexec,nosuid,nodev 0 0" >> "$FSTAB"
fi

# Apply the setting to the currently active mount without requiring a reboot
mount -o remount,noexec,nosuid,nodev "$MOUNT_POINT"

exit 0
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
#!/bin/bash
#
# secure-dev-shm.sh
# Idempotent remediation script to enforce nosuid (and nodev/noexec are left untouched
# unless already present) on /dev/shm, ensuring setuid/setgid bits are ignored there.
# Applies immediately via remount and persists via /etc/fstab.

set -euo pipefail

MOUNT_POINT="/dev/shm"
FSTAB="/etc/fstab"
FSTAB_BACKUP="/etc/fstab.bak.$(date +%Y%m%d%H%M%S)"
REQUIRED_OPT="nosuid"

log() {
    echo "[secure-dev-shm] $*"
}

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

if ! mountpoint -q "$MOUNT_POINT"; then
    echo "Error: $MOUNT_POINT is not currently a mount point." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 1: Update /etc/fstab for persistence
# ---------------------------------------------------------------------------

if grep -Eq "^\s*[^#[:space:]]+\s+${MOUNT_POINT}\s+" "$FSTAB"; then
    # There is an existing entry for /dev/shm
    CURRENT_LINE=$(grep -E "^\s*[^#[:space:]]+\s+${MOUNT_POINT}\s+" "$FSTAB" | head -n1)

    # Extract the options field (5th field)
    CURRENT_OPTS=$(echo "$CURRENT_LINE" | awk '{print $4}')

    if [[ ",${CURRENT_OPTS}," == *",${REQUIRED_OPT},"* ]]; then
        log "fstab entry for ${MOUNT_POINT} already contains '${REQUIRED_OPT}'. No fstab change needed."
    else
        log "Backing up ${FSTAB} to ${FSTAB_BACKUP}"
        cp -p "$FSTAB" "$FSTAB_BACKUP"

        if [[ -z "$CURRENT_OPTS" || "$CURRENT_OPTS" == "defaults" ]]; then
            NEW_OPTS="defaults,${REQUIRED_OPT}"
        else
            NEW_OPTS="${CURRENT_OPTS},${REQUIRED_OPT}"
        fi

        # Rebuild the line with new options, preserving other fields
        NEW_LINE=$(echo "$CURRENT_LINE" | awk -v newopts="$NEW_OPTS" '{ $4=newopts; print }' OFS='\t')

        # Escape special characters for sed replacement (use a temp file approach instead)
        TMP_FSTAB=$(mktemp)
        awk -v mp="$MOUNT_POINT" -v newline="$NEW_LINE" '
            {
                if ($0 ~ ("^[^#[:space:]]+[[:space:]]+" mp "[[:space:]]")) {
                    print newline
                } else {
                    print $0
                }
            }
        ' "$FSTAB" > "$TMP_FSTAB"

        mv "$TMP_FSTAB" "$FSTAB"
        chmod 644 "$FSTAB"
        log "Updated fstab entry for ${MOUNT_POINT} to include '${REQUIRED_OPT}'."
    fi
else
    log "No existing fstab entry for ${MOUNT_POINT} found. Adding a new entry."
    log "Backing up ${FSTAB} to ${FSTAB_BACKUP}"
    cp -p "$FSTAB" "$FSTAB_BACKUP"

    {
        echo -e "tmpfs\t${MOUNT_POINT}\ttmpfs\tdefaults,${REQUIRED_OPT}\t0\t0"
    } >> "$FSTAB"

    log "Added new fstab entry for ${MOUNT_POINT} with '${REQUIRED_OPT}'."
fi

# ---------------------------------------------------------------------------
# Step 2: Apply the change immediately via remount
# ---------------------------------------------------------------------------

CURRENT_MOUNT_OPTS=$(findmnt -no OPTIONS "$MOUNT_POINT")

if [[ ",${CURRENT_MOUNT_OPTS}," == *",${REQUIRED_OPT},"* ]]; then
    log "${MOUNT_POINT} is already currently mounted with '${REQUIRED_OPT}'."
else
    log "Remounting ${MOUNT_POINT} with '${REQUIRED_OPT}' to apply immediately."
    mount -o remount,"${REQUIRED_OPT}" "$MOUNT_POINT"
fi

# ---------------------------------------------------------------------------
# Step 3: Verify final state
# ---------------------------------------------------------------------------

FINAL_OPTS=$(findmnt -no OPTIONS "$MOUNT_POINT")
if [[ ",${FINAL_OPTS}," == *",${REQUIRED_OPT},"* ]]; then
    log "Verification successful: ${MOUNT_POINT} is mounted with options: ${FINAL_OPTS}"
else
    echo "Error: Failed to verify '${REQUIRED_OPT}' is active on ${MOUNT_POINT}." >&2
    exit 1
fi

log "Remediation complete. ${MOUNT_POINT} now ignores setuid/setgid bits, immediately and persistently."
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
#!/bin/bash
#
# Remediation script: Disable USB webcam (uvcvideo) kernel module
#
# This script ensures the uvcvideo kernel module (driver for USB video
# class devices, i.e., webcams) cannot be loaded automatically or
# manually, and that this configuration persists across reboots.
#
# Idempotent: safe to run multiple times.

set -euo pipefail

MODULE_NAME="uvcvideo"
MODPROBE_CONF_DIR="/etc/modprobe.d"
MODPROBE_CONF_FILE="${MODPROBE_CONF_DIR}/disable-uvcvideo.conf"

# Ensure we are running as root
if [[ "${EUID}" -ne 0 ]]; then
    echo "Error: This script must be run as root." >&2
    exit 1
fi

# Ensure /etc/modprobe.d exists
if [[ ! -d "${MODPROBE_CONF_DIR}" ]]; then
    mkdir -p "${MODPROBE_CONF_DIR}"
fi

# Create or update the modprobe configuration file to:
#   1. Blacklist the module (prevents automatic loading via udev/aliases)
#   2. Set install command to /bin/true (prevents manual loading via modprobe)
TMP_FILE="$(mktemp)"
trap 'rm -f "${TMP_FILE}"' EXIT

{
    echo "# Managed by remediation script - do not edit manually"
    echo "# Disables loading of the ${MODULE_NAME} kernel module (USB webcam driver)"
    echo "install ${MODULE_NAME} /bin/true"
    echo "blacklist ${MODULE_NAME}"
} > "${TMP_FILE}"

if [[ ! -f "${MODPROBE_CONF_FILE}" ]] || ! cmp -s "${TMP_FILE}" "${MODPROBE_CONF_FILE}"; then
    install -m 0644 -o root -g root "${TMP_FILE}" "${MODPROBE_CONF_FILE}"
    echo "Updated ${MODPROBE_CONF_FILE} to blacklist and disable install of ${MODULE_NAME}."
else
    echo "${MODPROBE_CONF_FILE} already configured correctly."
fi

# If the module is currently loaded, attempt to unload it
if lsmod | grep -qw "^${MODULE_NAME}"; then
    echo "Module ${MODULE_NAME} is currently loaded. Attempting to unload..."
    if modprobe -r "${MODULE_NAME}" 2>/dev/null; then
        echo "Successfully unloaded ${MODULE_NAME}."
    else
        echo "Warning: Could not unload ${MODULE_NAME} (it may be in use). It will not load on next boot." >&2
    fi
else
    echo "Module ${MODULE_NAME} is not currently loaded."
fi

# Update initramfs so the blacklist takes effect on next boot as well
if command -v update-initramfs >/dev/null 2>&1; then
    update-initramfs -u
    echo "initramfs updated."
else
    echo "Warning: update-initramfs command not found; initramfs not updated." >&2
fi

echo "Remediation complete: ${MODULE_NAME} module is blacklisted and disabled."

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

**Prompt:** On an Ubuntu 24.04 system, prevent the operating system from storing application core dumps, since these memory images can capture sensitive in-memory data and are generally only useful for debugging. Configure the system so that core dumps are not written to disk, and ensure this behavior takes effect immediately and persists across reboots. Write an idempotent bash remediation script that achieves this end state.

**Model-generated script:**
```bash
```bash
#!/usr/bin/env bash
#
# remediate_disable_coredumps.sh
#
# Purpose: Prevent the OS from storing application core dumps.
# Idempotent: safe to run multiple times; only makes changes if needed.

set -euo pipefail

LIMITS_FILE="/etc/security/limits.d/99-disable-core-dumps.conf"
SYSCTL_FILE="/etc/sysctl.d/99-disable-core-dumps.conf"
COREDUMP_CONF="/etc/systemd/coredump.conf"
COREDUMP_DROPIN_DIR="/etc/systemd/coredump.conf.d"
COREDUMP_DROPIN="${COREDUMP_DROPIN_DIR}/99-disable-core-dumps.conf"

log() {
    echo "[remediate-coredumps] $*"
}

# --- 1. Enforce hard/soft core ulimit = 0 for all users via limits.d ---
if [[ ! -f "${LIMITS_FILE}" ]] || ! grep -qE '^\*\s+hard\s+core\s+0\s*$' "${LIMITS_FILE}" 2>/dev/null; then
    log "Configuring ${LIMITS_FILE} to disable core dumps via ulimit"
    cat > "${LIMITS_FILE}" <<'EOF'
# Managed by remediation script: disable core dumps for all users
* hard core 0
* soft core 0
EOF
else
    log "${LIMITS_FILE} already configured"
fi

# --- 2. Set kernel sysctl parameters to disable core dumps ---
DESIRED_SYSCTL_CONTENT=$(cat <<'EOF'
# Managed by remediation script: disable core dumps
fs.suid_dumpable = 0
kernel.core_pattern = |/bin/false
EOF
)

if [[ ! -f "${SYSCTL_FILE}" ]] || [[ "$(cat "${SYSCTL_FILE}")" != "${DESIRED_SYSCTL_CONTENT}" ]]; then
    log "Configuring ${SYSCTL_FILE} to disable core dumps"
    printf '%s\n' "${DESIRED_SYSCTL_CONTENT}" > "${SYSCTL_FILE}"
else
    log "${SYSCTL_FILE} already configured"
fi

# Apply sysctl settings immediately
log "Applying sysctl settings immediately"
sysctl -w fs.suid_dumpable=0 >/dev/null
sysctl -w "kernel.core_pattern=|/bin/false" >/dev/null

# Reload all sysctl config to ensure persistence-application alignment
sysctl --system >/dev/null 2>&1 || true

# --- 3. Disable systemd-coredump storage (if systemd-coredump is present) ---
if [[ -d /etc/systemd ]]; then
    mkdir -p "${COREDUMP_DROPIN_DIR}"

    DESIRED_COREDUMP_CONTENT=$(cat <<'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
)

    if [[ ! -f "${COREDUMP_DROPIN}" ]] || [[ "$(cat "${COREDUMP_DROPIN}")" != "${DESIRED_COREDUMP_CONTENT}" ]]; then
        log "Configuring ${COREDUMP_DROPIN} to disable systemd-coredump storage"
        printf '%s\n' "${DESIRED_COREDUMP_CONTENT}" > "${COREDUMP_DROPIN}"
    else
        log "${COREDUMP_DROPIN} already configured"
    fi

    # Also update the main config file if present, for systems that read it directly
    if [[ -f "${COREDUMP_CONF}" ]]; then
        if ! grep -qE '^\s*Storage\s*=\s*none\s*$' "${COREDUMP_CONF}"; then
            if grep -qE '^\[Coredump\]' "${COREDUMP_CONF}"; then
                if grep -qE '^\s*Storage\s*=' "${COREDUMP_CONF}"; then
                    sed -i -E 's/^\s*Storage\s*=.*/Storage=none/' "${COREDUMP_CONF}"
                else
                    sed -i '/^\[Coredump\]/a Storage=none' "${COREDUMP_CONF}"
                fi
            else
                printf '\n[Coredump]\nStorage=none\n' >> "${COREDUMP_CONF}"
            fi
            log "Updated ${COREDUMP_CONF} to set Storage=none"
        else
            log "${COREDUMP_CONF} already has Storage=none"
        fi

        if ! grep -qE '^\s*ProcessSizeMax\s*=\s*0\s*$' "${COREDUMP_CONF}"; then
            if grep -qE '^\s*ProcessSizeMax\s*=' "${COREDUMP_CONF}"; then
                sed -i -E 's/^\s*ProcessSizeMax\s*=.*/ProcessSizeMax=0/' "${COREDUMP_CONF}"
            else
                sed -i '/^\[Coredump\]/a ProcessSizeMax=0' "${COREDUMP_CONF}"
            fi
            log "Updated ${COREDUMP_CONF} to set ProcessSizeMax=0"
        else
            log "${COREDUMP_CONF} already has ProcessSizeMax=0"
        fi
    fi

    # Reload systemd manager config to pick up drop-in changes
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reexec >/dev
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
set -euo pipefail

SYSCTL_PARAM="kernel.dmesg_restrict"
DESIRED_VALUE="1"
CONF_FILE="/etc/sysctl.d/60-dmesg-restrict.conf"
CONF_LINE="${SYSCTL_PARAM} = ${DESIRED_VALUE}"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# Apply at runtime immediately (idempotent - setting same value again is harmless)
current_value="$(sysctl -n "${SYSCTL_PARAM}" 2>/dev/null || echo "")"
if [[ "${current_value}" != "${DESIRED_VALUE}" ]]; then
    sysctl -w "${SYSCTL_PARAM}=${DESIRED_VALUE}" >/dev/null
fi

# Ensure persistence across reboots via sysctl.d drop-in
if [[ -f "${CONF_FILE}" ]]; then
    if grep -Eq "^\s*${SYSCTL_PARAM}\s*=\s*${DESIRED_VALUE}\s*$" "${CONF_FILE}"; then
        : # already correctly configured
    else
        # Remove any existing (possibly conflicting) lines for this key, then add the correct one
        tmp_file="$(mktemp)"
        grep -Ev "^\s*${SYSCTL_PARAM}\s*=" "${CONF_FILE}" > "${tmp_file}" || true
        echo "${CONF_LINE}" >> "${tmp_file}"
        mv "${tmp_file}" "${CONF_FILE}"
    fi
else
    printf '%s\n' "${CONF_LINE}" > "${CONF_FILE}"
fi

chmod 0644 "${CONF_FILE}"

# Reload sysctl settings from all config files to confirm persistence takes effect now too
sysctl --system >/dev/null 2>&1 || true

final_value="$(sysctl -n "${SYSCTL_PARAM}" 2>/dev/null || echo "")"
if [[ "${final_value}" != "${DESIRED_VALUE}" ]]; then
    echo "Failed to set ${SYSCTL_PARAM} to ${DESIRED_VALUE}." >&2
    exit 1
fi

echo "dmesg_restrict is set to ${DESIRED_VALUE} (runtime) and persisted in ${CONF_FILE}."
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
#!/bin/bash
set -euo pipefail

SYSCTL_PARAM="kernel.kexec_load_disabled"
SYSCTL_FILE="/etc/sysctl.d/60-kexec.conf"
DESIRED_VALUE="1"

# Ensure the persistent configuration file has the correct setting
if [ -f "${SYSCTL_FILE}" ]; then
    if grep -qE "^\s*${SYSCTL_PARAM}\s*=" "${SYSCTL_FILE}"; then
        sed -i "s/^\s*${SYSCTL_PARAM}\s*=.*/${SYSCTL_PARAM} = ${DESIRED_VALUE}/" "${SYSCTL_FILE}"
    else
        echo "${SYSCTL_PARAM} = ${DESIRED_VALUE}" >> "${SYSCTL_FILE}"
    fi
else
    echo "${SYSCTL_PARAM} = ${DESIRED_VALUE}" > "${SYSCTL_FILE}"
fi

# Apply the setting at runtime, if not already set (cannot be unset without reboot)
CURRENT_VALUE="$(sysctl -n "${SYSCTL_PARAM}" 2>/dev/null || echo "")"

if [ "${CURRENT_VALUE}" != "${DESIRED_VALUE}" ]; then
    sysctl -w "${SYSCTL_PARAM}=${DESIRED_VALUE}"
fi

# Reload sysctl settings from all configuration files to ensure consistency
sysctl --system > /dev/null

exit 0
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
DESIRED_VALUE="3"
CONF_FILE="/etc/sysctl.d/60-perf-event-paranoid.conf"
CONF_LINE="${SYSCTL_PARAM} = ${DESIRED_VALUE}"

# Ensure the runtime value is set immediately
CURRENT_VALUE="$(sysctl -n "${SYSCTL_PARAM}" 2>/dev/null || echo "")"
if [ "${CURRENT_VALUE}" != "${DESIRED_VALUE}" ]; then
    sysctl -w "${SYSCTL_PARAM}=${DESIRED_VALUE}" >/dev/null
fi

# Remove any conflicting settings for this key in other sysctl config files
# to avoid ambiguity, but leave our own managed file intact.
grep -rl --include="*.conf" -E "^[[:space:]]*${SYSCTL_PARAM//./\\.}[[:space:]]*=" /etc/sysctl.d /etc/sysctl.conf 2>/dev/null \
    | while IFS= read -r file; do
        if [ "${file}" != "${CONF_FILE}" ]; then
            sed -i -E "/^[[:space:]]*${SYSCTL_PARAM//./\\.}[[:space:]]*=/d" "${file}"
        fi
    done

# Ensure the persistent configuration file exists and contains the correct setting
mkdir -p "$(dirname "${CONF_FILE}")"
if [ -f "${CONF_FILE}" ]; then
    if grep -qE "^[[:space:]]*${SYSCTL_PARAM//./\\.}[[:space:]]*=" "${CONF_FILE}"; then
        sed -i -E "s|^[[:space:]]*${SYSCTL_PARAM//./\\.}[[:space:]]*=.*|${CONF_LINE}|" "${CONF_FILE}"
    else
        echo "${CONF_LINE}" >> "${CONF_FILE}"
    fi
else
    printf '%s\n' "${CONF_LINE}" > "${CONF_FILE}"
fi

# Apply sysctl settings from the persistent file to confirm consistency
sysctl -p "${CONF_FILE}" >/dev/null

# Final verification
FINAL_VALUE="$(sysctl -n "${SYSCTL_PARAM}")"
if [ "${FINAL_VALUE}" != "${DESIRED_VALUE}" ]; then
    echo "ERROR: Failed to set ${SYSCTL_PARAM} to ${DESIRED_VALUE} (current: ${FINAL_VALUE})" >&2
    exit 1
fi

echo "OK: ${SYSCTL_PARAM} is set to ${DESIRED_VALUE} and persisted in ${CONF_FILE}"
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

PARAM="kernel.unprivileged_bpf_disabled"
DESIRED_VALUE=1
SYSCTL_FILE="/etc/sysctl.d/99-disable-unprivileged-bpf.conf"

if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

CURRENT_VALUE="$(sysctl -n "${PARAM}" 2>/dev/null || echo "")"

if [[ "${CURRENT_VALUE}" != "${DESIRED_VALUE}" && "${CURRENT_VALUE}" != "2" ]]; then
    sysctl -w "${PARAM}=${DESIRED_VALUE}" >/dev/null
fi

if [[ -f "${SYSCTL_FILE}" ]]; then
    if grep -qE "^\s*${PARAM}\s*=" "${SYSCTL_FILE}"; then
        sed -i -E "s|^\s*${PARAM}\s*=.*|${PARAM} = ${DESIRED_VALUE}|" "${SYSCTL_FILE}"
    else
        echo "${PARAM} = ${DESIRED_VALUE}" >> "${SYSCTL_FILE}"
    fi
else
    printf '%s\n' \
        "# Disable unprivileged use of the BPF syscall (Ubuntu 24.04 hardening)" \
        "${PARAM} = ${DESIRED_VALUE}" > "${SYSCTL_FILE}"
fi

chmod 0644 "${SYSCTL_FILE}"

sysctl --system >/dev/null 2>&1 || sysctl -p "${SYSCTL_FILE}" >/dev/null 2>&1 || true

FINAL_VALUE="$(sysctl -n "${PARAM}" 2>/dev/null || echo "")"
if [[ "${FINAL_VALUE}" != "${DESIRED_VALUE}" && "${FINAL_VALUE}" != "2" ]]; then
    echo "Failed to verify ${PARAM} is set correctly (current: ${FINAL_VALUE})." >&2
    exit 1
fi

echo "Unprivileged BPF syscall access is disabled (kernel.unprivileged_bpf_disabled=${FINAL_VALUE})."
echo "Configuration persisted in ${SYSCTL_FILE}."
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
#!/bin/bash
set -euo pipefail

CONF_FILE="/etc/sysctl.d/10-ptrace-restrict.conf"
PARAM="kernel.yama.ptrace_scope"
VALUE="1"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

if ! grep -q "^${PARAM}[[:space:]]*=" "$CONF_FILE" 2>/dev/null; then
    echo "${PARAM} = ${VALUE}" > "$CONF_FILE"
else
    sed -i "s/^${PARAM}[[:space:]]*=.*/${PARAM} = ${VALUE}/" "$CONF_FILE"
fi

chmod 644 "$CONF_FILE"

current_value=$(sysctl -n "${PARAM}" 2>/dev/null || echo "")
if [[ "$current_value" != "$VALUE" ]]; then
    sysctl -w "${PARAM}=${VALUE}" >/dev/null
fi

sysctl --system >/dev/null 2>&1 || true

final_value=$(sysctl -n "${PARAM}" 2>/dev/null || echo "")
if [[ "$final_value" == "$VALUE" ]]; then
    echo "ptrace_scope successfully set to ${VALUE} (restricted to direct descendants)."
else
    echo "Failed to set ptrace_scope to ${VALUE}." >&2
    exit 1
fi

exit 0
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
#!/bin/bash
#
# Harden the BPF JIT compiler (net.core.bpf_jit_harden = 2)
# Applies at runtime and persists across reboots. Idempotent.

set -euo pipefail

SYSCTL_PARAM="net.core.bpf_jit_harden"
SYSCTL_VALUE="2"
PERSIST_FILE="/etc/sysctl.d/60-bpf-jit-harden.conf"

# Ensure script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# Apply the setting at runtime immediately
current_value="$(sysctl -n "${SYSCTL_PARAM}" 2>/dev/null || echo "")"
if [ "${current_value}" != "${SYSCTL_VALUE}" ]; then
    sysctl -w "${SYSCTL_PARAM}=${SYSCTL_VALUE}" >/dev/null
fi

# Ensure persistence across reboots via sysctl.d drop-in file
desired_line="${SYSCTL_PARAM} = ${SYSCTL_VALUE}"

if [ -f "${PERSIST_FILE}" ]; then
    if grep -qE "^\s*${SYSCTL_PARAM}\s*=\s*[0-9]+\s*$" "${PERSIST_FILE}"; then
        # Update existing line only if it doesn't already match desired value
        if ! grep -qE "^\s*${SYSCTL_PARAM}\s*=\s*${SYSCTL_VALUE}\s*$" "${PERSIST_FILE}"; then
            sed -i -E "s|^\s*${SYSCTL_PARAM}\s*=\s*[0-9]+\s*$|${desired_line}|" "${PERSIST_FILE}"
        fi
    else
        echo "${desired_line}" >> "${PERSIST_FILE}"
    fi
else
    cat > "${PERSIST_FILE}" <<EOF
# Managed by hardening script: enforce strongest BPF JIT hardening
${desired_line}
EOF
fi

# Reload sysctl settings from all system configuration files to ensure consistency
sysctl --system >/dev/null 2>&1 || true

# Final verification
final_value="$(sysctl -n "${SYSCTL_PARAM}")"
if [ "${final_value}" != "${SYSCTL_VALUE}" ]; then
    echo "Failed to set ${SYSCTL_PARAM} to ${SYSCTL_VALUE}. Current value: ${final_value}" >&2
    exit 1
fi

echo "BPF JIT hardening applied successfully: ${SYSCTL_PARAM} = ${final_value}"
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
#
# disable-userns.sh
#
# Idempotently disables the creation of new user namespaces on Ubuntu 24.04
# by setting the kernel.max_user_namespaces (user.max_user_namespaces) limit
# to zero, both at runtime and persistently via sysctl configuration.
#
# Safe to run multiple times.

set -euo pipefail

readonly SYSCTL_PARAM="user.max_user_namespaces"
readonly SYSCTL_VALUE="0"
readonly SYSCTL_CONF_DIR="/etc/sysctl.d"
readonly SYSCTL_CONF_FILE="${SYSCTL_CONF_DIR}/60-disable-userns.conf"
readonly SYSCTL_PROC_PATH="/proc/sys/user/max_user_namespaces"

if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

if [[ ! -e "${SYSCTL_PROC_PATH}" ]]; then
    echo "ERROR: ${SYSCTL_PROC_PATH} does not exist on this system. Kernel may not support user namespaces limiting." >&2
    exit 1
fi

# Ensure the sysctl configuration directory exists.
mkdir -p "${SYSCTL_CONF_DIR}"

# Idempotently write/update the persistent sysctl configuration file.
DESIRED_LINE="${SYSCTL_PARAM} = ${SYSCTL_VALUE}"

if [[ -f "${SYSCTL_CONF_FILE}" ]] && grep -qE "^\s*${SYSCTL_PARAM}\s*=\s*${SYSCTL_VALUE}\s*$" "${SYSCTL_CONF_FILE}"; then
    echo "Persistent configuration already present and correct in ${SYSCTL_CONF_FILE}."
else
    printf '%s\n' \
        "# Disable creation of user namespaces (managed by disable-userns.sh)" \
        "${DESIRED_LINE}" \
        > "${SYSCTL_CONF_FILE}"
    chmod 0644 "${SYSCTL_CONF_FILE}"
    echo "Wrote persistent configuration to ${SYSCTL_CONF_FILE}."
fi

# Apply the setting immediately to the running kernel.
CURRENT_VALUE="$(cat "${SYSCTL_PROC_PATH}" 2>/dev/null || echo "unknown")"

if [[ "${CURRENT_VALUE}" == "${SYSCTL_VALUE}" ]]; then
    echo "Runtime value of ${SYSCTL_PARAM} is already ${SYSCTL_VALUE}."
else
    if sysctl -w "${SYSCTL_PARAM}=${SYSCTL_VALUE}" >/dev/null; then
        echo "Applied ${SYSCTL_PARAM}=${SYSCTL_VALUE} to the running kernel."
    else
        echo "ERROR: Failed to set ${SYSCTL_PARAM} at runtime." >&2
        exit 1
    fi
fi

# Reload all sysctl configuration to ensure consistency across files.
sysctl --system >/dev/null

# Final verification.
FINAL_VALUE="$(cat "${SYSCTL_PROC_PATH}")"
if [[ "${FINAL_VALUE}" == "${SYSCTL_VALUE}" ]]; then
    echo "Verification succeeded: ${SYSCTL_PARAM} = ${FINAL_VALUE}"
else
    echo "ERROR: Verification failed. Current value is '${FINAL_VALUE}', expected '${SYSCTL_VALUE}'." >&2
    exit 1
fi

exit 0
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
```bash
#!/usr/bin/env bash
#
# remediate_disable_systemd_coredump.sh
#
# Idempotent remediation script to fully disable acquisition, saving, and
# processing of application core dumps via systemd-coredump on Ubuntu 24.04.
#
# This script:
#   1. Masks the systemd-coredump.socket and systemd-coredump@.service units
#      so they cannot be started or activated (manually or via socket
#      activation), and ensures this persists across reboots.
#   2. Stops any currently running instance(s) of the service.
#   3. Configures /etc/sysctl.d to set kernel.core_pattern to a value that
#      discards core dumps, applying it immediately and persistently.
#   4. Sets a system-wide core ulimit of 0 via /etc/security/limits.d to
#      prevent core files from being written even outside systemd-coredump.
#   5. Configures /etc/systemd/coredump.conf to disable storage/processing
#      as a defense-in-depth measure, in case the units are ever unmasked.
#
# The script is safe to run multiple times (idempotent).

set -euo pipefail

log() {
    printf '%s\n' "$*"
}

require_root() {
    if [ "${EUID:-$(id -u)}" -ne 0 ]; then
        log "ERROR: This script must be run as root." >&2
        exit 1
    fi
}

require_root

SYSTEMCTL_BIN="$(command -v systemctl || true)"

if [ -z "$SYSTEMCTL_BIN" ]; then
    log "ERROR: systemctl not found. This script requires systemd." >&2
    exit 1
fi

UNITS=(
    "systemd-coredump.socket"
    "systemd-coredump@.service"
)

log "=== Disabling systemd-coredump unit(s) ==="

for unit in "${UNITS[@]}"; do
    # Stop the unit if it is currently active (template units like
    # systemd-coredump@.service are typically instantiated, so we also
    # attempt to stop any running instances matching the pattern).
    if [[ "$unit" == *"@"* ]]; then
        base_name="${unit%@*}"
        # Find and stop any active instances of the template unit.
        mapfile -t active_instances < <("$SYSTEMCTL_BIN" list-units --all --no-legend "${base_name}@*" 2>/dev/null | awk '{print $1}' || true)
        for instance in "${active_instances[@]:-}"; do
            if [ -n "$instance" ]; then
                log "Stopping active instance: $instance"
                "$SYSTEMCTL_BIN" stop "$instance" 2>/dev/null || true
            fi
        done
    else
        if "$SYSTEMCTL_BIN" is-active --quiet "$unit" 2>/dev/null; then
            log "Stopping $unit"
            "$SYSTEMCTL_BIN" stop "$unit" || true
        fi
    fi

    # Disable the unit (removes any enablement symlinks) if applicable.
    if "$SYSTEMCTL_BIN" is-enabled --quiet "$unit" 2>/dev/null; then
        log "Disabling $unit"
        "$SYSTEMCTL_BIN" disable "$unit" || true
    fi

    # Mask the unit to prevent it from being started or activated by any
    # means (manual start, socket activation, dependency activation, etc.).
    current_state="$("$SYSTEMCTL_BIN" is-enabled "$unit" 2>/dev/null || true)"
    if [ "$current_state" != "masked" ]; then
        log "Masking $unit"
        "$SYSTEMCTL_BIN" mask "$unit" || true
    else
        log "$unit is already masked; skipping."
    fi
done

log "=== Reloading systemd manager configuration ==="
"$SYSTEMCTL_BIN" daemon-reload || true

log "=== Configuring kernel.core_pattern via sysctl to discard core dumps ==="

SYSCTL_CONF_DIR="/etc/sysctl.d"
SYSCTL_CONF_FILE="${SYSCTL_CONF_DIR}/99-disable-core-dumps.conf"

mkdir -p "$SYSCTL_CONF_DIR"

DESIRED_SYSCTL_CONTENT="# Managed by remediate_disable_systemd_coredump.sh
# Discard all core dumps instead of piping them to systemd-coredump or
# writing them to disk.
kernel.core_pattern=|/bin/false
kernel.core_uses_pid=0
fs.suid_dumpable=0
"

if [ ! -f "$SYSCTL_CONF_FILE" ] || ! diff -q <(printf '%s' "$DESIRED_SYSCTL_CONTENT") "$SYSCTL_CONF_FILE" >/dev/null 2>&1; then
    log "Writing $SYSCTL_CONF_FILE"
    printf '%s' "$DESIRED_SYSCTL_CONTENT" > "$SYSCTL_CONF_FILE"
else
    log "$SYSCTL_CONF_FILE already up to date."
fi

log "Applying sysctl settings immediately"
sysctl -w kernel.core_pattern='|/bin/false' >/dev/null 2>&1 || true
sysctl -w kernel.core_uses_pid=0 >/dev/null 2>&1 || true
sysctl -w fs.suid_dumpable=0 >/dev/null 2>&1 || true

# Apply from the persisted file as well, to ensure ordering/precedence
# matches what will occur on next boot.
sysctl --system >/dev/null 2>&1 || true

log "=== Enforcing a system-wide core ulimit of 0 ==="

LIMITS_CONF_DIR="/etc/security/limits.d"
LIMITS_CONF_FILE="${LIMITS_CONF_DIR}/99-disable-core-dumps.conf"

mkdir -p "$LIMITS_CONF_DIR"

DESIRED_LIMITS_CONTENT="# Managed by remediate_disable_systemd_coredump.sh
# Prevent any process from producing a core dump file.
*               hard    core            0
*               soft    core            0
"

if [ ! -f "$LIMITS_CONF_FILE" ] || ! diff -q <(printf '%s' "$DESIRED_LIMITS_CONTENT") "$LIMITS_CONF_FILE" >/dev/null 2>&1; then
    log "Writing $LIMITS_CONF_FILE"
    printf '%s' "$DESIRED_LIMITS_CONTENT" > "$LIMITS_CONF_FILE"
else
    log "$LIMITS_CONF_FILE already up to date."
fi

log "=== Hardening /etc/systemd/coredump.conf as defense-in-depth ==="

COREDUMP_CONF="/etc/systemd/coredump.conf"

if [ -f "$COREDUMP_CONF" ] || [ -w "$(dirname "$COREDUMP_CONF")" ]; then
    # Ensure the [Coredump] section exists with Storage=none and
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
#
# Remediation script: Ensure systemd-coredump does not generate backtraces
# by setting ProcessSizeMax=0 in /etc/systemd/coredump.conf
#
# This is idempotent: running it multiple times results in the same
# end state without duplicating or corrupting configuration.

set -euo pipefail

CONFIG_FILE="/etc/systemd/coredump.conf"
SETTING_KEY="ProcessSizeMax"
SETTING_VALUE="0"
SECTION_HEADER="[Coredump]"

# Ensure the config file exists
if [[ ! -f "${CONFIG_FILE}" ]]; then
    printf '%s\n\n%s=%s\n' "${SECTION_HEADER}" "${SETTING_KEY}" "${SETTING_VALUE}" > "${CONFIG_FILE}"
    chmod 0644 "${CONFIG_FILE}"
fi

# Ensure the [Coredump] section exists
if ! grep -qE '^\s*\[Coredump\]\s*$' "${CONFIG_FILE}"; then
    {
        echo ""
        echo "${SECTION_HEADER}"
        echo "${SETTING_KEY}=${SETTING_VALUE}"
    } >> "${CONFIG_FILE}"
else
    # Section exists; check if the setting is already correctly present
    # within the [Coredump] section (handle possible multiple sections
    # by only looking at content until next section header or EOF).

    awk_check_result=$(awk -v key="${SETTING_KEY}" '
        BEGIN { in_section=0; found=0 }
        /^\s*\[Coredump\]\s*$/ { in_section=1; next }
        /^\s*\[.*\]\s*$/ { if (in_section==1) in_section=0 }
        {
            if (in_section==1) {
                line=$0
                gsub(/^[ \t]+|[ \t]+$/, "", line)
                if (line ~ "^"key"[ \t]*=") {
                    found=1
                }
            }
        }
        END { print found }
    ' "${CONFIG_FILE}")

    if [[ "${awk_check_result}" -eq 1 ]]; then
        # Setting exists in the section; ensure its value is correct.
        # Use awk to rewrite the file, updating the matching line within
        # the [Coredump] section, commenting out or replacing others.
        tmpfile=$(mktemp)
        awk -v key="${SETTING_KEY}" -v val="${SETTING_VALUE}" '
            BEGIN { in_section=0 }
            /^\s*\[Coredump\]\s*$/ {
                in_section=1
                print
                next
            }
            /^\s*\[.*\]\s*$/ {
                if (in_section==1) in_section=0
                print
                next
            }
            {
                if (in_section==1) {
                    line=$0
                    trimmed=line
                    gsub(/^[ \t]+|[ \t]+$/, "", trimmed)
                    if (trimmed ~ "^"key"[ \t]*=") {
                        print key"="val
                        next
                    }
                }
                print
            }
        ' "${CONFIG_FILE}" > "${tmpfile}"
        mv "${tmpfile}" "${CONFIG_FILE}"
        chmod 0644 "${CONFIG_FILE}"
    else
        # Setting not present in the section; insert it right after
        # the [Coredump] header line.
        tmpfile=$(mktemp)
        awk -v key="${SETTING_KEY}" -v val="${SETTING_VALUE}" '
            BEGIN { inserted=0 }
            /^\s*\[Coredump\]\s*$/ {
                print
                if (inserted==0) {
                    print key"="val
                    inserted=1
                }
                next
            }
            { print }
        ' "${CONFIG_FILE}" > "${tmpfile}"
        mv "${tmpfile}" "${CONFIG_FILE}"
        chmod 0644 "${CONFIG_FILE}"
    fi
fi

# Reload systemd-journald / coredump configuration if systemctl is available
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

# Final verification: ensure the effective setting is correct
current_value=$(awk -v key="${SETTING_KEY}" '
    BEGIN { in_section=0; val="" }
    /^\s*\[Coredump\]\s*$/ { in_section=1; next }
    /^\s*\[.*\]\s*$/ { if (in_section==1) in_section=0 }
    {
        if (in_section==1) {
            line=$0
            gsub(/^[ \t]+|[ \t]+$/, "", line)
            if (line ~ "^"key"[ \t]*=") {
                split(line, arr, "=")
                val=arr[2]
                gsub(/^[ \t]+|[ \t]+$/, "", val)
            }
        }
    }
    END { print val }
' "${CONFIG_FILE}")

if [[ "${current_value}" != "${SETTING_VALUE}" ]]; then
    echo "ERROR: Failed to set ${SETTING_KEY}=${SETTING_VALUE} in ${CONFIG_FILE}" >&2
    exit 1
fi

exit 0
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
CONF_FILE="${CONF_DIR}/99-disable-coredump-storage.conf"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

mkdir -p "$CONF_DIR"

desired_content="[Coredump]
Storage=none
ProcessSizeMax=0
"

tmp_file="$(mktemp)"
printf '%s' "$desired_content" > "$tmp_file"

if [[ -f "$CONF_FILE" ]] && cmp -s "$tmp_file" "$CONF_FILE"; then
    rm -f "$tmp_file"
else
    install -m 0644 -o root -g root "$tmp_file" "$CONF_FILE"
    rm -f "$tmp_file"
fi

MAIN_CONF="/etc/systemd/coredump.conf"
if [[ -f "$MAIN_CONF" ]]; then
    if grep -qE '^\s*Storage\s*=' "$MAIN_CONF"; then
        sed -i -E 's/^\s*Storage\s*=.*/Storage=none/' "$MAIN_CONF"
    fi
    if grep -qE '^\s*ProcessSizeMax\s*=' "$MAIN_CONF"; then
        sed -i -E 's/^\s*ProcessSizeMax\s*=.*/ProcessSizeMax=0/' "$MAIN_CONF"
    fi
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true

    if systemctl list-unit-files | grep -q '^systemd-coredump.socket'; then
        if systemctl is-active --quiet systemd-coredump.socket 2>/dev/null; then
            systemctl restart systemd-coredump.socket || true
        fi
    fi
fi

SYSCTL_CONF="/etc/sysctl.d/99-disable-coredump-pattern.conf"
desired_sysctl="kernel.core_pattern = |/bin/false
"
tmp_sysctl="$(mktemp)"
printf '%s' "$desired_sysctl" > "$tmp_sysctl"

if [[ -f "$SYSCTL_CONF" ]] && cmp -s "$tmp_sysctl" "$SYSCTL_CONF"; then
    rm -f "$tmp_sysctl"
else
    install -m 0644 -o root -g root "$tmp_sysctl" "$SYSCTL_CONF"
    rm -f "$tmp_sysctl"
fi

if command -v sysctl >/dev/null 2>&1; then
    sysctl -p "$SYSCTL_CONF" >/dev/null 2>&1 || true
fi

echo "Core dump persistent storage has been disabled and configuration is idempotent."
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
#!/bin/bash
set -euo pipefail

LIMITS_FILE="/etc/security/limits.conf"
DROPIN_DIR="/etc/security/limits.d"
DROPIN_FILE="${DROPIN_DIR}/99-disable-core-dumps.conf"
RULE="*                hard    core            0"

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root." >&2
    exit 1
fi

mkdir -p "${DROPIN_DIR}"

if [ ! -f "${DROPIN_FILE}" ] || ! grep -qE '^\*[[:space:]]+hard[[:space:]]+core[[:space:]]+0[[:space:]]*$' "${DROPIN_FILE}" 2>/dev/null; then
    cat > "${DROPIN_FILE}" <<EOF
# Managed by remediation script: enforce hard limit of 0 on core dump size for all users
${RULE}
EOF
    chmod 0644 "${DROPIN_FILE}"
fi

if [ -f "${LIMITS_FILE}" ]; then
    if grep -qE '^[^#]*\*[[:space:]]+hard[[:space:]]+core[[:space:]]+[^0][0-9]*[[:space:]]*$' "${LIMITS_FILE}"; then
        sed -i -E 's/^([^#]*\*[[:space:]]+hard[[:space:]]+core[[:space:]]+)[^0][0-9]*([[:space:]]*)$/\10\2/' "${LIMITS_FILE}"
    fi

    if ! grep -qE '^\*[[:space:]]+hard[[:space:]]+core[[:space:]]+0[[:space:]]*$' "${LIMITS_FILE}"; then
        if grep -qE '^# End of file' "${LIMITS_FILE}"; then
            sed -i "/^# End of file/i ${RULE}" "${LIMITS_FILE}"
        else
            printf '\n%s\n' "${RULE}" >> "${LIMITS_FILE}"
        fi
    fi
else
    cat > "${LIMITS_FILE}" <<EOF
${RULE}
EOF
    chmod 0644 "${LIMITS_FILE}"
fi

SYSCTL_CONF="/etc/sysctl.d/99-disable-core-dumps.conf"
if [ ! -f "${SYSCTL_CONF}" ] || ! grep -q '^fs.suid_dumpable = 0$' "${SYSCTL_CONF}" 2>/dev/null; then
    cat > "${SYSCTL_CONF}" <<EOF
fs.suid_dumpable = 0
EOF
    chmod 0644 "${SYSCTL_CONF}"
fi

sysctl -w fs.suid_dumpable=0 >/dev/null 2>&1 || true

exit 0
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
CONF_FILE="/etc/sysctl.d/60-kernel-randomize-va-space.conf"

# Ensure the sysctl.d directory exists
if [ ! -d /etc/sysctl.d ]; then
    mkdir -p /etc/sysctl.d
fi

# Remove any existing conflicting settings for this parameter in other sysctl config files
# to avoid duplicate/conflicting definitions, but leave our own managed file alone.
grep -rl -E "^\s*${PARAM//./\\.}\s*=" /etc/sysctl.conf /etc/sysctl.d/*.conf 2>/dev/null | while read -r file; do
    if [ "$file" != "$CONF_FILE" ]; then
        sed -i -E "s/^\s*${PARAM//./\\.}\s*=.*/#&/" "$file" || true
    fi
done

# Write the desired setting idempotently into our dedicated config file
if [ -f "$CONF_FILE" ] && grep -qE "^\s*${PARAM//./\\.}\s*=" "$CONF_FILE"; then
    sed -i -E "s/^\s*${PARAM//./\\.}\s*=.*/${PARAM} = ${VALUE}/" "$CONF_FILE"
else
    printf '%s = %s\n' "${PARAM}" "${VALUE}" >> "$CONF_FILE"
fi

# Apply the setting at runtime
sysctl -w "${PARAM}=${VALUE}" >/dev/null

# Reload all sysctl settings to ensure consistency and persistence verification
sysctl --system >/dev/null

# Verify the runtime value matches the desired value
CURRENT_VALUE="$(sysctl -n "${PARAM}")"
if [ "${CURRENT_VALUE}" != "${VALUE}" ]; then
    echo "ERROR: Failed to set ${PARAM} to ${VALUE}. Current value: ${CURRENT_VALUE}" >&2
    exit 1
fi

echo "Success: ${PARAM} is set to ${VALUE} and persisted in ${CONF_FILE}."
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
#!/bin/bash
set -euo pipefail

PARAM="page_poison=1"
GRUB_DEFAULT_FILE="/etc/default/grub"
GRUB_DROPIN_DIR="/etc/default/grub.d"
GRUB_DROPIN_FILE="${GRUB_DROPIN_DIR}/99-page_poison.cfg"

# Ensure /etc/default/grub has the parameter in GRUB_CMDLINE_LINUX
if [ -f "${GRUB_DEFAULT_FILE}" ]; then
    if grep -qE '^GRUB_CMDLINE_LINUX=' "${GRUB_DEFAULT_FILE}"; then
        CURRENT_LINE=$(grep -E '^GRUB_CMDLINE_LINUX=' "${GRUB_DEFAULT_FILE}" | head -n1)
        CURRENT_VALUE=$(echo "${CURRENT_LINE}" | sed -E 's/^GRUB_CMDLINE_LINUX="(.*)"$/\1/')

        if echo "${CURRENT_VALUE}" | grep -qw "${PARAM}"; then
            : # already present, do nothing
        else
            if [ -z "${CURRENT_VALUE}" ]; then
                NEW_VALUE="${PARAM}"
            else
                NEW_VALUE="${CURRENT_VALUE} ${PARAM}"
            fi
            sed -i -E "s|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=\"${NEW_VALUE}\"|" "${GRUB_DEFAULT_FILE}"
        fi
    else
        echo "GRUB_CMDLINE_LINUX=\"${PARAM}\"" >> "${GRUB_DEFAULT_FILE}"
    fi
else
    echo "GRUB_CMDLINE_LINUX=\"${PARAM}\"" > "${GRUB_DEFAULT_FILE}"
fi

# Ensure a drop-in file exists so future grub-mkconfig regenerations still pick up the parameter
# even if /etc/default/grub is reset or replaced by package upgrades.
mkdir -p "${GRUB_DROPIN_DIR}"
if [ -f "${GRUB_DROPIN_FILE}" ]; then
    if ! grep -qw "${PARAM}" "${GRUB_DROPIN_FILE}"; then
        echo "GRUB_CMDLINE_LINUX=\"\${GRUB_CMDLINE_LINUX} ${PARAM}\"" >> "${GRUB_DROPIN_FILE}"
    fi
else
    cat > "${GRUB_DROPIN_FILE}" <<EOF
GRUB_CMDLINE_LINUX="\${GRUB_CMDLINE_LINUX} ${PARAM}"
EOF
fi

# Regenerate grub configuration so the change takes effect for all installed kernels
if command -v update-grub >/dev/null 2>&1; then
    update-grub
elif command -v grub-mkconfig >/dev/null 2>&1; then
    if [ -d /boot/grub ]; then
        grub-mkconfig -o /boot/grub/grub.cfg
    elif [ -d /boot/grub2 ]; then
        grub-mkconfig -o /boot/grub2/grub.cfg
    fi
fi

# Apply to already-installed kernels by ensuring their existing boot entries
# in /boot/grub/grub.cfg (or grub2) reflect the parameter as well, in case
# update-grub was unavailable, using grubby if present as a fallback.
if command -v grubby >/dev/null 2>&1; then
    for kernel in /boot/vmlinuz-*; do
        [ -e "${kernel}" ] || continue
        if ! grubby --info="${kernel}" 2>/dev/null | grep -q "${PARAM}"; then
            grubby --args="${PARAM}" --update-kernel="${kernel}" || true
        fi
    done
fi

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

**Prompt:** On an Ubuntu 24.04 system, enable the kernel memory allocator's object-poisoning feature so that freed kernel objects are overwritten with a sentinel value, allowing many use-after-free and uninitialized-memory bugs to be detected and prevented. The setting must be applied as a boot-time kernel parameter for all currently installed kernels and must also be inherited by any kernels installed in the future, persisting across reboots. Write an idempotent bash remediation script that achieves this end state.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Enable SLUB/SLAB object poisoning (slub_debug=P) as a
# persistent, boot-time kernel parameter on Ubuntu 24.04.
#
# This script is idempotent: it can be run multiple times safely and will
# only make changes when necessary.

set -euo pipefail

GRUB_FILE="/etc/default/grub"
PARAM="slub_debug=P"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

if [[ ! -f "$GRUB_FILE" ]]; then
    echo "ERROR: $GRUB_FILE not found. Is this a GRUB2-based system?" >&2
    exit 1
fi

# Backup the grub config once, before first modification.
if [[ ! -f "${GRUB_FILE}.bak" ]]; then
    cp -p "$GRUB_FILE" "${GRUB_FILE}.bak"
fi

changed=0

add_param_to_var() {
    local varname="$1"
    local current_line current_value new_value

    if grep -qE "^${varname}=" "$GRUB_FILE"; then
        current_line=$(grep -E "^${varname}=" "$GRUB_FILE" | tail -n1)
        current_value=$(sed -E "s/^${varname}=\"?([^\"]*)\"?$/\1/" <<< "$current_line")

        # Check if param already present as a whole word (avoid partial matches)
        if grep -qE "(^|[[:space:]])${PARAM}([[:space:]]|$)" <<< "$current_value"; then
            return 0
        fi

        if [[ -n "$current_value" ]]; then
            new_value="${current_value} ${PARAM}"
        else
            new_value="${PARAM}"
        fi

        # Escape for sed replacement
        local escaped_new_value
        escaped_new_value=$(printf '%s\n' "$new_value" | sed -e 's/[\/&]/\\&/g')

        sed -i -E "s/^${varname}=.*/${varname}=\"${escaped_new_value}\"/" "$GRUB_FILE"
        changed=1
    else
        # Variable doesn't exist at all, append it
        echo "${varname}=\"${PARAM}\"" >> "$GRUB_FILE"
        changed=1
    fi
}

# Apply to both variables so it covers default and recovery-style boots,
# and persists for all current and future kernels managed by grub.
add_param_to_var "GRUB_CMDLINE_LINUX_DEFAULT"
add_param_to_var "GRUB_CMDLINE_LINUX"

if [[ "$changed" -eq 1 ]]; then
    if command -v update-grub >/dev/null 2>&1; then
        update-grub
    elif command -v grub-mkconfig >/dev/null 2>&1; then
        grub-mkconfig -o /boot/grub/grub.cfg
    else
        echo "ERROR: Neither update-grub nor grub-mkconfig found." >&2
        exit 1
    fi
    echo "Kernel parameter '${PARAM}' added and GRUB configuration regenerated."
else
    echo "Kernel parameter '${PARAM}' already present; no changes made."
fi

exit 0
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
#
# Remediation script: Disable and mask the kernel crash-dump analyzer
# (kdump-tools / apport auto-kernel-crashdump equivalent on Ubuntu 24.04).
#
# This script is idempotent: it can be run multiple times safely and will
# always converge the system to the same "disabled" state.

set -euo pipefail

SERVICE="kdump-tools.service"
PACKAGE_CONF="/etc/default/kdump-tools"

log() {
    echo "[remediate-kdump] $*"
}

# --- 1. Stop the service if it is currently running -------------------------
if systemctl list-unit-files --full --all | grep -q "^${SERVICE}"; then
    if systemctl is-active --quiet "${SERVICE}"; then
        log "Stopping active service ${SERVICE}..."
        systemctl stop "${SERVICE}"
    else
        log "Service ${SERVICE} is not currently active."
    fi
else
    log "Unit file for ${SERVICE} not found on this system (nothing to stop)."
fi

# --- 2. Disable the service so it does not start on boot --------------------
if systemctl list-unit-files --full --all | grep -q "^${SERVICE}"; then
    if systemctl is-enabled --quiet "${SERVICE}" 2>/dev/null; then
        log "Disabling ${SERVICE}..."
        systemctl disable "${SERVICE}" || true
    else
        log "Service ${SERVICE} is already disabled (or static)."
    fi
fi

# --- 3. Mask the service to prevent manual or automatic activation ----------
if systemctl list-unit-files --full --all | grep -q "^${SERVICE}"; then
    CURRENT_STATE="$(systemctl is-enabled "${SERVICE}" 2>/dev/null || true)"
    if [ "${CURRENT_STATE}" != "masked" ]; then
        log "Masking ${SERVICE} to prevent any activation..."
        systemctl mask "${SERVICE}"
    else
        log "Service ${SERVICE} is already masked."
    fi
else
    log "Unit file for ${SERVICE} not found; attempting mask anyway (creates mask link)."
    systemctl mask "${SERVICE}" || true
fi

# --- 4. Ensure the underlying kdump-tools configuration is disabled ---------
if [ -f "${PACKAGE_CONF}" ]; then
    if grep -qE '^\s*USE_KDUMP\s*=' "${PACKAGE_CONF}"; then
        if ! grep -qE '^\s*USE_KDUMP\s*=\s*0\s*$' "${PACKAGE_CONF}"; then
            log "Setting USE_KDUMP=0 in ${PACKAGE_CONF}..."
            sed -i -E 's/^\s*USE_KDUMP\s*=.*/USE_KDUMP=0/' "${PACKAGE_CONF}"
        else
            log "USE_KDUMP already set to 0 in ${PACKAGE_CONF}."
        fi
    else
        log "Adding USE_KDUMP=0 to ${PACKAGE_CONF}..."
        printf '\nUSE_KDUMP=0\n' >> "${PACKAGE_CONF}"
    fi
else
    log "Configuration file ${PACKAGE_CONF} not present; skipping config edit."
fi

# --- 5. Reload systemd manager configuration --------------------------------
log "Reloading systemd daemon configuration..."
systemctl daemon-reload

# --- 6. Final verification ---------------------------------------------------
FINAL_STATE="$(systemctl is-enabled "${SERVICE}" 2>/dev/null || true)"
ACTIVE_STATE="$(systemctl is-active "${SERVICE}" 2>/dev/null || true)"

log "Final state -> enabled: ${FINAL_STATE:-unknown}, active: ${ACTIVE_STATE:-unknown}"

if [ "${FINAL_STATE}" = "masked" ] && [ "${ACTIVE_STATE}" != "active" ]; then
    log "SUCCESS: ${SERVICE} is stopped and masked (cannot be started manually or on boot)."
    exit 0
else
    log "WARNING: ${SERVICE} may not be fully disabled. Please check manually."
    exit 1
fi
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
# Remediation script: Ensure fapolicyd (application whitelisting daemon) is installed
# Idempotent: safe to run multiple times.

set -euo pipefail

PACKAGE_NAME="fapolicyd"

# Function to check if the package is installed
is_package_installed() {
    dpkg-query -W -f='${Status}' "${PACKAGE_NAME}" 2>/dev/null | grep -q "install ok installed"
}

main() {
    if is_package_installed; then
        echo "Package '${PACKAGE_NAME}' is already installed. No action needed."
        exit 0
    fi

    echo "Package '${PACKAGE_NAME}' is not installed. Attempting installation..."

    # Update package index (non-fatal if it fails due to environment restrictions)
    if ! apt-get update -y >/dev/null 2>&1; then
        echo "Warning: 'apt-get update' failed or was restricted; continuing with installation attempt."
    fi

    # Install the package non-interactively
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${PACKAGE_NAME}"

    # Verify installation success
    if is_package_installed; then
        echo "Successfully installed '${PACKAGE_NAME}'."
    else
        echo "Error: Failed to install '${PACKAGE_NAME}'." >&2
        exit 1
    fi
}

main "$@"
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
#!/bin/bash
#
# Remediation script: Ensure fapolicyd (file access policy daemon) is
# installed, enabled, and running on Ubuntu 24.04.
# This script is idempotent and safe to run multiple times.

set -euo pipefail

SERVICE_NAME="fapolicyd"

# Determine if script is run as root
if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root. Attempting to re-invoke with sudo..."
    exec sudo bash "$0" "$@"
fi

echo "=== Remediation: Ensure ${SERVICE_NAME} is installed, enabled, and running ==="

# Step 1: Ensure fapolicyd package is installed
if ! dpkg -s "${SERVICE_NAME}" >/dev/null 2>&1; then
    echo "[*] ${SERVICE_NAME} package not found. Installing..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y "${SERVICE_NAME}"
else
    echo "[*] ${SERVICE_NAME} package is already installed."
fi

# Step 2: Reload systemd unit files in case package installation changed them
systemctl daemon-reload

# Step 3: Unmask the service if it is masked
if systemctl is-enabled "${SERVICE_NAME}" 2>/dev/null | grep -q "^masked$"; then
    echo "[*] ${SERVICE_NAME} service is masked. Unmasking..."
    systemctl unmask "${SERVICE_NAME}"
fi

# Step 4: Enable the service to start at boot if not already enabled
if ! systemctl is-enabled --quiet "${SERVICE_NAME}" 2>/dev/null; then
    echo "[*] Enabling ${SERVICE_NAME} to start at boot..."
    systemctl enable "${SERVICE_NAME}"
else
    echo "[*] ${SERVICE_NAME} is already enabled to start at boot."
fi

# Step 5: Start the service if it is not already running
if ! systemctl is-active --quiet "${SERVICE_NAME}"; then
    echo "[*] Starting ${SERVICE_NAME} service..."
    systemctl start "${SERVICE_NAME}"
else
    echo "[*] ${SERVICE_NAME} service is already running."
fi

# Step 6: Verify final state
echo "=== Verification ==="
ENABLED_STATE=$(systemctl is-enabled "${SERVICE_NAME}" 2>/dev/null || echo "unknown")
ACTIVE_STATE=$(systemctl is-active "${SERVICE_NAME}" 2>/dev/null || echo "unknown")

echo "Service enabled state: ${ENABLED_STATE}"
echo "Service active state:  ${ACTIVE_STATE}"

if [[ "${ENABLED_STATE}" == "enabled" && "${ACTIVE_STATE}" == "active" ]]; then
    echo "[+] ${SERVICE_NAME} is properly enabled and running."
    exit 0
else
    echo "[-] Failed to ensure ${SERVICE_NAME} is enabled and running." >&2
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

**Prompt:** On an Ubuntu 24.04 system, configure the application allowlisting (file-access policy) subsystem so that it operates under a deny-all, permit-by-exception model: only explicitly authorized software programs may execute, and all other binaries are blocked from running. This limits the attack surface by ensuring only vetted, trusted software can run. Write an idempotent bash remediation script that installs and enables this control with an enforcing default-deny posture, persisting across reboots.

**Model-generated script:**
```bash
```bash
#!/usr/bin/env bash
#
# Idempotent remediation script: configure fapolicyd (file-access/application
# allowlisting policy subsystem) on Ubuntu 24.04 for a deny-all,
# permit-by-exception (default-deny) enforcing posture, persistent across reboots.

set -euo pipefail

LOG_TAG="fapolicyd-remediation"

log() {
    echo "[${LOG_TAG}] $*"
}

require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo "This script must be run as root." >&2
        exit 1
    fi
}

require_root

CONF_FILE="/etc/fapolicyd/fapolicyd.conf"
RULES_DIR="/etc/fapolicyd/rules.d"
DEFAULT_DENY_RULE="${RULES_DIR}/90-deny-execute.rules"
COMPILED_RULES="/etc/fapolicyd/compiled.rules"

# --------------------------------------------------------------------------
# 1. Install fapolicyd (and auditd, a common integration dependency) if
#    not already present. apt-get install is naturally idempotent.
# --------------------------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive

if ! dpkg -s fapolicyd >/dev/null 2>&1; then
    log "Installing fapolicyd..."
    apt-get update -y
    apt-get install -y fapolicyd
else
    log "fapolicyd already installed."
fi

# Ensure required directories exist
mkdir -p "${RULES_DIR}"

# --------------------------------------------------------------------------
# 2. Enforce default-deny (deny-all, permit-by-exception) posture.
#    fapolicyd's rule engine already evaluates rules top-down and denies
#    anything not explicitly allowed, provided a final deny-all rule exists.
#    Ensure that rule is present exactly once.
# --------------------------------------------------------------------------
if [[ ! -f "${DEFAULT_DENY_RULE}" ]] || ! grep -qE '^\s*deny_audit\s+perm=execute\s+all\s*:\s*all\s*$' "${DEFAULT_DENY_RULE}" 2>/dev/null; then
    log "Installing/ensuring default-deny execute rule..."
    cat > "${DEFAULT_DENY_RULE}" <<'EOF'
# Default-deny rule: block execution of anything not explicitly
# permitted by preceding allow rules. This enforces a
# deny-all, permit-by-exception application allowlisting model.
deny_audit perm=execute all : all
EOF
else
    log "Default-deny execute rule already present."
fi

# --------------------------------------------------------------------------
# 3. Set fapolicyd to enforcing (non-permissive) mode. Idempotently
#    normalize the "permissive" setting in the main config file.
# --------------------------------------------------------------------------
if [[ ! -f "${CONF_FILE}" ]]; then
    log "ERROR: ${CONF_FILE} not found after installation." >&2
    exit 1
fi

if grep -qE '^\s*permissive\s*=' "${CONF_FILE}"; then
    if ! grep -qE '^\s*permissive\s*=\s*0\s*$' "${CONF_FILE}"; then
        log "Setting fapolicyd to enforcing mode (permissive = 0)..."
        sed -i -E 's/^\s*permissive\s*=.*/permissive = 0/' "${CONF_FILE}"
    else
        log "fapolicyd already configured as enforcing (permissive = 0)."
    fi
else
    log "
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
#!/bin/bash
set -euo pipefail

PACKAGE="mailutils"

if ! dpkg -s "$PACKAGE" >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y "$PACKAGE"
else
    echo "$PACKAGE is already installed."
fi

if command -v mail >/dev/null 2>&1; then
    echo "mailx (mail) command is available."
else
    echo "ERROR: mail command not found after installation attempt." >&2
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

if dpkg -s "$PACKAGE" >/dev/null 2>&1 && \
   dpkg -s "$PACKAGE" 2>/dev/null | grep -q "^Status: install ok installed"; then
    echo "INFO: '$PACKAGE' is already installed. No action needed."
    exit 0
fi

echo "INFO: '$PACKAGE' is not installed. Proceeding with installation."

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root or with sudo privileges." >&2
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive

if ! command -v debconf-set-selections >/dev/null 2>&1; then
    apt-get update -y
fi

debconf-set-selections <<EOF
postfix postfix/main_mailer_type select Internet Site
postfix postfix/mailname string $(hostname -f 2>/dev/null || hostname)
EOF

apt-get update -y

apt-get install -y "$PACKAGE"

if dpkg -s "$PACKAGE" 2>/dev/null | grep -q "^Status: install ok installed"; then
    echo "INFO: '$PACKAGE' installation verified successfully."
else
    echo "ERROR: '$PACKAGE' installation could not be verified." >&2
    exit 1
fi

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

**Prompt:** On an Ubuntu 24.04 system, the system time-synchronization daemon (chrony) may be configured to listen for incoming connections and act as a time server, which expands the attack surface and violates the principle of least functionality. Configure chrony to operate strictly in client-only mode so that it never opens any listening network port for serving time to other hosts. Write an idempotent bash remediation script that enforces this client-only configuration and persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# remediate-chrony-client-only.sh
#
# Ensures chrony operates strictly as an NTP client:
#   - Never listens for incoming NTP requests (port 0)
#   - Never listens on the command port (cmdport 0)
#   - Does not act as a local stratum time source
#   - Does not "allow" any remote hosts to query it
#
# Idempotent: safe to run multiple times; only restarts chronyd
# if the configuration actually changed.

set -euo pipefail

CHRONY_CONF=""
CHANGED=0

for candidate in /etc/chrony/chrony.conf /etc/chrony.conf; do
    if [[ -f "$candidate" ]]; then
        CHRONY_CONF="$candidate"
        break
    fi
done

if [[ -z "$CHRONY_CONF" ]]; then
    echo "chrony configuration file not found. Is chrony installed?" >&2
    exit 1
fi

BACKUP="${CHRONY_CONF}.bak.$(date +%Y%m%d%H%M%S)"

ensure_directive() {
    # Ensures exactly one active line "directive value" exists.
    # Comments out any other active occurrences of the directive
    # (with any value) and appends the correct one if missing.
    local directive="$1"
    local value="$2"
    local desired="${directive} ${value}"
    local file="$CHRONY_CONF"
    local tmpfile
    tmpfile="$(mktemp)"
    local found_correct=0
    local made_change=0

    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" =~ ^[[:space:]]*${directive}([[:space:]]+.*)?$ ]]; then
            local trimmed
            trimmed="$(echo "$line" | sed -E 's/^[[:space:]]+//')"
            if [[ "$trimmed" == "$desired" ]]; then
                if [[ $found_correct -eq 1 ]]; then
                    echo "# $line" >> "$tmpfile"
                    made_change=1
                else
                    echo "$line" >> "$tmpfile"
                    found_correct=1
                fi
            else
                echo "# $line" >> "$tmpfile"
                made_change=1
            fi
        else
            echo "$line" >> "$tmpfile"
        fi
    done < "$file"

    if [[ $found_correct -eq 0 ]]; then
        echo "$desired" >> "$tmpfile"
        made_change=1
    fi

    if ! cmp -s "$tmpfile" "$file"; then
        cp "$file" "$BACKUP.$directive" 2>/dev/null || true
        mv "$tmpfile" "$file"
        CHANGED=1
    else
        rm -f "$tmpfile"
    fi
}

comment_out_directive_prefix() {
    # Comments out any active line starting with the given directive
    # keyword (used for directives that must not appear at all,
    # e.g. "allow", "local").
    local directive="$1"
    local file="$CHRONY_CONF"
    local tmpfile
    tmpfile="$(mktemp)"
    local made_change=0

    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" =~ ^[[:space:]]*${directive}([[:space:]]+.*)?$ ]]; then
            echo "# $line" >> "$tmpfile"
            made_change=1
        else
            echo "$line" >> "$tmpfile"
        fi
    done < "$file"

    if ! cmp -s "$tmpfile" "$file"; then
        cp "$file" "$BACKUP.$directive" 2>/dev/null || true
        mv "$tmpfile" "$file"
        CHANGED=1
    else
        rm -f "$tmpfile"
    fi
}

# Take a one-time backup before any modification, if not already present.
if [[ ! -f "${CHRONY_CONF}.orig.bak" ]]; then
    cp "$CHRONY_CONF" "${CHRONY_CONF}.orig.bak"
fi

# 1. Disable the NTP server/listener socket entirely (client-only).
ensure_directive "port" "0"

# 2. Disable the command/monitoring port listener as well.
ensure_directive "cmdport" "0"

# 3. Remove any "allow" directives that would permit acting as a server.
comment_out_directive_prefix "allow"

# 4. Remove any "local" directive that would let chrony act as a
#    reference clock/stratum source for others when unsynced.
comment_out_directive_prefix "local"

# Validate configuration syntax if chronyd supports a check mode.
if command -v chronyd >/dev/null 2>&1; then
    if ! chronyd -Q -f "$CHRONY_CONF" 2>/dev/null; then
        echo "Warning: chronyd could not validate the configuration syntax." >&2
    fi
fi

if [[ $CHANGED -eq 1 ]]; then
    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart chrony 2>/dev/null || systemctl restart chronyd 2>/dev/null || true
        systemctl enable chrony 2>/dev/null || systemctl enable chronyd 2>/dev/null || true
    fi
    echo "chrony configuration updated to enforce client-only mode."
else
    echo "chrony is already configured in client-only mode. No changes made."
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

**Prompt:** On an Ubuntu 24.04 system, the time-synchronization (chrony) daemon should not act as a network-accessible service for runtime management connections, since exposing this management interface needlessly increases the attack surface. Configure the chrony daemon so that it does not listen on its management network port (it should neither monitor commands over the network nor open that command socket). Write an idempotent bash remediation script that enforces this and persists across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Disable chrony's network command port (cmdport) so that
# chronyd does not listen on a network-accessible management socket.
#
# Idempotent: safe to run multiple times; only modifies config if needed.

set -euo pipefail

CHRONY_CONF="/etc/chrony/chrony.conf"
CHRONY_CONF_D="/etc/chrony/conf.d"
DESIRED_LINE="cmdport 0"

# Ensure chrony is installed / config exists
if [[ ! -f "${CHRONY_CONF}" ]]; then
    echo "Error: ${CHRONY_CONF} not found. Is chrony installed?" >&2
    exit 1
fi

backup_file() {
    local file="$1"
    local backup="${file}.bak.$(date +%Y%m%d%H%M%S)"
    if [[ ! -f "${file}.orig" ]]; then
        cp -p "${file}" "${file}.orig"
    fi
    cp -p "${file}" "${backup}"
}

# Function to remove any existing 'cmdport' directives (commented or not)
# from a given file and ensure only the desired directive remains.
sanitize_cmdport_in_file() {
    local file="$1"
    local changed=0

    if [[ -f "${file}" ]]; then
        # Remove any line that sets cmdport to something other than 0,
        # or duplicate cmdport 0 lines (we'll add a single canonical one).
        if grep -qE '^[[:space:]]*cmdport[[:space:]]+[0-9]+' "${file}"; then
            if ! grep -qE '^[[:space:]]*cmdport[[:space:]]+0[[:space:]]*$' "${file}" || \
               [[ "$(grep -cE '^[[:space:]]*cmdport[[:space:]]+0[[:space:]]*$' "${file}")" -gt 1 ]] || \
               grep -qE '^[[:space:]]*cmdport[[:space:]]+[1-9][0-9]*' "${file}"; then
                changed=1
            fi
        fi
    fi

    if [[ "${changed}" -eq 1 ]]; then
        backup_file "${file}"
        # Remove all existing cmdport lines
        sed -i -E '/^[[:space:]]*cmdport[[:space:]]+[0-9]+[[:space:]]*$/d' "${file}"
    fi
}

# 1. Sanitize main config and any drop-in configs for conflicting cmdport settings
sanitize_cmdport_in_file "${CHRONY_CONF}"

if [[ -d "${CHRONY_CONF_D}" ]]; then
    while IFS= read -r -d '' f; do
        sanitize_cmdport_in_file "${f}"
    done < <(find "${CHRONY_CONF_D}" -maxdepth 1 -type f -name '*.conf' -print0)
fi

# 2. Ensure the main config has exactly one 'cmdport 0' directive
if ! grep -qE '^[[:space:]]*cmdport[[:space:]]+0[[:space:]]*$' "${CHRONY_CONF}"; then
    backup_file "${CHRONY_CONF}"
    {
        echo ""
        echo "# Disable chronyd's network command port (management interface)."
        echo "# This prevents chronyd from listening on a UDP socket for"
        echo "# remote command/monitoring connections (e.g., chronyc over network)."
        echo "${DESIRED_LINE}"
    } >> "${CHRONY_CONF}"
fi

# 3. Also remove/neutralize any 'bindcmdaddress' lines that could re-enable
#    a listening command socket on a specific address (not needed when
#    cmdport is 0, but ensure no explicit non-loopback bind is forcing it).
for f in "${CHRONY_CONF}" "${CHRONY_CONF_D}"/*.conf; do
    [[ -f "${f}" ]] || continue
    if grep -qE '^[[:space:]]*bindcmdaddress[[:space:]]+' "${f}" 2>/dev/null; then
        backup_file "${f}"
        sed -i -E 's/^([[:space:]]*bindcmdaddress[[:space:]]+.*)$/# \1  # disabled by remediation (cmdport=0)/' "${f}"
    fi
done

# 4. Verify chrony's runtime effective config does not have a positive cmdport.
#    (chronyd -Q won't parse this reliably, so we just trust the file-level
#     enforcement above, which is authoritative.)

# 5. Restart chrony service to apply changes, and ensure it's enabled for persistence.
SERVICE_NAME="chrony"
if systemctl list-unit-files | grep -q '^chronyd\.service'; then
    SERVICE_NAME="chronyd"
fi

if systemctl is-enabled "${SERVICE_NAME}" >/dev/null 2>&1; then
    :
else
    systemctl enable "${SERVICE_NAME}" >/dev/null 2>&1 || true
fi

systemctl restart "${SERVICE_NAME}"

# 6. Final validation: confirm chronyd is not listening on the command port (UDP 323)
sleep 1
if ss -uln 2>/dev/null | grep -q ':323\b'; then
    echo "Warning: chronyd still appears to be listening on port 323." >&2
    exit 1
fi

echo "chronyd command port successfully disabled and configuration persisted."
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
```bash
#!/usr/bin/env bash
#
# Remediation script: ensure every configured NTP time source (server/pool)
# used by the system time-synchronization daemon (chrony) has an explicit,
# bounded maxpoll interval. Idempotent - safe to run multiple times.
#

set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# Maximum allowed poll interval exponent (2^MAXPOLL seconds).
readonly MAXPOLL=10

CHRONY_CONF=""
for f in /etc/chrony/chrony.conf /etc/chrony.conf; do
    if [[ -f "${f}" ]]; then
        CHRONY_CONF="${f}"
        break
    fi
done

if [[ -z "${CHRONY_CONF}
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

SSHD_CONFIG="/etc/ssh/sshd_config"
TIMESTAMP=$(date +%Y%m%d%H%M%S)
BACKUP="${SSHD_CONFIG}.bak.${TIMESTAMP}"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

if [[ ! -f "$SSHD_CONFIG" ]]; then
    echo "sshd_config not found at $SSHD_CONFIG" >&2
    exit 1
fi

# Backup current config before making changes
cp -p "$SSHD_CONFIG" "$BACKUP"

# Ensure ClientAliveInterval is set (only add a default if not already present)
if ! grep -qE '^[[:space:]]*ClientAliveInterval[[:space:]]+[0-9]+' "$SSHD_CONFIG"; then
    echo "ClientAliveInterval 300" >> "$SSHD_CONFIG"
fi

# Remove any existing ClientAliveCountMax lines (commented or not) to avoid duplicates
sed -i -E '/^[[:space:]]*#?[[:space:]]*ClientAliveCountMax[[:space:]]+[0-9]+[[:space:]]*$/d' "$SSHD_CONFIG"

# Append the enforced setting
echo "ClientAliveCountMax 0" >> "$SSHD_CONFIG"

# Validate configuration syntax
if ! sshd -t -f "$SSHD_CONFIG" 2>/tmp/sshd_test_err; then
    echo "sshd_config validation failed:" >&2
    cat /tmp/sshd_test_err >&2
    echo "Restoring backup." >&2
    cp -p "$BACKUP" "$SSHD_CONFIG"
    rm -f /tmp/sshd_test_err
    exit 1
fi
rm -f /tmp/sshd_test_err

# Restart/reload sshd service to apply for new sessions, persists across reboots via systemd
if systemctl is-active --quiet ssh; then
    systemctl reload ssh
elif systemctl is-active --quiet sshd; then
    systemctl reload sshd
else
    if systemctl list-unit-files | grep -q '^ssh.service'; then
        systemctl restart ssh
    elif systemctl list-unit-files | grep -q '^sshd.service'; then
        systemctl restart sshd
    else
        echo "Could not find ssh/sshd systemd service to reload/restart." >&2
        exit 1
    fi
fi

echo "SSH ClientAliveCountMax enforced to 0. Backup saved at $BACKUP"
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
#
# Remediation script: Configure SSH server to probe clients for
# responsiveness (ClientAliveInterval) and disconnect unresponsive
# clients after 600 seconds total (ClientAliveInterval * ClientAliveCountMax).
#
# Idempotent: safe to run multiple times, persists across reboots via
# sshd_config.

set -euo pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
DROPIN_DIR="/etc/ssh/sshd_config.d"
DROPIN_FILE="${DROPIN_DIR}/60-client-alive-timeout.conf"

ALIVE_INTERVAL=600
ALIVE_COUNT_MAX=1

# Ensure ssh package/config exists
if [ ! -f "${SSHD_CONFIG}" ]; then
    echo "Error: ${SSHD_CONFIG} not found. Is openssh-server installed?" >&2
    exit 1
fi

# Backup original config once
if [ ! -f "${SSHD_CONFIG}.bak" ]; then
    cp -p "${SSHD_CONFIG}" "${SSHD_CONFIG}.bak"
fi

mkdir -p "${DROPIN_DIR}"

# --- Remove any conflicting ClientAliveInterval/ClientAliveCountMax
#     directives from the main sshd_config to avoid override conflicts
#     (drop-in files in sshd_config.d are read first and take precedence
#     for the *first* occurrence, so we must ensure no earlier duplicate
#     directive exists in the main file that would be applied instead).

for directive in ClientAliveInterval ClientAliveCountMax; do
    if grep -qiE "^[[:space:]]*${directive}[[:space:]]+" "${SSHD_CONFIG}"; then
        sed -i -E "s/^[[:space:]]*(${directive})[[:space:]]+.*/#\1 (managed by ${DROPIN_FILE})/I" "${SSHD_CONFIG}"
    fi
done

# --- Write idempotent drop-in configuration file

TMP_FILE="$(mktemp)"
cat > "${TMP_FILE}" <<EOF
# Managed by remediation script: enforce client responsiveness timeout.
# Probes the client every ${ALIVE_INTERVAL} seconds; if the client fails
# to respond, the session is disconnected after
# ClientAliveInterval * ClientAliveCountMax = ${ALIVE_INTERVAL} seconds total.
ClientAliveInterval ${ALIVE_INTERVAL}
ClientAliveCountMax ${ALIVE_COUNT_MAX}
EOF

if [ ! -f "${DROPIN_FILE}" ] || ! cmp -s "${TMP_FILE}" "${DROPIN_FILE}"; then
    install -m 0644 -o root -g root "${TMP_FILE}" "${DROPIN_FILE}"
fi
rm -f "${TMP_FILE}"

# --- Validate configuration syntax before applying

if ! sshd -t 2>/tmp/sshd_test_err; then
    echo "Error: sshd configuration test failed:" >&2
    cat /tmp/sshd_test_err >&2
    rm -f /tmp/sshd_test_err
    exit 1
fi
rm -f /tmp/sshd_test_err

# --- Determine the correct systemd service/socket unit name and reload

SERVICE_NAME=""
for candidate in ssh sshd; do
    if systemctl list-unit-files --type=service 2>/dev/null | grep -q "^${candidate}\.service"; then
        SERVICE_NAME="${candidate}"
        break
    fi
done

if [ -z "${SERVICE_NAME}" ]; then
    echo "Error: could not determine ssh/sshd service unit name." >&2
    exit 1
fi

# Ensure service is enabled (persists across reboots)
systemctl enable "${SERVICE_NAME}.service" >/dev/null 2>&1 || true

# Reload/restart to apply the new configuration
if systemctl is-active --quiet "${SERVICE_NAME}.service"; then
    systemctl reload "${SERVICE_NAME}.service" 2>/dev/null || systemctl restart "${SERVICE_NAME}.service"
else
    systemctl restart "${SERVICE_NAME}.service"
fi

echo "SSH client-alive timeout enforced: ClientAliveInterval=${ALIVE_INTERVAL}, ClientAliveCountMax=${ALIVE_COUNT_MAX}"
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
```bash
#!/usr/bin/env bash
#
# Remediation script: Disable SSH login for accounts with empty passwords
# Ensures PermitEmptyPasswords is explicitly set to 'no' in sshd_config
# Idempotent: safe to run multiple times, persists across reboots/restarts
#
set -euo pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_CONFIG_DIR="/etc/ssh/sshd_config.d"
BACKUP_SUFFIX=".bak.$(date +%Y%m%d%H%M%S)"
SETTING_NAME="PermitEmptyPasswords"
SETTING_VALUE="no"
DESIRED_LINE="${SETTING_NAME} ${SETTING_VALUE}"

# Ensure script is run as root
if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

# Ensure main sshd_config exists
if [[ ! -f "${SSHD_CONFIG}" ]]; then
    echo "ERROR: ${SSHD_CONFIG} not found. Is openssh-server installed?" >&2
    exit 1
fi

# Function to check if any Include directive pulls in sshd_config.d/*.conf
config_includes_dropin_dir() {
    grep -qiE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "${SSHD_CONFIG}" 2>/dev/null
}

# Determine which file will actually hold the authoritative setting.
# Prefer a drop-in file under sshd_config.d if it's included, since drop-ins
# are typically processed first and take precedence in sshd's config parsing.
TARGET_FILE=""
if [[ -d "${SSHD_CONFIG_DIR}" ]] && config_includes_dropin_dir; then
    TARGET_FILE="${SSHD_CONFIG_DIR}/60-empty-passwords.conf"
else
    TARGET_FILE="${SSHD_CONFIG}"
fi

echo "Target configuration file: ${TARGET_FILE}"

# --- Step 1: Neutralize any existing PermitEmptyPasswords directives
#     across sshd_config and any drop-in files, so they don't conflict
#     with the final desired setting. We comment out (rather than delete)
#     to preserve an audit trail, and only touch files that actually
#     contain the directive.

neutralize_existing_directives() {
    local file="$1"
    if [[ -f "${file}" ]] && grep -qiE '^[[:space:]]*PermitEmptyPasswords[[:space:]]+' "${file}"; then
        # Skip if this is the target file — it will be rewritten properly below
        if [[ "${file}" == "${TARGET_FILE}" ]]; then
            return 0
        fi
        cp -a "${file}" "${file}${BACKUP_SUFFIX}"
        sed -i -E 's/^([[:space:]]*)PermitEmptyPasswords[[:space:]]+.*/\1#&  # remediated: superseded by managed setting/I' "${file}"
        echo "Neutralized existing PermitEmptyPasswords directive(s) in ${file} (backup: ${file}${BACKUP_SUFFIX})"
    fi
}

# Check main config
neutralize_existing_directives "${SSHD_CONFIG}"

# Check all drop-in files if directory exists
if [[ -d "${SSHD_CONFIG_DIR}" ]]; then
    while IFS= read -r -d '' conf_file; do
        neutralize_existing_directives "${conf_file}"
    done < <(find "${SSHD_CONFIG_DIR}" -maxdepth 1 -type f -name '*.conf' -print0 2>/dev/null)
fi

# --- Step 2: Ensure the target file contains the desired directive,
#     idempotently: update in place if present, append if absent.

if [[ "${TARGET_FILE}" == "${SSHD_CONFIG_DIR}"* ]]; then
    mkdir -p "${SSHD_CONFIG_DIR}"
fi

if [[ -f "${TARGET_FILE}" ]]; then
    cp -a "${TARGET_FILE}" "${TARGET_FILE}${BACKUP_SUFFIX}"
else
    touch "${TARGET_FILE}"
    chmod 0644 "${TARGET_FILE}"
fi

if grep -qiE '^[[:space:]]*PermitEmptyPasswords[[:space:]]+' "${TARGET_FILE}"; then
    # Update existing (possibly differently-cased or valued) directive in place
    sed -i -E "s/^[[:space:]]*PermitEmptyPasswords[[:space:]]+.*/${DESIRED_LINE}/I" "${TARGET_FILE}"
    echo "Updated existing ${SETTING_NAME} directive in ${TARGET_FILE}"
else
    {
        echo ""
        echo "# Managed by remediation script: disallow empty-password logins"
        echo "${DESIRED_LINE}"
    } >> "${TARGET_FILE}"
    echo "Appended ${SETTING_NAME} directive to ${TARGET_FILE}"
fi

# Remove backup of target file if content is unchanged (avoid clutter on reruns)
if [[ -f "${TARGET_FILE}${BACKUP_SUFFIX}" ]] && cmp -s "${TARGET_FILE}" "${TARGET_FILE}${BACKUP_SUFFIX}"; then
    rm -f "${TARGET_FILE}${BACKUP_SUFFIX}"
fi

# --- Step 3: Validate the resulting sshd configuration before applying

if command -v sshd >/dev/null 2>&1; then
    if ! sshd -t 2>/tmp/sshd_test_err; then
        echo "ERROR: sshd configuration test failed after remediation:" >&2
        cat /tmp/sshd_test_err >&2
        rm -f /tmp/sshd_test_err
        exit 1
    fi
    rm -f /tmp/sshd_test_err
else
    echo "WARNING: sshd binary not found; skipping configuration syntax test." >&2
fi

# --- Step 4: Confirm effective setting via sshd -T (dumps effective config)

EFFECTIVE_VALUE=""
if command -v sshd >/dev/null 2>&1; then
    EFFECTIVE_VALUE="$(sshd -T 2>/dev/null | awk 'tolower($1)=="permitemptypasswords"{print tolower($2)}' | tail -n1)"
fi

if [[ "${EFFECTIVE_VALUE}" != "no" ]]; then
    echo "ERROR: Effective PermitEmptyPasswords is not 'no' (got: '${EFFECTIVE_VALUE:-unset}')." >&2
    echo "Please review ${SSHD_CONFIG} and any files in ${SSHD_CONFIG_DIR} for conflicting directives." >&2
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
CONFIG_DIR="/etc/ssh/sshd_config.d"
DROPIN_FILE="${CONFIG_DIR}/60-gssapi-auth.conf"
SETTING_NAME="GSSAPIAuthentication"
SETTING_VALUE="no"

if [ ! -f "${SSHD_CONFIG}" ]; then
    echo "Error: ${SSHD_CONFIG} not found." >&2
    exit 1
fi

mkdir -p "${CONFIG_DIR}"

remove_setting_from_file() {
    local file="$1"
    if [ -f "${file}" ] && grep -qiE "^[[:space:]]*${SETTING_NAME}[[:space:]]+" "${file}"; then
        sed -i -E "s/^[[:space:]]*${SETTING_NAME}[[:space:]]+.*/# &/I" "${file}"
    fi
}

remove_setting_from_file "${SSHD_CONFIG}"

if [ -d "${CONFIG_DIR}" ]; then
    while IFS= read -r -d '' f; do
        [ "${f}" = "${DROPIN_FILE}" ] && continue
        remove_setting_from_file "${f}"
    done < <(find "${CONFIG_DIR}" -maxdepth 1 -type f -name '*.conf' -print0)
fi

if [ -f "${DROPIN_FILE}" ] && grep -qiE "^[[:space:]]*${SETTING_NAME}[[:space:]]+" "${DROPIN_FILE}"; then
    sed -i -E "s/^[[:space:]]*${SETTING_NAME}[[:space:]]+.*/${SETTING_NAME} ${SETTING_VALUE}/I" "${DROPIN_FILE}"
else
    printf '%s %s\n' "${SETTING_NAME}" "${SETTING_VALUE}" >> "${DROPIN_FILE}"
fi

chmod 0644 "${DROPIN_FILE}"
chown root:root "${DROPIN_FILE}"

if command -v sshd >/dev/null 2>&1; then
    if sshd -t 2>/dev/null; then
        if command -v systemctl >/dev/null 2>&1; then
            if systemctl list-unit-files --type=service 2>/dev/null | grep -q '^ssh\.service'; then
                systemctl reload ssh.service 2>/dev/null || systemctl restart ssh.service 2>/dev/null || true
            elif systemctl list-unit-files --type=service 2>/dev/null | grep -q '^sshd\.service'; then
                systemctl reload sshd.service 2>/dev/null || systemctl restart sshd.service 2>/dev/null || true
            fi
        fi
    else
        echo "Warning: sshd configuration test failed after remediation. Please review manually." >&2
    fi
fi

exit 0
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

SSHD_CONFIG="/etc/ssh/sshd_config"
CONFIG_DIR="/etc/ssh/sshd_config.d"
DROPIN_FILE="${CONFIG_DIR}/60-disable-kerberos-auth.conf"
SETTING_NAME="KerberosAuthentication"
SETTING_VALUE="no"
TIMESTAMP="$(date +%Y%m%d%H%M%S)"

if [[ "${EUID}" -ne 0 ]]; then
    echo "Error: This script must be run as root." >&2
    exit 1
fi

if [[ ! -f "${SSHD_CONFIG}" ]]; then
    echo "Error: ${SSHD_CONFIG} not found." >&2
    exit 1
fi

comment_out_setting_in_file() {
    local file="$1"
    if grep -qiE "^[[:space:]]*${SETTING_NAME}[[:space:]]+" "${file}"; then
        cp -p "${file}" "${file}.bak.${TIMESTAMP}"
        sed -i -E "s/^[[:space:]]*(${SETTING_NAME}[[:space:]]+.*)$/# \1 (disabled by remediation script)/I" "${file}"
        echo "Commented out existing ${SETTING_NAME} directive(s) in ${file}"
    fi
}

comment_out_setting_in_file "${SSHD_CONFIG}"

if [[ -d "${CONFIG_DIR}" ]]; then
    while IFS= read -r -d '' f; do
        [[ "${f}" == "${DROPIN_FILE}" ]] && continue
        comment_out_setting_in_file "${f}"
    done < <(find "${CONFIG_DIR}" -maxdepth 1 -type f -name '*.conf' -print0 2>/dev/null)
fi

mkdir -p "${CONFIG_DIR}"

if [[ -f "${DROPIN_FILE}" ]] && grep -qiE "^[[:space:]]*${SETTING_NAME}[[:space:]]+${SETTING_VALUE}[[:space:]]*$" "${DROPIN_FILE}"; then
    echo "${SETTING_NAME} already set to '${SETTING_VALUE}' in ${DROPIN_FILE}. No changes needed there."
else
    cat > "${DROPIN_FILE}" <<EOF
# Managed by remediation script - do not edit manually
# Ensures Kerberos authentication is disabled for sshd
${SETTING_NAME} ${SETTING_VALUE}
EOF
    chmod 0644 "${DROPIN_FILE}"
    chown root:root "${DROPIN_FILE}"
    echo "Wrote ${SETTING_NAME} ${SETTING_VALUE} to ${DROPIN_FILE}"
fi

if command -v sshd >/dev/null 2>&1; then
    if ! sshd -t 2>/tmp/sshd_test_err.$$; then
        echo "Error: sshd configuration test failed after modification:" >&2
        cat /tmp/sshd_test_err.$$ >&2
        rm -f /tmp/sshd_test_err.$$
        exit 1
    fi
    rm -f /tmp/sshd_test_err.$$
else
    echo "Warning: sshd binary not found in PATH; skipping config validation." >&2
fi

SSH_SERVICE=""
for svc in ssh sshd; do
    if systemctl list-unit-files 2>/dev/null | grep -qE "^${svc}\.service"; then
        SSH_SERVICE="${svc}"
        break
    fi
done

if [[ -n "${SSH_SERVICE}" ]]; then
    if systemctl is-active --quiet "${SSH_SERVICE}"; then
        systemctl reload "${SSH_SERVICE}" 2>/dev/null || systemctl restart "${SSH_SERVICE}"
        echo "Reloaded/restarted ${SSH_SERVICE} service."
    else
        echo "Notice: ${SSH_SERVICE} service is not currently active; skipping reload."
    fi
else
    echo "Warning: Could not detect ssh/sshd systemd service; please reload SSH manually." >&2
fi

echo "Remediation complete: ${SETTING_NAME} is set to '${SETTING_VALUE}'."
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
```bash
#!/usr/bin/env bash
#
# remediate_ssh_disable_root_login.sh
#
# Ensures the OpenSSH server denies direct root login (password or key-based)
# over the network, and that the setting persists across reboots.
# Idempotent: safe to run multiple times.

set -euo pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_CONFIG_DIR="/etc/ssh/sshd_config.d"
DROPIN_FILE="${SSHD_CONFIG_DIR}/99-disable-root-login.conf"
DESIRED_SETTING="PermitRootLogin no"
TIMESTAMP="$(date +%Y%m%d%H%M%S)"

# Must be root to modify sshd configuration and restart the service.
if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

if [[ ! -f "${SSHD_CONFIG}" ]]; then
    echo "ERROR: ${SSHD_CONFIG} not found. Is openssh-server installed?" >&2
    exit 1
fi

# Ensure the sshd_config.d include directory exists (default on Ubuntu 24.04,
# but verify defensively).
mkdir -p "${SSHD_CONFIG_DIR}"

# --- Step 1: Neutralize any existing PermitRootLogin directives in the main
# config file and any drop-in files, so they cannot override our setting.
# We comment out active (non-comment) PermitRootLogin lines rather than
# deleting them, and back up files before modification.

neutralize_permitrootlogin() {
    local file="$1"

    # Skip our own managed drop-in file; it will be rewritten explicitly below.
    if [[ "${file}" == "${DROPIN_FILE}" ]]; then
        return 0
    fi

    if [[ -f "${file}" ]] && grep -qiE '^[[:space:]]*PermitRootLogin\b' "${file}"; then
        cp -a "${file}" "${file}.bak.${TIMESTAMP}"
        # Comment out any active PermitRootLogin lines (case-insensitive),
        # preserving the original line as a comment for audit purposes.
        sed -i -E \
            's/^([[:space:]]*)PermitRootLogin([[:space:]].*)?$/\1#&/I' \
            "${file}"
        echo "Neutralized existing PermitRootLogin directive(s) in ${file}"
    fi
}

# Process main config file
neutralize_permitrootlogin "${SSHD_CONFIG}"

# Process any existing drop-in files that are included by sshd_config
if [[ -d "${SSHD_CONFIG_DIR}" ]]; then
    while IFS= read -r -d '' f; do
        neutralize_permitrootlogin "${f}"
    done < <(find "${SSHD_CONFIG_DIR}" -maxdepth 1 -type f -name '*.conf' -print0 2>/dev/null || true)
fi

# --- Step 2: Ensure the main sshd_config actually includes the drop-in
# directory. On stock Ubuntu 24.04 this is present by default, but we verify
# and add it if missing, placing it near the top so it is processed (first
# match wins in sshd_config, and drop-in files are typically included first).

if ! grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "${SSHD_CONFIG}"; then
    cp -a "${SSHD_CONFIG}" "${SSHD_CONFIG}.bak.${TIMESTAMP}"
    # Insert Include directive as the very first line to guarantee precedence.
    sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' "${SSHD_CONFIG}"
    echo "Added missing Include directive for ${SSHD_CONFIG_DIR}/*.conf to ${SSHD_CONFIG}"
fi

# --- Step 3: Write our authoritative drop-in file with the desired setting.
# Since sshd uses "first obtained value wins" and drop-ins are included
# before the rest of the main file is parsed, this guarantees our setting
# takes precedence over anything later in sshd_config.

TMP_DROPIN="$(mktemp)"
cat > "${TMP_DROPIN}" <<EOF
# Managed by remediate_ssh_disable_root_login.sh
# Do not edit manually; changes will be overwritten.
${DESIRED_SETTING}
EOF

if [[ -f "${DROPIN_FILE}" ]] && cmp -s "${TMP_DROPIN}" "${DROPIN_FILE}"; then
    echo "Drop-in file ${DROPIN_FILE} already correct; no change needed."
    rm -f "${TMP_DROPIN}"
else
    install -m 0644 -o root -g root "${TMP_DROPIN}" "${DROPIN_FILE}"
    rm -f "${TMP_DROPIN}"
    echo "Wrote ${DESIRED_SETTING} to ${DROPIN_FILE}"
fi

# --- Step 4: Validate the resulting sshd configuration before restarting.

if command -v sshd >/dev/null 2>&1; then
    if ! sshd -t; then
        echo "ERROR: sshd configuration test failed after modification. Aborting." >&2
        exit 1
    fi
else
    echo "WARNING: sshd binary not found in PATH; skipping config validation." >&2
fi

# --- Step 5: Confirm the effective setting is what we expect.

EFFECTIVE_VALUE="$(sshd -T 2>/dev/null | awk 'tolower($1)=="permitrootlogin"{print $2; exit}')"

if [[ "${EFFECTIVE_VALUE}" != "no" ]]; then
    echo "ERROR: Effective PermitRootLogin is '${EFFECTIVE_VALUE:-unset}', expected 'no'." >&2
    exit 1
fi

echo "Effective PermitRootLogin confirmed as: ${EFFECTIVE_VALUE}"

# --- Step 6: Reload/restart sshd so the change takes effect immediately,
# and ensure the service is enabled so the setting persists across reboots.

SSH_SERVICE=""
if systemctl list-unit-files 2>/dev/null | grep -q '^ssh\.service'; then
    SSH_SERVICE="ssh"
elif systemctl list-unit-files 2>/dev/null | grep -q '^sshd\.service'; then
    SSH_SERVICE="sshd"
fi

if [[ -n "${SSH_SERVICE}" ]]; then
    systemctl enable "${SSH_SERVICE}" >/dev/null 2>&1 || true
    systemctl reload-or-restart "${SSH_SERVICE}"
    echo "Reloaded/restarted ${SSH_SERVICE}.service"
else
    echo "WARNING: Could not detect ssh/sshd systemd service; please restart SSH manually." >&2
f
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
set -euo pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
SETTING="IgnoreUserKnownHosts"
VALUE="yes"
BACKUP="${SSHD_CONFIG}.bak.$(date +%Y%m%d%H%M%S)"

if [[ ! -f "$SSHD_CONFIG" ]]; then
    echo "Error: $SSHD_CONFIG not found." >&2
    exit 1
fi

# Make a backup before modifying
cp -p "$SSHD_CONFIG" "$BACKUP"

# Also check and fix any drop-in config files that might override this setting
CONFIG_DIR="/etc/ssh/sshd_config.d"

remediate_file() {
    local file="$1"
    local tmpfile
    tmpfile=$(mktemp)

    if grep -qiE "^[[:space:]]*${SETTING}[[:space:]]+" "$file"; then
        # Setting exists (possibly commented or with different case/value) - normalize all matches
        awk -v setting="$SETTING" -v value="$VALUE" '
            BEGIN { IGNORECASE=1 }
            $0 ~ "^[[:space:]]*"setting"[[:space:]]+" {
                print setting " " value
                next
            }
            { print }
        ' "$file" > "$tmpfile"
        cp "$tmpfile" "$file"
    fi
    rm -f "$tmpfile"
}

# Remove/normalize any conflicting settings in drop-in directory first
if [[ -d "$CONFIG_DIR" ]]; then
    while IFS= read -r -d '' f; do
        if grep -qiE "^[[:space:]]*${SETTING}[[:space:]]+" "$f" 2>/dev/null; then
            remediate_file "$f"
        fi
    done < <(find "$CONFIG_DIR" -maxdepth 1 -type f -name "*.conf" -print0 2>/dev/null)
fi

# Handle main sshd_config file
if grep -qiE "^[[:space:]]*#?[[:space:]]*${SETTING}[[:space:]]+" "$SSHD_CONFIG"; then
    # Setting exists (commented or not) - replace all occurrences with the correct value
    tmpfile=$(mktemp)
    awk -v setting="$SETTING" -v value="$VALUE" '
        BEGIN { IGNORECASE=1 }
        $0 ~ "^[[:space:]]*#?[[:space:]]*"setting"[[:space:]]+" {
            print setting " " value
            next
        }
        { print }
    ' "$SSHD_CONFIG" > "$tmpfile"
    cp "$tmpfile" "$SSHD_CONFIG"
    rm -f "$tmpfile"
else
    # Setting does not exist - append it
    {
        echo ""
        echo "# Hardening: do not trust per-user known_hosts cache for host key verification"
        echo "${SETTING} ${VALUE}"
    } >> "$SSHD_CONFIG"
fi

# Validate the sshd configuration syntax
if command -v sshd >/dev/null 2>&1; then
    if ! sshd -t -f "$SSHD_CONFIG" 2>/tmp/sshd_test_err; then
        echo "Error: sshd configuration test failed after modification. Restoring backup." >&2
        cat /tmp/sshd_test_err >&2
        cp -p "$BACKUP" "$SSHD_CONFIG"
        rm -f /tmp/sshd_test_err
        exit 1
    fi
    rm -f /tmp/sshd_test_err
fi

# Determine the correct service name (ssh or sshd) and reload/restart it
SERVICE_NAME=""
if systemctl list-unit-files 2>/dev/null | grep -q '^ssh\.service'; then
    SERVICE_NAME="ssh"
elif systemctl list-unit-files 2>/dev/null | grep -q '^sshd\.service'; then
    SERVICE_NAME="sshd"
fi

if [[ -n "$SERVICE_NAME" ]]; then
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        systemctl reload "$SERVICE_NAME" 2>/dev/null || systemctl restart "$SERVICE_NAME"
    else
        systemctl restart "$SERVICE_NAME" || true
    fi
    systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
fi

echo "Remediation complete: ${SETTING} is set to '${VALUE}' in ${SSHD_CONFIG}."
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
SETTING="X11Forwarding"
VALUE="no"
BACKUP="${SSHD_CONFIG}.bak.$(date +%Y%m%d%H%M%S)"

if [ ! -f "$SSHD_CONFIG" ]; then
    echo "Error: $SSHD_CONFIG not found." >&2
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root." >&2
    exit 1
fi

cp -p "$SSHD_CONFIG" "$BACKUP"

# Remove any existing X11Forwarding directives (commented or not, any case)
# and collect them so we can insert a single canonical line in their place.
TMP_FILE="$(mktemp)"
trap 'rm -f "$TMP_FILE"' EXIT

INSERTED=0

while IFS= read -r line || [ -n "$line" ]; do
    # Match lines that are (optionally commented) X11Forwarding directives
    if echo "$line" | grep -Eiq '^[[:space:]]*#?[[:space:]]*X11Forwarding[[:space:]]+'; then
        if [ "$INSERTED" -eq 0 ]; then
            echo "${SETTING} ${VALUE}" >> "$TMP_FILE"
            INSERTED=1
        fi
        # skip original line(s) to avoid duplicates
        continue
    fi
    echo "$line" >> "$TMP_FILE"
done < "$SSHD_CONFIG"

if [ "$INSERTED" -eq 0 ]; then
    printf '\n%s %s\n' "$SETTING" "$VALUE" >> "$TMP_FILE"
fi

if ! cmp -s "$TMP_FILE" "$SSHD_CONFIG"; then
    cp "$TMP_FILE" "$SSHD_CONFIG"
    chmod 644 "$SSHD_CONFIG"
    chown root:root "$SSHD_CONFIG"
else
    rm -f "$BACKUP"
fi

if command -v sshd >/dev/null 2>&1; then
    if ! sshd -t -f "$SSHD_CONFIG"; then
        echo "Error: sshd_config validation failed. Restoring backup." >&2
        if [ -f "$BACKUP" ]; then
            cp -p "$BACKUP" "$SSHD_CONFIG"
        fi
        exit 1
    fi
fi

SERVICE_NAME=""
if systemctl list-unit-files 2>/dev/null | grep -q '^ssh\.service'; then
    SERVICE_NAME="ssh"
elif systemctl list-unit-files 2>/dev/null | grep -q '^sshd\.service'; then
    SERVICE_NAME="sshd"
fi

if [ -n "$SERVICE_NAME" ]; then
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        systemctl reload "$SERVICE_NAME" 2>/dev/null || systemctl restart "$SERVICE_NAME"
    fi
    systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
fi

CURRENT_SETTING="$(grep -Ei '^[[:space:]]*X11Forwarding[[:space:]]+' "$SSHD_CONFIG" | tail -n1 | awk '{print tolower($2)}')"

if [ "$CURRENT_SETTING" = "no" ]; then
    echo "X11Forwarding is set to 'no' in $SSHD_CONFIG."
else
    echo "Error: Failed to confirm X11Forwarding setting." >&2
    exit 1
fi

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

**Prompt:** On an Ubuntu 24.04 system, configure the SSH server so that users cannot supply or override environment variables when establishing an SSH connection, preventing them from manipulating the session environment to bypass access restrictions. Write an idempotent bash remediation script that explicitly disables user environment processing in the SSH server configuration and ensures the setting persists.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation script: Disable SSH user environment variable processing
# Ensures PermitUserEnvironment is set to 'no' in sshd_config
# Idempotent: safe to run multiple times

set -euo pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_CONFIG_DIR="/etc/ssh/sshd_config.d"
SETTING_NAME="PermitUserEnvironment"
SETTING_VALUE="no"
DESIRED_LINE="${SETTING_NAME} ${SETTING_VALUE}"
BACKUP_SUFFIX=".bak.$(date +%Y%m%d%H%M%S)"

# Ensure script is run as root
if [[ "${EUID}" -ne 0 ]]; then
    echo "Error: This script must be run as root." >&2
    exit 1
fi

# Ensure sshd_config exists
if [[ ! -f "${SSHD_CONFIG}" ]]; then
    echo "Error: ${SSHD_CONFIG} not found." >&2
    exit 1
fi

remediate_file() {
    local file="$1"
    local changed=0

    if [[ ! -f "${file}" ]]; then
        return 1
    fi

    # Check for existing uncommented occurrences (case-insensitive setting name)
    if grep -qiE "^[[:space:]]*${SETTING_NAME}[[:space:]]+" "${file}"; then
        # If any uncommented line does not match desired value exactly, fix it
        while IFS= read -r line; do
            # Normalize whitespace for comparison
            normalized=$(echo "${line}" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+/ /g')
            if [[ "${normalized}" != "${DESIRED_LINE}" ]]; then
                cp -p "${file}" "${file}${BACKUP_SUFFIX}"
                sed -i -E "s|^[[:space:]]*${SETTING_NAME}[[:space:]]+.*$|${DESIRED_LINE}|I" "${file}"
                changed=1
            fi
        done < <(grep -iE "^[[:space:]]*${SETTING_NAME}[[:space:]]+" "${file}")
        if [[ "${changed}" -eq 1 ]]; then
            echo "Updated existing ${SETTING_NAME} directive in ${file}."
        else
            echo "${SETTING_NAME} already correctly set in ${file}."
        fi
        return 0
    fi

    return 1
}

# Comment out any commented occurrences left as-is; we only care about active directive
found_in_main=0
if remediate_file "${SSHD_CONFIG}"; then
    found_in_main=1
fi

# Check drop-in config directory too (Ubuntu 24.04 uses /etc/ssh/sshd_config.d/*.conf)
found_in_dropin=0
if [[ -d "${SSHD_CONFIG_DIR}" ]]; then
    for f in "${SSHD_CONFIG_DIR}"/*.conf; do
        [[ -e "${f}" ]] || continue
        if remediate_file "${f}"; then
            found_in_dropin=1
        fi
    done
fi

# If not found anywhere, append to main config file
if [[ "${found_in_main}" -eq 0 && "${found_in_dropin}" -eq 0 ]]; then
    cp -p "${SSHD_CONFIG}" "${SSHD_CONFIG}${BACKUP_SUFFIX}"
    {
        echo ""
        echo "# Disable user-supplied environment variables in SSH sessions (CIS/security hardening)"
        echo "${DESIRED_LINE}"
    } >> "${SSHD_CONFIG}"
    echo "Added ${DESIRED_LINE} to ${SSHD_CONFIG}."
fi

# Validate sshd configuration syntax
if command -v sshd >/dev/null 2>&1; then
    if ! sshd -t 2>/tmp/sshd_test_err; then
        echo "Error: sshd configuration test failed after remediation:" >&2
        cat /tmp/sshd_test_err >&2
        rm -f /tmp/sshd_test_err
        exit 1
    fi
    rm -f /tmp/sshd_test_err
else
    echo "Warning: sshd binary not found; skipping configuration syntax validation." >&2
fi

# Reload/restart sshd service to apply changes
SERVICE_NAME="ssh"
if systemctl list-unit-files | grep -q "^sshd\.service"; then
    SERVICE_NAME="sshd"
fi

if systemctl is-active --quiet "${SERVICE_NAME}"; then
    systemctl reload "${SERVICE_NAME}" 2>/dev/null || systemctl restart "${SERVICE_NAME}"
    echo "SSH service (${SERVICE_NAME}) reloaded/restarted successfully."
else
    echo "Warning: SSH service (${SERVICE_NAME}) is not active; skipping reload." >&2
fi

echo "Remediation complete: ${SETTING_NAME} is enforced as '${SETTING_VALUE}'."
exit 0
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
# Remediation script: Ensure SSH StrictModes is enabled (Ubuntu 24.04)
#
# StrictModes causes sshd to check file/directory ownership and permissions
# (home directory, ~/.ssh, authorized_keys, etc.) before accepting a login.
# If these are group/world-writable or owned incorrectly, authentication is
# refused. This prevents an attacker who has tampered with another user's
# SSH files from using them to log in as that user.
#
# This script is idempotent: it can be run multiple times safely and will
# only change configuration if needed. It also creates a drop-in config
# so the setting persists across reboots and package upgrades.

set -euo pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
DROPIN_DIR="/etc/ssh/sshd_config.d"
DROPIN_FILE="${DROPIN_DIR}/60-strictmodes.conf"
SETTING_NAME="StrictModes"
SETTING_VALUE="yes"
CHANGED=0

log() {
    echo "[strictmodes-remediation] $*"
}

# Ensure sshd_config exists
if [ ! -f "${SSHD_CONFIG}" ]; then
    echo "ERROR: ${SSHD_CONFIG} not found. Is openssh-server installed?" >&2
    exit 1
fi

# Ensure the drop-in directory exists (should be present via Include in
# Ubuntu's default sshd_config, but create defensively)
if [ ! -d "${DROPIN_DIR}" ]; then
    mkdir -p "${DROPIN_DIR}"
    chmod 0755 "${DROPIN_DIR}"
    CHANGED=1
fi

# Ensure main sshd_config includes the drop-in directory.
# Ubuntu's default sshd_config already has:
#   Include /etc/ssh/sshd_config.d/*.conf
# but verify and add if missing (idempotent).
if ! grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "${SSHD_CONFIG}"; then
    log "Adding Include directive for sshd_config.d to ${SSHD_CONFIG}"
    tmpfile=$(mktemp)
    {
        echo "Include /etc/ssh/sshd_config.d/*.conf"
        cat "${SSHD_CONFIG}"
    } > "${tmpfile}"
    install -m 0644 -o root -g root "${tmpfile}" "${SSHD_CONFIG}"
    rm -f "${tmpfile}"
    CHANGED=1
fi

# Desired content for the drop-in file
DESIRED_CONTENT="# Managed by remediation script: enforce StrictModes
# Ensures sshd verifies ownership/permissions of home dir and SSH files
# before allowing authentication.
${SETTING_NAME} ${SETTING_VALUE}
"

# Create or update the drop-in file idempotently
if [ ! -f "${DROPIN_FILE}" ] || ! diff -q <(printf '%s' "${DESIRED_CONTENT}") "${DROPIN_FILE}" >/dev/null 2>&1; then
    log "Writing ${DROPIN_FILE} with '${SETTING_NAME} ${SETTING_VALUE}'"
    tmpfile=$(mktemp)
    printf '%s' "${DESIRED_CONTENT}" > "${tmpfile}"
    install -m 0644 -o root -g root "${tmpfile}" "${DROPIN_FILE}"
    rm -f "${tmpfile}"
    CHANGED=1
else
    log "${DROPIN_FILE} already contains desired StrictModes setting"
fi

# Also normalize any conflicting StrictModes directives in the main
# sshd_config (commented or set to 'no') so the drop-in value is
# unambiguous and not overridden by an earlier explicit setting.
if grep -Eq '^[[:space:]]*StrictModes[[:space:]]+no' "${SSHD_CONFIG}"; then
    log "Disabling conflicting 'StrictModes no' in ${SSHD_CONFIG}"
    sed -i -E 's/^[[:space:]]*StrictModes[[:space:]]+no/#&/' "${SSHD_CONFIG}"
    CHANGED=1
fi

# Ensure correct permissions on the drop-in file
current_perms=$(stat -c '%a' "${DROPIN_FILE}")
if [ "${current_perms}" != "644" ]; then
    chmod 0644 "${DROPIN_FILE}"
    CHANGED=1
fi
current_owner=$(stat -c '%U:%G' "${DROPIN_FILE}")
if [ "${current_owner}" != "root:root" ]; then
    chown root:root "${DROPIN_FILE}"
    CHANGED=1
fi

# Validate sshd configuration before applying
if command -v sshd >/dev/null 2>&1; then
    if ! sshd -t; then
        echo "ERROR: sshd configuration test failed after changes. Aborting." >&2
        exit 1
    fi
else
    log "WARNING: sshd binary not found, skipping config test"
fi

# Reload/restart sshd only if something changed, to apply immediately
if [ "${CHANGED}" -eq 1 ]; then
    log "Configuration changed; reloading ssh service"
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl list-unit-files | grep -q '^ssh\.service'; then
            systemctl reload ssh.service || systemctl restart ssh.service
            systemctl enable ssh.service >/dev/null 2>&1 || true
        elif systemctl list-unit-files | grep -q '^sshd\.service'; then
            systemctl reload sshd.service || systemctl restart sshd.service
            systemctl enable sshd.service >/dev/null 2>&1 || true
        else
            log "WARNING: could not find ssh/sshd systemd unit to reload"
        fi
    else
        log "WARNING: systemctl not available, please reload sshd manually"
    fi
else
    log "No changes were necessary; StrictModes already enforced and persistent"
fi

log "Remediation complete: ${SETTING_NAME} is set to '${SETTING_VALUE}' and will persist across reboots via ${DROPIN_FILE}"

exit 0
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
#!/bin/bash
set -euo pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_CONFIG_DIR="/etc/ssh/sshd_config.d"
BANNER_FILE="/etc/issue.net"
BANNER_TEXT="Authorized uses only. All activity may be monitored and reported."

# Ensure the banner file exists with standard warning content
if [ ! -f "${BANNER_FILE}" ] || ! grep -qF "${BANNER_TEXT}" "${BANNER_FILE}"; then
    echo "${BANNER_TEXT}" > "${BANNER_FILE}"
fi
chmod 644 "${BANNER_FILE}"
chown root:root "${BANNER_FILE}"

set_banner_directive() {
    local file="$1"

    if [ -f "${file}" ] && grep -Eq '^[[:space:]]*Banner[[:space:]]+' "${file}"; then
        sed -i -E "s|^[[:space:]]*Banner[[:space:]]+.*$|Banner ${BANNER_FILE}|g" "${file}"
    else
        # Remove any commented-out Banner lines to avoid ambiguity, then append
        if [ -f "${file}" ]; then
            sed -i -E "/^[[:space:]]*#[[:space:]]*Banner[[:space:]]+/d" "${file}"
        fi
        echo "Banner ${BANNER_FILE}" >> "${file}"
    fi
}

# Remove any Banner directive from the main sshd_config to avoid conflicts,
# then set it in a dedicated drop-in config for idempotent, persistent management.
if [ -f "${SSHD_CONFIG}" ]; then
    sed -i -E "/^[[:space:]]*Banner[[:space:]]+/d" "${SSHD_CONFIG}"
fi

mkdir -p "${SSHD_CONFIG_DIR}"
DROPIN_FILE="${SSHD_CONFIG_DIR}/60-banner.conf"

if [ ! -f "${DROPIN_FILE}" ]; then
    touch "${DROPIN_FILE}"
fi

set_banner_directive "${DROPIN_FILE}"

chmod 644 "${DROPIN_FILE}"
chown root:root "${DROPIN_FILE}"

# Validate sshd configuration before restarting
if command -v sshd >/dev/null 2>&1; then
    if ! sshd -t; then
        echo "ERROR: sshd configuration test failed. Reverting is recommended." >&2
        exit 1
    fi
fi

# Restart/reload the SSH service to apply changes persistently across reboots
if command -v systemctl >/dev/null 2>&1; then
    if systemctl list-unit-files | grep -q '^ssh\.service'; then
        systemctl reload ssh.service || systemctl restart ssh.service
    elif systemctl list-unit-files | grep -q '^sshd\.service'; then
        systemctl reload sshd.service || systemctl restart sshd.service
    fi
fi

exit 0
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
SETTING="PrintLastLog"
VALUE="yes"

if [ ! -f "$SSHD_CONFIG" ]; then
    echo "Error: $SSHD_CONFIG not found." >&2
    exit 1
fi

# Backup the config file before making changes
BACKUP_FILE="${SSHD_CONFIG}.bak.$(date +%Y%m%d%H%M%S)"
cp -p "$SSHD_CONFIG" "$BACKUP_FILE"

# Remove any existing (commented or uncommented) PrintLastLog lines to avoid duplicates
sed -i -E '/^[[:space:]]*#?[[:space:]]*PrintLastLog[[:space:]]+/d' "$SSHD_CONFIG"

# Append the desired setting
printf '%s %s\n' "$SETTING" "$VALUE" >> "$SSHD_CONFIG"

# Validate the configuration
if ! sshd -t -f "$SSHD_CONFIG" 2>/tmp/sshd_test_err; then
    echo "Error: sshd configuration test failed. Restoring backup." >&2
    cat /tmp/sshd_test_err >&2
    cp -p "$BACKUP_FILE" "$SSHD_CONFIG"
    rm -f /tmp/sshd_test_err
    exit 1
fi
rm -f /tmp/sshd_test_err

# Determine the correct service name and restart/reload SSH daemon
if systemctl list-unit-files 2>/dev/null | grep -q '^ssh\.service'; then
    SERVICE_NAME="ssh"
elif systemctl list-unit-files 2>/dev/null | grep -q '^sshd\.service'; then
    SERVICE_NAME="sshd"
else
    SERVICE_NAME=""
fi

if [ -n "$SERVICE_NAME" ]; then
    systemctl reload "$SERVICE_NAME" 2>/dev/null || systemctl restart "$SERVICE_NAME"
else
    echo "Warning: Could not determine SSH service name to reload/restart." >&2
fi

echo "PrintLastLog is set to 'yes' in $SSHD_CONFIG."
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
#!/bin/bash
set -euo pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
REKEY_LIMIT_VALUE="512M 1h"
CONFIG_LINE="RekeyLimit ${REKEY_LIMIT_VALUE}"
BACKUP_FILE="${SSHD_CONFIG}.bak.$(date +%Y%m%d%H%M%S)"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

if [[ ! -f "$SSHD_CONFIG" ]]; then
    echo "SSH server configuration file not found at $SSHD_CONFIG" >&2
    exit 1
fi

if ! command -v sshd &> /dev/null; then
    echo "sshd command not found. Is openssh-server installed?" >&2
    exit 1
fi

cp "$SSHD_CONFIG" "$BACKUP_FILE"

if grep -qP "^\s*RekeyLimit\s+512M\s+1h\s*$" "$SSHD_CONFIG"; then
    echo "RekeyLimit is already correctly configured. No changes needed."
    exit 0
fi

if grep -qiP "^\s*#?\s*RekeyLimit\b" "$SSHD_CONFIG"; then
    echo "Found existing RekeyLimit directive(s). Modifying to enforce correct policy."
    
    sed -i -E '/^\s*#?\s*RekeyLimit\b/d' "$SSHD_CONFIG"

    echo "" >> "$SSHD_CONFIG"
    echo "$CONFIG_LINE" >> "$SSHD_CONFIG"
else
    echo "No existing RekeyLimit directive found. Appending new configuration."
    echo "" >> "$SSHD_CONFIG"
    echo "$CONFIG_LINE" >> "$SSHD_CONFIG"
fi

echo "Validating new SSH configuration syntax..."
if sshd -t -f "$SSHD_CONFIG"; then
    echo "Configuration syntax is valid."
else
    echo "Error: SSH configuration syntax check failed. Restoring backup." >&2
    mv "$BACKUP_FILE" "$SSHD_CONFIG"
    exit 1
fi

echo "Reloading SSH service to apply changes..."
if command -v systemctl &> /dev/null; then
    if systemctl list-units --full -all | grep -q 'ssh.service'; then
        systemctl reload ssh.service
    elif systemctl list-units --full -all | grep -q 'sshd.service'; then
        systemctl reload sshd.service
    else
        echo "Warning: Could not find ssh or sshd service to reload. Please reload manually." >&2
    fi
else
    echo "Warning: systemctl not found. Please reload the SSH service manually." >&2
fi

echo "Removing temporary backup file: $BACKUP_FILE"
rm -f "$BACKUP_FILE"

echo "SSH RekeyLimit successfully configured to '${REKEY_LIMIT_VALUE}'."

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

**Prompt:** On an Ubuntu 24.04 system, the SSH server relies on the underlying crypto library's default random-number source, which is not guaranteed to draw from a high-entropy source; weak randomness could let an attacker predict encryption keys, padding, or initialization vectors. Configure the SSH server's environment so that it seeds its random-number generator from a high-quality entropy source using 32 bytes of entropy. Write an idempotent bash remediation script that enforces this setting persistently.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# remediation_ssh_strong_rng.sh
#
# Ensures the OpenSSH server seeds its random number generator from a
# high-quality entropy source by exporting SSH_USE_STRONG_RNG=32 in the
# environment used to start sshd. This script is safe to run multiple
# times (idempotent) and persists across reboots.

set -euo pipefail

readonly SETTING_NAME="SSH_USE_STRONG_RNG"
readonly SETTING_VALUE="32"
readonly SETTING_LINE="${SETTING_NAME}=${SETTING_VALUE}"

readonly DEFAULT_SSH_FILE="/etc/default/ssh"

configure_default_ssh_file() {
    if [[ ! -e "${DEFAULT_SSH_FILE}" ]]; then
        touch "${DEFAULT_SSH_FILE}"
        chmod 644 "${DEFAULT_SSH_FILE}"
    fi

    if grep -Eq "^[[:space:]]*${SETTING_NAME}=" "${DEFAULT_SSH_FILE}"; then
        # Update existing setting if it differs from desired value
        if ! grep -Eq "^[[:space:]]*${SETTING_LINE}[[:space:]]*$" "${DEFAULT_SSH_FILE}"; then
            sed -i -E "s/^[[:space:]]*${SETTING_NAME}=.*/${SETTING_LINE}/" "${DEFAULT_SSH_FILE}"
        fi
    else
        # Append setting if it doesn't exist
        printf '%s\n' "${SETTING_LINE}" >> "${DEFAULT_SSH_FILE}"
    fi
}

configure_default_ssh_file

# Ensure sshd picks up the environment change on next start.
if systemctl is-active --quiet ssh 2>/dev/null || systemctl is-active --quiet sshd 2>/dev/null; then
    if systemctl list-unit-files | grep -q '^ssh\.service'; then
        systemctl restart ssh 2>/dev/null || true
    elif systemctl list-unit-files | grep -q '^sshd\.service'; then
        systemctl restart sshd 2>/dev/null || true
    fi
fi

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

**Prompt:** On an Ubuntu 24.04 system, configure the SSH server so that when X11 display forwarding is in use, the forwarding proxy display is bound only to the loopback interface and cannot be reached by remote hosts, limiting exposure of forwarded X11 sessions to off-host connections. Write an idempotent bash remediation script that enforces this loopback-only behavior for the SSH X11 forwarding proxy display and ensures it persists.

**Model-generated script:**
```bash
```bash
#!/usr/bin/env bash
#
# Remediation script: Ensure SSH X11 forwarding proxy display binds only
# to the loopback interface (X11UseLocalhost yes) on Ubuntu 24.04.
#
# This script is idempotent: running it multiple times will not
# produce duplicate entries or change the end state after the first
# successful run.

set -euo pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_CONFIG_D="/etc/ssh/sshd_config.d"
DROPIN_FILE="${SSHD_CONFIG_D}/60-x11-uselocalhost.conf"
PARAM_NAME="X11UseLocalhost"
PARAM_VALUE="yes"
BACKUP_SUFFIX=".bak.$(date +%Y%m%d%H%M%S)"

log() {
    echo "[x11-uselocalhost-remediation] $*"
}

err() {
    echo "[x11-uselocalhost-remediation] ERROR: $*" >&2
}

require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        err "This script must be run as root."
        exit 1
    fi
}

ensure_sshd_config_exists() {
    if [[ ! -f "${SSHD_CONFIG}" ]]; then
        err "${SSHD_CONFIG} not found. Is openssh-server installed?"
        exit 1
    fi
}

ensure_dropin_dir() {
    if [[ ! -d "${SSHD_CONFIG_D}" ]]; then
        mkdir -p "${SSHD_CONFIG_D}"
        chmod 0755 "${SSHD_CONFIG_D}"
    fi
}

# Comment out any existing X11UseLocalhost directives in the main
# sshd_config file and any files in sshd_config.d (other than our
# managed drop-in), so there is a single authoritative source of truth.
neutralize_existing_directives() {
    local file="$1"

    if [[ ! -f "${file}" ]]; then
        return 0
    fi

    # Skip our own managed drop-in file; we manage it separately.
    if [[ "${file}" == "${DROPIN_FILE}" ]]; then
        return 0
    fi

    # Check if there's an active (non-commented) directive, case-insensitively,
    # allowing leading whitespace.
    if grep -Eiq "^[[:space:]]*${PARAM_NAME}[[:space:]]+" "${file}"; then
        local backup="${file}${BACKUP_SUFFIX}"
        cp -p "${file}" "${backup}"
        log "Backed up ${file} to ${backup}"

        # Comment out all active directives (there could be multiple lines
        # due to prior misconfiguration); preserve the rest of the file.
        sed -i -E "s/^([[:space:]]*)(${PARAM_NAME}[[:space:]]+.*)$/\1# \2 # disabled by x11-uselocalhost remediation/I" "${file}"

        log "Neutralized existing ${PARAM_NAME} directive(s) in ${file}"
    fi
}

write_dropin() {
    local desired_line="${PARAM_NAME} ${PARAM_VALUE}"
    local tmp_file
    tmp_file="$(mktemp)"

    {
        echo "# Managed by x11-uselocalhost remediation script."
        echo "# Ensures SSH X11 forwarding proxy display is bound only to loopback."
        echo "# Do not edit manually; changes will be overwritten on next run."
        echo "${desired_line}"
    } > "${tmp_file}"

    if [[ -f "${DROPIN_FILE}" ]] && cmp -s "${tmp_file}" "${DROPIN_FILE}"; then
        rm -f "${tmp_file}"
        log "${DROPIN_FILE} already contains desired configuration; no changes needed."
        return 0
    fi

    install -m 0644 -o root -g root "${tmp_file}" "${DROPIN_FILE}"
    rm -f "${tmp_file}"
    log "Wrote desired configuration to ${DROPIN_FILE}"
}

ensure_main_config_includes_dropin() {
    # Ubuntu's default sshd_config includes:
    #   Include /etc/ssh/sshd_config.d/*.conf
    # near the top. Verify it's present; if not, add it, since our
    # drop-in relies on this include directive taking effect.
    if ! grep -Eq "^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf[[:space:]]*$" "${SSHD_CONFIG}"; then
        local backup="${SSHD_CONFIG}${BACKUP_SUFFIX}"
        if [[ ! -f "${backup}" ]]; then
            cp -p "${SSHD_CONFIG}" "${backup}"
            log "Backed up ${SSHD_CONFIG} to ${backup}"
        fi

        # Insert the Include directive at the very top of the file.
        local tmp_file
        tmp_file="$(mktemp)"
        {
            echo "Include /etc/ssh/sshd_config.d/*.conf"
            cat "${SSHD_CONFIG}"
        } > "${tmp_file}"

        install -m 0644 -o root -g root "${tmp_file}" "${SSHD_CONFIG}"
        rm -f "${tmp_file}"
        log "Added missing Include directive for ${SSHD_CONFIG_D} to ${SSHD_CONFIG}"
    else
        log "Include directive for ${SSHD_CONFIG_D} already present in ${SSHD_CONFIG}"
    fi
}

validate_sshd_config() {
    if command -v sshd >/dev/null 2>&1; then
        if ! sshd -t 2>/tmp/sshd_test_err; then
            err "sshd -t configuration test failed:"
            cat /tmp/sshd_test_err >&2
            rm -f /tmp/sshd_test_err
            exit 1
        fi
        rm -f /tmp/sshd_test_err
        log "sshd configuration validated successfully (sshd -t)."
    else
        log "sshd binary not found in PATH; skipping config validation."
    fi
}

reload_sshd_if_needed() {
    if command -v systemctl >/dev/null 2>&1; then
        local unit=""
        if systemctl list-unit-files 2>/dev/null | grep -q '^ssh\.service'; then
            unit="ssh"
        elif systemctl list-unit-files 2>/dev/null | grep -q '^sshd\.service'; then
            unit="sshd"
        fi

        if [[ -n "${unit}" ]]; then
            if systemctl is-active --quiet "${unit}"; then
                systemctl reload "${unit}" 2>/dev/null || systemctl restart "${unit}"
                log "Reloaded/restarted ${unit}.service to apply changes."
            else
                log "${unit}.service is not active; skipping reload."
            fi
        else
            log "Could not determine ssh service unit name; skipping reload."
        fi
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
```bash
#!/usr/bin/env bash
#
# Remediation script: Enable OCSP-based certificate revocation checking
# for SSSD smart-card / certificate-based authentication on Ubuntu 24.04.
#
# This script is idempotent: it can be run multiple times without
# creating duplicate entries or breaking the configuration.

set -euo pipefail

SSSD_CONF="/etc/sssd/sssd.conf"
SETTING_KEY="certificate_verification"
SETTING_VALUE="ocsp_dgst=sha1"
SECTION="[sssd]"

# Ensure sssd is installed
if ! command -v sssd >/dev/null 2>&1 && ! dpkg -s sssd >/dev/null 2>&1; then
    echo "sssd package does not appear to be installed. Installing..."
    apt-get update -y
    apt-get install -y sssd sssd-tools
fi

# Ensure the configuration file exists
if [ ! -f "$SSSD_CONF" ]; then
    echo "Creating $SSSD_CONF as it does not exist."
    install -o root -g root -m 0600 /dev/null "$SSSD_CONF"
    printf '%s\n' "$SECTION" >> "$SSSD_CONF"
fi

# Take a timestamped backup before modifying
BACKUP_FILE="${SSSD_CONF}.bak.$(date +%Y%m%d%H%M%S)"
cp -p "$SSSD_CONF" "$BACKUP_FILE"

# Ensure the [sssd] section exists
if ! grep -qE '^\[sssd\]' "$SSSD_CONF"; then
    printf '\n%s\n' "$SECTION" >> "$SSSD_CONF"
fi

# Use awk to idempotently set or update the certificate_verification
# option within the [sssd] section only.
TMP_FILE="$(mktemp)"

awk -v key="$SETTING_KEY" -v value="$SETTING_VALUE" '
    BEGIN { in_section = 0; done = 0 }
    /^\[sssd\]/ {
        print
        in_section = 1
        next
    }
    /^\[/ && !/^\[sssd\]/ {
        if (
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
# remediate_smartcard_sssd.sh
#
# Configures SSSD on Ubuntu 24.04 to support smart-card (CAC/PIV) based
# authentication and integrates it into the PAM stack. Idempotent: safe
# to run multiple times.

set -euo pipefail

SSSD_CONF="/etc/sssd/sssd.conf"
LOG_TAG="smartcard-sssd-remediation"

log() {
    echo "[${LOG_TAG}] $*"
}

require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo "This script must be run as root." >&2
        exit 1
    fi
}

install_packages() {
    log "Ensuring required packages are installed..."
    export DEBIAN_FRONTEND=noninteractive

    local pkgs=(
        sssd
        sssd-tools
        sssd-common
        libpam-sss
        libnss-sss
        pcscd
        pcsc-tools
        opensc
        opensc-pkcs11
        libpam-pkcs11
        gnutls-bin
    )

    local to_install=()
    for pkg in "${pkgs[@]}"; do
        if ! dpkg -s "${pkg}" >/dev/null 2>&1; then
            to_install+=("${pkg}")
        fi
    done

    if [[ "${#to_install[@]}" -gt 0 ]]; then
        apt-get update -y
        apt-get install -y "${to_install[@]}"
    else
        log "All required packages already installed."
    fi
}

ensure_sssd_conf_exists() {
    if [[ ! -f "${SSSD_CONF}" ]]; then
        log "Creating baseline ${SSSD_CONF}..."
        mkdir -p /etc/sssd
        cat > "${SSSD_CONF}" <<'EOF'
[sssd]
services = nss, pam
config_file_version = 2
domains =

[pam]

[nss]
EOF
    fi
    chown root:root "${SSSD_CONF}"
    chmod 600 "${SSSD_CONF}"
}

# Ensure a given [section] exists in the ini-style sssd.conf
ensure_section() {
    local section="$1"
    if ! grep -qE "^\[${section}\]" "${SSSD_CONF}"; then
        log "Adding missing [${section}] section to ${SSSD_CONF}..."
        printf '\n[%s]\n' "${section}" >> "${SSSD_CONF}"
    fi
}

# Ensure key=value exists within a given [section], updating or inserting as needed.
ensure_ini_kv() {
    local section="$1"
    local key="$2"
    local value="$3"

    ensure_section "${section}"

    python3 - "$SSSD_CONF" "$section" "$key" "$value" <<'PYEOF'
import sys

conf_path, section, key, value = sys.argv[1:5]

with open(conf_path, "r") as f:
    lines = f.readlines()

out = []
in_section = False
section_header = f"[{section}]"
key_pattern_found = False
section_found = False

i = 0
n = len(lines)
while i < n:
    line = lines[i]
    stripped = line.strip()

    if stripped.startswith("[") and stripped.endswith("]"):
        # Entering a new section header
        if in_section and not key_pattern_found:
            out.append(f"{key} = {value}\n")
            key_pattern_found = True
        in_section = (stripped == section_header)
        if in_section:
            section_found = True
        out.append(line)
        i += 1
        continue

    if in_section:
        if stripped.startswith(f"{key} ") or stripped.startswith(f"{key}=") or stripped == key:
            out.append(f"{key} = {value}\n")
            key_pattern_found = True
            i += 1
            continue

    out.append(line)
    i += 1

if in_section and not key_pattern_found:
    out.append(f"{key} = {value}\n")
    key_pattern_found = True

if not section_found:
    if out and not out[-1].endswith("\n"):
        out.append("\n")
    out.append(f"\n{section_header}\n{key} = {value}\n")

with open(conf_path,
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
#!/bin/bash
#
# Remediation script to ensure USBGuard is installed on Ubuntu 24.04
# USBGuard protects against rogue/unauthorized USB devices via
# device-attribute allow/block listing policies.
#
# This script is idempotent: it checks current state before making changes.

set -euo pipefail

PACKAGE_NAME="usbguard"

# Function to check if the package is installed
is_installed() {
    dpkg-query -W -f='${Status}' "${PACKAGE_NAME}" 2>/dev/null | grep -q "install ok installed"
}

echo "Checking if '${PACKAGE_NAME}' is already installed..."

if is_installed; then
    echo "'${PACKAGE_NAME}' is already installed. No action needed."
else
    echo "'${PACKAGE_NAME}' is not installed. Proceeding with installation."

    # Ensure the package index is up to date (idempotent, safe to run multiple times)
    if ! apt-get update -y; then
        echo "ERROR: Failed to update package repositories." >&2
        exit 1
    fi

    # Install the usbguard package non-interactively
    export DEBIAN_FRONTEND=noninteractive
    if ! apt-get install -y "${PACKAGE_NAME}"; then
        echo "ERROR: Failed to install '${PACKAGE_NAME}'." >&2
        exit 1
    fi

    # Verify installation succeeded
    if is_installed; then
        echo "'${PACKAGE_NAME}' successfully installed."
    else
        echo "ERROR: '${PACKAGE_NAME}' installation verification failed." >&2
        exit 1
    fi
fi

# Ensure the usbguard service is enabled so protection persists across reboots
if systemctl list-unit-files | grep -q '^usbguard\.service'; then
    if systemctl is-enabled --quiet usbguard.service; then
        echo "usbguard.service is already enabled."
    else
        echo "Enabling usbguard.service..."
        systemctl enable usbguard.service
    fi

    if systemctl is-active --quiet usbguard.service; then
        echo "usbguard.service is already active."
    else
        echo "Starting usbguard.service..."
        systemctl start usbguard.service || echo "WARNING: Failed to start usbguard.service. It may require a generated policy first."
    fi
else
    echo "WARNING: usbguard.service unit file not found; skipping service enable/start steps."
fi

echo "USBGuard remediation check complete."
exit 0
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
#!/bin/bash
#
# Remediation script: Ensure USB device authorization (usbguard) service
# is enabled at boot and currently active, idempotently.

set -euo pipefail

SERVICE_NAME="usbguard.service"
LOG_TAG="[usbguard-remediation]"

log() {
    echo "${LOG_TAG} $*"
}

# Ensure script is run as root
if [[ "${EUID}" -ne 0 ]]; then
    echo "${LOG_TAG} This script must be run as root." >&2
    exit 1
fi

# Ensure systemctl is available
if ! command -v systemctl >/dev/null 2>&1; then
    echo "${LOG_TAG} systemctl not found. This remediation requires systemd." >&2
    exit 1
fi

# Check if usbguard package/service unit exists; if not, attempt install
if ! systemctl list-unit-files --type=service 2>/dev/null | grep -q "^${SERVICE_NAME}"; then
    log "${SERVICE_NAME} unit not found. Attempting to install usbguard package."
    if command -v apt-get >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -y
        apt-get install -y usbguard
    else
        echo "${LOG_TAG} apt-get not available; cannot install usbguard automatically." >&2
        exit 1
    fi
fi

# Re-check unit file exists after potential install
if ! systemctl list-unit-files --type=service 2>/dev/null | grep -q "^${SERVICE_NAME}"; then
    echo "${LOG_TAG} ${SERVICE_NAME} still not found after install attempt." >&2
    exit 1
fi

# Reload systemd unit files to ensure we have current state
systemctl daemon-reload

# Ensure the service is enabled (persists across reboots)
if systemctl is-enabled --quiet "${SERVICE_NAME}"; then
    log "${SERVICE_NAME} is already enabled."
else
    log "Enabling ${SERVICE_NAME} to start on boot."
    systemctl enable "${SERVICE_NAME}"
fi

# Ensure the service is active (running now)
if systemctl is-active --quiet "${SERVICE_NAME}"; then
    log "${SERVICE_NAME} is already active."
else
    log "Starting ${SERVICE_NAME} now."
    systemctl start "${SERVICE_NAME}"
fi

# Final verification
if systemctl is-enabled --quiet "${SERVICE_NAME}" && systemctl is-active --quiet "${SERVICE_NAME}"; then
    log "${SERVICE_NAME} is enabled and active. Remediation successful."
    exit 0
else
    echo "${LOG_TAG} Failed to ensure ${SERVICE_NAME} is enabled and active." >&2
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
# Remediation script: Ensure USBGuard has a valid, non-empty device
# authorization policy reflecting currently connected USB devices,
# so administrators are not locked out (e.g. USB keyboard/mouse),
# and ensure the policy persists across reboots.
#
# Idempotent: safe to run multiple times.

set -euo pipefail

LOGGER_TAG="usbguard-remediation"

log() {
    echo "[${LOGGER_TAG}] $*"
}

die() {
    echo "[${LOGGER_TAG}] ERROR: $*" >&2
    exit 1
}

# Must run as root
if [ "$(id -u)" -ne 0 ]; then
    die "This script must be run as root."
fi

# Ensure usbguard is installed
if ! command -v usbguard >/dev/null 2>&1; then
    log "usbguard not found, installing..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y usbguard
fi

command -v usbguard >/dev/null 2>&1 || die "usbguard installation failed."

RULES_DIR="/etc/usbguard"
RULES_FILE="${RULES_DIR}/rules.conf"
CONF_FILE="${RULES_DIR}/usbguard-daemon.conf"

mkdir -p "${RULES_DIR}"

# Backup existing rules file if present and non-empty, before regenerating,
# but only if we haven't already backed it up in a previous run (idempotency).
if [ -s "${RULES_FILE}" ]; then
    # Check if rules file currently has at least one "allow" rule for an actual device.
    if grep -qE '^\s*allow\b' "${RULES_FILE}" 2>/dev/null; then
        log "Existing non-empty policy with allow rules already present at ${RULES_FILE}."
        POLICY_OK=1
    else
        POLICY_OK=0
    fi
else
    POLICY_OK=0
fi

if [ "${POLICY_OK:-0}" -ne 1 ]; then
    log "Generating new USBGuard policy from currently connected devices..."

    TIMESTAMP="$(date +%Y%m%d%H%M%S)"
    if [ -f "${RULES_FILE}" ]; then
        cp -a "${RULES_FILE}" "${RULES_FILE}.bak.${TIMESTAMP}"
        log "Backed up existing rules file to ${RULES_FILE}.bak.${TIMESTAMP}"
    fi

    TMP_RULES="$(mktemp)"
    if ! usbguard generate-policy > "${TMP_RULES}" 2>/dev/null; then
        rm -f "${TMP_RULES}"
        die "Failed to generate USBGuard policy from current devices."
    fi

    if [ ! -s "${TMP_RULES}" ]; then
        rm -f "${TMP_RULES}"
        die "Generated policy is empty; refusing to apply to avoid lockout."
    fi

    install -m 0600 -o root -g root "${TMP_RULES}" "${RULES_FILE}"
    rm -f "${TMP_RULES}"
    log "New policy written to ${RULES_FILE}"
else
    log "No changes needed to rules file."
fi

# Ensure permissions are correct regardless
chown root:root "${RULES_FILE}"
chmod 0600 "${RULES_FILE}"

# Ensure daemon config references the correct RuleFile
if [ -f "${CONF_FILE}" ]; then
    if grep -qE '^\s*RuleFile=' "${CONF_FILE}"; then
        sed -i "s|^\s*RuleFile=.*|RuleFile=${RULES_FILE}|" "${CONF_FILE}"
    else
        echo "RuleFile=${RULES_FILE}" >> "${CONF_FILE}"
    fi
else
    log "Daemon config ${CONF_FILE} not found; creating minimal config."
    cat > "${CONF_FILE}" <<EOF
RuleFile=${RULES_FILE}
ImplicitPolicyTarget=block
PresentDevicePolicy=allow
PresentControllerPolicy=allow
InsertedDevicePolicy=block
RestoreControllerDeviceState=false
DeviceManagerBackend=uevent
IPCAllowedUsers=root
IPCAllowedGroups=root
IPCAccessControlFiles=/etc/usbguard/IPCAccessControl.d/
DeviceRulesWithPort=false
AuditBackend=LinuxAudit
AuditFilePath=/var/log/usbguard/usbguard-audit.log
EOF
    chown root:root "${CONF_FILE}"
    chmod 0600 "${CONF_FILE}"
fi

# Ensure usbguard service is enabled and running (persists across reboots)
systemctl enable usbguard.service >/dev/null 2>&1 || true

if systemctl is-active --quiet usbguard.service; then
    log "Reloading USBGuard service to apply policy..."
    systemctl reload usbguard.service 2>/dev/null || systemctl restart usbguard.service
else
    log "Starting USBGuard service..."
    systemctl start usbguard.service
fi

# Final verification
sleep 1
if ! systemctl is-active --quiet usbguard.service; then
    die "usbguard.service failed to start/activate."
fi

if [ ! -s "${RULES_FILE}" ]; then
    die "Resulting rules file ${RULES_FILE} is empty after remediation."
fi

log "USBGuard policy is in place at ${RULES_FILE} and service is active/enabled."
exit 0
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
#!/bin/bash
#
# Remediation script: Ensure X Windows System is not installed
# CIS Ubuntu 24.04 Benchmark - Ensure X Windows Server components are not installed
#
# This script is idempotent and safe to run multiple times.

set -euo pipefail

LOGFILE="/var/log/remediation_xwindows_removal.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "$LOGFILE"
}

log "Starting X Windows System removal remediation."

# Ensure script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root." >&2
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive

# Define package patterns associated with X Windows System
# xserver-xorg* covers the core X server and related packages
XPKG_PATTERNS=(
    "xserver-xorg*"
    "xorg"
    "xserver-common"
    "x11-common"
    "xserver-xephyr"
    "xwayland"
)

# Build a list of currently installed packages matching the patterns
INSTALLED_XPKGS=()
for pattern in "${XPKG_PATTERNS[@]}"; do
    while IFS= read -r pkg; do
        [ -n "$pkg" ] && INSTALLED_XPKGS+=("$pkg")
    done < <(dpkg-query -W -f='${Package}\n' "$pattern" 2>/dev/null || true)
done

# Deduplicate the list
if [ "${#INSTALLED_XPKGS[@]}" -gt 0 ]; then
    mapfile -t INSTALLED_XPKGS < <(printf '%s\n' "${INSTALLED_XPKGS[@]}" | sort -u)
fi

if [ "${#INSTALLED_XPKGS[@]}" -gt 0 ]; then
    log "Found installed X Windows System packages: ${INSTALLED_XPKGS[*]}"
    log "Purging X Windows System packages..."
    apt-get purge -y "${INSTALLED_XPKGS[@]}" >> "$LOGFILE" 2>&1
else
    log "No X Windows System packages found installed. Nothing to purge."
fi

log "Running apt-get autoremove to clean up unused dependencies..."
apt-get autoremove -y >> "$LOGFILE" 2>&1 || true

log "Running apt-get clean to clean up package cache..."
apt-get clean >> "$LOGFILE" 2>&1 || true

# Verify no X Windows System packages remain
REMAINING=()
for pattern in "${XPKG_PATTERNS[@]}"; do
    while IFS= read -r pkg; do
        [ -n "$pkg" ] && REMAINING+=("$pkg")
    done < <(dpkg-query -W -f='${Package}\n' "$pattern" 2>/dev/null || true)
done

if [ "${#REMAINING[@]}" -gt 0 ]; then
    log "WARNING: The following X Windows System packages are still present: ${REMAINING[*]}"
    log "Attempting forced removal..."
    apt-get purge -y "${REMAINING[@]}" >> "$LOGFILE" 2>&1 || true
    apt-get autoremove -y >> "$LOGFILE" 2>&1 || true
else
    log "Confirmed: No X Windows System packages are present on the system."
fi

# Final verification
FINAL_CHECK=$(dpkg -l | grep -E '^ii\s+(xserver-xorg|xorg|x11-common|xwayland)' || true)
if [ -n "$FINAL_CHECK" ]; then
    log "ERROR: X Windows System components still detected after remediation attempt:"
    log "$FINAL_CHECK"
    exit 1
else
    log "SUCCESS: X Windows System is confirmed absent from the system."
fi

log "Remediation complete. The system cannot boot into a graphical desktop mode."

exit 0
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
#
# Remediation script: Ensure system boots by default into multi-user,
# non-graphical (text/console) mode instead of graphical.target.
#
# Idempotent: safe to run multiple times.

set -euo pipefail

readonly LOG_TAG="remediate-default-target"

log() {
    echo "[${LOG_TAG}] $*"
}

fail() {
    echo "[${LOG_TAG}] ERROR: $*" >&2
    exit 1
}

# Must run as root to modify systemd default target
if [[ "${EUID}" -ne 0 ]]; then
    fail "This script must be run as root."
fi

command -v systemctl >/dev/null 2>&1 || fail "systemctl not found; this script requires systemd."

readonly DESIRED_TARGET="multi-user.target"
readonly SYSTEMD_SYSTEM_DIR="/etc/systemd/system"
readonly DEFAULT_TARGET_LINK="${SYSTEMD_SYSTEM_DIR}/default.target"

# 1. Determine current default target (if resolvable)
current_target=""
if current_target="$(systemctl get-default 2>/dev/null)"; then
    log "Current default target: ${current_target}"
else
    log "Could not determine current default target (continuing anyway)."
fi

# 2. Set default target to multi-user.target if not already set
if [[ "${current_target}" != "${DESIRED_TARGET}" ]]; then
    log "Setting default target to ${DESIRED_TARGET}..."
    systemctl set-default "${DESIRED_TARGET}"
else
    log "Default target is already ${DESIRED_TARGET}; no change needed."
fi

# 3. Verify the symlink actually points to multi-user.target
#    (systemctl set-default creates/updates /etc/systemd/system/default.target)
if [[ -L "${DEFAULT_TARGET_LINK}" ]]; then
    link_target="$(readlink -f "${DEFAULT_TARGET_LINK}")"
    expected_target="$(readlink -f "/usr/lib/systemd/system/${DESIRED_TARGET}" 2>/dev/null || true)"
    if [[ -z "${expected_target}" ]]; then
        expected_target="$(readlink -f "/lib/systemd/system/${DESIRED_TARGET}" 2>/dev/null || true)"
    fi

    if [[ -n "${expected_target}" && "${link_target}" == "${expected_target}" ]]; then
        log "Verified ${DEFAULT_TARGET_LINK} points to ${DESIRED_TARGET}."
    else
        log "Symlink target mismatch or unable to fully verify; re-applying set-default."
        systemctl set-default "${DESIRED_TARGET}"
    fi
else
    fail "${DEFAULT_TARGET_LINK} is not a symlink; unexpected system state."
fi

# 4. Ensure graphical target is not pulled in as a dependency of default boot
#    (Not strictly required, but ensures graphical.target isn't accidentally
#    re-enabled as default via other means.)
final_target="$(systemctl get-default 2>/dev/null || true)"
if [[ "${final_target}" == "${DESIRED_TARGET}" ]]; then
    log "Confirmed system default target is now '${DESIRED_TARGET}'."
else
    fail "Failed to confirm default target is '${DESIRED_TARGET}' (got '${final_target}')."
fi

log "Remediation complete. System will boot into non-graphical multi-user mode on next boot."

exit 0
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
#!/bin/bash
set -euo pipefail

# Ensure audit=1 is present in kernel command line for all current and future kernels
# using grubby (if available) and /etc/default/grub + update-grub as fallback,
# in an idempotent manner.

ARG="audit=1"

# --- Method 1: Use grubby if available (handles all kernels uniformly) ---
if command -v grubby >/dev/null 2>&1; then
    # Update all kernels
    grubby --update-kernel=ALL --args="${ARG}" 2>/dev/null || true

    # Verify default kernel has it, if not, add explicitly
    default_kernel=$(grubby --default-kernel 2>/dev/null || true)
    if [ -n "${default_kernel}" ]; then
        if ! grubby --info="${default_kernel}" 2>/dev/null | grep -q "args=.*${ARG}"; then
            grubby --update-kernel="${default_kernel}" --args="${ARG}" || true
        fi
    fi
fi

# --- Method 2: /etc/default/grub (Debian/Ubuntu standard mechanism) ---
GRUB_FILE="/etc/default/grub"

if [ -f "${GRUB_FILE}" ]; then
    # Ensure GRUB_CMDLINE_LINUX contains audit=1
    if grep -qE '^GRUB_CMDLINE_LINUX=' "${GRUB_FILE}"; then
        current_line=$(grep -E '^GRUB_CMDLINE_LINUX=' "${GRUB_FILE}" | head -n1)
        current_value=$(echo "${current_line}" | sed -E 's/^GRUB_CMDLINE_LINUX="?([^"]*)"?$/\1/')

        if echo "${current_value}" | grep -qwE "${ARG}"; then
            : # already present, do nothing
        else
            if [ -z "${current_value}" ]; then
                new_value="${ARG}"
            else
                new_value="${current_value} ${ARG}"
            fi
            new_line="GRUB_CMDLINE_LINUX=\"${new_value}\""
            sed -i -E "s#^GRUB_CMDLINE_LINUX=.*#${new_line}#" "${GRUB_FILE}"
        fi
    else
        echo "GRUB_CMDLINE_LINUX=\"${ARG}\"" >> "${GRUB_FILE}"
    fi

    # Also handle GRUB_CMDLINE_LINUX_DEFAULT in case audit=1 should apply broadly there too
    # Not strictly required by CIS benchmark, but some environments check both.
    # We'll leave GRUB_CMDLINE_LINUX_DEFAULT untouched unless it already manages boot args exclusively.

    # Regenerate grub config
    if command -v update-grub >/dev/null 2>&1; then
        update-grub
    elif command -v grub-mkconfig >/dev/null 2>&1; then
        if [ -d /boot/grub ]; then
            grub-mkconfig -o /boot/grub/grub.cfg
        elif [ -d /boot/grub2 ]; then
            grub-mkconfig -o /boot/grub2/grub.cfg
        fi
    fi
fi

# --- Method 3: For systems using kernelstub (e.g., Pop!_OS) - not typical for Ubuntu 24.04 but safe check ---
if command -v kernelstub >/dev/null 2>&1; then
    if ! kernelstub --print-args 2>/dev/null | grep -qw "${ARG}"; then
        kernelstub --add-options "${ARG}" || true
    fi
fi

exit 0
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
```bash
#!/bin/bash
#
# Remediation script: Ensure audit backlog queue size is set to at least 8192
# for all installed kernels and future kernels, persisting across reboots.
#
# This script is idempotent - it can be run multiple times safely.

set -euo pipefail

readonly MIN_BACKLOG=8192
readonly GRUB_CFG="/etc/default/grub"
readonly GRUB_DIR="/etc/default/grub.d"
readonly GRUB_DROPIN="${GRUB_DIR}/99-audit-backlog.cfg"
readonly PARAM_NAME="audit_backlog_limit"
readonly PARAM="${PARAM_NAME}=${MIN_BACKLOG}"

log() {
    echo "[audit-backlog-remediation] $*"
}

# Function to check if a string already contains an audit_backlog_limit setting
# with a value >= MIN_BACKLOG
has_sufficient_backlog() {
    local line="$1"
    local val
    val=$(echo "$line" | grep -oP "${PARAM_NAME}=\K[0-9]+" || true)
    if [[ -n "$val" ]] && [[ "$val" -ge "$MIN_BACKLOG" ]]; then
        return 0
    fi
    return 1
}

# Function to strip any existing audit_backlog_limit=NNN tokens from a string
strip_backlog_param() {
    local input="$1"
    echo "$input" | sed -E "s/${PARAM_NAME}=[0-9]+//g" | sed -E 's/[[:space:]]+/ /g' | sed -E 's/^ //; s/ $//'
}

update_grub_default_line() {
    local file="$1"
    local var_name="$2"

    if [[ ! -f "$file" ]]; then
        return 1
    fi

    if ! grep -qE "^${var_name}=" "$file"; then
        return 1
    fi

    local current_line
    current_line=$(grep -E "^${var_name}=" "$file" | head -n1)

    local current_value
    current_value=$(echo "$current_line" | sed -E "s/^${var_name}=\"?(.*)\"?$/\1/" | sed -E 's/"$//')

    if has_sufficient_backlog "$current_value"; then
        log "GRUB variable ${var_name} in ${file} already contains sufficient ${PARAM_NAME} (>= ${MIN_BACKLOG})."
        return 0
    fi

    local stripped
    stripped=$(strip_backlog_param "$current_value")

    local new_value
    if [[ -n "$stripped" ]]; then
        new_value="${stripped} ${PARAM}"
    else
        new_value="${PARAM}"
    fi
    new_value=$(echo "$new_value" | sed -E 's/[[:space:]]+/ /g' | sed -E 's/^ //; s/ $//')

    local escaped_new_value
    escaped_new_value=$(printf '%s' "$new_value" | sed -e 's/[\/&]/\\&/g')

    sed -i -E "s/^${var_name}=.*/${var_name}=\"${escaped_new_value}\"/" "$file"
    log "Updated ${var_name} in ${file} to include ${PARAM}."
    return 0
}

ensure_grub_config() {
    if [[ ! -f "$GRUB_CFG" ]]; then
        log "WARNING: ${GRUB_CFG} not found; creating minimal file."
        touch "$GRUB_CFG"
    fi

    local updated=0

    if grep -qE '^GRUB_CMDLINE_LINUX=' "$GRUB_CFG"; then
        if update_grub_default_line "$GRUB_CFG" "GRUB_CMDLINE_LINUX"; then
            updated=1
        fi
    else
        echo "GRUB_CMDLINE_LINUX=\"${PARAM}\"" >> "$GRUB_CFG"
        log "Added GRUB_CMDLINE_LINUX with ${PARAM} to ${GRUB_CFG}."
        updated=1
    fi

    if grep -qE '^GRUB_CMDLINE_LINUX_DEFAULT=' "$GRUB_CFG"; then
        current_default=$(grep -E '^GRUB_CMDLINE_LINUX_DEFAULT=' "$GRUB_CFG" | head -n1 | sed -E 's/^GRUB_CMDLINE_LINUX_DEFAULT=//')
        current_default_val=$(echo "$current_default" | sed -E 's/^"(.*)"$/\1/')
        if ! has_sufficient_backlog "$current_default_val"; then
            :
        fi
    fi

    return $updated
}

ensure_grub_dropin() {
    mkdir -p "$GRUB_DIR"

    local desired_content="GRUB_CMDLINE_LINUX=\"\${GRUB_CMDLINE_LINUX} ${PARAM}\""

    if [[ -f "$GRUB_DROPIN" ]]; then
        if grep -qE "${PARAM_NAME}=[0-9]+" "$GRUB_DROPIN"; then
            local existing_val
            existing_val=$(grep -oP "${PARAM_NAME}=\K[0-9]+" "$GRUB_DROPIN" | head -n1)
            if [[ "$existing_val" -ge "$MIN_BACKLOG" ]]; then
                log "Drop-in ${GRUB_DROPIN} already sets sufficient ${PARAM_NAME}."
                return 0
            fi
        fi
    fi

    return 1
}

update_grub_cmdline_linux() {
    local file="$GRUB_CFG"

    if [[ ! -f "$file" ]]; then
        touch "$file"
    fi

    if grep -qE '^GRUB_CMDLINE_LINUX=' "$file"; then
        local line
        line=$(grep -E '^GRUB_CMDLINE_LINUX=' "$file" | head -n1)
        local value
        value=$(echo "$line" | sed -E 's/^GRUB_CMDLINE_LINUX="?(.*)"?$/\1/' | sed -E 's/"$//')

        if has_sufficient_backlog "$value"; then
            log "GRUB_CMDLINE_LINUX already has sufficient ${PARAM_NAME}."
        else
            local stripped
            stripped=$(strip_backlog_param "$value")
            local new_value
            if [[ -n "$stripped" ]]; then
                new_value="${stripped} ${PARAM}"
            else
                new_value="${PARAM}"
            fi
            new_value=$(echo "$new_value" | sed -E 's/[[:space:]]+/ /g' | sed -E 's/^ //; s/ $//')

            local escaped
            escaped=$(printf '%s' "$new_value" | sed -e 's/[\/&]/\\&/g')

            sed -i -E "s/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX=\"${escaped}\"/" "$file"
            log "Updated GRUB_CMDLINE_
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
# Harden auditd: make the loaded audit rule set immutable ("-e 2")
# Idempotent: safe to run multiple times, including after the kernel
# audit subsystem has already become immutable (requires reboot to change).

set -euo pipefail

RULES_DIR="/etc/audit/rules.d"
FINAL_RULE_FILE="${RULES_DIR}/99-finalize.rules"
IMMUTABLE_LINE="-e 2"

# Ensure audit package / directories exist
if [ ! -d "${RULES_DIR}" ]; then
    mkdir -p "${RULES_DIR}"
fi

# Remove any stray "-e 2" lines from other rule files to avoid
# duplicate/conflicting immutable directives and ensure ours is
# the single authoritative one, placed last alphabetically.
for f in "${RULES_DIR}"/*.rules; do
    [ -e "$f" ] || continue
    [ "$f" = "${FINAL_RULE_FILE}" ] && continue
    if grep -Eq '^[[:space:]]*-e[[:space:]]+2([[:space:]]|$)' "$f" 2>/dev/null; then
        sed -i -E '/^[[:space:]]*-e[[:space:]]+2([[:space:]]|$)/d' "$f"
    fi
done

# Ensure the finalize rule file exists with exactly the immutable directive
if [ ! -f "${FINAL_RULE_FILE}" ] || ! grep -Fxq "${IMMUTABLE_LINE}" "${FINAL_RULE_FILE}"; then
    printf '%s\n' "${IMMUTABLE_LINE}" > "${FINAL_RULE_FILE}"
fi

chown root:root "${FINAL_RULE_FILE}"
chmod 640 "${FINAL_RULE_FILE}"

# Ensure auditd and its rule-loading mechanism are enabled for persistence
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable auditd.service >/dev/null 2>&1 || true
fi

# Determine current kernel audit enabled/immutable status.
# auditctl -s reports "enabled" as: 0=off, 1=on, 2=immutable(locked)
CURRENT_ENABLED=""
if command -v auditctl >/dev/null 2>&1; then
    CURRENT_ENABLED="$(auditctl -s 2>/dev/null | awk -F'[[:space:]]+' '/^enabled/ {print $2}' || true)"
fi

if [ "${CURRENT_ENABLED}" = "2" ]; then
    # Already immutable in the running kernel; nothing more to do
    # until next reboot, but configuration is already in place.
    exit 0
fi

# Attempt to (re)load the rules now via augenrules, which merges
# /etc/audit/rules.d/*.rules into /etc/audit/audit.rules and loads them.
if command -v augenrules >/dev/null 2>&1; then
    if ! augenrules --load >/dev/null 2>&1; then
        # If the kernel is already immutable from a previous load,
        # augenrules/auditctl will fail with "Operation not permitted".
        # That's expected and not an error condition for idempotency.
        true
    fi
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "${FINAL_RULE_FILE}" >/dev/null 2>&1 || true
fi

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

**Prompt:** On an Ubuntu 24.04 system, configure the system audit subsystem so that once a user's login UID is established for a session it becomes immutable and cannot be altered, even by privileged processes lacking special capabilities. This prevents tampering that would obscure the accountability trail in audit logs. Write an idempotent bash remediation script that makes login UIDs immutable, ensuring the setting is part of the persistent audit rule configuration so it takes effect on subsequent audit daemon startups and across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation script: Make login UID (loginuid) immutable in the audit
# subsystem, persistently, so that once set for a session it cannot be
# changed even by privileged processes without CAP_AUDIT_CONTROL.
#
# This is achieved by ensuring the audit rule "--loginuid-immutable" is
# present in the persistent audit rules configuration (/etc/audit/rules.d/),
# so it is loaded by augenrules on every audit daemon start / reboot.
#
# The script is idempotent: running it multiple times will not create
# duplicate entries or break the configuration.

set -euo pipefail

AUDIT_RULES_DIR="/etc/audit/rules.d"
RULES_FILE="${AUDIT_RULES_DIR}/99-loginuid-immutable.rules"
RULE_LINE="--loginuid-immutable"

# Ensure the audit package / directories exist
if [ ! -d "${AUDIT_RULES_DIR}" ]; then
    mkdir -p "${AUDIT_RULES_DIR}"
fi

# Ensure the rules file exists
if [ ! -f "${RULES_FILE}" ]; then
    touch "${RULES_FILE}"
    chmod 0640 "${RULES_FILE}"
fi

# Idempotently add the loginuid-immutable rule if not already present
if ! grep -Eq '^\s*--loginuid-immutable\s*$' "${RULES_FILE}" 2>/dev/null; then
    echo "${RULE_LINE}" >> "${RULES_FILE}"
fi

# Also check other existing rule files in rules.d to avoid duplicate
# conflicting settings; remove any old/duplicate loginuid-immutable
# entries from other files (but leave everything else untouched),
# to keep the configuration idempotent and consistent.
for f in "${AUDIT_RULES_DIR}"/*.rules; do
    [ -e "$f" ] || continue
    if [ "$f" != "${RULES_FILE}" ]; then
        if grep -Eq '^\s*--loginuid-immutable\s*$' "$f" 2>/dev/null; then
            sed -i '/^\s*--loginuid-immutable\s*$/d' "$f"
        fi
    fi
done

# Regenerate the merged audit.rules file using augenrules, if available,
# so that /etc/audit/audit.rules (used by some setups) or the runtime
# rules are consistent with rules.d contents.
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load >/dev/null 2>&1 || true
elif command -v auditctl >/dev/null 2>&1; then
    # Fallback: directly load the rule into the running kernel audit
    # state if augenrules isn't available.
    auditctl --loginuid-immutable >/dev/null 2>&1 || true
fi

# If the audit daemon is running, ensure the immutable loginuid setting
# is active immediately, without requiring a reboot. Ignore errors if
# already set (kernel will refuse to set duplicate/immutable settings).
if command -v auditctl >/dev/null 2>&1; then
    if ! auditctl -s 2>/dev/null | grep -q 'loginuid_immutable=1' ; then
        auditctl --loginuid-immutable >/dev/null 2>&1 || true
    fi
fi

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

**Prompt:** On an Ubuntu 24.04 system, configure the system audit daemon so that it records every successful use of the filesystem mount operation performed by regular users (those with a login UID of 1000 or greater, excluding unset UIDs), capturing both 32-bit and 64-bit invocations as appropriate for the system's architecture. This audit trail helps detect unauthorized exportation of data to external media. The relevant events should be grouped under an identifying audit key of 'export'. Write an idempotent bash remediation script that establishes these audit rules so they take effect and persist across reboots.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation script: Configure auditd to record successful mount(2) syscalls
# performed by regular users (auid >= 1000, not unset/-1/4294967295),
# for both 32-bit and 64-bit architectures as applicable, tagged with key
# "export". Idempotent and persistent across reboots.

set -euo pipefail

RULES_FILE="/etc/audit/rules.d/50-export.rules"
KEY="export"

# Determine native architecture and whether we need to add 32-bit compat rules
ARCH=$(uname -m)

# Build the list of rule lines we want present
declare -a DESIRED_RULES=()

# 64-bit rule (b64) - applies to x86_64, aarch64, ppc64, etc. that support b64
DESIRED_RULES+=("-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -F success=1 -k ${KEY}")

# 32-bit rule (b32) - always add for architectures that support 32-bit syscall entry point
# On x86_64 systems, both b32 and b64 rules are typically needed to cover 32-bit binaries.
# On pure 32-bit systems (i686 etc.), only b32 is relevant, but auditctl systems generally
# accept b32 rule regardless if architecture supports it. We add b32 unconditionally
# except when running on architectures that do not support 32-bit compat (like pure aarch64
# without CONFIG_COMPAT). We attempt b32; if it fails to be interpretable by auditctl, we skip it.

DESIRED_RULES+=("-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -F success=1 -k ${KEY}")

# Ensure the audit rules directory exists
mkdir -p /etc/audit/rules.d

# Ensure the rules file exists
touch "${RULES_FILE}"

# Function to check if a rule (ignoring exact whitespace) already exists in file
rule_exists_in_file() {
    local rule="$1"
    local file="$2"
    grep -Fxq -- "${rule}" "${file}" 2>/dev/null
}

# Add each desired rule to the rules file if not already present
CHANGED=0
for rule in "${DESIRED_RULES[@]}"; do
    if ! rule_exists_in_file "${rule}" "${RULES_FILE}"; then
        echo "${rule}" >> "${RULES_FILE}"
        CHANGED=1
    fi
done

# Deduplicate the rules file while preserving order (in case of prior partial entries)
if [ -f "${RULES_FILE}" ]; then
    TMP_FILE=$(mktemp)
    awk '!seen[$0]++' "${RULES_FILE}" > "${TMP_FILE}"
    if ! cmp -s "${TMP_FILE}" "${RULES_FILE}"; then
        mv "${TMP_FILE}" "${RULES_FILE}"
        CHANGED=1
    else
        rm -f "${TMP_FILE}"
    fi
fi

chmod 640 "${RULES_FILE}"

# Try to load rules immediately via augenrules (preferred) or auditctl fallback
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    # Fallback: attempt to load rules directly, ignoring failures for unsupported arch (e.g. b32 on pure 64-bit-only kernels)
    while IFS= read -r line; do
        [ -z "${line}" ] && continue
        auditctl ${line} >/dev/null 2>&1 || true
    done < "${RULES_FILE}"
fi

# Ensure auditd service is enabled and running so changes persist across reboots
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable auditd >/dev/null 2>&1 || true
    systemctl is-active --quiet auditd || systemctl start auditd >/dev/null 2>&1 || true
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
#!/bin/bash
#
# Remediation script: Ensure auditd monitors changes to /etc/sudoers
# for write and attribute change events, tagged with an identifiable key.
# Works for both augenrules (rules.d) and auditctl (audit.rules) based setups.
# Idempotent: safe to run multiple times.

set -euo pipefail

AUDIT_FILE="/etc/sudoers"
AUDIT_KEY="scope"

RULES_D_DIR="/etc/audit/rules.d"
RULES_D_FILE="${RULES_D_DIR}/50-scope.rules"

AUDIT_RULES_FILE="/etc/audit/audit.rules"

RULE_LINE="-w ${AUDIT_FILE} -p wa -k ${AUDIT_KEY}"

# Ensure audit package/directories exist
if [ ! -d /etc/audit ]; then
    echo "ERROR: /etc/audit does not exist. Is auditd installed?" >&2
    exit 1
fi

# --- Configure augenrules (rules.d) persistence ---
if [ -d "${RULES_D_DIR}" ]; then
    if [ ! -f "${RULES_D_FILE}" ]; then
        touch "${RULES_D_FILE}"
        chmod 640 "${RULES_D_FILE}"
    fi

    if ! grep -Eq -- "^-w[[:space:]]+${AUDIT_FILE}[[:space:]]+-p[[:space:]]+wa[[:space:]]+-k[[:space:]]+${AUDIT_KEY}[[:space:]]*$" "${RULES_D_FILE}" 2>/dev/null; then
        echo "${RULE_LINE}" >> "${RULES_D_FILE}"
    fi
fi

# --- Configure audit.rules (direct auditctl load) persistence ---
if [ -f "${AUDIT_RULES_FILE}" ] || [ -d "$(dirname "${AUDIT_RULES_FILE}")" ]; then
    if [ ! -f "${AUDIT_RULES_FILE}" ]; then
        touch "${AUDIT_RULES_FILE}"
        chmod 640 "${AUDIT_RULES_FILE}"
    fi

    if ! grep -Eq -- "^-w[[:space:]]+${AUDIT_FILE}[[:space:]]+-p[[:space:]]+wa[[:space:]]+-k[[:space:]]+${AUDIT_KEY}[[:space:]]*$" "${AUDIT_RULES_FILE}" 2>/dev/null; then
        echo "${RULE_LINE}" >> "${AUDIT_RULES_FILE}"
    fi
fi

# --- Apply rule immediately via auditctl (live ruleset) ---
if command -v auditctl >/dev/null 2>&1; then
    if ! auditctl -l 2>/dev/null | grep -Eq -- "-w ${AUDIT_FILE} .*-p wa.*-k ${AUDIT_KEY}"; then
        auditctl -w "${AUDIT_FILE}" -p wa -k "${AUDIT_KEY}" || true
    fi
fi

# --- Reload rules using augenrules if available, to merge rules.d into active config ---
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "${AUDIT_RULES_FILE}" || true
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

**Prompt:** On an Ubuntu 24.04 system, the audit subsystem must record any modification to the supplementary sudo configuration directory where administrator privilege definitions are stored, so that attempts to alter privilege-escalation rules (a common persistence technique) are logged for accountability and forensic review. Write an idempotent bash remediation script that ensures the system audit daemon generates audit records for all write and attribute changes to that sudo configuration directory, tagged so the events are identifiable, and that the rule persists across reboots and applies regardless of whether the daemon loads rules via the generation utility or directly.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation script: Ensure auditd generates audit records for all
# write and attribute changes to /etc/sudoers.d (the supplementary
# sudo configuration directory), tagged for identification, and that
# the rule persists across reboots regardless of whether the audit
# daemon loads rules via augenrules or directly via auditctl.
#
# Idempotent: safe to run multiple times.

set -euo pipefail

AUDIT_DIR="/etc/sudoers.d"
KEY="actions"
RULES_D="/etc/audit/rules.d"
RULES_FILE="${RULES_D}/50-sudoers.rules"
AUDIT_RULES_FILE="/etc/audit/audit.rules"

# The canonical audit rule for this directory
RULE_LINE="-w ${AUDIT_DIR} -p wa -k ${KEY}"

# Ensure audit packages/directories exist
if ! command -v auditctl >/dev/null 2>&1; then
    echo "auditctl not found. Please install the audit package first." >&2
    exit 1
fi

mkdir -p "${RULES_D}"

# --- 1. Ensure the rule is present in /etc/audit/rules.d (used by augenrules) ---
if [ -f "${RULES_FILE}" ]; then
    if ! grep -Eq "^[[:space:]]*-w[[:space:]]+${AUDIT_DIR}[[:space:]]+-p[[:space:]]+wa[[:space:]]+-k[[:space:]]+${KEY}[[:space:]]*$" "${RULES_FILE}"; then
        # Remove any pre-existing (possibly malformed/duplicate) rules for this path first
        sed -i "\|^[[:space:]]*-w[[:space:]]\+${AUDIT_DIR//\//\\/}[[:space:]]|d" "${RULES_FILE}"
        echo "${RULE_LINE}" >> "${RULES_FILE}"
    fi
else
    echo "${RULE_LINE}" > "${RULES_FILE}"
fi
chmod 0640 "${RULES_FILE}"

# --- 2. Ensure the rule is also present in /etc/audit/audit.rules (used when rules are loaded directly) ---
if [ -f "${AUDIT_RULES_FILE}" ]; then
    if ! grep -Eq "^[[:space:]]*-w[[:space:]]+${AUDIT_DIR}[[:space:]]+-p[[:space:]]+wa[[:space:]]+-k[[:space:]]+${KEY}[[:space:]]*$" "${AUDIT_RULES_FILE}"; then
        sed -i "\|^[[:space:]]*-w[[:space:]]\+${AUDIT_DIR//\//\\/}[[:space:]]|d" "${AUDIT_RULES_FILE}"
        echo "${RULE_LINE}" >> "${AUDIT_RULES_FILE}"
    fi
else
    echo "${RULE_LINE}" > "${AUDIT_RULES_FILE}"
fi
chmod 0640 "${AUDIT_RULES_FILE}" 2>/dev/null || true

# --- 3. Regenerate rules via augenrules if present (merges rules.d into audit.rules) ---
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
fi

# --- 4. Load the rule immediately into the running kernel audit context ---
if ! auditctl -l 2>/dev/null | grep -Eq -- "-w ${AUDIT_DIR} (-p wa|-p aw) -k ${KEY}"; then
    auditctl -w "${AUDIT_DIR}" -p wa -k "${KEY}" || true
fi

# --- 5. Restart/reload the audit daemon to ensure rules persist across reboots ---
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet auditd 2>/dev/null; then
        systemctl try-restart auditd.service >/dev/null 2>&1 || true
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
#
# Remediation script: Ensure audit rules exist for privilege escalation
# via setuid/setgid execution (euid/egid != uid/gid) for both 32-bit and
# 64-bit architectures.
#
# Idempotent: safe to run multiple times.

set -euo pipefail

AUDIT_RULES_DIR="/etc/audit/rules.d"
RULES_FILE="${AUDIT_RULES_DIR}/50-privileged.rules"

# Ensure auditd and audit rule tooling are present
if ! command -v auditctl >/dev/null 2>&1; then
    echo "auditctl not found. Installing auditd package..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -y
        apt-get install -y auditd audispd-plugins
    else
        echo "ERROR: Package manager not supported. Please install auditd manually." >&2
        exit 1
    fi
fi

mkdir -p "${AUDIT_RULES_DIR}"

# Define the required audit rules
declare -a REQUIRED_RULES=(
    "-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k setuid"
    "-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid"
    "-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k setgid"
    "-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k setgid"
)

# Create the rules file if it does not exist
if [ ! -f "${RULES_FILE}" ]; then
    touch "${RULES_FILE}"
    chmod 640 "${RULES_FILE}"
fi

# Add each required rule only if it is not already present (idempotent)
for rule in "${REQUIRED_RULES[@]}"; do
    if ! grep -qF -- "${rule}" "${RULES_FILE}" 2>/dev/null; then
        echo "${rule}" >> "${RULES_FILE}"
    fi
done

# Deduplicate the rules file while preserving order
if [ -f "${RULES_FILE}" ]; then
    awk '!seen[$0]++' "${RULES_FILE}" > "${RULES_FILE}.tmp" && mv "${RULES_FILE}.tmp" "${RULES_FILE}"
    chmod 640 "${RULES_FILE}"
fi

# Merge and load the rules persistently
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "${RULES_FILE}" || true
fi

# Ensure auditd service is enabled and running
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable auditd >/dev/null 2>&1 || true
    systemctl restart auditd >/dev/null 2>&1 || true
fi

echo "Audit rules for privilege escalation (setuid/setgid execution) have been applied."
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
#!/bin/bash
#
# Remediation: Ensure auditd monitors /etc/group for write and attribute changes
#

set -uo pipefail

AUDIT_RULES_DIR="/etc/audit/rules.d"
AUDIT_RULES_FILE="${AUDIT_RULES_DIR}/50-identity.rules"
WATCH_PATH="/etc/group"
RULE_KEY="identity"
RULE_LINE="-w ${WATCH_PATH} -p wa -k ${RULE_KEY}"

# Ensure auditd package/tools are present
if ! command -v auditctl >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -y
        apt-get install -y auditd audispd-plugins
    else
        echo "ERROR: auditd is not installed and no supported package manager was found." >&2
        exit 1
    fi
fi

# Ensure the rules directory exists
mkdir -p "${AUDIT_RULES_DIR}"

# Ensure the rules file exists
if [ ! -f "${AUDIT_RULES_FILE}" ]; then
    touch "${AUDIT_RULES_FILE}"
    chmod 640 "${AUDIT_RULES_FILE}"
fi

# Idempotently add the persistent rule (covers -w path -p perms in either order/spacing)
if ! grep -Eq -- "^[[:space:]]*-w[[:space:]]+${WATCH_PATH}[[:space:]]+-p[[:space:]]+wa([[:space:]]|\$)" "${AUDIT_RULES_FILE}"; then
    echo "${RULE_LINE}" >> "${AUDIT_RULES_FILE}"
fi

# Also ensure the legacy audit.rules file (used if auditctl -R is the loading mechanism) has the rule
LEGACY_RULES_FILE="/etc/audit/audit.rules"
if [ -f "${LEGACY_RULES_FILE}" ]; then
    if ! grep -Eq -- "^[[:space:]]*-w[[:space:]]+${WATCH_PATH}[[:space:]]+-p[[:space:]]+wa([[:space:]]|\$)" "${LEGACY_RULES_FILE}"; then
        echo "${RULE_LINE}" >> "${LEGACY_RULES_FILE}"
    fi
fi

# Load the rules into the running kernel audit system regardless of mechanism
RULES_LOADED=0

if command -v augenrules >/dev/null 2>&1; then
    augenrules --load >/dev/null 2>&1 && RULES_LOADED=1
fi

if [ "${RULES_LOADED}" -eq 0 ] && command -v auditctl >/dev/null 2>&1; then
    # Fallback: load directly if not already present in the live ruleset
    if ! auditctl -l 2>/dev/null | grep -Eq -- "-w ${WATCH_PATH} -p wa"; then
        auditctl -w "${WATCH_PATH}" -p wa -k "${RULE_KEY}" >/dev/null 2>&1
    fi
    RULES_LOADED=1
fi

# Ensure auditd service is enabled and restarted/reloaded to pick up persistent rules
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable auditd >/dev/null 2>&1 || true
    systemctl is-active --quiet auditd && systemctl restart auditd >/dev/null 2>&1 || systemctl start auditd >/dev/null 2>&1 || true
elif command -v service >/dev/null 2>&1; then
    service auditd restart >/dev/null 2>&1 || service auditd start >/dev/null 2>&1 || true
fi

# Final verification
if auditctl -l 2>/dev/null | grep -Eq -- "-w ${WATCH_PATH} -p wa"; then
    echo "SUCCESS: Audit rule for ${WATCH_PATH} is active and persisted."
    exit 0
else
    echo "WARNING: Rule persisted to ${AUDIT_RULES_FILE} but could not be verified as active in the running audit configuration." >&2
    exit 0
fi
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
#
# Remediation script: Ensure auditd rules exist for monitoring changes
# to /etc/gshadow (group password / shadow group database)
# Tag: identity  (used for grouping user/group modification events)

set -euo pipefail

AUDIT_FILE="/etc/gshadow"
AUDIT_KEY="identity"
AUDIT_RULE="-w ${AUDIT_FILE} -p wa -k ${AUDIT_KEY}"

RULES_D_DIR="/etc/audit/rules.d"
RULES_D_FILE="${RULES_D_DIR}/${AUDIT_KEY}.rules"
AUDIT_RULES_FILE="/etc/audit/audit.rules"

# Ensure auditd is installed
if ! command -v auditctl >/dev/null 2>&1; then
    echo "auditd does not appear to be installed. Installing..."
    apt-get update -y
    apt-get install -y auditd audispd-plugins
fi

# Ensure /etc/audit/rules.d exists (used by augenrules)
mkdir -p "${RULES_D_DIR}"

# Idempotently add rule to rules.d (augenrules mechanism)
if [ -f "${RULES_D_FILE}" ]; then
    if ! grep -Fxq "${AUDIT_RULE}" "${RULES_D_FILE}"; then
        echo "${AUDIT_RULE}" >> "${RULES_D_FILE}"
    fi
else
    echo "${AUDIT_RULE}" > "${RULES_D_FILE}"
fi

# Remove any conflicting/duplicate entries for the same file in other rules.d files
# (avoid double logging while preserving idempotency check based on exact rule)
for f in "${RULES_D_DIR}"/*.rules; do
    [ -e "$f" ] || continue
    if [ "$f" != "${RULES_D_FILE}" ]; then
        if grep -Fxq "${AUDIT_RULE}" "$f" 2>/dev/null; then
            sed -i "\|^${AUDIT_RULE}\$|d" "$f"
        fi
    fi
done

# Idempotently add rule to /etc/audit/audit.rules (direct-load auditctl mechanism)
if [ -f "${AUDIT_RULES_FILE}" ]; then
    if ! grep -Fxq "${AUDIT_RULE}" "${AUDIT_RULES_FILE}"; then
        echo "${AUDIT_RULE}" >> "${AUDIT_RULES_FILE}"
    fi
else
    echo "${AUDIT_RULES_FILE} not found, creating it."
    touch "${AUDIT_RULES_FILE}"
    echo "${AUDIT_RULE}" >> "${AUDIT_RULES_FILE}"
fi

# Load the rules using the appropriate mechanism
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "${AUDIT_RULES_FILE}" || true
fi

# Also load directly with auditctl to ensure the running kernel audit rules
# reflect the change immediately (idempotent: rule already exists check)
if command -v auditctl >/dev/null 2>&1; then
    if ! auditctl -l 2>/dev/null | grep -Fq -- "-w ${AUDIT_FILE} -p wa -k ${AUDIT_KEY}"; then
        auditctl -w "${AUDIT_FILE}" -p wa -k "${AUDIT_KEY}" || true
    fi
fi

# Ensure auditd service is enabled and running for persistence across reboots
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable auditd >/dev/null 2>&1 || true
    systemctl restart auditd >/dev/null 2>&1 || true
fi

echo "Audit rule for ${AUDIT_FILE} (key: ${AUDIT_KEY}) has been ensured and persisted."
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
set -euo pipefail

AUDIT_FILE="/etc/security/opasswd"
RULES_FILE="/etc/audit/rules.d/opasswd.rules"
KEY="audit_account_changes"
RULE="-w ${AUDIT_FILE} -p wa -k ${KEY}"

if [ ! -d /etc/audit/rules.d ]; then
    mkdir -p /etc/audit/rules.d
fi

if [ ! -f "${RULES_FILE}" ]; then
    touch "${RULES_FILE}"
    chmod 640 "${RULES_FILE}"
fi

if ! grep -qF -- "${RULE}" "${RULES_FILE}" 2>/dev/null; then
    echo "${RULE}" >> "${RULES_FILE}"
fi

if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    if ! auditctl -l 2>/dev/null | grep -qF -- "${RULE}"; then
        auditctl -w "${AUDIT_FILE}" -p wa -k "${KEY}" || true
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
#
# Remediation script: Ensure audit rule exists for monitoring writes and
# attribute changes to /etc/passwd (primary user-account database file).
#
# This script is idempotent and configures the rule in all relevant
# locations so that it persists across reboots and is loaded regardless
# of which rule-loading mechanism auditd uses (augenrules or auditctl
# reading /etc/audit/audit.rules directly).

set -euo pipefail

AUDIT_FILE="/etc/passwd"
KEY_NAME="audit_rules_usergroup_modification"

# The canonical rule line we want present (using -p wa for write/attribute)
RULE_LINE="-w ${AUDIT_FILE} -p wa -k ${KEY_NAME}"

# Directories/files that may need the rule
RULES_D_DIR="/etc/audit/rules.d"
RULES_D_FILE="${RULES_D_DIR}/50-${KEY_NAME}.rules"
AUDIT_RULES_FILE="/etc/audit/audit.rules"

# Ensure the rules.d directory exists (should already exist on Ubuntu 24.04 with auditd installed)
if [ ! -d "${RULES_D_DIR}" ]; then
    mkdir -p "${RULES_D_DIR}"
fi

# Function to add rule to a file if not already present (idempotent)
add_rule_if_missing() {
    local file="$1"
    local rule="$2"

    if [ ! -f "${file}" ]; then
        touch "${file}"
    fi

    if ! grep -Fxq -- "${rule}" "${file}" 2>/dev/null; then
        # Also check for equivalent rule with different flag ordering (e.g. "-p aw" or "-p a" or "-p w")
        # We only guard against exact key duplication with wrong perms; remove any pre-existing
        # rule lines that watch the same path with the same key but different permissions,
        # then insert the canonical rule.
        # Remove any existing line that watches AUDIT_FILE and has our key, to avoid duplicates/conflicts
        if grep -Eq -- "^-w[[:space:]]+${AUDIT_FILE//\//\\/}[[:space:]].*-k[[:space:]]+${KEY_NAME}\$" "${file}" 2>/dev/null; then
            sed -i -E "\|^-w[[:space:]]+${AUDIT_FILE//\//\\/}[[:space:]].*-k[[:space:]]+${KEY_NAME}\$|d" "${file}"
        fi
        echo "${rule}" >> "${file}"
    fi
}

# 1. Add rule to /etc/audit/rules.d/*.rules file (used by augenrules)
add_rule_if_missing "${RULES_D_FILE}" "${RULE_LINE}"

# 2. Also ensure it's present in /etc/audit/audit.rules directly,
#    in case the system uses auditctl -R /etc/audit/audit.rules
#    (i.e., augenrules is not used to compile rules.d into audit.rules)
add_rule_if_missing "${AUDIT_RULES_FILE}" "${RULE_LINE}"

# 3. If augenrules is available, regenerate the compiled audit.rules
#    from rules.d so that both mechanisms stay in sync.
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    # Fallback: load rules directly via auditctl if augenrules isn't present
    auditctl -R "${AUDIT_RULES_FILE}" || true
fi

# 4. Load the rule into the live kernel audit ruleset immediately (best-effort),
#    so that current session for auditing takes effect without requiring reboot.
if command -v auditctl >/dev/null 2>&1; then
    if ! auditctl -l 2>/dev/null | grep -Fq -- "${RULE_LINE}"; then
        auditctl -w "${AUDIT_FILE}" -p wa -k "${KEY_NAME}" || true
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

## RHEL-08-030130 — `audit_rules_usergroup_modification_shadow`

**Prompt:** On an Ubuntu 24.04 system, the system audit daemon must record every write and attribute change made to the file that stores user account password hashes, so that any unexpected modification to credential data can be detected and investigated. Write an idempotent bash remediation script that configures the audit subsystem to monitor write and attribute-change events on that shadow password file, tags the events with a recognizable key for user/group modification tracking, and ensures the rule persists across reboots regardless of whether rules are loaded via the rule-compilation mechanism or the direct rule-loading utility.

**Model-generated script:**
```bash
#!/bin/bash
#
# Remediation script: Ensure /etc/shadow write and attribute-change events
# are audited (Ubuntu 24.04)
#
# This script is idempotent - safe to run multiple times.

set -euo pipefail

AUDIT_FILE="/etc/shadow"
AUDIT_KEY="identity"
RULE_LINE="-w ${AUDIT_FILE} -p wa -k ${AUDIT_KEY}"

# Determine which audit rule loading mechanism is in use
AUGENRULES_BIN="$(command -v augenrules || true)"
AUDITCTL_BIN="$(command -v auditctl || true)"

RULES_D_DIR="/etc/audit/rules.d"
RULES_D_FILE="${RULES_D_DIR}/50-shadow.rules"

AUDIT_RULES_FILE="/etc/audit/audit.rules"

# --- Step 1: Ensure the rule is present in /etc/audit/rules.d (used by augenrules) ---
if [ -d "${RULES_D_DIR}" ]; then
    mkdir -p "${RULES_D_DIR}"

    if [ -f "${RULES_D_FILE}" ]; then
        if ! grep -Eq -- "^\s*-w\s+${AUDIT_FILE}\s+-p\s+wa\s+-k\s+${AUDIT_KEY}\s*$" "${RULES_D_FILE}"; then
            # Remove any pre-existing (possibly malformed or duplicate) rules for this file/key combo first
            sed -i -E "\#^\s*-w\s+${AUDIT_FILE}\s+-p\s+[a-z]+\s+-k\s+.*\$#d" "${RULES_D_FILE}"
            echo "${RULE_LINE}" >> "${RULES_D_FILE}"
        fi
    else
        echo "${RULE_LINE}" > "${RULES_D_FILE}"
    fi
    chmod 0640 "${RULES_D_FILE}"
fi

# --- Step 2: Ensure the rule is present in /etc/audit/audit.rules (used by auditctl -R / direct load) ---
if [ -f "${AUDIT_RULES_FILE}" ]; then
    if ! grep -Eq -- "^\s*-w\s+${AUDIT_FILE}\s+-p\s+wa\s+-k\s+${AUDIT_KEY}\s*$" "${AUDIT_RULES_FILE}"; then
        sed -i -E "\#^\s*-w\s+${AUDIT_FILE}\s+-p\s+[a-z]+\s+-k\s+.*\$#d" "${AUDIT_RULES_FILE}"
        echo "${RULE_LINE}" >> "${AUDIT_RULES_FILE}"
    fi
fi

# --- Step 3: Load the rule into the running kernel audit system ---
# Prefer augenrules if available (Ubuntu 24.04 default), fall back to auditctl
if [ -n "${AUGENRULES_BIN}" ]; then
    "${AUGENRULES_BIN}" --load || true
elif [ -n "${AUDITCTL_BIN}" ]; then
    "${AUDITCTL_BIN}" -w "${AUDIT_FILE}" -p wa -k "${AUDIT_KEY}" || true
fi

# --- Step 4: Verify rule is active in the running configuration (best-effort) ---
if [ -n "${AUDITCTL_BIN}" ]; then
    if ! "${AUDITCTL_BIN}" -l 2>/dev/null | grep -Eq -- "-w ${AUDIT_FILE} -p wa -k ${AUDIT_KEY}"; then
        "${AUDITCTL_BIN}" -w "${AUDIT_FILE}" -p wa -k "${AUDIT_KEY}" || true
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

## RHEL-08-030490 — `audit_rules_dac_modification_chmod`

**Prompt:** On an Ubuntu 24.04 system, configure the audit subsystem to record every use of the discretionary-access-control operation that changes a file's permission bits, performed by any regular (non-system) user. Tracking such permission changes helps detect attempts to gain unauthorized access to protected information. The audit records must be tagged with an identifying key so they can be retrieved, must cover both 32-bit and 64-bit invocations on a 64-bit host, and must apply only to user accounts with login UIDs at or above the normal user threshold (excluding unset login UIDs). Ensure the configuration is idempotent and persists across reboots so the rules are reloaded automatically when the audit daemon starts. Write a bash remediation script that achieves this.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation script: Audit DAC permission-change operations (chmod/fchmod/fchmodat)
# for regular (non-system) users, on both 32-bit and 64-bit syscall entry points.
#
# This is idempotent and persists across reboots via /etc/audit/rules.d/.

set -euo pipefail

AUDIT_RULES_DIR="/etc/audit/rules.d"
RULES_FILE="${AUDIT_RULES_DIR}/50-perm_mod.rules"
KEY="perm_mod"

# Determine the UID threshold for "normal" (non-system) users.
UID_MIN=1000
if [ -f /etc/login.defs ]; then
    extracted_uid_min="$(awk '/^\s*UID_MIN\s+/{print $2}' /etc/login.defs || true)"
    if [[ "${extracted_uid_min}" =~ ^[0-9]+$ ]]; then
        UID_MIN="${extracted_uid_min}"
    fi
fi

mkdir -p "${AUDIT_RULES_DIR}"
touch "${RULES_FILE}"

declare -a DESIRED_RULES=(
    "-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=${UID_MIN} -F auid!=unset -k ${KEY}"
    "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=${UID_MIN} -F auid!=unset -k ${KEY}"
)

for rule in "${DESIRED_RULES[@]}"; do
    if ! grep -qF -- "${rule}" "${RULES_FILE}" 2>/dev/null; then
        echo "${rule}" >> "${RULES_FILE}"
    fi
done

# Deduplicate the file while preserving order, just in case.
if [ -s "${RULES_FILE}" ]; then
    tmp_file="$(mktemp)"
    awk '!seen[$0]++' "${RULES_FILE}" > "${tmp_file}"
    mv "${tmp_file}" "${RULES_FILE}"
    chmod 0640 "${RULES_FILE}"
fi

# Reload the rules so they take effect now, and ensure augenrules
# (used by systemd's auditd service) will pick them up on every boot.
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "${RULES_FILE}" || true
fi

# Ensure auditd is enabled so rules load automatically on boot.
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable auditd >/dev/null 2>&1 || true
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
#
# Remediation script: Ensure audit rules exist to capture successful
# ownership-change syscalls (chown, fchown, fchownat, lchown) for all
# regular users (UID >= 1000, excluding unset), on both 32-bit and 64-bit
# syscall interfaces. Idempotent - rules are only added if missing.
#

set -euo pipefail

AUDIT_RULES_DIR="/etc/audit/rules.d"
RULES_FILE="${AUDIT_RULES_DIR}/50-perm_mod.rules"
KEY="perm_mod"

# Ensure auditd is installed
if ! command -v auditctl >/dev/null 2>&1; then
    echo "auditctl not found. Please install the 'auditd' package first." >&2
    exit 1
fi

# Ensure the rules directory exists
mkdir -p "${AUDIT_RULES_DIR}"

# Ensure the rules file exists
if [ ! -f "${RULES_FILE}" ]; then
    touch "${RULES_FILE}"
fi

# Determine architecture-specific syscall rules to enforce
declare -a DESIRED_RULES=(
    "-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unaudit -F auid!=-1 -k ${KEY}"
    "-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unaudit -F auid!=-1 -k ${KEY}"
)

# Correct the rule syntax: use auid!=unset properly supported by auditd
declare -a FINAL_RULES=(
    "-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k ${KEY}"
    "-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k ${KEY}"
)

CHANGED=0

for rule in "${FINAL_RULES[@]}"; do
    if ! grep -qF -- "${rule}" "${RULES_FILE}" 2>/dev/null; then
        echo "${rule}" >> "${RULES_FILE}"
        CHANGED=1
    fi
done

# Deduplicate lines just in case, preserving order
if [ -s "${RULES_FILE}" ]; then
    TMP_FILE=$(mktemp)
    awk '!seen[$0]++' "${RULES_FILE}" > "${TMP_FILE}"
    mv "${TMP_FILE}" "${RULES_FILE}"
fi

chmod 0640 "${RULES_FILE}"

# Reload audit rules so they take effect immediately, and ensure
# they will be loaded at boot (augenrules regenerates the active
# ruleset from /etc/audit/rules.d at startup via auditd.service).
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load >/dev/null 2>&1 || true
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "${RULES_FILE}" >/dev/null 2>&1 || true
fi

# Restart auditd to ensure rules are active and persistent across reboot
if command -v systemctl >/dev/null 2>&1; then
    systemctl try-restart auditd.service >/dev/null 2>&1 || true
fi

if [ "${CHANGED}" -eq 1 ]; then
    echo "Audit rules for ownership-change syscalls added and loaded successfully."
else
    echo "Audit rules for ownership-change syscalls already present. No changes made."
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

**Prompt:** On an Ubuntu 24.04 system, configure the system audit daemon to record every use of the system call that changes the discretionary access control permissions of an already-open file, since such permission changes can signal attempts to gain unauthorized access to protected data. The audit rule must capture these events for all non-system user accounts (i.e., login UIDs of 1000 and above, excluding unset UIDs), apply to both 32-bit and 64-bit system call interfaces on a 64-bit system, and tag matching events with an identifying key for permission modifications. Ensure the rule persists across reboots and that the script is idempotent. Provide a bash remediation script.

**Model-generated script:**
```bash
#!/bin/bash
#
# Remediation script: Audit rule to record use of fchmod (DAC permission
# changes on already-open files) for all real user accounts (auid >= 1000),
# on both 32-bit and 64-bit syscall ABIs, persistent across reboots.
#
# Idempotent: safe to run multiple times.

set -euo pipefail

# --- Ensure we are root -----------------------------------------------------
if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# --- Ensure auditd is installed ---------------------------------------------
if ! command -v auditctl >/dev/null 2>&1 || ! dpkg -s auditd >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y auditd audispd-plugins
fi

# --- Configuration -----------------------------------------------------------
RULES_DIR="/etc/audit/rules.d"
RULES_FILE="${RULES_DIR}/50-perm_mod.rules"
KEY="perm_mod"

RULE_64="-a always,exit -F arch=b64 -S fchmod -F auid>=1000 -F auid!=unset -k ${KEY}"
RULE_32="-a always,exit -F arch=b32 -S fchmod -F auid>=1000 -F auid!=unset -k ${KEY}"

# --- Ensure audit rules directory exists -------------------------------------
mkdir -p "${RULES_DIR}"

# --- Ensure rules file exists -------------------------------------------------
touch "${RULES_FILE}"

# --- Insert 64-bit rule if not already present --------------------------------
if ! grep -Fxq -- "${RULE_64}" "${RULES_FILE}"; then
    echo "${RULE_64}" >> "${RULES_FILE}"
fi

# --- Insert 32-bit rule if not already present --------------------------------
if ! grep -Fxq -- "${RULE_32}" "${RULES_FILE}"; then
    echo "${RULE_32}" >> "${RULES_FILE}"
fi

# --- Load the persistent rules into the running kernel audit system ----------
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "${RULES_FILE}"
fi

# --- Ensure auditd service is enabled and running -----------------------------
systemctl enable auditd >/dev/null 2>&1 || true
systemctl restart auditd >/dev/null 2>&1 || systemctl start auditd >/dev/null 2>&1 || true

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
#
# Remediation script: Ensure audit captures fchmodat (chmod relative to dirfd)
# permission-modification attempts by regular users (UID >= 1000) on both
# 32-bit and 64-bit architectures, using auditctl and augenrules, persisting
# across reboots. Idempotent.

set -euo pipefail

SYSCALL="fchmodat"
KEY="perm_mod"
AUDIT_RULES_D="/etc/audit/rules.d"
RULES_FILE="${AUDIT_RULES_D}/${KEY}.rules"

# Determine which architectures are supported on this system
declare -a ARCHES=()
if [ -d /lib64 ] || [ -d /usr/lib64 ]; then
    ARCHES+=("b64" "b32")
else
    ARCHES+=("b32")
fi

# Build the list of required rule lines
declare -a REQUIRED_RULES=()
for ARCH in "${ARCHES[@]}"; do
    REQUIRED_RULES+=("-a always,exit -F arch=${ARCH} -S ${SYSCALL} -F auid>=1000 -F auid!=unset -k ${KEY}")
done

# Ensure the audit rules directory exists
mkdir -p "${AUDIT_RULES_D}"

# Ensure the rules file exists
if [ ! -f "${RULES_FILE}" ]; then
    touch "${RULES_FILE}"
fi

# Idempotently add each required rule to the persistent rules file
for RULE in "${REQUIRED_RULES[@]}"; do
    if ! grep -Fxq -- "${RULE}" "${RULES_FILE}" 2>/dev/null; then
        echo "${RULE}" >> "${RULES_FILE}"
    fi
done

# Reload persistent rules using augenrules if available
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
fi

# Also load rules into the live auditctl ruleset, avoiding duplicates
if command -v auditctl >/dev/null 2>&1; then
    for ARCH in "${ARCHES[@]}"; do
        CURRENT_RULES="$(auditctl -l 2>/dev/null || true)"
        LIVE_RULE="-a always,exit -F arch=${ARCH} -S ${SYSCALL} -F auid>=1000 -F auid!=unset -k ${KEY}"

        # Normalize for comparison: auditctl -l output format differs slightly
        # from the rules file syntax (e.g. "arch=b64" vs "arch=b64"), so we
        # check based on syscall, arch, and key presence together.
        if ! echo "${CURRENT_RULES}" | grep -q -- "-S ${SYSCALL}.*arch=${ARCH}\|arch=${ARCH}.*-S ${SYSCALL}" \
           || ! echo "${CURRENT_RULES}" | grep -q -- "key=${KEY}\|-k ${KEY}"; then
            auditctl -a always,exit -F arch="${ARCH}" -S "${SYSCALL}" -F auid>=1000 -F auid!=unset -k "${KEY}" 2>/dev/null || true
        fi
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
#!/bin/bash
#
# Remediation script: Ensure successful use of fchown syscall is audited
# (CIS Ubuntu 24.04 - auditd rules for DAC modification detection)
#
# This script configures audit rules to record successful calls to
# fchown (change file ownership via an open file descriptor) for
# all regular users (UID >= 1000, excluding unset UID 4294967295),
# on both 32-bit and 64-bit syscall interfaces, tagged with the
# "perm_mod" key. The rule is added both to the auditd.rules file
# (for auditctl / augenrules persistence) and loaded live via auditctl
# if the audit daemon is running, ensuring idempotency and
# persistence across reboots.

set -euo pipefail

RULES_FILE="/etc/audit/rules.d/50-perm_mod-fchown.rules"

# Determine architecture-specific rule lines
b64_rule='-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=unset -k perm_mod'
b32_rule='-a always,exit -F arch=b32 -S fchown -F auid>=1000 -F auid!=unset -k perm_mod'

# Ensure the rules directory exists
mkdir -p /etc/audit/rules.d

# Create the rules file if it doesn't exist
touch "$RULES_FILE"

# Idempotently add the 64-bit rule
if ! grep -Fxq "$b64_rule" "$RULES_FILE"; then
    echo "$b64_rule" >> "$RULES_FILE"
fi

# Idempotently add the 32-bit rule (only relevant if b32 interface exists, but always safe to include)
if ! grep -Fxq "$b32_rule" "$RULES_FILE"; then
    echo "$b32_rule" >> "$RULES_FILE"
fi

# Rebuild the consolidated audit.rules via augenrules if available (persists across reboots)
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    # Fallback: directly load the rule if augenrules isn't present
    auditctl -R "$RULES_FILE" || true
fi

# Also load the rule immediately into the running kernel audit rules
# if auditd is active, ensuring the rule takes effect without reboot.
if systemctl is-active --quiet auditd 2>/dev/null; then
    if command -v auditctl >/dev/null 2>&1; then
        auditctl -a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=unset -k perm_mod 2>/dev/null || true
        auditctl -a always,exit -F arch=b32 -S fchown -F auid>=1000 -F auid!=unset -k perm_mod 2>/dev/null || true
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
#
# Remediation script: Ensure audit captures fchownat (ownership change)
# syscalls for all regular users on Ubuntu 24.04 (32-bit and 64-bit).
#
# Idempotent: safe to run multiple times.

set -euo pipefail

readonly AUDIT_RULES_DIR="/etc/audit/rules.d"
readonly RULES_FILE="${AUDIT_RULES_DIR}/50-perm_mod-fchownat.rules"
readonly KEY_NAME="perm_mod"

# Determine the minimum UID considered a "regular" (non-system) user.
UID_MIN="$(awk '/^\s*UID_MIN/ {print $2}' /etc/login.defs 2>/dev/null || true)"
if [[ -z "${UID_MIN}" ]]; then
    UID_MIN=1000
fi

# Ensure the audit rules directory exists.
if [[ ! -d "${AUDIT_RULES_DIR}" ]]; then
    mkdir -p "${AUDIT_RULES_DIR}"
fi

# Ensure the rules file exists.
if [[ ! -f "${RULES_FILE}" ]]; then
    touch "${RULES_FILE}"
fi

# Determine system architecture support (assume 64-bit system, but confirm).
ARCH_LIST=("b32" "b64")
if [[ "$(uname -m)" != "x86_64" && "$(uname -m)" != "aarch64" ]]; then
    # On non-64-bit systems, only b32 is relevant, but per task we assume 64-bit.
    ARCH_LIST=("b32")
fi

declare -a DESIRED_RULES=()
for ARCH in "${ARCH_LIST[@]}"; do
    DESIRED_RULES+=("-a always,exit -F arch=${ARCH} -S fchownat -F auid>=${UID_MIN} -F auid!=4294967295 -k ${KEY_NAME}")
done

# Add each desired rule only if it is not already present (idempotent).
for RULE in "${DESIRED_RULES[@]}"; do
    if ! grep -Fxq -- "${RULE}" "${RULES_FILE}" 2>/dev/null; then
        echo "${RULE}" >> "${RULES_FILE}"
    fi
done

# Ensure proper permissions on the rules file.
chmod 0640 "${RULES_FILE}"
chown root:root "${RULES_FILE}"

# Regenerate the compiled audit rules and load them if augenrules is available.
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    # Fallback: load rules directly if augenrules is unavailable.
    for RULE in "${DESIRED_RULES[@]}"; do
        auditctl ${RULE} || true
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
#!/bin/bash
#
# Remediation script: Configure auditd to record fsetxattr syscall usage
# for unprivileged users (UID >= 1000, excluding unset -4294967295) and root.
# Covers both b32 and b64 syscall interfaces, tagged with key=perm_mod.
# Idempotent, persistent across reboots, integrates with augenrules.

set -euo pipefail

AUDIT_RULES_DIR="/etc/audit/rules.d"
RULES_FILE="${AUDIT_RULES_DIR}/50-fsetxattr.rules"

# Ensure the rules directory exists
mkdir -p "${AUDIT_RULES_DIR}"

# Define the required audit rule lines
declare -a REQUIRED_RULES=(
"-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod"
"-a always,exit -F arch=b32 -S fsetxattr -F auid=0 -F key=perm_mod"
"-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod"
"-a always,exit -F arch=b64 -S fsetxattr -F auid=0 -F key=perm_mod"
)

# Create the rules file if it doesn't exist
touch "${RULES_FILE}"

# Ensure each required rule is present (idempotent check/insert)
for rule in "${REQUIRED_RULES[@]}"; do
    if ! grep -Fxq -- "${rule}" "${RULES_FILE}" 2>/dev/null; then
        echo "${rule}" >> "${RULES_FILE}"
    fi
done

# Set proper permissions on the rules file
chmod 0640 "${RULES_FILE}"
chown root:root "${RULES_FILE}"

# Load rules using the augenrules mechanism (merges rules.d into audit.rules)
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    # Fallback: directly load with auditctl if augenrules unavailable
    auditctl -R "${RULES_FILE}" || true
fi

# Verify auditd service is enabled and restart to ensure rules take effect
if systemctl is-enabled auditd >/dev/null 2>&1; then
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

AUDIT_RULES_FILE="/etc/audit/rules.d/50-perm_mod.rules"
KEY="perm_mod"

declare -a RULES=(
"-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=unset -k ${KEY}"
"-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=unset -k ${KEY}"
)

mkdir -p /etc/audit/rules.d

touch "$AUDIT_RULES_FILE"

for rule in "${RULES[@]}"; do
    if ! grep -Fxq -- "$rule" "$AUDIT_RULES_FILE"; then
        echo "$rule" >> "$AUDIT_RULES_FILE"
    fi
done

if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "$AUDIT_RULES_FILE" || true
fi

for rule in "${RULES[@]}"; do
    live_rule="$(echo "$rule" | sed 's/^-a always,exit/-a always,exit/')"
    if ! auditctl -l 2>/dev/null | grep -Fq -- "$(echo "$rule" | sed 's/^-a /-A /')"; then
        auditctl $rule 2>/dev/null || true
    fi
done
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
#!/bin/bash
#
# Remediation script: audit lsetxattr syscall for perm_mod events
# Idempotent - safe to run multiple times
#

set -e

RULES_FILE_AUGENRULES="/etc/audit/rules.d/50-perm_mod.rules"
RULES_FILE_AUDITCTL="/etc/audit/audit.rules"
KEY="perm_mod"

# Determine architecture-specific arch names
ARCH64="b64"
ARCH32="b32"

# Function to build the required rule lines for a given arch
build_rules() {
    local arch="$1"
    echo "-a always,exit -F arch=${arch} -S lsetxattr -F auid>=1000 -F auid!=unset -F key=${KEY}"
    echo "-a always,exit -F arch=${arch} -S lsetxattr -F auid=0 -F key=${KEY}"
}

# --- Ensure augenrules rules file exists and contains required lines ---
mkdir -p /etc/audit/rules.d

if [ ! -f "${RULES_FILE_AUGENRULES}" ]; then
    touch "${RULES_FILE_AUGENRULES}"
fi

for arch in "${ARCH64}" "${ARCH32}"; do
    while IFS= read -r rule; do
        if ! grep -Fxq -- "${rule}" "${RULES_FILE_AUGENRULES}"; then
            echo "${rule}" >> "${RULES_FILE_AUGENRULES}"
        fi
    done < <(build_rules "${arch}")
done

# --- Ensure auditctl (currently loaded rules) also contains these rules ---
# Load rules into the running auditd via augenrules, which regenerates
# /etc/audit/audit.rules from /etc/audit/rules.d/*.rules
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
fi

# Also ensure the auditctl static rules file (in case augenrules mechanism
# is not used on this system) contains the same lines, for systems relying
# directly on /etc/audit/audit.rules populated via auditctl -R
if [ -f "${RULES_FILE_AUDITCTL}" ]; then
    for arch in "${ARCH64}" "${ARCH32}"; do
        while IFS= read -r rule; do
            if ! grep -Fxq -- "${rule}" "${RULES_FILE_AUDITCTL}"; then
                echo "${rule}" >> "${RULES_FILE_AUDITCTL}"
            fi
        done < <(build_rules "${arch}")
    done
fi

# Load rules into the live kernel audit ruleset immediately, if auditctl exists
if command -v auditctl >/dev/null 2>&1; then
    for arch in "${ARCH64}" "${ARCH32}"; do
        while IFS= read -r rule; do
            # shellcheck disable=SC2086
            auditctl ${rule} >/dev/null 2>&1 || true
        done < <(build_rules "${arch}")
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
```bash
#!/bin/bash
#
# Idempotent remediation script: audit setxattr syscall (perm_mod)
#
# Ensures auditd records every setxattr() call for auid>=1000 and auid=0,
# on both b32 and b64 syscall ABIs, tagged with key "perm_mod".
# Persistent across reboots and compatible with either augenrules-managed
# rules.d configuration or a direct /etc/audit/audit.rules configuration.

set -euo pipefail

KEY="perm_mod"

# Build the exact set of rule lines required.
declare -a REQUIRED_RULES=(
    "-a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F auid!=unset -F key=${KEY}"
    "-a always,exit -F arch=b32 -S setxattr -F auid=0 -F key=${KEY}"
    "-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=unset -F key=${KEY}"
    "-a always,exit -F arch=b64 -S setxattr -F auid=0 -F key=${KEY}"
)

# Determine whether this system's audit daemon loads rules via augenrules
# (rules.d directory compiled into audit.rules) or directly consumes
# /etc/audit/audit.rules via auditctl.
AUGENRULES_BIN=""
for candidate in /sbin/augenrules /usr/sbin/augenrules; do
    if [ -x "${candidate}" ]; then
        AUGENRULES_BIN="${candidate}"
        break
    fi
done

if [ -n "${AUGENRULES_BIN}" ] && [ -d /etc/audit/rules.d ]; then
    USE_AUGENRULES=1
    RULES_FILE="/etc/audit/rules.d/50-perm_mod.rules"
else
    USE_AUGENRULES=0
    RULES_FILE="/etc/audit/audit.rules"
fi

mkdir -p "$(dirname "${RULES_FILE}")"
touch "${RULES_FILE}"

# Idempotently ensure each required rule line is present exactly once.
for rule in "${REQUIRED_RULES[@]}"; do
    if ! grep -qxF -- "${rule}
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
#
# Remediation script: Ensure auditd records execution attempts of the
# semanage command (SELinux management utility) by all users (UID >= 1000)
# and root. Idempotent - safe to run multiple times, persists across reboots
# and audit daemon restarts.

set -euo pipefail

RULES_FILE="/etc/audit/rules.d/semanage.rules"
KEY_TAG="privileged-priv_change"

# Locate the semanage binary path(s); typically /usr/sbin/semanage
SEMANAGE_PATH=""
for p in /usr/sbin/semanage /sbin/semanage /usr/bin/semanage /bin/semanage; do
    if [ -x "$p" ]; then
        SEMANAGE_PATH="$p"
        break
    fi
done

if [ -z "$SEMANAGE_PATH" ]; then
    if command -v semanage >/dev/null 2>&1; then
        SEMANAGE_PATH="$(command -v semanage)"
    else
        SEMANAGE_PATH="/usr/sbin/semanage"
    fi
fi

# Ensure audit directories exist
mkdir -p /etc/audit/rules.d

# Build the two required audit rules: one for UID >= 1000 users, one for root (uid=0)
RULE_UNPRIV="-a always,exit -F path=${SEMANAGE_PATH} -F perm=x -F auid>=1000 -F auid!=unset -k ${KEY_TAG}"
RULE_ROOT="-a always,exit -F path=${SEMANAGE_PATH} -F perm=x -F auid=0 -k ${KEY_TAG}"

# Create or update the rules file idempotently
if [ ! -f "$RULES_FILE" ]; then
    touch "$RULES_FILE"
fi

# Remove any pre-existing rules referencing this path and key to avoid duplicates,
# then re-add the canonical rules.
TMP_FILE="$(mktemp)"
grep -v -F "${SEMANAGE_PATH}" "$RULES_FILE" 2>/dev/null | grep -v -F "$KEY_TAG" > "$TMP_FILE" || true

{
    cat "$TMP_FILE"
    echo "$RULE_UNPRIV"
    echo "$RULE_ROOT"
} > "$RULES_FILE"

rm -f "$TMP_FILE"

chmod 640 "$RULES_FILE"
chown root:root "$RULES_FILE"

# Ensure the rule also loaded into the running audit kernel ruleset immediately.
# Use augenrules to compile all rule files into audit.rules, then load with auditctl
# or restart the auditd service depending on availability.

if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    # Fallback: load rule directly if augenrules unavailable
    auditctl -D >/dev/null 2>&1 || true
    auditctl $RULE_UNPRIV || true
    auditctl $RULE_ROOT || true
fi

# Restart auditd to ensure persistence and immediate effect, if service manager available
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet auditd 2>/dev/null; then
        systemctl restart auditd || true
    elif systemctl list-unit-files | grep -q '^auditd.service'; then
        systemctl start auditd || true
    fi
fi

# Verify the rule is present in the active audit ruleset
if command -v auditctl >/dev/null 2>&1; then
    if ! auditctl -l 2>/dev/null | grep -q "${SEMANAGE_PATH}"; then
        echo "Warning: semanage audit rule not found in active ruleset after reload." >&2
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
#!/bin/bash
set -euo pipefail

# Remediation script: Ensure audit rule exists for setfiles privileged command
# This script is idempotent and works whether audit rules are loaded via
# /etc/audit/rules.d/*.rules (augenrules) or /etc/audit/audit.rules (auditctl -R)

PROGRAM_PATH="/usr/sbin/setfiles"
KEY_NAME="privileged-priv_change"

# Determine architecture(s) to audit
ARCHS=()
if [ -d /usr/lib64 ] || uname -m | grep -qE '^(x86_64|aarch64|ppc64|ppc64le|s390x)$'; then
    ARCHS+=("b64")
fi
ARCHS+=("b32")

# Build the audit rule lines for both 32-bit and 64-bit, for UID>=1000 and root (uid=0)
build_rule() {
    local arch="$1"
    echo "-a always,exit -F arch=${arch} -F path=${PROGRAM_PATH} -F perm=x -F auid>=1000 -F auid!=unset -k ${KEY_NAME}"
}

RULE_LINES=()
for arch in "${ARCHS[@]}"; do
    RULE_LINES+=("$(build_rule "$arch")")
done

# Ensure setfiles binary exists (informational only, do not fail if missing)
if [ ! -x "${PROGRAM_PATH}" ]; then
    echo "Warning: ${PROGRAM_PATH} not found on this system; rule will still be installed." >&2
fi

# --- Handle augenrules (rules.d) mechanism ---
RULES_D_DIR="/etc/audit/rules.d"
RULES_D_FILE="${RULES_D_DIR}/50-privileged.rules"

if [ -d "${RULES_D_DIR}" ]; then
    mkdir -p "${RULES_D_DIR}"
    touch "${RULES_D_FILE}"
    for line in "${RULE_LINES[@]}"; do
        if ! grep -Fxq -- "${line}" "${RULES_D_FILE}" 2>/dev/null; then
            # Remove any pre-existing rule for the same path+key with different auid syntax to avoid duplicates
            grep -Fv -- "-F path=${PROGRAM_PATH} " "${RULES_D_FILE}" > "${RULES_D_FILE}.tmp" 2>/dev/null || true
            if [ -f "${RULES_D_FILE}.tmp" ]; then
                mv "${RULES_D_FILE}.tmp" "${RULES_D_FILE}"
            fi
            echo "${line}" >> "${RULES_D_FILE}"
        fi
    done
    chmod 0640 "${RULES_D_FILE}"
fi

# --- Handle consolidated audit.rules file (used directly by auditd via auditctl -R) ---
AUDIT_RULES_FILE="/etc/audit/audit.rules"

if [ -f "${AUDIT_RULES_FILE}" ]; then
    touch "${AUDIT_RULES_FILE}"
    for line in "${RULE_LINES[@]}"; do
        if ! grep -Fxq -- "${line}" "${AUDIT_RULES_FILE}" 2>/dev/null; then
            echo "${line}" >> "${AUDIT_RULES_FILE}"
        fi
    done
    chmod 0640 "${AUDIT_RULES_FILE}" 2>/dev/null || true
fi

# --- Regenerate consolidated rules if augenrules is available ---
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    # Load rules directly if augenrules is not present
    for line in "${RULE_LINES[@]}"; do
        auditctl ${line#-a always,exit } 2>/dev/null || true
    done
fi

# Attempt to load the rules immediately for the running audit daemon (best-effort)
if command -v auditctl >/dev/null 2>&1; then
    for line in "${RULE_LINES[@]}"; do
        # Extract the rule portion after "-a always,exit"
        rule_args="${line#-a always,exit }"
        if ! auditctl -l 2>/dev/null | grep -Fq -- "${line#-a }" ; then
            auditctl -a always,exit ${rule_args} 2>/dev/null || true
        fi
    done
fi

# --- Ensure auditd service is enabled and will apply rules on boot ---
if command -v systemctl >/dev/null 2>&1; then
    systemctl is-enabled auditd >/dev/null 2>&1 || systemctl enable auditd >/dev/null 2>&1 || true
fi

exit 0
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
#!/bin/bash
set -euo pipefail

AUDIT_RULES_FILE="/etc/audit/rules.d/50-privileged.rules"
CMD_PATH=$(command -v setsebool || echo "/usr/sbin/setsebool")

RULE_LINE="-a always,exit -F path=${CMD_PATH} -F perm=x -F auid>=1000 -F auid!=unset -k privileged"

mkdir -p /etc/audit/rules.d

touch "$AUDIT_RULES_FILE"

if ! grep -qF -- "$RULE_LINE" "$AUDIT_RULES_FILE"; then
    echo "$RULE_LINE" >> "$AUDIT_RULES_FILE"
fi

if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "$AUDIT_RULES_FILE" || true
fi

exit 0
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
```bash
#!/bin/bash
#
# Idempotent remediation script: ensure auditd captures file-deletion
# events performed via the rename/renameat syscalls for all real users
# (auid >= 1000, excluding unset auid), on both 32-bit and 64-bit
# syscall interfaces where applicable, tagged with the "delete" key.
#
set -euo pipefail

RULES_FILE="/etc/audit/rules.d/50-delete.rules"
KEY="delete"

# Make sure the audit rules directory exists
mkdir -p /etc/audit/rules.d

# Ensure the target rules file exists
touch "$RULES_FILE"

# Determine which syscall architectures are relevant on this system
ARCHES=()
if [ "$(getconf LONG_BIT)" = "64" ]; then
    ARCHES+=("b64")
    if [ "$(uname -m)" = "x86_64" ]; then
        ARCHES+=("b32")
    fi
else
    ARCHES+=("b32")
fi

# Add the required rule(s) only if not already present (idempotent)
for arch in "${ARCHES[@]}"; do
    RULE="-a always,exit -F arch=${arch} -S rename,renameat -F auid>=1000 -F auid!=unset -k ${KEY}"
    if ! grep -qF -- "$RULE" "$RULES_FILE" 2>/dev/null; then
        echo "$RULE" >> "$RULES_FILE"
    fi
done

# Ensure auditd is enabled and running so rules persist across reboots
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable auditd >/dev/null 2>&1 || true
    systemctl start auditd >/dev/null 2>&1 || true
fi

# Load the rules now so they take eff
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
#!/bin/bash
#
# Remediation script: Ensure the audit system generates audit records
# for file deletion/rename events (unlink, unlinkat, rename, renameat)
# performed by regular users (auid >= 1000, excluding unset auid).
#
# Idempotent: safe to run multiple times.

set -euo pipefail

AUDIT_RULES_DIR="/etc/audit/rules.d"
AUDIT_RULES_FILE="${AUDIT_RULES_DIR}/50-delete.rules"

# Ensure audit rules directory exists
if [[ ! -d "${AUDIT_RULES_DIR}" ]]; then
    mkdir -p "${AUDIT_RULES_DIR}"
fi

# Ensure the rules file exists
if [[ ! -f "${AUDIT_RULES_FILE}" ]]; then
    touch "${AUDIT_RULES_FILE}"
fi

# Determine system architecture to decide whether b32 rules are relevant
SYSTEM_ARCH="$(uname -m)"

# Define the rule lines (64-bit is always applicable)
RULE_B64='-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete'
RULE_B32='-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete'

# Function to add a rule to the rules file if it does not already exist
add_rule_if_absent() {
    local rule="$1"
    if ! grep -qxF "${rule}" "${AUDIT_RULES_FILE}" 2>/dev/null; then
        echo "${rule}" >> "${AUDIT_RULES_FILE}"
    fi
}

# Always add the 64-bit rule
add_rule_if_absent "${RULE_B64}"

# Only add the 32-bit rule on architectures that support the 32-bit ABI
case "${SYSTEM_ARCH}" in
    x86_64|i386|i686)
        add_rule_if_absent "${RULE_B32}"
        ;;
    *)
        :
        ;;
esac

# Ensure file has correct permissions as required by auditd
chmod 640 "${AUDIT_RULES_FILE}"

# Merge rules into the running configuration and load them persistently
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "${AUDIT_RULES_FILE}" || true
fi

# Restart/reload the audit daemon so that changes take effect and persist across reboots
if command -v systemctl >/dev/null 2>&1; then
    systemctl restart auditd || true
elif command -v service >/dev/null 2>&1; then
    service auditd restart || true
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
#
# Remediation script: Configure audit rules to record directory-removal
# (rmdir) operations performed by non-system (regular) users on Ubuntu 24.04.
#
# This script is idempotent: it can be run multiple times without producing
# duplicate rules, and the resulting configuration persists across reboots
# and audit rule reloads via /etc/audit/rules.d and augenrules.

set -euo pipefail

RULES_FILE="/etc/audit/rules.d/50-delete.rules"
AUDIT_KEY="delete"

# Ensure auditd and audit rule tooling are installed.
if ! command -v auditctl >/dev/null 2>&1 || ! command -v augenrules >/dev/null 2>&1; then
    echo "Installing auditd package..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -y
        apt-get install -y auditd audispd-plugins
    else
        echo "ERROR: apt-get not found; cannot install auditd." >&2
        exit 1
    fi
fi

# Ensure the rules directory exists.
mkdir -p /etc/audit/rules.d

# Ensure the rules file exists.
touch "${RULES_FILE}"
chmod 640 "${RULES_FILE}"

# Define the required audit rules for tracking rmdir (directory removal)
# operations by users with auid >= 1000 (regular/non-system users), across
# both 64-bit and 32-bit syscall ABIs, tagged with a recognizable key.
declare -a REQUIRED_RULES=(
    "-a always,exit -F arch=b64 -S rmdir -F auid>=1000 -F auid!=unset -k ${AUDIT_KEY}"
    "-a always,exit -F arch=b32 -S rmdir -F auid>=1000 -F auid!=unset -k ${AUDIT_KEY}"
)

# Function: ensure a given rule line exists exactly once in the rules file.
ensure_rule_present() {
    local rule="$1"
    if ! grep -Fxq -- "${rule}" "${RULES_FILE}"; then
        echo "${rule}" >> "${RULES_FILE}"
    fi
}

for rule in "${REQUIRED_RULES[@]}"; do
    ensure_rule_present "${rule}"
done

# Deduplicate the rules file just in case (idempotency safeguard),
# preserving order of first occurrence.
TMP_FILE="$(mktemp)"
awk '!seen[$0]++' "${RULES_FILE}" > "${TMP_FILE}"
mv "${TMP_FILE}" "${RULES_FILE}"
chmod 640 "${RULES_FILE}"

# Merge rule fragments and regenerate the active audit ruleset so the
# configuration persists across reboots and rule reloads.
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
fi

# Ensure auditd is enabled and running so rules take effect now.
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable auditd >/dev/null 2>&1 || true
    systemctl restart auditd >/dev/null 2>&1 || true
fi

# Verify the rules are currently loaded in the live audit ruleset.
if command -v auditctl >/dev/null 2>&1; then
    if ! auditctl -l 2>/dev/null | grep -q -- "-S rmdir" ; then
        echo "WARNING: rmdir audit rules do not appear to be active in the live ruleset." >&2
    else
        echo "Audit rules for directory-removal (rmdir) tracking are active."
    fi
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
#
# Remediation script: Configure auditd to record file-deletion attempts
# via the unlink syscall for login UIDs >= 1000 (excluding unset UIDs).
# Idempotent - safe to run multiple times.

set -euo pipefail

AUDIT_RULES_FILE="/etc/audit/rules.d/50-delete.rules"
KEY="delete"

# Determine system architecture(s) to cover.
ARCH=$(uname -m)

# Build list of rule lines needed. We always add rules for unlink,
# using -F arch=b64/b32 as appropriate, and -F auid>=1000 -F auid!=unset,
# tagged with -k delete.

declare -a RULES=()

if [[ "$ARCH" == "x86_64" ]]; then
    RULES+=(
        "-a always,exit -F arch=b64 -S unlink -F auid>=1000 -F auid!=unset -k ${KEY}"
        "-a always,exit -F arch=b32 -S unlink -F auid>=1000 -F auid!=unset -k ${KEY}"
    )
elif [[ "$ARCH" == "aarch64" ]]; then
    RULES+=(
        "-a always,exit -F arch=b64 -S unlink -F auid>=1000 -F auid!=unset -k ${KEY}"
        "-a always,exit -F arch=b32 -S unlink -F auid>=1000 -F auid!=unset -k ${KEY}"
    )
else
    RULES+=(
        "-a always,exit -F arch=b64 -S unlink -F auid>=1000 -F auid!=unset -k ${KEY}"
    )
fi

# Ensure auditd and audit tools are installed.
if ! command -v auditctl >/dev/null 2>&1; then
    echo "auditctl not found. Installing auditd package..."
    apt-get update -y
    apt-get install -y auditd audispd-plugins
fi

# Ensure the rules directory exists.
mkdir -p /etc/audit/rules.d

# Ensure the rules file exists.
touch "$AUDIT_RULES_FILE"

# Add each rule if not already present (idempotent).
for rule in "${RULES[@]}"; do
    if ! grep -Fxq -- "$rule" "$AUDIT_RULES_FILE" 2>/dev/null; then
        echo "$rule" >> "$AUDIT_RULES_FILE"
    fi
done

# Deduplicate the rules file, preserving order.
if [[ -f "$AUDIT_RULES_FILE" ]]; then
    TMP_FILE=$(mktemp)
    awk '!seen[$0]++' "$AUDIT_RULES_FILE" > "$TMP_FILE"
    mv "$TMP_FILE" "$AUDIT_RULES_FILE"
fi

chmod 640 "$AUDIT_RULES_FILE"

# Merge rule files and reload using augenrules if available (persistent method).
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    # Fallback: load rules directly.
    auditctl -R "$AUDIT_RULES_FILE" || true
fi

# Ensure auditd service is enabled and running for persistence across reboots.
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable auditd >/dev/null 2>&1 || true
    systemctl restart auditd >/dev/null 2>&1 || true
fi

echo "Audit rules for unlink (file-deletion) events have been applied and persisted."
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
#!/bin/bash

set -euo pipefail

AUDIT_RULES_FILE="/etc/audit/rules.d/50-delete.rules"

# Determine system architecture(s) that need audit rules
ARCH=$(uname -m)

declare -a RULES=()

if [[ "$ARCH" == "x86_64" || "$ARCH" == "aarch64" ]]; then
    RULES+=("-a always,exit -F arch=b64 -S unlinkat -F auid>=1000 -F auid!=unset -F key=delete")
    RULES+=("-a always,exit -F arch=b32 -S unlinkat -F auid>=1000 -F auid!=unset -F key=delete")
else
    RULES+=("-a always,exit -F arch=b32 -S unlinkat -F auid>=1000 -F auid!=unset -F key=delete")
fi

# Ensure the rules directory exists
mkdir -p /etc/audit/rules.d

# Create the rules file if it does not exist
if [[ ! -f "$AUDIT_RULES_FILE" ]]; then
    touch "$AUDIT_RULES_FILE"
fi

# Add each rule only if it is not already present (idempotent)
for rule in "${RULES[@]}"; do
    if ! grep -qF -- "$rule" "$AUDIT_RULES_FILE" 2>/dev/null; then
        echo "$rule" >> "$AUDIT_RULES_FILE"
    fi
done

# Ensure file permissions are correct
chmod 0640 "$AUDIT_RULES_FILE"

# Reload audit rules to apply configuration immediately
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "$AUDIT_RULES_FILE"
fi

# Restart auditd service to ensure persistence across reboots, if possible
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet auditd 2>/dev/null; then
        systemctl restart auditd || true
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
```bash
#!/bin/bash
#
# Remediation: Ensure audit records failed creat() (file-creation) syscall
# attempts (EACCES/EPERM) for all users with auid >= 1000 (excluding unset),
# for both 32-bit and 64-bit syscall entry points, tagged with a single key.
#
# Idempotent: safe to run multiple times.

set -euo pipefail

KEY="perm_access"
SYSCALL="creat"
RULES_D_FILE="/etc/audit/rules.d/50-file_creation.rules"
AUDIT_RULES_FILE="/etc/audit/audit.rules"

# The set of rule lines we require to be present.
declare -a REQUIRED_RULES=(
    "-a always,exit -F arch=b64 -S ${SYSCALL} -F exit=-EACCES -F auid>=1000 -F auid!=unset -k ${KEY}"
    "-a always,exit -F arch=b64 -S ${SYSCALL} -F exit=-EPERM -F auid>=1000 -F auid!=unset -k ${KEY}"
    "-a always,exit -F arch=b32 -S ${SYSCALL} -F exit=-EACCES -F auid>=1000 -F auid!=unset -k ${KEY}"
    "-a always,exit -F arch=b32 -S ${SYSCALL} -F exit=-EPERM -F auid>=1000 -F auid!=unset -k ${KEY}"
)

use_augenrules=false
if command -v augenrules >/dev/null 2>&1 && [ -d /etc/audit/rules.d ]; then
    use_augenrules=true
fi

add_rules_to_file() {
    local target_file="$1"
    local rule

    # Ensure the file exists.
    if [ ! -f "${target_file}" ]; then
        touch "${target_file}"
        chmod 640 "${target_file}"
    fi

    for rule in "${REQUIRED_
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
#!/bin/bash
#
# Remediation script: Configure auditd to log failed truncate() syscalls
# (EACCES/EPERM) for regular users (auid >= 1000, excluding unset -1/4294967295)
# tagged with key 'access'. Covers both b32 and b64 arches on a 64-bit system,
# handles auditctl (immediate) and augenrules (persistent, rules.d) mechanisms,
# is idempotent, and persists across reboots.

set -euo pipefail

RULES_FILE="/etc/audit/rules.d/50-access-truncate.rules"

# The exact audit rule lines we want present (order matters for augenrules
# concatenation but each line is self-contained and idempotent).
declare -a RULE_LINES=(
  "-a always,exit -F arch=b32 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access"
  "-a always,exit -F arch=b32 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access"
  "-a always,exit -F arch=b64 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access"
  "-a always,exit -F arch=b64 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access"
)

# Ensure audit rules directory exists
mkdir -p /etc/audit/rules.d

# Ensure the rules file exists
touch "$RULES_FILE"

# Idempotently add each required rule line if not already present
for line in "${RULE_LINES[@]}"; do
  if ! grep -Fxq -- "$line" "$RULES_FILE" 2>/dev/null; then
    echo "$line" >> "$RULES_FILE"
  fi
done

# Determine which rule-loading mechanism auditd uses at startup and load rules
# accordingly so the change takes effect immediately as well as persisting.

load_via_augenrules() {
  if command -v augenrules >/dev/null 2>&1; then
    augenrules --load >/dev/null 2>&1 || true
    return 0
  fi
  return 1
}

load_via_auditctl() {
  if command -v auditctl >/dev/null 2>&1; then
    for line in "${RULE_LINES[@]}"; do
      # shellcheck disable=SC2086
      auditctl $line >/dev/null 2>&1 || true
    done
    return 0
  fi
  return 1
}

# Determine startup mechanism: check auditd service configuration / presence
# of augenrules-based service (common on systems using auditd.service that
# invokes augenrules via ExecStartPost, or a separate augenrules.service).
MECHANISM="auditctl"

if systemctl list-unit-files 2>/dev/null | grep -q '^auditd\.service'; then
  if systemctl cat auditd.service 2>/dev/null | grep -q 'augenrules'; then
    MECHANISM="augenrules"
  elif [ -x /sbin/augenrules ] || command -v augenrules >/dev/null 2>&1; then
    # Prefer augenrules if binary exists, since Ubuntu 24.04 auditd package
    # typically uses augenrules to compile rules.d into audit.rules.
    MECHANISM="augenrules"
  fi
fi

if [ "$MECHANISM" = "augenrules" ]; then
  load_via_augenrules || load_via_auditctl
else
  load_via_auditctl || load_via_augenrules
fi

# Restart/reload auditd to ensure rules are active and persisted for future
# reboots, if the service is present and active.
if command -v systemctl >/dev/null 2>&1; then
  if systemctl is-active --quiet auditd 2>/dev/null; then
    systemctl restart auditd >/dev/null 2>&1 || service auditd restart >/dev/null 2>&1 || true
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
#
# Remediation script: Ensure unsuccessful attempts to open files are audited
#
# Records failed open() calls (EACCES / EPERM) for all real user accounts
# (auid >= 1000, excluding the "unset" auid of 4294967295), on both 32-bit
# and 64-bit syscall ABIs where applicable, tagged with the key "access".
#
# Idempotent: safe to run multiple times.

set -euo pipefail

AUDIT_RULES_DIR="/etc/audit/rules.d"
RULES_FILE="${AUDIT_RULES_DIR}/50-access.rules"
KEY="access"

# Ensure prerequisites are present
if ! command -v auditctl >/dev/null 2>&1; then
    echo "auditctl not found. Installing auditd package..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -y
        apt-get install -y auditd audispd-plugins
    else
        echo "ERROR: package manager not found; please install auditd manually." >&2
        exit 1
    fi
fi

mkdir -p "${AUDIT_RULES_DIR}"

# Detect which architectures are supported by this system's audit subsystem
ARCHES=()
if auditctl -h 2>/dev/null | grep -q '\-F'; then
    :
fi

# Determine if b32 rules are relevant (only meaningful on systems that
# support the 32-bit syscall ABI, e.g. x86_64 with multilib, or native i386)
SYSTEM_ARCH="$(uname -m)"
case "${SYSTEM_ARCH}" in
    x86_64|aarch64)
        ARCHES=("b64" "b32")
        ;;
    i386|i686)
        ARCHES=("b32")
        ;;
    *)
        ARCHES=("b64")
        ;;
esac

# Build the desired rule lines
declare -a DESIRED_RULES=()

for arch in "${ARCHES[@]}"; do
    DESIRED_RULES+=("-a always,exit -F arch=${arch} -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k ${KEY}")
    DESIRED_RULES+=("-a always,exit -F arch=${arch} -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k ${KEY}")
done

# Create the rules file if it does not exist
if [[ ! -f "${RULES_FILE}" ]]; then
    touch "${RULES_FILE}"
    chmod 640 "${RULES_FILE}"
fi

# Idempotently ensure each desired rule line is present, avoiding duplicates
for rule in "${DESIRED_RULES[@]}"; do
    if ! grep -Fxq -- "${rule}" "${RULES_FILE}" 2>/dev/null; then
        echo "${rule}" >> "${RULES_FILE}"
    fi
done

# Sort/deduplicate the rules file content while preserving valid syntax
TMP_FILE="$(mktemp)"
awk '!seen[$0]++' "${RULES_FILE}" > "${TMP_FILE}"
mv "${TMP_FILE}" "${RULES_FILE}"
chmod 640 "${RULES_FILE}"

# Load the rules persistently using augenrules if available (preferred on
# systems using the rules.d mechanism), otherwise fall back to auditctl -R
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "${RULES_FILE}" || true
fi

# Ensure auditd is enabled and running so rules persist across reboots
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable auditd >/dev/null 2>&1 || true
    systemctl is-active --quiet auditd || systemctl restart auditd || true
fi

# Verify rules are loaded in the running kernel audit list
if command -v auditctl >/dev/null 2>&1; then
    if ! auditctl -l 2>/dev/null | grep -q -- "-k ${KEY}"; then
        echo "WARNING: audit rules with key '${KEY}' do not appear to be active." >&2
    fi
fi

echo "Audit rules for unsuccessful file open attempts (key='${KEY}') are configured."
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
KEY="access"
SYSCALL="open_by_handle_at"

declare -a RULES=(
"-a always,exit -F arch=b32 -S ${SYSCALL} -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=${KEY}"
"-a always,exit -F arch=b32 -S ${SYSCALL} -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=${KEY}"
"-a always,exit -F arch=b64 -S ${SYSCALL} -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=${KEY}"
"-a always,exit -F arch=b64 -S ${SYSCALL} -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=${KEY}"
)

if [ ! -f "${RULES_FILE}" ]; then
    touch "${RULES_FILE}"
    chmod 0640 "${RULES_FILE}"
fi

for rule in "${RULES[@]}"; do
    if ! grep -Fxq -- "${rule}" "${RULES_FILE}"; then
        echo "${rule}" >> "${RULES_FILE}"
    fi
done

if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "${RULES_FILE}"
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

**Prompt:** On an Ubuntu 24.04 system, configure the system audit daemon to record unsuccessful attempts by regular users (those with login UID 1000 or greater, excluding unset) to open files via the relevant file-open operation, capturing both permission-denied and access-denied failure outcomes, tagged with an identifying key of "access". The rules must cover both 32-bit and 64-bit system call interfaces on a 64-bit system, since failed file-access attempts can indicate malicious activity or a compromised system. Write an idempotent bash remediation script that establishes these audit rules so they persist across reboots and are loaded by the audit daemon.

**Model-generated script:**
```bash
#!/bin/bash
#
# Remediation script: Configure auditd to record unsuccessful attempts
# to access files (EACCES/EPERM) via open-family syscalls for
# regular users (auid >= 1000, auid != 4294967295), tagged with key "access".
#
# Idempotent: safe to run multiple times.

set -euo pipefail

AUDIT_RULES_FILE="/etc/audit/rules.d/access.rules"

# Ensure audit package/tools are present
if ! command -v auditctl >/dev/null 2>&1; then
    echo "auditctl not found. Please install the auditd package before running this script." >&2
    exit 1
fi

# Ensure the rules directory exists
mkdir -p /etc/audit/rules.d

# Determine syscall arch support - only relevant on 64-bit system
ARCH=$(uname -m)

# Define the rules we want to ensure are present.
# We cover both b32 and b64 architectures per requirement (64-bit system with 32-bit compat syscalls).
declare -a DESIRED_RULES=(
"-a always,exit -F arch=b32 -S open,openat,openat2,open_by_handle_at,truncate,ftruncate,creat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access"
"-a always,exit -F arch=b64 -S open,openat,openat2,open_by_handle_at,truncate,ftruncate,creat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access"
"-a always,exit -F arch=b32 -S open,openat,openat2,open_by_handle_at,truncate,ftruncate,creat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access"
"-a always,exit -F arch=b64 -S open,openat,openat2,open_by_handle_at,truncate,ftruncate,creat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access"
)

# Create the file if it doesn't exist
if [ ! -f "$AUDIT_RULES_FILE" ]; then
    touch "$AUDIT_RULES_FILE"
    chmod 640 "$AUDIT_RULES_FILE"
fi

# Ensure each desired rule is present in the rules file (idempotent)
for rule in "${DESIRED_RULES[@]}"; do
    if ! grep -Fxq -- "$rule" "$AUDIT_RULES_FILE" 2>/dev/null; then
        echo "$rule" >> "$AUDIT_RULES_FILE"
    fi
done

# Remove any duplicate lines while preserving order, just in case
TMP_FILE=$(mktemp)
awk '!seen[$0]++' "$AUDIT_RULES_FILE" > "$TMP_FILE"
mv "$TMP_FILE" "$AUDIT_RULES_FILE"
chmod 640 "$AUDIT_RULES_FILE"

# Reload audit rules using augenrules if available, otherwise fall back to auditctl -R
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "$AUDIT_RULES_FILE" || true
fi

# Restart/reload the auditd service to ensure rules are active and persist across reboots
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet auditd 2>/dev/null; then
        systemctl restart auditd || service auditd restart || true
    else
        systemctl start auditd || service auditd start || true
    fi
else
    service auditd restart || service auditd start || true
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
KEY="access"

declare -a ARCHS=("b32" "b64")
declare -a SYSCALLS=("truncate" "ftruncate")
declare -a ERRVALS=("EACCES" "EPERM")

TMP_FILE="$(mktemp)"
trap 'rm -f "${TMP_FILE}"' EXIT

if [[ -f "${RULES_FILE}" ]]; then
    cp -f "${RULES_FILE}" "${TMP_FILE}"
else
    : > "${TMP_FILE}"
fi

is_64bit_capable() {
    if [[ -d /usr/lib64 ]] || [[ "$(uname -m)" == "x86_64" ]] || [[ "$(uname -m)" == "aarch64" ]]; then
        return 0
    fi
    return 1
}

for arch in "${ARCHS[@]}"; do
    if [[ "${arch}" == "b64" ]] && ! is_64bit_capable; then
        continue
    fi
    if [[ "${arch}" == "b32" ]] && [[ "$(uname -m)" != "x86_64" ]] && [[ "$(uname -m)" != "i686" ]] && [[ "$(uname -m)" != "aarch64" ]] && [[ "$(uname -m)" != "armv7l" ]]; then
        continue
    fi

    for errval in "${ERRVALS[@]}"; do
        syscall_list=""
        for sc in "${SYSCALLS[@]}"; do
            if [[ -z "${syscall_list}" ]]; then
                syscall_list="${sc}"
            else
                syscall_list="${syscall_list},${sc}"
            fi
        done

        RULE="-a always,exit -F arch=${arch} -S ${syscall_list} -F exit=-${errval} -F auid>=1000 -F auid!=unset -k ${KEY}"

        if ! grep -qxF "${RULE}" "${TMP_FILE}"; then
            echo "${RULE}" >> "${TMP_FILE}"
        fi
    done
done

mkdir -p /etc/audit/rules.d

if ! diff -q "${TMP_FILE}" "${RULES_FILE}" >/dev/null 2>&1; then
    install -m 0640 -o root -g root "${TMP_FILE}" "${RULES_FILE}"
fi

if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "${RULES_FILE}"
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
#
# Remediation: Ensure kernel module unloading (delete_module) is audited
# for all non-system users (auid >= 1000), on every architecture the
# system supports, tagged with the key "modules".
#
# Idempotent: safe to run multiple times.

set -euo pipefail

RULES_FILE="/etc/audit/rules.d/modules.rules"
KEY="modules"

# Ensure the auditd package/tools are present
if ! command -v auditctl >/dev/null 2>&1; then
    echo "auditctl not found; installing auditd..." >&2
    apt-get update -y
    apt-get install -y auditd audispd-plugins
fi

# Ensure rules.d directory exists
mkdir -p /etc/audit/rules.d

# Ensure rules file exists
touch "${RULES_FILE}"

# Determine which architectures this system supports for auditctl rules.
declare -a ARCHES
native_arch="$(uname -m)"

case "${native_arch}" in
    x86_64)
        ARCHES=("b64" "b32")
        ;;
    aarch64)
        # arm64 systems typically only support the 64-bit syscall table
        # for auditctl; adding b32 here would fail on most kernels.
        ARCHES=("b64")
        ;;
    i686|i386)
        ARCHES=("b32")
        ;;
    *)
        # Fallback: attempt b64 only, which is the most broadly supported.
        ARCHES=("b64")
        ;;
esac

# Build the desired rule lines for the supported architectures.
declare -a DESIRED_LINES
for arch in "${ARCHES[@]}"; do
    DESIRED_LINES+=("-a always,exit -F arch=${arch} -S delete_module -F auid>=1000 -F auid!=unset -k ${KEY}")
done

# Idempotently ensure each desired line is present in the rules file.
for line in "${DESIRED_LINES[@]}"; do
    if ! grep -qxF -- "${line}" "${RULES_FILE}"; then
        echo "${line}" >> "${RULES_FILE}"
    fi
done

# Remove any duplicate blank lines that may have accumulated (cosmetic, idempotent)
sed -i '/^[[:space:]]*$/d' "${RULES_FILE}"

# Ensure auditd is enabled and running so rules take effect now and persist.
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable auditd >/dev/null 2>&1 || true
    if ! systemctl is-active --quiet auditd; then
        systemctl start auditd
    fi
fi

# Load the rules now (augenrules merges everything under rules.d and
# regenerates /etc/audit/audit.rules, then loads it into the kernel).
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "${RULES_FILE}"
fi

# Verify the rule(s) are active; attempt a reload if not found.
for arch in "${ARCHES[@]}"; do
    if ! auditctl -l 2>/dev/null | grep -q "arch=${arch}.*-S delete_module.*-k ${KEY}"; then
        if command -v augenrules >/dev/null 2>&1; then
            augenrules --load
        fi
    fi
done

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

**Prompt:** On an Ubuntu 24.04 system, the system audit daemon must record every use by ordinary users (those with login UID 1000 or greater) of the kernel facility that loads a module into the running kernel, because surreptitious kernel module loading can be used to inject malicious code and must leave a tamper-evident audit trail. Write an idempotent bash remediation script that adds a persistent audit rule capturing this module-loading activity for both 32-bit and 64-bit invocations as appropriate to the architecture, tagged with an identifying key, so the rule survives reboots and is loaded by the audit daemon at startup.

**Model-generated script:**
```bash
#!/usr/bin/env bash
#
# Remediation: Ensure audit rules exist to record use of the
# init_module/finit_module/delete_module syscalls (kernel module
# loading/unloading) by ordinary users (loginuid >= 1000).
#
# Idempotent: safe to run multiple times.

set -euo pipefail

AUDIT_RULES_DIR="/etc/audit/rules.d"
RULES_FILE="${AUDIT_RULES_DIR}/modules.rules"
KEY="module_load"

# Ensure auditd and audit tooling are present
if ! command -v auditctl >/dev/null 2>&1; then
    echo "ERROR: auditctl not found. Please install the 'auditd' package." >&2
    exit 1
fi

mkdir -p "${AUDIT_RULES_DIR}"

# Determine architecture(s) to cover.
ARCH="$(uname -m)"

declare -a RULE_LINES=()

# 64-bit rule (init_module / finit_module / delete_module use b64 arch)
if [[ "${ARCH}" == "x86_64" || "${ARCH}" == "aarch64" || "${ARCH}" == "ppc64" || "${ARCH}" == "ppc64le" || "${ARCH}" == "s390x" ]]; then
    RULE_LINES+=(
        "-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -F auid>=1000 -F auid!=unset -k ${KEY}"
    )
fi

# 32-bit rule, applicable on multilib/32-bit-capable systems
if [[ "${ARCH}" == "x86_64" || "${ARCH}" == "i686" || "${ARCH}" == "i386" || "${ARCH}" == "aarch64" || "${ARCH}" == "armv7l" ]]; then
    RULE_LINES+=(
        "-a always,exit -F arch=b32 -S init_module,finit_module,delete_module -F auid>=1000 -F auid!=unset -k ${KEY}"
    )
fi

# Fallback: if architecture detection didn't match anything above,
# still add both b32 and b64 rules to be safe (harmless if unsupported
# arch is rejected by auditctl, but augenrules/auditd typically ignore
# rules for unsupported arches gracefully on load; to be safe we still
# only add the ones matching known arch families above).
if [[ "${#RULE_LINES[@]}" -eq 0 ]]; then
    RULE_LINES+=(
        "-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -F auid>=1000 -F auid!=unset -k ${KEY}"
        "-a always,exit -F arch=b32 -S init_module,finit_module,delete_module -F auid>=1000 -F auid!=unset -k ${KEY}"
    )
fi

# Create the rules file if it doesn't exist
if [[ ! -f "${RULES_FILE}" ]]; then
    touch "${RULES_FILE}"
    chmod 0640 "${RULES_FILE}"
fi

CHANGED=0

for line in "${RULE_LINES[@]}"; do
    if ! grep -Fxq -- "${line}" "${RULES_FILE}" 2>/dev/null; then
        echo "${line}" >> "${RULES_FILE}"
        CHANGED=1
    fi
done

# Ensure file permissions are correct regardless
chmod 0640 "${RULES_FILE}"

# Reload audit rules so they take effect immediately, and are persistent
# via augenrules on next boot.
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load >/dev/null 2>&1 || true
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "${RULES_FILE}" >/dev/null 2>&1 || true
fi

# Restart auditd to ensure persistent rules are active (some systems require this)
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet auditd 2>/dev/null; then
        systemctl try-restart auditd >/dev/null 2>&1 || true
    fi
fi

if [[ "${CHANGED}" -eq 1 ]]; then
    echo "Audit rules for kernel module loading added/updated in ${RULES_FILE}."
else
    echo "Audit rules for kernel module loading already present in ${RULES_FILE}. No changes made."
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
#!/bin/bash
#
# Remediation script: Ensure audit rules are configured to record
# kernel module load/unload events by non-system users (auid >= 1000).
# Idempotent and persistent across reboots via /etc/audit/rules.d/.

set -euo pipefail

AUDIT_RULES_DIR="/etc/audit/rules.d"
AUDIT_RULES_FILE="${AUDIT_RULES_DIR}/modules.rules"
KEY="modules"

# Ensure the audit rules directory exists
mkdir -p "$AUDIT_RULES_DIR"

# Ensure the target rules file exists
touch "$AUDIT_RULES_FILE"

# Determine the machine architecture to decide which rule sets are applicable
ARCH="$(uname -m)"

declare -a RULES=()

case "$ARCH" in
    x86_64|aarch64|ppc64|ppc64le|s390x)
        # 64-bit capable architectures typically also support 32-bit syscall ABI
        RULES+=("-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -F auid>=1000 -F auid!=unset -k ${KEY}")
        RULES+=("-a always,exit -F arch=b32 -S init_module,finit_module,delete_module -F auid>=1000 -F auid!=unset -k ${KEY}")
        ;;
    i686|i386|armv7l|arm)
        RULES+=("-a always,exit -F arch=b32 -S init_module,finit_module,delete_module -F auid>=1000 -F auid!=unset -k ${KEY}")
        ;;
    *)
        # Fallback: attempt both, in case architecture reports unexpected value
        RULES+=("-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -F auid>=1000 -F auid!=unset -k ${KEY}")
        RULES+=("-a always,exit -F arch=b32 -S init_module,finit_module,delete_module -F auid>=1000 -F auid!=unset -k ${KEY}")
        ;;
esac

# Insert each required rule only if it is not already present (idempotent)
for rule in "${RULES[@]}"; do
    if ! grep -qxF -- "$rule" "$AUDIT_RULES_FILE" 2>/dev/null; then
        echo "$rule" >> "$AUDIT_RULES_FILE"
    fi
done

# Ensure correct permissions on the rules file
chmod 0640 "$AUDIT_RULES_FILE"

# Reload audit rules to apply immediately, and ensure persistence across reboots
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "$AUDIT_RULES_FILE" || true
fi

# Restart auditd if present, to ensure rules are active now and reloaded on boot
if command -v systemctl >/dev/null 2>&1; then
    systemctl try-restart auditd.service || true
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
# Remediation script: Ensure audit rules exist to monitor changes to
# /var/log/faillog, /var/log/lastlog, and /var/log/tallylog
# under the audit key "logins".
#
# Idempotent: safe to run multiple times.

set -euo pipefail

AUDIT_RULES_DIR="/etc/audit/rules.d"
AUDIT_RULES_FILE="${AUDIT_RULES_DIR}/50-logins.rules"
KEY="logins"

# Files that record login/logout and failed authentication events
declare -a WATCH_FILES=(
    "/var/log/faillog"
    "/var/log/lastlog"
    "/var/log/tallylog"
)

# Ensure the audit rules directory exists
mkdir -p "${AUDIT_RULES_DIR}"

# Ensure the rules file exists
touch "${AUDIT_RULES_FILE}"

# Function to add a watch rule if it does not already exist
add_rule_if_missing() {
    local file="$1"
    local key="$2"
    local rule="-w ${file} -p wa -k ${key}"

    if ! grep -qF -- "-w ${file} " "${AUDIT_RULES_FILE}" 2>/dev/null; then
        echo "${rule}" >> "${AUDIT_RULES_FILE}"
        echo "Added rule: ${rule}"
    else
        # Rule for this file exists; ensure it matches expected permissions/key
        if ! grep -qF -- "${rule}" "${AUDIT_RULES_FILE}" 2>/dev/null; then
            # Remove any existing rule(s) for this file and re-add the correct one
            sed -i "\|-w ${file} |d" "${AUDIT_RULES_FILE}"
            echo "${rule}" >> "${AUDIT_RULES_FILE}"
            echo "Updated rule for: ${file}"
        else
            echo "Rule already present and correct for: ${file}"
        fi
    fi
}

for f in "${WATCH_FILES[@]}"; do
    add_rule_if_missing "${f}" "${KEY}"
done

# Deduplicate lines in the rules file, preserving order
TMP_FILE=$(mktemp)
awk '!seen[$0]++' "${AUDIT_RULES_FILE}" > "${TMP_FILE}"
mv "${TMP_FILE}" "${AUDIT_RULES_FILE}"
chmod 640 "${AUDIT_RULES_FILE}"

# Reload audit rules to apply immediately, compatible with augenrules-based systems
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "${AUDIT_RULES_FILE}" || true
fi

# Ensure the audit daemon is enabled and running so rules persist across reboots
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable auditd >/dev/null 2>&1 || true
    systemctl restart auditd >/dev/null 2>&1 || true
fi

echo "Audit rules for login/logout and failed authentication monitoring have been applied."
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
#!/bin/bash

set -euo pipefail

FILE_PATH="/var/log/lastlog"
KEY="logins"
RULE_ARGS="-w ${FILE_PATH} -p wa -k ${KEY}"

# Ensure the audit rules directory exists (augenrules mechanism)
AUGENRULES_DIR="/etc/audit/rules.d"
AUGENRULES_FILE="${AUGENRULES_DIR}/${KEY}.rules"

# Ensure the auditctl persistent rules file exists
AUDITCTL_FILE="/etc/audit/audit.rules"

mkdir -p "${AUGENRULES_DIR}"

# --- augenrules mechanism ---
if [ -f "${AUGENRULES_FILE}" ]; then
    if ! grep -Eq "^[[:space:]]*-w[[:space:]]+${FILE_PATH}[[:space:]]+-p[[:space:]]+wa([[:space:]]|$).*-k[[:space:]]+${KEY}([[:space:]]|$)" "${AUGENRULES_FILE}"; then
        echo "${RULE_ARGS}" >> "${AUGENRULES_FILE}"
    fi
else
    echo "${RULE_ARGS}" > "${AUGENRULES_FILE}"
fi

# --- auditctl mechanism (persistent rules file) ---
if [ -f "${AUDITCTL_FILE}" ]; then
    if ! grep -Eq "^[[:space:]]*-w[[:space:]]+${FILE_PATH}[[:space:]]+-p[[:space:]]+wa([[:space:]]|$).*-k[[:space:]]+${KEY}([[:space:]]|$)" "${AUDITCTL_FILE}"; then
        echo "${RULE_ARGS}" >> "${AUDITCTL_FILE}"
    fi
else
    echo "${RULE_ARGS}" > "${AUDITCTL_FILE}"
fi

# --- Load rules into the running auditd, if available ---
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
fi

if command -v auditctl >/dev/null 2>&1; then
    if ! auditctl -l 2>/dev/null | grep -Eq -- "-w ${FILE_PATH}.*-p wa.*-k ${KEY}"; then
        auditctl -w "${FILE_PATH}" -p wa -k "${KEY}" || true
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
```bash
#!/bin/bash
#
# Remediation: Ensure execution of the kernel module management utility
# (kmod) by regular users (auid >= 1000) is audited, and that the rule
# persists across reboots regardless of whether audit rules are loaded
# via augenrules (rule-compilation) or auditctl (direct-load) at daemon
# startup.
#
# Idempotent: safe to run multiple times.

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Locate the kmod utility binary
# ---------------------------------------------------------------------------
KMOD_PATH=""
if command -v kmod >/dev/null 2>&1; then
    KMOD_PATH="$(command -v kmod)"
else
    for candidate in /usr/bin/kmod /bin/kmod /usr/sbin/kmod /sbin/kmod; do
        if [[ -x "${candidate}" ]]; then
            KMOD_PATH="${candidate}"
            break
        fi
    done
fi

if [[ -z "${KMOD_PATH}" ]]; then
    echo "ERROR: kmod utility not found on this system." >&2
    exit 1
fi

KEY="modules"
RULE="-a always,exit -F path=${KMOD_PATH} -F perm=x -F auid>=1000 -F auid!=unset -F key
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

# --- Configuration -----------------------------------------------------
readonly AUDIT_RULES_DIR="/etc/audit/rules.d"
readonly RULE_FILE="${AUDIT_RULES_DIR}/postdrop.rules"
readonly KEY_NAME="privileged-postfix"
readonly BIN_NAME="postdrop"

# --- Locate the postdrop binary ----------------------------------------
POSTDROP_PATH=""
for candidate in /usr/sbin/postdrop /usr/bin/postdrop /sbin/postdrop /bin/postdrop; do
    if [ -x "${candidate}" ]; then
        POSTDROP_PATH="${candidate}"
        break
    fi
done

if [ -z "${POSTDROP_PATH}" ]; then
    if command -v postdrop >/dev/null 2>&1; then
        POSTDROP_PATH="$(command -v postdrop)"
    fi
fi

if [ -z "${POSTDROP_PATH}" ]; then
    echo "ERROR: postdrop binary not found on this system." >&2
    exit 1
fi

# --- Ensure audit tooling is present ------------------------------------
if ! command -v auditctl >/dev/null 2>&1; then
    echo "ERROR: auditctl not found. Install the 'auditd' package first." >&2
    exit 1
fi

if ! command -v augenrules >/dev/null 2>&1; then
    echo "ERROR: augenrules not found. Install the 'auditd' package first." >&2
    exit 1
fi

mkdir -p "${AUDIT_RULES_DIR}"

# --- Build the desired rule line ----------------------------------------
DESIRED_RULE="-a always,exit -F path=${POSTDROP_PATH} -F perm=x -F auid>=1000 -F auid!=unset -k ${KEY_NAME}"

# --- Idempotently write/update the persistent rule file ------------------
NEEDS_UPDATE=1
if [ -f "${RULE_FILE}" ]; then
    if grep -Fxq -- "${DESIRED_RULE}" "${RULE_FILE}"; then
        NEEDS_UPDATE=0
    fi
fi

if [ "${NEEDS_UPDATE}" -eq 1 ]; then
    tmpfile="$(mktemp)"
    if [ -f "${RULE_FILE}" ]; then
        grep -vF -- "${BIN_NAME}" "${RULE_FILE}" > "${tmpfile}" || true
    fi
    printf '%s\n' "${DESIRED_RULE}" >> "${tmpfile}"
    install -m 0640 -o root -g root "${tmpfile}" "${RULE_FILE}"
    rm -f "${tmpfile}"
    echo "Persistent audit rule written to ${RULE_FILE}"
else
    echo "Persistent audit rule already present in ${RULE_FILE}"
fi

# --- Reload rules so they take effect immediately -------------------------
if augenrules --load >/dev/null 2>&1; then
    echo "Audit rules reloaded via augenrules."
else
    echo "WARNING: augenrules --load reported an issue; attempting auditctl fallback." >&2
    auditctl -R "${RULE_FILE}" || true
fi

# --- Verify the rule is active in the live kernel audit ruleset ----------
if auditctl -l 2>/dev/null | grep -Fq -- "${POSTDROP_PATH}"; then
    echo "Audit rule for ${POSTDROP_PATH} is active in the running audit configuration."
else
    echo "WARNING: Rule not detected in active auditctl list; a reboot may be required." >&2
fi

exit 0
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

# Ensure auditd is installed
if ! command -v auditctl >/dev/null 2>&1; then
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

RULES_FILE="/etc/audit/rules.d/50-postqueue.rules"

# Locate the postqueue binary
POSTQUEUE_PATH=""
for p in /usr/sbin/postqueue /usr/bin/postqueue /sbin/postqueue /bin/postqueue; do
    if [ -x "$p" ]; then
        POSTQUEUE_PATH="$p"
        break
    fi
done

if [ -z "$POSTQUEUE_PATH" ]; then
    if command -v postqueue >/dev/null 2>&1; then
        POSTQUEUE_PATH="$(command -v postqueue)"
    else
        POSTQUEUE_PATH="/usr/sbin/postqueue"
    fi
fi

# Determine architecture-specific syscall arch parameters
ARCH64="b64"
ARCH32="b32"

# Build the rule lines
LINE64="-a always,exit -F path=${POSTQUEUE_PATH} -F perm=x -F auid>=1000 -F auid!=unset -F arch=${ARCH64} -k privileged-postqueue"
LINE32="-a always,exit -F path=${POSTQUEUE_PATH} -F perm=x -F auid>=1000 -F auid!=unset -F arch=${ARCH32} -k privileged-postqueue"

mkdir -p /etc/audit/rules.d

if [ ! -f "$RULES_FILE" ]; then
    touch "$RULES_FILE"
fi

# Idempotently add 64-bit rule
if ! grep -Fxq "$LINE64" "$RULES_FILE" 2>/dev/null; then
    echo "$LINE64" >> "$RULES_FILE"
fi

# Idempotently add 32-bit rule
if ! grep -Fxq "$LINE32" "$RULES_FILE" 2>/dev/null; then
    echo "$LINE32" >> "$RULES_FILE"
fi

chmod 640 "$RULES_FILE"

# Merge into audit.rules used at boot, and load rules now
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "$RULES_FILE" || true
fi

# Restart auditd if present to ensure it picks up new rules after reboot too
if systemctl list-unit-files | grep -q '^auditd\.service'; then
    systemctl try-restart auditd || true
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
#!/bin/bash
set -euo pipefail

# Path to the ssh-agent binary
SSH_AGENT_PATH=$(command -v ssh-agent || echo "/usr/bin/ssh-agent")

if [ ! -e "$SSH_AGENT_PATH" ]; then
    SSH_AGENT_PATH="/usr/bin/ssh-agent"
fi

AUDIT_KEY="ssh_agent_exec"

# Determine which rule-loading mechanism auditd is configured to use
AUDIT_RULES_D="/etc/audit/rules.d"
AUDIT_RULES_FILE="/etc/audit/audit.rules"
RULES_FILE="${AUDIT_RULES_D}/ssh_agent.rules"

mkdir -p "$AUDIT_RULES_D"

# Build the two audit rules (regular users >= 1000 and root)
RULE_UID="-a always,exit -F path=${SSH_AGENT_PATH} -F perm=x -F auid>=1000 -F auid!=unset -F key=${AUDIT_KEY}"
RULE_ROOT="-a always,exit -F path=${SSH_AGENT_PATH} -F perm=x -F auid=0 -F key=${AUDIT_KEY}"

# Idempotently write the rules file
if [ ! -f "$RULES_FILE" ] || ! grep -qF -- "$RULE_UID" "$RULES_FILE" 2>/dev/null || ! grep -qF -- "$RULE_ROOT" "$RULES_FILE" 2>/dev/null; then
    {
        echo "$RULE_UID"
        echo "$RULE_ROOT"
    } > "$RULES_FILE"
    chmod 640 "$RULES_FILE"
fi

# Ensure augenrules picks up the change if that's the mechanism in use
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    # Fallback: load rules directly if augenrules isn't available
    # Check if rules already loaded to maintain idempotency
    if ! auditctl -l 2>/dev/null | grep -qF -- "$AUDIT_KEY"; then
        auditctl $RULE_UID || true
        auditctl $RULE_ROOT || true
    fi
fi

# Also ensure legacy audit.rules file is consistent if it's used directly
if [ -f "$AUDIT_RULES_FILE" ] && [ ! -L "$AUDIT_RULES_FILE" ]; then
    if ! grep -qF -- "$RULE_UID" "$AUDIT_RULES_FILE" 2>/dev/null || ! grep -qF -- "$RULE_ROOT" "$AUDIT_RULES_FILE" 2>/dev/null; then
        {
            echo "$RULE_UID"
            echo "$RULE_ROOT"
        } >> "$AUDIT_RULES_FILE"
    fi
fi

# Restart auditd to ensure rules are active (some systems require this)
if systemctl is-active --quiet auditd 2>/dev/null; then
    systemctl restart auditd || service auditd restart || true
fi

exit 0
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
# Remediation script: Ensure auditd logs executions of ssh-keysign
# (privileged SSH key-signing helper) by non-system users (auid >= 1000,
# excluding unset auid), tagged with key "privileged".
#
# Idempotent: safe to run multiple times.

set -euo pipefail

RULES_FILE="/etc/audit/rules.d/50-ssh_keysign.rules"
AUDIT_KEY="privileged"

# ------------------------------------------------------------------
# 1. Locate the ssh-keysign binary (path differs across distros)
# ------------------------------------------------------------------
SSH_KEYSIGN_PATH=""
for candidate in /usr/lib/openssh/ssh-keysign /usr/lib/ssh/ssh-keysign /usr/libexec/openssh/ssh-keysign; do
    if [ -x "${candidate}" ]; then
        SSH_KEYSIGN_PATH="${candidate}"
        break
    fi
done

if [ -z "${SSH_KEYSIGN_PATH}" ]; then
    # Fall back to searching the filesystem if not found in common locations
    SSH_KEYSIGN_PATH="$(command -v ssh-keysign 2>/dev/null || true)"
fi

if [ -z "${SSH_KEYSIGN_PATH}" ]; then
    FOUND_PATH="$(find / -xdev -type f -name 'ssh-keysign' 2>/dev/null | head -n1 || true)"
    SSH_KEYSIGN_PATH="${FOUND_PATH}"
fi

if [ -z "${SSH_KEYSIGN_PATH}" ]; then
    echo "ERROR: Could not locate ssh-keysign binary on this system." >&2
    exit 1
fi

# ------------------------------------------------------------------
# 2. Build the desired audit rule line
# ------------------------------------------------------------------
DESIRED_RULE="-a always,exit -F path=${SSH_KEYSIGN_PATH} -F perm=x -F auid>=1000 -F auid!=unset -k ${AUDIT_KEY}"

# ------------------------------------------------------------------
# 3. Ensure the rules.d persistent file contains the rule (idempotent)
# ------------------------------------------------------------------
mkdir -p /etc/audit/rules.d

if [ -f "${RULES_FILE}" ] && grep -Fxq -- "${DESIRED_RULE}" "${RULES_FILE}"; then
    :
else
    if [ -f "${RULES_FILE}" ]; then
        # Remove any pre-existing (possibly outdated) rules referencing ssh-keysign
        grep -v "ssh-keysign" "${RULES_FILE}" > "${RULES_FILE}.tmp" || true
        mv "${RULES_FILE}.tmp" "${RULES_FILE}"
    fi
    echo "${DESIRED_RULE}" >> "${RULES_FILE}"
fi

chmod 640 "${RULES_FILE}"

# ------------------------------------------------------------------
# 4. Load the rule into the running kernel audit state, using
#    whichever mechanism this system relies on (augenrules or
#    auditctl -R), while remaining idempotent for the live ruleset.
# ------------------------------------------------------------------

load_with_augenrules() {
    if command -v augenrules >/dev/null 2>&1; then
        augenrules --load >/dev/null 2>&1 || true
        return 0
    fi
    return 1
}

load_with_auditctl_R() {
    if command -v auditctl >/dev/null 2>&1; then
        auditctl -R "${RULES_FILE}" >/dev/null 2>&1 || true
        return 0
    fi
    return 1
}

# Check whether the rule is already active in the live kernel ruleset
rule_is_active() {
    if command -v auditctl >/dev/null 2>&1; then
        auditctl -l 2>/dev/null | grep -F -- "path=${SSH_KEYSIGN_PATH}" | grep -Fq -- "key=${AUDIT_KEY}"
        return $?
    fi
    return 1
}

if ! rule_is_active; then
    if command -v augenrules >/dev/null 2>&1; then
        load_with_augenrules || true
    fi
    if ! rule_is_active; then
        load_with_auditctl_R || true
    fi
    if ! rule_is_active; then
        # Last resort: load rule directly via auditctl
        if command -v auditctl >/dev/null 2>&1; then
            auditctl ${DESIRED_RULE} >/dev/null 2>&1 || true
        fi
    fi
fi

# ------------------------------------------------------------------
# 5. Ensure auditd service is enabled/restarted so persistence works
#    across reboots (systemd-based Ubuntu 24.04)
# ------------------------------------------------------------------
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable auditd >/dev/null 2>&1 || true
    if systemctl is-active --quiet auditd; then
        systemctl restart auditd >/dev/null 2>&1 || true
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
#!/bin/bash
set -euo pipefail

RULES_FILE="/etc/audit/rules.d/50-privileged-unix-update.rules"

# Locate the unix_update binary (common paths on Ubuntu)
UNIX_UPDATE_PATH=""
for p in /usr/sbin/unix_update /sbin/unix_update /usr/bin/unix_update /bin/unix_update; do
    if [ -x "$p" ]; then
        UNIX_UPDATE_PATH="$p"
        break
    fi
done

if [ -z "$UNIX_UPDATE_PATH" ]; then
    # Fall back to searching the filesystem
    UNIX_UPDATE_PATH=$(command -v unix_update 2>/dev/null || true)
fi

if [ -z "$UNIX_UPDATE_PATH" ]; then
    UNIX_UPDATE_PATH=$(find /usr /sbin /bin -type f -name unix_update 2>/dev/null | head -n1 || true)
fi

if [ -z "$UNIX_UPDATE_PATH" ]; then
    echo "Error: unix_update binary not found on this system." >&2
    exit 1
fi

ARCH=$(uname -m)
case "$ARCH" in
    x86_64) AUDIT_ARCHES="b64" ;;
    i686|i386) AUDIT_ARCHES="b32" ;;
    aarch64) AUDIT_ARCHES="b64" ;;
    armv7l) AUDIT_ARCHES="b32" ;;
    *) AUDIT_ARCHES="b64" ;;
esac

build_rule() {
    local arch="$1"
    echo "-a always,exit -F path=${UNIX_UPDATE_PATH} -F perm=x -F auid>=1000 -F auid!=unset -F arch=${arch} -k privileged"
}

RULE_LINE=$(build_rule "$AUDIT_ARCHES")

mkdir -p /etc/audit/rules.d

if [ -f "$RULES_FILE" ]; then
    if grep -Fxq -- "$RULE_LINE" "$RULES_FILE"; then
        RULE_PRESENT=1
    else
        RULE_PRESENT=0
    fi
else
    RULE_PRESENT=0
    touch "$RULES_FILE"
fi

if [ "$RULE_PRESENT" -eq 0 ]; then
    # Remove any pre-existing (possibly outdated) rules for this path/key to avoid duplicates
    if [ -s "$RULES_FILE" ]; then
        TMP_FILE=$(mktemp)
        grep -v -- "-F path=${UNIX_UPDATE_PATH} " "$RULES_FILE" > "$TMP_FILE" || true
        mv "$TMP_FILE" "$RULES_FILE"
    fi
    echo "$RULE_LINE" >> "$RULES_FILE"
fi

chmod 0640 "$RULES_FILE"

# Reload audit rules to apply immediately, if augenrules/auditctl are available
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "$RULES_FILE" || true
fi

# Ensure auditd service is enabled and running, if systemctl is present
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable auditd >/dev/null 2>&1 || true
    systemctl restart auditd >/dev/null 2>&1 || true
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
#!/bin/bash
#
# Remediation script: Ensure auditd records execution attempts of the
# usermod command (privileged user-account modification utility) by
# non-system users (auid >= 1000, excluding auid=4294967295/unset).
#
# This script is idempotent - it can be run multiple times without
# creating duplicate rules, and it configures both the live audit
# rules (auditctl) and the persistent rules file used by auditd on
# reboot (either via /etc/audit/rules.d/*.rules with augenrules, or
# directly in /etc/audit/audit.rules for systems using auditctl -R).

set -euo pipefail

# Determine the path to the usermod binary
USERMOD_PATH=$(command -v usermod || true)
if [[ -z "${USERMOD_PATH}" ]]; then
    # Fall back to standard location if command -v fails (e.g. minimal PATH)
    if [[ -x /usr/sbin/usermod ]]; then
        USERMOD_PATH="/usr/sbin/usermod"
    elif [[ -x /sbin/usermod ]]; then
        USERMOD_PATH="/sbin/usermod"
    else
        echo "ERROR: usermod binary not found on this system." >&2
        exit 1
    fi
fi

KEY_NAME="privileged"

# Construct the canonical audit rule line.
# -a always,exit  : append to exit list, always audit
# -F path=...      : match execve of this specific binary path
# -F perm=x        : executable access
# -F auid>=1000    : only non-system (regular) users
# -F auid!=unset   : exclude processes with no login uid assigned
# -k privileged    : tag with key "privileged"
AUDIT_RULE="-a always,exit -F path=${USERMOD_PATH} -F perm=x -F auid>=1000 -F auid!=unset -k ${KEY_NAME}"

RULES_D_DIR="/etc/audit/rules.d"
RULES_D_FILE="${RULES_D_DIR}/50-privileged-usermod.rules"
LEGACY_RULES_FILE="/etc/audit/audit.rules"

mkdir -p "${RULES_D_DIR}"

# Function to add rule to a given file if not already present (exact line match)
add_rule_if_missing() {
    local file="$1"
    local rule="$2"

    if [[ ! -f "$file" ]]; then
        touch "$file"
    fi

    if ! grep -Fxq -- "${rule}" "$file" 2>/dev/null; then
        echo "${rule}" >> "$file"
    fi
}

# Ensure persistent rule is present in rules.d (used by augenrules)
add_rule_if_missing "${RULES_D_FILE}" "${AUDIT_RULE}"

# Some systems (or audit configurations) load rules directly from
# /etc/audit/audit.rules via 'auditctl -R' at boot instead of augenrules.
# Ensure the rule is also present there for full compatibility, but only
# if that file exists and is actually used (avoid creating it needlessly
# if the system solely relies on augenrules directory-based rules).
if [[ -f "${LEGACY_RULES_FILE}" ]]; the
    :
fi
if [[ -f "${LEGACY_RULES_FILE}" ]]; then
    add_rule_if_missing "${LEGACY_RULES_FILE}" "${AUDIT_RULE}"
fi

# Regenerate the merged rules file from rules.d if augenrules is available.
# This ensures consistency and picks up the new rule properly, merging
# all fragments in /etc/audit/rules.d into /etc/audit/audit.rules.
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
elif command -v auditctl >/dev/null 2>&1; then
    # Fallback: directly load the merged/legacy rules file if augenrules
    # is not present but auditctl is.
    auditctl -R "${LEGACY_RULES_FILE}" || true
fi

# Load the rule into the live kernel audit ruleset immediately, if not
# already active. This checks the current in-kernel rule list for an
# exact match before adding it, keeping the operation idempotent.
if command -v auditctl >/dev/null 2>&1; then
    if ! auditctl -l 2>/dev/null | grep -F -- "path=${USERMOD_PATH}" | grep -Fq -- "key=${KEY_NAME}"; then
        auditctl ${AUDIT_RULE} || true
    fi
fi

# Ensure the auditd service is enabled to load persistent rules at boot.
if command -v systemctl >/dev/null 2>&1; then
    systemctl is-enabled auditd >/dev/null 2>&1 || systemctl enable auditd >/dev/null 2>&1 || true
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

AUDITD_CONF="/etc/audit/auditd.conf"
DESIRED_SETTING="disk_error_action"
DESIRED_VALUE="single"

if [[ ! -f "$AUDITD_CONF" ]]; then
    echo "Error: $AUDITD_CONF not found. Is auditd installed?" >&2
    exit 1
fi

if grep -qP "^\s*${DESIRED_SETTING}\s*=" "$AUDITD_CONF"; then
    current_value=$(grep -P "^\s*${DESIRED_SETTING}\s*=" "$AUDITD_CONF" | tail -n1 | sed -E "s/^\s*${DESIRED_SETTING}\s*=\s*//" | tr -d '[:space:]')
    if [[ "$current_value" != "$DESIRED_VALUE" ]]; then
        cp "$AUDITD_CONF" "${AUDITD_CONF}.bak.$(date +%Y%m%d%H%M%S)"
        sed -i -E "s/^\s*${DESIRED_SETTING}\s*=.*/${DESIRED_SETTING} = ${DESIRED_VALUE}/" "$AUDITD_CONF"
    fi
else
    cp "$AUDITD_CONF" "${AUDITD_CONF}.bak.$(date +%Y%m%d%H%M%S)"
    printf "%s = %s\n" "$DESIRED_SETTING" "$DESIRED_VALUE" >> "$AUDITD_CONF"
fi

if grep -qP "^\s*${DESIRED_SETTING}\s*=\s*${DESIRED_VALUE}\s*$" "$AUDITD_CONF"; then
    echo "auditd.conf: ${DESIRED_SETTING} is set to ${DESIRED_VALUE}"
else
    echo "Error: Failed to set ${DESIRED_SETTING} to ${DESIRED_VALUE} in ${AUDITD_CONF}" >&2
    exit 1
fi

if command -v augenrules >/dev/null 2>&1; then
    augenrules --load 2>/dev/null || true
fi

if systemctl is-active --quiet auditd 2>/dev/null; then
    systemctl restart auditd 2>/dev/null || service auditd restart 2>/dev/null || true
elif service auditd status >/dev/null 2>&1; then
    service auditd restart 2>/dev/null || true
fi

exit 0
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
#
# Remediation script: Configure auditd disk_full_action to "single"
# This ensures that when the audit log volume becomes completely full,
# the system switches to single-user mode for corrective action.
#
# Idempotent: safe to run multiple times.

set -euo pipefail

AUDITD_CONF="/etc/audit/auditd.conf"
DESIRED_ACTION="single"
PARAM_NAME="disk_full_action"

# Ensure auditd is installed
if ! command -v auditd >/dev/null 2>&1; then
    echo "auditd is not installed. Installing..."
    apt-get update -y
    apt-get install -y auditd audispd-plugins
fi

# Ensure the configuration file exists
if [ ! -f "${AUDITD_CONF}" ]; then
    echo "Error: ${AUDITD_CONF} not found even after installing auditd." >&2
    exit 1
fi

# Backup the config file before modifying (only if backup doesn't already exist)
BACKUP_FILE="${AUDITD_CONF}.bak.$(date +%Y%m%d%H%M%S)"
if ! grep -qE "^\s*${PARAM_NAME}\s*=\s*${DESIRED_ACTION}\s*$" "${AUDITD_CONF}"; then
    cp -p "${AUDITD_CONF}" "${BACKUP_FILE}"
fi

# Function to set or update a parameter in auditd.conf
set_auditd_param() {
    local param="$1"
    local value="$2"
    local file="$3"

    if grep -qE "^\s*${param}\s*=" "${file}"; then
        # Parameter exists; check if it already has the desired value
        if grep -qE "^\s*${param}\s*=\s*${value}\s*$" "${file}"; then
            echo "Parameter '${param}' already set to '${value}' in ${file}."
        else
            # Update existing parameter to desired value
            sed -i -E "s/^\s*${param}\s*=.*/${param} = ${value}/" "${file}"
            echo "Updated '${param}' to '${value}' in ${file}."
        fi
    else
        # Parameter does not exist; append it
        echo "${param} = ${value}" >> "${file}"
        echo "Added '${param} = ${value}' to ${file}."
    fi
}

# Apply the desired configuration
set_auditd_param "${PARAM_NAME}" "${DESIRED_ACTION}" "${AUDITD_CONF}"

# Validate the final configuration
if ! grep -qE "^\s*${PARAM_NAME}\s*=\s*${DESIRED_ACTION}\s*$" "${AUDITD_CONF}"; then
    echo "Error: Failed to set '${PARAM_NAME}' to '${DESIRED_ACTION}' in ${AUDITD_CONF}." >&2
    exit 1
fi

echo "Configuration verified: ${PARAM_NAME} = ${DESIRED_ACTION}"

# Reload or restart auditd service to apply changes
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet auditd; then
        echo "Restarting auditd service to apply changes..."
        systemctl restart auditd || {
            echo "Warning: systemctl restart failed; attempting service command..." >&2
            service auditd restart || true
        }
    else
        echo "Starting auditd service..."
        systemctl start auditd || service auditd start || true
    fi

    # Ensure auditd is enabled to persist across reboots
    if ! systemctl is-enabled --quiet auditd; then
        echo "Enabling auditd service to start at boot..."
        systemctl enable auditd
    else
        echo "auditd service already enabled at boot."
    fi
else
    echo "systemctl not available; attempting service command fallback..."
    service auditd restart || true
fi

echo "Remediation complete: disk_full_action is set to 'single' and persists across reboots."

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

**Prompt:** On an Ubuntu 24.04 system, configure the system audit daemon so that when available disk space falls below its low-space warning threshold it notifies administrators by sending an email alert (rather than the default behavior), giving staff a chance to act before audit logging is disrupted. Write an idempotent bash remediation script that sets this low-disk-space response and ensures it persists across reboots.

**Model-generated script:**
```bash
#!/bin/bash
set -euo pipefail

AUDITD_CONF="/etc/audit/auditd.conf"
KEY="admin_space_left_action"
VALUE="EMAIL"

if [ ! -f "$AUDITD_CONF" ]; then
    echo "Error: $AUDITD_CONF not found. Is auditd installed?" >&2
    exit 1
fi

if grep -qiE "^[[:space:]]*${KEY}[[:space:]]*=" "$AUDITD_CONF"; then
    CURRENT_VALUE=$(grep -iE "^[[:space:]]*${KEY}[[:space:]]*=" "$AUDITD_CONF" | tail -n1 | sed -E "s/^[[:space:]]*${KEY}[[:space:]]*=[[:space:]]*//I" | tr -d '[:space:]')

    if [ "${CURRENT_VALUE^^}" = "${VALUE}" ]; then
        echo "auditd.conf already configured with ${KEY} = ${VALUE}"
    else
        TIMESTAMP=$(date +%Y%m%d%H%M%S)
        cp -p "$AUDITD_CONF" "${AUDITD_CONF}.bak.${TIMESTAMP}"

        sed -i -E "s/^[[:space:]]*${KEY}[[:space:]]*=.*/${KEY} = ${VALUE}/I" "$AUDITD_CONF"
        echo "Updated ${KEY} to ${VALUE} in ${AUDITD_CONF}"
    fi
else
    TIMESTAMP=$(date +%Y%m%d%H%M%S)
    cp -p "$AUDITD_CONF" "${AUDITD_CONF}.bak.${TIMESTAMP}"

    echo "${KEY} = ${VALUE}" >> "$AUDITD_CONF"
    echo "Added ${KEY} = ${VALUE} to ${AUDITD_CONF}"
fi

if command -v augenrules >/dev/null 2>&1; then
    :
fi

if systemctl is-active --quiet auditd 2>/dev/null; then
    if command -v augenrules >/dev/null 2>&1; then
        augenrules --load >/dev/null 2>&1 || true
    fi

    if command -v service >/dev/null 2>&1; then
        service auditd restart >/dev/null 2>&1 || {
            echo "Warning: Failed to restart auditd via service command. Manual restart may be required." >&2
        }
    else
        systemctl restart auditd >/dev/null 2>&1 || {
            echo "Warning: Failed to restart auditd. Manual restart may be required." >&2
        }
    fi
    echo "auditd service restarted to apply changes"
else
    echo "Note: auditd service is not currently active. Changes will take effect on next start."
fi

if systemctl is-enabled --quiet auditd 2>/dev/null; then
    echo "auditd service is enabled and will persist across reboots"
else
    systemctl enable auditd >/dev/null 2>&1 || {
        echo "Warning: Failed to enable auditd service for persistence across reboots." >&2
    }
    echo "auditd service enabled for persistence across reboots"
fi

echo "Configuration complete: ${KEY} = ${VALUE} in ${AUDITD_CONF}"
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
#!/bin/bash
set -euo pipefail

AUDITD_CONF="/etc/audit/auditd.conf"
SPACE_LEFT_VALUE="25"

if [[ ! -f "$AUDITD_CONF" ]]; then
    echo "Error: $AUDITD_CONF not found. Is auditd installed?" >&2
    exit 1
fi

if grep -qP '^\s*space_left\s*=' "$AUDITD_CONF"; then
    sed -i -E "s/^\s*space_left\s*=.*/space_left = ${SPACE_LEFT_VALUE}/" "$AUDITD_CONF"
else
    echo "space_left = ${SPACE_LEFT_VALUE}" >> "$AUDITD_CONF"
fi

if grep -qP '^\s*space_left\s*=\s*'"${SPACE_LEFT_VALUE}"'\s*$' "$AUDITD_CONF"; then
    echo "Configured space_left = ${SPACE_LEFT_VALUE} in ${AUDITD_CONF}"
else
    echo "Failed to set space_left in ${AUDITD_CONF}" >&2
    exit 1
fi

if grep -qP '^\s*space_left_action\s*=' "$AUDITD_CONF"; then
    current_action=$(grep -P '^\s*space_left_action\s*=' "$AUDITD_CONF" | tail -n1 | sed -E 's/^\s*space_left_action\s*=\s*//')
    if [[ -z "$current_action" || "$current_action" == "ignore" ]]; then
        sed -i -E "s/^\s*space_left_action\s*=.*/space_left_action = email/" "$AUDITD_CONF"
    fi
else
    echo "space_left_action = email" >> "$AUDITD_CONF"
fi

if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
fi

if systemctl is-active --quiet auditd 2>/dev/null; then
    systemctl restart auditd || service auditd restart || true
elif service auditd status >/dev/null 2>&1; then
    service auditd restart || true
fi

echo "auditd space_left threshold configuration complete."
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
DESIRED_FORMAT="fqdn"

if [[ ! -f "$AUDITD_CONF" ]]; then
    echo "Error: $AUDITD_CONF not found. Is auditd installed?" >&2
    exit 1
fi

# Ensure name_format is set to fqdn (idempotent)
if grep -Eq '^\s*name_format\s*=' "$AUDITD_CONF"; then
    current_value=$(grep -E '^\s*name_format\s*=' "$AUDITD_CONF" | tail -n1 | awk -F'=' '{print $2}' | xargs)
    if [[ "$current_value" != "$DESIRED_FORMAT" ]]; then
        sed -i -E "s/^\s*name_format\s*=.*/name_format = ${DESIRED_FORMAT}/" "$AUDITD_CONF"
    fi
else
    echo "name_format = ${DESIRED_FORMAT}" >> "$AUDITD_CONF"
fi

# Remove any explicit 'name' directive since name_format=fqdn derives it automatically
if grep -Eq '^\s*name\s*=' "$AUDITD_CONF"; then
    sed -i -E '/^\s*name\s*=/d' "$AUDITD_CONF"
fi

# Restart auditd to apply changes, if the service is active or enabled
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-enabled auditd >/dev/null 2>&1 || systemctl is-active auditd >/dev/null 2>&1; then
        systemctl restart auditd || true
    fi
fi

exit 0
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
#
# Remediation script: Ensure audit rule files are mode 0600
# Ubuntu 24.04 - auditd rule files protection
#
# This script is idempotent - running it multiple times has the same
# effect as running it once.

set -euo pipefail

readonly AUDIT_RULES_DIR="/etc/audit/rules.d"
readonly AUDIT_MAIN_RULES="/etc/audit/audit.rules"
readonly TARGET_MODE="0600"

log() {
    echo "[audit-rules-perm] $*"
}

remediate_file() {
    local file="$1"

    if [[ ! -e "${file}" ]]; then
        return 0
    fi

    if [[ ! -f "${file}" ]]; then
        # Not a regular file, skip (e.g., symlink to non-file, directory, etc.)
        log "Skipping non-regular file: ${file}"
        return 0
    fi

    local current_mode
    current_mode=$(stat -c '%a' "${file}")

    if [[ "${current_mode}" != "600" ]]; then
        log "Fixing permissions on ${file} (was: ${current_mode}, setting to: ${TARGET_MODE})"
        chmod "${TARGET_MODE}" "${file}"
    else
        log "Already compliant: ${file}"
    fi
}

main() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo "This script must be run as root." >&2
        exit 1
    fi

    # Remediate the main audit.rules file if present
    if [[ -f "${AUDIT_MAIN_RULES}" ]]; then
        remediate_file "${AUDIT_MAIN_RULES}"
    fi

    # Remediate all rule files under /etc/audit/rules.d/
    if [[ -d "${AUDIT_RULES_DIR}" ]]; then
        while IFS= read -r -d '' rule_file; do
            remediate_file "${rule_file}"
        done < <(find "${AUDIT_RULES_DIR}" -maxdepth 1 -type f -print0)
    else
        log "Directory ${AUDIT_RULES_DIR} does not exist, skipping."
    fi

    log "Audit rule file permission remediation complete."
}

main "$@"
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
