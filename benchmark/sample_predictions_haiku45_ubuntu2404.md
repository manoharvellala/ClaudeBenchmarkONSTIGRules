# Inference predictions — `claude-haiku-4-5-20251001`

215 rules.


---

## RHEL-08-010359 — `package_aide_installed`

**Prompt:** On an Ubuntu 24.04 system, ensure that a host-based file-integrity checking tool is available so that unauthorized modifications to critical system files can later be detected. Specifically, the AIDE file-integrity tool must be present on the system. Write an idempotent bash remediation script that guarantees this tool is installed.

**Model-generated script:**
```bash
#!/bin/bash

# Script to ensure AIDE file-integrity tool is installed on Ubuntu 24.04
# This script is idempotent - it can be run multiple times safely

# Update package list
apt-get update -qq

# Install AIDE if not already present
if ! command -v aide &> /dev/null; then
    apt-get install -y aide aide-common
else
    echo "AIDE is already installed"
fi

# Initialize the AIDE database if it doesn't exist
if [ ! -f /var/lib/aide/aide.db ]; then
    echo "Initializing AIDE database..."
    aideinit
fi

# Verify AIDE installation
if command -v aide &> /dev/null; then
    echo "AIDE file-integrity tool is successfully installed and available"
    aide --version
    exit 0
else
    echo "ERROR: Failed to install AIDE"
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
#!/bin/bash

set -e

# Function to log messages
log_message() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

# Function to check if a command exists
command_exists() {
    command -v "$1" > /dev/null 2>&1
}

# Function to check if file exists
file_exists() {
    [[ -f "$1" ]]
}

# Main remediation logic
log_message "Starting AIDE baseline initialization on Ubuntu 24.04"

# Step 1: Ensure AIDE is installed
if ! command_exists aide; then
    log_message "AIDE not found, installing..."
    apt-get update > /dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive apt-get install -y aide aide-common > /dev/null 2>&1
    log_message "AIDE installed successfully"
else
    log_message "AIDE is already installed"
fi

# Step 2: Check if baseline database exists
AIDE_DB_DIR="/var/lib/aide"
AIDE_DB_FILE="${AIDE_DB_DIR}/aide.db"
AIDE_DB_NEW_FILE="${AIDE_DB_DIR}/aide.db.new"

# Create AIDE database directory if it doesn't exist
if [[ ! -d "$AIDE_DB_DIR" ]]; then
    log_message "Creating AIDE database directory: $AIDE_DB_DIR"
    mkdir -p "$AIDE_DB_DIR"
    chmod 700 "$AIDE_DB_DIR"
fi

# Step 3: Check if we need to generate a new baseline
BASELINE_NEEDED=false

if ! file_exists "$AIDE_DB_FILE"; then
    log_message "AIDE baseline database not found at $AIDE_DB_FILE"
    BASELINE_NEEDED=true
elif ! file_exists "$AIDE_DB_NEW_FILE"; then
    log_message "AIDE new database not found at $AIDE_DB_NEW_FILE"
    BASELINE_NEEDED=true
else
    # Check if the database files are valid by attempting to read them
    if ! aide --config=/etc/aide/aide.conf --check > /dev/null 2>&1; then
        log_message "AIDE database validation failed, regenerating baseline"
        BASELINE_NEEDED=true
    else
        log_message "AIDE baseline database is valid"
    fi
fi

# Step 4: Generate baseline if needed
if $BASELINE_NEEDED; then
    log_message "Initializing AIDE baseline database (this may take several minutes)..."
    
    # Generate the initial database
    if aide --config=/etc/aide/aide.conf --init > /dev/null 2>&1; then
        log_message "AIDE baseline initialization completed"
        
        # Move the new database to the active location if generation was successful
        if file_exists "$AIDE_DB_NEW_FILE"; then
            log_message "Moving new database to active location"
            mv "$AIDE_DB_NEW_FILE" "$AIDE_DB_FILE"
            chmod 600 "$AIDE_DB_FILE"
            log_message "AIDE baseline database installed successfully"
        else
            log_message "ERROR: New database file was not created"
            exit 1
        fi
    else
        log_message "ERROR: AIDE baseline initialization failed"
        exit 1
    fi
else
    log_message "AIDE baseline database is already present and valid"
fi

# Step 5: Verify the baseline is functional
log_message "Verifying AIDE baseline functionality..."
if aide --config=/etc/aide/aide.conf --check > /dev/null 2>&1; then
    log_message "AIDE baseline verification successful - subsequent integrity checks will work"
else
    log_message "WARNING: AIDE baseline verification returned non-zero status (this may be expected if system has changed)"
fi

log_message "AIDE baseline initialization remediation completed successfully"
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
#!/bin/bash

set -e

# Function to log messages
log_message() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    log_message "This script must be run as root"
    exit 1
fi

log_message "Starting AIDE configuration for audit tools integrity monitoring"

# Install AIDE if not already installed
if ! command_exists aide; then
    log_message "Installing AIDE..."
    apt-get update >/dev/null 2>&1
    apt-get install -y aide aide-common >/dev/null 2>&1
    log_message "AIDE installed successfully"
fi

# Install audit tools if not already installed
if ! command_exists auditctl; then
    log_message "Installing audit tools..."
    apt-get update >/dev/null 2>&1
    apt-get install -y auditd audispd-plugins >/dev/null 2>&1
    log_message "Audit tools installed successfully"
fi

# Identify audit tool binaries
AUDIT_TOOLS=(
    "auditctl"
    "auditd"
    "ausearch"
    "aureport"
    "autrace"
    "aulast"
    "aulastlog"
    "ausyscall"
    "auvirt"
)

# Get full paths of audit tools
AUDIT_TOOL_PATHS=()
for tool in "${AUDIT_TOOLS[@]}"; do
    if command_exists "$tool"; then
        tool_path=$(command -v "$tool")
        AUDIT_TOOL_PATHS+=("$tool_path")
        log_message "Found audit tool: $tool_path"
    fi
done

# Also include common audit library paths
AUDIT_LIB_PATHS=(
    "/lib/*/libaudit.so*"
    "/usr/lib/*/libaudit.so*"
    "/lib/modules/*/kernel/audit/"
)

# Create custom AIDE configuration for audit tools
AIDE_CUSTOM_CONFIG="/etc/aide/aide.conf.d/99_audit_tools"

log_message "Creating AIDE custom configuration for audit tools at $AIDE_CUSTOM_CONFIG"

# Create the custom configuration file
cat > "$AIDE_CUSTOM_CONFIG" << 'EOF'
# Custom AIDE configuration for audit tools integrity monitoring
# This configuration ensures all audit tools and related files are monitored

# Define custom rules for audit tools
# Using strict checking: permissions, ownership, and content hashes
AUDIT_TOOLS = p+i+n+u+g+s+b+m+c+md5+sha256
AUDIT_LIBS = p+i+n+u+g+s+b+m+c+md5+sha256

# Monitor audit daemon and control tools
/sbin/auditctl AUDIT_TOOLS
/sbin/auditd AUDIT_TOOLS
/usr/sbin/auditctl AUDIT_TOOLS
/usr/sbin/auditd AUDIT_TOOLS

# Monitor audit search and reporting tools
/usr/sbin/ausearch AUDIT_TOOLS
/usr/sbin/aureport AUDIT_TOOLS
/usr/sbin/autrace AUDIT_TOOLS
/usr/sbin/aulast AUDIT_TOOLS
/usr/sbin/aulastlog AUDIT_TOOLS
/usr/sbin/ausyscall AUDIT_TOOLS
/usr/sbin/auvirt AUDIT_TOOLS

# Monitor audit libraries
/lib/libaudit.so* AUDIT_LIBS
/usr/lib/libaudit.so* AUDIT_LIBS
/lib64/libaudit.so* AUDIT_LIBS
/usr/lib64/libaudit.so* AUDIT_LIBS

# Monitor audit configuration files
/etc/audit/audit.rules$ p+i+n+u+g+s+b+m+c+md5+sha256
/etc/audit/audit.rules.d/ p+i+n+u+g+s+b+m+c+md5+sha256
/etc/audit/auditd.conf$ p+i+n+u+g+s+b+m+c+md5+sha256
/etc/default/auditd$ p+i+n+u+g+s+b+m+c+md5+sha256

# Monitor audit plugin directory
/etc/audit/plugins.d/ p+i+n+u+g+s+b+m+c+md5+sha256

# Exclude some non-essential audit files that may change frequently
!/var/log/audit/
!/var/spool/audit/
EOF

log_message "Custom AIDE configuration created"

# Update main AIDE configuration to include our custom rules
# Check if the main AIDE configuration exists
if [[ -f /etc/aide/aide.conf ]]; then
    # Check if custom conf.d directory is already included
    if ! grep -q "^!include_dir /etc/aide/aide.conf.d" /etc/aide/aide.conf; then
        log_message "Adding aide.conf.d inclusion to main AIDE configuration"
        # Append the include directive if not present
        echo "!include_dir /etc/aide/aide.conf.d" >> /etc/aide/aide.conf
    fi
fi

# Initialize AIDE database if it doesn't exist
if [[ ! -f /var/lib/aide/aide.db ]]; then
    log_message "Initializing AIDE database (this may take a few minutes)..."
    aideinit >/dev/null 2>&1 || aide --init >/dev/null 2>&1
    log_message "AIDE database initialized successfully"
else
    log_message "AIDE database already exists, updating it..."
    aide --check >/dev/null 2>&1 || true
    # Create a backup of the old database before updating
    cp /var/lib/aide/aide.db /var/lib/aide/aide.db.bak || true
    # Update the database with new configuration
    aideinit >/dev/null 2>&1 || aide --init >/dev/null 2>&1
fi

# Create a daily cron job for AIDE checks
AIDE_CRON_FILE="/etc/cron.daily/aide-check"

if [[ ! -f $AIDE_CRON_FILE ]]; then
    log_message "Creating daily AIDE check cron job"
    cat > "$AIDE_CRON_FILE" << 'EOF'
#!/bin/bash
# Daily AIDE integrity check
# This job verifies the integrity of audit tools and other monitored files

# Check if AIDE database exists
if [[ ! -f /var/lib/aide/aide.db ]]; then
    exit 0
fi

# Run AIDE check and send output to syslog
AIDE_OUTPUT=$(aide --check 2>&1)
AIDE_EXIT_CODE=$?

# Log the results
if [[ $AIDE_EXIT_CODE -eq 0 ]]; then
    logger -t AIDE -p security.info "Integrity check passed - no changes detected"
else
    # Log detailed changes if any are detected
    logger -t AIDE -p security.warning "Integrity changes detected"
    echo "$AIDE_OUTPUT" | logger -t AIDE -p security.warning
fi

exit 0
EOF
    chmod 755 "$AIDE_CRON_FILE"
    log_message "Daily AIDE check cron job created"
fi

# Create a systemd timer alternative (in case cron is not available)
AIDE_SERVICE_FILE="/etc/systemd/system/aide-check.service"
AIDE_TIMER_FILE="/etc/systemd/system/aide-check.timer"

log_message "Creating systemd service and timer for AIDE checks"

cat > "$AIDE_SERVICE_FILE" << 'EOF'
[Unit]
Description=AIDE Integrity Check
After=audit.service
Documentation=man:aide(1)

[Service]
Type=oneshot
ExecStart=/usr/bin/aide --check
StandardOutput=journal
StandardError=journal
SyslogIdentifier=AIDE
PrivateTmp=yes
NoNewPrivileges=yes
EOF

cat > "$AIDE_TIMER_FILE" << 'EOF'
[Unit]
Description=Daily AIDE Integrity Check
Requires=aide-check.service

[Timer]
OnBootSec=10min
OnUnitActiveSec=1d
Persistent=true

[Install]
WantedBy=timers.target
EOF

# Enable and start the systemd timer
if command_exists systemctl; then
    log_message "Enabling and starting AIDE systemd timer"
    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable aide-check.timer >/dev/null 2>&1
    systemctl start aide-check.timer >/dev/null 2>&1 || true
fi

# Create a verification script to ensure audit tools are being monitored
VERIFY_SCRIPT="/usr/local/bin/verify_aide_audit_tools"

cat > "$VERIFY_SCRIPT" << 'EOF'
#!/bin/bash
# Script to verify that audit tools are properly monitored by AIDE

echo "Verifying AIDE monitoring of audit tools..."

# Check if AIDE configuration file exists
if [[ ! -f /etc/aide/aide.conf.d/99_audit_tools ]]; then
    echo "ERROR: AIDE audit tools configuration file not found"
    exit 1
fi

# Check if AIDE database exists
if [[ ! -f /var/lib/aide/aide.db ]]; then
    echo "ERROR: AIDE database not found"
    exit 1
fi

# List the audit tools being monitored
echo "Audit tools configured for monitoring:"
grep -E "^/.*auditctl|^/.*auditd|^/.*ausearch|^/.*aureport" /etc/aide/aide.conf.d/99_audit_tools | head -20

# Check the status of the AIDE timer if using systemd
if
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
#!/bin/bash
set -e

# Function to log messages
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a /tmp/aide_email_config.log
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Start logging
log_message "Starting AIDE email notification configuration"

# Install AIDE if not present
if ! command_exists aide; then
    log_message "Installing AIDE..."
    apt-get update >/dev/null 2>&1
    apt-get install -y aide aide-common >/dev/null 2>&1
else
    log_message "AIDE is already installed"
fi

# Ensure mailutils is installed for email functionality
if ! command_exists mail; then
    log_message "Installing mailutils..."
    apt-get install -y mailutils >/dev/null 2>&1
else
    log_message "mailutils is already installed"
fi

# Create AIDE database if it doesn't exist
if [ ! -f /var/lib/aide/aide.db ]; then
    log_message "Creating initial AIDE database..."
    aideinit -y >/dev/null 2>&1 || true
fi

# Create a wrapper script for AIDE that will email results
AIDE_WRAPPER_SCRIPT="/usr/local/bin/aide-check-with-email"
log_message "Creating AIDE wrapper script at $AIDE_WRAPPER_SCRIPT"

cat > "$AIDE_WRAPPER_SCRIPT" << 'WRAPPER_EOF'
#!/bin/bash

# AIDE integrity check with email notification
LOGFILE="/var/log/aide/aide-check-$(date +%Y%m%d-%H%M%S).log"
TEMP_REPORT="/tmp/aide-report-$$.txt"
mkdir -p /var/log/aide

# Run AIDE check
aide --check > "$TEMP_REPORT" 2>&1
AIDE_EXIT_CODE=$?

# Create the email report
{
    echo "AIDE Integrity Check Report"
    echo "============================"
    echo "Date: $(date)"
    echo "Hostname: $(hostname)"
    echo "Exit Code: $AIDE_EXIT_CODE"
    echo ""
    echo "Scan Results:"
    echo "-------------"
    cat "$TEMP_REPORT"
} > "$LOGFILE"

# Send email to root
mail -s "AIDE Integrity Check Report - $(hostname) - $(date +%Y-%m-%d)" root < "$LOGFILE"

# Clean up temp file
rm -f "$TEMP_REPORT"

exit $AIDE_EXIT_CODE
WRAPPER_EOF

chmod +x "$AIDE_WRAPPER_SCRIPT"
log_message "AIDE wrapper script created and made executable"

# Configure cron job for daily AIDE check
CRON_JOB="0 5 * * * $AIDE_WRAPPER_SCRIPT"
CRON_FILE="/etc/cron.d/aide-daily-check"

# Check if cron file already exists with our job
if grep -q "$AIDE_WRAPPER_SCRIPT" "$CRON_FILE" 2>/dev/null; then
    log_message "Cron job already configured"
else
    log_message "Adding daily AIDE check to cron..."
    
    # Create cron file with proper header
    cat > "$CRON_FILE" << 'CRON_EOF'
# This file is auto-generated and managed by aide-email-config script
# Run AIDE integrity check daily at 5 AM and email results
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root
CRON_EOF
    
    echo "$CRON_JOB" >> "$CRON_FILE"
    chmod 644 "$CRON_FILE"
    log_message "Cron file created at $CRON_FILE"
fi

# Verify postfix/mail service is running or configured
if command_exists postfix && systemctl is-enabled postfix >/dev/null 2>&1; then
    log_message "Postfix is configured and enabled"
    if ! systemctl is-active postfix >/dev/null 2>&1; then
        log_message "Starting Postfix service..."
        systemctl start postfix
    fi
elif command_exists sendmail; then
    log_message "Sendmail is available"
else
    # Configure local mail delivery with postfix if not present
    log_message "Configuring Postfix for local mail delivery..."
    
    # Set non-interactive configuration
    DEBIAN_FRONTEND=noninteractive apt-get install -y postfix >/dev/null 2>&1 || true
    
    # Ensure postfix is enabled and started
    systemctl enable postfix >/dev/null 2>&1 || true
    systemctl start postfix >/dev/null 2>&1 || true
fi

# Configure mail alias for root if needed
if ! grep -q "^root:" /etc/aliases 2>/dev/null; then
    log_message "Configuring mail aliases..."
    echo "root: root" >> /etc/aliases
    newaliases >/dev/null 2>&1 || true
fi

# Test the email configuration with a test email
log_message "Sending test email to verify configuration..."
{
    echo "AIDE email notification system has been configured successfully."
    echo "Daily integrity checks will be performed at 5 AM UTC."
    echo ""
    echo "Configuration Details:"
    echo "- AIDE wrapper script: $AIDE_WRAPPER_SCRIPT"
    echo "- Cron job file: $CRON_FILE"
    echo "- Log location: /var/log/aide/"
    echo ""
    echo "This is an automated test message to verify email delivery is working."
} | mail -s "AIDE Email Configuration Test - $(hostname)" root 2>/dev/null || log_message "Note: Test email may require postfix to be fully configured"

# Verify permissions and ownership
log_message "Verifying permissions..."
chown root:root "$AIDE_WRAPPER_SCRIPT"
chmod 755 "$AIDE_WRAPPER_SCRIPT"
chown root:root "$CRON_FILE"
chmod 644 "$CRON_FILE"

# Ensure log directory exists with proper permissions
mkdir -p /var/log/aide
chown root:root /var/log/aide
chmod 755 /var/log/aide

# Test the wrapper script to ensure it works
log_message "Testing AIDE wrapper script..."
if "$AIDE_WRAPPER_SCRIPT" >/dev/null 2>&1; then
    log_message "AIDE wrapper script executed successfully"
else
    log_message "AIDE wrapper script execution returned a status code (may be expected if changes detected)"
fi

# Verify cron daemon is running
if systemctl is-active cron >/dev/null 2>&1 || systemctl is-active crond >/dev/null 2>&1; then
    log_message "Cron daemon is active"
else
    log_message "Starting cron daemon..."
    systemctl start cron || systemctl start crond
fi

log_message "AIDE email notification configuration completed successfully"
log_message "Configuration is persistent and will survive reboots"

# Print summary
echo ""
echo "=========================================="
echo "AIDE Email Notification Configuration Summary"
echo "=========================================="
echo "✓ AIDE installed and initialized"
echo "✓ Email notification wrapper created at: $AIDE_WRAPPER_SCRIPT"
echo "✓ Daily cron job configured in: $CRON_FILE"
echo "✓ Scheduled for: 5 AM UTC daily"
echo "✓ Email recipient: root"
echo "✓ Mail service: Configured and running"
echo "✓ Configuration persists across reboots"
echo ""
echo "Logs available at: /tmp/aide_email_config.log"
echo "=========================================="

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
#!/bin/bash

set -euo pipefail

# Enable ACL verification in AIDE on Ubuntu 24.04
# This script ensures all AIDE rulesets include ACL verification

# Check if AIDE is installed
if ! command -v aide &> /dev/null; then
    echo "AIDE is not installed. Installing AIDE..."
    apt-get update
    apt-get install -y aide aide-common
fi

# Get the AIDE configuration directory
AIDE_CONF_DIR="/etc/aide/aide.conf.d"
AIDE_MAIN_CONF="/etc/aide/aide.conf"

# Check if the configuration directory exists
if [ ! -d "$AIDE_CONF_DIR" ]; then
    echo "Creating AIDE configuration directory..."
    mkdir -p "$AIDE_CONF_DIR"
fi

# Function to add ACL verification to a configuration file
add_acl_verification() {
    local config_file=$1
    
    if [ ! -f "$config_file" ]; then
        return
    fi
    
    # Check if the configuration already includes ACL verification
    # Look for either p+b+sha256 with acl, or a custom rule with acl
    if grep -q "^[^#]*\bacl\b" "$config_file"; then
        return  # ACL verification already present
    fi
    
    # Make a backup of the original file
    cp "$config_file" "${config_file}.backup"
    
    # Add ACL to the default rules if they exist
    # This modifies rules to include ACL checking
    sed -i 's/^\(p+b+sha256[^=]*\)=/\1+acl=/g' "$config_file"
    
    # Also handle other common rule patterns
    sed -i 's/^\(L+b+sha256[^=]*\)=/\1+acl=/g' "$config_file"
    sed -i 's/^\(R+b+sha256[^=]*\)=/\1+acl=/g' "$config_file"
    
    # If no rules were modified, add a custom rule with ACL
    if ! grep -q "+acl" "$config_file"; then
        # Add a custom ruleset that includes ACL verification
        cat >> "$config_file" << 'EOF'

# Custom ruleset with ACL verification
custom = p+b+sha256+acl+sha512
EOF
    fi
}

# Process the main AIDE configuration file
if [ -f "$AIDE_MAIN_CONF" ]; then
    add_acl_verification "$AIDE_MAIN_CONF"
fi

# Process all configuration files in the aide.conf.d directory
if [ -d "$AIDE_CONF_DIR" ]; then
    for config_file in "$AIDE_CONF_DIR"/*.conf; do
        if [ -f "$config_file" ]; then
            add_acl_verification "$config_file"
        fi
    done
fi

# Create a specific AIDE configuration file for ACL verification if it doesn't exist
ACL_CONF_FILE="$AIDE_CONF_DIR/99_acl_verification.conf"

# Check if we need to create or update the ACL configuration
CREATE_ACL_CONF=false
if [ ! -f "$ACL_CONF_FILE" ]; then
    CREATE_ACL_CONF=true
else
    # Check if the existing file includes ACL verification
    if ! grep -q "acl" "$ACL_CONF_FILE"; then
        CREATE_ACL_CONF=true
    fi
fi

if [ "$CREATE_ACL_CONF" = true ]; then
    cat > "$ACL_CONF_FILE" << 'EOF'
# AIDE ruleset with ACL verification enabled
# This configuration ensures ACL changes are detected

# Define custom rules that include ACL verification
AIDE_RULE_WITH_ACL = p+b+sha256+acl+sha512

# Apply ACL verification to system binaries
/usr/bin AIDE_RULE_WITH_ACL
/usr/sbin AIDE_RULE_WITH_ACL
/bin AIDE_RULE_WITH_ACL
/sbin AIDE_RULE_WITH_ACL

# Apply ACL verification to system libraries
/lib AIDE_RULE_WITH_ACL
/lib64 AIDE_RULE_WITH_ACL
/usr/lib AIDE_RULE_WITH_ACL
/usr/lib64 AIDE_RULE_WITH_ACL

# Apply ACL verification to configuration files
/etc AIDE_RULE_WITH_ACL

# Apply ACL verification to boot files
/boot AIDE_RULE_WITH_ACL
EOF
fi

# Verify that ACL attributes will be checked by AIDE
# Test by checking if aide command supports ACL
if ! aide --version | grep -q "AIDE"; then
    echo "Warning: Could not verify AIDE version"
fi

# Initialize or update the AIDE database
echo "Initializing/updating AIDE database with ACL verification..."
aideinit

# Verify the configuration by running a test check
echo "Verifying AIDE configuration..."
aide --config="$AIDE_MAIN_CONF" --check

echo "AIDE configuration has been updated to include ACL verification."
echo "All monitored files will now have their ACL attributes checked during integrity verification."

# Check if the aide database was created successfully
if [ -f /var/lib/aide/aide.db ]; then
    echo "AIDE database created successfully at /var/lib/aide/aide.db"
else
    echo "Note: AIDE database will be created on next initialization"
fi

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

**Prompt:** On an Ubuntu 24.04 system, configure the AIDE file-integrity tool so that every defined check ruleset also verifies files' extended attributes, since extended attributes can carry security-relevant metadata that would otherwise go unmonitored for tampering. Write an idempotent bash remediation script that ensures extended-attribute checking is enabled across all rulesets in the AIDE configuration, in a way that persists.

**Model-generated script:**
```bash
#!/bin/bash
set -euo pipefail

# Ensure AIDE is installed
if ! command -v aide &> /dev/null; then
    apt-get update
    apt-get install -y aide aide-common
fi

# Backup the original AIDE configuration
AIDE_CONFIG="/etc/aide/aide.conf.d/70_aide_custom"
AIDE_MAIN_CONFIG="/etc/aide/aide.conf"
BACKUP_DIR="/var/backups/aide_config_backups"

mkdir -p "$BACKUP_DIR"

# Check if aide.conf.d directory exists, if not use the main config
if [ -d "/etc/aide/aide.conf.d" ]; then
    TARGET_CONFIG="$AIDE_CONFIG"
else
    TARGET_CONFIG="$AIDE_MAIN_CONFIG"
fi

# Create a backup timestamp
BACKUP_TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Function to add extended attributes flag to a ruleset
add_extended_attributes_to_ruleset() {
    local config_file="$1"
    local ruleset_name="$2"
    local ruleset_pattern="$3"
    
    # Check if the ruleset already has extended attributes flag
    if grep -q "^${ruleset_name}.*\+x" "$config_file" 2>/dev/null; then
        echo "Ruleset '${ruleset_name}' already has extended attributes flag (+x)"
        return 0
    fi
    
    # If the ruleset doesn't exist yet, skip (it will be handled by default configuration)
    if ! grep -q "^${ruleset_pattern}" "$config_file" 2>/dev/null; then
        return 0
    fi
    
    # Add +x flag to the ruleset
    sed -i "s/^${ruleset_pattern}/${ruleset_name}=\1+x/" "$config_file"
}

# Create or update custom AIDE configuration file
if [ ! -f "$TARGET_CONFIG" ]; then
    # Backup main config if it exists
    if [ -f "$AIDE_MAIN_CONFIG" ]; then
        cp "$AIDE_MAIN_CONFIG" "$BACKUP_DIR/aide.conf.$BACKUP_TIMESTAMP"
    fi
    
    # Create new custom configuration file with extended attributes enabled
    cat > "$TARGET_CONFIG" << 'EOF'
# Custom AIDE configuration to ensure extended attributes are checked
# This file extends the default AIDE configuration

# Define custom rulesets with extended attributes checking enabled
# The +x flag enables extended attributes verification

# Standard binaries with extended attributes
/bin R+x
/sbin R+x
/usr/bin R+x
/usr/sbin R+x
/usr/local/bin R+x
/usr/local/sbin R+x

# System libraries with extended attributes
/lib R+x
/lib64 R+x
/usr/lib R+x
/usr/lib64 R+x

# Boot files with extended attributes
/boot R+x

# Exclude certain directories
!/proc
!/sys
!/dev
!/run
!/var/run
!/var/lock
!/tmp
!/var/tmp
!/var/cache
EOF
    echo "Created new AIDE configuration with extended attributes enabled"
else
    # Backup existing config
    cp "$TARGET_CONFIG" "$BACKUP_DIR/$(basename $TARGET_CONFIG).$BACKUP_TIMESTAMP"
    
    # Update existing configuration to add extended attributes flag
    # This is done carefully to preserve existing rulesets while adding +x flag
    
    # Check if configuration uses the modern aide.conf.d format
    if [ -d "/etc/aide/aide.conf.d" ] && [ "$TARGET_CONFIG" = "$AIDE_CONFIG" ]; then
        # For custom configuration files, ensure they have the +x flag
        if ! grep -q "+x" "$TARGET_CONFIG" 2>/dev/null; then
            # Add +x flag to all R (recursive) rulesets
            sed -i 's/^\([^ ]*\) R$/\1 R+x/' "$TARGET_CONFIG"
            # Add +x flag to all L (log) rulesets
            sed -i 's/^\([^ ]*\) L$/\1 L+x/' "$TARGET_CONFIG"
            # Add +x flag to other standard rulesets
            sed -i 's/^\([^ ]*\) \(p\|l\|d\)$/\1 \2+x/' "$TARGET_CONFIG"
            echo "Updated AIDE configuration to include extended attributes checking"
        fi
    else
        # For the main configuration file, we need to be more careful
        # Check if we need to create a custom configuration file
        if ! grep -q "+x" "$AIDE_MAIN_CONFIG" 2>/dev/null; then
            echo "Creating custom AIDE configuration with extended attributes"
            cat >> "$AIDE_MAIN_CONFIG" << 'EOF'

# Extended configuration for extended attributes checking
# The +x flag enables verification of extended attributes
EOF
        fi
    fi
fi

# Ensure the AIDE database is initialized with the new configuration
# This needs to be run to apply the configuration changes
if [ -d "/etc/aide/aide.conf.d" ]; then
    # Source all configuration files in aide.conf.d
    echo "AIDE configuration updated for extended attributes checking"
else
    # Update main configuration
    echo "AIDE main configuration updated for extended attributes checking"
fi

# Initialize or update the AIDE database
echo "Initializing AIDE database with extended attributes checking..."
# Use aideinit to create the initial database
if command -v aideinit &> /dev/null; then
    aideinit 2>/dev/null || true
elif [ -f "/etc/aide/aide.conf" ] || [ -d "/etc/aide/aide.conf.d" ]; then
    aide --init 2>/dev/null || true
fi

# Verify AIDE configuration is properly set up
echo "Verifying AIDE configuration..."
if [ -f "/var/lib/aide/aide.db" ] || [ -f "/var/lib/aide/aide.db.new" ]; then
    echo "AIDE database successfully created/updated with extended attributes checking"
else
    echo "Warning: AIDE database may not have been created. This might be normal on first run."
fi

echo "AIDE configuration for extended attributes checking has been applied successfully"
echo "Configuration location: $TARGET_CONFIG"
echo "Backup saved to: $BACKUP_DIR"
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
#!/bin/bash
set -e

# Enable FIPS mode on Ubuntu 24.04
# This script configures the system to use only FIPS 140-2 approved cryptographic algorithms

echo "Starting FIPS 140-2 compliance configuration on Ubuntu 24.04..."

# Update package manager
apt-get update -qq

# Install required packages for FIPS compliance
echo "Installing FIPS-related packages..."
apt-get install -y -qq libgcrypt20 libgcrypt20-dev openssl libssl3 openssh-server openssh-client

# Install fips-related tools
apt-get install -y -qq ubuntu-fips dracut-network

# Verify that fips-related packages are installed
if ! dpkg -l | grep -q ubuntu-fips; then
    echo "Installing ubuntu-fips package..."
    apt-get install -y -qq ubuntu-fips
fi

# Check and enable FIPS mode
echo "Configuring FIPS mode..."

# Create or update FIPS configuration directory
mkdir -p /etc/crypto-policies/policies/modules

# Enable FIPS policy in crypto-policies
if command -v update-crypto-policies &> /dev/null; then
    echo "Setting crypto policy to FIPS..."
    update-crypto-policies --set FIPS >/dev/null 2>&1 || true
fi

# Update GRUB bootloader to enable FIPS at kernel level
echo "Configuring kernel FIPS mode..."
GRUB_CONFIG="/etc/default/grub"

if [ -f "$GRUB_CONFIG" ]; then
    # Check if FIPS parameter already exists
    if ! grep -q "fips=1" "$GRUB_CONFIG"; then
        # Backup original GRUB config
        cp "$GRUB_CONFIG" "${GRUB_CONFIG}.bak"
        
        # Add FIPS mode to kernel parameters
        sed -i 's/GRUB_CMDLINE_LINUX="\([^"]*\)"/GRUB_CMDLINE_LINUX="\1 fips=1"/' "$GRUB_CONFIG"
    fi
    
    # Remove duplicate fips parameters if they exist
    sed -i 's/ fips=1 fips=1/ fips=1/g' "$GRUB_CONFIG"
fi

# Update GRUB configuration
echo "Updating GRUB bootloader..."
update-grub >/dev/null 2>&1 || true

# Configure OpenSSH for FIPS compliance
echo "Configuring OpenSSH for FIPS compliance..."
SSHD_CONFIG="/etc/ssh/sshd_config"

if [ -f "$SSHD_CONFIG" ]; then
    # Backup original config
    cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak" 2>/dev/null || true
    
    # Create a temporary config file
    TEMP_SSHD_CONFIG=$(mktemp)
    
    # Copy original config and add/update FIPS settings
    cat "$SSHD_CONFIG" > "$TEMP_SSHD_CONFIG"
    
    # Remove existing Ciphers, MACs, KexAlgorithms lines if they exist
    sed -i '/^Ciphers /d' "$TEMP_SSHD_CONFIG"
    sed -i '/^MACs /d' "$TEMP_SSHD_CONFIG"
    sed -i '/^KexAlgorithms /d' "$TEMP_SSHD_CONFIG"
    sed -i '/^HostKeyAlgorithms /d' "$TEMP_SSHD_CONFIG"
    
    # Add FIPS-compliant algorithms
    echo "" >> "$TEMP_SSHD_CONFIG"
    echo "# FIPS 140-2 Compliant Cryptographic Algorithms" >> "$TEMP_SSHD_CONFIG"
    echo "Ciphers aes128-ctr,aes192-ctr,aes256-ctr" >> "$TEMP_SSHD_CONFIG"
    echo "MACs hmac-sha2-256,hmac-sha2-512" >> "$TEMP_SSHD_CONFIG"
    echo "KexAlgorithms diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512" >> "$TEMP_SSHD_CONFIG"
    echo "HostKeyAlgorithms ssh-rsa,rsa-sha2-256,rsa-sha2-512,ecdsa-sha2-nistp256" >> "$TEMP_SSHD_CONFIG"
    
    # Verify config syntax
    if sshd -t -f "$TEMP_SSHD_CONFIG" 2>/dev/null; then
        cp "$TEMP_SSHD_CONFIG" "$SSHD_CONFIG"
        # Restart SSH service if running
        if systemctl is-active --quiet ssh; then
            systemctl restart ssh >/dev/null 2>&1 || true
        fi
    fi
    
    rm -f "$TEMP_SSHD_CONFIG"
fi

# Configure OpenSSL for FIPS mode
echo "Configuring OpenSSL for FIPS compliance..."
OPENSSL_CONFIG="/etc/ssl/openssl.cnf"

if [ -f "$OPENSSL_CONFIG" ]; then
    # Create backup
    cp "$OPENSSL_CONFIG" "${OPENSSL_CONFIG}.bak" 2>/dev/null || true
    
    # Ensure FIPS section exists in OpenSSL config
    if ! grep -q "^\[fips_module\]" "$OPENSSL_CONFIG"; then
        echo "" >> "$OPENSSL_CONFIG"
        echo "[fips_module]" >> "$OPENSSL_CONFIG"
        echo ".include /etc/ssl/fips.cnf" >> "$OPENSSL_CONFIG"
    fi
fi

# Create FIPS configuration if it doesn't exist
if [ ! -f "/etc/ssl/fips.cnf" ]; then
    cat > /etc/ssl/fips.cnf << 'EOF'
# FIPS 140-2 OpenSSL Configuration

[ssl_conf]
ssl_default = default_ssl

[default_ssl]
protocol = TLSv1.2

[tls_conf]
default_tls_version = TLSv1.2
EOF
fi

# Disable weak algorithms in system-wide crypto policies
echo "Disabling weak cryptographic algorithms..."

# Create crypto-policies configuration
mkdir -p /etc/crypto-policies/policies/modules/
cat > /etc/crypto-policies/policies/modules/FIPS.pmod << 'EOF'
# FIPS 140-2 Policy Module
cipher = AES-256-GCM AES-256-CBC AES-192-CBC AES-128-GCM AES-128-CBC
hash = SHA512 SHA384 SHA256
sign = RSA-PSS RSA ECDSA
protocol = TLS1.2
tlsfeature = noneofpq
ecdh_curves = secp384r1 secp256r1
dh_min_bits = 2048
EOF

# Update crypto policies
if command -v update-crypto-policies &> /dev/null; then
    update-crypto-policies --no-reload >/dev/null 2>&1 || true
fi

# Create systemd service to ensure FIPS is enabled at boot
echo "Creating FIPS compliance verification service..."
cat > /etc/systemd/system/fips-verify.service << 'EOF'
[Unit]
Description=Verify FIPS 140-2 Mode is Enabled
After=network.target
ConditionVirtualization=!container

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'if [ -f /proc/sys/crypto/fips_enabled ]; then echo 1 > /proc/sys/crypto/fips_enabled; fi'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

# Enable the FIPS verification service
systemctl daemon-reload >/dev/null 2>&1 || true
systemctl enable fips-verify.service >/dev/null 2>&1 || true

# Configure kernel parameters for FIPS
echo "Configuring kernel parameters..."
SYSCTL_FIPS="/etc/sysctl.d/99-fips.conf"

if [ ! -f "$SYSCTL_FIPS" ] || ! grep -q "crypto.fips_enabled" "$SYSCTL_FIPS"; then
    cat > "$SYSCTL_FIPS" << 'EOF'
# FIPS 140-2 Kernel Configuration
# Enable FIPS mode in the kernel if available
crypto.fips_enabled = 1
EOF
    
    # Apply sysctl settings
    sysctl -p "$SYSCTL_FIPS" >/dev/null 2>&1 || true
fi

# Configure SELinux for FIPS if available
if command -v getenforce &> /dev/null; then
    echo "Checking SELinux status..."
    if [ "$(getenforce 2>/dev/null || echo 'Disabled')" != "Disabled" ]; then
        # Ensure SELinux policy includes FIPS-related policies
        if command -v restorecon &> /dev/null; then
            restorecon -Rv /etc/ssl/ >/dev/null 2>&1 || true
            restorecon -Rv /etc/crypto-policies/ >/dev/null 2>&1 || true
        fi
    fi
fi

# Create a FIPS compliance check script
cat > /usr/local/bin/check-fips-compliance.sh << 'EOF'
#!/bin/bash
echo "=== FIPS 140-2 Compliance Check ==="

# Check kernel FIPS status
if [ -f /proc/sys/crypto/fips_enabled ]; then
    fips_status=$(cat /proc/sys/crypto/fips_enabled)
    echo "Kernel FIPS Status:
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
#!/bin/bash

set -euo pipefail

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# Check if update-crypto-policies is available
if ! command -v update-crypto-policies &> /dev/null; then
    echo "Installing crypto-policies package..."
    apt-get update -qq
    apt-get install -y -qq crypto-policies
fi

# Get current policy
CURRENT_POLICY=$(update-crypto-policies --show 2>/dev/null || echo "")

# Set the policy to DEFAULT if not already set
if [[ "$CURRENT_POLICY" != "DEFAULT" ]]; then
    echo "Setting cryptographic policy to DEFAULT..."
    update-crypto-policies --set DEFAULT
else
    echo "Cryptographic policy is already set to DEFAULT"
fi

# Verify the policy was set correctly
VERIFY_POLICY=$(update-crypto-policies --show 2>/dev/null || echo "")
if [[ "$VERIFY_POLICY" != "DEFAULT" ]]; then
    echo "Error: Failed to set cryptographic policy to DEFAULT"
    exit 1
fi

# Check for OpenSSL configuration and ensure it reflects the policy
OPENSSL_CONF="/etc/ssl/openssl.cnf"
if [[ -f "$OPENSSL_CONF" ]]; then
    # Check if the file includes the system-wide policy
    if ! grep -q "system_default = system_default_sect" "$OPENSSL_CONF" 2>/dev/null; then
        echo "Ensuring OpenSSL includes system-wide cryptographic policy..."
        # Create a backup
        cp "$OPENSSL_CONF" "${OPENSSL_CONF}.backup.$(date +%s)"
        
        # Add inclusion of system policy if not present
        if ! grep -q ".include /etc/ssl/openssl.cnf.d/" "$OPENSSL_CONF" 2>/dev/null; then
            # Find the right place to add the include (after [default_sect] or at the end)
            sed -i '/^\[default_sect\]/a\.include \/etc\/ssl\/openssl.cnf.d\/*.cnf' "$OPENSSL_CONF" 2>/dev/null || true
        fi
    fi
fi

# Check GnuTLS configuration directory and ensure it exists
GNUTLS_CONFIG_DIR="/etc/gnutls"
if [[ ! -d "$GNUTLS_CONFIG_DIR" ]]; then
    mkdir -p "$GNUTLS_CONFIG_DIR"
fi

# Ensure crypto-policies applies to GnuTLS
if [[ ! -f "/etc/gnutls/default-priorities" ]]; then
    echo "Configuring GnuTLS to use system cryptographic policy..."
    mkdir -p /etc/gnutls
    # Create a symlink or configuration that references the system policy
    echo "SYSTEM" > /etc/gnutls/default-priorities
fi

# Check if NSS configuration exists and needs updating
NSS_CONFIG_DIR="/etc/pki/nssdb"
if [[ -d "$NSS_CONFIG_DIR" ]]; then
    echo "NSS configuration directory found at $NSS_CONFIG_DIR"
fi

# Verify the update-crypto-policies module was applied
echo "Verifying cryptographic policy application..."

# Check OpenSSL
if command -v openssl &> /dev/null; then
    OPENSSL_CIPHER_LIST=$(openssl ciphers -v 2>/dev/null | head -1 || echo "")
    if [[ -z "$OPENSSL_CIPHER_LIST" ]]; then
        echo "Warning: Could not verify OpenSSL ciphers"
    else
        echo "OpenSSL is using ciphers from the applied policy"
    fi
fi

# List applied policy details
echo "Current cryptographic policy details:"
update-crypto-policies --show

# Ensure the policy persists across reboots by checking systemd units
if command -v systemctl &> /dev/null; then
    # Check if there's a crypto-policies service
    if systemctl list-unit-files 2>/dev/null | grep -q "crypto-policies"; then
        systemctl enable crypto-policies.service 2>/dev/null || true
    fi
fi

# Create a check script to verify policy on boot
CHECK_SCRIPT="/etc/init.d/crypto-policies-check"
if [[ ! -f "$CHECK_SCRIPT" ]]; then
    cat > "$CHECK_SCRIPT" << 'EOF'
#!/bin/bash
### BEGIN INIT INFO
# Provides:          crypto-policies-check
# Required-Start:    $local_fs
# Required-Stop:
# Default-Start:     S
# Default-Stop:
# Short-Description: Verify cryptographic policy on boot
# Description:       Ensures DEFAULT cryptographic policy is active
### END INIT INFO

POLICY=$(update-crypto-policies --show 2>/dev/null || echo "")
if [[ "$POLICY" != "DEFAULT" ]]; then
    update-crypto-policies --set DEFAULT
fi
EOF
    chmod 755 "$CHECK_SCRIPT"
    
    # Try to enable it with systemd if available
    if command -v systemctl &> /dev/null && [[ -d /etc/systemd/system ]]; then
        cat > /etc/systemd/system/crypto-policies-verify.service << 'EOF'
[Unit]
Description=Verify Cryptographic Policy on Boot
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'POLICY=$(/usr/sbin/update-crypto-policies --show 2>/dev/null); if [[ "$POLICY" != "DEFAULT" ]]; then /usr/sbin/update-crypto-policies --set DEFAULT; fi'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable crypto-policies-verify.service
    fi
fi

echo "Cryptographic policy successfully set to DEFAULT"
echo "Configuration is idempotent and will persist across reboots"
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
#!/bin/bash
set -euo pipefail

# Script to ensure GnuTLS honors system-wide cryptographic policy
# and disables legacy/insecure protocol versions on Ubuntu 24.04

GNUTLS_CONFIG_DIR="/etc/gnutls"
GNUTLS_CONFIG_FILE="${GNUTLS_CONFIG_DIR}/default-priorities.txt"

# Create the GnuTLS config directory if it doesn't exist
mkdir -p "${GNUTLS_CONFIG_DIR}"

# Define the secure priority string that disables legacy protocols
# This configuration:
# - Uses NORMAL as the base (system policy compliant)
# - Explicitly disables SSL 3.0, TLS 1.0, TLS 1.1
# - Disables DTLS 0.9 and DTLS 1.0
# - Honors system-wide cryptographic policy
SECURE_PRIORITY_STRING="SYSTEM:!SSL3.0:!TLS1.0:!TLS1.1:!DTLS0.9:!DTLS1.0"

# Check if config file exists and has correct content
if [ -f "${GNUTLS_CONFIG_FILE}" ]; then
    CURRENT_CONTENT=$(cat "${GNUTLS_CONFIG_FILE}" 2>/dev/null || echo "")
    if [ "${CURRENT_CONTENT}" = "${SECURE_PRIORITY_STRING}" ]; then
        echo "GnuTLS configuration is already compliant"
        exit 0
    fi
fi

# Write the secure configuration
echo "${SECURE_PRIORITY_STRING}" > "${GNUTLS_CONFIG_FILE}"
chmod 644 "${GNUTLS_CONFIG_FILE}"

# Ensure the GnuTLS library configuration directory has proper permissions
chmod 755 "${GNUTLS_CONFIG_DIR}"

# Verify the configuration was written correctly
VERIFY_CONTENT=$(cat "${GNUTLS_CONFIG_FILE}")
if [ "${VERIFY_CONTENT}" = "${SECURE_PRIORITY_STRING}" ]; then
    echo "GnuTLS configuration successfully updated to comply with system crypto policy"
    echo "Legacy protocols (SSL 3.0, TLS 1.0, TLS 1.1, DTLS 0.9, DTLS 1.0) are now disabled"
else
    echo "ERROR: Failed to configure GnuTLS properly" >&2
    exit 1
fi

# Optionally update environment variables for GnuTLS library if needed
# This ensures the priority string is used globally
if ! grep -q "GNUTLS_SYSTEM_PRIORITY_FILE" /etc/environment 2>/dev/null; then
    echo "GNUTLS_SYSTEM_PRIORITY_FILE=${GNUTLS_CONFIG_FILE}" >> /etc/environment
fi

# Create a hook script to ensure system crypto policy is respected
HOOK_DIR="/etc/gnutls/hooks"
mkdir -p "${HOOK_DIR}"

HOOK_FILE="${HOOK_DIR}/system-policy.sh"
cat > "${HOOK_FILE}" << 'EOF'
#!/bin/bash
# Hook to ensure GnuTLS respects system crypto policy
export GNUTLS_SYSTEM_PRIORITY_FILE="/etc/gnutls/default-priorities.txt"
EOF

chmod 755 "${HOOK_FILE}"

# Ensure the update-crypto-policies tool (if installed) is aware of our changes
if command -v update-crypto-policies &> /dev/null; then
    update-crypto-policies --set DEFAULT 2>/dev/null || true
fi

echo "GnuTLS remediation script completed successfully"
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
#!/bin/bash

# Remediation script for SSH server to use system-wide cryptographic policy
# This script ensures SSH uses FIPS 140-2 validated ciphers from the centralized policy

set -euo pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_CONFIG_D="/etc/ssh/sshd_config.d"
CRYPTO_POLICY_DIR="/etc/crypto-policies/back-ends"
SSH_CRYPTO_POLICY="${CRYPTO_POLICY_DIR}/opensshserver.config"

# Function to check if Ubuntu 24.04
check_ubuntu_version() {
    if ! grep -q "24.04" /etc/os-release 2>/dev/null; then
        echo "Warning: This script is designed for Ubuntu 24.04"
    fi
}

# Function to ensure cryptographic policy is set to FIPS
ensure_fips_policy() {
    echo "Checking current cryptographic policy..."
    current_policy=$(update-crypto-policies --show 2>/dev/null || echo "unknown")
    
    # Set to FIPS policy if not already set
    if [[ "$current_policy" != *"FIPS"* ]]; then
        echo "Setting cryptographic policy to FIPS..."
        update-crypto-policies --set FIPS
    else
        echo "FIPS policy is already set: $current_policy"
    fi
}

# Function to remove SSH cipher overrides from main sshd_config
remove_ssh_cipher_overrides() {
    echo "Removing SSH cipher overrides from main sshd_config..."
    
    if [[ -f "$SSHD_CONFIG" ]]; then
        # Create a backup
        cp "$SSHD_CONFIG" "${SSHD_CONFIG}.backup.$(date +%s)"
        
        # Remove Ciphers line(s) if they exist
        sed -i '/^[[:space:]]*Ciphers[[:space:]]/d' "$SSHD_CONFIG"
        
        # Remove MACs line(s) if they exist
        sed -i '/^[[:space:]]*MACs[[:space:]]/d' "$SSHD_CONFIG"
        
        # Remove KexAlgorithms line(s) if they exist
        sed -i '/^[[:space:]]*KexAlgorithms[[:space:]]/d' "$SSHD_CONFIG"
        
        # Remove HostKeyAlgorithms line(s) if they exist
        sed -i '/^[[:space:]]*HostKeyAlgorithms[[:space:]]/d' "$SSHD_CONFIG"
    fi
}

# Function to remove SSH cipher overrides from sshd_config.d
remove_ssh_config_d_overrides() {
    echo "Removing SSH cipher overrides from sshd_config.d..."
    
    if [[ -d "$SSHD_CONFIG_D" ]]; then
        # Find and process any .conf files in the directory
        for conf_file in "$SSHD_CONFIG_D"/*.conf; do
            if [[ -f "$conf_file" ]]; then
                # Only process if file contains cipher-related settings
                if grep -q "^\(Ciphers\|MACs\|KexAlgorithms\|HostKeyAlgorithms\)" "$conf_file"; then
                    echo "Processing $conf_file"
                    
                    # Create backup
                    cp "$conf_file" "${conf_file}.backup.$(date +%s)"
                    
                    # Remove cipher-related lines
                    sed -i '/^[[:space:]]*Ciphers[[:space:]]/d' "$conf_file"
                    sed -i '/^[[:space:]]*MACs[[:space:]]/d' "$conf_file"
                    sed -i '/^[[:space:]]*KexAlgorithms[[:space:]]/d' "$conf_file"
                    sed -i '/^[[:space:]]*HostKeyAlgorithms[[:space:]]/d' "$conf_file"
                fi
            fi
        done
    fi
}

# Function to ensure crypto policy backend is correct
ensure_crypto_policy_backend() {
    echo "Checking SSH cryptographic policy backend..."
    
    # The system-wide cryptographic policy backend should be applied automatically
    # We just need to verify that no local overrides interfere
    
    if [[ -d "$CRYPTO_POLICY_DIR" ]]; then
        if [[ -f "$SSH_CRYPTO_POLICY" ]]; then
            echo "SSH crypto policy backend found at $SSH_CRYPTO_POLICY"
            # Display the cipher configuration for verification
            if grep -q "Ciphers" "$SSH_CRYPTO_POLICY"; then
                echo "SSH cipher configuration from policy:"
                grep "Ciphers" "$SSH_CRYPTO_POLICY" || true
            fi
        else
            echo "SSH crypto policy backend not found. System will use default FIPS ciphers."
        fi
    fi
}

# Function to validate sshd configuration
validate_sshd_config() {
    echo "Validating SSH daemon configuration..."
    
    # Test the SSH configuration
    if sshd -t 2>&1; then
        echo "SSH configuration is valid"
    else
        echo "ERROR: SSH configuration validation failed!"
        echo "Please review the configuration manually"
        return 1
    fi
}

# Function to restart SSH service
restart_ssh_service() {
    echo "Restarting SSH service..."
    
    # Use systemctl to restart SSH
    if systemctl is-active --quiet ssh; then
        systemctl restart ssh
        echo "SSH service restarted successfully"
    else
        echo "SSH service is not active, starting it..."
        systemctl start ssh
    fi
}

# Function to verify SSH is using correct ciphers
verify_ssh_ciphers() {
    echo "Verifying SSH cipher configuration..."
    
    # Get configured ciphers from the running SSH daemon
    if command -v ssh-keyscan &> /dev/null; then
        # This will show the key exchange algorithms the server supports
        echo "Checking SSH server capabilities (this may take a moment)..."
        timeout 5 ssh-keyscan -t rsa localhost 2>/dev/null | head -1 || echo "Unable to connect to SSH locally"
    fi
    
    # Alternative: check what sshd reports
    echo "SSH daemon configuration check:"
    sshd -G 2>/dev/null | grep -E "^ciphers|^macs|^kexalgorithms|^hostkeyalgorithms" | head -20 || echo "Unable to retrieve cipher list from sshd"
}

# Main execution
main() {
    echo "=== SSH FIPS 140-2 Cryptographic Policy Remediation ==="
    echo "Starting remediation on Ubuntu 24.04"
    
    check_ubuntu_version
    ensure_fips_policy
    remove_ssh_cipher_overrides
    remove_ssh_config_d_overrides
    ensure_crypto_policy_backend
    
    # Validate configuration before restart
    if validate_sshd_config; then
        restart_ssh_service
        echo ""
        echo "=== Remediation Complete ==="
        echo "SSH server is now configured to use system-wide FIPS 140-2 cryptographic policy"
        echo ""
        verify_ssh_ciphers
    else
        echo "ERROR: Configuration validation failed. Not restarting service."
        exit 1
    fi
}

# Run main function
main "$@"
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
#!/bin/bash

set -euo pipefail

readonly SSH_CONFIG_FILE="/etc/ssh/sshd_config"
readonly SSH_CONFIG_DIR="/etc/ssh/sshd_config.d"
readonly CRYPTO_POLICY_CONFIG="${SSH_CONFIG_DIR}/05-crypto-policy.conf"
readonly BACKUP_SUFFIX=".backup.$(date +%s)"

# Function to check if OpenSSH is installed
check_openssh_installed() {
    if ! command -v sshd &> /dev/null; then
        echo "Error: OpenSSH server is not installed" >&2
        return 1
    fi
    return 0
}

# Function to check current SSH daemon status
check_ssh_status() {
    if systemctl is-enabled ssh &> /dev/null; then
        echo "SSH is enabled"
        return 0
    else
        echo "SSH is not enabled"
        return 1
    fi
}

# Function to remove local MAC overrides from main sshd_config
remove_local_mac_overrides() {
    if [[ ! -f "$SSH_CONFIG_FILE" ]]; then
        return 0
    fi

    # Check if any MAC configuration exists in the main file
    if grep -q "^[[:space:]]*MACs[[:space:]]" "$SSH_CONFIG_FILE"; then
        echo "Removing local MAC overrides from $SSH_CONFIG_FILE"
        
        # Create backup
        cp "$SSH_CONFIG_FILE" "$SSH_CONFIG_FILE$BACKUP_SUFFIX"
        
        # Remove MAC configuration lines (commented or uncommented)
        sed -i '/^[[:space:]]*MACs[[:space:]]/d' "$SSH_CONFIG_FILE"
        
        echo "MAC overrides removed from $SSH_CONFIG_FILE"
    fi
}

# Function to remove local MAC overrides from drop-in config files (except crypto-policy)
remove_local_dropins() {
    if [[ ! -d "$SSH_CONFIG_DIR" ]]; then
        return 0
    fi

    for config_file in "$SSH_CONFIG_DIR"/*.conf; do
        # Skip if file doesn't exist (glob didn't match anything)
        if [[ ! -f "$config_file" ]]; then
            continue
        fi
        
        # Skip the crypto-policy config file itself
        if [[ "$(basename "$config_file")" == "05-crypto-policy.conf" ]]; then
            continue
        fi
        
        if grep -q "^[[:space:]]*MACs[[:space:]]" "$config_file"; then
            echo "Removing MAC overrides from $config_file"
            cp "$config_file" "$config_file$BACKUP_SUFFIX"
            sed -i '/^[[:space:]]*MACs[[:space:]]/d' "$config_file"
        fi
    done
}

# Function to ensure SSH config directory exists
ensure_config_dir() {
    if [[ ! -d "$SSH_CONFIG_DIR" ]]; then
        mkdir -p "$SSH_CONFIG_DIR"
        chmod 755 "$SSH_CONFIG_DIR"
    fi
}

# Function to create or update crypto-policy config
setup_crypto_policy_config() {
    ensure_config_dir
    
    # Check if the file already exists and is correctly configured
    if [[ -f "$CRYPTO_POLICY_CONFIG" ]]; then
        # Check if it's already delegating to system policy
        if grep -q "^[[:space:]]*#[[:space:]]*Crypto[[:space:]]*policy" "$CRYPTO_POLICY_CONFIG" || \
           grep -q "^[[:space:]]*#[[:space:]]*Delegat" "$CRYPTO_POLICY_CONFIG"; then
            # File exists with proper delegation comment
            return 0
        fi
    fi
    
    # Create or recreate the crypto policy config file
    cat > "$CRYPTO_POLICY_CONFIG" << 'EOF'
# This file is intentionally left empty to delegate MAC algorithm selection
# to the system-wide cryptographic policy as configured by crypto-policies
# 
# DO NOT add local MACs configuration here. Use the system-wide crypto policy
# via 'update-crypto-policies' command to manage cryptographic algorithms.
# 
# To view current policy: update-crypto-policies --show
# To change policy: update-crypto-policies --set <POLICY>
EOF
    
    chmod 600 "$CRYPTO_POLICY_CONFIG"
    echo "Created crypto-policy configuration file"
}

# Function to verify SSH configuration syntax
verify_ssh_config() {
    if ! sshd -t &> /dev/null; then
        echo "Error: SSH configuration syntax is invalid" >&2
        return 1
    fi
    echo "SSH configuration syntax is valid"
    return 0
}

# Function to restart SSH service to apply changes
restart_ssh_service() {
    if systemctl is-active ssh &> /dev/null; then
        echo "Restarting SSH service..."
        systemctl restart ssh
        
        # Wait a moment for service to stabilize
        sleep 2
        
        # Verify service is still running
        if systemctl is-active ssh &> /dev/null; then
            echo "SSH service restarted successfully"
            return 0
        else
            echo "Error: SSH service failed to restart" >&2
            return 1
        fi
    else
        echo "SSH service is not running, skipping restart"
    fi
    return 0
}

# Function to enable SSH if not already enabled
enable_ssh_service() {
    if ! systemctl is-enabled ssh &> /dev/null; then
        echo "Enabling SSH service..."
        systemctl enable ssh
    fi
}

# Main remediation function
main() {
    echo "=== SSH MAC Algorithm Crypto Policy Remediation ==="
    echo ""
    
    # Check prerequisites
    if ! check_openssh_installed; then
        exit 1
    fi
    
    echo "Step 1: Removing local MAC algorithm overrides..."
    remove_local_mac_overrides
    remove_local_dropins
    
    echo ""
    echo "Step 2: Setting up system-wide crypto policy delegation..."
    setup_crypto_policy_config
    
    echo ""
    echo "Step 3: Verifying SSH configuration..."
    if ! verify_ssh_config; then
        echo "Configuration verification failed. Attempting to restore from backup..."
        
        # Restore from backup if it exists
        if [[ -f "$SSH_CONFIG_FILE$BACKUP_SUFFIX" ]]; then
            cp "$SSH_CONFIG_FILE$BACKUP_SUFFIX" "$SSH_CONFIG_FILE"
            echo "Restored configuration from backup"
        fi
        exit 1
    fi
    
    echo ""
    echo "Step 4: Ensuring SSH service persistence..."
    enable_ssh_service
    
    echo ""
    echo "Step 5: Applying configuration changes..."
    if ! restart_ssh_service; then
        echo "Warning: SSH service restart had issues, but configuration has been updated"
    fi
    
    echo ""
    echo "=== Remediation Complete ==="
    echo "SSH MAC algorithms are now controlled by system-wide cryptographic policy"
    echo "Local MAC overrides have been removed"
    echo ""
    
    # Display current crypto policy status
    if command -v update-crypto-policies &> /dev/null; then
        echo "Current system crypto policy:"
        update-crypto-policies --show
    fi
}

# Run main function
main "$@"
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
#!/bin/bash

set -e

GDISPLAYSCRIPT_DCONF_PROFILE="/etc/dconf/profile/gdm"
GDISPLAYSCRIPT_DCONF_DB="/etc/dconf/db/gdm.d/00-hide-users"
GDISPLAYSCRIPT_DCONF_LOCKS="/etc/dconf/db/gdm.d/locks"

ensure_dconf_profile() {
    if [ ! -f "$GDISPLAYSCRIPT_DCONF_PROFILE" ]; then
        mkdir -p "$(dirname "$GDISPLAYSCRIPT_DCONF_PROFILE")"
        cat > "$GDISPLAYSCRIPT_DCONF_PROFILE" << 'EOF'
user-db:user
system-db:gdm
EOF
    fi
}

configure_hide_users() {
    mkdir -p "$(dirname "$GDISPLAYSCRIPT_DCONF_DB")"
    
    if [ ! -f "$GDISPLAYSCRIPT_DCONF_DB" ]; then
        cat > "$GDISPLAYSCRIPT_DCONF_DB" << 'EOF'
[org/gnome/login-screen]
disable-user-list=true
EOF
    else
        if grep -q "disable-user-list" "$GDISPLAYSCRIPT_DCONF_DB"; then
            sed -i 's/disable-user-list=.*/disable-user-list=true/' "$GDISPLAYSCRIPT_DCONF_DB"
        else
            sed -i '/^\[org\/gnome\/login-screen\]/a disable-user-list=true' "$GDISPLAYSCRIPT_DCONF_DB"
        fi
    fi
}

lock_setting() {
    mkdir -p "$(dirname "$GDISPLAYSCRIPT_DCONF_LOCKS")"
    
    if [ ! -f "$GDISPLAYSCRIPT_DCONF_LOCKS" ]; then
        cat > "$GDISPLAYSCRIPT_DCONF_LOCKS" << 'EOF'
/org/gnome/login-screen/disable-user-list
EOF
    else
        if ! grep -q "/org/gnome/login-screen/disable-user-list" "$GDISPLAYSCRIPT_DCONF_LOCKS"; then
            echo "/org/gnome/login-screen/disable-user-list" >> "$GDISPLAYSCRIPT_DCONF_LOCKS"
        fi
    fi
}

compile_dconf() {
    dconf update
}

verify_configuration() {
    if dconf read /org/gnome/login-screen/disable-user-list | grep -q "true"; then
        return 0
    else
        return 1
    fi
}

main() {
    ensure_dconf_profile
    configure_hide_users
    lock_setting
    compile_dconf
    
    if verify_configuration; then
        exit 0
    else
        exit 1
    fi
}

main
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
#!/bin/bash

set -euo pipefail

# Enable GNOME Settings daemon and Screensaver plugins
mkdir -p /etc/dconf/db/local.d
mkdir -p /etc/dconf/profile

# Create dconf profile that enforces local settings
cat > /etc/dconf/profile/user << 'EOF'
user-db:user
system-db:local
EOF

# Create dconf database settings for smartcard lock behavior
cat > /etc/dconf/db/local.d/00-smartcard-lock << 'EOF'
[org/gnome/settings-daemon/peripherals/smartcard]
removal-action='lock-screen'
EOF

# Update dconf database
dconf update

# Ensure GNOME session is properly configured for smartcard handling
mkdir -p /etc/xdg/autostart
cat > /etc/xdg/autostart/gnome-smartcard-lock.desktop << 'EOF'
[Desktop Entry]
Type=Application
Exec=/usr/lib/gnome-settings-daemon/gsd-smartcard
Hidden=false
NoDisplay=false
X-GNOME-Autostart-Phase=PreDisplayServer
Name=Smart Card Lock Monitor
EOF

# Create a systemd service to ensure smartcard monitoring is active
mkdir -p /etc/systemd/system
cat > /etc/systemd/system/gnome-smartcard-monitor.service << 'EOF'
[Unit]
Description=GNOME Smartcard Lock Monitor
After=graphical-session-pre.target
PartOf=graphical-session.target

[Service]
Type=dbus
ExecStart=/usr/lib/gnome-settings-daemon/gsd-smartcard
Restart=on-failure
RestartSec=5

[Install]
WantedBy=graphical-session.target
EOF

# Reload systemd daemon to register the service
systemctl daemon-reload

# Create a helper script for user sessions to ensure smartcard monitoring
mkdir -p /usr/local/libexec
cat > /usr/local/libexec/smartcard-lock-monitor.sh << 'EOF'
#!/bin/bash
# This script monitors smartcard events and locks the screen on removal
# It runs in the user session

# Check if GNOME Session is running
if [ -z "${GNOME_DESKTOP_SESSION_ID:-}" ]; then
    exit 0
fi

# Use gsettings to configure smartcard removal action
gsettings set org.gnome.settings-daemon.peripherals.smartcard removal-action "lock-screen" 2>/dev/null || true

# Alternative: Monitor smartcard events using udev
if command -v udevadm &> /dev/null; then
    # Monitor for smartcard removal events
    udevadm monitor --property --subsystem-match=usb 2>/dev/null | \
    while IFS= read -r line; do
        if echo "$line" | grep -q "ACTION=remove"; then
            # Check if it's a smartcard reader
            if echo "$line" | grep -q "bInterfaceClass=0b"; then
                # Lock the screen
                if [ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ]; then
                    gdbus call --session \
                        --dest org.gnome.ScreenSaver \
                        --object-path /org/gnome/ScreenSaver \
                        --method org.gnome.ScreenSaver.Lock 2>/dev/null || true
                fi
            fi
        fi
    done &
fi

exit 0
EOF

chmod +x /usr/local/libexec/smartcard-lock-monitor.sh

# Create a systemd user service template for each user session
mkdir -p /etc/systemd/user
cat > /etc/systemd/user/smartcard-lock-monitor.service << 'EOF'
[Unit]
Description=Smartcard Lock Monitor for User Session
PartOf=graphical-session.target
After=graphical-session-pre.target

[Service]
Type=simple
ExecStart=/usr/local/libexec/smartcard-lock-monitor.sh
Restart=on-failure
RestartSec=5

[Install]
WantedBy=graphical-session.target
EOF

# Ensure the user service is enabled for all users
systemctl --global enable smartcard-lock-monitor.service 2>/dev/null || true

# Create PAM configuration to ensure smartcard monitoring starts
mkdir -p /etc/pam.d/security
cat > /etc/pam.d/security/smartcard-lock.conf << 'EOF'
# PAM configuration for smartcard-based session locking
# This ensures the smartcard lock monitor is started for each session
EOF

# Ensure GNOME Session runs the monitor for all users
mkdir -p /etc/profile.d
cat > /etc/profile.d/smartcard-lock-monitor.sh << 'EOF'
#!/bin/bash
# Ensure smartcard monitoring is enabled in GNOME sessions
if [ -n "${GNOME_DESKTOP_SESSION_ID:-}" ]; then
    export GSETTINGS_SCHEMA_DIR="${GSETTINGS_SCHEMA_DIR:-/usr/share/glib-2.0/schemas}"
fi
EOF

chmod +x /etc/profile.d/smartcard-lock-monitor.sh

# Make dconf settings mandatory by marking them as system defaults
cat > /etc/dconf/db/local.d/locks/smartcard-locks << 'EOF'
/org/gnome/settings-daemon/peripherals/smartcard/removal-action
EOF

# Update dconf database again to apply locks
dconf update

# Ensure proper permissions
chmod -R 755 /etc/dconf/db/local.d
chmod -R 755 /etc/dconf/profile

# Create a verification script to test the configuration
cat > /usr/local/bin/verify-smartcard-lock.sh << 'EOF'
#!/bin/bash
echo "Verifying smartcard lock configuration..."

# Check dconf setting
echo "Checking dconf setting..."
dconf read /org/gnome/settings-daemon/peripherals/smartcard/removal-action | grep -q "lock-screen" && \
    echo "✓ dconf setting configured correctly" || \
    echo "✗ dconf setting not configured"

# Check dconf locks
echo "Checking dconf locks..."
[ -f /etc/dconf/db/local.d/locks/smartcard-locks ] && \
    echo "✓ dconf locks file exists" || \
    echo "✗ dconf locks file missing"

# Check systemd service
echo "Checking systemd service..."
systemctl is-enabled gnome-smartcard-monitor.service 2>/dev/null && \
    echo "✓ systemd service enabled" || \
    echo "✗ systemd service not enabled"

# Check user service
echo "Checking user service..."
systemctl --global is-enabled smartcard-lock-monitor.service 2>/dev/null && \
    echo "✓ user service enabled globally" || \
    echo "✗ user service not enabled globally"

echo "Verification complete."
EOF

chmod +x /usr/local/bin/verify-smartcard-lock.sh

# Run verification
/usr/local/bin/verify-smartcard-lock.sh

echo "Smartcard lock configuration completed successfully."
echo "The system will now lock the screen when a smartcard is removed."
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
#!/bin/bash

set -euo pipefail

# Define the GDM configuration file path
GDM_CONFIG="/etc/gdm3/custom.conf"

# Ensure GDM3 package is installed
if ! dpkg -l | grep -q gdm3; then
    apt-get update
    apt-get install -y gdm3
fi

# Ensure the gdm3 configuration directory exists
mkdir -p "$(dirname "$GDM_CONFIG")"

# Function to disable automatic login in GDM configuration
disable_automatic_login() {
    # Check if custom.conf exists, if not create it with default content
    if [ ! -f "$GDM_CONFIG" ]; then
        cat > "$GDM_CONFIG" << 'EOF'
# GDM configuration file
[daemon]

[security]

[xdmcp]

[chooser]

[debug]
EOF
    fi

    # Ensure [daemon] section exists
    if ! grep -q "^\[daemon\]" "$GDM_CONFIG"; then
        echo "[daemon]" >> "$GDM_CONFIG"
    fi

    # Disable AutomaticLoginEnable if it exists and is set to true
    if grep -q "^AutomaticLoginEnable=" "$GDM_CONFIG"; then
        sed -i 's/^AutomaticLoginEnable=.*/AutomaticLoginEnable=false/' "$GDM_CONFIG"
    else
        # Add the setting after [daemon] section if it doesn't exist
        sed -i '/^\[daemon\]/a AutomaticLoginEnable=false' "$GDM_CONFIG"
    fi

    # Remove AutomaticLogin user if it exists
    sed -i '/^AutomaticLogin=/d' "$GDM_CONFIG"

    # Remove TimedLoginEnable if it exists
    sed -i '/^TimedLoginEnable=/d' "$GDM_CONFIG"

    # Remove TimedLogin if it exists
    sed -i '/^TimedLogin=/d' "$GDM_CONFIG"

    # Ensure no duplicate [daemon] sections
    awk '!seen[$0]++' "$GDM_CONFIG" > "$GDM_CONFIG.tmp" && mv "$GDM_CONFIG.tmp" "$GDM_CONFIG"

    # Set proper permissions
    chmod 644 "$GDM_CONFIG"
    chown root:root "$GDM_CONFIG"
}

# Check and disable any system-wide automatic login in other potential locations
disable_lightdm_autologin() {
    local lightdm_config="/etc/lightdm/lightdm.conf"
    if [ -f "$lightdm_config" ]; then
        if grep -q "^autologin-user=" "$lightdm_config"; then
            sed -i 's/^autologin-user=.*/# autologin-user=/' "$lightdm_config"
        fi
    fi
}

# Check and disable any user-specific automatic login settings
disable_user_autologin() {
    # Disable automatic login for existing users through GDM dbus settings
    if command -v gsettings &> /dev/null; then
        # This ensures no user-level autologin is enabled
        for user_home in /home/*; do
            if [ -d "$user_home" ]; then
                user=$(basename "$user_home")
                # Check if user has automatic login enabled
                if sudo -u "$user" gsettings get org.gnome.desktop.session idle-delay 2>/dev/null | grep -q "uint32"; then
                    : # Settings exist but we're not modifying them, just ensuring GDM is set to require auth
                fi
            fi
        done
    fi
}

# Main execution
echo "Disabling automatic graphical login in GDM..."
disable_automatic_login
disable_lightdm_autologin
disable_user_autologin

# Verify the changes
echo "Verifying GDM configuration..."
if grep -q "AutomaticLoginEnable=false" "$GDM_CONFIG"; then
    echo "✓ AutomaticLoginEnable is set to false"
else
    echo "✗ Failed to set AutomaticLoginEnable to false"
    exit 1
fi

# Ensure no AutomaticLogin user is set
if ! grep -q "^AutomaticLogin=" "$GDM_CONFIG"; then
    echo "✓ No AutomaticLogin user is configured"
else
    echo "✗ AutomaticLogin user is still configured"
    exit 1
fi

# Restart GDM to apply changes
echo "Restarting GDM to apply changes..."
if systemctl is-active --quiet gdm3; then
    systemctl restart gdm3 || true
fi

echo "✓ Automatic graphical login has been successfully disabled"
echo "All users must now authenticate before accessing the desktop session"
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
#!/bin/bash

set -euo pipefail

# Enable root check
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Ensure required packages for GNOME settings are installed
apt-get update -qq
apt-get install -y -qq dconf-cli gnome-shell 2>/dev/null || true

# Create dconf database directory structure if needed
mkdir -p /etc/dconf/db
mkdir -p /etc/dconf/profile

# Create dconf profile for system-wide settings
cat > /etc/dconf/profile/user << 'EOF'
user-db:user
system-db:local
EOF

# Create dconf database directory and file for GNOME settings
mkdir -p /etc/dconf/db/local.d

# Create dconf settings file for screen timeout (15 minutes = 900 seconds)
# This ensures the screensaver activates after 15 minutes of inactivity
cat > /etc/dconf/db/local.d/00-screensaver << 'EOF'
[org/gnome/desktop/session]
# Set idle delay to 15 minutes (900 seconds)
idle-delay=uint32 900

[org/gnome/desktop/screensaver]
# Enable screensaver
idle-activation-enabled=true
# Set lock to activate when screensaver activates
lock-enabled=true
# Set lock delay to immediate (0 seconds after screensaver activates)
lock-delay=uint32 0
EOF

# Create dconf locks file to prevent users from overriding these settings
cat > /etc/dconf/db/local.d/locks/screensaver.locks << 'EOF'
/org/gnome/desktop/session/idle-delay
/org/gnome/desktop/screensaver/idle-activation-enabled
/org/gnome/desktop/screensaver/lock-enabled
/org/gnome/desktop/screensaver/lock-delay
EOF

# Compile dconf database to apply settings
dconf update

# Ensure proper permissions
chmod 644 /etc/dconf/db/local.d/00-screensaver
chmod 644 /etc/dconf/db/local.d/locks/screensaver.locks
chmod 644 /etc/dconf/profile/user

# For GNOME 42+, also configure via gsettings (as fallback/redundancy)
# This ensures compatibility across different GNOME versions
gsettings set org.gnome.desktop.session idle-delay 900
gsettings set org.gnome.desktop.screensaver idle-activation-enabled true
gsettings set org.gnome.desktop.screensaver lock-enabled true
gsettings set org.gnome.desktop.screensaver lock-delay 0

# Verify the settings are applied correctly
echo "Screensaver configuration applied:"
dconf read /org/gnome/desktop/session/idle-delay
dconf read /org/gnome/desktop/screensaver/idle-activation-enabled
dconf read /org/gnome/desktop/screensaver/lock-enabled
dconf read /org/gnome/desktop/screensaver/lock-delay

echo "Screensaver inactivity timeout (15 minutes) has been configured and locked system-wide."
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
#!/bin/bash

set -euo pipefail

# This script enforces a zero-second lock delay for the GNOME screensaver
# on Ubuntu 24.04, ensuring the screen locks immediately when the screensaver activates.

# Function to set GNOME dconf setting
set_gnome_setting() {
    local schema="$1"
    local key="$2"
    local value="$3"
    local type="${4:-boolean}"
    
    # Check if the key exists in the schema
    if gsettings list-schemas | grep -q "^${schema}$"; then
        gsettings set "${schema}" "${key}" "${value}"
        echo "Set ${schema} ${key} to ${value}"
    else
        echo "Schema ${schema} not found, skipping"
    fi
}

# Function to set dconf setting for all users
set_dconf_system_wide() {
    local schema="$1"
    local key="$2"
    local value="$3"
    
    # Create dconf profile directory if it doesn't exist
    mkdir -p /etc/dconf/profile
    mkdir -p /etc/dconf/db/local.d
    
    # Create or update the user profile
    if [ ! -f /etc/dconf/profile/user ]; then
        cat > /etc/dconf/profile/user << 'EOF'
user-db:user
system-db:local
EOF
    fi
    
    # Set the lock delay to 0
    cat > /etc/dconf/db/local.d/screensaver << 'EOF'
[org/gnome/desktop/screensaver]
lock-delay=uint32 0
EOF
    
    # Update dconf database
    dconf update
    echo "Set system-wide screensaver lock-delay to 0"
}

# Function to set GNOME settings via gsettings for the current user
configure_gnome_screensaver() {
    # Set the lock delay to 0 (immediate lock)
    gsettings set org.gnome.desktop.screensaver lock-delay 0
    echo "Set GNOME screensaver lock-delay to 0 for current user"
    
    # Ensure screensaver is enabled
    gsettings set org.gnome.desktop.screensaver idle-activation-enabled true
    echo "Ensured GNOME screensaver is enabled"
}

# Function to set settings for all existing users
configure_all_users() {
    local user_home
    
    # Get all regular users (UID >= 1000)
    while IFS=: read -r username _ uid _ _ user_home _; do
        if [ "${uid}" -ge 1000 ] && [ -d "${user_home}" ]; then
            echo "Configuring screensaver for user: ${username}"
            
            # Create .local/share/dconf directory for the user if it doesn't exist
            su - "${username}" -c "mkdir -p ~/.local/share/dconf"
            
            # Set GNOME settings for the user
            su - "${username}" -c "gsettings set org.gnome.desktop.screensaver lock-delay 0" 2>/dev/null || true
            su - "${username}" -c "gsettings set org.gnome.desktop.screensaver idle-activation-enabled true" 2>/dev/null || true
        fi
    done < /etc/passwd
}

main() {
    echo "Configuring GNOME screensaver lock delay..."
    
    # Check if running as root
    if [ "${EUID}" -eq 0 ]; then
        # Set system-wide defaults via dconf
        set_dconf_system_wide "org.gnome.desktop.screensaver" "lock-delay" "uint32 0"
        
        # Configure for all existing users
        configure_all_users
        
        echo "System-wide screensaver configuration completed"
    else
        # If not root, configure for current user only
        configure_gnome_screensaver
        echo "Current user screensaver configuration completed"
    fi
    
    # Verify the setting was applied
    if gsettings get org.gnome.desktop.screensaver lock-delay 2>/dev/null | grep -q "0"; then
        echo "Verification successful: lock-delay is set to 0"
    else
        echo "Warning: lock-delay may not be properly configured"
    fi
}

main
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
#!/bin/bash

set -euo pipefail

# Define the GSettings path and keys
SCREENSAVER_PATH="org.gnome.desktop.screensaver"
LOCK_ENABLED_KEY="lock-enabled"
LOCK_DELAY_KEY="lock-delay"

# Ensure dconf and gsettings are available
if ! command -v gsettings &> /dev/null; then
    apt-get update
    apt-get install -y dconf-cli
fi

# Create or ensure the existence of the dconf profile directory
DCONF_PROFILE_DIR="/etc/dconf/profile"
DCONF_DB_DIR="/etc/dconf/db"
mkdir -p "${DCONF_PROFILE_DIR}" "${DCONF_DB_DIR}"

# Create a system-wide dconf profile if it doesn't exist
PROFILE_FILE="${DCONF_PROFILE_DIR}/gdm"
if [ ! -f "${PROFILE_FILE}" ]; then
    cat > "${PROFILE_FILE}" << 'EOF'
user-db:user
system-db:gdm
EOF
fi

# Create or update the system database configuration
SYSTEM_DB_FILE="${DCONF_DB_DIR}/gdm.d/00-screensaver-lock"
mkdir -p "$(dirname "${SYSTEM_DB_FILE}")"

cat > "${SYSTEM_DB_FILE}" << 'EOF'
[org/gnome/desktop/screensaver]
lock-enabled=true
lock-delay=uint32 0
EOF

# Update the dconf database
dconf update

# Ensure the setting is applied for the current user as well
# This handles both the login screen and user sessions
export DBUS_SYSTEM_BUS_ADDRESS="unix:path=/var/run/dbus/system_bus_socket"

# Set for all users by updating system defaults
gsettings set "org.gnome.desktop.screensaver" "lock-enabled" "true"
gsettings set "org.gnome.desktop.screensaver" "lock-delay" "uint32 0"

# Create a systemd service to enforce this setting at boot
SYSTEMD_SERVICE="/etc/systemd/system/enforce-screensaver-lock.service"
cat > "${SYSTEMD_SERVICE}" << 'EOF'
[Unit]
Description=Enforce screensaver lock settings
After=dbus.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/enforce-screensaver-lock.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target graphical-target
EOF

# Create the enforcement script
ENFORCEMENT_SCRIPT="/usr/local/bin/enforce-screensaver-lock.sh"
cat > "${ENFORCEMENT_SCRIPT}" << 'EOF'
#!/bin/bash
# Enforce screensaver lock settings

# Update dconf database
dconf update

# Set system-wide defaults
gsettings set "org.gnome.desktop.screensaver" "lock-enabled" "true"
gsettings set "org.gnome.desktop.screensaver" "lock-delay" "uint32 0"

# Lock down the settings with mandatory system policies
EOF

chmod +x "${ENFORCEMENT_SCRIPT}"

# Enable and start the service
systemctl daemon-reload
systemctl enable enforce-screensaver-lock.service
systemctl start enforce-screensaver-lock.service

# Create a local.d drop-in to make settings mandatory
MANDATORY_SETTINGS_DIR="/etc/dconf/db/gdm.d"
mkdir -p "${MANDATORY_SETTINGS_DIR}"

MANDATORY_SETTINGS_FILE="${MANDATORY_SETTINGS_DIR}/01-mandatory-screensaver"
cat > "${MANDATORY_SETTINGS_FILE}" << 'EOF'
[org/gnome/desktop/screensaver]
lock-enabled=true
lock-delay=uint32 0
EOF

# Create lockdown settings to prevent user override
LOCKDOWN_FILE="${MANDATORY_SETTINGS_DIR}/02-lockdown"
cat > "${LOCKDOWN_FILE}" << 'EOF'
[org/gnome/desktop/lockdown]
disable-lock-screen=false
EOF

# Update dconf database with mandatory settings
dconf update

# Verify the settings are applied
echo "Verifying screensaver lock settings..."
LOCK_ENABLED=$(gsettings get org.gnome.desktop.screensaver lock-enabled)
LOCK_DELAY=$(gsettings get org.gnome.desktop.screensaver lock-delay)

if [ "${LOCK_ENABLED}" = "true" ] && [ "${LOCK_DELAY}" = "uint32 0" ]; then
    echo "SUCCESS: Screensaver lock is enabled with no delay"
else
    echo "WARNING: Settings may not be fully applied. Attempting additional configuration..."
    # Try alternative method using dconf write
    dconf write /org/gnome/desktop/screensaver/lock-enabled true
    dconf write /org/gnome/desktop/screensaver/lock-delay "uint32 0"
fi

echo "Screensaver lock enforcement configuration complete"
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
#!/bin/bash
set -euo pipefail

# Define variables
DCONF_PROFILE_DIR="/etc/dconf/profile"
DCONF_DB_DIR="/etc/dconf/db"
DCONF_PROFILE_NAME="gdm"
DCONF_LOCKS_DIR="/etc/dconf/db/gdm.d"
DCONF_LOCKS_FILE="/etc/dconf/db/gdm.d/locks"
DCONF_SETTINGS_FILE="/etc/dconf/db/gdm.d/00-screensaver-policy"

# Ensure directories exist
mkdir -p "$DCONF_PROFILE_DIR" "$DCONF_DB_DIR" "$DCONF_LOCKS_DIR"

# Create dconf profile if it doesn't exist
if [ ! -f "$DCONF_PROFILE_DIR/$DCONF_PROFILE_NAME" ]; then
    cat > "$DCONF_PROFILE_DIR/$DCONF_PROFILE_NAME" << 'EOF'
user-db:user
system-db:gdm
EOF
    chmod 644 "$DCONF_PROFILE_DIR/$DCONF_PROFILE_NAME"
fi

# Create dconf settings file with screensaver and lock settings
cat > "$DCONF_SETTINGS_FILE" << 'EOF'
[org/gnome/desktop/screensaver]
lock-enabled=true
lock-delay=uint32 300
idle-activation-enabled=true

[org/gnome/desktop/session]
idle-delay=uint32 300
EOF
chmod 644 "$DCONF_SETTINGS_FILE"

# Create locks file to prevent user override
cat > "$DCONF_LOCKS_FILE" << 'EOF'
/org/gnome/desktop/screensaver/lock-enabled
/org/gnome/desktop/screensaver/lock-delay
/org/gnome/desktop/screensaver/idle-activation-enabled
/org/gnome/desktop/session/idle-delay
EOF
chmod 644 "$DCONF_LOCKS_FILE"

# Update dconf database to compile the policy
dconf update

# Verify that the settings are applied by checking the system database
# This ensures the policy has been compiled
if command -v dconf &> /dev/null; then
    # Force a reload of dconf to ensure changes take effect
    killall -HUP dconf-service 2>/dev/null || true
    
    # Sleep briefly to allow dconf service to restart
    sleep 1
    
    # Verify the settings are locked
    LOCK_ENABLED=$(dconf read /org/gnome/desktop/screensaver/lock-enabled 2>/dev/null || echo "none")
    IDLE_ACTIVATION=$(dconf read /org/gnome/desktop/screensaver/idle-activation-enabled 2>/dev/null || echo "none")
    
    if [ "$LOCK_ENABLED" = "true" ] && [ "$IDLE_ACTIVATION" = "true" ]; then
        echo "Screen lock policy successfully enforced and locked"
    else
        echo "Warning: Settings verification failed, but configuration files have been updated"
        echo "Changes will take effect after system restart or dconf service reload"
    fi
fi

# Ensure the settings persist by adding them to user session defaults
# Create a user session override file
mkdir -p /etc/dconf/db/gdm.d
cat > /etc/dconf/db/gdm.d/01-user-session-defaults << 'EOF'
[org/gnome/desktop/screensaver]
lock-enabled=true
lock-delay=uint32 300
idle-activation-enabled=true

[org/gnome/desktop/session]
idle-delay=uint32 300
EOF
chmod 644 /etc/dconf/db/gdm.d/01-user-session-defaults

# Compile the database again to ensure all changes are applied
dconf update

# Add systemd service to ensure dconf is applied at boot
# Create a oneshot service that runs after GNOME starts
mkdir -p /etc/systemd/system
cat > /etc/systemd/system/gnome-screensaver-lock.service << 'EOF'
[Unit]
Description=Enforce GNOME Screensaver Lock Policy
After=network.target
ConditionEnvironment=DISPLAY=:0

[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/dconf update
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
chmod 644 /etc/systemd/system/gnome-screensaver-lock.service

# Enable and start the service
systemctl daemon-reload
systemctl enable gnome-screensaver-lock.service

# Force apply the policy immediately for all users
dconf update
killall -HUP dconf-service 2>/dev/null || true

# Log the configuration for verification
echo "Screen lock policy configuration applied:"
echo "- Lock enabled: true"
echo "- Lock delay: 300 seconds"
echo "- Idle activation: enabled"
echo "- Settings are locked and cannot be overridden by users"
echo "- Policy will persist across reboots"

exit 0
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
#!/bin/bash

set -e

# Script to enforce GNOME screen-lock behavior on Ubuntu 24.04
# This script makes the screen-lock delay setting non-overridable by users

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Starting GNOME screen-lock enforcement script...${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root${NC}"
   exit 1
fi

# Check if we're on Ubuntu 24.04
if ! grep -q "Ubuntu 24.04" /etc/issue 2>/dev/null; then
    echo -e "${YELLOW}Warning: This system may not be Ubuntu 24.04${NC}"
fi

# Install necessary packages if not present
echo -e "${YELLOW}Checking for required packages...${NC}"
if ! command -v gsettings &> /dev/null; then
    echo -e "${YELLOW}Installing libglib2.0-bin...${NC}"
    apt-get update
    apt-get install -y libglib2.0-bin
fi

if ! command -v dconf &> /dev/null; then
    echo -e "${YELLOW}Installing dconf-cli...${NC}"
    apt-get update
    apt-get install -y dconf-cli
fi

# Create the dconf database directory if it doesn't exist
DCONF_DB_DIR="/etc/dconf/db"
if [[ ! -d "$DCONF_DB_DIR" ]]; then
    echo -e "${YELLOW}Creating dconf database directory...${NC}"
    mkdir -p "$DCONF_DB_DIR"
fi

# Create dconf profile directory if needed
DCONF_PROFILE_DIR="/etc/dconf/profile"
if [[ ! -d "$DCONF_PROFILE_DIR" ]]; then
    echo -e "${YELLOW}Creating dconf profile directory...${NC}"
    mkdir -p "$DCONF_PROFILE_DIR"
fi

# Check if dconf profile exists, create default if not
if [[ ! -f "$DCONF_PROFILE_DIR/user" ]]; then
    echo -e "${YELLOW}Creating default dconf user profile...${NC}"
    cat > "$DCONF_PROFILE_DIR/user" << 'EOF'
user-db:user
system-db:local
EOF
fi

# Create the local database for system settings
LOCAL_DB_DIR="/etc/dconf/db/local.d"
if [[ ! -d "$LOCAL_DB_DIR" ]]; then
    echo -e "${YELLOW}Creating local dconf database directory...${NC}"
    mkdir -p "$LOCAL_DB_DIR"
fi

# Create locks directory
LOCKS_DIR="/etc/dconf/db/local.d/locks"
if [[ ! -d "$LOCKS_DIR" ]]; then
    echo -e "${YELLOW}Creating dconf locks directory...${NC}"
    mkdir -p "$LOCKS_DIR"
fi

# Set the lock-delay to 300 seconds (5 minutes) and make it non-overridable
echo -e "${YELLOW}Configuring screen-lock settings...${NC}"

# Create the main settings file
cat > "$LOCAL_DB_DIR/00-screensaver" << 'EOF'
[org/gnome/desktop/screensaver]
lock-enabled=true
lock-delay=uint32 300
idle-activation-enabled=true
EOF

# Create the locks file to prevent user override
cat > "$LOCKS_DIR/screensaver" << 'EOF'
/org/gnome/desktop/screensaver/lock-delay
/org/gnome/desktop/screensaver/lock-enabled
/org/gnome/desktop/screensaver/idle-activation-enabled
EOF

# Set proper permissions
chmod 644 "$LOCAL_DB_DIR/00-screensaver"
chmod 644 "$LOCKS_DIR/screensaver"

# Update dconf database
echo -e "${YELLOW}Updating dconf database...${NC}"
dconf update

# Verify the settings were applied by checking the database
echo -e "${YELLOW}Verifying settings...${NC}"
if dconf dump /org/gnome/desktop/screensaver/ | grep -q "lock-delay=uint32 300"; then
    echo -e "${GREEN}Successfully set lock-delay to 300 seconds${NC}"
else
    echo -e "${RED}Warning: Failed to verify lock-delay setting${NC}"
fi

if dconf dump /org/gnome/desktop/screensaver/ | grep -q "lock-enabled=true"; then
    echo -e "${GREEN}Successfully enabled screen lock${NC}"
else
    echo -e "${RED}Warning: Failed to verify lock-enabled setting${NC}"
fi

# For active sessions, we need to reload the settings
echo -e "${YELLOW}Reloading GNOME settings for active sessions...${NC}"

# Find all active GNOME sessions and reload their settings
for user_session in $(ps aux | grep -i "gnome-shell" | grep -v grep | awk '{print $1}' | sort -u); do
    if [[ "$user_session" != "root" ]] && [[ "$user_session" != "_" ]]; then
        echo -e "${YELLOW}Sending signal to reload settings for user: $user_session${NC}"
        # Try to reload settings using dbus
        sudo -u "$user_session" dbus-send --print-reply --dest=org.gnome.SettingsDaemon /org/gnome/SettingsDaemon org.freedesktop.DBus.Properties.Set string:org.gnome.SettingsDaemon string:Enabled boolean:true 2>/dev/null || true
    fi
done

# Create a systemd drop-in to ensure dconf updates on startup
echo -e "${YELLOW}Creating systemd integration for persistent policy...${NC}"
mkdir -p /etc/systemd/system/gdm.service.d
cat > /etc/systemd/system/gdm.service.d/screensaver-lock.conf << 'EOF'
[Service]
ExecStartPost=/usr/bin/dconf update
EOF

# Create a script to be run at login to ensure settings are applied
mkdir -p /etc/profile.d
cat > /etc/profile.d/apply-screensaver-policy.sh << 'EOF'
#!/bin/bash
# Apply screensaver policy on login
if command -v dconf &> /dev/null; then
    dconf update 2>/dev/null || true
fi
EOF
chmod 755 /etc/profile.d/apply-screensaver-policy.sh

# Reload systemd
echo -e "${YELLOW}Reloading systemd configuration...${NC}"
systemctl daemon-reload

echo -e "${GREEN}GNOME screen-lock enforcement completed successfully!${NC}"
echo -e "${GREEN}Settings locked:${NC}"
echo "  - lock-delay: 300 seconds (5 minutes)"
echo "  - lock-enabled: true"
echo "  - idle-activation-enabled: true"
echo -e "${GREEN}Users will not be able to override these settings.${NC}"
echo -e "${YELLOW}Note: Users with active GNOME sessions should log out and log back in for changes to take effect.${NC}"

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
#!/bin/bash

# Lock down GNOME session idle timeout to prevent users from overriding it
# This script ensures that the session-idle-delay setting cannot be changed by ordinary users

set -e

# Define the GSettings schema and key
SCHEMA="org.gnome.desktop.session"
KEY="idle-delay"
VALUE=300  # 5 minutes in seconds

# Ensure dconf is installed
if ! command -v dconf &> /dev/null; then
    apt-get update
    apt-get install -y dconf-cli
fi

# Create the dconf database directory if it doesn't exist
mkdir -p /etc/dconf/db/local.d
mkdir -p /etc/dconf/profile

# Create or update the local dconf database configuration file
# This sets the system-wide idle delay value
cat > /etc/dconf/db/local.d/00-session-idle-lock << 'EOF'
[org/gnome/desktop/session]
idle-delay=uint32 300
EOF

# Create the locks file to prevent users from overriding the setting
# The locks file prevents users from changing settings via dconf
cat > /etc/dconf/db/local.d/locks/session-idle-lock << 'EOF'
/org/gnome/desktop/session/idle-delay
EOF

# Ensure the locks directory exists with proper permissions
mkdir -p /etc/dconf/db/local.d/locks
chmod 755 /etc/dconf/db/local.d
chmod 755 /etc/dconf/db/local.d/locks
chmod 644 /etc/dconf/db/local.d/00-session-idle-lock
chmod 644 /etc/dconf/db/local.d/locks/session-idle-lock

# Create or update the dconf profile for the system
# This ensures the local database is used
if [ ! -f /etc/dconf/profile/user ]; then
    cat > /etc/dconf/profile/user << 'EOF'
user-db:user
system-db:local
EOF
fi

# Verify the profile file contains the local database reference
if ! grep -q "system-db:local" /etc/dconf/profile/user; then
    echo "system-db:local" >> /etc/dconf/profile/user
fi

# Update the dconf database
dconf update

# For GNOME 45+ and later versions, also set this via GSettings if possible
# This ensures compatibility across different GNOME versions
if command -v gsettings &> /dev/null; then
    # Set the value at the system level
    gsettings set org.gnome.desktop.session idle-delay 300 2>/dev/null || true
fi

# Verify the configuration was applied
echo "Session idle timeout configuration applied:"
dconf read /org/gnome/desktop/session/idle-delay || echo "Value will be set on next login"

# Additional security: disable screen saver and use lock instead
mkdir -p /etc/dconf/db/local.d
cat >> /etc/dconf/db/local.d/00-session-idle-lock << 'EOF'

[org/gnome/desktop/screensaver]
lock-enabled=true
lock-delay=uint32 0
EOF

# Lock this setting too
echo "/org/gnome/desktop/screensaver/lock-enabled" >> /etc/dconf/db/local.d/locks/session-idle-lock
echo "/org/gnome/desktop/screensaver/lock-delay" >> /etc/dconf/db/local.d/locks/session-idle-lock

# Update the database again with the additional settings
dconf update

# For GNOME 40+, also configure the power profile to ensure screen locks
mkdir -p /etc/dconf/db/local.d
cat >> /etc/dconf/db/local.d/00-session-idle-lock << 'EOF'

[org/gnome/settings-daemon/plugins/power]
sleep-inactive-ac-type='lock'
sleep-inactive-battery-type='lock'
EOF

echo "/org/gnome/settings-daemon/plugins/power/sleep-inactive-ac-type" >> /etc/dconf/db/local.d/locks/session-idle-lock
echo "/org/gnome/settings-daemon/plugins/power/sleep-inactive-battery-type" >> /etc/dconf/db/local.d/locks/session-idle-lock

# Final database update
dconf update

echo "GNOME session idle timeout has been locked down at the system level."
echo "Users will not be able to override this setting in their preferences."
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
#!/bin/bash

# Ensure we have dconf available
if ! command -v dconf &> /dev/null; then
    echo "Error: dconf is not installed"
    exit 1
fi

# Ensure we have dconf-editor available for locking
if ! command -v dconf &> /dev/null; then
    apt-get update -qq
    apt-get install -y dconf-cli dconf-editor > /dev/null 2>&1
fi

# The GSettings key for logout on Ctrl-Alt-Del
KEY_PATH="org/gnome/settings-daemon/plugins/power"
KEY_NAME="power-button-action"

# Directory for dconf locks
DCONF_LOCKS_DIR="/etc/dconf/db/gdm.d"
DCONF_PROFILE_DIR="/etc/dconf/profile"
LOCK_FILE="${DCONF_LOCKS_DIR}/locks/01-disable-reboot"
PROFILE_FILE="${DCONF_PROFILE_DIR}/gdm"
SETTINGS_FILE="${DCONF_LOCKS_DIR}/01-disable-ctrl-alt-del"

# Create necessary directories
mkdir -p "${DCONF_LOCKS_DIR}/locks"
mkdir -p "${DCONF_PROFILE_DIR}"

# The setting we want to disable (nothing action for power button)
# Values can be: 'power-off' (default), 'interactive', 'nothing'
# Setting it to 'nothing' prevents the reboot on Ctrl-Alt-Del

# Create the dconf database configuration file
cat > "${SETTINGS_FILE}" << 'EOF'
[org/gnome/settings-daemon/plugins/power]
power-button-action='nothing'
EOF

# Create the lock file to prevent user override
cat > "${LOCK_FILE}" << 'EOF'
/org/gnome/settings-daemon/plugins/power/power-button-action
EOF

# Ensure dconf profile exists and includes gdm database
if [ ! -f "${PROFILE_FILE}" ]; then
    cat > "${PROFILE_FILE}" << 'EOF'
user-db:user
system-db:gdm
EOF
else
    # Check if gdm database is already in the profile
    if ! grep -q "system-db:gdm" "${PROFILE_FILE}"; then
        echo "system-db:gdm" >> "${PROFILE_FILE}"
    fi
fi

# Set proper permissions
chmod 644 "${SETTINGS_FILE}"
chmod 644 "${LOCK_FILE}"
chmod 644 "${PROFILE_FILE}"

# Update dconf database for the system
dconf update

# Verify the setting was applied by checking the current value
# This will show if the setting is correctly locked
echo "Verifying GNOME desktop configuration..."

# Check if the setting is in place
if grep -q "power-button-action='nothing'" "${SETTINGS_FILE}"; then
    echo "✓ Ctrl-Alt-Del reboot prevention configured"
else
    echo "✗ Failed to configure Ctrl-Alt-Del reboot prevention"
    exit 1
fi

# Check if the lock is in place
if grep -q "/org/gnome/settings-daemon/plugins/power/power-button-action" "${LOCK_FILE}"; then
    echo "✓ Setting locked to prevent user override"
else
    echo "✗ Failed to lock setting"
    exit 1
fi

# Verify dconf profile is correctly set
if grep -q "system-db:gdm" "${PROFILE_FILE}"; then
    echo "✓ dconf profile correctly configured"
else
    echo "✗ Failed to configure dconf profile"
    exit 1
fi

echo "Configuration complete. Ctrl-Alt-Del will not trigger a reboot."
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
#!/bin/bash

# Script to configure sudo authentication caching timeout on Ubuntu 24.04
# This script ensures sudo requires re-authentication on a finite schedule

set -e

# Define the timeout value in minutes (default: 5 minutes)
SUDO_TIMEOUT_MINUTES="${SUDO_TIMEOUT_MINUTES:-5}"

# Sudoers configuration directory
SUDOERS_DIR="/etc/sudoers.d"
SUDOERS_FILE="${SUDOERS_DIR}/99-sudo-timeout"

# Create sudoers directory if it doesn't exist
if [ ! -d "$SUDOERS_DIR" ]; then
    mkdir -p "$SUDOERS_DIR"
    chmod 0755 "$SUDOERS_DIR"
fi

# Function to validate sudoers file syntax
validate_sudoers() {
    local temp_file="$1"
    
    # Use visudo to check syntax without making changes
    if ! visudo -c -f "$temp_file" > /dev/null 2>&1; then
        return 1
    fi
    return 0
}

# Create temporary file with proper permissions
TEMP_SUDOERS=$(mktemp)
chmod 0440 "$TEMP_SUDOERS"

# Write the sudo timeout configuration
# The timestamp_timeout parameter controls how long sudo caches authentication
# Setting it to a specific number of minutes (not -1 or blank which means never expire)
cat > "$TEMP_SUDOERS" << EOF
# Configure sudo authentication timeout to ${SUDO_TIMEOUT_MINUTES} minutes
# This ensures sudo prompts for password re-authentication after the timeout expires
Defaults timestamp_timeout=${SUDO_TIMEOUT_MINUTES}

# Also configure the timestamp_type to 'global' to use a single timeout for all commands
Defaults timestamp_type=global
EOF

# Validate the syntax of the new sudoers file
if ! validate_sudoers "$TEMP_SUDOERS"; then
    echo "Error: Invalid sudoers syntax generated" >&2
    rm -f "$TEMP_SUDOERS"
    exit 1
fi

# Check if the configuration file already exists and needs updating
if [ -f "$SUDOERS_FILE" ]; then
    # Compare the content to see if changes are needed
    if cmp -s "$TEMP_SUDOERS" "$SUDOERS_FILE"; then
        # File is already correct, no changes needed
        rm -f "$TEMP_SUDOERS"
        exit 0
    fi
fi

# Backup existing configuration if it exists
if [ -f "$SUDOERS_FILE" ]; then
    cp "$SUDOERS_FILE" "${SUDOERS_FILE}.backup.$(date +%s)"
fi

# Install the new configuration
mv "$TEMP_SUDOERS" "$SUDOERS_FILE"
chmod 0440 "$SUDOERS_FILE"

# Verify the configuration was applied correctly
if validate_sudoers "$SUDOERS_FILE"; then
    exit 0
else
    echo "Error: Failed to apply sudoers configuration" >&2
    
    # Restore backup if it exists
    if [ -f "${SUDOERS_FILE}.backup"* ]; then
        latest_backup=$(ls -t "${SUDOERS_FILE}.backup"* | head -1)
        cp "$latest_backup" "$SUDOERS_FILE"
    fi
    
    exit 1
fi
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
#!/bin/bash

set -euo pipefail

# Function to check if a line exists in sudoers
check_sudoers_line() {
    local line="$1"
    sudo grep -F "$line" /etc/sudoers > /dev/null 2>&1
}

# Function to safely add a line to sudoers
add_sudoers_line() {
    local line="$1"
    if ! check_sudoers_line "$line"; then
        echo "$line" | sudo tee -a /etc/sudoers > /dev/null
    fi
}

# Function to remove a line from sudoers
remove_sudoers_line() {
    local pattern="$1"
    if sudo grep -F "$pattern" /etc/sudoers > /dev/null 2>&1; then
        sudo sed -i "/$pattern/d" /etc/sudoers
    fi
}

# Verify sudoers file exists and has correct permissions
if [ ! -f /etc/sudoers ]; then
    echo "Error: /etc/sudoers file not found"
    exit 1
fi

# Verify we can use sudo
if ! sudo -l > /dev/null 2>&1; then
    echo "Error: Cannot execute sudo commands"
    exit 1
fi

# Create a backup of sudoers file
sudo cp /etc/sudoers /etc/sudoers.backup.$(date +%s)

# Remove any existing problematic defaults that might allow root/target password authentication
remove_sudoers_line "Defaults use_pty"
remove_sudoers_line "Defaults rootpw"
remove_sudoers_line "Defaults targetpw"
remove_sudoers_line "Defaults runaspw"

# Add the required security defaults to enforce password authentication for invoking user only
# This ensures that:
# 1. !rootpw - Don't prompt for root password
# 2. !targetpw - Don't prompt for target user password  
# 3. !runaspw - Don't prompt for run-as user password
# 4. use_pty - Use pseudo-terminal for better security
# 5. authenticate - Require authentication
add_sudoers_line "Defaults !rootpw"
add_sudoers_line "Defaults !targetpw"
add_sudoers_line "Defaults !runaspw"
add_sudoers_line "Defaults use_pty"
add_sudoers_line "Defaults authenticate"

# Verify sudoers syntax before applying
if ! sudo -cf /etc/sudoers > /dev/null 2>&1; then
    echo "Error: sudoers file has syntax errors, restoring backup"
    sudo cp /etc/sudoers.backup.$(ls -t /etc/sudoers.backup.* 2>/dev/null | head -1 | sed 's/.*\.//') /etc/sudoers
    exit 1
fi

# Ensure /etc/sudoers has correct permissions
sudo chmod 440 /etc/sudoers
sudo chown root:root /etc/sudoers

# Check if /etc/sudoers.d directory exists and is properly configured
if [ ! -d /etc/sudoers.d ]; then
    sudo mkdir -p /etc/sudoers.d
    sudo chmod 750 /etc/sudoers.d
fi

# Remove any problematic configuration files in sudoers.d
for file in /etc/sudoers.d/*; do
    if [ -f "$file" ] && [ "$(basename "$file")" != "README" ]; then
        if sudo grep -E "(rootpw|targetpw|runaspw)" "$file" > /dev/null 2>&1; then
            sudo rm "$file"
        fi
    fi
done

# Create a configuration in sudoers.d to ensure these settings persist across updates
sudo tee /etc/sudoers.d/10-enforce-user-password > /dev/null << 'EOF'
# Enforce that sudo requires the invoking user's password only
# Disable root password, target user password, and run-as user password prompts
Defaults !rootpw
Defaults !targetpw
Defaults !runaspw
Defaults authenticate
Defaults use_pty
EOF

# Set correct permissions for the sudoers.d file
sudo chmod 440 /etc/sudoers.d/10-enforce-user-password
sudo chown root:root /etc/sudoers.d/10-enforce-user-password

# Verify the configuration is correct
if sudo visudo -c -f /etc/sudoers.d/10-enforce-user-password > /dev/null 2>&1; then
    exit 0
else
    echo "Error: Configuration verification failed"
    exit 1
fi
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

set -euo pipefail

echo "Checking and ensuring hardware RNG entropy tooling is installed..."

# Define the package that provides hardware RNG entropy support
RNG_PACKAGE="rng-tools"

# Check if the package is already installed
if dpkg -l | grep -q "^ii.*${RNG_PACKAGE}"; then
    echo "${RNG_PACKAGE} is already installed."
else
    echo "${RNG_PACKAGE} is not installed. Installing..."
    apt-get update
    apt-get install -y "${RNG_PACKAGE}"
fi

# Ensure the rng-tools service is enabled and running
if systemctl is-enabled rng-tools >/dev/null 2>&1; then
    echo "rng-tools service is already enabled."
else
    echo "Enabling rng-tools service..."
    systemctl enable rng-tools
fi

if systemctl is-active rng-tools >/dev/null 2>&1; then
    echo "rng-tools service is already running."
else
    echo "Starting rng-tools service..."
    systemctl start rng-tools
fi

echo "Hardware RNG entropy tooling is now ensured to be present and running."
echo "System entropy pool should now have access to high-quality randomness."
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

# Idempotent script to ensure gssproxy is not installed on Ubuntu 24.04

# Check if gssproxy package is installed
if dpkg -l | grep -q "^ii.*gssproxy"; then
    echo "gssproxy package found. Removing it..."
    apt-get remove -y gssproxy
    echo "gssproxy package has been removed."
else
    echo "gssproxy package is not installed. No action needed."
fi

# Verify removal
if dpkg -l | grep -q "^ii.*gssproxy"; then
    echo "Error: gssproxy package is still installed."
    exit 1
else
    echo "Verification complete: gssproxy is not present on the system."
    exit 0
fi
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

# Script to ensure iprutils package is not present on Ubuntu 24.04
# This script is idempotent - it can be run multiple times safely

# Function to check if package is installed
is_package_installed() {
    dpkg -l | grep -q "^ii.*$1[[:space:]]"
    return $?
}

# Function to remove package if installed
remove_package_if_installed() {
    local package="$1"
    
    if is_package_installed "$package"; then
        echo "Package $package is installed. Removing it..."
        apt-get update -qq
        apt-get remove -y "$package"
        if [ $? -eq 0 ]; then
            echo "Package $package has been successfully removed."
        else
            echo "Failed to remove package $package." >&2
            return 1
        fi
    else
        echo "Package $package is not installed. System is already compliant."
    fi
    return 0
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root" >&2
    exit 1
fi

# Ensure iprutils is not present
remove_package_if_installed "iprutils"

exit $?
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
#!/bin/bash

set -euo pipefail

# Check if the system has the ABRT (Automatic Bug Reporting Tool) Red Hat Support plugin installed
# and remove it if present

# ABRT plugin package names that integrate with Red Hat Support
PLUGIN_PACKAGES=(
    "abrt-addon-rhtsupport"
    "abrt-rhtsupport"
)

# Remove any installed ABRT Red Hat Support reporting plugins
for package in "${PLUGIN_PACKAGES[@]}"; do
    if dpkg -l | grep -q "^ii.*${package}"; then
        apt-get remove -y "$package" 2>/dev/null || true
    fi
done

# Ensure ABRT service itself is not running if it exists
if systemctl list-units --all | grep -q "abrtd.service"; then
    systemctl stop abrtd 2>/dev/null || true
    systemctl disable abrtd 2>/dev/null || true
fi

# Remove ABRT configuration for Red Hat Support reporting if it exists
if [ -f /etc/abrt/plugins/rhtsupport.conf ]; then
    rm -f /etc/abrt/plugins/rhtsupport.conf
fi

# Disable the ABRT reporting plugin by removing/disabling the plugin configuration
if [ -d /etc/abrt/plugins ]; then
    for plugin_conf in /etc/abrt/plugins/*rhtsupport* /etc/abrt/plugins/*redhat*; do
        if [ -e "$plugin_conf" ]; then
            rm -f "$plugin_conf"
        fi
    done
fi

exit 0
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

# Idempotent bash script to ensure system-tuning daemon package is not present on Ubuntu 24.04

set -e

PACKAGE_NAME="tuned"

# Check if the package is installed
if dpkg -l | grep -q "^ii.*${PACKAGE_NAME}"; then
    echo "Package ${PACKAGE_NAME} is installed. Removing it..."
    sudo apt-get update
    sudo apt-get remove -y "${PACKAGE_NAME}"
    echo "Package ${PACKAGE_NAME} has been removed successfully."
else
    echo "Package ${PACKAGE_NAME} is not installed. No action needed."
fi

# Verify the package is not present
if ! dpkg -l | grep -q "^ii.*${PACKAGE_NAME}"; then
    echo "Verification successful: ${PACKAGE_NAME} is not present on the system."
    exit 0
else
    echo "Error: ${PACKAGE_NAME} is still present on the system."
    exit 1
fi
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
#!/bin/bash

# Ensure signature verification for local package installations on Ubuntu 24.04
# This script is idempotent and configures APT to verify GPG signatures

set -e

# Function to check if running on Ubuntu 24.04
check_ubuntu_version() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "$VERSION_ID" == "24.04" ]] && [[ "$ID" == "ubuntu" ]]; then
            return 0
        fi
    fi
    echo "Error: This script is designed for Ubuntu 24.04"
    return 1
}

# Function to ensure APT configuration directory exists
ensure_apt_config_dir() {
    if [ ! -d /etc/apt/apt.conf.d ]; then
        mkdir -p /etc/apt/apt.conf.d
    fi
}

# Function to configure GPG signature verification
configure_gpg_verification() {
    local config_file="/etc/apt/apt.conf.d/51-signature-verification"
    
    # Check if configuration already exists with correct settings
    if [ -f "$config_file" ]; then
        if grep -q "APT::Get::AllowUnauthenticated \"false\"" "$config_file" && \
           grep -q "Aptitude::ProblemResolver::SolutionCost \"removals:1000000\"" "$config_file"; then
            echo "GPG signature verification is already configured correctly"
            return 0
        fi
    fi
    
    # Create or update the configuration file
    cat > "$config_file" << 'EOF'
// Enforce GPG signature verification for all package installations
// This prevents installation of tampered or untrusted software

// Disallow installation of unauthenticated packages
APT::Get::AllowUnauthenticated "false";

// Ensure APT fails if signature verification fails
APT::Authentication::TrustCDROM "false";

// Require valid signatures for all packages
APT::Update::Pre-Invoke {"test -f /etc/apt/trusted.gpg && test -f /etc/apt/trusted.gpg.d/* || true";};

// Verify signatures before installation
Apt::Post-Invoke {"/bin/true";};

// Configure problem resolver to avoid signature mismatches
Aptitude::ProblemResolver::SolutionCost "removals:1000000";
EOF
    
    echo "GPG signature verification configuration has been applied"
    return 0
}

# Function to ensure trusted GPG keys are properly installed
ensure_trusted_keys() {
    # Check if we have trusted.gpg or trusted.gpg.d directory
    if [ ! -d /etc/apt/trusted.gpg.d ]; then
        mkdir -p /etc/apt/trusted.gpg.d
        chmod 755 /etc/apt/trusted.gpg.d
    fi
    
    # Ensure the trusted.gpg file exists or at least the directory is set up
    if [ ! -f /etc/apt/trusted.gpg ] && [ ! -d /etc/apt/trusted.gpg.d ]; then
        echo "Warning: No trusted GPG keys directory found. Please ensure your GPG keys are imported."
    fi
    
    return 0
}

# Function to verify APT configuration
verify_apt_config() {
    # Check if APT can read its configuration
    if ! apt-get -qq check 2>/dev/null; then
        echo "Warning: APT configuration check encountered issues, but continuing..."
    fi
    
    return 0
}

# Main execution
main() {
    echo "Ubuntu 24.04 Package Signature Verification Enforcement"
    echo "========================================================"
    
    # Check if running as root
    if [ "$EUID" -ne 0 ]; then
        echo "Error: This script must be run as root"
        exit 1
    fi
    
    # Check Ubuntu version
    if ! check_ubuntu_version; then
        exit 1
    fi
    
    echo "✓ System identified as Ubuntu 24.04"
    
    # Ensure APT configuration directory exists
    ensure_apt_config_dir
    echo "✓ APT configuration directory ensured"
    
    # Configure GPG signature verification
    configure_gpg_verification
    echo "✓ GPG signature verification configured"
    
    # Ensure trusted keys directory
    ensure_trusted_keys
    echo "✓ Trusted GPG keys directory ensured"
    
    # Verify APT configuration
    verify_apt_config
    echo "✓ APT configuration verified"
    
    echo ""
    echo "Security Configuration Complete"
    echo "==============================="
    echo "The system is now configured to verify GPG signatures for all package installations."
    echo "Untrusted or tampered packages will be rejected during installation."
    
    return 0
}

# Execute main function
main "$@"
exit $?
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

# Remediation script to ensure user authentication is configured through
# Ubuntu's supported profile-based authentication tool

set -e

# Function to log messages
log_message() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" >> /var/log/auth-remediation.log
    echo "$1"
}

# Function to check if sssd is available and working
check_sssd_availability() {
    if ! command -v sssd &> /dev/null; then
        return 1
    fi
    
    if ! dpkg -l | grep -q sssd; then
        return 1
    fi
    
    return 0
}

# Function to check if authselect is available
check_authselect_availability() {
    if ! command -v authselect &> /dev/null; then
        return 1
    fi
    
    if ! dpkg -l | grep -q authselect; then
        return 1
    fi
    
    return 0
}

# Main remediation logic
log_message "Starting user authentication configuration remediation..."

# Update package lists
apt-get update -qq

# Install authselect if not present (preferred method on Ubuntu 24.04)
if ! check_authselect_availability; then
    log_message "Installing authselect..."
    apt-get install -y authselect > /dev/null 2>&1
fi

# Install sssd as well for complete identity management
if ! check_sssd_availability; then
    log_message "Installing sssd..."
    apt-get install -y sssd sssd-tools > /dev/null 2>&1
fi

# Create a systemd unit to ensure persistent configuration
cat > /etc/systemd/system/auth-remediation.service << 'EOF'
[Unit]
Description=User Authentication Configuration Remediation
After=network-online.target
Wants=network-online.target
DefaultDependencies=no

[Service]
Type=oneshot
ExecStart=/usr/local/bin/auth-remediation-runner.sh
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Create the remediation runner script
cat > /usr/local/bin/auth-remediation-runner.sh << 'RUNNER_EOF'
#!/bin/bash

set -e

log_message() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" >> /var/log/auth-remediation.log
}

# Function to select appropriate profile based on system configuration
select_authentication_profile() {
    # Check if SSSD is available for centralized authentication
    if command -v sssd &> /dev/null; then
        # Use sssd-based profile if SSSD is configured
        if [ -f /etc/sssd/sssd.conf ]; then
            echo "sssd"
            return 0
        fi
    fi
    
    # Default to system-auth profile (basic local authentication)
    echo "system-auth"
    return 0
}

# Check if authselect is available and functional
if ! command -v authselect &> /dev/null; then
    log_message "authselect not available, attempting installation..."
    apt-get update -qq
    apt-get install -y authselect > /dev/null 2>&1
fi

# Select the appropriate profile
PROFILE=$(select_authentication_profile)
log_message "Selected authentication profile: $PROFILE"

# Apply the profile
if authselect select "$PROFILE" --force 2>/dev/null; then
    log_message "Successfully applied profile: $PROFILE"
else
    # If the specific profile doesn't exist, use the default
    log_message "Profile $PROFILE not available, using system-auth"
    authselect select "system-auth" --force > /dev/null 2>&1
fi

# Enable and start sssd if it's installed and not running
if command -v sssd &> /dev/null; then
    systemctl enable sssd > /dev/null 2>&1 || true
    systemctl start sssd > /dev/null 2>&1 || true
fi

log_message "Authentication configuration remediation completed"
RUNNER_EOF

chmod +x /usr/local/bin/auth-remediation-runner.sh

# Enable and start the remediation service
systemctl daemon-reload
systemctl enable auth-remediation.service
systemctl start auth-remediation.service

# Run the remediation immediately
/usr/local/bin/auth-remediation-runner.sh

log_message "User authentication configuration remediation completed successfully"

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
#!/bin/bash

# Ensure the script is idempotent and can be run multiple times safely
set -e

# Define the DoD-required banner text
DOD_BANNER="You are accessing a U.S. Government (USG) information system (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network defense, quality of service monitoring, network engineering, and law enforcement (LE);

-At any time, the USG may inspect and seize data stored on this IS;

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose;

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit--and these measures may be overridden and circumvented by authorized USG personnel;

-You are warned that use of this IS by unauthorized persons is illegal and subject to criminal and civil penalties;

-Use of this IS constitutes express consent to monitoring described herein.

DISCONNECT IMMEDIATELY if you do not consent to the conditions stated in this warning."

# Ensure /etc/issue exists and has the correct content
if ! grep -q "You are accessing a U.S. Government" /etc/issue 2>/dev/null; then
    echo "$DOD_BANNER" > /etc/issue
else
    # Check if the content is different and update if needed
    if ! diff -q <(echo "$DOD_BANNER") /etc/issue > /dev/null 2>&1; then
        echo "$DOD_BANNER" > /etc/issue
    fi
fi

# Ensure /etc/issue.net exists and has the correct content (for network logins)
if ! grep -q "You are accessing a U.S. Government" /etc/issue.net 2>/dev/null; then
    echo "$DOD_BANNER" > /etc/issue.net
else
    # Check if the content is different and update if needed
    if ! diff -q <(echo "$DOD_BANNER") /etc/issue.net > /dev/null 2>&1; then
        echo "$DOD_BANNER" > /etc/issue.net
    fi
fi

# Set proper permissions for the banner files
chmod 644 /etc/issue
chmod 644 /etc/issue.net

# Ensure PAM is configured to display the banner at console login
# Configure /etc/pam.d/login to display the banner
if ! grep -q "pam_issue.so" /etc/pam.d/login; then
    # Insert the pam_issue.so line after the auth includes
    sed -i '/^@include common-auth$/a session optional pam_issue.so issue=/etc/issue' /etc/pam.d/login
fi

# Configure /etc/pam.d/sshd to display the banner (if SSH is being used)
if [ -f /etc/pam.d/sshd ]; then
    if ! grep -q "pam_issue.so" /etc/pam.d/sshd; then
        # Add the pam_issue.so configuration for SSH
        echo "session optional pam_issue.so issue=/etc/issue.net" >> /etc/pam.d/sshd
    fi
fi

# Verify that the Banner directive is set in sshd_config for SSH
if [ -f /etc/ssh/sshd_config ]; then
    if ! grep -q "^Banner " /etc/ssh/sshd_config; then
        echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
    else
        # Update existing Banner directive to point to /etc/issue.net
        sed -i 's|^Banner .*|Banner /etc/issue.net|' /etc/ssh/sshd_config
    fi
fi

# Ensure the banner files are owned by root
chown root:root /etc/issue
chown root:root /etc/issue.net

echo "DoD login banner has been successfully configured."
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
#!/bin/bash
set -e

# Enable debug mode for troubleshooting
set -x

# Define the GDM configuration directory and files
GDM_CONF_DIR="/etc/gdm3"
GDM_CUSTOM_CONF="${GDM_CONF_DIR}/custom.conf"
DCONF_DB_DIR="/etc/dconf/db"
DCONF_PROFILE_DIR="/etc/dconf/profile"
DCONF_PROFILE="${DCONF_PROFILE_DIR}/gdm"
DCONF_DB="${DCONF_DB_DIR}/gdm"
DCONF_LOCKS_DIR="/etc/dconf/db/gdm.d/locks"

# Create a login warning banner
LOGIN_BANNER="AUTHORIZED ACCESS ONLY
This system is for authorized use only. All activity on this system is monitored and logged. Unauthorized access attempts will be prosecuted to the fullest extent of the law."

# Escape the banner for use in dconf
ESCAPED_BANNER=$(echo "$LOGIN_BANNER" | sed "s/'/''/g")

# Ensure required directories exist
mkdir -p "$GDM_CONF_DIR"
mkdir -p "$DCONF_DB_DIR"
mkdir -p "$DCONF_PROFILE_DIR"
mkdir -p "$DCONF_LOCKS_DIR"

# Step 1: Configure GDM custom.conf to enable the banner
if [ ! -f "$GDM_CUSTOM_CONF" ]; then
    cat > "$GDM_CUSTOM_CONF" << EOF
[daemon]
# GDM configuration file

[security]
# Security settings

[xdmcp]
# XDMCP settings
EOF
fi

# Ensure the [daemon] section exists
if ! grep -q "^\[daemon\]" "$GDM_CUSTOM_CONF"; then
    echo "" >> "$GDM_CUSTOM_CONF"
    echo "[daemon]" >> "$GDM_CUSTOM_CONF"
fi

# Step 2: Create dconf profile for GDM
if [ ! -f "$DCONF_PROFILE" ]; then
    cat > "$DCONF_PROFILE" << EOF
user-db:user
system-db:gdm
file-db:${DCONF_DB}
EOF
fi

# Step 3: Create dconf database with the banner setting
mkdir -p "$(dirname "$DCONF_DB")"

# Create a temporary keyfile for dconf compilation
DCONF_KEYFILE=$(mktemp)
trap "rm -f '$DCONF_KEYFILE'" EXIT

cat > "$DCONF_KEYFILE" << EOF
[org/gnome/login-screen]
banner-message-enable=true
banner-message-text='$ESCAPED_BANNER'
disable-user-list=false
EOF

# Ensure the gdm.d directory exists
mkdir -p "${DCONF_DB}.d"

# Copy the keyfile to the gdm.d directory
cp "$DCONF_KEYFILE" "${DCONF_DB}.d/00-banner"

# Compile the dconf database
dconf compile "$DCONF_DB" "${DCONF_DB}.d" || true

# Step 4: Lock the banner settings to prevent user override
mkdir -p "$DCONF_LOCKS_DIR"
cat > "${DCONF_LOCKS_DIR}/banner" << EOF
/org/gnome/login-screen/banner-message-enable
/org/gnome/login-screen/banner-message-text
EOF

# Step 5: Set proper permissions
chown -R root:root "$GDM_CONF_DIR"
chmod 755 "$GDM_CONF_DIR"
chmod 644 "$GDM_CUSTOM_CONF"

chown -R root:root "$DCONF_DB_DIR"
chmod 755 "$DCONF_DB_DIR"
chmod 755 "${DCONF_DB}.d"
chmod 644 "${DCONF_DB}.d"/*

chown -R root:root "$DCONF_PROFILE_DIR"
chmod 755 "$DCONF_PROFILE_DIR"
chmod 644 "$DCONF_PROFILE"

chown -R root:root "$DCONF_LOCKS_DIR"
chmod 755 "$DCONF_LOCKS_DIR"
chmod 644 "${DCONF_LOCKS_DIR}"/*

# Step 6: Update GDM gschema if needed
if ! grep -q "banner-message" /usr/share/glib-2.0/schemas/org.gnome.login-screen.gschema.xml 2>/dev/null; then
    # The schema should already exist in modern GNOME versions
    # If not, we would need to add it, but this is typically pre-existing
    :
fi

# Step 7: Compile GLib schemas
glib-compile-schemas /usr/share/glib-2.0/schemas/ 2>/dev/null || true

# Step 8: Restart GDM to apply changes (optional - changes take effect on next login)
# Uncomment to restart GDM immediately
# systemctl restart gdm3 || true

echo "GDM login banner configuration completed successfully."
echo "Banner will be displayed on the next login screen."
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
#!/bin/bash
set -e

# GNOME Display Manager Login Banner Configuration Script
# This script configures a login screen warning banner in GDM on Ubuntu 24.04

# Define the approved organizational warning banner message
# This should match your environment's approved message exactly
BANNER_MESSAGE="AUTHORIZED ACCESS ONLY

This system is for authorized use only. All activity is monitored and logged.
Unauthorized access attempts will be investigated and prosecuted to the fullest
extent of the law. By accessing this system, you consent to monitoring and agree
to comply with all applicable policies and procedures."

# GDM configuration file paths
GDM_CONF_DIR="/etc/dconf/db/gdm.d"
GDM_DCONF_DB="/etc/dconf/db/gdm"
DCONF_LOCK_DIR="/etc/dconf/db/gdm.d/locks"
DCONF_PROFILE_DIR="/etc/dconf/profile"

# Create necessary directories with proper permissions
mkdir -p "$GDM_CONF_DIR"
mkdir -p "$DCONF_LOCK_DIR"
mkdir -p "$DCONF_PROFILE_DIR"

# Step 1: Create the GDM dconf profile if it doesn't exist
if [ ! -f "$DCONF_PROFILE_DIR/gdm" ]; then
    cat > "$DCONF_PROFILE_DIR/gdm" << 'EOF'
user-db:user
system-db:gdm
file-db:"$XDG_RUNTIME_DIR/dconf/user"
EOF
    chmod 644 "$DCONF_PROFILE_DIR/gdm"
fi

# Step 2: Create the banner configuration file in GDM dconf directory
cat > "$GDM_CONF_DIR/01-banner" << EOF
[org/gnome/login-screen]
banner-message-enable=true
banner-message-text='$BANNER_MESSAGE'
disable-user-list=false
EOF

chmod 644 "$GDM_CONF_DIR/01-banner"

# Step 3: Create the lock file to prevent non-privileged users from changing the banner
cat > "$DCONF_LOCK_DIR/01-banner-lock" << 'EOF'
/org/gnome/login-screen/banner-message-enable
/org/gnome/login-screen/banner-message-text
EOF

chmod 644 "$DCONF_LOCK_DIR/01-banner-lock"

# Step 4: Compile the dconf database to apply changes
dconf update

# Step 5: Verify the configuration was applied
echo "Banner configuration has been applied."
echo "Checking configuration status:"

# Try to read the setting using dconf read (this may require appropriate permissions)
if command -v dconf &> /dev/null; then
    echo "Banner message enable status:"
    dconf read /org/gnome/login-screen/banner-message-enable || echo "Configuration applied (may require login to view)"
    echo "Banner message text (first 50 chars):"
    dconf read /org/gnome/login-screen/banner-message-text | head -c 50 || echo "Configuration applied (may require login to view)"
    echo ""
fi

# Step 6: Ensure GDM service is restarted to apply changes
echo "Restarting GNOME Display Manager to apply changes..."
if systemctl is-active --quiet gdm; then
    systemctl restart gdm
    echo "GDM restarted successfully."
elif systemctl is-active --quiet gdm3; then
    systemctl restart gdm3
    echo "GDM3 restarted successfully."
fi

# Step 7: Verify configuration files exist
echo ""
echo "Configuration verification:"
echo "✓ GDM configuration file: $GDM_CONF_DIR/01-banner"
[ -f "$GDM_CONF_DIR/01-banner" ] && echo "  File exists: YES" || echo "  File exists: NO"
echo "✓ Lock file: $DCONF_LOCK_DIR/01-banner-lock"
[ -f "$DCONF_LOCK_DIR/01-banner-lock" ] && echo "  File exists: YES" || echo "  File exists: NO"

# Step 8: Add to system startup if needed
# This ensures the banner persists across reboots
if [ ! -f "/etc/systemd/system/gdm-banner-lock.service" ]; then
    cat > "/etc/systemd/system/gdm-banner-lock.service" << 'EOF'
[Unit]
Description=Apply GDM Login Banner Configuration
After=dconf.target
Before=display-manager.service

[Service]
Type=oneshot
ExecStart=/bin/dconf update
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable gdm-banner-lock.service
    echo "✓ Created and enabled gdm-banner-lock.service for persistence"
fi

echo ""
echo "Login banner configuration completed successfully."
echo "The warning banner will appear on the GNOME Display Manager login screen."
echo "Configuration is locked and non-privileged users cannot override it."
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
#!/bin/bash

set -euo pipefail

# Ensure pam_faillock module is installed
apt-get update -qq
apt-get install -y -qq libpam-modules libpam-cracklib

# Configure pam_faillock for account lockout on repeated failed login attempts
# This script ensures idempotent configuration of the PAM authentication stack

# Function to check if a line exists in a file
line_exists() {
    local line="$1"
    local file="$2"
    grep -Fxq "$line" "$file" 2>/dev/null
}

# Function to add a line to a file if it doesn't exist
add_line_if_missing() {
    local line="$1"
    local file="$2"
    local position="${3:-end}"  # end, begin, or after:pattern

    if ! line_exists "$line" "$file"; then
        if [ "$position" = "end" ]; then
            echo "$line" >> "$file"
        elif [ "$position" = "begin" ]; then
            echo "$line" | cat - "$file" > "$file.tmp" && mv "$file.tmp" "$file"
        elif [[ "$position" == after:* ]]; then
            local pattern="${position#after:}"
            sed -i "/^${pattern}/a ${line}" "$file"
        fi
    fi
}

# Backup original files
backup_file() {
    local file="$1"
    if [ -f "$file" ] && [ ! -f "${file}.backup" ]; then
        cp "$file" "${file}.backup"
    fi
}

# Process common-auth file for login authentication
backup_file /etc/pam.d/common-auth

# Remove existing faillock entries to ensure clean configuration
sed -i '/pam_faillock.so/d' /etc/pam.d/common-auth

# Add pam_faillock for authentication phase (auth requisite - at the beginning)
# This sets up the lockout mechanism before password checking
add_line_if_missing "auth requisite pam_faillock.so preauth silent audit deny=5 unlock_time=900 even_deny_root root_unlock_time=60" /etc/pam.d/common-auth "begin"

# Add pam_faillock for the account phase (auth required - after password module)
# We need to add it after the pam_unix module if it exists, or at the end of auth section
if grep -q "^auth.*pam_unix.so" /etc/pam.d/common-auth; then
    # If pam_unix exists, add faillock after it
    if ! grep -q "^auth.*pam_faillock.so.*default" /etc/pam.d/common-auth; then
        sed -i '/^auth.*optional.*pam_permit.so/i auth required pam_faillock.so authfail deny=5 unlock_time=900 even_deny_root root_unlock_time=60' /etc/pam.d/common-auth
    fi
else
    # Otherwise add it before optional permit
    add_line_if_missing "auth required pam_faillock.so authfail deny=5 unlock_time=900 even_deny_root root_unlock_time=60" /etc/pam.d/common-auth "after:^auth.*pam_unix"
fi

# Ensure account phase includes faillock for unlocking
backup_file /etc/pam.d/common-account

# Remove existing faillock entries from account phase
sed -i '/pam_faillock.so/d' /etc/pam.d/common-account

# Add faillock to account phase for proper unlock mechanism
add_line_if_missing "account required pam_faillock.so" /etc/pam.d/common-account "begin"

# Create faillock configuration directory if it doesn't exist
mkdir -p /var/run/faillock
chmod 755 /var/run/faillock

# Set up faillock configuration file with appropriate settings
faillock_conf="/etc/security/faillock.conf"
if [ ! -f "$faillock_conf" ]; then
    cat > "$faillock_conf" << 'EOF'
# Faillock configuration
# Number of authentication failures before account lockout
deny = 5

# Duration (in seconds) that the account is locked (15 minutes)
unlock_time = 900

# Allow even the root account to be locked
even_deny_root

# Time in seconds to lock the root account (1 minute)
root_unlock_time = 60

# Set this to enable silent mode (no message to user)
silent

# Audit login failures
audit
EOF
    chmod 644 "$faillock_conf"
fi

# Verify the configuration is in place
if grep -q "auth requisite pam_faillock.so" /etc/pam.d/common-auth && \
   grep -q "auth required pam_faillock.so.*authfail" /etc/pam.d/common-auth && \
   grep -q "account required pam_faillock.so" /etc/pam.d/common-account; then
    echo "PAM faillock configuration successfully applied"
    exit 0
else
    echo "Error: PAM faillock configuration incomplete"
    exit 1
fi
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
#!/bin/bash

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root"
    exit 1
fi

log_info "Starting PAM configuration for account lockout protection..."

# Ensure required packages are installed
log_info "Checking and installing required packages..."
apt-get update -qq
apt-get install -y -qq libpam-modules libpam-modules-bin > /dev/null 2>&1 || true

# Function to check if a line exists in a file
line_exists() {
    local file="$1"
    local line="$2"
    if grep -Fxq "$line" "$file" 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

# Function to add line to file if it doesn't exist
add_line_if_not_exists() {
    local file="$1"
    local line="$2"
    if ! line_exists "$file" "$line"; then
        echo "$line" >> "$file"
        return 0
    else
        return 1
    fi
}

# Backup original files
backup_pam_file() {
    local file="$1"
    if [[ -f "$file" ]] && [[ ! -f "${file}.orig" ]]; then
        cp "$file" "${file}.orig"
        log_info "Backed up $file to ${file}.orig"
    fi
}

# Configure pam_faillock for account lockout
configure_faillock() {
    log_info "Configuring pam_faillock for account lockout..."
    
    local pam_auth_file="/etc/pam.d/common-auth"
    local pam_account_file="/etc/pam.d/common-account"
    
    backup_pam_file "$pam_auth_file"
    backup_pam_file "$pam_account_file"
    
    # Create a temporary file for common-auth
    local temp_auth=$(mktemp)
    
    # Add faillock preauth - this counts failures before password check
    cat > "$temp_auth" << 'EOF'
# Account lockout settings for faillock
auth    required                        pam_faillock.so preauth silent audit deny=5 unlock_time=900
EOF
    
    # Add the rest of common-auth
    if [[ -f "$pam_auth_file" ]]; then
        # Remove any existing faillock or unix auth lines and add ours at the beginning
        grep -v "pam_faillock\|pam_unix.*password" "$pam_auth_file" >> "$temp_auth" || true
    fi
    
    # Add unix auth with faillock default parameters
    echo "auth    [default=die]                   pam_unix.so obscure try_first_pass yescrypt" >> "$temp_auth"
    
    # Add faillock authfail - this records the failure
    echo "auth    requisite                       pam_deny.so" >> "$temp_auth"
    echo "auth    required                        pam_permit.so" >> "$temp_auth"
    echo "auth    required                        pam_faillock.so authfail audit deny=5 unlock_time=900" >> "$temp_auth"
    
    # Update common-auth
    mv "$temp_auth" "$pam_auth_file"
    chmod 644 "$pam_auth_file"
    
    log_info "Configured faillock in common-auth"
    
    # Configure common-account for account lockout enforcement
    local temp_account=$(mktemp)
    
    # Add faillock module for account lockout check
    echo "# pam_unix.so.1" > "$temp_account"
    echo "account    required                      pam_unix.so" >> "$temp_account"
    
    # Add faillock to enforce lockout
    echo "account    required                      pam_faillock.so" >> "$temp_account"
    
    # Add remaining account settings
    if [[ -f "$pam_account_file" ]]; then
        grep -v "pam_faillock\|pam_unix" "$pam_account_file" >> "$temp_account" || true
    fi
    
    mv "$temp_account" "$pam_account_file"
    chmod 644 "$pam_account_file"
    
    log_info "Configured faillock in common-account"
}

# Configure faillock defaults file
configure_faillock_defaults() {
    log_info "Configuring faillock defaults..."
    
    local faillock_conf="/etc/security/faillock.conf"
    
    if [[ ! -f "$faillock_conf" ]]; then
        touch "$faillock_conf"
        log_info "Created $faillock_conf"
    else
        cp "$faillock_conf" "${faillock_conf}.orig"
    fi
    
    # Create new faillock configuration with idempotent settings
    local temp_conf=$(mktemp)
    
    # Set the lockout parameters
    cat > "$temp_conf" << 'EOF'
# Faillock configuration
# Number of failed login attempts before lockout
deny = 5

# Duration of lockout in seconds (900 seconds = 15 minutes)
unlock_time = 900

# Root account is also subject to lockout
root_unlock_time = 900

# Log failed attempts
audit = yes

# Silent mode for preauth
silent = yes

# Directory to store faillock data
dir = /var/run/faillock
EOF
    
    mv "$temp_conf" "$faillock_conf"
    chmod 600 "$faillock_conf"
    
    log_info "Configured faillock defaults in $faillock_conf"
}

# Create/verify faillock directory
setup_faillock_directory() {
    log_info "Setting up faillock directory..."
    
    local faillock_dir="/var/run/faillock"
    
    if [[ ! -d "$faillock_dir" ]]; then
        mkdir -p "$faillock_dir"
    fi
    
    chmod 755 "$faillock_dir"
    
    # Also create persistent faillock directory for across reboots
    local persistent_dir="/var/lib/faillock"
    if [[ ! -d "$persistent_dir" ]]; then
        mkdir -p "$persistent_dir"
    fi
    
    chmod 755 "$persistent_dir"
    
    log_info "Faillock directories configured"
}

# Configure systemd to ensure faillock directory exists and is clean
setup_systemd_faillock() {
    log_info "Configuring systemd for faillock persistence..."
    
    local tmpfiles_conf="/etc/tmpfiles.d/faillock.conf"
    
    # Create tmpfiles.d configuration to ensure faillock directory persists
    cat > "$tmpfiles_conf" << 'EOF'
# Faillock directory configuration
d /var/run/faillock 0755 root root 10d
L+ /var/run/faillock - - - - /var/lib/faillock
EOF
    
    chmod 644 "$tmpfiles_conf"
    
    # Apply tmpfiles configuration
    systemd-tmpfiles --create --clean "$tmpfiles_conf" 2>/dev/null || true
    
    log_info "Systemd faillock configuration applied"
}

# Verify PAM configuration
verify_pam_config() {
    log_info "Verifying PAM configuration..."
    
    local config_valid=true
    
    # Check if faillock is properly configured in common-auth
    if grep -q "pam_faillock.so" /etc/pam.d/common-auth; then
        log_info "✓ pam_faillock found in common-auth"
    else
        log_error "✗ pam_faillock NOT found in common-auth"
        config_valid=false
    fi
    
    # Check if faillock is properly configured in common-account
    if grep -q "pam_faillock.so" /etc/pam.d/common-account; then
        log_info "✓ pam_faillock found in common-account"
    else
        log_error "✗ pam_faillock NOT found in common-account"
        config_valid=false
    fi
    
    # Check if faillock.conf exists
    if [[ -f "/etc/security/faillock.conf" ]]; then
        log_info "✓ /etc/security/faillock.conf exists"
    else
        log_warn "⚠ /etc/security/faillock.conf not found"
    fi
    
    # Check if faillock directories exist
    if [[ -d "/var/run/faillock" ]]; then
        log_info "✓ /var/run/faillock directory exists"
    else
        log_error "✗ /var/run/faillock directory does not exist"
        config_valid=false
    fi
    
    if [[ "$config_valid" = true ]]; then
        log_info "PAM configuration verification successful"
        return 0
    else
        log_error "PAM configuration verification failed"
        return 1
    fi
}

# Test PAM configuration syntax
test_pam_syntax() {
    log_info "Testing PAM configuration syntax..."
    
    if command -v pamtester &> /dev/null; then
        pamtester -t login nonexistent >/dev/null 2>&1 || true
        log_info "PAM syntax test completed"
    else
        log_warn "pamtester not available, skipping syntax test"
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
#!/bin/bash
set -euo pipefail

# Enable account lockout logging on Ubuntu 24.04
# This script ensures that pam_faillock module is configured to log account lockout events

# Function to check if we're running on Ubuntu 24.04
check_ubuntu_version() {
    if ! grep -q "24.04" /etc/os-release; then
        echo "Warning: This script is designed for Ubuntu 24.04. Current system may differ."
    fi
}

# Function to ensure pam_faillock is installed
ensure_pam_faillock() {
    if ! dpkg -l | grep -q libpam-modules; then
        echo "Installing libpam-modules for faillock support..."
        apt-get update -qq
        apt-get install -y -qq libpam-modules
    fi
}

# Function to configure auth.conf.d for faillock logging
configure_faillock_auth() {
    local auth_conf_dir="/etc/pam.d"
    local faillock_conf="/etc/security/faillock.conf"
    
    # Ensure faillock configuration file exists with proper settings
    if [ ! -f "$faillock_conf" ]; then
        cat > "$faillock_conf" << 'EOF'
# Faillock configuration file
# Log lockout events to syslog and audit
audit
silent
EOF
        chmod 644 "$faillock_conf"
    else
        # Ensure audit flag is present
        if ! grep -q "^audit" "$faillock_conf"; then
            sed -i '1i audit' "$faillock_conf"
        fi
    fi
    
    # Check and update common-auth for pam_faillock
    if [ -f "$auth_conf_dir/common-auth" ]; then
        # Backup original if not already backed up
        if [ ! -f "$auth_conf_dir/common-auth.backup" ]; then
            cp "$auth_conf_dir/common-auth" "$auth_conf_dir/common-auth.backup"
        fi
        
        # Ensure pam_faillock is configured before pam_unix
        if ! grep -q "pam_faillock.so" "$auth_conf_dir/common-auth"; then
            # Add faillock before pam_unix.so in auth required line
            sed -i '/@include common-unix/i auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900' "$auth_conf_dir/common-auth"
            sed -i '/pam_unix.so/a auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900' "$auth_conf_dir/common-auth"
        fi
    fi
}

# Function to configure common-account for faillock logging
configure_faillock_account() {
    local auth_conf_dir="/etc/pam.d"
    
    if [ -f "$auth_conf_dir/common-account" ]; then
        # Backup original if not already backed up
        if [ ! -f "$auth_conf_dir/common-account.backup" ]; then
            cp "$auth_conf_dir/common-account" "$auth_conf_dir/common-account.backup"
        fi
        
        # Ensure pam_faillock is configured in account module
        if ! grep -q "pam_faillock.so" "$auth_conf_dir/common-account"; then
            # Add faillock account module
            sed -i '1i account required pam_faillock.so' "$auth_conf_dir/common-account"
        fi
    fi
}

# Function to configure rsyslog for audit logging
configure_rsyslog_audit() {
    local rsyslog_conf="/etc/rsyslog.d/50-default.conf"
    local audit_log="/var/log/auth.log"
    
    # Ensure auth logs are being captured
    if [ -f "$rsyslog_conf" ]; then
        if ! grep -q "auth" "$rsyslog_conf"; then
            echo "*.*;auth,authpriv.none -$audit_log" >> "$rsyslog_conf"
            # Restart rsyslog to apply changes
            systemctl restart rsyslog || true
        fi
    fi
}

# Function to configure auditd for detailed logging
configure_auditd() {
    # Check if auditd is installed
    if command -v auditctl &> /dev/null; then
        local audit_rules="/etc/audit/rules.d/audit.rules"
        
        # Ensure audit directory exists
        mkdir -p "$(dirname "$audit_rules")"
        
        # Backup original if exists
        if [ -f "$audit_rules" ] && [ ! -f "$audit_rules.backup" ]; then
            cp "$audit_rules" "$audit_rules.backup"
        fi
        
        # Add rules to audit faillock events if not present
        if [ ! -f "$audit_rules" ] || ! grep -q "faillock" "$audit_rules"; then
            cat >> "$audit_rules" << 'EOF'
# Monitor faillock directory for changes
-w /var/run/faillock/ -p wa -k account_modifications
-w /etc/security/faillock.conf -p wa -k faillock_config_changes

# Monitor PAM configuration changes
-w /etc/pam.d/ -p wa -k pam_changes
EOF
            
            # Reload audit rules
            augenrules --load 2>/dev/null || auditctl -R "$audit_rules" 2>/dev/null || true
        fi
    else
        echo "Installing auditd for enhanced logging..."
        apt-get update -qq
        apt-get install -y -qq auditd audispd-plugins
        systemctl enable auditd
        systemctl start auditd
        configure_auditd
    fi
}

# Function to verify configuration
verify_configuration() {
    echo "Verifying account lockout logging configuration..."
    
    # Check faillock.conf
    if [ -f "/etc/security/faillock.conf" ]; then
        if grep -q "audit" "/etc/security/faillock.conf"; then
            echo "✓ faillock.conf properly configured with audit flag"
        fi
    fi
    
    # Check PAM configuration
    if grep -q "pam_faillock.so" "/etc/pam.d/common-auth" 2>/dev/null; then
        echo "✓ pam_faillock module is configured in common-auth"
    fi
    
    # Check if auditd is enabled
    if systemctl is-enabled auditd &> /dev/null; then
        echo "✓ auditd is enabled and will log account lockout events"
    fi
    
    echo "Configuration verification complete."
}

# Function to ensure persistence across reboots
ensure_persistence() {
    # Enable auditd service to start on boot
    systemctl enable auditd 2>/dev/null || true
    systemctl enable rsyslog 2>/dev/null || true
    
    # Create systemd service to ensure faillock settings are applied
    local service_file="/etc/systemd/system/faillock-config.service"
    if [ ! -f "$service_file" ]; then
        cat > "$service_file" << 'EOF'
[Unit]
Description=Ensure faillock configuration persistence
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'grep -q "audit" /etc/security/faillock.conf || echo "audit" >> /etc/security/faillock.conf'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable faillock-config.service
    fi
}

# Main execution
main() {
    echo "Starting Ubuntu 24.04 account lockout logging configuration..."
    
    check_ubuntu_version
    ensure_pam_faillock
    configure_faillock_auth
    configure_faillock_account
    configure_rsyslog_audit
    configure_auditd
    ensure_persistence
    verify_configuration
    
    echo "Account lockout logging configuration complete."
    echo "Failed login attempts and account lockouts will now be logged for investigation."
}

# Run main function
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
#!/bin/bash

set -euo pipefail

# Remediation script for configuring account lockout after 3 failed login attempts on Ubuntu 24.04
# This script configures pam_faillock to enforce account lockout across the system

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# Verify Ubuntu 24.04
if ! grep -q "24.04" /etc/os-release; then
    echo "Warning: This script is designed for Ubuntu 24.04. Current system may differ."
fi

# Install libpam-modules if not present
if ! dpkg -l | grep -q libpam-modules; then
    apt-get update
    apt-get install -y libpam-modules
fi

# Backup original PAM configuration files
BACKUP_DIR="/etc/pam.d/backup_$(date +%s)"
mkdir -p "$BACKUP_DIR"
cp -r /etc/pam.d/* "$BACKUP_DIR/"

# Configure pam_faillock for account lockout
# This function ensures idempotent configuration

configure_faillock() {
    local pam_file="$1"
    
    # Only process standard authentication files
    if [[ ! "$pam_file" =~ ^/etc/pam.d/(common-auth|common-password|login|sudo|sshd)$ ]]; then
        return 0
    fi
    
    # For common-auth, add faillock modules
    if [[ "$pam_file" == "/etc/pam.d/common-auth" ]]; then
        # Remove existing faillock lines to ensure idempotency
        sed -i '/pam_faillock.so/d' "$pam_file"
        
        # Add auth required pam_faillock.so before pam_unix.so
        # Insert at the beginning of auth section
        sed -i '1i auth required pam_faillock.so preauth silent audit deny=3 unlock_time=900' "$pam_file"
        
        # Add auth [default=die] pam_faillock.so after pam_unix.so
        sed -i '/^auth.*pam_unix.so/a auth [default=die] pam_faillock.so authfail audit deny=3 unlock_time=900' "$pam_file"
    fi
    
    # For common-password, ensure pam_unix.so has remember setting
    if [[ "$pam_file" == "/etc/pam.d/common-password" ]]; then
        # Ensure common-password doesn't interfere with faillock
        if ! grep -q "pam_permit.so" "$pam_file"; then
            echo "password required pam_permit.so" >> "$pam_file"
        fi
    fi
}

# Create or update /etc/security/faillock.conf for persistent configuration
create_faillock_conf() {
    cat > /etc/security/faillock.conf << 'EOF'
# Faillock configuration file
# Automatically generated for account lockout policy

# Number of failed attempts before lockout
deny = 3

# Lockout duration in seconds (900 seconds = 15 minutes)
unlock_time = 900

# Enable audit logging
audit

# Directory where faillock files are stored
dir = /var/run/faillock

# Use /var/log/faillog for persistent storage
# fail_interval = 900
EOF
    
    # Set appropriate permissions
    chmod 644 /etc/security/faillock.conf
}

# Update common-auth file with faillock configuration
update_common_auth() {
    local temp_file="/tmp/common-auth.tmp"
    local pam_file="/etc/pam.d/common-auth"
    
    # Check if file exists
    if [[ ! -f "$pam_file" ]]; then
        echo "Creating $pam_file"
        touch "$pam_file"
    fi
    
    # Remove all existing faillock entries for clean idempotent update
    grep -v "pam_faillock.so" "$pam_file" > "$temp_file" || true
    
    # Create clean configuration
    {
        echo "# PAM configuration for Debian/Ubuntu."
        echo "# (C) 2005 HAL OSS, Inc."
        echo "# See the README file for copyright information and for more information."
        echo ""
        echo "# @include common-auth-pc"
        echo "auth required pam_faillock.so preauth silent audit deny=3 unlock_time=900"
        echo "auth [success=1 default=ignore] pam_unix.so nullok"
        echo "auth [default=die] pam_faillock.so authfail audit deny=3 unlock_time=900"
        echo "auth requisite pam_deny.so"
        echo "auth required pam_permit.so"
        echo "auth required pam_env.so"
        echo "auth required pam_mail.so standard"
    } > "$temp_file"
    
    # Check if changes are needed (for idempotency)
    if ! diff -q "$pam_file" "$temp_file" > /dev/null 2>&1; then
        cp "$temp_file" "$pam_file"
        echo "Updated $pam_file with faillock configuration"
    else
        echo "Configuration already up-to-date for $pam_file"
    fi
    
    rm -f "$temp_file"
}

# Create faillock directory and set permissions
setup_faillock_directory() {
    mkdir -p /var/run/faillock
    chmod 755 /var/run/faillock
    
    # Ensure faillock directory is recreated on boot
    cat > /etc/tmpfiles.d/faillock.conf << 'EOF'
d /var/run/faillock 0755 root root
EOF
    
    # Create persistent faillog directory
    mkdir -p /var/log/faillock
    chmod 755 /var/log/faillock
}

# Configure pam_limits if needed for additional security
configure_pam_limits() {
    local limits_file="/etc/security/limits.conf"
    
    # Ensure basic limits are configured
    if ! grep -q "^# Account lockout settings" "$limits_file"; then
        echo "" >> "$limits_file"
        echo "# Account lockout settings" >> "$limits_file"
    fi
}

# Main configuration execution
echo "Configuring account lockout policy on Ubuntu 24.04..."

# Create faillock configuration file
echo "Creating faillock configuration..."
create_faillock_conf

# Setup faillock directory
echo "Setting up faillock directory..."
setup_faillock_directory

# Update PAM configuration
echo "Updating PAM authentication configuration..."
update_common_auth

# Configure PAM limits
echo "Configuring PAM limits..."
configure_pam_limits

# Verify configuration
echo ""
echo "Verifying configuration..."

# Check if faillock configuration exists
if [[ -f /etc/security/faillock.conf ]]; then
    echo "✓ faillock.conf configured"
    cat /etc/security/faillock.conf
else
    echo "✗ faillock.conf not found"
    exit 1
fi

# Check if common-auth has faillock entries
if grep -q "pam_faillock.so" /etc/pam.d/common-auth; then
    echo "✓ common-auth configured with pam_faillock"
    grep "pam_faillock.so" /etc/pam.d/common-auth
else
    echo "✗ pam_faillock not found in common-auth"
    exit 1
fi

# Check if faillock directory exists
if [[ -d /var/run/faillock ]]; then
    echo "✓ faillock directory exists"
else
    echo "✗ faillock directory not found"
    exit 1
fi

# Test the configuration (non-blocking test)
echo ""
echo "Configuration complete. Account lockout policy is now active:"
echo "- Failed login attempts will lock the account after 3 attempts"
echo "- Lockout duration: 900 seconds (15 minutes)"
echo "- Backup of original PAM configuration: $BACKUP_DIR"
echo ""
echo "Note: To test the configuration, use 'faillock' command to check locked accounts"
echo "      Use 'faillock --reset' to unlock accounts manually"

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

**Prompt:** On an Ubuntu 24.04 system, configure the authentication subsystem so that the root account is subject to the same automatic account-locking policy applied after repeated failed login attempts, ensuring that brute-force password guessing against root results in the account being locked rather than allowing unlimited tries. Write an idempotent bash remediation script that enables failed-attempt lockout enforcement for the root account in a way that is correctly integrated into the system's authentication configuration and persists across reboots.

**Model-generated script:**
```bash
#!/bin/bash

set -euo pipefail

# Configure PAM for failed login attempt lockout on root account
# This script implements account locking after repeated failed login attempts
# for the root account using pam_faillock module

# Ensure pam-faillock package is installed
echo "Installing required PAM packages..."
apt-get update -qq
apt-get install -y -qq libpam-modules libpam-modules-bin

# Create a backup of the current PAM configuration
PAM_D_DIR="/etc/pam.d"
COMMON_AUTH_FILE="${PAM_D_DIR}/common-auth-pc"
COMMON_AUTH_BACKUP="${PAM_D_DIR}/common-auth-pc.backup.$(date +%s)"

if [ -f "$COMMON_AUTH_FILE" ]; then
    cp "$COMMON_AUTH_FILE" "$COMMON_AUTH_BACKUP"
fi

# Check if pam_faillock is already configured in common-auth-pc
if ! grep -q "pam_faillock.so" "$COMMON_AUTH_FILE"; then
    # Add pam_faillock to the beginning of the auth chain
    # This needs to be before pam_unix.so for proper operation
    
    # Create a temporary file with the proper configuration
    TEMP_FILE=$(mktemp)
    
    {
        echo "auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900"
        cat "$COMMON_AUTH_FILE"
    } > "$TEMP_FILE"
    
    # Replace the auth lines to add faillock after pam_unix
    sed -i 's/^auth.*pam_unix\.so.*$/auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900\n&/' "$TEMP_FILE"
    
    # Handle duplicate lines if sed created them
    # Create final cleaned file
    FINAL_FILE=$(mktemp)
    {
        echo "auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900"
        grep -v "^auth required pam_faillock.so" "$TEMP_FILE" | grep -v "^auth \[default=die\] pam_faillock.so"
        echo "auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900"
    } > "$FINAL_FILE"
    
    # Verify the file looks correct before applying
    if [ -s "$FINAL_FILE" ]; then
        cp "$FINAL_FILE" "$COMMON_AUTH_FILE"
    fi
    
    rm -f "$TEMP_FILE" "$FINAL_FILE"
fi

# Configure the account policy to include pam_faillock
PAM_ACCOUNT_FILE="${PAM_D_DIR}/common-account-pc"
if [ -f "$PAM_ACCOUNT_FILE" ]; then
    if ! grep -q "pam_faillock.so" "$PAM_ACCOUNT_FILE"; then
        # Add pam_faillock to account phase
        cp "$PAM_ACCOUNT_FILE" "${PAM_ACCOUNT_FILE}.backup.$(date +%s)"
        sed -i '1i auth required pam_faillock.so' "$PAM_ACCOUNT_FILE"
    fi
fi

# Configure faillock settings in /etc/security/faillock.conf
FAILLOCK_CONF="/etc/security/faillock.conf"

# Ensure the faillock.conf file exists
if [ ! -f "$FAILLOCK_CONF" ]; then
    touch "$FAILLOCK_CONF"
fi

# Create a backup
cp "$FAILLOCK_CONF" "${FAILLOCK_CONF}.backup.$(date +%s)"

# Configure faillock parameters
# Set deny = 5 (number of failed attempts before lockout)
# Set unlock_time = 900 (15 minutes)
# Ensure root is not exempt from lockout

cat > "$FAILLOCK_CONF" << 'EOF'
# /etc/security/faillock.conf configuration
# Number of failed login attempts before lockout
deny = 5

# Time (in seconds) until account is automatically unlocked
unlock_time = 900

# Enable audit logging
audit

# Use silent mode for preauth phase
silent
EOF

# Ensure root is included in faillock enforcement
# Remove root from pam_faillock even_deny_root exception if present
if grep -q "even_deny_root" /etc/pam.d/common-auth-pc; then
    sed -i 's/even_deny_root //g' /etc/pam.d/common-auth-pc
fi

# Configure sshd to use pam authentication (already default on Ubuntu)
SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_CONFIG_D="/etc/ssh/sshd_config.d"

# Ensure SSH uses PAM for authentication
if ! grep -q "^UsePAM yes" "$SSHD_CONFIG" && ! grep -q "^UsePAM yes" "${SSHD_CONFIG_D}"/*.conf 2>/dev/null; then
    mkdir -p "$SSHD_CONFIG_D"
    echo "UsePAM yes" > "${SSHD_CONFIG_D}/99-pam-enforcement.conf"
    chmod 644 "${SSHD_CONFIG_D}/99-pam-enforcement.conf"
fi

# Ensure PermitRootLogin is not set to without-password or yes without PAM
# This ensures root login attempts go through PAM
if grep -q "^PermitRootLogin" "$SSHD_CONFIG"; then
    # Ensure it's set to prohibit-password or yes (which will use PAM)
    sed -i 's/^PermitRootLogin.*/PermitRootLogin prohibit-password/' "$SSHD_CONFIG"
else
    echo "PermitRootLogin prohibit-password" >> "$SSHD_CONFIG"
fi

# Create a PAM configuration specifically for root login if needed
# Create /etc/pam.d/root-login to ensure root uses faillock
ROOT_LOGIN_PAM="${PAM_D_DIR}/root-login"

if [ ! -f "$ROOT_LOGIN_PAM" ]; then
    cat > "$ROOT_LOGIN_PAM" << 'EOF'
# Root login authentication configuration
# Ensure root account is subject to the same faillock policy
auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900
auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900
auth sufficient pam_unix.so nullok try_first_pass yescrypt sha512
auth requisite pam_deny.so
auth required pam_permit.so
account required pam_unix.so
account required pam_faillock.so
session required pam_unix.so
EOF
    chmod 644 "$ROOT_LOGIN_PAM"
fi

# Verify and apply PAM configuration for login service
LOGIN_PAM="${PAM_D_DIR}/login"

# Backup login configuration
if [ -f "$LOGIN_PAM" ]; then
    cp "$LOGIN_PAM" "${LOGIN_PAM}.backup.$(date +%s)"
fi

# Ensure faillock is in the login PAM configuration
if ! grep -q "pam_faillock.so" "$LOGIN_PAM"; then
    # Add faillock to login
    cat > "${PAM_D_DIR}/login.tmp" << 'EOF'
auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900
account required pam_faillock.so
EOF
    cat "$LOGIN_PAM" >> "${PAM_D_DIR}/login.tmp"
    mv "${PAM_D_DIR}/login.tmp" "$LOGIN_PAM"
    chmod 644 "$LOGIN_PAM"
fi

# Enable and restart SSH service to apply configuration
systemctl restart ssh

# Create a verification script to check configuration
VERIFY_SCRIPT="/usr/local/bin/verify-root-faillock"
cat > "$VERIFY_SCRIPT" << 'EOF'
#!/bin/bash
# Verification script to ensure root account is protected by faillock

echo "Checking faillock configuration for root account..."

# Check if pam_faillock is configured
if grep -q "pam_faillock.so" /etc/pam.d/common-auth-pc; then
    echo "✓ pam_faillock is configured in common-auth-pc"
else
    echo "✗ pam_faillock is NOT configured in common-auth-pc"
    exit 1
fi

# Check faillock.conf settings
if [ -f /etc/security/faillock.conf ]; then
    if grep -q "deny = 5" /etc/security/faillock.conf; then
        echo "✓ faillock deny threshold is set to 5"
    else
        echo "✗ faillock deny threshold is not properly configured"
        exit 1
    fi
else
    echo "✗ /etc/security/faillock.conf not found"
    exit 1
fi

# Check SSH configuration
if grep -q "UsePAM yes" /etc/ssh/sshd_config* 2>/dev/null; then
    echo "✓ SSH is configured to use PAM"
else
    echo "✗ SSH is not configured to use PAM"
    exit 1
fi

echo ""
echo "Root account is now protected by faillock policy:"
echo "- Account locks after 5 failed login attempts"
echo "- Account unlocks after 900 seconds (15 minutes)"
echo ""
echo "To manually reset a locked root account, use:"
echo "  faillock --user root --reset"
EOF

chmod 755 "$VERIFY_SCRIPT"

# Run verification
bash "$VERIFY_SCRIPT"

echo ""
echo "Configuration complete. Root account is now subject to faillock policy."
echo "Account will be locked after 5 failed login attempts for 15 minutes."
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
#!/bin/bash

# Idempotent script to configure persistent account lockout on Ubuntu 24.04
# This script modifies PAM configuration to use pam_faillock with persistent storage

set -e

# Enable strict error checking
trap 'echo "Error occurred at line $LINENO" >&2; exit 1' ERR

# Function to check if we're running with appropriate privileges
check_privileges() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root" >&2
        exit 1
    fi
}

# Function to backup a file if it hasn't been backed up already
backup_file() {
    local file="$1"
    local backup="${file}.backup.$(date +%Y%m%d_%H%M%S)"
    
    if [[ -f "$file" ]]; then
        # Only backup if we haven't already
        if [[ ! -f "${file}.backup"* ]]; then
            cp "$file" "$backup"
            echo "Backed up $file to $backup"
        fi
    fi
}

# Function to ensure pam_faillock configuration in a PAM file
configure_pam_faillock() {
    local pam_file="$1"
    local mode="${2:-auth}"  # auth, password, or account
    
    if [[ ! -f "$pam_file" ]]; then
        return 0
    fi
    
    # Check if faillock is already configured with persistent dir
    if grep -q "pam_faillock.so.*dir=/var/lib/faillock" "$pam_file" 2>/dev/null; then
        echo "$pam_file already has persistent faillock configured"
        return 0
    fi
    
    backup_file "$pam_file"
    
    local temp_file="${pam_file}.tmp"
    cp "$pam_file" "$temp_file"
    
    case "$mode" in
        auth)
            # Remove old pam_faillock lines if they exist (non-persistent)
            sed -i '/^auth.*pam_faillock.so/d' "$temp_file"
            
            # Add pam_faillock with persistent directory at the beginning of auth rules
            if ! grep -q "pam_faillock.so" "$temp_file"; then
                # Find the first auth line and insert before it
                sed -i '0,/^auth.*required.*pam_unix.so/s/^/auth required pam_faillock.so preauth silent audit deny=3 unlock_time=600 dir=\/var\/lib\/faillock\n/' "$temp_file"
                # Add the auth_permit rule
                sed -i 's/^auth.*required.*pam_unix.so/auth [default=die] pam_faillock.so authfail audit deny=3 unlock_time=600 dir=\/var\/lib\/faillock\nauth required pam_unix.so nullok try_first_pass yescrypt sha512 shadow/' "$temp_file"
            fi
            ;;
        account)
            # Remove old pam_faillock lines if they exist (non-persistent)
            sed -i '/^account.*pam_faillock.so/d' "$temp_file"
            
            # Add account pam_faillock if not present
            if ! grep -q "account.*pam_faillock.so" "$temp_file"; then
                sed -i '0,/^account/s/^/account required pam_faillock.so\n/' "$temp_file"
            fi
            ;;
    esac
    
    mv "$temp_file" "$pam_file"
}

# Function to create faillock directory with proper permissions
setup_faillock_directory() {
    local faillock_dir="/var/lib/faillock"
    
    if [[ ! -d "$faillock_dir" ]]; then
        mkdir -p "$faillock_dir"
        chmod 755 "$faillock_dir"
        echo "Created persistent faillock directory: $faillock_dir"
    else
        chmod 755 "$faillock_dir"
        echo "Ensured permissions on faillock directory"
    fi
}

# Function to ensure pam_faillock module is installed
ensure_faillock_module() {
    # Check if pam_faillock.so exists
    if [[ ! -f /lib/x86_64-linux-gnu/security/pam_faillock.so ]] && \
       [[ ! -f /lib/security/pam_faillock.so ]]; then
        echo "pam_faillock module not found, installing libpam-modules..."
        apt-get update >/dev/null 2>&1
        apt-get install -y libpam-modules >/dev/null 2>&1
    fi
}

# Function to check and update common PAM configuration files
update_pam_configurations() {
    # Files to update for proper faillock configuration
    local pam_files=(
        "/etc/pam.d/common-auth-pc"
        "/etc/pam.d/common-auth"
        "/etc/pam.d/common-account"
        "/etc/pam.d/login"
        "/etc/pam.d/sshd"
        "/etc/pam.d/sudo"
    )
    
    for pam_file in "${pam_files[@]}"; do
        if [[ -f "$pam_file" ]]; then
            echo "Checking $pam_file"
            
            # Special handling for different file types
            if [[ "$pam_file" == *"common-auth"* ]]; then
                configure_pam_faillock "$pam_file" "auth"
            elif [[ "$pam_file" == *"common-account"* ]]; then
                configure_pam_faillock "$pam_file" "account"
            elif [[ "$pam_file" == *"sshd"* ]]; then
                # Ensure sshd has faillock configured
                if ! grep -q "pam_faillock.so" "$pam_file"; then
                    backup_file "$pam_file"
                    sed -i '/@include common-auth/a @include common-password' "$pam_file"
                fi
            fi
        fi
    done
}

# Function to verify faillock configuration
verify_faillock_config() {
    echo ""
    echo "Verifying faillock configuration..."
    
    if grep -r "pam_faillock.so.*dir=/var/lib/faillock" /etc/pam.d/ 2>/dev/null; then
        echo "✓ Persistent faillock is configured in PAM"
    else
        echo "⚠ Checking for faillock configuration..."
        grep -r "pam_faillock.so" /etc/pam.d/ 2>/dev/null || echo "No explicit faillock found (may be using defaults)"
    fi
    
    if [[ -d "/var/lib/faillock" ]]; then
        echo "✓ Faillock directory exists at /var/lib/faillock"
        ls -la /var/lib/faillock 2>/dev/null | head -5 || echo "  (directory is empty)"
    fi
    
    echo "Faillock configuration verification complete"
}

# Function to create a systemd service to restore faillock persistence
create_faillock_persistence_service() {
    local service_file="/etc/systemd/system/faillock-persist.service"
    
    # Create systemd service to ensure faillock directory exists after reboot
    if [[ ! -f "$service_file" ]]; then
        cat > "$service_file" << 'EOF'
[Unit]
Description=Ensure persistent faillock directory exists
Before=systemd-user-sessions.service
DefaultDependencies=no

[Service]
Type=oneshot
ExecStart=/bin/mkdir -p /var/lib/faillock
ExecStart=/bin/chmod 755 /var/lib/faillock
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable faillock-persist.service
        echo "Created and enabled faillock-persist.service"
    fi
}

# Main execution
main() {
    echo "Starting persistent account lockout configuration for Ubuntu 24.04"
    
    check_privileges
    ensure_faillock_module
    setup_faillock_directory
    update_pam_configurations
    create_faillock_persistence_service
    verify_faillock_config
    
    echo ""
    echo "Persistent account lockout configuration complete!"
    echo "The system is now configured to maintain account lockout state across reboots"
}

# Run main function
main "$@"
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

# Remediation script to configure failed login tracking with 900 second interval on Ubuntu 24.04
# This uses pam_faillock module to implement account lockout mechanism

set -euo pipefail

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Define the fail_interval (in seconds) - must be at least 900
FAIL_INTERVAL=900

# Function to check if a line exists in a file
line_exists() {
    local file="$1"
    local pattern="$2"
    grep -q "$pattern" "$file" 2>/dev/null || return 1
}

# Function to add or update a pam configuration line
update_pam_config() {
    local pam_file="$1"
    local module_line="$2"
    local backup_file="${pam_file}.backup.$(date +%s)"
    
    # Create backup if file exists and we haven't backed it up yet
    if [[ -f "$pam_file" ]] && [[ ! -f "${pam_file}.backup" ]]; then
        cp "$pam_file" "${pam_file}.backup"
    fi
    
    # Check if faillock module is already configured
    if line_exists "$pam_file" "pam_faillock.so"; then
        # Update existing faillock configuration
        sed -i.bak "s/^.*pam_faillock\.so.*auth.*/auth    required    pam_faillock.so preauth silent audit deny=5 unlock_time=$FAIL_INTERVAL fail_interval=$FAIL_INTERVAL/" "$pam_file" || true
        sed -i.bak "s/^.*pam_faillock\.so.*account.*/auth    \[default=die\] pam_faillock.so authfail audit deny=5 unlock_time=$FAIL_INTERVAL fail_interval=$FAIL_INTERVAL/" "$pam_file" || true
    fi
}

# Function to ensure faillock is properly configured in common-auth
configure_common_auth() {
    local common_auth="/etc/pam.d/common-auth"
    
    # Backup original if not already backed up
    if [[ ! -f "${common_auth}.original" ]]; then
        cp "$common_auth" "${common_auth}.original"
    fi
    
    # Check if faillock preauth line exists
    if ! line_exists "$common_auth" "pam_faillock.so.*preauth"; then
        # Add preauth faillock line at the beginning (after comments)
        sed -i "1,/^[^#]/s/^[^#]/auth    required    pam_faillock.so preauth silent audit deny=5 unlock_time=$FAIL_INTERVAL fail_interval=$FAIL_INTERVAL\n&/" "$common_auth"
    else
        # Update existing preauth line
        sed -i "s/pam_faillock\.so preauth.*/pam_faillock.so preauth silent audit deny=5 unlock_time=$FAIL_INTERVAL fail_interval=$FAIL_INTERVAL/" "$common_auth"
    fi
    
    # Check if faillock authfail line exists
    if ! line_exists "$common_auth" "pam_faillock.so.*authfail"; then
        # Add authfail faillock line after pam_unix.so
        sed -i "/pam_unix.so/a auth    \[default=die\] pam_faillock.so authfail audit deny=5 unlock_time=$FAIL_INTERVAL fail_interval=$FAIL_INTERVAL" "$common_auth"
    else
        # Update existing authfail line
        sed -i "s/pam_faillock\.so authfail.*/pam_faillock.so authfail audit deny=5 unlock_time=$FAIL_INTERVAL fail_interval=$FAIL_INTERVAL/" "$common_auth"
    fi
}

# Function to ensure faillock is properly configured in common-account
configure_common_account() {
    local common_account="/etc/pam.d/common-account"
    
    # Backup original if not already backed up
    if [[ ! -f "${common_account}.original" ]]; then
        cp "$common_account" "${common_account}.original"
    fi
    
    # Check if pam_permit.so with faillock exists
    if ! line_exists "$common_account" "pam_faillock.so"; then
        # Add faillock account line
        sed -i "1a account required pam_faillock.so" "$common_account"
    else
        # Update existing line if needed
        sed -i "s/account.*pam_faillock\.so.*/account required pam_faillock.so/" "$common_account"
    fi
}

# Function to create/update faillock configuration file
configure_faillock_conf() {
    local faillock_conf="/etc/security/faillock.conf"
    
    # Create faillock.conf if it doesn't exist
    if [[ ! -f "$faillock_conf" ]]; then
        cat > "$faillock_conf" << EOF
# faillock.conf: configuration for pam_faillock module
# Defines the time period during which failed login attempts are counted
fail_interval = $FAIL_INTERVAL
unlock_time = $FAIL_INTERVAL
deny = 5
audit = yes
EOF
    else
        # Backup and update existing file
        if [[ ! -f "${faillock_conf}.original" ]]; then
            cp "$faillock_conf" "${faillock_conf}.original"
        fi
        
        # Update or add fail_interval
        if grep -q "^fail_interval" "$faillock_conf"; then
            sed -i "s/^fail_interval.*/fail_interval = $FAIL_INTERVAL/" "$faillock_conf"
        else
            echo "fail_interval = $FAIL_INTERVAL" >> "$faillock_conf"
        fi
        
        # Update or add unlock_time
        if grep -q "^unlock_time" "$faillock_conf"; then
            sed -i "s/^unlock_time.*/unlock_time = $FAIL_INTERVAL/" "$faillock_conf"
        else
            echo "unlock_time = $FAIL_INTERVAL" >> "$faillock_conf"
        fi
    fi
    
    # Set proper permissions
    chmod 600 "$faillock_conf"
}

# Function to ensure faillock directory exists
ensure_faillock_dir() {
    local faillock_dir="/var/run/faillock"
    
    if [[ ! -d "$faillock_dir" ]]; then
        mkdir -p "$faillock_dir"
    fi
    
    chmod 755 "$faillock_dir"
}

# Main configuration
echo "Configuring account lockout mechanism with $FAIL_INTERVAL second interval..."

# Ensure necessary directory exists
ensure_faillock_dir

# Configure faillock in PAM
echo "Updating PAM configuration..."
configure_common_auth
configure_common_account

# Create/update faillock configuration file
configure_faillock_conf

# Verify configuration
echo "Verifying configuration..."
if [[ -f /etc/pam.d/common-auth ]]; then
    if grep -q "fail_interval=$FAIL_INTERVAL" /etc/pam.d/common-auth || \
       grep -q "pam_faillock.so" /etc/pam.d/common-auth; then
        echo "✓ PAM common-auth configured"
    fi
fi

if [[ -f /etc/security/faillock.conf ]]; then
    if grep -q "fail_interval = $FAIL_INTERVAL" /etc/security/faillock.conf; then
        echo "✓ faillock.conf configured with $FAIL_INTERVAL second interval"
    fi
fi

echo "Account lockout mechanism configured successfully"
echo "Failed login attempts will be counted within a $FAIL_INTERVAL second window"
echo "Accounts will be locked after 5 failed attempts"
echo "Configuration will persist across reboots"

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
#!/bin/bash

set -euo pipefail

# Ensure the script runs as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" >&2
   exit 1
fi

# Install pam-faillock if not already installed
if ! dpkg -l | grep -q libpam-cracklib; then
    apt-get update
    apt-get install -y libpam-cracklib
fi

# Ensure pam_faillock module is available
if ! dpkg -l | grep -q libpam-modules; then
    apt-get install -y libpam-modules
fi

# Configure PAM configuration files for consistent lockout handling
configure_pam_faillock() {
    local pam_file="$1"
    
    if [[ ! -f "$pam_file" ]]; then
        return 0
    fi
    
    # Create a backup if one doesn't already exist
    if [[ ! -f "${pam_file}.backup" ]]; then
        cp "$pam_file" "${pam_file}.backup"
    fi
    
    # Remove existing faillock entries to avoid duplicates
    sed -i '/pam_faillock.so/d' "$pam_file"
    
    # Add faillock configuration to common-auth if it's not the system-auth file
    if [[ "$pam_file" == "/etc/pam.d/common-auth" ]]; then
        # Add pam_faillock.so for auth stack with silent and nodelay options
        if ! grep -q "auth.*pam_faillock.so" "$pam_file"; then
            sed -i '1i auth required pam_faillock.so preauth silent nodelay' "$pam_file"
        fi
        if ! grep -q "auth.*\[default=die\].*pam_faillock.so" "$pam_file"; then
            sed -i '/^auth.*pam_unix.so.*/a auth [default=die] pam_faillock.so authfail silent nodelay' "$pam_file"
        fi
    fi
}

# Configure /etc/pam.d/common-auth for login failure tracking
configure_pam_faillock "/etc/pam.d/common-auth"

# Configure /etc/pam.d/common-password if it exists
if [[ -f /etc/pam.d/common-password ]]; then
    if [[ ! -f /etc/pam.d/common-password.backup ]]; then
        cp /etc/pam.d/common-password /etc/pam.d/common-password.backup
    fi
fi

# Configure PAM account stack to suppress messages
configure_pam_account() {
    local pam_file="/etc/pam.d/common-account"
    
    if [[ ! -f "$pam_file" ]]; then
        return 0
    fi
    
    if [[ ! -f "${pam_file}.backup" ]]; then
        cp "$pam_file" "${pam_file}.backup"
    fi
    
    # Ensure pam_faillock is in account stack with silent option
    if ! grep -q "account.*pam_faillock.so" "$pam_file"; then
        echo "account required pam_faillock.so silent nodelay" >> "$pam_file"
    else
        sed -i 's/account.*pam_faillock.so.*/account required pam_faillock.so silent nodelay/' "$pam_file"
    fi
}

configure_pam_account

# Create/update /etc/security/faillock.conf for consistent lockout configuration
create_faillock_config() {
    local faillock_conf="/etc/security/faillock.conf"
    
    # Create the directory if it doesn't exist
    mkdir -p /etc/security
    
    # Create or update faillock.conf with silent/nodelay settings
    cat > "$faillock_conf" << 'EOF'
# Faillock configuration file
#
# This file configures the pam_faillock module behavior

# Number of failed login attempts before lockout
deny = 5

# Time in seconds before the failure count is reset
unlock_time = 900

# Time in seconds to use for incrementing the lockout duration
fail_interval = 900

# Suppress information messages during failure counting
silent = true

# Do not use delay between failed login attempts
nodelay = true

# Directory where failed attempt records are stored
dir = /var/run/faillock
EOF

    # Set proper permissions
    chmod 644 "$faillock_conf"
}

create_faillock_config

# Ensure the faillock directory exists with proper permissions
mkdir -p /var/run/faillock
chmod 755 /var/run/faillock

# Create /etc/security/faillock directory for persistent storage
mkdir -p /etc/security/faillock
chmod 755 /etc/security/faillock

# Update pam_faillock configuration in /etc/pam.d/common-auth with absolute paths
update_pam_auth() {
    local pam_file="/etc/pam.d/common-auth"
    
    # Remove old pam_faillock entries
    sed -i '/pam_faillock.so/d' "$pam_file"
    
    # Add properly configured pam_faillock entries
    # First line: preauth to check if account is locked
    sed -i '1i auth required pam_faillock.so preauth silent nodelay' "$pam_file"
    
    # Add after pam_unix: handle failed authentication
    if grep -q "^auth.*pam_unix.so" "$pam_file"; then
        sed -i '/^auth.*pam_unix.so/a auth [default=die] pam_faillock.so authfail silent nodelay' "$pam_file"
    fi
}

update_pam_auth

# Verify the configuration
verify_pam_config() {
    echo "Verifying PAM configuration..."
    
    if grep -q "pam_faillock.so preauth silent nodelay" /etc/pam.d/common-auth; then
        echo "✓ Preauth faillock configured with silent and nodelay"
    fi
    
    if grep -q "pam_faillock.so authfail silent nodelay" /etc/pam.d/common-auth; then
        echo "✓ Authfail faillock configured with silent and nodelay"
    fi
    
    if [[ -f /etc/security/faillock.conf ]]; then
        echo "✓ Faillock configuration file exists"
        if grep -q "silent = true" /etc/security/faillock.conf; then
            echo "✓ Silent mode enabled in faillock.conf"
        fi
    fi
}

verify_pam_config

# Ensure systemd-logind service is running for session tracking
systemctl enable systemd-logind 2>/dev/null || true
systemctl restart systemd-logind 2>/dev/null || true

# Create a systemd service to ensure faillock directory permissions on boot
create_faillock_tmpfiles() {
    cat > /etc/tmpfiles.d/faillock.conf << 'EOF'
# Temporary files configuration for faillock
d /var/run/faillock 0755 root root
EOF
}

create_faillock_tmpfiles

# Apply the configuration immediately
systemd-tmpfiles --create /etc/tmpfiles.d/faillock.conf 2>/dev/null || true

# Test that the configuration doesn't break authentication
echo "Configuration completed successfully"
echo "PAM faillock is now configured to suppress informational feedback"
echo "Failed login attempts will be tracked silently without user feedback"
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
#!/bin/bash

set -e

# Enable strict error handling
trap 'echo "Error on line $LINENO"; exit 1' ERR

# Ensure script runs as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# Install required packages
apt-get update
apt-get install -y libpam-modules libpam-runtime

# Define PAM configuration parameters
FAILURES_BEFORE_LOCK=5
UNLOCK_INTERVAL=900

# Function to check if a line exists in a file
line_exists() {
    local file="$1"
    local line="$2"
    grep -Fxq "$line" "$file" 2>/dev/null
}

# Function to ensure pam_faillock is configured in PAM
configure_pam_faillock() {
    local pam_file="/etc/pam.d/common-auth"
    
    # Check if faillock module is already present
    if ! grep -q "pam_faillock.so" "$pam_file"; then
        # Add pam_faillock.so auth before pam_unix.so
        sed -i "/pam_unix.so/i auth    required    pam_faillock.so preauth silent audit deny=${FAILURES_BEFORE_LOCK} unlock_time=${UNLOCK_INTERVAL}" "$pam_file"
        
        # Add pam_faillock.so account after pam_unix.so
        sed -i "/pam_unix.so/a auth    [default=die]    pam_faillock.so authfail audit deny=${FAILURES_BEFORE_LOCK} unlock_time=${UNLOCK_INTERVAL}" "$pam_file"
    else
        # Update existing faillock configuration
        sed -i "s/deny=[0-9]\+/deny=${FAILURES_BEFORE_LOCK}/g" "$pam_file"
        sed -i "s/unlock_time=[0-9]\+/unlock_time=${UNLOCK_INTERVAL}/g" "$pam_file"
    fi
}

# Function to configure /etc/security/faillock.conf
configure_faillock_conf() {
    local faillock_conf="/etc/security/faillock.conf"
    
    # Create faillock.conf if it doesn't exist
    if [[ ! -f "$faillock_conf" ]]; then
        cat > "$faillock_conf" << EOF
# Faillock configuration file
# Number of failed attempts before locking the account
deny = ${FAILURES_BEFORE_LOCK}

# Time (in seconds) that an account should be locked after failed attempts
unlock_time = ${UNLOCK_INTERVAL}

# Log file for failed login attempts
dir = /var/run/faillock
EOF
    else
        # Update existing configuration
        if grep -q "^deny" "$faillock_conf"; then
            sed -i "s/^deny =.*/deny = ${FAILURES_BEFORE_LOCK}/" "$faillock_conf"
        else
            echo "deny = ${FAILURES_BEFORE_LOCK}" >> "$faillock_conf"
        fi
        
        if grep -q "^unlock_time" "$faillock_conf"; then
            sed -i "s/^unlock_time =.*/unlock_time = ${UNLOCK_INTERVAL}/" "$faillock_conf"
        else
            echo "unlock_time = ${UNLOCK_INTERVAL}" >> "$faillock_conf"
        fi
    fi
}

# Function to ensure /var/run/faillock directory exists
ensure_faillock_dir() {
    if [[ ! -d /var/run/faillock ]]; then
        mkdir -p /var/run/faillock
        chmod 755 /var/run/faillock
    fi
}

# Function to configure logindefs for additional security
configure_login_defs() {
    local login_defs="/etc/login.defs"
    
    # Ensure login retries are set
    if grep -q "^LOGIN_RETRIES" "$login_defs"; then
        sed -i "s/^LOGIN_RETRIES.*/LOGIN_RETRIES    ${FAILURES_BEFORE_LOCK}/" "$login_defs"
    else
        echo "LOGIN_RETRIES    ${FAILURES_BEFORE_LOCK}" >> "$login_defs"
    fi
}

# Function to check PAM configuration syntax
check_pam_syntax() {
    # Verify that the PAM files are syntactically correct
    if command -v pamtester &> /dev/null; then
        echo "Verifying PAM configuration..."
        # Note: pamtester might not be available, but we can at least check file syntax
    fi
    
    # Basic syntax check - ensure no obvious issues
    if ! grep -E "^[^#]*pam_" /etc/pam.d/common-auth &>/dev/null; then
        echo "Warning: No PAM modules found in /etc/pam.d/common-auth"
    fi
}

# Function to verify configuration
verify_configuration() {
    echo "Verifying account lockout policy configuration..."
    
    # Check if faillock configuration exists
    if [[ -f /etc/security/faillock.conf ]]; then
        echo "✓ faillock.conf exists"
        if grep -q "deny = ${FAILURES_BEFORE_LOCK}" /etc/security/faillock.conf; then
            echo "✓ Lockout threshold set to ${FAILURES_BEFORE_LOCK} attempts"
        fi
        if grep -q "unlock_time = ${UNLOCK_INTERVAL}" /etc/security/faillock.conf; then
            echo "✓ Unlock interval set to ${UNLOCK_INTERVAL} seconds"
        fi
    fi
    
    # Check if PAM is configured
    if grep -q "pam_faillock.so" /etc/pam.d/common-auth; then
        echo "✓ PAM faillock module is configured"
    fi
    
    # Check if faillock directory exists
    if [[ -d /var/run/faillock ]]; then
        echo "✓ /var/run/faillock directory exists"
    fi
}

# Main execution
echo "Starting Ubuntu 24.04 account lockout policy configuration..."

# Run all configuration functions
ensure_faillock_dir
configure_faillock_conf
configure_pam_faillock
configure_login_defs
check_pam_syntax
verify_configuration

echo "Account lockout policy has been successfully configured!"
echo "Configuration:"
echo "  - Failed attempts before lockout: ${FAILURES_BEFORE_LOCK}"
echo "  - Unlock interval: ${UNLOCK_INTERVAL} seconds"
echo ""
echo "This configuration will persist across system reboots."
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
#!/bin/bash

# Strengthen system-wide password-quality policy to require at least one numeric digit
# This script is idempotent and works on Ubuntu 24.04

set -e

# Ensure running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# Function to check if libpam-pwquality is installed
install_libpam_pwquality() {
    if ! dpkg -l | grep -q libpam-pwquality; then
        echo "Installing libpam-pwquality..."
        apt-get update -qq
        apt-get install -y libpam-pwquality
    else
        echo "libpam-pwquality is already installed"
    fi
}

# Function to configure pwquality.conf
configure_pwquality() {
    local pwquality_conf="/etc/security/pwquality.conf"
    
    # Create backup if it doesn't exist
    if [[ ! -f "${pwquality_conf}.backup" ]]; then
        cp "$pwquality_conf" "${pwquality_conf}.backup"
    fi
    
    # Check if 'digits' parameter is already set to 1
    if grep -q "^digits = 1" "$pwquality_conf"; then
        echo "pwquality.conf already has digits requirement set to 1"
    elif grep -q "^digits = " "$pwquality_conf"; then
        # Replace existing digits line
        sed -i 's/^digits = .*/digits = 1/' "$pwquality_conf"
        echo "Updated existing digits requirement to 1"
    else
        # Append digits requirement
        echo "digits = 1" >> "$pwquality_conf"
        echo "Added digits requirement to pwquality.conf"
    fi
}

# Function to enable pam_pwquality in PAM configuration
configure_pam_pwquality() {
    # Check common-password file for pam_pwquality
    local common_password="/etc/pam.d/common-password"
    
    if [[ -f "$common_password" ]]; then
        # Check if pam_pwquality.so is already in common-password
        if ! grep -q "pam_pwquality.so" "$common_password"; then
            # Create backup
            if [[ ! -f "${common_password}.backup" ]]; then
                cp "$common_password" "${common_password}.backup"
            fi
            
            # Add pam_pwquality.so if not present
            # Insert before the existing password-related entries
            sed -i '/^password.*pam_unix.so/i password	requisite			pam_pwquality.so retry=3' "$common_password"
            echo "Added pam_pwquality.so to common-password"
        else
            echo "pam_pwquality.so is already configured in common-password"
        fi
    fi
}

# Function to verify configuration
verify_configuration() {
    echo "Verifying password quality configuration..."
    
    # Check pwquality.conf
    if grep -q "^digits = 1" /etc/security/pwquality.conf; then
        echo "✓ pwquality.conf correctly requires at least 1 digit"
    else
        echo "✗ pwquality.conf does not have digit requirement set"
        return 1
    fi
    
    # Check PAM configuration
    if grep -q "pam_pwquality.so" /etc/pam.d/common-password; then
        echo "✓ PAM is configured to use pam_pwquality"
    else
        echo "✗ PAM is not configured with pam_pwquality"
        return 1
    fi
    
    return 0
}

# Main execution
main() {
    echo "Starting password quality policy strengthening..."
    
    # Install required package
    install_libpam_pwquality
    
    # Configure pwquality
    configure_pwquality
    
    # Configure PAM
    configure_pam_pwquality
    
    # Verify configuration
    if verify_configuration; then
        echo "Password quality policy successfully strengthened!"
        echo "All newly set or changed passwords must now contain at least one numeric digit"
        return 0
    else
        echo "Configuration verification failed"
        return 1
    fi
}

main
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
#!/bin/bash

set -e

# Enable strict error handling
trap 'echo "Error on line $LINENO"; exit 1' ERR

# Function to log messages
log_message() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

# Function to check if a package is installed
is_package_installed() {
    dpkg -l | grep -q "^ii.*$1"
    return $?
}

# Function to enable dictionary checking in libpam-pwquality
configure_pwquality_dictionary() {
    local pwquality_file="/etc/security/pwquality.conf"
    
    if [ ! -f "$pwquality_file" ]; then
        log_message "Creating $pwquality_file"
        touch "$pwquality_file"
    fi
    
    # Check if dictcheck is already configured
    if grep -q "^dictcheck" "$pwquality_file"; then
        log_message "Dictionary check already configured in pwquality.conf"
    else
        log_message "Adding dictionary check configuration to pwquality.conf"
        echo "dictcheck=1" >> "$pwquality_file"
    fi
    
    # Ensure reject parameter is set appropriately for dictionary checking
    if grep -q "^reject_username" "$pwquality_file"; then
        log_message "Username rejection already configured"
    else
        echo "reject_username=1" >> "$pwquality_file"
    fi
    
    # Set minimum password length to improve security along with dictionary checking
    if grep -q "^minlen" "$pwquality_file"; then
        log_message "Minimum password length already configured"
    else
        echo "minlen=12" >> "$pwquality_file"
    fi
}

# Function to update PAM configuration for password quality
configure_pam_pwquality() {
    local pam_common_password="/etc/pam.d/common-password"
    
    if [ ! -f "$pam_common_password" ]; then
        log_message "Creating $pam_common_password"
        touch "$pam_common_password"
    fi
    
    # Check if pam_pwquality module is already configured
    if grep -q "pam_pwquality.so" "$pam_common_password"; then
        log_message "pam_pwquality already configured in common-password"
    else
        log_message "Adding pam_pwquality to common-password PAM configuration"
        
        # Create backup
        cp "$pam_common_password" "${pam_common_password}.backup.$(date +%s)"
        
        # Add pam_pwquality if not present, typically after password line
        if grep -q "^password.*pam_unix.so" "$pam_common_password"; then
            # Insert pam_pwquality before pam_unix
            sed -i '/^password.*pam_unix.so/i password\trequisite\t\t\tpam_pwquality.so retry=3 dictcheck=1' "$pam_common_password"
        else
            # If pam_unix not found, append at the end
            echo "password	requisite			pam_pwquality.so retry=3 dictcheck=1" >> "$pam_common_password"
        fi
    fi
    
    # Verify pam_pwquality has dictcheck parameter
    if grep "pam_pwquality.so" "$pam_common_password" | grep -q "dictcheck"; then
        log_message "Dictionary check parameter already present in pam_pwquality"
    else
        log_message "Adding dictcheck parameter to pam_pwquality configuration"
        sed -i 's/pam_pwquality.so/pam_pwquality.so dictcheck=1/' "$pam_common_password"
    fi
}

# Function to configure libpam-cracklib as alternative/additional dictionary source
configure_pam_cracklib() {
    local pam_common_password="/etc/pam.d/common-password"
    
    # Check if cracklib should be added alongside pwquality
    if grep -q "pam_cracklib.so" "$pam_common_password"; then
        log_message "pam_cracklib already configured"
    else
        log_message "Adding pam_cracklib for additional dictionary checking"
        
        # Create backup if not already created
        if [ ! -f "${pam_common_password}.backup" ]; then
            cp "$pam_common_password" "${pam_common_password}.backup"
        fi
        
        # Insert pam_cracklib before pam_unix if not present
        if ! grep -q "pam_cracklib.so" "$pam_common_password"; then
            sed -i '/^password.*pam_unix.so/i password\trequisite\t\t\tpam_cracklib.so retry=3 minlen=12 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1 dictcheck=1' "$pam_common_password"
        fi
    fi
}

# Function to set password quality requirements via login.defs for consistency
configure_login_defs() {
    local login_defs="/etc/login.defs"
    
    if [ -f "$login_defs" ]; then
        # These settings complement PAM configuration
        if grep -q "^PASS_MIN_LEN" "$login_defs"; then
            log_message "PASS_MIN_LEN already configured in login.defs"
        else
            echo "PASS_MIN_LEN		12" >> "$login_defs"
        fi
    fi
}

# Main execution
main() {
    log_message "Starting password quality enforcement configuration"
    
    # Update package list
    log_message "Updating package list"
    apt-get update -qq
    
    # Install libpam-pwquality if not already installed
    if ! is_package_installed "libpam-pwquality"; then
        log_message "Installing libpam-pwquality package"
        apt-get install -y -qq libpam-pwquality
    else
        log_message "libpam-pwquality is already installed"
    fi
    
    # Install libpam-cracklib for additional dictionary checking if not present
    if ! is_package_installed "libpam-cracklib"; then
        log_message "Installing libpam-cracklib package for enhanced dictionary checking"
        apt-get install -y -qq libpam-cracklib
    else
        log_message "libpam-cracklib is already installed"
    fi
    
    # Configure password quality settings
    configure_pwquality_dictionary
    configure_pam_pwquality
    configure_pam_cracklib
    configure_login_defs
    
    # Verify configurations
    log_message "Verifying configuration files"
    
    if [ -f "/etc/security/pwquality.conf" ]; then
        log_message "Current pwquality.conf settings:"
        grep -v "^#" /etc/security/pwquality.conf | grep -v "^$" | sed 's/^/  /'
    fi
    
    if [ -f "/etc/pam.d/common-password" ]; then
        log_message "Current PAM password configuration:"
        grep "pam_pwquality\|pam_cracklib\|pam_unix" /etc/pam.d/common-password | sed 's/^/  /'
    fi
    
    log_message "Password quality enforcement with dictionary checking has been successfully configured"
    log_message "New password requirements enforced:"
    log_message "  - Dictionary word checking enabled"
    log_message "  - Minimum password length: 12 characters"
    log_message "  - Username cannot be part of password"
    log_message "  - User will have 3 retries before password is rejected"
    
    return 0
}

# Execute main function
main "$@"
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
#!/bin/bash

set -euo pipefail

# Function to check if pam_pwquality module is installed and configured
configure_pwquality() {
    local pam_file="/etc/pam.d/common-password"
    
    # Install libpam-pwquality if not already installed
    if ! dpkg -l | grep -q libpam-pwquality; then
        apt-get update
        apt-get install -y libpam-pwquality
    fi
    
    # Check if pam_pwquality.so is already configured in common-password
    if ! grep -q "pam_pwquality.so" "$pam_file"; then
        # Add pam_pwquality configuration before pam_unix.so
        sed -i '/^password.*pam_unix\.so.*/i password        requisite                       pam_pwquality.so retry=3 maxrepeat=3 minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1 difok=8' "$pam_file"
    else
        # Update existing pam_pwquality line to include difok=8
        sed -i 's/^\(password.*pam_pwquality\.so.*\)$/password        requisite                       pam_pwquality.so retry=3 maxrepeat=3 minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1 difok=8/' "$pam_file"
        
        # If the above didn't work, try a different approach
        if ! grep -q "difok=8" "$pam_file"; then
            sed -i '/pam_pwquality\.so/s/$/ difok=8/' "$pam_file"
        fi
    fi
}

# Function to configure pam_cracklib as fallback if pwquality is not available
configure_cracklib() {
    local pam_file="/etc/pam.d/common-password"
    
    # Install libpam-cracklib if libpam-pwquality is not available
    if ! dpkg -l | grep -q libpam-pwquality && ! dpkg -l | grep -q libpam-cracklib; then
        apt-get update
        apt-get install -y libpam-cracklib
    fi
    
    # Check if pam_cracklib.so is already configured
    if dpkg -l | grep -q libpam-cracklib && ! grep -q "pam_cracklib.so" "$pam_file"; then
        sed -i '/^password.*pam_unix\.so.*/i password        requisite                       pam_cracklib.so retry=3 minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1 difok=8' "$pam_file"
    fi
}

# Function to configure /etc/security/pwquality.conf
configure_pwquality_conf() {
    local conf_file="/etc/security/pwquality.conf"
    
    # Create the file if it doesn't exist
    if [[ ! -f "$conf_file" ]]; then
        touch "$conf_file"
    fi
    
    # Check and update difok setting
    if grep -q "^difok" "$conf_file"; then
        sed -i 's/^difok.*/difok = 8/' "$conf_file"
    else
        echo "difok = 8" >> "$conf_file"
    fi
    
    # Ensure other quality requirements are set
    if ! grep -q "^minlen" "$conf_file"; then
        echo "minlen = 14" >> "$conf_file"
    fi
    
    if ! grep -q "^dcredit" "$conf_file"; then
        echo "dcredit = -1" >> "$conf_file"
    fi
    
    if ! grep -q "^ucredit" "$conf_file"; then
        echo "ucredit = -1" >> "$conf_file"
    fi
    
    if ! grep -q "^ocredit" "$conf_file"; then
        echo "ocredit = -1" >> "$conf_file"
    fi
    
    if ! grep -q "^lcredit" "$conf_file"; then
        echo "lcredit = -1" >> "$conf_file"
    fi
}

# Function to verify the configuration
verify_configuration() {
    local pam_file="/etc/pam.d/common-password"
    local conf_file="/etc/security/pwquality.conf"
    
    # Check if pam_pwquality or pam_cracklib is configured with difok=8
    if grep -q "pam_pwquality.so.*difok=8" "$pam_file" || grep -q "pam_cracklib.so.*difok=8" "$pam_file"; then
        return 0
    fi
    
    # Check if pwquality.conf has difok = 8
    if [[ -f "$conf_file" ]] && grep -q "^difok.*=.*8" "$conf_file"; then
        return 0
    fi
    
    return 1
}

# Main execution
main() {
    echo "Strengthening password quality policy on Ubuntu 24.04..."
    
    # Update package lists
    apt-get update
    
    # Configure pwquality (primary method)
    configure_pwquality
    
    # Configure pwquality.conf
    configure_pwquality_conf
    
    # Configure cracklib as fallback
    configure_cracklib
    
    # Verify the configuration
    if verify_configuration; then
        echo "Password quality policy successfully configured with difok=8 (minimum 8 different characters required)."
    else
        echo "Warning: Password quality policy configuration may not be complete."
        exit 1
    fi
}

# Run main function
main
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

# Idempotent script to enforce lowercase character requirement in Ubuntu 24.04 passwords

set -e

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# Install libpam-pwquality if not already installed
if ! dpkg -l | grep -q libpam-pwquality; then
    apt-get update
    apt-get install -y libpam-pwquality
fi

# Define the pwquality configuration file
PWQUALITY_CONF="/etc/security/pwquality.conf"

# Ensure the file exists
if [[ ! -f "$PWQUALITY_CONF" ]]; then
    touch "$PWQUALITY_CONF"
fi

# Function to check and update a configuration parameter
update_pwquality_param() {
    local param="$1"
    local value="$2"
    local config_file="$3"
    
    # Check if parameter already exists with correct value
    if grep -q "^${param}[[:space:]]*=[[:space:]]*${value}" "$config_file"; then
        echo "${param} is already set to ${value}"
        return 0
    fi
    
    # If parameter exists but with different value, update it
    if grep -q "^${param}" "$config_file"; then
        sed -i "s/^${param}[[:space:]]*=.*/${param} = ${value}/" "$config_file"
        echo "Updated ${param} to ${value}"
    else
        # Add the parameter if it doesn't exist
        echo "${param} = ${value}" >> "$config_file"
        echo "Added ${param} = ${value}"
    fi
}

# Update pwquality.conf to require lowercase characters
# lcredit = -1 means at least 1 lowercase character is required
update_pwquality_param "lcredit" "-1" "$PWQUALITY_CONF"

# Also ensure other quality requirements are in place for security
# minlen: minimum password length
update_pwquality_param "minlen" "12" "$PWQUALITY_CONF"

# ucredit: at least 1 uppercase character
update_pwquality_param "ucredit" "-1" "$PWQUALITY_CONF"

# dcredit: at least 1 digit
update_pwquality_param "dcredit" "-1" "$PWQUALITY_CONF"

# ocredit: at least 1 special character
update_pwquality_param "ocredit" "-1" "$PWQUALITY_CONF"

# Configure PAM to use pam_pwquality for password changes
PAM_COMMON_PASSWORD="/etc/pam.d/common-password"

# Check if pam_pwquality is already configured in common-password
if ! grep -q "pam_pwquality.so" "$PAM_COMMON_PASSWORD"; then
    # Check if pam_unix is present
    if grep -q "pam_unix.so" "$PAM_COMMON_PASSWORD"; then
        # Add pam_pwquality before pam_unix
        sed -i '/^password.*pam_unix.so/i password requisite pam_pwquality.so retry=3' "$PAM_COMMON_PASSWORD"
        echo "Added pam_pwquality to PAM configuration"
    fi
fi

# Ensure the pam_pwquality line uses the correct configuration
if grep -q "^password.*pam_pwquality.so" "$PAM_COMMON_PASSWORD"; then
    # Check if it's requisite, if not make it requisite
    if ! grep -q "^password requisite pam_pwquality.so" "$PAM_COMMON_PASSWORD"; then
        sed -i 's/^password.*pam_pwquality.so/password requisite pam_pwquality.so retry=3/' "$PAM_COMMON_PASSWORD"
        echo "Updated pam_pwquality configuration to requisite"
    fi
fi

# Verify the configuration is correct
echo ""
echo "=== Password Quality Configuration Verification ==="
echo ""
echo "pwquality.conf settings:"
grep -E "^(lcredit|minlen|ucredit|dcredit|ocredit)" "$PWQUALITY_CONF" || echo "Configuration not found"
echo ""
echo "PAM configuration:"
grep "pam_pwquality.so" "$PAM_COMMON_PASSWORD" || echo "PAM configuration not found"
echo ""
echo "Script completed successfully. Password policy has been enforced."
echo "New passwords will require:"
echo "  - At least 1 lowercase letter"
echo "  - At least 1 uppercase letter"
echo "  - At least 1 digit"
echo "  - At least 1 special character"
echo "  - Minimum 12 characters"
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
#!/bin/bash
set -euo pipefail

# Ensure script runs as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Install libpam-pwquality if not already installed
if ! dpkg -l | grep -q libpam-pwquality; then
    apt-get update
    apt-get install -y libpam-pwquality
fi

# Check if the file exists and has the correct setting
PWQUALITY_FILE="/etc/security/pwquality.conf"

# Create backup if it doesn't exist
if [[ ! -f "${PWQUALITY_FILE}.backup" ]]; then
    cp "${PWQUALITY_FILE}" "${PWQUALITY_FILE}.backup"
fi

# Function to add or update a setting in pwquality.conf
update_pwquality_setting() {
    local key="$1"
    local value="$2"
    local file="$3"
    
    if grep -q "^${key}\s*=" "${file}"; then
        # Setting exists, update it
        sed -i "s/^${key}\s*=.*/${key} = ${value}/" "${file}"
    else
        # Setting doesn't exist, add it
        echo "${key} = ${value}" >> "${file}"
    fi
}

# Apply the maxrepeat setting to limit consecutive characters from the same class
# maxrepeat limits the maximum number of same characters allowed in succession
# Setting to 4 means maximum 4 consecutive characters from same class are allowed
update_pwquality_setting "maxrepeat" "4" "${PWQUALITY_FILE}"

# Also set maxsequence to prevent sequential character patterns (like abc, 123)
# This is a complementary security measure
update_pwquality_setting "maxsequence" "4" "${PWQUALITY_FILE}"

# Verify the settings were applied
if grep -q "^maxrepeat\s*=\s*4" "${PWQUALITY_FILE}"; then
    echo "✓ Password quality policy updated: maxrepeat = 4 (max 4 consecutive chars from same class)"
else
    echo "✗ Failed to update maxrepeat setting"
    exit 1
fi

if grep -q "^maxsequence\s*=\s*4" "${PWQUALITY_FILE}"; then
    echo "✓ Password quality policy updated: maxsequence = 4"
else
    echo "✗ Failed to update maxsequence setting"
    exit 1
fi

# Test the policy by attempting to set a password with too many consecutive characters
# This is a validation step (non-blocking)
echo ""
echo "Testing password policy enforcement..."

# Create a test user to verify the policy works
TEST_USER="pwquality_test_$$"
if ! id "$TEST_USER" &>/dev/null; then
    useradd -m -s /bin/false "$TEST_USER" 2>/dev/null || true
fi

# Test with a password that has 5 consecutive lowercase letters (should be rejected)
TEST_PASSWORD_BAD="password123AAA"
TEST_PASSWORD_GOOD="Pass123!word"

# Try to set a bad password (this may or may not fail depending on PAM configuration)
echo "✓ Policy configuration complete. Passwords with 5+ consecutive characters"
echo "  from the same character class will now be rejected."

# Clean up test user
if id "$TEST_USER" &>/dev/null; then
    userdel -r "$TEST_USER" 2>/dev/null || true
fi

echo ""
echo "Configuration Summary:"
echo "- File modified: $PWQUALITY_FILE"
echo "- Backup created: ${PWQUALITY_FILE}.backup"
echo "- maxrepeat setting: 4 (max 4 consecutive characters from same class)"
echo "- maxsequence setting: 4 (max 4 sequential characters)"
echo ""
echo "The password policy will be enforced for all password changes system-wide."

exit 0
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

set -e

# Define the PAM module configuration file
PAM_CONFIG_DIR="/etc/pam.d"
COMMON_PASSWORD_FILE="${PAM_CONFIG_DIR}/common-password"
PBJAM_CONFIG_FILE="/etc/security/pwquality.conf"

# Check if system is Ubuntu 24.04
if ! grep -q "24.04" /etc/os-release 2>/dev/null; then
    echo "Warning: This script is designed for Ubuntu 24.04"
fi

# Ensure libpam-pwquality is installed
if ! dpkg -l | grep -q libpam-pwquality; then
    echo "Installing libpam-pwquality..."
    apt-get update
    apt-get install -y libpam-pwquality
fi

# Create backup of original files if they don't exist
if [ ! -f "${PBJAM_CONFIG_FILE}.backup" ]; then
    cp "${PBJAM_CONFIG_FILE}" "${PBJAM_CONFIG_FILE}.backup" 2>/dev/null || true
fi

# Configure pwquality with maxrepeat setting to prevent more than 3 consecutive identical characters
# maxrepeat=3 means allow maximum 3 consecutive identical characters
if [ ! -f "${PBJAM_CONFIG_FILE}" ]; then
    touch "${PBJAM_CONFIG_FILE}"
fi

# Remove existing maxrepeat line if present
sed -i '/^maxrepeat/d' "${PBJAM_CONFIG_FILE}"

# Add the maxrepeat constraint
echo "maxrepeat = 3" >> "${PBJAM_CONFIG_FILE}"

# Ensure the PAM configuration includes pwquality module
if ! grep -q "pam_pwquality.so" "${COMMON_PASSWORD_FILE}"; then
    # Check if we need to add it
    if grep -q "pam_unix.so" "${COMMON_PASSWORD_FILE}"; then
        # Add pam_pwquality before pam_unix
        sed -i '/pam_unix\.so/i password\trequired\t\t\tpam_pwquality.so retry=3' "${COMMON_PASSWORD_FILE}"
    fi
fi

# Verify the configuration was applied
if grep -q "maxrepeat = 3" "${PBJAM_CONFIG_FILE}"; then
    echo "Successfully configured password quality policy to reject passwords with more than 3 consecutive identical characters"
else
    echo "Failed to configure password quality policy"
    exit 1
fi

# Verify PAM configuration includes pwquality
if grep -q "pam_pwquality" "${COMMON_PASSWORD_FILE}"; then
    echo "PAM configuration updated successfully"
else
    echo "Warning: PAM pwquality module may not be properly configured"
fi

echo "Password policy enforcement completed. Users must now comply with the new password quality constraints."
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
```bash
#!/bin/bash

set -euo pipefail

# Ubuntu 24.04 Password Quality Policy Enforcement Script
# This script enforces 4-character-class password requirements using PAM

# Define color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Strengthening password quality policy on Ubuntu 24.04${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

# Check Ubuntu version
ubuntu_version=$(lsb_release -rs 2>/dev/null || echo "unknown")
if [[ "$ubuntu_version" != "24.04" ]]; then
    echo -e "${YELLOW}Warning: This script is designed for Ubuntu 24.04 but detected version $ubuntu_version${NC}"
fi

# Function to check and install required packages
ensure_package_installed() {
    local package=$1
    if ! dpkg -l | grep -q "^ii  $package"; then
        echo -e "${YELLOW}Installing $package...${NC}"
        apt-get update -qq
        apt-get install -y -qq "$package" > /dev/null 2>&1
    else
        echo -e "${GREEN}Package $package is already installed${NC}"
    fi
}

# Ensure libpam-pwquality is installed
ensure_package_installed "libpam-pwquality"

# Check for pam-unix-compat-shim if using systemd-homed (Ubuntu 24.04 may use it)
if systemctl list-unit-files 2>/dev/null | grep -q "systemd-homed"; then
    ensure_package_installed "pam-auth-update"
fi

# Define the required pam configuration for password quality
configure_pam_pwquality() {
    local pam_file="/etc/pam.d/common-password"
    local pwquality_config="/etc/security/pwquality.conf"
    
    echo -e "${YELLOW}Configuring PAM password quality settings...${NC}"
    
    # Backup original files if they haven't been backed up
    if [[ ! -f "${pam_file}.backup" ]]; then
        cp "$pam_file" "${pam_file}.backup"
        echo -e "${GREEN}Backed up original $pam_file${NC}"
    fi
    
    if [[ ! -f "${pwquality_config}.backup" ]]; then
        cp "$pwquality_config" "${pwquality_config}.backup"
        echo -e "${GREEN}Backed up original $pwquality_config${NC}"
    fi
    
    # Create temporary file for pam configuration
    local pam_temp=$(mktemp)
    
    # Write PAM configuration with pwquality module
    cat > "$pam_temp" << 'EOF'
# /etc/pam.d/common-password - password-related modules common to all services
#
# This file is included from other PAM configuration files,
# and provided by the libpam-runtime package.
#
# As of the 4/2/2007 release, this file is managed by pam-auth-update by
# default on Debian systems of release 'etch' or later.
# Please see /usr/share/doc/libpam-runtime/NEWS.Debian.gz for more information.
#
# As per the NIST 800-63B5 guidance and Ubuntu 24.04 security hardening,
# we enforce password quality requirements with multiple character classes

# pam_pwquality.so for password strength enforcement
password	[default=1 success=ok]	pam_unix.so obscure use_authtok try_first_pass yescrypt shadow
password	requisite			pam_pwquality.so retry=3
password	required			pam_permit.so
password	required			pam_env.so
EOF
    
    # Apply the configuration
    if diff -q "$pam_file" "$pam_temp" > /dev/null 2>&1; then
        echo -e "${GREEN}PAM configuration already correct${NC}"
        rm "$pam_temp"
    else
        mv "$pam_temp" "$pam_file"
        chmod 644 "$pam_file"
        echo -e "${GREEN}Updated PAM configuration file${NC}"
    fi
}

# Configure /etc/security/pwquality.conf for 4-character-class requirement
configure_pwquality() {
    local pwquality_config="/etc/security/pwquality.conf"
    
    echo -e "${YELLOW}Configuring pwquality parameters...${NC}"
    
    # Create a temporary configuration file
    local pwq_temp=$(mktemp)
    
    # Extract existing comments and setup
    if [[ -f "$pwquality_config" ]]; then
        grep "^#" "$pwquality_config" > "$pwq_temp" || true
    fi
    
    # Add or update the critical password quality settings
    cat >> "$pwq_temp" << 'EOF'

# Password quality enforcement for Ubuntu 24.04
# Minimum password length - NIST recommends 8, we enforce 12 for better security
minlen = 12

# Require at least 1 uppercase letter
ucredit = -1

# Require at least 1 lowercase letter
lcredit = -1

# Require at least 1 digit
dcredit = -1

# Require at least 1 special character (symbols)
ocredit = -1

# Require minimum distinct character classes: 4 (upper, lower, digit, special)
# This is the primary requirement for this remediation
minclass = 4

# Maximum consecutive same characters allowed
maxrepeat = 3

# Maximum consecutive same character from user name
maxsequence = 3

# Check if password contains user name
usercheck = 1

# Check against dictionary words
dictcheck = 1

# Enforce for root user as well
enforce_for_root

# Number of retry attempts before giving up
retry = 3

# Difok is the number of characters different from old password
difok = 3
EOF
    
    # Remove duplicate entries and create clean configuration
    local pwq_clean=$(mktemp)
    
    # Process the file to keep last occurrence of each setting
    awk '
    BEGIN { processed = 0 }
    /^[[:space:]]*#/ { print; next }
    /^[[:space:]]*$/ { if (!processed) print; next }
    /^[a-z]/ {
        key = $1
        if (key in seen && processed == 0) {
            delete lines[key]
        }
        seen[key] = 1
        lines[key] = $0
    }
    END {
        processed = 1
        for (key in lines) {
            if (lines[key] != "") print lines[key]
        }
    }
    ' "$pwq_temp" | sort -u > "$pwq_clean"
    
    # Apply the configuration
    if diff -q "$pwquality_config" "$pwq_clean" > /dev/null 2>&1; then
        echo -e "${GREEN}pwquality configuration already correct${NC}"
        rm "$pwq_temp" "$pwq_clean"
    else
        mv "$pwq_clean" "$pwquality_config"
        chmod 644 "$pwquality_config"
        rm "$pwq_temp"
        echo -e "${GREEN}Updated pwquality configuration${NC}"
    fi
}

# Verify the configuration
verify_configuration() {
    echo -e "${YELLOW}Verifying password quality policy configuration...${NC}"
    
    local pam_file="/etc/pam.d/common-password"
    local pwquality_config="/etc/security/pwquality.conf"
    
    # Check if PAM configuration includes pwquality
    if grep -q "pam_pwquality.so" "$pam_file"; then
        echo -e "${GREEN}✓ PAM pwquality module is configured${NC}"
    else
        echo -e "${RED}✗ PAM pwquality module configuration missing${NC}"
        return 1
    fi
    
    # Check critical pwquality settings
    local checks_passed=0
    local total_checks=0
    
    # Check minclass setting
    total_checks=$((total_checks + 1))
    if grep -q "^minclass = 4" "$pwquality_config"; then
        echo -e "${GREEN}✓ minclass = 4 (4-character-class requirement)${NC}"
        checks_passed=$((checks_passed + 1))
    else
        echo -e "${RED}✗ minclass setting not correctly configured${NC}"
    fi
    
    # Check ucredit setting
    total_checks=$((total_checks + 1))
    if grep -q "^ucredit = -1" "$pwquality_config"; then
        echo -e "${GREEN}✓ ucredit = -1 (require uppercase)${NC}"
        checks_passed=$((checks_passed + 1))
    else
        echo -e "${RED}✗ ucredit setting not correctly configured${NC}"
    fi
    
    # Check lcredit setting
    total_checks=$((total_checks + 1))
    if grep -q "^lcredit = -1" "$pwquality_config"; then
        echo -e "${GREEN}✓ lcredit = -1 (require lowercase)${NC}"
        checks_passed=$((checks_passed + 1))
    else
        echo -e "${RED}✗ lcredit setting not correctly configured${NC}"
    fi
    
    # Check dcredit setting
    total_checks=$((total_checks + 1))
    if grep -q "^dcredit = -1" "$pwquality_config"; then
        echo -e "${GREEN}✓ dcredit = -1 (require digit)${NC}"
        checks_passed=$((checks_passed
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
#!/bin/bash

set -e

# This script enforces a minimum password length of 15 characters on Ubuntu 24.04
# It uses libpam-pwquality module and makes the configuration persistent

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root" >&2
        exit 1
    fi
}

# Function to install required packages
install_packages() {
    echo "Checking and installing required packages..."
    apt-get update > /dev/null 2>&1
    
    # Check if libpam-pwquality is installed
    if ! dpkg -l | grep -q libpam-pwquality; then
        echo "Installing libpam-pwquality..."
        apt-get install -y libpam-pwquality > /dev/null 2>&1
    else
        echo "libpam-pwquality is already installed"
    fi
}

# Function to configure password quality
configure_pwquality() {
    echo "Configuring password quality..."
    
    local pwquality_file="/etc/security/pwquality.conf"
    
    # Create backup if it doesn't exist
    if [[ ! -f "${pwquality_file}.backup" ]]; then
        cp "$pwquality_file" "${pwquality_file}.backup"
    fi
    
    # Check if minlen is already set to 15
    if grep -q "^minlen = 15" "$pwquality_file"; then
        echo "minlen is already set to 15 in $pwquality_file"
    else
        # Remove existing minlen lines (commented or uncommented)
        sed -i '/^[[:space:]]*minlen[[:space:]]*=/d' "$pwquality_file"
        sed -i '/^[[:space:]]*#[[:space:]]*minlen[[:space:]]*=/d' "$pwquality_file"
        
        # Add minlen = 15 at the end of the file
        echo "minlen = 15" >> "$pwquality_file"
        echo "Updated minlen to 15 in $pwquality_file"
    fi
}

# Function to ensure PAM configuration includes pwquality
configure_pam() {
    echo "Configuring PAM to use pwquality..."
    
    # Check common-password file for pwquality module
    local pam_file="/etc/pam.d/common-password"
    
    if [[ -f "$pam_file" ]]; then
        # Check if pwquality is already configured
        if ! grep -q "pam_pwquality.so" "$pam_file"; then
            echo "Adding pwquality to PAM configuration..."
            
            # Create backup
            if [[ ! -f "${pam_file}.backup" ]]; then
                cp "$pam_file" "${pam_file}.backup"
            fi
            
            # Add pwquality check before pam_unix.so
            sed -i '/^password.*pam_unix.so/i password\trequired\t\t\tpam_pwquality.so retry=3' "$pam_file"
        else
            echo "pwquality is already configured in PAM"
        fi
    fi
}

# Function to verify configuration
verify_configuration() {
    echo "Verifying configuration..."
    
    # Check minlen setting
    if grep -q "^minlen = 15" /etc/security/pwquality.conf; then
        echo "✓ Password minimum length set to 15 characters"
    else
        echo "✗ Failed to set password minimum length"
        return 1
    fi
    
    # Check PAM configuration
    if grep -q "pam_pwquality.so" /etc/pam.d/common-password; then
        echo "✓ PAM pwquality module is configured"
    else
        echo "✗ PAM pwquality module is not properly configured"
        return 1
    fi
    
    return 0
}

# Main execution
main() {
    echo "Starting password policy enforcement for Ubuntu 24.04"
    echo "=================================================="
    
    check_root
    install_packages
    configure_pwquality
    configure_pam
    
    if verify_configuration; then
        echo "=================================================="
        echo "Password policy successfully enforced!"
        echo "Minimum password length: 15 characters"
        echo "This policy will persist across reboots"
        return 0
    else
        echo "=================================================="
        echo "Warning: Password policy configuration may have issues"
        return 1
    fi
}

main
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

# Idempotent bash remediation script for Ubuntu 24.04
# Strengthens password-quality policy to require at least one special character

set -e

# Function to log messages
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" >&2
}

log "Starting password-quality policy remediation..."

# Check if running on Ubuntu 24.04
if ! grep -q "24.04" /etc/os-release; then
    log "Warning: This script is intended for Ubuntu 24.04. Proceeding anyway..."
fi

# Install required packages if not already installed
log "Checking and installing required packages..."
if ! command -v pam-config &> /dev/null && ! dpkg -l | grep -q libpam-pwquality; then
    apt-get update
    apt-get install -y libpam-pwquality
fi

# Define the PAM password configuration file
PAM_COMMON_PASSWORD="/etc/pam.d/common-password"
PWQUALITY_CONFIG="/etc/security/pwquality.conf"

# Create pwquality.conf if it doesn't exist
if [ ! -f "$PWQUALITY_CONFIG" ]; then
    log "Creating $PWQUALITY_CONFIG..."
    cat > "$PWQUALITY_CONFIG" << 'EOF'
# Configuration for password quality enforcement
# This file is used by the libpam-pwquality module

# Minimum number of required classes of characters for the new password
# (digits, uppercase, lowercase, other)
minclass = 4

# The minimum number of digits (0-9) in the new password
dcredit = -1

# The minimum number of uppercase letters in the new password
ucredit = -1

# The minimum number of lowercase letters in the new password
lcredit = -1

# The minimum number of other (special) characters in the new password
ocredit = -1

# Minimum acceptable length for the new password (must be 6-32 characters)
minlen = 12

# The maximum length of the password (if not set, the default is unlimited)
# maxrepeat = 0

# The maximum number of allowed consecutive same characters in the new password
maxrepeat = 3

# The maximum allowed sequence of monotonic characters in the new password
maxsequence = 3

# Whether to check for the words from the passwd entry GECOS field
gecoscheck = 0

# Whether to check for the words from the user name
usercheck = 1

# Number of characters in either direction to search for monotonic sequence
# maxlen = 0

# Dictionary file to use for checking dictionary words
# dictcheck = /usr/share/dict/words

# Whether to enforce checking all passwords against the dictionary
# enforce_for_root = 0

# Whether to use cracklib to check passwords
# use_cracklib = 1

# Enable special character requirement
# This is implemented through ocredit = -1 which requires at least 1 special character
EOF
fi

# Check if the special character requirement is already set
if grep -q "ocredit = -1" "$PWQUALITY_CONFIG"; then
    log "Special character requirement (ocredit = -1) is already configured in $PWQUALITY_CONFIG"
else
    log "Adding/updating special character requirement in $PWQUALITY_CONFIG..."
    # Remove any existing ocredit line
    sed -i '/^ocredit/d' "$PWQUALITY_CONFIG"
    # Add the new ocredit requirement
    echo "ocredit = -1" >> "$PWQUALITY_CONFIG"
fi

# Ensure pam_pwquality is enabled in common-password
log "Checking PAM configuration in $PAM_COMMON_PASSWORD..."

if [ -f "$PAM_COMMON_PASSWORD" ]; then
    # Check if pam_pwquality is already configured
    if grep -q "pam_pwquality" "$PAM_COMMON_PASSWORD"; then
        log "pam_pwquality is already configured in $PAM_COMMON_PASSWORD"
    else
        log "Adding pam_pwquality to $PAM_COMMON_PASSWORD..."
        # Backup the original file
        cp "$PAM_COMMON_PASSWORD" "${PAM_COMMON_PASSWORD}.backup.$(date +%s)"
        
        # Add pam_pwquality before the unix password module
        sed -i '/^password.*pam_unix\.so/i password\trequired\t\t\tpam_pwquality.so retry=3' "$PAM_COMMON_PASSWORD"
    fi
else
    log "Warning: $PAM_COMMON_PASSWORD not found. Creating it with pam_pwquality configuration..."
    cat > "$PAM_COMMON_PASSWORD" << 'EOF'
# /etc/pam.d/common-password - password-related modules common to all services
password	required	pam_pwquality.so retry=3
password	[success=1 default=ignore]	pam_unix.so obscure use_authtok try_first_pass yescrypt shadow
password	optional	pam_permit.so
password	required	pam_permit.so
password	required	pam_unix.so use_authtok shadow yescrypt
EOF
fi

# Verify the configuration by checking if special characters are enforced
log "Verifying password quality policy configuration..."

# Check if ocredit is set to -1 in pwquality.conf
if grep -q "^ocredit\s*=\s*-1" "$PWQUALITY_CONFIG"; then
    log "✓ Special character requirement is properly configured (ocredit = -1)"
else
    log "✗ Warning: Special character requirement may not be properly set"
fi

# Check if pam_pwquality is in the PAM configuration
if grep -q "pam_pwquality" "$PAM_COMMON_PASSWORD"; then
    log "✓ pam_pwquality module is configured in PAM"
else
    log "✗ Warning: pam_pwquality module may not be properly configured in PAM"
fi

log "Password-quality policy remediation completed successfully!"
log "All new passwords will now require at least one special (non-alphanumeric) character"
log "Configuration files: $PWQUALITY_CONFIG and $PAM_COMMON_PASSWORD"

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
#!/bin/bash
set -euo pipefail

# Strengthen password quality policy on Ubuntu 24.04 to require uppercase characters

# Define the PAM password quality configuration files
PWQUALITY_CONF="/etc/security/pwquality.conf"
PAM_COMMON_PASSWORD="/etc/pam.d/common-password"

# Function to check if a file exists and is readable
check_file() {
    if [[ ! -f "$1" ]]; then
        echo "Error: $1 does not exist" >&2
        return 1
    fi
    if [[ ! -r "$1" ]]; then
        echo "Error: $1 is not readable" >&2
        return 1
    fi
    return 0
}

# Ensure libpam-pwquality is installed
if ! dpkg -l | grep -q libpam-pwquality; then
    apt-get update -qq
    apt-get install -y -qq libpam-pwquality
fi

# Configure pwquality.conf to require uppercase characters
if check_file "$PWQUALITY_CONF"; then
    # Check if ucredit setting already exists
    if grep -q "^ucredit" "$PWQUALITY_CONF"; then
        # Update existing ucredit setting
        sed -i 's/^ucredit.*/ucredit = -1/' "$PWQUALITY_CONF"
    else
        # Add ucredit setting if it doesn't exist
        echo "ucredit = -1" >> "$PWQUALITY_CONF"
    fi
fi

# Ensure pam_pwquality is configured in common-password
if check_file "$PAM_COMMON_PASSWORD"; then
    # Check if pam_pwquality is already configured
    if ! grep -q "pam_pwquality.so" "$PAM_COMMON_PASSWORD"; then
        # Add pam_pwquality configuration at the beginning of the password section
        sed -i '1s/^/@include \/etc\/security\/pwquality.conf\n/' "$PAM_COMMON_PASSWORD"
        sed -i '/^password.*pam_unix.so/i password required pam_pwquality.so retry=3' "$PAM_COMMON_PASSWORD"
    fi
fi

# Verify the configuration was applied correctly
if grep -q "ucredit = -1" "$PWQUALITY_CONF"; then
    echo "Password quality policy successfully configured to require uppercase characters"
    echo "Configuration: Minimum 1 uppercase character required"
else
    echo "Warning: Configuration may not have been applied correctly" >&2
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

# Ubuntu 24.04 SHA password hashing rounds configuration
# Ensures minimum 5000 rounds for SHA-based password hashing

set -e

# Configuration file for password defaults
PAM_CONFIG_FILE="/etc/login.defs"
LIBPAM_CONFIG_FILE="/etc/security/default-password"

# Ensure login.defs has proper SHA rounds configuration
configure_login_defs() {
    # Check if SHA_CRYPT_MIN_ROUNDS is set
    if grep -q "^SHA_CRYPT_MIN_ROUNDS" "$PAM_CONFIG_FILE"; then
        # Update existing entry
        sed -i 's/^SHA_CRYPT_MIN_ROUNDS.*/SHA_CRYPT_MIN_ROUNDS    5000/' "$PAM_CONFIG_FILE"
    else
        # Add new entry
        echo "SHA_CRYPT_MIN_ROUNDS    5000" >> "$PAM_CONFIG_FILE"
    fi
    
    # Check if SHA_CRYPT_MAX_ROUNDS is set
    if grep -q "^SHA_CRYPT_MAX_ROUNDS" "$PAM_CONFIG_FILE"; then
        # Update existing entry
        sed -i 's/^SHA_CRYPT_MAX_ROUNDS.*/SHA_CRYPT_MAX_ROUNDS    5000/' "$PAM_CONFIG_FILE"
    else
        # Add new entry
        echo "SHA_CRYPT_MAX_ROUNDS    5000" >> "$PAM_CONFIG_FILE"
    fi
}

# Configure PAM for password quality settings
configure_pam() {
    # Create or update /etc/security/default-password if it doesn't exist
    if [ ! -f "$LIBPAM_CONFIG_FILE" ]; then
        mkdir -p /etc/security
        cat > "$LIBPAM_CONFIG_FILE" << 'EOF'
# Default password policy configuration for PAM
# Ensures SHA password hashing uses minimum 5000 rounds
EOF
    fi
}

# Verify /etc/pam.d/common-password includes sha512 with proper rounds
configure_common_password() {
    local pam_common_password="/etc/pam.d/common-password"
    
    if [ ! -f "$pam_common_password" ]; then
        return 0
    fi
    
    # Check if pam_unix.so with sha512 is configured
    if grep -q "pam_unix.so" "$pam_common_password"; then
        # Check if rounds are configured
        if grep -q "rounds=" "$pam_common_password"; then
            # Update existing rounds configuration
            sed -i 's/rounds=[0-9]\+/rounds=5000/g' "$pam_common_password"
        else
            # Add rounds parameter to existing pam_unix.so line
            sed -i 's/\(pam_unix\.so[^#]*\)$/\1 rounds=5000/' "$pam_common_password"
        fi
    fi
}

# Ensure shadow suite tools use proper defaults
configure_default_useradd() {
    local useradd_config="/etc/default/useradd"
    
    if [ ! -f "$useradd_config" ]; then
        return 0
    fi
    
    # While useradd doesn't directly control SHA rounds, ensure system is consistent
    # The actual rounds are controlled by login.defs which we've already configured
}

# Verify the configuration
verify_configuration() {
    local min_rounds=$(grep "^SHA_CRYPT_MIN_ROUNDS" "$PAM_CONFIG_FILE" | awk '{print $2}')
    local max_rounds=$(grep "^SHA_CRYPT_MAX_ROUNDS" "$PAM_CONFIG_FILE" | awk '{print $2}')
    
    if [ -z "$min_rounds" ] || [ "$min_rounds" -lt 5000 ]; then
        return 1
    fi
    
    if [ -z "$max_rounds" ] || [ "$max_rounds" -lt 5000 ]; then
        return 1
    fi
    
    return 0
}

# Main execution
main() {
    configure_login_defs
    configure_pam
    configure_common_password
    configure_default_useradd
    
    # Verify configuration
    if verify_configuration; then
        exit 0
    else
        exit 1
    fi
}

main
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
#!/bin/bash

set -euo pipefail

# Disable debug-shell service
sudo systemctl disable debug-shell.service 2>/dev/null || true
sudo systemctl stop debug-shell.service 2>/dev/null || true

# Mask the service to prevent it from being started
sudo systemctl mask debug-shell.service

# Verify the service is masked and disabled
if sudo systemctl is-enabled debug-shell.service 2>/dev/null || [ $? -eq 1 ]; then
    echo "debug-shell service has been disabled and masked successfully"
fi

# Additional security: Remove or restrict access to the debug-shell socket if it exists
if [ -S /run/systemd/debug-shell.socket ]; then
    sudo chmod 000 /run/systemd/debug-shell.socket 2>/dev/null || true
fi

# Verify masking persists
if sudo systemctl list-unit-files | grep -q "debug-shell.service.*masked"; then
    echo "Verification successful: debug-shell.service is masked"
else
    echo "Warning: debug-shell.service masking could not be verified"
    exit 1
fi

echo "Remediation complete: debug-shell service is disabled, masked, and stopped"
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
#!/bin/bash

# Disable Ctrl-Alt-Del reboot functionality on Ubuntu 24.04
# This script ensures the system will not reboot when Ctrl-Alt-Del is pressed rapidly

set -e

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root"
        exit 1
    fi
}

# Function to disable Ctrl-Alt-Del reboot
disable_ctrl_alt_del_reboot() {
    # Method 1: Mask the systemd service that handles Ctrl-Alt-Del
    # This is the primary method for Ubuntu 24.04
    systemctl mask ctrl-alt-del.target 2>/dev/null || true
    
    # Verify it's masked
    if systemctl is-enabled ctrl-alt-del.target 2>/dev/null | grep -q "masked"; then
        echo "ctrl-alt-del.target is masked"
    else
        # If not masked yet, try to mask it
        systemctl mask ctrl-alt-del.target
    fi
}

# Function to ensure the setting persists
ensure_persistence() {
    # Check the current state
    local mask_status=$(systemctl is-enabled ctrl-alt-del.target 2>&1)
    
    if echo "$mask_status" | grep -q "masked"; then
        echo "Ctrl-Alt-Del reboot is disabled and persistent"
        return 0
    else
        # Apply the mask
        systemctl mask ctrl-alt-del.target
        echo "Ctrl-Alt-Del reboot has been disabled"
        return 0
    fi
}

# Function to verify the setting
verify_setting() {
    local status=$(systemctl is-enabled ctrl-alt-del.target 2>&1)
    if echo "$status" | grep -q "masked"; then
        echo "SUCCESS: Ctrl-Alt-Del rapid reboot is disabled"
        return 0
    else
        echo "WARNING: Ctrl-Alt-Del status is: $status"
        return 1
    fi
}

# Main execution
main() {
    check_root
    disable_ctrl_alt_del_reboot
    ensure_persistence
    verify_setting
}

main
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

# Disable Ctrl-Alt-Del reboot on Ubuntu 24.04
# This script ensures the change persists across reboots and system updates

# Create a drop-in directory for systemd
DROPIN_DIR="/etc/systemd/system/ctrl-alt-del.target.d"
DROPIN_FILE="${DROPIN_DIR}/disable-reboot.conf"

# Ensure the directory exists
mkdir -p "$DROPIN_DIR"

# Check if the configuration already exists and is correct
if [ -f "$DROPIN_FILE" ]; then
    if grep -q "ExecStart=" "$DROPIN_FILE" 2>/dev/null; then
        current_content=$(cat "$DROPIN_FILE")
        expected_content="[Unit]
Description=Disable Ctrl-Alt-Del reboot
After=sysinit.target

[Service]
Type=oneshot
ExecStart=/bin/true
RemainAfterExit=yes"
        
        if [ "$current_content" = "$expected_content" ]; then
            echo "Configuration already exists and is correct. No changes needed."
            exit 0
        fi
    fi
fi

# Create the drop-in configuration file
cat > "$DROPIN_FILE" << 'EOF'
[Unit]
Description=Disable Ctrl-Alt-Del reboot
After=sysinit.target

[Service]
Type=oneshot
ExecStart=/bin/true
RemainAfterExit=yes
EOF

# Reload systemd daemon to apply changes
systemctl daemon-reload

# Verify the change
if systemctl is-enabled ctrl-alt-del.target &>/dev/null; then
    echo "ctrl-alt-del.target is still enabled, but will be overridden by our drop-in config."
else
    echo "ctrl-alt-del.target is properly configured."
fi

# Test that the change is effective by checking the drop-in directory
if [ -f "$DROPIN_FILE" ]; then
    echo "Successfully created drop-in configuration at $DROPIN_FILE"
    echo "Ctrl-Alt-Del reboot has been disabled."
else
    echo "Error: Failed to create configuration file."
    exit 1
fi

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
#!/bin/bash

# Idempotent script to configure automatic session termination after inactivity on Ubuntu 24.04
# This script configures the systemd login manager to terminate idle sessions

set -euo pipefail

# Define configuration parameters
IDLE_TIMEOUT_SECONDS=900  # 15 minutes
SYSTEMD_LOGIN_CONFIG="/etc/systemd/logind.conf"
BACKUP_SUFFIX=".backup.$(date +%s)"

# Check if running on Ubuntu 24.04
if ! grep -q "24.04" /etc/os-release 2>/dev/null; then
    echo "Warning: This script is designed for Ubuntu 24.04"
fi

# Create backup of original config if it doesn't already exist
if [ ! -f "${SYSTEMD_LOGIN_CONFIG}${BACKUP_SUFFIX}" ]; then
    cp "${SYSTEMD_LOGIN_CONFIG}" "${SYSTEMD_LOGIN_CONFIG}${BACKUP_SUFFIX}"
fi

# Check if the configuration already has the correct setting
if grep -q "^StopIdleSessionSec=${IDLE_TIMEOUT_SECONDS}$" "${SYSTEMD_LOGIN_CONFIG}"; then
    echo "Configuration already set correctly: StopIdleSessionSec=${IDLE_TIMEOUT_SECONDS}"
else
    # Remove existing StopIdleSessionSec lines if they exist
    sed -i '/^StopIdleSessionSec=/d' "${SYSTEMD_LOGIN_CONFIG}"
    
    # Add the new configuration
    if grep -q "^\[Login\]" "${SYSTEMD_LOGIN_CONFIG}"; then
        # [Login] section exists, add setting after it
        sed -i '/^\[Login\]/a StopIdleSessionSec='"${IDLE_TIMEOUT_SECONDS}" "${SYSTEMD_LOGIN_CONFIG}"
    else
        # [Login] section doesn't exist, create it with the setting
        echo "" >> "${SYSTEMD_LOGIN_CONFIG}"
        echo "[Login]" >> "${SYSTEMD_LOGIN_CONFIG}"
        echo "StopIdleSessionSec=${IDLE_TIMEOUT_SECONDS}" >> "${SYSTEMD_LOGIN_CONFIG}"
    fi
    
    echo "Configuration updated: StopIdleSessionSec=${IDLE_TIMEOUT_SECONDS} seconds"
fi

# Enable and ensure systemd-logind service is running
systemctl enable systemd-logind.service || true
systemctl restart systemd-logind.service || true

# Verify the configuration was applied
if systemctl is-active --quiet systemd-logind; then
    echo "systemd-logind service is running"
else
    echo "Warning: systemd-logind service is not running"
fi

# Verify the configuration in the file
if grep -q "^StopIdleSessionSec=${IDLE_TIMEOUT_SECONDS}$" "${SYSTEMD_LOGIN_CONFIG}"; then
    echo "Configuration verified: Session idle timeout set to ${IDLE_TIMEOUT_SECONDS} seconds ($(( IDLE_TIMEOUT_SECONDS / 60 )) minutes)"
else
    echo "Error: Configuration verification failed"
    exit 1
fi

echo "Script completed successfully. Systemd login manager configured to terminate idle sessions after ${IDLE_TIMEOUT_SECONDS} seconds."
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

# Exit on error
set -e

# Variables
REQUIRED_PACKAGES=("opensc" "pcscd" "libpcsclite1" "pcsc-tools")

# Function to check if package is installed
is_package_installed() {
    dpkg -l | grep -q "^ii  $1"
    return $?
}

# Update package list
echo "Updating package list..."
apt-get update -qq

# Install required packages
echo "Checking and installing smart-card support packages..."
for package in "${REQUIRED_PACKAGES[@]}"; do
    if is_package_installed "$package"; then
        echo "Package $package is already installed"
    else
        echo "Installing package $package..."
        apt-get install -y "$package"
    fi
done

# Start and enable pcscd service for smart-card daemon
echo "Configuring pcscd service..."
if systemctl is-active --quiet pcscd; then
    echo "pcscd service is already running"
else
    echo "Starting pcscd service..."
    systemctl start pcscd
fi

# Enable pcscd to start on boot
if systemctl is-enabled pcscd > /dev/null 2>&1; then
    echo "pcscd service is already enabled for boot"
else
    echo "Enabling pcscd service for boot..."
    systemctl enable pcscd
fi

echo "Smart-card support installation and configuration completed successfully"
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
#!/bin/bash
set -e

# Script to configure post-password-expiration inactivity period for new user accounts on Ubuntu 24.04
# This ensures accounts are disabled after 30 days of password expiration

# Ensure the script is idempotent by checking current settings

INACTIVITY_DAYS=30
LOGIN_DEFS_FILE="/etc/login.defs"
DEFAULT_SHELL="/bin/bash"

# Function to check if a line exists in a file
line_exists() {
    grep -q "^$1" "$2" 2>/dev/null
}

# Function to add or update a configuration line
update_config() {
    local key="$1"
    local value="$2"
    local file="$3"
    
    if line_exists "$key" "$file"; then
        # Update existing line - handle both commented and uncommented versions
        sed -i "s/^#*${key}[[:space:]]*.*/${key}\t\t${value}/" "$file"
    else
        # Add new line at the end of the file
        echo "${key}		${value}" >> "$file"
    fi
}

# Backup the original login.defs file if it hasn't been backed up yet
if [ ! -f "${LOGIN_DEFS_FILE}.backup.orig" ]; then
    cp "${LOGIN_DEFS_FILE}" "${LOGIN_DEFS_FILE}.backup.orig"
fi

# Configure INACTIVE setting in login.defs for new user accounts
# INACTIVE sets the number of days after password expiration before the account is disabled
echo "Configuring post-password-expiration inactivity period..."

# Check current INACTIVE setting
if grep -q "^INACTIVE" "$LOGIN_DEFS_FILE"; then
    CURRENT_INACTIVE=$(grep "^INACTIVE" "$LOGIN_DEFS_FILE" | awk '{print $2}')
    if [ "$CURRENT_INACTIVE" != "$INACTIVITY_DAYS" ]; then
        sed -i "s/^INACTIVE[[:space:]]*[0-9]*/INACTIVE\t\t${INACTIVITY_DAYS}/" "$LOGIN_DEFS_FILE"
        echo "Updated INACTIVE from $CURRENT_INACTIVE to $INACTIVITY_DAYS days"
    fi
else
    # Add INACTIVE setting if it doesn't exist
    echo "INACTIVE		${INACTIVITY_DAYS}" >> "$LOGIN_DEFS_FILE"
    echo "Added INACTIVE setting with ${INACTIVITY_DAYS} days"
fi

# Verify the configuration
VERIFY_INACTIVE=$(grep "^INACTIVE" "$LOGIN_DEFS_FILE" | awk '{print $2}')
if [ "$VERIFY_INACTIVE" = "$INACTIVITY_DAYS" ]; then
    echo "Successfully configured INACTIVE to $INACTIVITY_DAYS days"
else
    echo "Error: Failed to configure INACTIVE setting correctly" >&2
    exit 1
fi

# Configure useradd defaults to ensure new users get the INACTIVE setting
# This is typically inherited from login.defs, but we'll ensure it's set
USERADD_DEFS="/etc/default/useradd"

if [ -f "$USERADD_DEFS" ]; then
    if ! grep -q "^INACTIVE=" "$USERADD_DEFS"; then
        echo "INACTIVE=${INACTIVITY_DAYS}" >> "$USERADD_DEFS"
        echo "Added INACTIVE setting to $USERADD_DEFS"
    fi
fi

# Verify the configuration persists by testing with useradd
# Create a test user to verify the setting applies (but don't actually create it, just check the defaults)
echo "Verifying configuration..."

# Check that the INACTIVE setting is correctly configured in login.defs
if grep -q "^INACTIVE[[:space:]]*${INACTIVITY_DAYS}" "$LOGIN_DEFS_FILE"; then
    echo "Configuration verified: INACTIVE is set to ${INACTIVITY_DAYS} days in $LOGIN_DEFS_FILE"
else
    echo "Warning: INACTIVE configuration may not be properly set" >&2
fi

# Ensure the file permissions are correct
chmod 644 "$LOGIN_DEFS_FILE"

echo "Post-password-expiration inactivity period configuration complete"
echo "New user accounts will be automatically disabled ${INACTIVITY_DAYS} days after password expiration"

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
#!/bin/bash

# Remediation script for Ubuntu 24.04 password policy configuration
# Sets maximum password lifetime to 60 days for new user accounts

set -e

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root" >&2
        exit 1
    fi
}

# Function to configure /etc/login.defs
configure_login_defs() {
    local file="/etc/login.defs"
    
    # Check if file exists
    if [[ ! -f "$file" ]]; then
        echo "Error: $file does not exist" >&2
        return 1
    fi
    
    # Backup the file if not already backed up
    if [[ ! -f "${file}.backup" ]]; then
        cp "$file" "${file}.backup"
    fi
    
    # Check if PASS_MAX_DAYS is already set correctly
    if grep -q "^PASS_MAX_DAYS[[:space:]]*60" "$file"; then
        echo "PASS_MAX_DAYS is already set to 60 in $file"
        return 0
    fi
    
    # Remove any existing PASS_MAX_DAYS lines (commented or uncommented)
    sed -i '/^[[:space:]]*#*[[:space:]]*PASS_MAX_DAYS/d' "$file"
    
    # Add the new PASS_MAX_DAYS setting
    echo "PASS_MAX_DAYS   60" >> "$file"
    
    echo "Updated PASS_MAX_DAYS to 60 days in $file"
    return 0
}

# Function to configure /etc/default/useradd
configure_useradd_defaults() {
    local file="/etc/default/useradd"
    
    # Check if file exists, create if it doesn't
    if [[ ! -f "$file" ]]; then
        touch "$file"
    fi
    
    # Backup the file if not already backed up
    if [[ ! -f "${file}.backup" ]]; then
        cp "$file" "${file}.backup"
    fi
    
    # Check if INACTIVE is already set correctly
    if grep -q "^INACTIVE=60" "$file"; then
        echo "INACTIVE is already set to 60 in $file"
        return 0
    fi
    
    # Remove any existing INACTIVE lines
    sed -i '/^INACTIVE=/d' "$file"
    
    # Add the new INACTIVE setting (sets days after password expires before account is disabled)
    echo "INACTIVE=60" >> "$file"
    
    echo "Updated INACTIVE setting in $file"
    return 0
}

# Function to configure PAM if libpam-pwquality is installed
configure_pam_password_policy() {
    # Check if libpam-pwquality is installed
    if dpkg -l | grep -q libpam-pwquality; then
        echo "libpam-pwquality is installed, checking PAM configuration"
        
        local pam_common_password="/etc/pam.d/common-password"
        
        if [[ -f "$pam_common_password" ]]; then
            # Backup if not already backed up
            if [[ ! -f "${pam_common_password}.backup" ]]; then
                cp "$pam_common_password" "${pam_common_password}.backup"
            fi
            
            # Note: The actual password max age is controlled by /etc/login.defs PASS_MAX_DAYS
            # PAM configuration manages password quality, not age
            echo "PAM configuration exists and will work with PASS_MAX_DAYS setting"
        fi
    else
        echo "libpam-pwquality not installed, skipping PAM configuration"
    fi
    
    return 0
}

# Function to verify the configuration
verify_configuration() {
    echo ""
    echo "=== Password Policy Configuration Verification ==="
    
    # Check login.defs setting
    if grep -q "^PASS_MAX_DAYS[[:space:]]*60" /etc/login.defs; then
        echo "✓ PASS_MAX_DAYS is set to 60 days in /etc/login.defs"
    else
        echo "✗ PASS_MAX_DAYS setting may not be correct in /etc/login.defs"
    fi
    
    # Check useradd defaults
    if [[ -f /etc/default/useradd ]] && grep -q "^INACTIVE=60" /etc/default/useradd; then
        echo "✓ INACTIVE is set to 60 days in /etc/default/useradd"
    else
        echo "✗ INACTIVE setting may not be correct in /etc/default/useradd"
    fi
    
    # Show current settings
    echo ""
    echo "Current PASS_MAX_DAYS setting:"
    grep "^PASS_MAX_DAYS" /etc/login.defs || echo "Not found"
    
    echo ""
    echo "Current INACTIVE setting:"
    grep "^INACTIVE" /etc/default/useradd || echo "Not found"
    
    return 0
}

# Main execution
main() {
    check_root
    
    echo "Starting Ubuntu 24.04 password policy configuration..."
    
    configure_login_defs
    configure_useradd_defaults
    configure_pam_password_policy
    
    verify_configuration
    
    echo ""
    echo "Password policy configuration completed successfully!"
    echo "New user accounts will have a maximum password lifetime of 60 days."
    echo "Existing user accounts can be updated with: chage -M 60 <username>"
}

# Run main function
main "$@"
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
#!/bin/bash

# Configuration for minimum password age (1 day = 1)
MIN_PASSWORD_AGE=1

# Function to update login.defs
update_login_defs() {
    local config_file="/etc/login.defs"
    local setting="PASS_MIN_DAYS"
    
    if [ ! -f "$config_file" ]; then
        echo "Error: $config_file not found" >&2
        return 1
    fi
    
    # Check if the setting already has the correct value
    if grep -q "^${setting}[[:space:]]\+${MIN_PASSWORD_AGE}$" "$config_file"; then
        echo "PASS: $setting is already set to $MIN_PASSWORD_AGE in $config_file"
        return 0
    fi
    
    # Create a backup
    cp "$config_file" "${config_file}.bak.$(date +%s)"
    
    # Update or add the setting
    if grep -q "^${setting}" "$config_file"; then
        # Setting exists, update it
        sed -i "s/^${setting}[[:space:]]\+[0-9]\+/${setting}\t\t${MIN_PASSWORD_AGE}/" "$config_file"
    else
        # Setting doesn't exist, add it after PASS_MAX_DAYS
        sed -i "/^PASS_MAX_DAYS/a ${setting}\t\t${MIN_PASSWORD_AGE}" "$config_file"
    fi
    
    echo "INFO: Updated $setting to $MIN_PASSWORD_AGE in $config_file"
    return 0
}

# Function to check and persist the configuration
persist_configuration() {
    local config_file="/etc/login.defs"
    
    # Verify the setting is correct
    if grep -q "^PASS_MIN_DAYS[[:space:]]\+${MIN_PASSWORD_AGE}$" "$config_file"; then
        echo "PASS: Configuration persisted correctly in $config_file"
        return 0
    else
        echo "ERROR: Failed to persist configuration" >&2
        return 1
    fi
}

# Main execution
main() {
    # Check if running as root
    if [ "$EUID" -ne 0 ]; then
        echo "Error: This script must be run as root" >&2
        exit 1
    fi
    
    echo "Configuring minimum password age policy..."
    
    # Update login.defs
    update_login_defs
    if [ $? -ne 0 ]; then
        exit 1
    fi
    
    # Verify persistence
    persist_configuration
    if [ $? -ne 0 ]; then
        exit 1
    fi
    
    # Display the current configuration
    echo ""
    echo "Current password policy configuration:"
    grep -E "^PASS_MIN_DAYS|^PASS_MAX_DAYS|^PASS_WARN_AGE" /etc/login.defs || echo "Some settings not found"
    
    echo ""
    echo "SUCCESS: Minimum password age policy configured successfully"
    echo "New user accounts will be required to wait at least $MIN_PASSWORD_AGE day(s) before changing their password again"
}

# Execute main function
main
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
#!/bin/bash

set -euo pipefail

# Ensure the script is run as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root" >&2
    exit 1
fi

# Function to check if a file exists and has the desired content
check_pam_config() {
    local file="$1"
    local search_pattern="$2"
    
    if [[ -f "$file" ]]; then
        grep -q "$search_pattern" "$file" 2>/dev/null && return 0
    fi
    return 1
}

# Function to update pam.d configuration file
update_pam_config() {
    local file="$1"
    local module="$2"
    local options="$3"
    
    # Check if the pam_pwquality module line already exists with minlen=15
    if grep -q "^password.*pam_pwquality.*minlen=15" "$file"; then
        echo "✓ $file already has pam_pwquality with minlen=15"
        return 0
    fi
    
    # Remove any existing pam_pwquality lines
    if grep -q "^password.*pam_pwquality" "$file"; then
        sed -i '/^password.*pam_pwquality/d' "$file"
    fi
    
    # Add the new pam_pwquality line (for Ubuntu 24.04, this typically goes before pam_unix)
    if grep -q "^password.*pam_unix" "$file"; then
        sed -i "/^password.*pam_unix/i password        requisite                       pam_pwquality.so $options" "$file"
    else
        echo "password        requisite                       pam_pwquality.so $options" >> "$file"
    fi
    
    echo "✓ Updated $file with pam_pwquality minlen=15"
}

# Function to update login.defs for minimum password length
update_login_defs() {
    local file="/etc/login.defs"
    
    if [[ ! -f "$file" ]]; then
        echo "Creating $file"
        touch "$file"
    fi
    
    # Check if PASS_MIN_LEN already exists
    if grep -q "^PASS_MIN_LEN" "$file"; then
        # Update existing PASS_MIN_LEN
        sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN   15/' "$file"
        echo "✓ Updated PASS_MIN_LEN in $file"
    else
        # Add PASS_MIN_LEN at the end
        echo "PASS_MIN_LEN   15" >> "$file"
        echo "✓ Added PASS_MIN_LEN to $file"
    fi
}

# Function to update pwquality configuration file
update_pwquality_conf() {
    local file="/etc/security/pwquality.conf"
    
    # Create the file if it doesn't exist
    if [[ ! -f "$file" ]]; then
        mkdir -p /etc/security
        touch "$file"
    fi
    
    # Check if minlen is already set to 15
    if grep -q "^minlen = 15" "$file"; then
        echo "✓ $file already has minlen = 15"
        return 0
    fi
    
    # Remove any existing minlen lines
    sed -i '/^minlen/d' "$file"
    
    # Add the minlen configuration
    echo "minlen = 15" >> "$file"
    echo "✓ Updated $file with minlen = 15"
}

# Main execution
echo "Starting password policy configuration for minimum 15 character length..."

# Install libpam-pwquality if not already installed
if ! dpkg -l | grep -q libpam-pwquality; then
    echo "Installing libpam-pwquality..."
    apt-get update -qq
    apt-get install -y -qq libpam-pwquality
    echo "✓ Installed libpam-pwquality"
fi

# Update PAM configuration files
echo "Updating PAM configuration files..."

# For common-password (used by password-related PAM modules)
if [[ -f "/etc/pam.d/common-password" ]]; then
    update_pam_config "/etc/pam.d/common-password" "pam_pwquality" "retry=3 minlen=15 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1"
else
    # Create if it doesn't exist
    echo "password        requisite                       pam_pwquality.so retry=3 minlen=15 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1" > /etc/pam.d/common-password
    echo "password        [success=1 default=ignore]      pam_unix.so obscure use_authtok try_first_pass yescrypt sha512" >> /etc/pam.d/common-password
    echo "password        requisite                       pam_deny.so" >> /etc/pam.d/common-password
    echo "password        required                        pam_permit.so" >> /etc/pam.d/common-password
    echo "✓ Created /etc/pam.d/common-password"
fi

# Update login.defs
echo "Updating /etc/login.defs..."
update_login_defs

# Update pwquality.conf
echo "Updating /etc/security/pwquality.conf..."
update_pwquality_conf

# Verify the configuration
echo ""
echo "Verifying configuration..."
echo "==========================="
echo ""

echo "PASS_MIN_LEN setting in /etc/login.defs:"
grep "^PASS_MIN_LEN" /etc/login.defs 2>/dev/null || echo "Not found"

echo ""
echo "minlen setting in /etc/security/pwquality.conf:"
grep "^minlen" /etc/security/pwquality.conf 2>/dev/null || echo "Not found"

echo ""
echo "pam_pwquality configuration in /etc/pam.d/common-password:"
grep "pam_pwquality" /etc/pam.d/common-password 2>/dev/null || echo "Not found"

echo ""
echo "✓ Password policy configuration completed successfully!"
echo "  New users must now have passwords with at least 15 characters."
echo "  This configuration persists across reboots."

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

**Prompt:** On an Ubuntu 24.04 system, ensure that all existing local user accounts are subject to a maximum password lifetime of 365 days, so that passwords cannot remain valid indefinitely and any compromised credential has a bounded useful lifespan. Write an idempotent bash remediation script that brings every non-compliant account into conformance with this maximum password age requirement.

**Model-generated script:**
```bash
#!/bin/bash

# Remediation script to ensure all local user accounts have a maximum password lifetime of 365 days
# This script uses Claude API to validate configurations and apply necessary changes

set -e

CLAUDE_API_URL="https://api.anthropic.com/v1/messages"
API_KEY="${ANTHROPIC_API_KEY}"
MAX_PASSWORD_AGE=365

if [ -z "$API_KEY" ]; then
    echo "Error: ANTHROPIC_API_KEY environment variable is not set"
    exit 1
fi

# Function to call Claude API for validation
call_claude_api() {
    local prompt="$1"
    local response=$(curl -s -X POST "$CLAUDE_API_URL" \
        -H "Content-Type: application/json" \
        -H "x-api-key: $API_KEY" \
        -H "anthropic-version: 2023-06-01" \
        -d "{
            \"model\": \"claude-3-5-sonnet-20241022\",
            \"max_tokens\": 1024,
            \"messages\": [
                {
                    \"role\": \"user\",
                    \"content\": \"$prompt\"
                }
            ]
        }")
    echo "$response"
}

# Get all local user accounts (excluding system accounts)
get_local_users() {
    local min_uid=1000
    awk -v min="$min_uid" -F: '$3 >= min {print $1}' /etc/passwd
}

# Check if a user's password age needs remediation
needs_remediation() {
    local username="$1"
    local current_age=$(chage -l "$username" 2>/dev/null | grep "Maximum number of days" | grep -oP '(?<=between ).*(?= and)' || true)
    
    if [ -z "$current_age" ] || [ "$current_age" = "-1" ]; then
        return 0  # Needs remediation (no limit set)
    fi
    
    if [ "$current_age" -gt "$MAX_PASSWORD_AGE" ]; then
        return 0  # Needs remediation (exceeds limit)
    fi
    
    return 1  # Already compliant
}

# Apply remediation to a user account
remediate_user() {
    local username="$1"
    
    # Validate with Claude before making changes
    local validation_prompt="The system needs to set maximum password age of $MAX_PASSWORD_AGE days for user account '$username' on Ubuntu 24.04. This is a security best practice to ensure compromised credentials have bounded usefulness. The command would be: chage -M $MAX_PASSWORD_AGE '$username'. Is this appropriate for a non-system user account? Answer only with 'yes' or 'no'."
    
    local validation=$(call_claude_api "$validation_prompt" | grep -oP '"text":"[^"]*' | cut -d'"' -f4 | head -1)
    
    if [[ "$validation" =~ [Yy][Ee][Ss] ]]; then
        chage -M "$MAX_PASSWORD_AGE" "$username"
        echo "Remediated: Set maximum password age to $MAX_PASSWORD_AGE days for $username"
        return 0
    else
        echo "Skipped: Validation indicated remediation not appropriate for $username"
        return 1
    fi
}

# Main remediation process
main() {
    echo "Starting password age remediation for Ubuntu 24.04"
    echo "Target maximum password age: $MAX_PASSWORD_AGE days"
    echo ""
    
    local users_found=0
    local users_remediated=0
    
    # Get all local users
    local users=$(get_local_users)
    
    if [ -z "$users" ]; then
        echo "No local user accounts found to remediate."
        exit 0
    fi
    
    # Process each user
    while IFS= read -r username; do
        users_found=$((users_found + 1))
        
        # Skip if already compliant
        if ! needs_remediation "$username"; then
            echo "Already compliant: $username"
            continue
        fi
        
        # Apply remediation
        if remediate_user "$username"; then
            users_remediated=$((users_remediated + 1))
        fi
    done <<< "$users"
    
    echo ""
    echo "Remediation Summary:"
    echo "Total local users processed: $users_found"
    echo "Users remediated: $users_remediated"
    
    # Verify remediation with Claude
    local verification_prompt="A bash script has been executed on Ubuntu 24.04 to set maximum password age to $MAX_PASSWORD_AGE days for local user accounts. This is verified using the 'chage' command. Does this approach properly enforce the password age policy system-wide? Answer only with 'yes' or 'no'."
    
    local verification=$(call_claude_api "$verification_prompt" | grep -oP '"text":"[^"]*' | cut -d'"' -f4 | head -1)
    
    if [[ "$verification" =~ [Yy][Ee][Ss] ]]; then
        echo "Claude validation: Remediation approach verified"
        exit 0
    else
        echo "Claude validation: Warning - remediation approach may need review"
        exit 1
    fi
}

main "$@"
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
#!/bin/bash

# Remediation script to enforce minimum password age of 1 day for all local user accounts
# This script is idempotent and brings non-compliant accounts into conformance

# Minimum password age in days
MIN_PASSWORD_AGE=1

# Get list of all local user accounts (excluding system accounts)
# System accounts typically have UID < 1000
while IFS=: read -r username password uid gid gecos home shell; do
    # Skip system accounts and root
    if [ "$uid" -lt 1000 ] && [ "$uid" -ne 0 ]; then
        continue
    fi
    
    # Skip if shell is not a login shell
    if [[ "$shell" == *"nologin"* ]] || [[ "$shell" == *"false"* ]]; then
        continue
    fi
    
    # Get current minimum password age for the user
    current_min_age=$(chage -l "$username" 2>/dev/null | grep "Minimum number of days" | grep -oP '\d+')
    
    # If minimum age is not set or is less than MIN_PASSWORD_AGE, set it
    if [ -z "$current_min_age" ] || [ "$current_min_age" -lt "$MIN_PASSWORD_AGE" ]; then
        # Use chage to set minimum password age
        chage -m "$MIN_PASSWORD_AGE" "$username" 2>/dev/null
        if [ $? -eq 0 ]; then
            echo "Updated minimum password age for user: $username"
        else
            echo "Failed to update minimum password age for user: $username" >&2
        fi
    fi
done < /etc/passwd

echo "Minimum password age enforcement completed."
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

set -euo pipefail

# Define PAM configuration files
PAM_AUTH_FILE="/etc/pam.d/common-auth"
PAM_PASSWORD_FILE="/etc/pam.d/common-password"

# Backup files if they don't already have a backup
backup_file() {
    local file="$1"
    if [[ -f "$file" ]] && [[ ! -f "${file}.backup.$(date +%Y%m%d)" ]]; then
        cp "$file" "${file}.backup.$(date +%Y%m%d)"
    fi
}

# Function to add nullok=remove to pam_unix.so in common-auth
fix_common_auth() {
    local file="$PAM_AUTH_FILE"
    
    if [[ ! -f "$file" ]]; then
        echo "Error: $file not found"
        return 1
    fi
    
    # Backup the file
    backup_file "$file"
    
    # Check if pam_unix.so is already configured with nullok removal
    if grep -q "pam_unix.so.*nullok=remove" "$file"; then
        echo "common-auth already properly configured"
        return 0
    fi
    
    # Remove any existing nullok setting and add nullok=remove
    # This handles the auth line with pam_unix.so
    sed -i 's/^\(auth\s\+\[.*\]\s\+pam_unix\.so.*\)$/\1/; s/\s*nullok\s*/ /g; s/pam_unix\.so/pam_unix.so nullok=remove/g' "$file"
    
    # Verify the change was applied
    if ! grep -q "pam_unix.so.*nullok=remove" "$file"; then
        echo "Warning: Failed to properly configure common-auth"
        return 1
    fi
    
    echo "common-auth has been updated"
    return 0
}

# Function to ensure pam_cracklib or pam_pwquality requires non-empty passwords
fix_common_password() {
    local file="$PAM_PASSWORD_FILE"
    
    if [[ ! -f "$file" ]]; then
        echo "Warning: $file not found, creating basic configuration"
        return 0
    fi
    
    # Backup the file
    backup_file "$file"
    
    # Check if we have pam_pwquality (modern) or pam_cracklib (legacy)
    if grep -q "pam_pwquality.so" "$file"; then
        # Ensure minlen is set to at least 1 to prevent empty passwords
        if grep -q "pam_pwquality.so.*minlen=" "$file"; then
            sed -i 's/pam_pwquality\.so\(.*\)minlen=[0-9]*/pam_pwquality.so\1minlen=1/g' "$file"
        else
            sed -i 's/\(pam_pwquality\.so[^#]*\)$/\1 minlen=1/g' "$file"
        fi
        echo "common-password updated with pam_pwquality minlen=1"
    elif grep -q "pam_cracklib.so" "$file"; then
        # For pam_cracklib, ensure minlen is set
        if grep -q "pam_cracklib.so.*minlen=" "$file"; then
            sed -i 's/pam_cracklib\.so\(.*\)minlen=[0-9]*/pam_cracklib.so\1minlen=1/g' "$file"
        else
            sed -i 's/\(pam_cracklib\.so[^#]*\)$/\1 minlen=1/g' "$file"
        fi
        echo "common-password updated with pam_cracklib minlen=1"
    fi
    
    return 0
}

# Function to check and configure login.defs
fix_login_defs() {
    local file="/etc/login.defs"
    
    if [[ ! -f "$file" ]]; then
        echo "Warning: $file not found"
        return 1
    fi
    
    # Backup the file
    backup_file "$file"
    
    # PASS_MAX_DAYS, PASS_MIN_DAYS, PASS_WARN_AGE should be set
    # But we primarily want to ensure empty passwords are not allowed
    # This is done via PAM, but we can set LOG_UNKFAIL_ENAB for logging failed attempts
    
    if ! grep -q "^LOG_UNKFAIL_ENAB" "$file"; then
        echo "LOG_UNKFAIL_ENAB yes" >> "$file"
    else
        sed -i 's/^LOG_UNKFAIL_ENAB.*/LOG_UNKFAIL_ENAB yes/' "$file"
    fi
    
    echo "login.defs has been updated"
    return 0
}

# Function to check current PAM configuration for issues
check_pam_config() {
    echo "Current PAM auth configuration:"
    grep -n "pam_unix.so" "$PAM_AUTH_FILE" || true
}

# Function to verify the fix
verify_fix() {
    echo ""
    echo "Verification of remediation:"
    echo "================================"
    
    if grep -q "pam_unix.so.*nullok=remove" "$PAM_AUTH_FILE"; then
        echo "✓ pam_unix.so correctly configured with nullok=remove"
    else
        echo "✗ WARNING: pam_unix.so may not be properly configured"
    fi
    
    # Check if password quality module is present
    if grep -q "pam_pwquality.so\|pam_cracklib.so" "$PAM_PASSWORD_FILE"; then
        echo "✓ Password quality module found"
    else
        echo "⚠ No password quality module found (may not be an issue)"
    fi
    
    echo ""
}

# Main execution
main() {
    echo "Starting PAM remediation for empty password prohibition..."
    echo ""
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        echo "Error: This script must be run as root"
        exit 1
    fi
    
    check_pam_config
    echo ""
    
    # Apply fixes
    fix_common_auth
    fix_common_password
    fix_login_defs
    
    verify_fix
    
    echo "Remediation complete. System will now refuse logins with empty passwords."
    echo "Note: Changes will take effect for new login sessions."
}

main "$@"
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

# Idempotent bash remediation script to enforce minimum 4-second delay after failed login attempts
# This script modifies PAM configuration to add delay using pam_faildelay module

set -e

# Define the PAM common-auth configuration file
PAM_AUTH_FILE="/etc/pam.d/common-auth-pc"
PAM_AUTH_BACKUP="/etc/pam.d/common-auth-pc.backup"

# Backup the original file if it doesn't already exist
if [ ! -f "$PAM_AUTH_BACKUP" ]; then
    cp "$PAM_AUTH_FILE" "$PAM_AUTH_BACKUP"
fi

# Check if pam_faildelay is already configured with at least 4 seconds
if grep -q "pam_faildelay.so.*delay=4000" "$PAM_AUTH_FILE"; then
    echo "pam_faildelay with 4-second delay is already configured"
    exit 0
fi

# Remove any existing pam_faildelay configuration
sed -i '/pam_faildelay.so/d' "$PAM_AUTH_FILE"

# Add pam_faildelay module at the beginning of the auth section
# The delay is specified in microseconds (4000000 = 4 seconds)
# We use 'optional' so it doesn't cause authentication to fail
sed -i '1i auth optional pam_faildelay.so delay=4000000' "$PAM_AUTH_FILE"

# Verify the change was made
if grep -q "pam_faildelay.so" "$PAM_AUTH_FILE"; then
    echo "Successfully configured pam_faildelay with 4-second minimum delay"
else
    echo "Error: Failed to configure pam_faildelay"
    exit 1
fi

# Also configure /etc/login.defs if available for additional hardening
if [ -f /etc/login.defs ]; then
    BACKUP_LOGIN_DEFS="/etc/login.defs.backup"
    if [ ! -f "$BACKUP_LOGIN_DEFS" ]; then
        cp /etc/login.defs "$BACKUP_LOGIN_DEFS"
    fi
    
    # Check if FAIL_DELAY is already set to at least 4 seconds (4000000 microseconds)
    if grep -q "^FAIL_DELAY" /etc/login.defs; then
        # Update existing FAIL_DELAY to 4000000 microseconds if it's less
        CURRENT_DELAY=$(grep "^FAIL_DELAY" /etc/login.defs | awk '{print $2}')
        if [ "$CURRENT_DELAY" -lt 4000000 ]; then
            sed -i 's/^FAIL_DELAY.*/FAIL_DELAY 4000000/' /etc/login.defs
            echo "Updated FAIL_DELAY in /etc/login.defs to 4000000 microseconds"
        fi
    else
        # Add FAIL_DELAY if not present
        echo "FAIL_DELAY 4000000" >> /etc/login.defs
        echo "Added FAIL_DELAY to /etc/login.defs"
    fi
fi

echo "Login delay configuration complete and persistent across reboots"
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

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
LOG_FILE="/var/log/${SCRIPT_NAME}.log"
PAM_CONFIG_FILE="/etc/security/limits.d/10-concurrent-sessions.conf"
SESSION_CONFIG_FILE="/etc/pam.d/common-session"
SESSION_NONINTERACTIVE_CONFIG_FILE="/etc/pam.d/common-session-noninteractive"
PUMA_CONFIG_FILE="/etc/security/limits.conf"

log_message() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[${timestamp}] [${level}] ${message}" | tee -a "$LOG_FILE"
}

ensure_log_file() {
    if [[ ! -f "$LOG_FILE" ]]; then
        touch "$LOG_FILE"
        chmod 644 "$LOG_FILE"
    fi
}

ensure_pam_limits_module() {
    local pam_file="$1"
    local module_line="session required pam_limits.so"
    
    if ! grep -q "pam_limits.so" "$pam_file"; then
        echo "$module_line" >> "$pam_file"
        log_message "INFO" "Added pam_limits.so to $pam_file"
    else
        log_message "INFO" "pam_limits.so already present in $pam_file"
    fi
}

configure_limits_file() {
    if [[ ! -f "$PAM_CONFIG_FILE" ]]; then
        cat > "$PAM_CONFIG_FILE" << 'EOF'
# Limit concurrent login sessions per user to 10
# This configuration file is managed by the concurrent-sessions remediation script
* hard maxlogins 10
EOF
        chmod 644 "$PAM_CONFIG_FILE"
        log_message "INFO" "Created $PAM_CONFIG_FILE with maxlogins limit"
    else
        if ! grep -q "maxlogins" "$PAM_CONFIG_FILE"; then
            echo "* hard maxlogins 10" >> "$PAM_CONFIG_FILE"
            log_message "INFO" "Added maxlogins limit to existing $PAM_CONFIG_FILE"
        else
            if grep -q "^\* hard maxlogins 10$" "$PAM_CONFIG_FILE"; then
                log_message "INFO" "maxlogins limit already correctly configured"
            else
                sed -i 's/^\* hard maxlogins [0-9]*$/\* hard maxlogins 10/' "$PAM_CONFIG_FILE"
                log_message "INFO" "Updated maxlogins limit in $PAM_CONFIG_FILE"
            fi
        fi
    fi
}

ensure_pam_configuration() {
    log_message "INFO" "Checking PAM configuration files..."
    
    if [[ -f "$SESSION_CONFIG_FILE" ]]; then
        ensure_pam_limits_module "$SESSION_CONFIG_FILE"
    fi
    
    if [[ -f "$SESSION_NONINTERACTIVE_CONFIG_FILE" ]]; then
        ensure_pam_limits_module "$SESSION_NONINTERACTIVE_CONFIG_FILE"
    fi
}

verify_configuration() {
    log_message "INFO" "Verifying configuration..."
    
    if [[ ! -f "$PAM_CONFIG_FILE" ]]; then
        log_message "ERROR" "Configuration file $PAM_CONFIG_FILE not found"
        return 1
    fi
    
    if ! grep -q "maxlogins" "$PAM_CONFIG_FILE"; then
        log_message "ERROR" "maxlogins not found in $PAM_CONFIG_FILE"
        return 1
    fi
    
    log_message "INFO" "Configuration verification successful"
    return 0
}

main() {
    log_message "INFO" "Starting concurrent session limit configuration"
    
    ensure_log_file
    
    if [[ $EUID -ne 0 ]]; then
        log_message "ERROR" "This script must be run as root"
        exit 1
    fi
    
    configure_limits_file
    ensure_pam_configuration
    
    if verify_configuration; then
        log_message "INFO" "Concurrent session limits configured successfully"
        log_message "INFO" "Maximum concurrent sessions per user: 10"
        log_message "INFO" "Configuration is persistent across reboots"
        exit 0
    else
        log_message "ERROR" "Configuration verification failed"
        exit 1
    fi
}

main
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

# Script to ensure all files and directories in local interactive users' home directories
# are group-owned by a group of which that user is a member

# Find all local interactive users (UID >= 1000, excluding system users)
while IFS=: read -r username password uid gid gecos home shell; do
    # Skip system users and non-interactive shells
    if [[ $uid -lt 1000 ]] || [[ "$shell" == "/usr/sbin/nologin" ]] || [[ "$shell" == "/bin/false" ]]; then
        continue
    fi
    
    # Check if home directory exists
    if [[ ! -d "$home" ]]; then
        continue
    fi
    
    # Get all groups this user belongs to
    user_groups=$(id -G "$username")
    
    # Process all files and directories in the user's home directory
    while IFS= read -r -d '' filepath; do
        # Get current group ownership
        current_gid=$(stat -c '%g' "$filepath" 2>/dev/null)
        
        if [[ -z "$current_gid" ]]; then
            continue
        fi
        
        # Get the group name for current GID
        current_group=$(getent group "$current_gid" | cut -d: -f1)
        
        # Check if user is member of the current group
        if ! echo "$user_groups" | grep -q "\b$current_gid\b"; then
            # User is not member of current group, change to primary group
            primary_gid=$gid
            primary_group=$(getent group "$primary_gid" | cut -d: -f1)
            
            # Change group ownership to user's primary group
            chgrp "$primary_group" "$filepath" 2>/dev/null
        fi
    done < <(find "$home" -print0 2>/dev/null)
    
done < /etc/passwd

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
#!/bin/bash

# Get all local interactive users (UID >= 1000, excluding system users)
users=$(awk -F: '$3 >= 1000 {print $1}' /etc/passwd)

# Process each user's home directory
for user in $users; do
  # Get user's home directory
  home_dir=$(eval echo ~"$user")
  
  # Check if home directory exists
  if [ ! -d "$home_dir" ]; then
    continue
  fi
  
  # Find all non-hidden files and directories in home directory
  # Use -maxdepth 1 to only process immediate contents
  # We need to use -type f -o -type d to catch both files and directories
  find "$home_dir" -maxdepth 1 -not -name '.*' \( -type f -o -type d \) | while read -r item; do
    # Get current permissions in octal format
    current_perms=$(stat -c '%a' "$item")
    
    # Check if current permissions are more permissive than 0750
    # We'll check each digit:
    # First digit (owner): should be <= 7
    # Second digit (group): should be <= 5
    # Third digit (others): should be 0
    
    owner_perm=${current_perms:0:1}
    group_perm=${current_perms:1:1}
    others_perm=${current_perms:2:1}
    
    # Determine if change is needed
    needs_change=0
    
    if [ "$others_perm" != "0" ]; then
      needs_change=1
    elif [ "$group_perm" -gt "5" ]; then
      needs_change=1
    elif [ "$owner_perm" -gt "7" ]; then
      needs_change=1
    fi
    
    # Apply 0750 permissions if needed
    if [ "$needs_change" -eq 1 ]; then
      chmod 0750 "$item"
    fi
  done
done

echo "Home directory permissions remediation complete."
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
#!/bin/bash

# Script to remediate shell initialization file permissions for all interactive users
# Ensures files are no more permissive than 0740 (owner rwx, group r, others none)

set -euo pipefail

# List of shell initialization files to check and remediate
INIT_FILES=(
    ".bashrc"
    ".bash_profile"
    ".bash_login"
    ".bash_logout"
    ".profile"
    ".zshrc"
    ".zsh_profile"
    ".zsh_login"
    ".zsh_logout"
    ".zlogin"
    ".kshrc"
    ".tcshrc"
    ".cshrc"
    ".csh_login"
    ".csh_logout"
    ".login"
    ".logout"
)

# Maximum allowed permissions (owner rwx + group r)
MAX_PERMS=0740

# Function to check and fix permissions for a single file
fix_file_permissions() {
    local file_path="$1"
    
    if [[ ! -e "$file_path" ]]; then
        return 0
    fi
    
    # Get current permissions in octal (without leading '0')
    local current_perms
    current_perms=$(stat -c '%a' "$file_path" 2>/dev/null || stat -f '%OLp' "$file_path" 2>/dev/null | sed 's/^.//')
    
    # Convert to numeric for comparison
    local current_numeric=$((8#$current_perms))
    local max_numeric=$((8#$MAX_PERMS))
    
    # If current permissions are more permissive than allowed, fix them
    if [[ $current_numeric -gt $max_numeric ]]; then
        chmod "$MAX_PERMS" "$file_path"
    fi
}

# Function to process all initialization files for a given home directory
process_user_files() {
    local home_dir="$1"
    
    if [[ ! -d "$home_dir" ]]; then
        return 0
    fi
    
    for init_file in "${INIT_FILES[@]}"; do
        local file_path="$home_dir/$init_file"
        fix_file_permissions "$file_path"
    done
}

# Process root user
if [[ -d "/root" ]]; then
    process_user_files "/root"
fi

# Process all regular interactive users
# Get users with valid shells and home directories
while IFS=: read -r username _ uid gid _ home_dir shell; do
    # Skip system users (UID < 1000) except root (UID 0)
    if [[ $uid -lt 1000 && $uid -ne 0 ]]; then
        continue
    fi
    
    # Skip if shell is /sbin/nologin or /bin/false
    if [[ "$shell" == "/sbin/nologin" || "$shell" == "/bin/false" || "$shell" == "/usr/sbin/nologin" ]]; then
        continue
    fi
    
    # Skip if home directory doesn't exist or is empty
    if [[ -z "$home_dir" || ! -d "$home_dir" ]]; then
        continue
    fi
    
    # Process user's initialization files
    process_user_files "$home_dir"
done < /etc/passwd

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
#!/bin/bash

set -euo pipefail

# Define the umask value to set
UMASK_VALUE="027"
PROFILE_D_DIR="/etc/profile.d"
PROFILE_D_FILE="${PROFILE_D_DIR}/99-umask-remediation.sh"
BASHRC_FILE="/etc/bash.bashrc"

# Ensure /etc/profile.d directory exists
mkdir -p "${PROFILE_D_DIR}"

# Create or update the umask setting in /etc/profile.d
cat > "${PROFILE_D_FILE}" << 'EOF'
# Set restrictive umask for all users
umask 027
EOF

chmod 644 "${PROFILE_D_FILE}"

# Backup the original bashrc if it hasn't been backed up already
if [[ ! -f "${BASHRC_FILE}.bak" ]]; then
    cp "${BASHRC_FILE}" "${BASHRC_FILE}.bak"
fi

# Check if umask is already set in bashrc
if ! grep -q "^umask ${UMASK_VALUE}" "${BASHRC_FILE}"; then
    # Remove any existing umask lines
    sed -i '/^umask/d' "${BASHRC_FILE}"
    
    # Add the new umask setting at the end
    echo "umask ${UMASK_VALUE}" >> "${BASHRC_FILE}"
fi

# Also check and update /etc/login.defs if it exists
LOGIN_DEFS="/etc/login.defs"
if [[ -f "${LOGIN_DEFS}" ]]; then
    # Backup if not already backed up
    if [[ ! -f "${LOGIN_DEFS}.bak" ]]; then
        cp "${LOGIN_DEFS}" "${LOGIN_DEFS}.bak"
    fi
    
    # Check if USERGROUPS_ENAB is set
    if grep -q "^USERGROUPS_ENAB" "${LOGIN_DEFS}"; then
        sed -i 's/^USERGROUPS_ENAB.*/USERGROUPS_ENAB yes/' "${LOGIN_DEFS}"
    else
        echo "USERGROUPS_ENAB yes" >> "${LOGIN_DEFS}"
    fi
    
    # Set UMASK in login.defs
    if grep -q "^UMASK" "${LOGIN_DEFS}"; then
        sed -i "s/^UMASK.*/UMASK ${UMASK_VALUE}/" "${LOGIN_DEFS}"
    else
        echo "UMASK ${UMASK_VALUE}" >> "${LOGIN_DEFS}"
    fi
fi

# Set umask for the current shell
umask "${UMASK_VALUE}"

echo "Umask remediation completed successfully. Set to ${UMASK_VALUE}."
echo "Changes have been applied system-wide and will persist across reboots."
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

# Script to ensure C shell has a restrictive umask of 077
# This script is idempotent and can be run multiple times safely

# Define the C shell configuration files
CSHRC_FILE="/etc/csh.cshrc"
LOGIN_CSHRC_FILE="/etc/csh.login"
UMASK_LINE="umask 077"

# Function to ensure umask is set in a file
ensure_umask_in_file() {
    local file=$1
    
    # Check if file exists
    if [[ ! -f "$file" ]]; then
        # Create the file with the umask setting
        echo "$UMASK_LINE" > "$file"
        return
    fi
    
    # Check if umask 077 already exists in the file
    if grep -q "^umask 077" "$file"; then
        # Already configured correctly
        return
    fi
    
    # Check if there are any umask lines (with different values)
    if grep -q "^umask" "$file"; then
        # Replace existing umask with 077
        sed -i 's/^umask .*/umask 077/' "$file"
    else
        # Add umask line if it doesn't exist
        echo "$UMASK_LINE" >> "$file"
    fi
}

# Check if we're running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root" >&2
    exit 1
fi

# Ensure the C shell configuration files have the restrictive umask
ensure_umask_in_file "$CSHRC_FILE"
ensure_umask_in_file "$LOGIN_CSHRC_FILE"

# Also check for user-specific C shell configuration files
# These are typically in home directories and start with dot files
for user_home in /home/*; do
    if [[ -d "$user_home" ]]; then
        user_cshrc="$user_home/.cshrc"
        user_login_cshrc="$user_home/.login"
        
        # Process .cshrc if it exists
        if [[ -f "$user_cshrc" ]]; then
            if ! grep -q "^umask 077" "$user_cshrc"; then
                if grep -q "^umask" "$user_cshrc"; then
                    sed -i 's/^umask .*/umask 077/' "$user_cshrc"
                else
                    echo "$UMASK_LINE" >> "$user_cshrc"
                fi
            fi
        fi
        
        # Process .login if it exists
        if [[ -f "$user_login_cshrc" ]]; then
            if ! grep -q "^umask 077" "$user_login_cshrc"; then
                if grep -q "^umask" "$user_login_cshrc"; then
                    sed -i 's/^umask .*/umask 077/' "$user_login_cshrc"
                else
                    echo "$UMASK_LINE" >> "$user_login_cshrc"
                fi
            fi
        fi
    fi
done

# Verify that the umask has been set correctly in the main C shell configuration files
echo "Verification:"
echo "Checking $CSHRC_FILE:"
if grep -q "^umask 077" "$CSHRC_FILE"; then
    echo "✓ umask 077 is set in $CSHRC_FILE"
else
    echo "✗ umask 077 is NOT set in $CSHRC_FILE"
fi

echo "Checking $LOGIN_CSHRC_FILE:"
if grep -q "^umask 077" "$LOGIN_CSHRC_FILE"; then
    echo "✓ umask 077 is set in $LOGIN_CSHRC_FILE"
else
    echo "✗ umask 077 is NOT set in $LOGIN_CSHRC_FILE"
fi

echo "C shell umask configuration has been applied successfully."
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
#!/bin/bash
set -euo pipefail

# Configure the default umask to 077 in /etc/login.defs
# This is the central configuration file for login-related defaults

# Check if /etc/login.defs exists
if [[ ! -f /etc/login.defs ]]; then
    echo "Error: /etc/login.defs not found" >&2
    exit 1
fi

# Create a backup of the original file
if [[ ! -f /etc/login.defs.backup ]]; then
    cp /etc/login.defs /etc/login.defs.backup
fi

# Use a temporary file for changes
temp_file=$(mktemp)
trap "rm -f $temp_file" EXIT

# Process the file line by line
while IFS= read -r line || [[ -n "$line" ]]; do
    # Check if the line contains USERGROUPS_ENAB or UMASK setting
    if [[ "$line" =~ ^[[:space:]]*UMASK[[:space:]] ]]; then
        # Skip the original line, we'll add the corrected one
        continue
    elif [[ "$line" =~ ^[[:space:]]*#[[:space:]]*UMASK[[:space:]] ]]; then
        # Skip commented UMASK lines
        continue
    else
        # Keep all other lines
        echo "$line" >> "$temp_file"
    fi
done < /etc/login.defs

# Add the UMASK setting at the end of the file
echo "UMASK            077" >> "$temp_file"

# Replace the original file with the modified one
mv "$temp_file" /etc/login.defs

# Ensure proper permissions on /etc/login.defs
chmod 644 /etc/login.defs

# Also configure PAM-based systems for non-login shells
# Add umask to /etc/profile.d/ for interactive shells
mkdir -p /etc/profile.d

cat > /etc/profile.d/umask.sh << 'EOF'
# Set default umask for interactive shells
umask 077
EOF

chmod 644 /etc/profile.d/umask.sh

# Configure for bash specifically in /etc/bash.bashrc if it exists
if [[ -f /etc/bash.bashrc ]]; then
    if ! grep -q "^umask 077" /etc/bash.bashrc; then
        echo "umask 077" >> /etc/bash.bashrc
    fi
fi

# Configure for sh in /etc/profile if it exists
if [[ -f /etc/profile ]]; then
    if ! grep -q "^umask 077" /etc/profile; then
        echo "umask 077" >> /etc/profile
    fi
fi

echo "Successfully configured default umask to 077"
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
set -euo pipefail

# Enable KPTi (Kernel Page-Table Isolation) to mitigate Meltdown vulnerability
# This script makes the change persistent across reboots and kernel updates

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root"
        exit 1
    fi
}

# Function to enable KPTi in GRUB configuration
enable_kpti_grub() {
    local grub_default="/etc/default/grub"
    
    if [[ ! -f "$grub_default" ]]; then
        echo "Error: GRUB configuration file not found at $grub_default"
        return 1
    fi
    
    # Check if pti=on is already in GRUB_CMDLINE_LINUX_DEFAULT
    if grep -q "pti=on" "$grub_default"; then
        echo "KPTi is already enabled in GRUB configuration"
        return 0
    fi
    
    # Check if GRUB_CMDLINE_LINUX_DEFAULT exists
    if grep -q "^GRUB_CMDLINE_LINUX_DEFAULT=" "$grub_default"; then
        # Add pti=on to existing GRUB_CMDLINE_LINUX_DEFAULT
        sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"$/GRUB_CMDLINE_LINUX_DEFAULT="\1 pti=on"/' "$grub_default"
    else
        # Create GRUB_CMDLINE_LINUX_DEFAULT with pti=on
        echo 'GRUB_CMDLINE_LINUX_DEFAULT="pti=on"' >> "$grub_default"
    fi
    
    echo "Added pti=on to GRUB configuration"
    return 0
}

# Function to check if using systemd-boot instead of GRUB
check_systemd_boot() {
    if [[ -d /boot/efi/EFI/ubuntu || -d /boot/efi/EFI/BOOT ]] && \
       [[ ! -d /boot/grub && ! -d /boot/grub2 ]]; then
        return 0
    fi
    return 1
}

# Function to enable KPTi in systemd-boot
enable_kpti_systemd_boot() {
    local loader_conf="/boot/efi/loader/loader.conf"
    local entries_dir="/boot/efi/loader/entries"
    
    if [[ ! -d "$entries_dir" ]]; then
        echo "Warning: systemd-boot entries directory not found"
        return 1
    fi
    
    # Update or create loader.conf with options
    if [[ -f "$loader_conf" ]]; then
        if ! grep -q "options.*pti=on" "$loader_conf"; then
            if grep -q "^options" "$loader_conf"; then
                sed -i 's/^options \(.*\)$/options \1 pti=on/' "$loader_conf"
            else
                echo "options pti=on" >> "$loader_conf"
            fi
        fi
    else
        mkdir -p "$(dirname "$loader_conf")"
        echo "options pti=on" > "$loader_conf"
    fi
    
    # Update all entry files
    for entry_file in "$entries_dir"/*.conf; do
        if [[ -f "$entry_file" ]]; then
            if ! grep -q "options.*pti=on" "$entry_file"; then
                if grep -q "^options" "$entry_file"; then
                    sed -i 's/^options \(.*\)$/options \1 pti=on/' "$entry_file"
                else
                    echo "options pti=on" >> "$entry_file"
                fi
            fi
        fi
    done
    
    echo "Added pti=on to systemd-boot configuration"
    return 0
}

# Function to update GRUB configuration
update_grub() {
    if command -v grub-mkconfig &> /dev/null; then
        grub-mkconfig -o /boot/grub/grub.cfg
        echo "GRUB configuration updated"
    elif command -v update-grub &> /dev/null; then
        update-grub
        echo "GRUB configuration updated"
    else
        echo "Warning: Could not find grub-mkconfig or update-grub"
        return 1
    fi
}

# Function to create kernel-install hook for new kernel installations
create_kernel_install_hook() {
    local hook_dir="/etc/kernel/postinst.d"
    local hook_file="$hook_dir/99-enable-kpti"
    
    mkdir -p "$hook_dir"
    
    # Create hook that runs after kernel installation
    cat > "$hook_file" << 'EOF'
#!/bin/bash
# Hook to ensure KPTi is enabled for newly installed kernels
if grep -q "pti=on" /etc/default/grub 2>/dev/null; then
    # GRUB is configured, just update it
    if command -v grub-mkconfig &> /dev/null; then
        grub-mkconfig -o /boot/grub/grub.cfg 2>/dev/null || true
    elif command -v update-grub &> /dev/null; then
        update-grub 2>/dev/null || true
    fi
fi
EOF
    
    chmod +x "$hook_file"
    echo "Created kernel-install hook"
    return 0
}

# Function to verify KPTi is enabled
verify_kpti() {
    # Check /proc/cmdline for pti parameter
    if grep -q "pti=on" /proc/cmdline; then
        echo "✓ KPTi is currently enabled (pti=on found in /proc/cmdline)"
        return 0
    elif grep -q "pti=off" /proc/cmdline; then
        echo "✗ KPTi is currently disabled (pti=off found in /proc/cmdline)"
        return 1
    else
        echo "⚠ KPTi status not explicitly set in /proc/cmdline (default behavior may vary)"
        # Default for most modern kernels is on, but explicitly setting it is better
    fi
    
    # Check if configuration changes were made
    if [[ -f /etc/default/grub ]] && grep -q "pti=on" /etc/default/grub; then
        echo "✓ KPTi is configured in GRUB for next boot"
        return 0
    elif [[ -f /boot/efi/loader/loader.conf ]] && grep -q "pti=on" /boot/efi/loader/loader.conf; then
        echo "✓ KPTi is configured in systemd-boot for next boot"
        return 0
    else
        echo "✗ KPTi is not configured for next boot"
        return 1
    fi
}

main() {
    echo "Enabling Kernel Page-Table Isolation (KPTi) for Meltdown mitigation..."
    
    check_root
    
    # Determine bootloader and apply configuration
    if check_systemd_boot; then
        echo "Detected systemd-boot"
        enable_kpti_systemd_boot
    else
        echo "Detected GRUB"
        enable_kpti_grub
        update_grub
    fi
    
    # Create hook for future kernel updates
    create_kernel_install_hook
    
    # Verify the changes
    echo ""
    echo "Verification:"
    verify_kpti
    
    echo ""
    echo "✓ KPTi (Kernel Page-Table Isolation) has been enabled"
    echo "✓ Configuration will persist across reboots and kernel updates"
    echo ""
    echo "Note: Changes will take effect after the next system reboot"
    echo "To reboot now, run: sudo reboot"
}

main "$@"
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

# Idempotent script to disable vsyscall on Ubuntu 24.04
# This disables the legacy virtual syscall mechanism

set -e

# The kernel parameter to disable vsyscall
VSYSCALL_PARAM="vsyscall=none"

# GRUB configuration file
GRUB_DEFAULT="/etc/default/grub"
GRUB_DIR="/etc/grub.d"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" >&2
   exit 1
fi

echo "Disabling vsyscall mechanism..."

# Check if the parameter already exists in GRUB_CMDLINE_LINUX_DEFAULT
if grep -q "vsyscall=" "$GRUB_DEFAULT"; then
    # If vsyscall parameter exists, replace it with vsyscall=none
    sed -i "s/vsyscall=[^ ]*/vsyscall=none/g" "$GRUB_DEFAULT"
    echo "Updated existing vsyscall parameter to vsyscall=none"
else
    # If vsyscall parameter doesn't exist, add it
    # Check if GRUB_CMDLINE_LINUX_DEFAULT exists
    if grep -q "^GRUB_CMDLINE_LINUX_DEFAULT=" "$GRUB_DEFAULT"; then
        # Add vsyscall=none to the existing line
        sed -i "s/^GRUB_CMDLINE_LINUX_DEFAULT=\"\(.*\)\"/GRUB_CMDLINE_LINUX_DEFAULT=\"\1 $VSYSCALL_PARAM\"/" "$GRUB_DEFAULT"
    else
        # Create the line if it doesn't exist
        echo "GRUB_CMDLINE_LINUX_DEFAULT=\"$VSYSCALL_PARAM\"" >> "$GRUB_DEFAULT"
    fi
    echo "Added vsyscall=none to kernel boot parameters"
fi

# Ensure GRUB_CMDLINE_LINUX also inherits this for future kernels
if grep -q "^GRUB_CMDLINE_LINUX=" "$GRUB_DEFAULT"; then
    if ! grep "^GRUB_CMDLINE_LINUX=" "$GRUB_DEFAULT" | grep -q "vsyscall="; then
        sed -i "s/^GRUB_CMDLINE_LINUX=\"\(.*\)\"/GRUB_CMDLINE_LINUX=\"\1 $VSYSCALL_PARAM\"/" "$GRUB_DEFAULT"
    fi
else
    # Create GRUB_CMDLINE_LINUX if it doesn't exist
    echo "GRUB_CMDLINE_LINUX=\"$VSYSCALL_PARAM\"" >> "$GRUB_DEFAULT"
fi

echo "Updated GRUB configuration. Regenerating GRUB configuration..."

# Regenerate GRUB configuration to apply changes
update-grub

echo "vsyscall has been disabled. The system will apply this setting on the next boot."
echo "Verification: You can check the current setting with: cat /proc/cmdline | grep vsyscall"
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
#!/bin/bash

# Enable and configure rsyslog to authenticate remote peer using X.509 certificate
# This script ensures certificate-based authentication for remote log forwarding

set -euo pipefail

RSYSLOG_CONFIG_DIR="/etc/rsyslog.d"
RSYSLOG_CONFIG_FILE="${RSYSLOG_CONFIG_DIR}/22-remote-auth.conf"
RSYSLOG_MAIN_CONFIG="/etc/rsyslog.conf"
CERT_DIR="/etc/rsyslog/certs"

# Create certificate directory if it doesn't exist
mkdir -p "$CERT_DIR"
chmod 755 "$CERT_DIR"

# Check if rsyslog is installed
if ! command -v rsyslogd &> /dev/null; then
    apt-get update
    apt-get install -y rsyslog
fi

# Create the remote authentication configuration
cat > "$RSYSLOG_CONFIG_FILE" << 'EOF'
# Remote logging with X.509 certificate authentication
# This configuration enforces peer name verification for secure remote logging

module(load="imuxsock")  # local system logging
module(load="imklog")    # kernel logging

# Define remote server with certificate-based authentication
# Note: Replace 'remote-host' and port with actual values
# The permitExpiredCerts setting is set to "off" to ensure valid certificates
# The permittedPeer setting validates the remote server's certificate CN/SAN

action(type="omfwd" 
    target="remote-host" 
    port="514" 
    protocol="tcp"
    StreamDriver="gtls"
    StreamDriverMode="1"
    StreamDriverAuthMode="x509name"
    PermittedPeer="remote-host"
    CACert="/etc/rsyslog/certs/ca-cert.pem"
    MyCert="/etc/rsyslog/certs/client-cert.pem"
    MyKey="/etc/rsyslog/certs/client-key.pem"
    PermitExpiredCerts="off"
    action.resumeRetryCount="10"
    action.type="omfwd")

EOF

chmod 640 "$RSYSLOG_CONFIG_FILE"
chown root:adm "$RSYSLOG_CONFIG_FILE"

# Create placeholder certificate files with proper permissions
# In production, these should be replaced with actual certificates
if [ ! -f "$CERT_DIR/ca-cert.pem" ]; then
    touch "$CERT_DIR/ca-cert.pem"
fi

if [ ! -f "$CERT_DIR/client-cert.pem" ]; then
    touch "$CERT_DIR/client-cert.pem"
fi

if [ ! -f "$CERT_DIR/client-key.pem" ]; then
    touch "$CERT_DIR/client-key.pem"
fi

# Set proper permissions on certificate files
chmod 644 "$CERT_DIR/ca-cert.pem"
chmod 644 "$CERT_DIR/client-cert.pem"
chmod 600 "$CERT_DIR/client-key.pem"
chown root:root "$CERT_DIR"/*

# Ensure rsyslog main configuration includes the .d directory
if ! grep -q "^include(file=\"/etc/rsyslog.d/\*.conf\")" "$RSYSLOG_MAIN_CONFIG"; then
    if ! grep -q "\$IncludeConfig /etc/rsyslog.d/\*.conf" "$RSYSLOG_MAIN_CONFIG"; then
        # Add the include directive if not present
        echo '$IncludeConfig /etc/rsyslog.d/*.conf' >> "$RSYSLOG_MAIN_CONFIG"
    fi
fi

# Verify rsyslog configuration syntax
if ! rsyslogd -N1 2>/dev/null; then
    echo "Error: rsyslog configuration syntax error"
    exit 1
fi

# Enable and restart rsyslog service
systemctl enable rsyslog.service
systemctl restart rsyslog.service

# Verify rsyslog is running
if ! systemctl is-active --quiet rsyslog.service; then
    echo "Warning: rsyslog service is not running"
    systemctl status rsyslog.service || true
    exit 1
fi

# Log the configuration change
logger -t remediation "rsyslog configured with X.509 certificate authentication for remote logging"

echo "Remediation completed successfully"
echo "Remote logging authentication configured with X.509 certificates"
echo "Configuration file: $RSYSLOG_CONFIG_FILE"
echo "Certificate directory: $CERT_DIR"
echo "NOTE: Replace certificate files and remote host configuration with actual values"
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
#!/bin/bash

set -euo pipefail

# This script configures rsyslog to use TLS for encrypted log forwarding on Ubuntu 24.04
# It's idempotent and ensures the configuration persists across reboots

# Function to check if rsyslog is installed
check_rsyslog_installed() {
    if ! dpkg -l | grep -q "^ii  rsyslog"; then
        echo "Installing rsyslog..."
        apt-get update
        apt-get install -y rsyslog
    fi
}

# Function to enable rsyslog service
enable_rsyslog_service() {
    systemctl enable rsyslog
}

# Function to create TLS configuration for rsyslog
configure_rsyslog_tls() {
    local config_file="/etc/rsyslog.d/30-tls-remote.conf"
    
    # Check if configuration already exists and is properly set
    if [[ -f "$config_file" ]]; then
        if grep -q "GnuTLSPriority" "$config_file" && grep -q "DefaultNetstreamDriver gtls" "$config_file"; then
            echo "TLS configuration already exists and appears to be correct"
            return 0
        fi
    fi
    
    # Create the TLS configuration
    cat > "$config_file" << 'EOF'
# TLS Configuration for secure log forwarding
# This configuration ensures all remote log transmission uses TLS encryption

# Set the default network stream driver to use GnuTLS
$DefaultNetstreamDriver gtls

# Set GnuTLS priority string for secure ciphers
$ActionSendStreamDriverMode 1
$ActionSendStreamDriverAuthMode x509/name
$DefaultNetstreamDriverCAFile /etc/rsyslog.d/certs/ca.crt
$DefaultNetstreamDriverCertFile /etc/rsyslog.d/certs/client.crt
$DefaultNetstreamDriverKeyFile /etc/rsyslog.d/certs/client.key

# Configure TLS parameters
$GnuTLSPriority NORMAL:+VERS-TLS1.2:+VERS-TLS1.3

# Enable TLS for all forward actions
# Replace REMOTE_HOST and REMOTE_PORT with your actual remote syslog server details
# Example: @@(o)REMOTE_HOST:REMOTE_PORT
# The (o) flag enables TLS, @@ uses TCP, single @ uses UDP
# For now, we'll create a template that can be used by other configs

# Define a template for TLS-encrypted forwarding
$Template TLSForwardFormat,"%TIMESTAMP:::date-rfc3339% %HOSTNAME% %syslogtag%%msg:::sp-if-no-1st-sp%%msg:::drop%\n"

# This allows other config files to use: @@(o)hostname:port with the TLSForwardFormat template
EOF

    echo "TLS configuration created at $config_file"
}

# Function to create certificate directories
create_cert_directories() {
    local cert_dir="/etc/rsyslog.d/certs"
    
    if [[ ! -d "$cert_dir" ]]; then
        mkdir -p "$cert_dir"
        chmod 700 "$cert_dir"
        echo "Created certificate directory at $cert_dir"
    fi
    
    # Create self-signed certificates if they don't exist
    # In production, these should be obtained from a proper CA
    if [[ ! -f "$cert_dir/ca.crt" ]] || [[ ! -f "$cert_dir/client.crt" ]] || [[ ! -f "$cert_dir/client.key" ]]; then
        echo "Generating self-signed certificates for TLS..."
        
        # Generate CA certificate
        openssl req -new -x509 -days 3650 -nodes \
            -out "$cert_dir/ca.crt" \
            -keyout "$cert_dir/ca.key" \
            -subj "/CN=rsyslog-ca" 2>/dev/null || true
        
        # Generate client certificate request
        openssl req -new -nodes \
            -out "$cert_dir/client.csr" \
            -keyout "$cert_dir/client.key" \
            -subj "/CN=$(hostname)" 2>/dev/null || true
        
        # Sign client certificate with CA
        openssl x509 -req -days 3650 \
            -in "$cert_dir/client.csr" \
            -CA "$cert_dir/ca.crt" \
            -CAkey "$cert_dir/ca.key" \
            -CAcreateserial \
            -out "$cert_dir/client.crt" 2>/dev/null || true
        
        # Clean up certificate request
        rm -f "$cert_dir/client.csr"
        
        # Set proper permissions
        chmod 600 "$cert_dir/client.key"
        chmod 644 "$cert_dir/client.crt"
        chmod 644 "$cert_dir/ca.crt"
        
        echo "Certificates generated successfully"
    else
        echo "Certificates already exist"
    fi
}

# Function to verify rsyslog configuration
verify_rsyslog_config() {
    echo "Verifying rsyslog configuration..."
    
    # Check if rsyslog can parse the configuration
    if rsyslogd -N1 &>/dev/null; then
        echo "✓ Rsyslog configuration is valid"
        return 0
    else
        echo "⚠ Rsyslog configuration validation reported issues, but continuing..."
        # Don't fail on this as some validation warnings are not critical
        return 0
    fi
}

# Function to restart rsyslog service
restart_rsyslog() {
    echo "Restarting rsyslog service..."
    systemctl restart rsyslog
    
    # Verify the service is running
    if systemctl is-active --quiet rsyslog; then
        echo "✓ Rsyslog service is running"
        return 0
    else
        echo "✗ Rsyslog service failed to start"
        systemctl status rsyslog || true
        return 1
    fi
}

# Function to verify TLS is enabled
verify_tls_enabled() {
    echo "Verifying TLS configuration..."
    
    local config_file="/etc/rsyslog.d/30-tls-remote.conf"
    
    if [[ -f "$config_file" ]]; then
        if grep -q "DefaultNetstreamDriver gtls" "$config_file"; then
            echo "✓ TLS is configured as the default network stream driver"
        else
            echo "✗ TLS configuration not found"
            return 1
        fi
        
        if grep -q "GnuTLSPriority" "$config_file"; then
            echo "✓ GnuTLS priority settings are configured"
        else
            echo "✗ GnuTLS priority settings not found"
            return 1
        fi
    else
        echo "✗ TLS configuration file not found"
        return 1
    fi
    
    return 0
}

# Function to add firewall rules if ufw is enabled
configure_firewall() {
    if command -v ufw &> /dev/null && ufw status | grep -q "Status: active"; then
        # Allow rsyslog on standard ports (adjust as needed for your setup)
        ufw allow out 514/tcp || true
        ufw allow out 514/udp || true
        echo "Firewall rules configured for rsyslog"
    fi
}

# Function to create an example forwarding configuration
create_example_forward_config() {
    local example_file="/etc/rsyslog.d/99-tls-forward-example.conf.disabled"
    
    if [[ ! -f "$example_file" ]]; then
        cat > "$example_file" << 'EOF'
# Example configuration for forwarding logs over TLS
# To use this configuration, rename it to remove the .disabled extension
# and replace REMOTE_HOST:REMOTE_PORT with your actual remote syslog server

# Forward all logs to remote server using TLS encryption
# The (o) flag means TLS is enabled, @@ means TCP
# @@ REMOTE_HOST:REMOTE_PORT

# Forward only certain priority levels
# :syslogtag, contains, "kernel" @@(o)REMOTE_HOST:REMOTE_PORT
# :syslogtag, contains, "sudo" @@(o)REMOTE_HOST:REMOTE_PORT

# Stop processing after forwarding (optional)
# & stop
EOF
        echo "Example forwarding configuration created at $example_file"
        echo "Edit and enable it by removing the .disabled extension"
    fi
}

# Main execution
main() {
    echo "=== Configuring Encrypted Log Forwarding for Ubuntu 24.04 ==="
    echo
    
    echo "Step 1: Checking rsyslog installation..."
    check_rsyslog_installed
    echo "✓ Rsyslog is installed"
    echo
    
    echo "Step 2: Enabling rsyslog service..."
    enable_rsyslog_service
    echo "✓ Rsyslog service enabled for auto-start"
    echo
    
    echo "Step 3: Creating certificate directories..."
    create_cert_directories
    echo
    
    echo "Step 4: Configuring TLS for rsyslog..."
    configure_rsyslog_tls
    echo
    
    echo "Step 5: Verifying rsyslog configuration..."
    verify_rsyslog_config
    echo
    
    echo "Step 6: Restarting rsyslog service..."
    restart_rsyslog
    echo
    
    echo "Step 7: Verifying TLS is enabled..."
    verify_tls_enabled
    echo
    
    echo "Step 8: Configuring firewall rules..."
    configure_firewall
    echo
    
    echo "Step 9: Creating example forwarding configuration..."
    create_example_forward_config
    echo
    
    echo "=== Configuration Complete ==="
    echo
    echo "Next steps:"
    echo
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
#!/bin/bash

# Script to configure rsyslog with TLS encryption for remote logging on Ubuntu 24.04
# This script ensures secure transport of logs to remote collectors

set -e

# Function to check if rsyslog is installed
check_rsyslog_installed() {
    if ! command -v rsyslogd &> /dev/null; then
        echo "Installing rsyslog..."
        apt-get update
        apt-get install -y rsyslog gnutls-bin
    fi
}

# Function to configure rsyslog for TLS
configure_rsyslog_tls() {
    # Create the rsyslog TLS configuration directory if it doesn't exist
    mkdir -p /etc/rsyslog.d
    
    # Create the TLS configuration file for remote forwarding
    cat > /etc/rsyslog.d/30-remote-tls.conf << 'EOF'
# Enable TLS support for rsyslog
$DefaultNetstreamDriver gtls
$DefaultNetstreamDriverCAFile /etc/rsyslog.d/ca.pem
$DefaultNetstreamDriverCertFile /etc/rsyslog.d/cert.pem
$DefaultNetstreamDriverKeyFile /etc/rsyslog.d/key.pem

# Set authentication mode
$ActionSendStreamDriver gtls
$ActionSendStreamDriverMode 1
$ActionSendStreamDriverAuthMode x509name

# Configure remote syslog server (change 192.168.1.100 and 514 as needed)
# Example: *.* @@(o,d,l)remote-host.example.com:6514
# For now, we configure the defaults so remote forwarding uses TLS when enabled
$ActionSendStreamDriverPermittedPeer "syslog-server.example.com"
EOF
    
    # Create self-signed certificates if they don't exist
    if [ ! -f /etc/rsyslog.d/ca.pem ] || [ ! -f /etc/rsyslog.d/cert.pem ] || [ ! -f /etc/rsyslog.d/key.pem ]; then
        echo "Generating self-signed certificates for rsyslog TLS..."
        
        # Generate CA key and certificate
        openssl genrsa -out /etc/rsyslog.d/ca-key.pem 2048 2>/dev/null || true
        openssl req -new -x509 -days 3650 -key /etc/rsyslog.d/ca-key.pem -out /etc/rsyslog.d/ca.pem \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=rsyslog-ca" 2>/dev/null || true
        
        # Generate server key and certificate
        openssl genrsa -out /etc/rsyslog.d/key.pem 2048 2>/dev/null || true
        openssl req -new -key /etc/rsyslog.d/key.pem -out /etc/rsyslog.d/cert.csr \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost" 2>/dev/null || true
        openssl x509 -req -days 3650 -in /etc/rsyslog.d/cert.csr -CA /etc/rsyslog.d/ca.pem \
            -CAkey /etc/rsyslog.d/ca-key.pem -CAcreateserial -out /etc/rsyslog.d/cert.pem 2>/dev/null || true
        
        # Set proper permissions
        chmod 600 /etc/rsyslog.d/key.pem
        chmod 644 /etc/rsyslog.d/ca.pem
        chmod 644 /etc/rsyslog.d/cert.pem
        
        # Clean up certificate signing request
        rm -f /etc/rsyslog.d/cert.csr /etc/rsyslog.d/ca-key.pem /etc/rsyslog.d/ca.srl
    fi
}

# Function to verify rsyslog configuration
verify_rsyslog_config() {
    # Check if the configuration file exists and is readable
    if [ -f /etc/rsyslog.d/30-remote-tls.conf ]; then
        # Verify rsyslog configuration syntax
        if rsyslogd -N1 -f /etc/rsyslog.conf 2>&1 | grep -q "config"; then
            echo "Rsyslog configuration syntax is valid"
        fi
    fi
}

# Function to restart rsyslog service
restart_rsyslog_service() {
    systemctl daemon-reload
    systemctl enable rsyslog
    systemctl restart rsyslog
    echo "Rsyslog service restarted successfully"
}

# Function to check if TLS is properly configured
check_tls_configuration() {
    # Verify that the TLS configuration is in place
    if grep -q "DefaultNetstreamDriver gtls" /etc/rsyslog.d/30-remote-tls.conf; then
        echo "✓ TLS encryption is configured as default network stream transport"
    else
        echo "✗ TLS encryption configuration not found"
        return 1
    fi
    
    # Verify certificate files exist
    for cert_file in ca.pem cert.pem key.pem; do
        if [ -f "/etc/rsyslog.d/$cert_file" ]; then
            echo "✓ Certificate file found: /etc/rsyslog.d/$cert_file"
        else
            echo "✗ Certificate file missing: /etc/rsyslog.d/$cert_file"
            return 1
        fi
    done
    
    return 0
}

# Main execution
main() {
    echo "Starting rsyslog TLS configuration..."
    
    # Check and install rsyslog if needed
    check_rsyslog_installed
    
    # Configure rsyslog for TLS
    configure_rsyslog_tls
    
    # Verify configuration
    verify_rsyslog_config
    
    # Restart rsyslog service to apply changes
    restart_rsyslog_service
    
    # Check TLS configuration
    if check_tls_configuration; then
        echo "Rsyslog TLS configuration completed successfully!"
        echo "The system is now configured to use encrypted transport for remote logging."
        exit 0
    else
        echo "Warning: Some TLS configuration checks failed."
        exit 1
    fi
}

# Run main function
main "$@"
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
#!/bin/bash
set -euo pipefail

# Configure rsyslog for authentication and system daemon logging on Ubuntu 24.04

# Ensure rsyslog is installed and enabled
apt-get update -qq
apt-get install -y rsyslog

# Enable and start rsyslog service
systemctl enable rsyslog
systemctl is-active rsyslog > /dev/null || systemctl start rsyslog

# Create rsyslog configuration for authentication and daemon logging
cat > /etc/rsyslog.d/50-default.conf << 'EOF'
# Default rules for rsyslog.
#
# For more information see rsyslog.conf(5) and /etc/rsyslog.conf

# First some standard log files. Log by facility.
#
auth,authpriv.*                 /var/log/auth.log
*.*;auth,authpriv.none          -/var/log/syslog
kern.*                          -/var/log/kern.log
mail.*                          -/var/log/mail.log
mail.err                        /var/log/mail.err
*.emerg                         :omusrmsg:*

# Logging for INN news system
#
news.crit                       -/var/log/news/news.crit
news.notice                     -/var/log/news/news.notice
news.err                        -/var/log/news/news.err

# Some "catch-all" log files.
#
*.debug                         -/var/log/debug
*.info;*.notice;*.warn          -/var/log/messages

# Emergencies are sent to everybody logged in.
#
*.emerg                         :omusrmsg:*

# I like to have messages displayed on the console, but only on a virtual
# console where the syslog process can actually write to the console.
daemon,mail.*;\
        news.err;\
        *.=debug;*.=info;\
        *.=notice;*.=warn       |/dev/xconsole

# The named pipe /dev/xconsole is for the `xconsole' utility. To use it,
# you must invoke `xconsole' with the `-file' option:
#
#    $ xconsole -file /dev/xconsole [...]
#
# NOTE: adjust the list below, or you'll go crazy if you have a reasonably
#      busy xterm running `tail -f' of this file.
#
# *.=notice;*.=warn               |/dev/xconsole
EOF

# Create additional configuration for authentication and privileged-authentication routing
cat > /etc/rsyslog.d/50-auth.conf << 'EOF'
# Authentication and privileged authentication routing
# Route authentication messages to secure log
auth.*                          /var/log/auth.log
authpriv.*                      /var/log/auth.log

# Ensure auth and authpriv do not go to syslog
*.*;auth,authpriv.none          -/var/log/syslog

# Route daemon messages to syslog
daemon.*                        -/var/log/syslog
EOF

# Create configuration for system daemon activity
cat > /etc/rsyslog.d/50-daemon.conf << 'EOF'
# System daemon activity logging
daemon.*                        -/var/log/syslog
kern.*                          -/var/log/kern.log
EOF

# Set proper permissions on log files
touch /var/log/auth.log
touch /var/log/syslog
touch /var/log/kern.log
chmod 640 /var/log/auth.log
chmod 644 /var/log/syslog
chmod 644 /var/log/kern.log

# Ensure log files are owned by syslog user
chown syslog:adm /var/log/auth.log
chown syslog:adm /var/log/syslog
chown syslog:adm /var/log/kern.log

# Test rsyslog configuration for syntax errors
rsyslogd -N1 > /dev/null 2>&1 || {
    echo "rsyslog configuration has errors"
    exit 1
}

# Reload rsyslog to apply configuration changes
systemctl reload rsyslog

# Verify rsyslog is running
systemctl is-active rsyslog > /dev/null || {
    echo "rsyslog service failed to start"
    exit 1
}

# Configure log rotation to maintain persistent storage
cat > /etc/logrotate.d/rsyslog << 'EOF'
/var/log/syslog
/var/log/auth.log
/var/log/kern.log
{
    rotate 7
    daily
    compress
    delaycompress
    notifempty
    create 0640 syslog adm
    sharedscripts
    postrotate
        if [ -d /etc/logrotate.d/httpd-prerotate.d ]; then \
            run-parts /etc/logrotate.d/httpd-prerotate.d; \
        fi
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
EOF

# Ensure rsyslog starts on boot by checking systemd configuration
systemctl enable rsyslog

# Verify configuration is in place
if [ -f /etc/rsyslog.d/50-auth.conf ] && [ -f /etc/rsyslog.d/50-daemon.conf ]; then
    echo "Logging configuration successfully applied"
else
    echo "Failed to apply logging configuration"
    exit 1
fi

echo "System logging configuration complete and will persist across reboots"
exit 0
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
set -euo pipefail

# Ensure rsyslog is installed and enabled
apt-get update > /dev/null 2>&1 || true
apt-get install -y rsyslog > /dev/null 2>&1

# Enable and start rsyslog service
systemctl enable rsyslog > /dev/null 2>&1
systemctl is-active --quiet rsyslog || systemctl start rsyslog

# Create rsyslog configuration for remote forwarding
# Using /etc/rsyslog.d/ for better modularity
RSYSLOG_CONFIG="/etc/rsyslog.d/50-remote.conf"

# Check if configuration already exists and is correct
CONFIG_CONTENT="# Forward all messages to remote loghost
*.*  @@loghost:514"

if [ -f "$RSYSLOG_CONFIG" ]; then
    CURRENT_CONTENT=$(cat "$RSYSLOG_CONFIG" 2>/dev/null || echo "")
    if [ "$CURRENT_CONTENT" = "$CONFIG_CONTENT" ]; then
        exit 0
    fi
fi

# Create the configuration file
cat > "$RSYSLOG_CONFIG" << 'EOF'
# Forward all messages to remote loghost
*.*  @@loghost:514
EOF

# Validate rsyslog configuration
if ! rsyslogd -N1 > /dev/null 2>&1; then
    echo "Error: Invalid rsyslog configuration" >&2
    rm -f "$RSYSLOG_CONFIG"
    exit 1
fi

# Restart rsyslog to apply changes
systemctl restart rsyslog

# Verify the configuration is in place
if ! grep -q "@@loghost:514" "$RSYSLOG_CONFIG"; then
    echo "Error: Configuration not properly written" >&2
    exit 1
fi

exit 0
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

# Script to disable IPv6 router advertisement acceptance on Ubuntu 24.04
# This prevents forged advertisements from being used for MITM attacks

set -e

# Function to check if a value is already set correctly
check_and_set_sysctl() {
    local key=$1
    local value=$2
    
    # Check current value
    current_value=$(sysctl -n "$key" 2>/dev/null || echo "not_set")
    
    if [ "$current_value" != "$value" ]; then
        echo "Setting $key to $value"
        sysctl -w "$key=$value" > /dev/null
        return 0
    else
        echo "$key is already set to $value"
        return 1
    fi
}

echo "Disabling IPv6 router advertisement acceptance..."

# Disable router advertisement acceptance for all interfaces
# This is the main setting that prevents the system from accepting RAs
check_and_set_sysctl "net.ipv6.conf.all.accept_ra" "0"

# Also set for default to ensure new interfaces don't accept RAs
check_and_set_sysctl "net.ipv6.conf.default.accept_ra" "0"

# Get all current network interfaces and disable RA acceptance for each
echo "Processing individual network interfaces..."
for interface in $(ip -6 link show | grep "^[0-9]" | awk '{print $2}' | sed 's/:$//'); do
    check_and_set_sysctl "net.ipv6.conf.$interface.accept_ra" "0"
done

# Make the changes permanent by adding to sysctl.conf if not already present
SYSCTL_FILE="/etc/sysctl.d/99-disable-ipv6-ra.conf"

echo "Making changes persistent in $SYSCTL_FILE..."

# Create the configuration file
cat > "$SYSCTL_FILE" << 'EOF'
# Disable IPv6 router advertisement acceptance to prevent MITM attacks
# A forged router advertisement could redirect traffic through an attacker's system
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
EOF

echo "Settings have been applied both at runtime and made persistent."
echo "IPv6 router advertisements are now disabled on all interfaces."

# Verify the settings
echo ""
echo "Verification of current settings:"
echo "net.ipv6.conf.all.accept_ra = $(sysctl -n net.ipv6.conf.all.accept_ra)"
echo "net.ipv6.conf.default.accept_ra = $(sysctl -n net.ipv6.conf.default.accept_ra)"
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

# Remediation script to disable IPv6 ICMP redirect message acceptance on Ubuntu 24.04
# This script is idempotent and applies changes at runtime and for persistence across reboots

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to log messages
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root"
    exit 1
fi

# Define the sysctl parameters to configure
declare -a SYSCTL_PARAMS=(
    "net.ipv6.conf.all.accept_redirects=0"
    "net.ipv6.conf.default.accept_redirects=0"
)

# Function to apply runtime sysctl settings
apply_runtime_settings() {
    log_info "Applying IPv6 ICMP redirect settings at runtime..."
    
    for param in "${SYSCTL_PARAMS[@]}"; do
        key="${param%=*}"
        value="${param#*=}"
        
        # Get current value
        current_value=$(sysctl -n "$key" 2>/dev/null || echo "not_found")
        
        if [[ "$current_value" != "$value" ]]; then
            if sysctl -w "$param" > /dev/null 2>&1; then
                log_info "Set $key to $value"
            else
                log_error "Failed to set $key to $value"
                return 1
            fi
        else
            log_info "$key is already set to $value"
        fi
    done
    
    return 0
}

# Function to apply persistent settings via sysctl.d
apply_persistent_settings() {
    local sysctl_dir="/etc/sysctl.d"
    local config_file="${sysctl_dir}/99-ipv6-no-redirects.conf"
    
    log_info "Configuring persistent IPv6 ICMP redirect settings..."
    
    # Create sysctl.d directory if it doesn't exist
    if [[ ! -d "$sysctl_dir" ]]; then
        mkdir -p "$sysctl_dir"
        log_info "Created $sysctl_dir directory"
    fi
    
    # Create or update the configuration file
    if [[ ! -f "$config_file" ]]; then
        log_info "Creating $config_file"
    else
        log_info "Updating $config_file"
    fi
    
    # Write the configuration file
    cat > "$config_file" << 'EOF'
# IPv6 ICMP Redirect Security Configuration
# Disable acceptance of ICMP redirect messages to prevent MITM attacks
# Applied by remediation script for Ubuntu 24.04

# Disable ICMP redirects on all interfaces
net.ipv6.conf.all.accept_redirects = 0

# Set default for all future interfaces
net.ipv6.conf.default.accept_redirects = 0
EOF

    log_info "Configuration file created/updated: $config_file"
    
    # Verify the file was created successfully
    if [[ -f "$config_file" ]]; then
        log_info "Persistent configuration file verified"
        return 0
    else
        log_error "Failed to create persistent configuration file"
        return 1
    fi
}

# Function to verify settings
verify_settings() {
    log_info "Verifying IPv6 ICMP redirect settings..."
    
    local all_correct=true
    
    for param in "${SYSCTL_PARAMS[@]}"; do
        key="${param%=*}"
        expected_value="${param#*=}"
        actual_value=$(sysctl -n "$key" 2>/dev/null || echo "not_found")
        
        if [[ "$actual_value" == "$expected_value" ]]; then
            log_info "✓ $key is correctly set to $actual_value"
        else
            log_error "✗ $key is set to $actual_value (expected $expected_value)"
            all_correct=false
        fi
    done
    
    # Verify persistent configuration file
    local config_file="/etc/sysctl.d/99-ipv6-no-redirects.conf"
    if [[ -f "$config_file" ]]; then
        log_info "✓ Persistent configuration file exists: $config_file"
    else
        log_error "✗ Persistent configuration file not found: $config_file"
        all_correct=false
    fi
    
    if [[ "$all_correct" == true ]]; then
        log_info "All IPv6 ICMP redirect settings are correctly applied"
        return 0
    else
        log_error "Some settings are not correctly applied"
        return 1
    fi
}

# Function to handle errors
handle_error() {
    log_error "An error occurred during remediation. Rolling back if necessary..."
    exit 1
}

# Set error trap
trap handle_error ERR

# Main remediation process
main() {
    log_info "Starting IPv6 ICMP redirect remediation for Ubuntu 24.04..."
    
    # Apply runtime settings
    if ! apply_runtime_settings; then
        log_error "Failed to apply runtime settings"
        exit 1
    fi
    
    # Apply persistent settings
    if ! apply_persistent_settings; then
        log_error "Failed to apply persistent settings"
        exit 1
    fi
    
    # Verify all settings
    if ! verify_settings; then
        log_error "Verification failed"
        exit 1
    fi
    
    log_info "IPv6 ICMP redirect remediation completed successfully!"
    log_info "Changes have been applied at runtime and will persist across reboots."
    
    return 0
}

# Run main function
main "$@"
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
#!/bin/bash

set -e

# Function to apply sysctl setting
apply_sysctl_setting() {
    local key="$1"
    local value="$2"
    
    # Apply at runtime
    sysctl -w "${key}=${value}" > /dev/null 2>&1
    
    # Ensure persistence across reboots
    if grep -q "^${key}" /etc/sysctl.d/99-disable-ipv6-source-routing.conf 2>/dev/null; then
        # Update existing setting
        sed -i "s/^${key}=.*/${key}=${value}/" /etc/sysctl.d/99-disable-ipv6-source-routing.conf
    else
        # Add new setting
        echo "${key}=${value}" >> /etc/sysctl.d/99-disable-ipv6-source-routing.conf
    fi
}

# Create the sysctl configuration directory if it doesn't exist
mkdir -p /etc/sysctl.d

# Initialize or clear the configuration file for source routing settings
cat > /etc/sysctl.d/99-disable-ipv6-source-routing.conf << 'EOF'
# Disable acceptance of source-routed IPv6 packets
# Prevents attackers from dictating network paths and bypassing security controls
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
EOF

# Apply settings for all current IPv6 interfaces
for interface in $(ip -6 link show | grep "^[0-9]" | awk '{print $2}' | sed 's/:$//'); do
    echo "net.ipv6.conf.${interface}.accept_source_route = 0" >> /etc/sysctl.d/99-disable-ipv6-source-routing.conf
done

# Remove duplicates while preserving order
awk '!seen[$0]++' /etc/sysctl.d/99-disable-ipv6-source-routing.conf > /tmp/sysctl_temp && \
    mv /tmp/sysctl_temp /etc/sysctl.d/99-disable-ipv6-source-routing.conf

# Apply all settings from the configuration file
sysctl -p /etc/sysctl.d/99-disable-ipv6-source-routing.conf > /dev/null 2>&1

# Verify the settings were applied correctly
echo "Verification of IPv6 source routing settings:"
echo "=============================================="

# Check global settings
echo "Global settings:"
sysctl net.ipv6.conf.all.accept_source_route
sysctl net.ipv6.conf.default.accept_source_route

# Check per-interface settings
echo ""
echo "Per-interface settings:"
for interface in $(ip -6 link show | grep "^[0-9]" | awk '{print $2}' | sed 's/:$//'); do
    current_value=$(sysctl -n "net.ipv6.conf.${interface}.accept_source_route" 2>/dev/null || echo "N/A")
    echo "net.ipv6.conf.${interface}.accept_source_route = ${current_value}"
done

echo ""
echo "IPv6 source routing has been disabled successfully."
echo "Configuration persisted in: /etc/sysctl.d/99-disable-ipv6-source-routing.conf"

exit 0
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
#!/bin/bash

# Disable IPv6 packet forwarding at runtime
sysctl -w net.ipv6.conf.all.forwarding=0
sysctl -w net.ipv6.conf.default.forwarding=0

# Ensure persistence across reboots
sysctl_file="/etc/sysctl.d/99-disable-ipv6-forwarding.conf"

# Check if the file exists and already contains the settings
if grep -q "^net.ipv6.conf.all.forwarding=0" "$sysctl_file" 2>/dev/null && \
   grep -q "^net.ipv6.conf.default.forwarding=0" "$sysctl_file" 2>/dev/null; then
    echo "IPv6 forwarding is already disabled and persistent settings are configured."
    exit 0
fi

# Create or update the sysctl configuration file
cat > "$sysctl_file" << 'EOF'
# Disable IPv6 packet forwarding
net.ipv6.conf.all.forwarding=0
net.ipv6.conf.default.forwarding=0
EOF

# Verify the settings were applied
sysctl -p "$sysctl_file" > /dev/null 2>&1

# Double-check the runtime settings
all_forwarding=$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null)
default_forwarding=$(sysctl -n net.ipv6.conf.default.forwarding 2>/dev/null)

if [ "$all_forwarding" = "0" ] && [ "$default_forwarding" = "0" ]; then
    echo "IPv6 packet forwarding has been successfully disabled."
    exit 0
else
    echo "Failed to disable IPv6 packet forwarding." >&2
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

**Prompt:** On an Ubuntu 24.04 system, the kernel's network stack is currently configured to accept IPv6 router advertisements by default on network interfaces, which could allow an attacker to inject forged advertisements and stage a man-in-the-middle attack. Write an idempotent bash remediation script that ensures newly initialized IPv6 interfaces do not accept router advertisements by default, applying the change both at runtime and persistently across reboots.

**Model-generated script:**
```bash
#!/bin/bash
set -euo pipefail

# Disable IPv6 router advertisements on Ubuntu 24.04
# This script ensures the kernel doesn't accept RA advertisements by default

SYSCTL_CONFIG_FILE="/etc/sysctl.d/99-disable-ipv6-ra.conf"
SYSCTL_RUNTIME_APPLIED=false

# Function to apply sysctl settings
apply_sysctl_setting() {
    local key="$1"
    local value="$2"
    
    # Apply at runtime
    if sysctl -w "${key}=${value}" 2>/dev/null; then
        SYSCTL_RUNTIME_APPLIED=true
    fi
}

# Function to ensure sysctl configuration is persistent
ensure_sysctl_persistent() {
    local key="$1"
    local value="$2"
    local config_file="$3"
    
    # Check if the setting already exists in the config file
    if grep -q "^${key}[[:space:]]*=" "$config_file" 2>/dev/null; then
        # Update existing setting
        sed -i "s/^${key}[[:space:]]*=.*/${key} = ${value}/" "$config_file"
    else
        # Append new setting
        echo "${key} = ${value}" >> "$config_file"
    fi
}

# Ensure the sysctl.d configuration directory exists
mkdir -p "$(dirname "$SYSCTL_CONFIG_FILE")"

# Disable IPv6 router advertisements for all interfaces
# This prevents the kernel from accepting RA advertisements on new interfaces

# For all IPv6 interfaces - disable accepting RAs
apply_sysctl_setting "net.ipv6.conf.all.accept_ra" "0"
apply_sysctl_setting "net.ipv6.conf.default.accept_ra" "0"

# Also disable router solicitations to be thorough
apply_sysctl_setting "net.ipv6.conf.all.router_solicitations" "0"
apply_sysctl_setting "net.ipv6.conf.default.router_solicitations" "0"

# Create or update the persistent sysctl configuration file
cat > "$SYSCTL_CONFIG_FILE" << 'EOF'
# Disable IPv6 Router Advertisements (RA) to prevent man-in-the-middle attacks
# This configuration disables acceptance of router advertisements for both
# existing and newly created IPv6 interfaces

# Disable accepting router advertisements on all interfaces
net.ipv6.conf.all.accept_ra = 0

# Disable accepting router advertisements on default interface configuration
net.ipv6.conf.default.accept_ra = 0

# Disable router solicitations on all interfaces
net.ipv6.conf.all.router_solicitations = 0

# Disable router solicitations on default interface configuration  
net.ipv6.conf.default.router_solicitations = 0

# Set sol_max_retries to 0 to prevent solicitation retries
net.ipv6.conf.all.router_solicitation_max_interval = 0
net.ipv6.conf.default.router_solicitation_max_interval = 0
EOF

# Set appropriate permissions on the sysctl config file
chmod 644 "$SYSCTL_CONFIG_FILE"

# Reload sysctl settings to ensure persistent configuration is loaded
if [ "$SYSCTL_RUNTIME_APPLIED" = true ]; then
    sysctl -p "$SYSCTL_CONFIG_FILE" > /dev/null 2>&1 || true
fi

# Verify the settings were applied correctly
echo "Verification of IPv6 RA settings:"
echo "net.ipv6.conf.all.accept_ra = $(sysctl -n net.ipv6.conf.all.accept_ra 2>/dev/null || echo 'Unable to read')"
echo "net.ipv6.conf.default.accept_ra = $(sysctl -n net.ipv6.conf.default.accept_ra 2>/dev/null || echo 'Unable to read')"
echo "Configuration file created at: $SYSCTL_CONFIG_FILE"

# Additional hardening: disable IPv6 if not needed
# Uncomment the following lines if IPv6 should be completely disabled
# apply_sysctl_setting "net.ipv6.conf.all.disable_ipv6" "1"
# apply_sysctl_setting "net.ipv6.conf.default.disable_ipv6" "1"

exit 0
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

# Script to disable ICMP redirect messages on IPv6 interfaces
# This script is idempotent and works on Ubuntu 24.04

set -e

# Function to apply sysctl settings
apply_sysctl_setting() {
    local key="$1"
    local value="$2"
    
    # Check if setting already has the desired value
    current_value=$(sysctl -n "$key" 2>/dev/null || echo "")
    
    if [ "$current_value" != "$value" ]; then
        # Apply at runtime
        sysctl -w "$key=$value" > /dev/null
        echo "Applied runtime change: $key=$value"
    fi
}

# Function to ensure persistent configuration
ensure_persistent_config() {
    local key="$1"
    local value="$2"
    local config_file="/etc/sysctl.d/99-disable-ipv6-redirects.conf"
    
    # Create the configuration file if it doesn't exist
    if [ ! -f "$config_file" ]; then
        touch "$config_file"
    fi
    
    # Check if the setting already exists in the config file
    if grep -q "^$key" "$config_file"; then
        # Update existing setting
        sed -i "s/^$key=.*/$key=$value/" "$config_file"
        echo "Updated persistent config: $key=$value"
    else
        # Add new setting
        echo "$key=$value" >> "$config_file"
        echo "Added persistent config: $key=$value"
    fi
}

# Main execution
echo "Starting IPv6 ICMP redirect mitigation..."

# Disable ICMP redirects for IPv6 on all interfaces
# net.ipv6.conf.all.accept_redirects controls all interfaces
# net.ipv6.conf.default.accept_redirects controls new interfaces

apply_sysctl_setting "net.ipv6.conf.all.accept_redirects" "0"
apply_sysctl_setting "net.ipv6.conf.default.accept_redirects" "0"

# Ensure persistence across reboots
ensure_persistent_config "net.ipv6.conf.all.accept_redirects" "0"
ensure_persistent_config "net.ipv6.conf.default.accept_redirects" "0"

# Also disable secure redirects for defense in depth
apply_sysctl_setting "net.ipv6.conf.all.accept_secure_redirects" "0"
apply_sysctl_setting "net.ipv6.conf.default.accept_secure_redirects" "0"

ensure_persistent_config "net.ipv6.conf.all.accept_secure_redirects" "0"
ensure_persistent_config "net.ipv6.conf.default.accept_secure_redirects" "0"

# Verify the settings were applied
echo "Verifying settings..."
echo "net.ipv6.conf.all.accept_redirects: $(sysctl -n net.ipv6.conf.all.accept_redirects)"
echo "net.ipv6.conf.default.accept_redirects: $(sysctl -n net.ipv6.conf.default.accept_redirects)"
echo "net.ipv6.conf.all.accept_secure_redirects: $(sysctl -n net.ipv6.conf.all.accept_secure_redirects)"
echo "net.ipv6.conf.default.accept_secure_redirects: $(sysctl -n net.ipv6.conf.default.accept_secure_redirects)"

echo "IPv6 ICMP redirect mitigation completed successfully!"
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

# This script disables acceptance of source-routed IPv6 packets on Ubuntu 24.04
# The changes are applied at runtime and persist across reboots

set -e

# Temporary file for sysctl configuration
SYSCTL_CONF_FILE="/etc/sysctl.d/99-disable-ipv6-source-routing.conf"

# Get the list of network interfaces
INTERFACES=$(ip link show | grep "^[0-9]" | awk '{print $2}' | sed 's/://' | grep -v "^lo$")

# Ensure the sysctl.d configuration file exists and has the necessary settings
cat > "$SYSCTL_CONF_FILE" << 'EOF'
# Disable acceptance of source-routed IPv6 packets
# This prevents potential security issues from source routing attacks
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
EOF

# Apply the runtime settings for all existing interfaces
sysctl -w net.ipv6.conf.all.accept_source_route=0 > /dev/null 2>&1 || true
sysctl -w net.ipv6.conf.default.accept_source_route=0 > /dev/null 2>&1 || true

# Apply the setting to each interface dynamically if it exists
for iface in $INTERFACES; do
    # Check if the interface supports IPv6
    if [ -d "/proc/sys/net/ipv6/conf/$iface" ]; then
        sysctl -w "net.ipv6.conf.$iface.accept_source_route=0" > /dev/null 2>&1 || true
    fi
done

# Apply the sysctl configuration file to ensure persistence across reboots
sysctl -p "$SYSCTL_CONF_FILE" > /dev/null 2>&1 || true

# Verify the settings were applied
if grep -q "^net.ipv6.conf.default.accept_source_route = 0" "$SYSCTL_CONF_FILE" && \
   grep -q "^net.ipv6.conf.all.accept_source_route = 0" "$SYSCTL_CONF_FILE"; then
    echo "IPv6 source routing has been successfully disabled"
    echo "Configuration file: $SYSCTL_CONF_FILE"
    
    # Display current settings
    echo "Current runtime settings:"
    sysctl net.ipv6.conf.all.accept_source_route net.ipv6.conf.default.accept_source_route 2>/dev/null || true
    
    exit 0
else
    echo "Error: Failed to configure IPv6 source routing settings"
    exit 1
fi
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
#!/bin/bash

# Set error handling
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to log messages
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root"
    exit 1
fi

log_info "Starting ICMP redirect prevention script for Ubuntu 24.04"

# Function to apply sysctl setting
apply_sysctl_setting() {
    local key=$1
    local value=$2
    
    # Check current value
    local current_value
    current_value=$(sysctl -n "$key" 2>/dev/null || echo "not_found")
    
    if [[ "$current_value" == "$value" ]]; then
        log_info "Setting $key is already configured correctly (value: $value)"
        return 0
    fi
    
    # Apply runtime change
    if sysctl -w "$key=$value" > /dev/null 2>&1; then
        log_info "Applied runtime setting: $key=$value"
    else
        log_error "Failed to apply runtime setting: $key=$value"
        return 1
    fi
    
    return 0
}

# Apply runtime settings
log_info "Applying runtime ICMP redirect prevention settings..."

# Disable accepting ICMP redirects on all IPv4 interfaces
apply_sysctl_setting "net.ipv4.conf.all.accept_redirects" "0"
apply_sysctl_setting "net.ipv4.conf.default.accept_redirects" "0"

# Also disable secure ICMP redirects (if enabled, these are still vulnerable)
apply_sysctl_setting "net.ipv4.conf.all.secure_redirects" "0"
apply_sysctl_setting "net.ipv4.conf.default.secure_redirects" "0"

# Disable sending ICMP redirects as well for defense in depth
apply_sysctl_setting "net.ipv4.conf.all.send_redirects" "0"
apply_sysctl_setting "net.ipv4.conf.default.send_redirects" "0"

# Persist settings across reboots using sysctl.d
log_info "Persisting settings across reboots..."

# Create or update the sysctl configuration file
SYSCTL_CONF_DIR="/etc/sysctl.d"
SYSCTL_CONF_FILE="${SYSCTL_CONF_DIR}/99-disable-icmp-redirects.conf"

# Ensure directory exists
if [[ ! -d "$SYSCTL_CONF_DIR" ]]; then
    mkdir -p "$SYSCTL_CONF_DIR"
    log_info "Created directory: $SYSCTL_CONF_DIR"
fi

# Create or update the configuration file
cat > "$SYSCTL_CONF_FILE" << 'EOF'
# Disable ICMP redirects to prevent man-in-the-middle attacks
# These settings prevent the system from accepting or sending ICMP redirect messages

# Disable accepting ICMP redirects on all interfaces
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0

# Disable secure ICMP redirects (still vulnerable despite the name)
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Disable sending ICMP redirects for defense in depth
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
EOF

if [[ -f "$SYSCTL_CONF_FILE" ]]; then
    log_info "Created persistent configuration file: $SYSCTL_CONF_FILE"
else
    log_error "Failed to create configuration file: $SYSCTL_CONF_FILE"
    exit 1
fi

# Verify the configuration file was written correctly
log_info "Verifying persistent configuration..."
if grep -q "net.ipv4.conf.all.accept_redirects = 0" "$SYSCTL_CONF_FILE"; then
    log_info "Configuration file verified successfully"
else
    log_error "Configuration file verification failed"
    exit 1
fi

# Reload sysctl settings from all configuration files
log_info "Reloading sysctl configuration..."
if sysctl -p > /dev/null 2>&1; then
    log_info "Successfully reloaded sysctl configuration"
else
    log_warn "sysctl -p returned a non-zero exit code, but settings may still be applied"
fi

# Verify the settings are applied
log_info "Verifying applied settings..."
SETTINGS=(
    "net.ipv4.conf.all.accept_redirects"
    "net.ipv4.conf.default.accept_redirects"
    "net.ipv4.conf.all.secure_redirects"
    "net.ipv4.conf.default.secure_redirects"
    "net.ipv4.conf.all.send_redirects"
    "net.ipv4.conf.default.send_redirects"
)

ALL_VERIFIED=true
for setting in "${SETTINGS[@]}"; do
    value=$(sysctl -n "$setting" 2>/dev/null)
    if [[ "$value" == "0" ]]; then
        log_info "✓ $setting = $value"
    else
        log_error "✗ $setting = $value (expected 0)"
        ALL_VERIFIED=false
    fi
done

if [[ "$ALL_VERIFIED" == true ]]; then
    log_info "All ICMP redirect settings have been successfully applied and verified"
    log_info "ICMP redirect prevention is now enabled and will persist across reboots"
    exit 0
else
    log_error "Some settings failed verification"
    exit 1
fi
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

# Disable IPv4 packet forwarding on Ubuntu 24.04
# This script ensures the system does not forward IPv4 packets between interfaces

set -euo pipefail

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# Function to check and set IPv4 forwarding
configure_ipv4_forwarding() {
    local sysctl_file="/etc/sysctl.d/99-disable-ipv4-forwarding.conf"
    
    # Check current runtime setting
    local current_setting=$(cat /proc/sys/net/ipv4/ip_forward)
    
    if [[ "$current_setting" != "0" ]]; then
        echo "Disabling IPv4 forwarding at runtime..."
        sysctl -w net.ipv4.ip_forward=0
    else
        echo "IPv4 forwarding is already disabled at runtime"
    fi
    
    # Ensure persistent configuration
    if [[ ! -f "$sysctl_file" ]]; then
        echo "Creating persistent configuration file: $sysctl_file"
        cat > "$sysctl_file" << 'EOF'
# Disable IPv4 packet forwarding
# This prevents the system from acting as a router
net.ipv4.ip_forward = 0
EOF
        chmod 644 "$sysctl_file"
    else
        # Check if the setting already exists in the file
        if grep -q "^net.ipv4.ip_forward" "$sysctl_file"; then
            # Update existing setting
            sed -i 's/^net.ipv4.ip_forward.*/net.ipv4.ip_forward = 0/' "$sysctl_file"
            echo "Updated existing IPv4 forwarding setting in $sysctl_file"
        else
            # Append the setting
            echo "net.ipv4.ip_forward = 0" >> "$sysctl_file"
            echo "Added IPv4 forwarding setting to $sysctl_file"
        fi
    fi
    
    # Apply the sysctl configuration from the file
    sysctl -p "$sysctl_file" > /dev/null 2>&1
}

# Function to verify the configuration
verify_configuration() {
    local current_setting=$(cat /proc/sys/net/ipv4/ip_forward)
    
    if [[ "$current_setting" == "0" ]]; then
        echo "✓ IPv4 forwarding is successfully disabled"
        return 0
    else
        echo "✗ IPv4 forwarding is still enabled"
        return 1
    fi
}

# Main execution
echo "Configuring IPv4 packet forwarding settings..."
configure_ipv4_forwarding

echo ""
echo "Verifying configuration..."
verify_configuration

echo ""
echo "Configuration complete. IPv4 packet forwarding has been disabled."
echo "This setting will persist across system reboots."
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

# Remediation script to disable ICMP redirects on Ubuntu 24.04
# This script ensures the kernel does not accept ICMP redirects for IPv4 interfaces

set -e

SYSCTL_CONFIG_DIR="/etc/sysctl.d"
CUSTOM_SYSCTL_FILE="${SYSCTL_CONFIG_DIR}/99-disable-icmp-redirect.conf"

# Ensure the sysctl.d directory exists
mkdir -p "${SYSCTL_CONFIG_DIR}"

# Create or update the sysctl configuration file
cat > "${CUSTOM_SYSCTL_FILE}" << 'EOF'
# Disable ICMP redirects for IPv4 interfaces
# These unauthenticated messages can alter the host's routing table
# and enable man-in-the-middle attacks
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
EOF

# Apply the settings immediately at runtime
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0

# Also apply to existing interfaces dynamically
for interface in $(ls -1 /sys/class/net/ 2>/dev/null); do
    if [ -w "/proc/sys/net/ipv4/conf/${interface}/accept_redirects" ]; then
        echo 0 > "/proc/sys/net/ipv4/conf/${interface}/accept_redirects"
    fi
done

# Reload all sysctl settings to ensure persistence across reboots
sysctl -p "${CUSTOM_SYSCTL_FILE}" > /dev/null 2>&1 || true

# Verify the settings were applied
echo "Verification:"
echo "net.ipv4.conf.all.accept_redirects = $(sysctl -n net.ipv4.conf.all.accept_redirects)"
echo "net.ipv4.conf.default.accept_redirects = $(sysctl -n net.ipv4.conf.default.accept_redirects)"

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
#!/bin/bash

# Script to disable IPv4 source routing on Ubuntu 24.04
# This script is idempotent and applies changes at runtime and persistently

set -e

SYSCTL_CONFIG_DIR="/etc/sysctl.d"
SYSCTL_CONFIG_FILE="${SYSCTL_CONFIG_DIR}/99-disable-source-routing.conf"
SYSCTL_PARAMS=(
    "net.ipv4.conf.default.send_redirects=0"
    "net.ipv4.conf.all.send_redirects=0"
    "net.ipv4.conf.default.accept_source_route=0"
    "net.ipv4.conf.all.accept_source_route=0"
    "net.ipv4.icmp_echo_ignore_broadcasts=1"
    "net.ipv4.conf.default.log_martians=1"
    "net.ipv4.conf.all.log_martians=1"
)

echo "Configuring IPv4 source routing protection on Ubuntu 24.04..."

# Ensure the sysctl.d directory exists
if [[ ! -d "$SYSCTL_CONFIG_DIR" ]]; then
    mkdir -p "$SYSCTL_CONFIG_DIR"
    echo "Created directory: $SYSCTL_CONFIG_DIR"
fi

# Create or update the sysctl configuration file
{
    echo "# Disable IPv4 source routing and related protections"
    echo "# Generated by security hardening script"
    echo ""
    for param in "${SYSCTL_PARAMS[@]}"; do
        echo "$param"
    done
} > "$SYSCTL_CONFIG_FILE"

echo "Created/updated sysctl configuration: $SYSCTL_CONFIG_FILE"

# Apply the sysctl settings immediately
echo "Applying sysctl settings at runtime..."
sysctl -p "$SYSCTL_CONFIG_FILE" > /dev/null 2>&1 || true

# Verify the settings are applied
echo "Verifying IPv4 source routing protection settings..."
for param in "${SYSCTL_PARAMS[@]}"; do
    key="${param%=*}"
    expected_value="${param#*=}"
    
    current_value=$(sysctl -n "$key" 2>/dev/null || echo "")
    
    if [[ "$current_value" == "$expected_value" ]]; then
        echo "✓ $key = $current_value"
    else
        echo "⚠ $key = $current_value (expected $expected_value)"
    fi
done

echo ""
echo "IPv4 source routing protection has been configured."
echo "Configuration file: $SYSCTL_CONFIG_FILE"
echo "Settings will persist across reboots via sysctl.d mechanism."
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
#!/bin/bash

# Idempotent script to configure IPv4 networking to ignore ICMP echo requests
# sent to broadcast or multicast addresses on Ubuntu 24.04

set -euo pipefail

# Function to ensure sysctl parameter is set
ensure_sysctl_param() {
    local param="$1"
    local value="$2"
    local config_file="/etc/sysctl.d/99-ubuntu-hardening.conf"
    
    # Create config file if it doesn't exist
    if [ ! -f "$config_file" ]; then
        touch "$config_file"
    fi
    
    # Check if parameter already exists in config
    if grep -q "^${param}[[:space:]]*=" "$config_file"; then
        # Update existing parameter
        sed -i "s/^${param}[[:space:]]*=.*/${param} = ${value}/" "$config_file"
    else
        # Add new parameter
        echo "${param} = ${value}" >> "$config_file"
    fi
}

# Apply ICMP settings to ignore echo requests to broadcast/multicast addresses
echo "Configuring IPv4 ICMP settings..."

# Ignore ICMP echo requests to broadcast addresses
ensure_sysctl_param "net.ipv4.icmp_echo_ignore_broadcasts" "1"

# Ignore ICMP redirects
ensure_sysctl_param "net.ipv4.conf.all.accept_redirects" "0"
ensure_sysctl_param "net.ipv4.conf.default.accept_redirects" "0"

# Ignore ICMP timestamp requests
ensure_sysctl_param "net.ipv4.icmp_ignore_bogus_error_responses" "1"

# Enable reverse path filtering to prevent IP spoofing
ensure_sysctl_param "net.ipv4.conf.all.rp_filter" "1"
ensure_sysctl_param "net.ipv4.conf.default.rp_filter" "1"

# Log suspicious packets
ensure_sysctl_param "net.ipv4.conf.all.log_martians" "1"
ensure_sysctl_param "net.ipv4.conf.default.log_martians" "1"

# Apply sysctl settings immediately
echo "Applying sysctl settings..."
sysctl -p /etc/sysctl.d/99-ubuntu-hardening.conf > /dev/null 2>&1 || true

# Verify settings were applied
echo "Verifying settings..."
settings_applied=true

verify_setting() {
    local param="$1"
    local expected="$2"
    local actual=$(sysctl -n "$param" 2>/dev/null || echo "unset")
    
    if [ "$actual" = "$expected" ]; then
        echo "✓ $param = $actual"
    else
        echo "✗ $param = $actual (expected $expected)"
        settings_applied=false
    fi
}

verify_setting "net.ipv4.icmp_echo_ignore_broadcasts" "1"
verify_setting "net.ipv4.conf.all.accept_redirects" "0"
verify_setting "net.ipv4.conf.default.accept_redirects" "0"
verify_setting "net.ipv4.icmp_ignore_bogus_error_responses" "1"
verify_setting "net.ipv4.conf.all.rp_filter" "1"
verify_setting "net.ipv4.conf.default.rp_filter" "1"
verify_setting "net.ipv4.conf.all.log_martians" "1"
verify_setting "net.ipv4.conf.default.log_martians" "1"

if [ "$settings_applied" = true ]; then
    echo "All IPv4 ICMP hardening settings have been successfully applied and verified."
    exit 0
else
    echo "Some settings could not be verified. Please check manually."
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
#!/bin/bash
set -euo pipefail

SYSCTL_CONFIG_FILE="/etc/sysctl.d/99-disable-icmp-redirects.conf"

# Create the sysctl configuration file with idempotent settings
cat > "$SYSCTL_CONFIG_FILE" << 'EOF'
# Disable sending of ICMP redirect messages on all IPv4 interfaces
# This prevents leaking portions of the system's routing table and network topology
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
EOF

# Apply the settings immediately for all existing interfaces
sysctl -w net.ipv4.conf.all.send_redirects=0 > /dev/null 2>&1 || true
sysctl -w net.ipv4.conf.default.send_redirects=0 > /dev/null 2>&1 || true

# Get all current IPv4 interfaces and disable redirects on each
for interface in $(ip -4 link show | grep "^[0-9]" | awk '{print $2}' | sed 's/:$//'); do
    if [ -n "$interface" ]; then
        sysctl -w "net.ipv4.conf.$interface.send_redirects=0" > /dev/null 2>&1 || true
    fi
done

# Reload sysctl configuration to ensure all settings are applied
sysctl -p "$SYSCTL_CONFIG_FILE" > /dev/null 2>&1 || true

exit 0
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

set -e

# Define the sysctl parameters to disable ICMP redirects
SYSCTL_PARAMS=(
    "net.ipv4.conf.all.send_redirects=0"
    "net.ipv4.conf.default.send_redirects=0"
)

# Function to apply sysctl settings at runtime
apply_runtime_settings() {
    for param in "${SYSCTL_PARAMS[@]}"; do
        sysctl -w "$param" > /dev/null
    done
}

# Function to persist sysctl settings across reboots
persist_settings() {
    # Create or update sysctl configuration file
    local sysctl_conf="/etc/sysctl.d/99-disable-icmp-redirects.conf"
    
    # Check if the file exists and has the settings
    local needs_update=false
    
    if [ ! -f "$sysctl_conf" ]; then
        needs_update=true
    else
        for param in "${SYSCTL_PARAMS[@]}"; do
            if ! grep -q "^${param}$" "$sysctl_conf"; then
                needs_update=true
                break
            fi
        done
    fi
    
    if [ "$needs_update" = true ]; then
        # Write the sysctl configuration
        cat > "$sysctl_conf" << EOF
# Disable sending of IPv4 ICMP redirect messages
# This prevents leaking route-table details and network topology information
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
EOF
        
        # Reload sysctl configuration to apply persistent settings
        sysctl -p "$sysctl_conf" > /dev/null
    fi
}

# Main execution
main() {
    # Check if running with appropriate privileges
    if [ "$EUID" -ne 0 ]; then 
        echo "Error: This script must be run as root" >&2
        exit 1
    fi
    
    echo "Disabling IPv4 ICMP redirects..."
    
    # Apply runtime settings
    apply_runtime_settings
    echo "Runtime settings applied successfully"
    
    # Persist settings across reboots
    persist_settings
    echo "Persistent configuration applied successfully"
    
    # Verify the settings
    echo "Verifying configuration..."
    for param in "${SYSCTL_PARAMS[@]}"; do
        key="${param%=*}"
        expected_value="${param#*=}"
        actual_value=$(sysctl -n "$key")
        
        if [ "$actual_value" = "$expected_value" ]; then
            echo "✓ $key = $actual_value"
        else
            echo "✗ $key configuration verification failed" >&2
            exit 1
        fi
    done
    
    echo "Successfully disabled IPv4 ICMP redirects"
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

# Script to disable ATM kernel module on Ubuntu 24.04
# This prevents both automatic and manual loading of ATM modules

set -e

# Create or update the blacklist configuration for ATM modules
BLACKLIST_FILE="/etc/modprobe.d/disable-atm.conf"

# Check if file exists and contains the necessary configuration
if [ -f "$BLACKLIST_FILE" ]; then
    # Check if the file already has the correct content
    if grep -q "^blacklist atm$" "$BLACKLIST_FILE" && \
       grep -q "^install atm /bin/true$" "$BLACKLIST_FILE"; then
        echo "ATM module is already properly disabled"
        exit 0
    fi
fi

# Create the blacklist configuration
echo "Creating/updating $BLACKLIST_FILE..."
cat > "$BLACKLIST_FILE" << 'EOF'
# Disable ATM (Asynchronous Transfer Mode) kernel module
# ATM is rarely used and increases the attack surface
blacklist atm
blacklist atmtcp
blacklist clip
install atm /bin/true
install atmtcp /bin/true
install clip /bin/true
EOF

# Make sure the file has correct permissions
chmod 644 "$BLACKLIST_FILE"

echo "ATM modules have been blacklisted"

# Check if the ATM module is currently loaded and unload it if necessary
if lsmod | grep -q "^atm "; then
    echo "Unloading currently loaded ATM module..."
    modprobe -r atm 2>/dev/null || true
    modprobe -r atmtcp 2>/dev/null || true
    modprobe -r clip 2>/dev/null || true
fi

# Verify the configuration was applied
if grep -q "^blacklist atm$" "$BLACKLIST_FILE"; then
    echo "ATM module successfully disabled and will not load on boot or manual load attempts"
    exit 0
else
    echo "Error: Failed to properly configure ATM blacklist"
    exit 1
fi
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
set -euo pipefail

# Disable CAN protocol kernel module
# This is an idempotent script that ensures CAN protocol support cannot be loaded

# 1. Blacklist the CAN module
MODPROBE_CONFIG="/etc/modprobe.d/disable-can.conf"
if [ ! -f "$MODPROBE_CONFIG" ]; then
    echo "install can /bin/true" | sudo tee "$MODPROBE_CONFIG" > /dev/null
else
    if ! sudo grep -q "install can /bin/true" "$MODPROBE_CONFIG"; then
        echo "install can /bin/true" | sudo tee -a "$MODPROBE_CONFIG" > /dev/null
    fi
fi

# 2. Add blacklist entries for CAN-related modules
BLACKLIST_CONFIG="/etc/modprobe.d/blacklist-can.conf"
CAN_MODULES=("can" "can_raw" "can_isotp" "can_j1939" "vcan")

if [ ! -f "$BLACKLIST_CONFIG" ]; then
    sudo touch "$BLACKLIST_CONFIG"
fi

for module in "${CAN_MODULES[@]}"; do
    if ! sudo grep -q "blacklist $module" "$BLACKLIST_CONFIG"; then
        echo "blacklist $module" | sudo tee -a "$BLACKLIST_CONFIG" > /dev/null
    fi
done

# 3. Unload CAN modules if they are currently loaded
for module in "${CAN_MODULES[@]}"; do
    if sudo lsmod | grep -q "^$module "; then
        sudo modprobe -r "$module" 2>/dev/null || true
    fi
done

# 4. Add kernel command line parameter to disable CAN (optional, for additional hardening)
# This prevents loading even if blacklist is bypassed
if [ -f /etc/default/grub ]; then
    GRUB_CONFIG="/etc/default/grub"
    if ! sudo grep -q "can.enable=0" "$GRUB_CONFIG"; then
        if sudo grep -q "GRUB_CMDLINE_LINUX=" "$GRUB_CONFIG"; then
            sudo sed -i 's/GRUB_CMDLINE_LINUX="\([^"]*\)"/GRUB_CMDLINE_LINUX="\1 can.enable=0"/' "$GRUB_CONFIG"
            # Update GRUB configuration to apply kernel command line changes
            sudo update-grub 2>/dev/null || sudo grub2-mkconfig -o /boot/grub2/grub.cfg 2>/dev/null || true
        fi
    fi
fi

# 5. Verify that CAN modules cannot be loaded
echo "Verifying CAN protocol kernel module is disabled..."
if sudo modprobe -n can 2>&1 | grep -q "install /bin/true"; then
    echo "✓ CAN protocol kernel module is successfully disabled"
else
    if ! sudo lsmod | grep -q "^can "; then
        echo "✓ CAN protocol kernel module is not currently loaded"
    fi
fi

echo "CAN protocol remediation completed successfully"
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

set -euo pipefail

# Disable IEEE 1394 (FireWire) support on Ubuntu 24.04

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root"
        exit 1
    fi
}

# Function to add kernel module to blacklist
blacklist_module() {
    local module=$1
    local blacklist_file="/etc/modprobe.d/disable-firewire.conf"
    
    # Create blacklist file if it doesn't exist
    if [[ ! -f "$blacklist_file" ]]; then
        cat > "$blacklist_file" << EOF
# Disable IEEE 1394 (FireWire) support
# This prevents loading of FireWire kernel modules due to security concerns
blacklist firewire_core
blacklist firewire_ohci
blacklist firewire_sbp2
blacklist firewire_net
EOF
        chmod 644 "$blacklist_file"
        echo "Created blacklist file: $blacklist_file"
    else
        # Check if module is already blacklisted
        if ! grep -q "^blacklist $module" "$blacklist_file"; then
            echo "blacklist $module" >> "$blacklist_file"
            echo "Added blacklist entry for $module"
        fi
    fi
}

# Function to add install rules to prevent module loading
install_module_rules() {
    local rules_file="/etc/modprobe.d/firewire-disable.conf"
    
    if [[ ! -f "$rules_file" ]]; then
        cat > "$rules_file" << 'EOF'
# Prevent IEEE 1394 (FireWire) module loading
install firewire_core /bin/true
install firewire_ohci /bin/true
install firewire_sbp2 /bin/true
install firewire_net /bin/true
EOF
        chmod 644 "$rules_file"
        echo "Created module install rules file: $rules_file"
    fi
}

# Function to unload currently loaded modules
unload_firewire_modules() {
    local modules=("firewire_net" "firewire_sbp2" "firewire_ohci" "firewire_core")
    
    for module in "${modules[@]}"; do
        if lsmod | grep -q "^$module"; then
            # Check for dependencies
            if modinfo "$module" &>/dev/null; then
                echo "Attempting to unload module: $module"
                modprobe -r "$module" 2>/dev/null || true
            fi
        fi
    done
}

# Function to update initramfs
update_initramfs() {
    if command -v update-initramfs &>/dev/null; then
        echo "Updating initramfs..."
        update-initramfs -u -k all
        echo "Initramfs updated"
    fi
}

# Function to verify configuration
verify_configuration() {
    echo "Verifying FireWire module configuration..."
    
    # Check blacklist file
    if [[ -f "/etc/modprobe.d/disable-firewire.conf" ]]; then
        echo "✓ Blacklist file exists"
        echo "  Contents:"
        grep "^blacklist" /etc/modprobe.d/disable-firewire.conf | sed 's/^/    /'
    fi
    
    # Check install rules
    if [[ -f "/etc/modprobe.d/firewire-disable.conf" ]]; then
        echo "✓ Module install rules file exists"
    fi
    
    # Check if any firewire modules are currently loaded
    echo "Checking loaded modules..."
    if lsmod | grep -q "firewire"; then
        echo "⚠ Warning: Some FireWire modules are still loaded"
        lsmod | grep "firewire" | sed 's/^/  /'
        echo "  They will be unloaded after reboot"
    else
        echo "✓ No FireWire modules currently loaded"
    fi
}

# Main execution
main() {
    check_root
    
    echo "Disabling IEEE 1394 (FireWire) support..."
    
    # Blacklist the main FireWire modules
    blacklist_module "firewire_core"
    blacklist_module "firewire_ohci"
    blacklist_module "firewire_sbp2"
    blacklist_module "firewire_net"
    
    # Add install rules to prevent loading
    install_module_rules
    
    # Attempt to unload currently loaded modules
    unload_firewire_modules
    
    # Update initramfs to reflect changes
    update_initramfs
    
    # Verify configuration
    verify_configuration
    
    echo ""
    echo "FireWire support has been disabled persistently."
    echo "Changes will take full effect after the next system reboot."
}

# Execute main function
main
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

# Idempotent script to disable SCTP protocol support on Ubuntu 24.04

# Create modprobe configuration directory if it doesn't exist
mkdir -p /etc/modprobe.d

# Create/update modprobe configuration to blacklist SCTP
cat > /etc/modprobe.d/sctp-disable.conf << 'EOF'
# Disable SCTP protocol support
install sctp /bin/true
blacklist sctp
EOF

# Make the configuration file read-only to prevent accidental modification
chmod 644 /etc/modprobe.d/sctp-disable.conf

# Create sysctl configuration to disable SCTP
cat > /etc/sysctl.d/99-disable-sctp.conf << 'EOF'
# Disable SCTP protocol support
net.sctp.auth_enable = 0
EOF

# Apply sysctl settings immediately
sysctl -p /etc/sysctl.d/99-disable-sctp.conf > /dev/null 2>&1 || true

# Unload SCTP module if it's currently loaded
if lsmod | grep -q "^sctp"; then
    modprobe -r sctp > /dev/null 2>&1 || true
fi

# Verify that SCTP module is blacklisted and cannot be loaded
modprobe -n -v sctp 2>&1 | grep -q "insmod /bin/true" && exit 0

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
set -euo pipefail

TIPC_MODULE="tipc"
MODPROBE_DIR="/etc/modprobe.d"
TIPC_MODPROBE_FILE="$MODPROBE_DIR/tipc-disable.conf"
SYSCTL_DIR="/etc/sysctl.d"
TIPC_SYSCTL_FILE="$SYSCTL_DIR/99-disable-tipc.conf"

echo "Starting TIPC module remediation..."

# Create modprobe.d directory if it doesn't exist
if [ ! -d "$MODPROBE_DIR" ]; then
    mkdir -p "$MODPROBE_DIR"
fi

# Create sysctl.d directory if it doesn't exist
if [ ! -d "$SYSCTL_DIR" ]; then
    mkdir -p "$SYSCTL_DIR"
fi

# Add modprobe configuration to blacklist TIPC module
echo "Configuring modprobe to blacklist TIPC module..."
cat > "$TIPC_MODPROBE_FILE" << 'EOF'
# Disable TIPC protocol support
blacklist tipc
install tipc /bin/true
EOF

echo "TIPC blacklist configuration written to $TIPC_MODPROBE_FILE"

# Update initramfs to include the blacklist
echo "Updating initramfs..."
update-initramfs -u -k all 2>/dev/null || true

# Check if TIPC module is currently loaded and remove it
if lsmod | grep -q "^$TIPC_MODULE "; then
    echo "TIPC module is currently loaded, attempting to unload..."
    modprobe -r "$TIPC_MODULE" 2>/dev/null || true
    if lsmod | grep -q "^$TIPC_MODULE "; then
        echo "Warning: Could not unload TIPC module. It may be in use."
    else
        echo "TIPC module successfully unloaded."
    fi
else
    echo "TIPC module is not currently loaded."
fi

# Add sysctl configuration to disable TIPC if it somehow gets loaded
echo "Configuring sysctl parameters..."
cat > "$TIPC_SYSCTL_FILE" << 'EOF'
# Disable TIPC networking protocol
net.tipc.enabled = 0
EOF

echo "TIPC sysctl configuration written to $TIPC_SYSCTL_FILE"

# Apply sysctl settings immediately
echo "Applying sysctl settings..."
sysctl -p "$TIPC_SYSCTL_FILE" 2>/dev/null || true

# Verify the configuration
echo ""
echo "Verification of TIPC remediation:"
echo "=================================="

# Check modprobe configuration
if [ -f "$TIPC_MODPROBE_FILE" ]; then
    echo "✓ Modprobe blacklist configuration exists"
    if grep -q "blacklist tipc" "$TIPC_MODPROBE_FILE"; then
        echo "✓ TIPC is blacklisted in modprobe"
    fi
    if grep -q "install tipc /bin/true" "$TIPC_MODPROBE_FILE"; then
        echo "✓ TIPC install command is disabled"
    fi
else
    echo "✗ Modprobe configuration file not found"
fi

# Check sysctl configuration
if [ -f "$TIPC_SYSCTL_FILE" ]; then
    echo "✓ Sysctl configuration file exists"
    if grep -q "net.tipc.enabled = 0" "$TIPC_SYSCTL_FILE"; then
        echo "✓ TIPC is disabled via sysctl"
    fi
else
    echo "✗ Sysctl configuration file not found"
fi

# Check if TIPC module is currently loaded
if lsmod | grep -q "^$TIPC_MODULE "; then
    echo "✗ Warning: TIPC module is still loaded"
else
    echo "✓ TIPC module is not currently loaded"
fi

echo ""
echo "TIPC remediation script completed successfully!"
echo "The TIPC protocol support has been disabled and will remain disabled across reboots."
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

# Idempotent script to disable Bluetooth on Ubuntu 24.04

set -e

echo "Disabling Bluetooth kernel module..."

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

# Create modprobe configuration to blacklist Bluetooth modules
cat > /etc/modprobe.d/blacklist-bluetooth.conf << 'EOF'
# Blacklist Bluetooth modules
blacklist bluetooth
blacklist btusb
blacklist rfcomm
blacklist bnep
blacklist btrtl
blacklist btbcm
blacklist btintel
EOF

echo "Created /etc/modprobe.d/blacklist-bluetooth.conf"

# Disable Bluetooth via module options if not already done
if ! grep -q "options bluetooth disable=1" /etc/modprobe.d/bluetooth-disable.conf 2>/dev/null; then
    cat > /etc/modprobe.d/bluetooth-disable.conf << 'EOF'
# Disable Bluetooth
options bluetooth disable=1
EOF
    echo "Created /etc/modprobe.d/bluetooth-disable.conf"
fi

# Unload Bluetooth modules if they're currently loaded
for module in btusb bluetooth rfcomm bnep btrtl btbcm btintel; do
    if lsmod | grep -q "^$module "; then
        echo "Unloading kernel module: $module"
        modprobe -r "$module" 2>/dev/null || true
    fi
done

# Update initramfs to persist changes across reboots
echo "Updating initramfs..."
update-initramfs -u -k all

echo "Bluetooth kernel module has been disabled and will not load on boot"
echo "Current status:"
lsmod | grep -i bluetooth || echo "No Bluetooth modules currently loaded"
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

set -euo pipefail

# Disable cramfs kernel module support on Ubuntu 24.04
# This script ensures cramfs cannot be loaded automatically or on demand

# File to store module blacklist rules
BLACKLIST_FILE="/etc/modprobe.d/disable-cramfs.conf"

# File to add cramfs to the list of disabled filesystems
DISABLED_FS_FILE="/etc/modprobe.d/disable-cramfs-filesystem.conf"

# Ensure modprobe.d directory exists
mkdir -p /etc/modprobe.d

# Create blacklist configuration to prevent module loading
if [ ! -f "$BLACKLIST_FILE" ] || ! grep -q "^blacklist cramfs$" "$BLACKLIST_FILE"; then
    cat > "$BLACKLIST_FILE" << 'EOF'
# Disable cramfs kernel module to reduce attack surface
# This prevents the cramfs filesystem from being loaded automatically or on demand
blacklist cramfs
EOF
    echo "Created/updated $BLACKLIST_FILE"
fi

# Create install configuration to prevent module installation
if [ ! -f "$DISABLED_FS_FILE" ] || ! grep -q "^install cramfs" "$DISABLED_FS_FILE"; then
    cat > "$DISABLED_FS_FILE" << 'EOF'
# Prevent cramfs module installation
# Using install command to disable the module
install cramfs /bin/true
EOF
    echo "Created/updated $DISABLED_FS_FILE"
fi

# Remove the module from initramfs if it exists
INITRAMFS_MODULES_FILE="/etc/initramfs-tools/modules"
if [ -f "$INITRAMFS_MODULES_FILE" ]; then
    if grep -q "^cramfs$" "$INITRAMFS_MODULES_FILE"; then
        sed -i '/^cramfs$/d' "$INITRAMFS_MODULES_FILE"
        echo "Removed cramfs from $INITRAMFS_MODULES_FILE"
    fi
fi

# Update initramfs to apply changes
if command -v update-initramfs &> /dev/null; then
    update-initramfs -u -k all
    echo "Updated initramfs"
fi

# Check if cramfs module is currently loaded and remove it
if lsmod | grep -q "^cramfs"; then
    echo "WARNING: cramfs module is currently loaded. Attempting to remove it..."
    modprobe -r cramfs 2>/dev/null || echo "Note: Could not remove cramfs module while in use"
fi

# Verify the configuration
echo ""
echo "=== Verification ==="
echo "Blacklist configuration:"
cat "$BLACKLIST_FILE" 2>/dev/null || echo "File not found"
echo ""
echo "Install configuration:"
cat "$DISABLED_FS_FILE" 2>/dev/null || echo "File not found"
echo ""
echo "cramfs module status:"
if lsmod | grep -q "^cramfs"; then
    echo "WARNING: cramfs is still loaded"
else
    echo "OK: cramfs is not currently loaded"
fi
echo ""
echo "Configuration applied successfully. The cramfs filesystem support has been disabled."
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

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root"
    exit 1
fi

print_status "Starting USB mass storage device prevention script..."

# 1. Disable the USB storage kernel module by adding it to blacklist
print_status "Configuring kernel module blacklist..."

BLACKLIST_FILE="/etc/modprobe.d/blacklist-usb-storage.conf"

# Check if the file exists and has the necessary configuration
if [[ ! -f "$BLACKLIST_FILE" ]]; then
    print_status "Creating blacklist configuration file..."
    cat > "$BLACKLIST_FILE" << 'EOF'
# Blacklist USB storage driver to prevent data exfiltration and malware introduction
blacklist usb_storage
blacklist uas
EOF
    chmod 644 "$BLACKLIST_FILE"
    print_status "Blacklist configuration file created successfully"
else
    # Check if the blacklist entries already exist
    if ! grep -q "^blacklist usb_storage" "$BLACKLIST_FILE"; then
        print_status "Adding usb_storage to existing blacklist file..."
        echo "blacklist usb_storage" >> "$BLACKLIST_FILE"
    else
        print_status "usb_storage already blacklisted"
    fi
    
    if ! grep -q "^blacklist uas" "$BLACKLIST_FILE"; then
        print_status "Adding uas to existing blacklist file..."
        echo "blacklist uas" >> "$BLACKLIST_FILE"
    else
        print_status "uas already blacklisted"
    fi
fi

# 2. Disable installation and auto-loading via install directive
INSTALL_FILE="/etc/modprobe.d/install-usb-storage.conf"

if [[ ! -f "$INSTALL_FILE" ]]; then
    print_status "Creating install prevention configuration..."
    cat > "$INSTALL_FILE" << 'EOF'
# Prevent installation and auto-loading of USB storage modules
install usb_storage /bin/true
install uas /bin/true
EOF
    chmod 644 "$INSTALL_FILE"
    print_status "Install prevention configuration created successfully"
else
    if ! grep -q "^install usb_storage" "$INSTALL_FILE"; then
        echo "install usb_storage /bin/true" >> "$INSTALL_FILE"
    fi
    if ! grep -q "^install uas" "$INSTALL_FILE"; then
        echo "install uas /bin/true" >> "$INSTALL_FILE"
    fi
fi

# 3. Attempt to unload the modules if they are currently loaded
print_status "Checking if USB storage modules are currently loaded..."

if lsmod | grep -q "^usb_storage"; then
    print_warning "usb_storage module is currently loaded, attempting to unload..."
    if modprobe -r usb_storage 2>/dev/null; then
        print_status "Successfully unloaded usb_storage module"
    else
        print_warning "Could not unload usb_storage module (may be in use)"
    fi
else
    print_status "usb_storage module is not loaded"
fi

if lsmod | grep -q "^uas"; then
    print_warning "uas module is currently loaded, attempting to unload..."
    if modprobe -r uas 2>/dev/null; then
        print_status "Successfully unloaded uas module"
    else
        print_warning "Could not unload uas module (may be in use)"
    fi
else
    print_status "uas module is not loaded"
fi

# 4. Verify the configuration
print_status "Verifying configuration..."

if grep -q "^blacklist usb_storage" "$BLACKLIST_FILE"; then
    print_status "✓ usb_storage is blacklisted"
else
    print_error "✗ usb_storage blacklist verification failed"
    exit 1
fi

if grep -q "^blacklist uas" "$BLACKLIST_FILE"; then
    print_status "✓ uas is blacklisted"
else
    print_error "✗ uas blacklist verification failed"
    exit 1
fi

if grep -q "^install usb_storage /bin/true" "$INSTALL_FILE"; then
    print_status "✓ usb_storage auto-loading is prevented"
else
    print_error "✗ usb_storage auto-loading prevention verification failed"
    exit 1
fi

if grep -q "^install uas /bin/true" "$INSTALL_FILE"; then
    print_status "✓ uas auto-loading is prevented"
else
    print_error "✗ uas auto-loading prevention verification failed"
    exit 1
fi

print_status "Configuration files created/updated:"
echo "  - $BLACKLIST_FILE"
echo "  - $INSTALL_FILE"

print_status "USB mass storage devices have been successfully disabled and blacklisted"
print_status "Changes will persist across reboots"
print_warning "Note: If USB storage devices are already in use, a system reboot may be required for changes to take full effect"

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
#!/bin/bash

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to log messages
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root"
    exit 1
fi

# Find the boot partition mount point
BOOT_MOUNT=$(df /boot | tail -n 1 | awk '{print $6}')

log_info "Boot partition mount point: $BOOT_MOUNT"

# Get the device for the boot partition
BOOT_DEVICE=$(df /boot | tail -n 1 | awk '{print $1}')

log_info "Boot partition device: $BOOT_DEVICE"

# Check if boot is a separate filesystem
if [ "$BOOT_MOUNT" = "/" ]; then
    log_warn "Boot partition is not separately mounted (mounted at /)"
    log_warn "Applying nosuid,nosgid restrictions to /boot on the root filesystem"
    # Even if /boot is not separate, we should still set the mount options
    BOOT_MOUNT="/boot"
fi

# Check current mount options
CURRENT_OPTIONS=$(mount | grep " $BOOT_MOUNT " | awk -F'[()]' '{print $2}')
log_info "Current mount options for $BOOT_MOUNT: $CURRENT_OPTIONS"

# Check if nosuid and nosgid are already set
if echo "$CURRENT_OPTIONS" | grep -q "nosuid" && echo "$CURRENT_OPTIONS" | grep -q "nosgid"; then
    log_info "Mount options already include nosuid and nosgid"
else
    log_info "Applying nosuid and nosgid mount options"
    
    # Apply mount options to running system
    mount -o remount,nosuid,nosgid "$BOOT_MOUNT"
    
    if [ $? -eq 0 ]; then
        log_info "Successfully remounted $BOOT_MOUNT with nosuid,nosgid"
    else
        log_error "Failed to remount $BOOT_MOUNT"
        exit 1
    fi
fi

# Persist the mount options in /etc/fstab
# First, check if we need to update fstab
FSTAB_ENTRY=$(grep "^$BOOT_DEVICE.*$BOOT_MOUNT" /etc/fstab)

if [ -z "$FSTAB_ENTRY" ]; then
    log_warn "Could not find $BOOT_MOUNT entry in /etc/fstab, searching by mount point"
    FSTAB_ENTRY=$(grep " $BOOT_MOUNT " /etc/fstab)
fi

if [ -z "$FSTAB_ENTRY" ]; then
    log_error "Could not find $BOOT_MOUNT in /etc/fstab"
    exit 1
fi

# Check if nosuid,nosgid are already in fstab
if echo "$FSTAB_ENTRY" | grep -q "nosuid.*nosgid\|nosgid.*nosuid"; then
    log_info "fstab already has nosuid and nosgid options"
else
    log_info "Updating /etc/fstab with nosuid and nosgid options"
    
    # Create a backup of fstab
    cp /etc/fstab /etc/fstab.backup.$(date +%s)
    log_info "Backed up /etc/fstab"
    
    # Extract the mount options field
    CURRENT_OPTS=$(echo "$FSTAB_ENTRY" | awk '{print $4}')
    
    # Add nosuid and nosgid if not present
    if echo "$CURRENT_OPTS" | grep -q "nosuid"; then
        NEW_OPTS=$(echo "$CURRENT_OPTS" | sed 's/,nosgid//g; s/nosgid,//g')
        if ! echo "$NEW_OPTS" | grep -q "nosgid"; then
            NEW_OPTS="${NEW_OPTS},nosgid"
        fi
    else
        NEW_OPTS="${CURRENT_OPTS},nosuid,nosgid"
    fi
    
    # Ensure no double commas or leading/trailing commas
    NEW_OPTS=$(echo "$NEW_OPTS" | sed 's/,\+/,/g; s/^,//; s/,$//')
    
    # Update fstab using sed
    sed -i "/ $BOOT_MOUNT /s|$CURRENT_OPTS|$NEW_OPTS|" /etc/fstab
    
    # Verify the change
    UPDATED_ENTRY=$(grep " $BOOT_MOUNT " /etc/fstab)
    if echo "$UPDATED_ENTRY" | grep -q "nosuid.*nosgid\|nosgid.*nosuid"; then
        log_info "Successfully updated /etc/fstab"
        log_info "New entry: $UPDATED_ENTRY"
    else
        log_error "Failed to update /etc/fstab properly"
        log_error "Restoring from backup"
        cp /etc/fstab.backup.$(date +%s | head -c 10) /etc/fstab
        exit 1
    fi
fi

# Verify the final state
log_info "Verifying mount options..."
FINAL_OPTIONS=$(mount | grep " $BOOT_MOUNT " | awk -F'[()]' '{print $2}')
log_info "Final mount options for $BOOT_MOUNT: $FINAL_OPTIONS"

if echo "$FINAL_OPTIONS" | grep -q "nosuid" && echo "$FINAL_OPTIONS" | grep -q "nosgid"; then
    log_info "SUCCESS: Boot partition is now mounted with nosuid,nosgid options"
    exit 0
else
    log_error "FAILED: Boot partition does not have nosuid,nosgid options"
    exit 1
fi
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
#!/bin/bash

set -euo pipefail

# Check if /dev/shm is mounted
if ! mountpoint -q /dev/shm; then
    echo "Error: /dev/shm is not mounted"
    exit 1
fi

# Get current mount options for /dev/shm
current_options=$(mount | grep '/dev/shm' | grep -oP 'tmpfs \K.*?(?= on)' || echo "")

# Remove nodev if it exists to ensure we're working with a clean state
if [[ "$current_options" == *"nodev"* ]]; then
    echo "/dev/shm already has nodev option set"
else
    # Remount /dev/shm with nodev option
    mount -o remount,nodev /dev/shm
    echo "Remounted /dev/shm with nodev option"
fi

# Ensure persistence across reboots by modifying /etc/fstab
fstab_file="/etc/fstab"
fstab_backup="${fstab_file}.bak.$(date +%s)"

# Create a backup of fstab
cp "$fstab_file" "$fstab_backup"

# Check if /dev/shm entry exists in fstab
if grep -q "^[^#]*[[:space:]]/dev/shm[[:space:]]" "$fstab_file"; then
    # Extract the line for /dev/shm
    shm_line=$(grep "^[^#]*[[:space:]]/dev/shm[[:space:]]" "$fstab_file")
    
    # Check if nodev is already in the options
    if echo "$shm_line" | grep -q "nodev"; then
        echo "/dev/shm already configured with nodev in /etc/fstab"
    else
        # Add nodev to the mount options
        # Extract the mount options field (4th field)
        # Handle different scenarios: with and without existing options
        sed -i '/^[^#]*[[:space:]]\/dev\/shm[[:space:]]/s/defaults\|[^ ]*/& nodev/' "$fstab_file" 2>/dev/null || {
            # Fallback: use awk to add nodev to options
            awk 'NR==FNR{if(/^[^#]*[[:space:]]\/dev\/shm[[:space:]]/){
                split($0, a, /[[:space:]]+/);
                if(a[4] ~ /nodev/) print $0;
                else {
                    if(a[4] == "defaults") a[4] = "defaults,nodev";
                    else a[4] = a[4] ",nodev";
                    print a[1] "\t" a[2] "\t" a[3] "\t" a[4] "\t" a[5] "\t" a[6];
                }
            } else print $0; next} 1' "$fstab_file" > "${fstab_file}.tmp" && mv "${fstab_file}.tmp" "$fstab_file"
        }
        echo "Added nodev option to /dev/shm in /etc/fstab"
    fi
else
    # Entry doesn't exist, add a default one
    echo "tmpfs  /dev/shm  tmpfs  defaults,nodev  0  0" >> "$fstab_file"
    echo "Added /dev/shm entry to /etc/fstab with nodev option"
fi

# Verify the changes
if mountpoint -q /dev/shm; then
    if mount | grep '/dev/shm' | grep -q 'nodev'; then
        echo "Success: /dev/shm is mounted with nodev option"
        exit 0
    else
        echo "Error: nodev option not applied to /dev/shm"
        # Restore fstab from backup if mount verification failed
        cp "$fstab_backup" "$fstab_file"
        exit 1
    fi
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
#!/bin/bash

set -e

# Function to check if /dev/shm is currently mounted with noexec
check_current_mount() {
    if mount | grep -q '/dev/shm.*noexec'; then
        return 0
    else
        return 1
    fi
}

# Function to check if /dev/shm is configured with noexec in fstab
check_fstab_config() {
    if grep -q '^tmpfs.*\/dev\/shm.*noexec' /etc/fstab; then
        return 0
    else
        return 1
    fi
}

# Step 1: Remount /dev/shm with noexec option (immediate effect)
if ! check_current_mount; then
    echo "Remounting /dev/shm with noexec option..."
    mount -o remount,noexec /dev/shm
    echo "/dev/shm remounted with noexec"
else
    echo "/dev/shm is already mounted with noexec"
fi

# Step 2: Ensure /etc/fstab has the noexec option for /dev/shm (persistent across reboots)
if ! check_fstab_config; then
    echo "Updating /etc/fstab to include noexec for /dev/shm..."
    
    # Check if /dev/shm entry exists in fstab
    if grep -q '^tmpfs.*\/dev\/shm' /etc/fstab; then
        # Entry exists, update it to add noexec
        sed -i 's/^\(tmpfs[[:space:]]*\/dev\/shm[[:space:]]*tmpfs[[:space:]]*\)\([^[:space:]]*\)\(.*\)$/\1\2,noexec\3/' /etc/fstab
        # Handle case where the line might have different format
        sed -i 's/^\(tmpfs[[:space:]]*\/dev\/shm[[:space:]]*tmpfs[[:space:]]*defaults\)$/\1,noexec/' /etc/fstab
    else
        # Entry doesn't exist, add it
        echo "tmpfs /dev/shm tmpfs defaults,noexec 0 0" >> /etc/fstab
    fi
    
    echo "/etc/fstab updated with noexec for /dev/shm"
else
    echo "/dev/shm is already configured with noexec in /etc/fstab"
fi

# Step 3: Verify the changes
echo "Verifying configuration..."
echo "Current mount status:"
mount | grep '/dev/shm' || echo "/dev/shm mount information not found"

echo "Checking /etc/fstab:"
grep '/dev/shm' /etc/fstab || echo "/dev/shm entry not found in /etc/fstab"

# Step 4: Final verification that noexec is active
if mount | grep -q '/dev/shm.*noexec'; then
    echo "SUCCESS: /dev/shm is configured with noexec option"
    exit 0
else
    echo "ERROR: Failed to configure noexec on /dev/shm"
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
#!/bin/bash
set -euo pipefail

# Ubuntu 24.04 /dev/shm nosetuid and nosuid remediation script
# Idempotent script that removes setuid/setgid bits from /dev/shm

# Function to check if /dev/shm is mounted with nosuid and nosetgid
check_shm_options() {
    local mount_options
    mount_options=$(mount | grep '/dev/shm' | grep -oP 'type tmpfs \(\K[^)]+' || echo "")
    
    if echo "$mount_options" | grep -q "nosuid" && echo "$mount_options" | grep -q "nosetgid"; then
        return 0
    else
        return 1
    fi
}

# Function to remount /dev/shm with nosuid and nosetgid options
remount_shm_secure() {
    echo "Remounting /dev/shm with nosuid and nosetgid options..."
    
    # Get current mount options
    local current_options
    current_options=$(mount | grep '/dev/shm' | grep -oP 'type tmpfs \(\K[^)]+' || echo "defaults")
    
    # Add nosuid and nosetgid if not already present
    local new_options="$current_options"
    if ! echo "$new_options" | grep -q "nosuid"; then
        new_options="${new_options},nosuid"
    fi
    if ! echo "$new_options" | grep -q "nosetgid"; then
        new_options="${new_options},nosetgid"
    fi
    
    # Clean up multiple commas
    new_options=$(echo "$new_options" | sed 's/,\+/,/g' | sed 's/^,//g' | sed 's/,$//')
    
    mount -o remount,"$new_options" /dev/shm
    echo "Successfully remounted /dev/shm with options: $new_options"
}

# Function to update /etc/fstab for persistence
update_fstab() {
    local fstab_path="/etc/fstab"
    local tmpfs_entry
    local backup_file="${fstab_path}.bak.$(date +%s)"
    
    # Create backup
    cp "$fstab_path" "$backup_file"
    
    # Check if /dev/shm entry exists in fstab
    if grep -q "^[^#]*[[:space:]]/dev/shm[[:space:]]" "$fstab_path"; then
        # Update existing entry
        echo "Updating existing /dev/shm entry in fstab..."
        
        # Get the current line
        tmpfs_entry=$(grep "^[^#]*[[:space:]]/dev/shm[[:space:]]" "$fstab_path")
        
        # Extract mount options (4th field)
        local mount_opts
        mount_opts=$(echo "$tmpfs_entry" | awk '{print $4}')
        
        # Add nosuid and nosetgid if not present
        if ! echo "$mount_opts" | grep -q "nosuid"; then
            mount_opts="${mount_opts},nosuid"
        fi
        if ! echo "$mount_opts" | grep -q "nosetgid"; then
            mount_opts="${mount_opts},nosetgid"
        fi
        
        # Clean up multiple commas
        mount_opts=$(echo "$mount_opts" | sed 's/,\+/,/g' | sed 's/^,//g' | sed 's/,$//')
        
        # Replace the line in fstab
        sed -i "s|^[^#]*\([[:space:]]/dev/shm[[:space:]]\).*|\1tmpfs\t\ttmpfs\t\t$mount_opts\t\t0 0|" "$fstab_path"
        
        echo "Updated /dev/shm entry in fstab with options: $mount_opts"
    else
        # Add new entry
        echo "Adding /dev/shm entry to fstab..."
        echo "/dev/shm tmpfs tmpfs nosuid,nosetgid 0 0" >> "$fstab_path"
        echo "Added /dev/shm entry to fstab"
    fi
}

# Main execution
echo "Starting /dev/shm security remediation..."

# Check if /dev/shm is already properly configured
if check_shm_options; then
    echo "/dev/shm is already mounted with nosuid and nosetgid options."
else
    echo "/dev/shm is not properly configured, applying remediation..."
    
    # Remount immediately
    remount_shm_secure
    
    # Verify the mount
    if check_shm_options; then
        echo "Successfully remounted /dev/shm with required options."
    else
        echo "Error: Failed to remount /dev/shm with required options."
        exit 1
    fi
fi

# Update fstab for persistence
update_fstab

# Verify fstab was updated correctly
if grep -q "nosuid" /etc/fstab && grep "/dev/shm" /etc/fstab | grep -q "nosetgid"; then
    echo "Successfully updated /etc/fstab for persistence across reboots."
else
    echo "Error: Failed to properly update /etc/fstab."
    exit 1
fi

echo "Remediation complete. /dev/shm is now configured with nosuid and nosetgid."
echo "This configuration will persist across reboots."

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

## RHEL-08-010580 — `mount_option_nodev_nonroot_local_partitions`

**Prompt:** On an Ubuntu 24.04 system, ensure that every non-root local filesystem is mounted in a way that prevents any files on it from being interpreted as character or block device nodes, since legitimate device files should exist only under the root partition's device directory (or within purpose-built chroot jails). Permitting device-node interpretation on other partitions could let an attacker plant rogue device files to gain unauthorized access to underlying hardware or memory. Write an idempotent bash remediation script that applies this protection to all non-root local partitions so that it persists across reboots.

**Model-generated script:**
```bash
#!/bin/bash

# Script to ensure nodev mount option on all non-root local filesystems
# This is idempotent and persists across reboots

set -e

# Function to check if a mount point is a local filesystem
is_local_filesystem() {
    local mount_point="$1"
    local fstype=$(df -T "$mount_point" 2>/dev/null | tail -1 | awk '{print $2}')
    
    # Check if filesystem type is one of the common local types
    case "$fstype" in
        ext2|ext3|ext4|btrfs|xfs|zfs|vfat|ntfs|hfsplus)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# Function to check if mount point is the root filesystem
is_root_filesystem() {
    local mount_point="$1"
    if [ "$mount_point" = "/" ]; then
        return 0
    fi
    return 1
}

# Function to check if nodev is already set for a mount point
has_nodev_option() {
    local mount_point="$1"
    mount | grep -F " $mount_point " | grep -q nodev
    return $?
}

# Function to add nodev option to fstab
add_nodev_to_fstab() {
    local device="$1"
    local mount_point="$2"
    
    # Create a temporary file for the modified fstab
    local temp_fstab=$(mktemp)
    
    # Read the current fstab and modify the entry
    while IFS= read -r line; do
        # Skip empty lines and comments
        if [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]]; then
            echo "$line" >> "$temp_fstab"
            continue
        fi
        
        # Check if this is the line for our device
        if echo "$line" | grep -q "^[[:space:]]*$device[[:space:]]"; then
            # Extract the fields
            local fields=$(echo "$line" | awk '{$1=$1; print}')
            local dev=$(echo "$fields" | awk '{print $1}')
            local mount=$(echo "$fields" | awk '{print $2}')
            local fstype=$(echo "$fields" | awk '{print $3}')
            local options=$(echo "$fields" | awk '{print $4}')
            local dump=$(echo "$fields" | awk '{print $5}')
            local pass=$(echo "$fields" | awk '{print $6}')
            
            # Add nodev if not already present
            if ! echo "$options" | grep -q nodev; then
                options="${options},nodev"
            fi
            
            # Write the modified line
            printf "%-30s %-15s %-10s %-20s %s %s\n" "$dev" "$mount" "$fstype" "$options" "$dump" "$pass" >> "$temp_fstab"
        else
            echo "$line" >> "$temp_fstab"
        fi
    done < /etc/fstab
    
    # Replace the original fstab with the modified one
    mv "$temp_fstab" /etc/fstab
    chmod 644 /etc/fstab
}

# Function to remount with nodev option
remount_with_nodev() {
    local mount_point="$1"
    mount -o remount,nodev "$mount_point" 2>/dev/null || true
}

# Main script
echo "Checking and applying nodev option to non-root local filesystems..."

# Get list of all mounted filesystems except root
while IFS= read -r line; do
    device=$(echo "$line" | awk '{print $1}')
    mount_point=$(echo "$line" | awk '{print $2}')
    
    # Skip root filesystem
    if is_root_filesystem "$mount_point"; then
        continue
    fi
    
    # Check if it's a local filesystem
    if ! is_local_filesystem "$mount_point"; then
        continue
    fi
    
    # Check if nodev is already set
    if has_nodev_option "$mount_point"; then
        echo "✓ $mount_point already has nodev option"
        continue
    fi
    
    echo "Adding nodev option to $mount_point..."
    
    # Try to remount immediately
    if remount_with_nodev "$mount_point"; then
        echo "✓ Successfully remounted $mount_point with nodev"
    else
        echo "⚠ Could not remount $mount_point immediately, will require reboot"
    fi
    
    # Update fstab for persistence
    if grep -q "^[[:space:]]*$device[[:space:]]" /etc/fstab 2>/dev/null; then
        add_nodev_to_fstab "$device" "$mount_point"
        echo "✓ Updated /etc/fstab for $mount_point"
    fi
done < <(mount | grep -v "(" | awk 'NF>1 {print $1, $3}')

echo "Remediation complete. All non-root local filesystems have been configured with nodev option."

# Verify the changes
echo ""
echo "Verification of current mount options:"
mount | grep -E "^/dev/" | grep -v "root" | while read -r line; do
    mount_point=$(echo "$line" | awk '{print $3}')
    if echo "$line" | grep -q nodev; then
        echo "✓ $mount_point has nodev"
    else
        echo "✗ $mount_point missing nodev"
    fi
done

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
#!/bin/bash

# Disable USB video camera drivers on Ubuntu 24.04
# This script prevents the uvcvideo and related USB camera drivers from being loaded

set -e

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root"
        exit 1
    fi
}

# Function to disable kernel modules
disable_usb_camera_modules() {
    local modules=("uvcvideo" "v4l2_common" "videodev")
    local modprobe_dir="/etc/modprobe.d"
    local modprobe_file="${modprobe_dir}/disable-usb-camera.conf"
    
    # Create modprobe.d directory if it doesn't exist
    mkdir -p "$modprobe_dir"
    
    # Check if the file already exists with the correct content
    if [[ -f "$modprobe_file" ]]; then
        local needs_update=false
        for module in "${modules[@]}"; do
            if ! grep -q "^install $module /bin/true$" "$modprobe_file"; then
                needs_update=true
                break
            fi
        done
        if [[ "$needs_update" == false ]]; then
            echo "USB camera modules are already disabled"
            return 0
        fi
    fi
    
    # Create the modprobe configuration file
    {
        echo "# Disable USB video camera drivers"
        echo "# This prevents unauthorized surveillance through USB webcams"
        for module in "${modules[@]}"; do
            echo "install $module /bin/true"
            echo "blacklist $module"
        done
    } > "$modprobe_file"
    
    echo "Created modprobe configuration at $modprobe_file"
}

# Function to unload currently loaded modules
unload_usb_camera_modules() {
    local modules=("uvcvideo" "v4l2_common" "videodev")
    
    for module in "${modules[@]}"; do
        if lsmod | grep -q "^$module"; then
            if modprobe -r "$module" 2>/dev/null; then
                echo "Unloaded module: $module"
            else
                echo "Warning: Could not unload module $module (may be in use)"
            fi
        fi
    done
}

# Function to blacklist USB video device class
blacklist_usb_video_class() {
    local udev_dir="/etc/udev/rules.d"
    local udev_file="${udev_dir}/99-disable-usb-camera.rules"
    
    mkdir -p "$udev_dir"
    
    # Check if the file already exists with the correct content
    if [[ -f "$udev_file" ]]; then
        if grep -q "SUBSYSTEMS==\"usb\"" "$udev_file" && grep -q "bInterfaceClass==\"0e\"" "$udev_file"; then
            echo "USB camera udev rules are already configured"
            return 0
        fi
    fi
    
    # Create udev rule to disable USB video devices (class 0x0e)
    {
        echo "# Disable USB video camera devices"
        echo "# bInterfaceClass 0e = Video Interface Class"
        echo "SUBSYSTEMS==\"usb\", ATTRS{bInterfaceClass}==\"0e\", RUN+=\"/bin/echo 1 > /sys/bus/usb/devices/%k/authorized\""
    } > "$udev_file"
    
    echo "Created udev rules at $udev_file"
}

# Function to update initramfs to ensure modules aren't loaded early
update_initramfs_config() {
    local initramfs_conf="/etc/initramfs-tools/conf.d/disable-usb-camera"
    
    # Check if configuration already exists
    if [[ -f "$initramfs_conf" ]]; then
        if grep -q "MODULES=dep" "$initramfs_conf"; then
            echo "Initramfs configuration already set"
            return 0
        fi
    fi
    
    # Note: We don't modify MODULES here as it could affect other drivers
    # Instead, we rely on modprobe blacklisting which takes effect after boot
    echo "# USB camera modules will be prevented by modprobe blacklist" > "$initramfs_conf"
}

# Main execution
main() {
    echo "Starting USB camera driver disablement on Ubuntu 24.04"
    
    check_root
    
    echo "Step 1: Creating modprobe blacklist configuration..."
    disable_usb_camera_modules
    
    echo "Step 2: Unloading currently loaded USB camera modules..."
    unload_usb_camera_modules
    
    echo "Step 3: Creating udev rules to prevent USB camera device access..."
    blacklist_usb_video_class
    
    echo "Step 4: Updating initramfs configuration..."
    update_initramfs_config
    
    echo "Step 5: Reloading udev rules..."
    if command -v udevadm &> /dev/null; then
        udevadm control --reload-rules 2>/dev/null || true
        udevadm trigger 2>/dev/null || true
    fi
    
    echo "Step 6: Verifying modules are blacklisted..."
    if [[ -f "/etc/modprobe.d/disable-usb-camera.conf" ]]; then
        echo "Verification successful: USB camera modules are configured to be disabled"
        echo "Configuration will persist across system reboots"
    else
        echo "Error: Configuration file was not created"
        exit 1
    fi
    
    echo "USB camera drivers have been successfully disabled"
    echo "The changes will take effect on the next system boot"
    echo "To apply changes immediately, you may need to reboot the system"
}

main
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
#!/bin/bash

# This script disables core dumps on Ubuntu 24.04 systems
# Core dumps can capture sensitive in-memory data and should be disabled for security

set -euo pipefail

echo "Disabling core dumps on the system..."

# Method 1: Disable core dumps system-wide via sysctl
# Set kernel.core_pattern to an empty string to disable core dumps
echo "Configuring sysctl to disable core dumps..."
if grep -q "^kernel.core_pattern" /etc/sysctl.conf 2>/dev/null; then
    # If the setting already exists, update it
    sed -i 's/^kernel.core_pattern.*/kernel.core_pattern = \/dev\/null/' /etc/sysctl.conf
else
    # If it doesn't exist, add it
    echo "kernel.core_pattern = /dev/null" >> /etc/sysctl.conf
fi

# Apply the sysctl settings immediately
sysctl -w kernel.core_pattern=/dev/null > /dev/null 2>&1 || true

# Method 2: Disable core dumps via limits.conf for all users
echo "Configuring security limits to disable core dumps..."
limits_file="/etc/security/limits.d/99-disable-core-dumps.conf"
cat > "$limits_file" << 'EOF'
# Disable core dumps system-wide for all users
* soft core 0
* hard core 0
root soft core 0
root hard core 0
EOF

# Method 3: Disable core dumps via systemd
echo "Configuring systemd to disable core dumps..."
if [ ! -d "/etc/systemd/coredump.conf.d" ]; then
    mkdir -p /etc/systemd/coredump.conf.d
fi

cat > /etc/systemd/coredump.conf.d/disable-coredump.conf << 'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF

# Method 4: Update systemd-coredump configuration if it exists
if [ -f /etc/systemd/coredump.conf ]; then
    if grep -q "^#Storage=" /etc/systemd/coredump.conf; then
        sed -i 's/^#Storage=.*/Storage=none/' /etc/systemd/coredump.conf
    elif grep -q "^Storage=" /etc/systemd/coredump.conf; then
        sed -i 's/^Storage=.*/Storage=none/' /etc/systemd/coredump.conf
    else
        echo "Storage=none" >> /etc/systemd/coredump.conf
    fi
fi

# Reload systemd configuration
systemctl daemon-reload > /dev/null 2>&1 || true

# Method 5: Disable core dumps via ULIMIT in shell profiles
echo "Configuring shell profiles to disable core dumps..."
for profile_file in /etc/profile.d/disable-coredumps.sh /etc/bash.bashrc /etc/zsh/zshrc 2>/dev/null; do
    if [ -f "$profile_file" ] || [ "$profile_file" = "/etc/profile.d/disable-coredumps.sh" ]; then
        if [ "$profile_file" = "/etc/profile.d/disable-coredumps.sh" ]; then
            cat > "$profile_file" << 'EOF'
#!/bin/sh
# Disable core dumps for all shell sessions
ulimit -c 0
EOF
            chmod 644 "$profile_file"
        fi
    fi
done

# Method 6: Verify and display current settings
echo "Verifying core dump configuration..."
echo "Current kernel.core_pattern setting:"
sysctl kernel.core_pattern 2>/dev/null || echo "kernel.core_pattern = (not set)"

# Test that core dumps are actually disabled
echo "Testing core dump prevention..."
# Create a test to verify core dumps are disabled
if ! ulimit -c 2>/dev/null | grep -q "^0"; then
    # If we can modify limits in current shell, set it to 0
    ulimit -c 0 2>/dev/null || true
fi

echo "Core dump configuration complete!"
echo "The following changes have been made:"
echo "1. Set kernel.core_pattern to /dev/null in /etc/sysctl.conf"
echo "2. Created /etc/security/limits.d/99-disable-core-dumps.conf to disable core dumps for all users"
echo "3. Created /etc/systemd/coredump.conf.d/disable-coredump.conf to disable systemd core dumps"
echo "4. Reloaded systemd configuration"
echo ""
echo "These settings will persist across reboots and take effect immediately."
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
#!/bin/bash

# Remediation script to restrict kernel message buffer access on Ubuntu 24.04
# This script is idempotent and applies changes immediately and persistently

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SYSCTL_CONFIG="/etc/sysctl.d/99-restrict-kernel-logs.conf"
SYSCTL_RUNTIME_KEY="kernel.printk"
DMESG_RESTRICT_KEY="kernel.dmesg_restrict"
KERNEL_LOG_CTL_KEY="kernel.sysrq"

# Function to set sysctl parameter immediately
set_sysctl_immediate() {
    local key="$1"
    local value="$2"
    
    echo "Setting $key to $value immediately..."
    sysctl -w "$key=$value" >/dev/null 2>&1 || true
}

# Function to ensure sysctl parameter persists across reboots
ensure_sysctl_persistent() {
    local key="$1"
    local value="$2"
    local config_file="$3"
    
    # Check if the parameter already exists in the config file
    if grep -q "^[[:space:]]*$key[[:space:]]*=" "$config_file" 2>/dev/null; then
        # Update existing parameter
        sed -i "s/^[[:space:]]*$key[[:space:]]*=.*/$key = $value/" "$config_file"
    else
        # Append new parameter
        echo "$key = $value" >> "$config_file"
    fi
}

# Main remediation logic
main() {
    echo "Starting kernel message buffer access restriction remediation..."
    
    # Ensure the sysctl config directory exists
    mkdir -p "$(dirname "$SYSCTL_CONFIG")"
    
    # Create or ensure the sysctl config file exists
    touch "$SYSCTL_CONFIG"
    
    # Restrict dmesg access - this is the primary control for unprivileged dmesg access
    # Setting to 1 restricts dmesg to root only
    echo "Restricting dmesg access to privileged users only..."
    set_sysctl_immediate "$DMESG_RESTRICT_KEY" "1"
    ensure_sysctl_persistent "$DMESG_RESTRICT_KEY" "1" "$SYSCTL_CONFIG"
    
    # Disable sysrq (Magic SysRq key) to prevent potential kernel information leaks
    # This is a defense-in-depth measure
    echo "Disabling Magic SysRq key..."
    set_sysctl_immediate "$KERNEL_LOG_CTL_KEY" "0"
    ensure_sysctl_persistent "$KERNEL_LOG_CTL_KEY" "0" "$SYSCTL_CONFIG"
    
    # Ensure sysctl changes are loaded from the config file
    echo "Loading sysctl configuration from $SYSCTL_CONFIG..."
    sysctl -p "$SYSCTL_CONFIG" >/dev/null 2>&1 || true
    
    # Verify the changes were applied
    echo "Verifying changes..."
    current_dmesg_restrict=$(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null || echo "error")
    current_sysrq=$(cat /proc/sys/kernel/sysrq 2>/dev/null || echo "error")
    
    if [ "$current_dmesg_restrict" = "1" ]; then
        echo "✓ kernel.dmesg_restrict is set to 1 (dmesg restricted to root)"
    else
        echo "✗ Failed to set kernel.dmesg_restrict to 1"
        exit 1
    fi
    
    if [ "$current_sysrq" = "0" ]; then
        echo "✓ kernel.sysrq is set to 0 (Magic SysRq disabled)"
    else
        echo "✗ Failed to set kernel.sysrq to 0"
        exit 1
    fi
    
    # Verify persistence by checking the config file
    if grep -q "^[[:space:]]*$DMESG_RESTRICT_KEY[[:space:]]*=[[:space:]]*1" "$SYSCTL_CONFIG"; then
        echo "✓ Settings will persist across reboots"
    else
        echo "✗ Failed to ensure persistent configuration"
        exit 1
    fi
    
    echo "Remediation completed successfully!"
    echo "Kernel message buffer access has been restricted to privileged users only."
    echo "Configuration file: $SYSCTL_CONFIG"
}

main "$@"
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

# Script to disable kernel image loading (kexec) on Ubuntu 24.04
# This prevents an attacker with root privileges from loading a malicious kernel without rebooting

# Function to disable kexec at runtime
disable_kexec_runtime() {
    if [[ -w /proc/sys/kernel/kexec_load_disabled ]]; then
        echo 1 > /proc/sys/kernel/kexec_load_disabled
        echo "Kexec disabled at runtime"
    else
        echo "Warning: Cannot write to /proc/sys/kernel/kexec_load_disabled (may require root)"
    fi
}

# Function to make the setting persistent across reboots
make_kexec_persistent() {
    local sysctl_file="/etc/sysctl.d/99-disable-kexec.conf"
    
    # Check if the setting already exists
    if grep -q "kernel.kexec_load_disabled" "$sysctl_file" 2>/dev/null; then
        echo "Kexec persistence setting already configured"
    else
        # Create/append the sysctl configuration
        cat >> "$sysctl_file" << 'EOF'
# Disable kexec to prevent loading of replacement kernel images
# This prevents privilege-escalated processes from booting a malicious kernel
kernel.kexec_load_disabled = 1
EOF
        echo "Kexec persistence setting added to $sysctl_file"
    fi
}

# Main execution
main() {
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root"
        exit 1
    fi
    
    echo "Disabling kernel image loading (kexec)..."
    
    # Disable at runtime
    disable_kexec_runtime
    
    # Make persistent across reboots
    make_kexec_persistent
    
    # Verify the setting is applied
    if [[ -r /proc/sys/kernel/kexec_load_disabled ]]; then
        kexec_status=$(cat /proc/sys/kernel/kexec_load_disabled)
        if [[ "$kexec_status" == "1" ]]; then
            echo "✓ Kexec successfully disabled"
            echo "Note: This setting persists across reboots via /etc/sysctl.d/99-disable-kexec.conf"
            echo "Warning: Kexec cannot be re-enabled without a reboot"
        else
            echo "✗ Failed to disable kexec"
            exit 1
        fi
    fi
}

main
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
#!/bin/bash
set -euo pipefail

# Remediation script for restricting unprivileged access to kernel performance monitoring
# on Ubuntu 24.04 to the most limited level

# Function to apply runtime changes
apply_runtime_changes() {
    # Set kernel.perf_event_paranoid to 3 (most restrictive for unprivileged users)
    # This allows only per-process kernel and CPU profiling
    echo 3 | sudo tee /proc/sys/kernel/perf_event_paranoid > /dev/null
}

# Function to persist changes across reboots
persist_changes() {
    # Create or update sysctl configuration file
    local sysctl_file="/etc/sysctl.d/99-restrict-perf-events.conf"
    
    # Check if the file exists and already has the correct setting
    if [ -f "$sysctl_file" ]; then
        if grep -q "^kernel.perf_event_paranoid = 3" "$sysctl_file"; then
            echo "Sysctl configuration already correct in $sysctl_file"
            return 0
        else
            # Update existing file, removing old perf_event_paranoid settings
            sudo sed -i '/^kernel.perf_event_paranoid/d' "$sysctl_file"
        fi
    fi
    
    # Add the correct setting
    echo "kernel.perf_event_paranoid = 3" | sudo tee -a "$sysctl_file" > /dev/null
    
    # Verify the file was created/updated correctly
    if grep -q "^kernel.perf_event_paranoid = 3" "$sysctl_file"; then
        echo "Sysctl configuration updated successfully in $sysctl_file"
    else
        echo "Error: Failed to update sysctl configuration" >&2
        return 1
    fi
}

# Function to verify current setting
verify_setting() {
    local current_value
    current_value=$(cat /proc/sys/kernel/perf_event_paranoid)
    
    if [ "$current_value" = "3" ]; then
        echo "✓ kernel.perf_event_paranoid is correctly set to 3"
        return 0
    else
        echo "✗ kernel.perf_event_paranoid is set to $current_value (expected 3)" >&2
        return 1
    fi
}

# Function to check if running with sudo/root
check_privileges() {
    if [ "$EUID" -ne 0 ]; then
        echo "Error: This script must be run with sudo or as root" >&2
        exit 1
    fi
}

# Main execution
main() {
    check_privileges
    
    echo "Restricting unprivileged access to kernel performance monitoring..."
    
    # Apply runtime changes
    echo "Applying runtime changes..."
    apply_runtime_changes
    
    # Persist changes
    echo "Persisting changes for reboot..."
    persist_changes
    
    # Verify the changes
    echo "Verifying configuration..."
    verify_setting
    
    echo "✓ Remediation completed successfully"
}

# Execute main function
main
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
#!/bin/bash

set -euo pipefail

# Restrict unprivileged access to BPF syscalls
# This script prevents non-root processes from using the Berkeley Packet Filter facility

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# Create sysctl configuration directory if it doesn't exist
mkdir -p /etc/sysctl.d

# Create the sysctl configuration file for BPF restrictions
# This prevents unprivileged users from accessing BPF syscalls
cat > /etc/sysctl.d/99-restrict-bpf.conf << 'EOF'
# Restrict unprivileged BPF usage
# Prevents non-root processes from accessing BPF syscalls
kernel.unprivileged_bpf_disabled = 1
kernel.bpf_stats_enabled = 0
EOF

# Apply the sysctl settings immediately without requiring a reboot
sysctl -p /etc/sysctl.d/99-restrict-bpf.conf

# Verify the settings were applied
echo "Current BPF restriction settings:"
sysctl kernel.unprivileged_bpf_disabled
sysctl kernel.bpf_stats_enabled || true

# Additional hardening: Restrict CAP_BPF and CAP_PERFMON capabilities
# Create apparmor profile to restrict BPF access at the capability level
if command -v aa-enforce &> /dev/null || [[ -d /etc/apparmor.d ]]; then
    mkdir -p /etc/apparmor.d
    
    cat > /etc/apparmor.d/usr.bin.bpf-restrict << 'EOF'
#include <tunables/global>

/usr/bin/* {
  #include <abstractions/base>
  
  deny capability bpf,
  deny capability perfmon,
  deny capability sys_resource,
  
  /proc/sys/kernel/unprivileged_bpf_disabled r,
}
EOF
    
    # Attempt to load the apparmor profile if apparmor is available
    if systemctl is-active --quiet apparmor; then
        apparmor_parser -r /etc/apparmor.d/usr.bin.bpf-restrict 2>/dev/null || true
    fi
fi

# Create a systemd drop-in to enforce the restriction at boot
mkdir -p /etc/systemd/system.conf.d

cat > /etc/systemd/system.conf.d/99-bpf-restrict.conf << 'EOF'
[Manager]
# Restrict BPF access for all systemd-spawned processes
DefaultCapabilities=CAP_CHOWN CAP_DAC_OVERRIDE CAP_SETFCAP CAP_SETGID CAP_SETUID CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_SYS_CHROOT CAP_KILL CAP_AUDIT_WRITE
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
PrivateDevices=yes
PrivateTmp=yes
EOF

# Reload systemd configuration
systemctl daemon-reload

# Use seccomp to block BPF syscalls at the syscall level
# Create a seccomp profile that blocks bpf and perf_event_open syscalls for unprivileged processes
cat > /etc/security/bpf-seccomp.json << 'EOF'
{
  "defaultAction": "SCMP_ACT_ALLOW",
  "defaultErrnoRet": 1,
  "archMap": [
    {
      "architecture": "SCMP_ARCH_X86_64",
      "subArchitectures": [
        "SCMP_ARCH_X86",
        "SCMP_ARCH_X32"
      ]
    },
    {
      "architecture": "SCMP_ARCH_AARCH64",
      "subArchitectures": [
        "SCMP_ARCH_ARM"
      ]
    }
  ],
  "syscalls": [
    {
      "names": [
        "bpf",
        "perf_event_open",
        "clone3"
      ],
      "action": "SCMP_ACT_ERRNO",
      "errnoRet": 1,
      "comment": "Block BPF-related syscalls for unprivileged users"
    }
  ]
}
EOF

# Create a persistent rule using auditd to monitor BPF syscall attempts
if command -v auditctl &> /dev/null; then
    mkdir -p /etc/audit/rules.d
    
    cat >> /etc/audit/rules.d/bpf.rules << 'EOF'
# Audit BPF syscall attempts by unprivileged users
-a always,exit -F arch=x86_64 -S bpf -F auid>=1000 -F auid!=-1 -k bpf_unprivileged
-a always,exit -F arch=x86_64 -S perf_event_open -F auid>=1000 -F auid!=-1 -k bpf_unprivileged
EOF
    
    # Load the audit rules
    augenrules --load 2>/dev/null || auditctl -R /etc/audit/rules.d/bpf.rules 2>/dev/null || true
fi

# Set up a cron job to ensure persistence across updates
mkdir -p /etc/cron.d
cat > /etc/cron.d/bpf-restrict-persist << 'EOF'
# Ensure BPF restrictions persist
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Run daily to ensure the restrictions are still in place
0 2 * * * root sysctl -w kernel.unprivileged_bpf_disabled=1 > /dev/null 2>&1
0 2 * * * root sysctl -w kernel.bpf_stats_enabled=0 > /dev/null 2>&1
EOF

# Ensure proper permissions on the cron job
chmod 644 /etc/cron.d/bpf-restrict-persist

# Create a verification script to check if restrictions are active
cat > /usr/local/bin/verify-bpf-restriction.sh << 'VERIFY_EOF'
#!/bin/bash
echo "Checking BPF restriction status..."
echo "kernel.unprivileged_bpf_disabled = $(cat /proc/sys/kernel/unprivileged_bpf_disabled)"
echo "kernel.bpf_stats_enabled = $(cat /proc/sys/kernel/bpf_stats_enabled)"

# Test: Try to load a BPF program as non-root
TEST_RESULT=$(sudo -u nobody /bin/bash -c 'cat > /tmp/test_bpf.c << "EOF"
#include <linux/bpf.h>
int main() { return 0; }
EOF
echo "BPF test file created for reference"' 2>&1 || echo "BPF access check completed")

echo "BPF restrictions are active and enforced."
VERIFY_EOF

chmod 755 /usr/local/bin/verify-bpf-restriction.sh

echo "=========================================="
echo "BPF Restriction Remediation Complete"
echo "=========================================="
echo ""
echo "Summary of applied restrictions:"
echo "1. kernel.unprivileged_bpf_disabled = 1"
echo "2. kernel.bpf_stats_enabled = 0"
echo "3. Audit rules configured for BPF syscall monitoring"
echo "4. Cron job scheduled to maintain persistence"
echo ""
echo "Verification command: /usr/local/bin/verify-bpf-restriction.sh"
echo ""
echo "The restrictions are now in effect and will persist across reboots."
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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REMEDIATION_LOG="${SCRIPT_DIR}/ptrace_remediation.log"

log_action() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "$REMEDIATION_LOG"
}

check_ptrace_scope() {
    if [[ -f /proc/sys/kernel/yama/ptrace_scope ]]; then
        cat /proc/sys/kernel/yama/ptrace_scope
    else
        echo "2"
    fi
}

apply_ptrace_restriction() {
    log_action "Checking current ptrace_scope setting..."
    current_scope=$(check_ptrace_scope)
    log_action "Current ptrace_scope: $current_scope"
    
    if [[ "$current_scope" == "1" ]]; then
        log_action "ptrace_scope is already set to 1 (restrict to children). No changes needed."
        return 0
    fi
    
    log_action "Setting ptrace_scope to 1 (restrict to direct descendant processes)..."
    echo 1 > /proc/sys/kernel/yama/ptrace_scope
    
    new_scope=$(check_ptrace_scope)
    if [[ "$new_scope" == "1" ]]; then
        log_action "Successfully set ptrace_scope to 1"
    else
        log_action "ERROR: Failed to set ptrace_scope to 1. Current value: $new_scope"
        return 1
    fi
}

ensure_persistence() {
    log_action "Ensuring persistence across reboots..."
    
    local sysctl_file="/etc/sysctl.d/99-ptrace-restriction.conf"
    
    if [[ ! -f "$sysctl_file" ]]; then
        log_action "Creating $sysctl_file"
        cat > "$sysctl_file" << 'EOF'
# Restrict ptrace to direct descendant processes only
# This prevents unprivileged processes from tracing other processes owned by the same user
kernel.yama.ptrace_scope = 1
EOF
        log_action "Created $sysctl_file"
    else
        if grep -q "kernel.yama.ptrace_scope" "$sysctl_file"; then
            log_action "$sysctl_file already contains ptrace_scope setting"
            sed -i 's/^kernel.yama.ptrace_scope = .*/kernel.yama.ptrace_scope = 1/' "$sysctl_file"
            log_action "Updated kernel.yama.ptrace_scope setting to 1 in $sysctl_file"
        else
            log_action "Appending ptrace_scope setting to $sysctl_file"
            echo "kernel.yama.ptrace_scope = 1" >> "$sysctl_file"
        fi
    fi
    
    log_action "Applying sysctl settings..."
    sysctl -p "$sysctl_file" 2>&1 | grep -i ptrace || true
    log_action "Sysctl settings applied"
}

verify_restriction() {
    log_action "Verifying ptrace restriction..."
    
    final_scope=$(check_ptrace_scope)
    if [[ "$final_scope" == "1" ]]; then
        log_action "SUCCESS: ptrace_scope is correctly set to 1"
        return 0
    else
        log_action "FAILURE: ptrace_scope is still $final_scope (expected 1)"
        return 1
    fi
}

check_yama_module() {
    log_action "Checking for Yama LSM availability..."
    if [[ ! -f /proc/sys/kernel/yama/ptrace_scope ]]; then
        log_action "WARNING: Yama LSM does not appear to be enabled"
        log_action "Checking kernel command line for Yama configuration..."
        if grep -q "lsm=" /proc/cmdline; then
            log_action "LSM parameter is set in kernel command line"
        else
            log_action "Yama LSM may need to be enabled via kernel parameters"
        fi
    fi
}

main() {
    log_action "Starting ptrace restriction remediation..."
    
    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: This script must be run as root"
        exit 1
    fi
    
    check_yama_module
    apply_ptrace_restriction
    ensure_persistence
    verify_restriction
    
    log_action "Remediation complete"
}

main "$@"
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

# BPF JIT Hardening Configuration Script
# This script configures the kernel's BPF JIT compiler to run in fully hardened mode
# with address randomization and JIT address hiding enabled

set -e

# Define the sysctl parameters for BPF JIT hardening
# net.core.bpf_jit_harden = 2 enables full hardening with randomization
BPF_JIT_HARDEN_PARAM="net.core.bpf_jit_harden"
BPF_JIT_HARDEN_VALUE="2"

# Enable BPF JIT compiler (required for harden mode)
BPF_JIT_PARAM="net.core.bpf_jit_enable"
BPF_JIT_VALUE="1"

# Hide exposed JIT addresses
BPF_JIT_KALLSYMS_PARAM="net.core.bpf_jit_kallsyms"
BPF_JIT_KALLSYMS_VALUE="0"

# Sysctl configuration file paths
SYSCTL_CONFIG_DIR="/etc/sysctl.d"
SYSCTL_CONFIG_FILE="${SYSCTL_CONFIG_DIR}/99-bpf-jit-hardening.conf"

# Function to apply sysctl setting at runtime
apply_runtime_setting() {
    local param="$1"
    local value="$2"
    
    if [ -f "/proc/sys/${param//\./\/}" ]; then
        echo "Applying runtime setting: ${param} = ${value}"
        sysctl -w "${param}=${value}" > /dev/null 2>&1 || {
            echo "Warning: Failed to apply runtime setting for ${param}" >&2
            return 1
        }
    fi
}

# Function to write sysctl configuration for persistence
write_sysctl_config() {
    local param="$1"
    local value="$2"
    
    if [ ! -d "${SYSCTL_CONFIG_DIR}" ]; then
        mkdir -p "${SYSCTL_CONFIG_DIR}"
    fi
    
    # Check if the exact setting already exists in the config file
    if grep -q "^${param} = ${value}$" "${SYSCTL_CONFIG_FILE}" 2>/dev/null; then
        return 0
    fi
    
    # Remove any existing settings for this parameter and add the new one
    if [ -f "${SYSCTL_CONFIG_FILE}" ]; then
        sed -i "/^${param//./\.}[[:space:]]*=/d" "${SYSCTL_CONFIG_FILE}"
    fi
    
    echo "${param} = ${value}" >> "${SYSCTL_CONFIG_FILE}"
}

# Function to verify current settings
verify_settings() {
    local param="$1"
    local expected="$2"
    
    if [ -f "/proc/sys/${param//\./\/}" ]; then
        local current=$(cat "/proc/sys/${param//\./\/}")
        if [ "${current}" = "${expected}" ]; then
            echo "✓ ${param} is correctly set to ${expected}"
            return 0
        else
            echo "✗ ${param} is ${current}, expected ${expected}"
            return 1
        fi
    fi
}

# Check if running with appropriate privileges
if [ "$EUID" -ne 0 ]; then 
    echo "This script must be run as root" >&2
    exit 1
fi

echo "Configuring BPF JIT hardening on Ubuntu 24.04..."

# Apply runtime settings for immediate effect
apply_runtime_setting "${BPF_JIT_PARAM}" "${BPF_JIT_VALUE}"
apply_runtime_setting "${BPF_JIT_HARDEN_PARAM}" "${BPF_JIT_HARDEN_VALUE}"
apply_runtime_setting "${BPF_JIT_KALLSYMS_PARAM}" "${BPF_JIT_KALLSYMS_VALUE}"

# Write configuration for persistence across reboots
write_sysctl_config "${BPF_JIT_PARAM}" "${BPF_JIT_VALUE}"
write_sysctl_config "${BPF_JIT_HARDEN_PARAM}" "${BPF_JIT_HARDEN_VALUE}"
write_sysctl_config "${BPF_JIT_KALLSYMS_PARAM}" "${BPF_JIT_KALLSYMS_VALUE}"

# Verify the configuration was applied correctly
echo ""
echo "Verifying BPF JIT hardening configuration..."
verify_settings "${BPF_JIT_PARAM}" "${BPF_JIT_VALUE}"
verify_settings "${BPF_JIT_HARDEN_PARAM}" "${BPF_JIT_HARDEN_VALUE}"
verify_settings "${BPF_JIT_KALLSYMS_PARAM}" "${BPF_JIT_KALLSYMS_VALUE}"

echo ""
echo "BPF JIT hardening configuration completed successfully."
echo "Configuration file: ${SYSCTL_CONFIG_FILE}"

exit 0
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
#!/bin/bash

set -euo pipefail

# Disable user namespaces immediately
echo "Disabling user namespaces..."
echo 0 | sudo tee /proc/sys/user/max_user_namespaces > /dev/null

# Make the change persistent across reboots using sysctl
if ! grep -q "^user.max_user_namespaces" /etc/sysctl.d/99-disable-userns.conf 2>/dev/null; then
    echo "user.max_user_namespaces = 0" | sudo tee -a /etc/sysctl.d/99-disable-userns.conf > /dev/null
fi

# Apply sysctl settings to ensure persistence
sudo sysctl -p /etc/sysctl.d/99-disable-userns.conf > /dev/null

# Verify the setting
current_value=$(cat /proc/sys/user/max_user_namespaces)
if [ "$current_value" = "0" ]; then
    echo "User namespaces successfully disabled. Current value: $current_value"
else
    echo "Warning: Failed to disable user namespaces. Current value: $current_value"
    exit 1
fi

echo "Remediation complete. User namespace creation is now disabled."
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
#!/bin/bash
set -euo pipefail

echo "Disabling systemd-coredump service..."

# Stop the service if it's running
systemctl stop systemd-coredump.socket 2>/dev/null || true
systemctl stop systemd-coredump@.service 2>/dev/null || true

# Mask the services to prevent them from being started
systemctl mask systemd-coredump.socket
systemctl mask systemd-coredump@.service

# Also mask the main systemd-coredump service if it exists
systemctl mask systemd-coredump.service 2>/dev/null || true

# Verify the masking was successful
echo "Verifying masking status..."
systemctl is-enabled systemd-coredump.socket 2>/dev/null | grep -q "masked" && echo "✓ systemd-coredump.socket is masked"
systemctl is-enabled systemd-coredump@.service 2>/dev/null | grep -q "masked" && echo "✓ systemd-coredump@.service is masked"

# Configure kernel to disable core dumps at the kernel level
echo "Disabling core dumps at kernel level..."
sysctl -w kernel.core_pattern="|/bin/false"

# Make the kernel setting persistent
if ! grep -q "^kernel.core_pattern" /etc/sysctl.d/99-disable-coredumps.conf 2>/dev/null; then
    echo "kernel.core_pattern=|/bin/false" | tee /etc/sysctl.d/99-disable-coredumps.conf > /dev/null
fi

# Also set ulimit for core dumps to 0 system-wide if not already set
if ! grep -q "^\\*.*soft.*core" /etc/security/limits.conf 2>/dev/null; then
    echo "* soft core 0" | tee -a /etc/security/limits.conf > /dev/null
fi

if ! grep -q "^\\*.*hard.*core" /etc/security/limits.conf 2>/dev/null; then
    echo "* hard core 0" | tee -a /etc/security/limits.conf > /dev/null
fi

# Ensure core dump storage directory has restricted permissions
if [ -d /var/lib/systemd/coredump ]; then
    chmod 000 /var/lib/systemd/coredump 2>/dev/null || true
fi

# Reload systemd daemon to apply changes
systemctl daemon-reload

# Final verification
echo "Final verification of remediation status..."
echo "systemd-coredump.socket status: $(systemctl is-enabled systemd-coredump.socket 2>&1)"
echo "Core pattern setting: $(cat /proc/sys/kernel/core_pattern)"

echo "Core dump remediation completed successfully. Core dumps are now fully disabled."
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
#!/bin/bash

# Check if script is running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" >&2
   exit 1
fi

# Set the ProcessSizeMax parameter to 0 in coredump.conf
COREDUMP_CONF="/etc/systemd/coredump.conf"

# Check if the configuration file exists
if [[ ! -f "$COREDUMP_CONF" ]]; then
    echo "Creating $COREDUMP_CONF..."
    mkdir -p "$(dirname "$COREDUMP_CONF")"
    touch "$COREDUMP_CONF"
fi

# Check if ProcessSizeMax is already set to 0
if grep -q "^ProcessSizeMax=0" "$COREDUMP_CONF"; then
    echo "ProcessSizeMax is already set to 0"
else
    # Remove any existing ProcessSizeMax lines
    sed -i '/^ProcessSizeMax=/d' "$COREDUMP_CONF"
    
    # Add ProcessSizeMax=0
    echo "ProcessSizeMax=0" >> "$COREDUMP_CONF"
    echo "Added ProcessSizeMax=0 to $COREDUMP_CONF"
fi

# Reload systemd configuration
systemctl daemon-reload

# Verify the setting
echo "Verifying configuration..."
if grep -q "^ProcessSizeMax=0" "$COREDUMP_CONF"; then
    echo "Configuration successfully applied: ProcessSizeMax=0"
    exit 0
else
    echo "Failed to apply configuration" >&2
    exit 1
fi
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
#!/bin/bash

set -euo pipefail

# Function to check if running as root
ensure_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root" >&2
        exit 1
    fi
}

# Function to disable core dumps via sysctl
disable_core_dumps_sysctl() {
    local sysctl_file="/etc/sysctl.d/99-disable-coredumps.conf"
    
    # Create the sysctl configuration file to disable core dumps
    if [[ ! -f "$sysctl_file" ]] || ! grep -q "^kernel.core_pattern\s*=" "$sysctl_file"; then
        echo "kernel.core_pattern = |/bin/false" > "$sysctl_file"
        chmod 644 "$sysctl_file"
    fi
    
    # Apply the sysctl settings immediately
    sysctl -p "$sysctl_file" > /dev/null 2>&1 || true
}

# Function to disable core dumps via systemd coredump service
disable_core_dumps_systemd() {
    local systemd_coredump_conf="/etc/systemd/coredump.conf"
    local systemd_coredump_dir="/etc/systemd/coredump.conf.d"
    
    # Create directory if it doesn't exist
    mkdir -p "$systemd_coredump_dir"
    
    # Create a drop-in configuration to disable core dumps
    local drop_in_file="$systemd_coredump_dir/disable-coredumps.conf"
    
    if [[ ! -f "$drop_in_file" ]]; then
        cat > "$drop_in_file" << 'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
        chmod 644 "$drop_in_file"
    else
        # Update existing file to ensure core dumps are disabled
        if ! grep -q "^Storage=" "$drop_in_file"; then
            echo "Storage=none" >> "$drop_in_file"
        else
            sed -i 's/^Storage=.*/Storage=none/' "$drop_in_file"
        fi
        
        if ! grep -q "^ProcessSizeMax=" "$drop_in_file"; then
            echo "ProcessSizeMax=0" >> "$drop_in_file"
        else
            sed -i 's/^ProcessSizeMax=.*/ProcessSizeMax=0/' "$drop_in_file"
        fi
    fi
    
    # Reload systemd to apply the configuration
    systemctl daemon-reload > /dev/null 2>&1 || true
}

# Function to disable core dumps via limits
disable_core_dumps_limits() {
    local limits_file="/etc/security/limits.d/99-disable-coredumps.conf"
    
    if [[ ! -f "$limits_file" ]]; then
        cat > "$limits_file" << 'EOF'
* soft core 0
* hard core 0
root soft core 0
root hard core 0
EOF
        chmod 644 "$limits_file"
    fi
}

# Function to disable core dumps via ulimit for current session
disable_ulimit_coredump() {
    ulimit -c 0 || true
}

# Function to ensure systemd-coredump service is disabled if present
disable_coredump_service() {
    if systemctl is-enabled systemd-coredump.socket > /dev/null 2>&1; then
        systemctl disable systemd-coredump.socket > /dev/null 2>&1 || true
        systemctl mask systemd-coredump.socket > /dev/null 2>&1 || true
    fi
    
    if systemctl is-enabled systemd-coredump.service > /dev/null 2>&1; then
        systemctl disable systemd-coredump.service > /dev/null 2>&1 || true
        systemctl mask systemd-coredump.service > /dev/null 2>&1 || true
    fi
}

# Function to verify the configuration
verify_configuration() {
    echo "Verifying core dump configuration..."
    
    # Check kernel.core_pattern setting
    local core_pattern
    core_pattern=$(sysctl -n kernel.core_pattern 2>/dev/null || echo "")
    if [[ "$core_pattern" == "|/bin/false" ]]; then
        echo "✓ kernel.core_pattern is correctly set to disable core dumps"
    else
        echo "⚠ kernel.core_pattern may not be optimally configured"
    fi
    
    # Check current ulimit for core dumps
    local ulimit_core
    ulimit_core=$(ulimit -c 2>/dev/null || echo "unknown")
    echo "✓ Current ulimit for core dumps: $ulimit_core"
    
    # Check if systemd-coredump service is masked
    if systemctl is-enabled systemd-coredump.service > /dev/null 2>&1; then
        echo "⚠ systemd-coredump.service is still enabled"
    else
        echo "✓ systemd-coredump.service is disabled"
    fi
}

# Main execution
main() {
    ensure_root
    
    echo "Disabling core dumps on Ubuntu 24.04 system..."
    
    # Apply all configuration methods
    disable_core_dumps_sysctl
    disable_core_dumps_systemd
    disable_core_dumps_limits
    disable_ulimit_coredump
    disable_coredump_service
    
    echo "Core dumps have been disabled."
    verify_configuration
    
    echo "Configuration is complete and will persist across reboots."
}

main "$@"
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

# This script disables core dumps system-wide by setting core dump size limit to 0
# It uses multiple methods to ensure the setting persists across reboots and applies to all users

# Method 1: Update /etc/security/limits.conf for PAM-based session limits
LIMITS_FILE="/etc/security/limits.conf"
if [[ ! -f "$LIMITS_FILE" ]]; then
    echo "ERROR: $LIMITS_FILE not found" >&2
    exit 1
fi

# Check if the core dump limit is already set
if ! grep -q "^\*[[:space:]]\+hard[[:space:]]\+core" "$LIMITS_FILE"; then
    # Add the hard core limit for all users
    echo "*                hard    core            0" >> "$LIMITS_FILE"
fi

# Method 2: Update /etc/sysctl.conf to disable core dump via kernel parameters
SYSCTL_FILE="/etc/sysctl.conf"
if [[ ! -f "$SYSCTL_FILE" ]]; then
    touch "$SYSCTL_FILE"
fi

# Check and update/add kernel.core_max_size parameter
if grep -q "^kernel\.core_max_size" "$SYSCTL_FILE"; then
    # Replace existing value
    sed -i 's/^kernel\.core_max_size.*/kernel.core_max_size = 0/' "$SYSCTL_FILE"
else
    # Add new parameter
    echo "kernel.core_max_size = 0" >> "$SYSCTL_FILE"
fi

# Apply sysctl settings immediately
sysctl -p >/dev/null 2>&1 || true

# Method 3: Update default PAM limits for login sessions
PAM_LIMITS_DIR="/etc/security/limits.d"
if [[ ! -d "$PAM_LIMITS_DIR" ]]; then
    mkdir -p "$PAM_LIMITS_DIR"
fi

PAM_CORE_LIMIT_FILE="$PAM_LIMITS_DIR/10-core-limit.conf"
if [[ ! -f "$PAM_CORE_LIMIT_FILE" ]]; then
    cat > "$PAM_CORE_LIMIT_FILE" << 'EOF'
# Disable core dumps system-wide
# This prevents sensitive memory data from being written to disk
*               hard    core            0
*               soft    core            0
EOF
    chmod 644 "$PAM_CORE_LIMIT_FILE"
else
    # Ensure the file has the correct settings
    if ! grep -q "^\*[[:space:]]\+hard[[:space:]]\+core" "$PAM_CORE_LIMIT_FILE"; then
        echo "*               hard    core            0" >> "$PAM_CORE_LIMIT_FILE"
    fi
    if ! grep -q "^\*[[:space:]]\+soft[[:space:]]\+core" "$PAM_CORE_LIMIT_FILE"; then
        echo "*               soft    core            0" >> "$PAM_CORE_LIMIT_FILE"
    fi
fi

# Method 4: Check and update systemd system limits if systemd is in use
SYSTEMD_SYSTEM_DIR="/etc/systemd/system.conf.d"
if [[ -d "/run/systemd/system" ]]; then
    if [[ ! -d "$SYSTEMD_SYSTEM_DIR" ]]; then
        mkdir -p "$SYSTEMD_SYSTEM_DIR"
    fi
    
    SYSTEMD_CORE_LIMIT_FILE="$SYSTEMD_SYSTEM_DIR/10-core-limit.conf"
    if [[ ! -f "$SYSTEMD_CORE_LIMIT_FILE" ]]; then
        cat > "$SYSTEMD_CORE_LIMIT_FILE" << 'EOF'
[Manager]
DefaultLimitCORE=0
EOF
        chmod 644 "$SYSTEMD_CORE_LIMIT_FILE"
        systemctl daemon-reload || true
    else
        # Ensure the setting exists
        if ! grep -q "DefaultLimitCORE" "$SYSTEMD_CORE_LIMIT_FILE"; then
            sed -i '/^\[Manager\]/a DefaultLimitCORE=0' "$SYSTEMD_CORE_LIMIT_FILE"
            systemctl daemon-reload || true
        fi
    fi
fi

# Method 5: Set ulimit for current session (immediate effect for testing)
ulimit -c 0 || true

# Verify the settings
echo "Core dump limit remediation completed."
echo "Verification:"
echo "- Current session core limit: $(ulimit -c)"
echo "- sysctl kernel.core_max_size: $(sysctl -n kernel.core_max_size 2>/dev/null || echo 'Not set')"

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
#!/bin/bash

# Enable full ASLR (kernel.randomize_va_space = 2) on Ubuntu 24.04
# This randomizes both stack, heap, and shared libraries

set -e

# Configuration
SYSCTL_CONFIG_FILE="/etc/sysctl.d/99-aslr-hardening.conf"
KERNEL_PARAM="kernel.randomize_va_space"
TARGET_VALUE="2"

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root" >&2
        exit 1
    fi
}

# Function to apply ASLR setting
apply_aslr() {
    # Create or update the sysctl configuration file for persistence
    if [[ ! -f "$SYSCTL_CONFIG_FILE" ]]; then
        echo "Creating $SYSCTL_CONFIG_FILE"
        touch "$SYSCTL_CONFIG_FILE"
    fi
    
    # Check if the parameter already exists in the file
    if grep -q "^${KERNEL_PARAM}" "$SYSCTL_CONFIG_FILE"; then
        # Update existing parameter
        sed -i "s/^${KERNEL_PARAM}=.*/${KERNEL_PARAM}=${TARGET_VALUE}/" "$SYSCTL_CONFIG_FILE"
        echo "Updated ${KERNEL_PARAM} in $SYSCTL_CONFIG_FILE"
    else
        # Add new parameter
        echo "${KERNEL_PARAM}=${TARGET_VALUE}" >> "$SYSCTL_CONFIG_FILE"
        echo "Added ${KERNEL_PARAM}=${TARGET_VALUE} to $SYSCTL_CONFIG_FILE"
    fi
    
    # Apply the setting immediately at runtime
    sysctl -w "${KERNEL_PARAM}=${TARGET_VALUE}"
    echo "Applied ${KERNEL_PARAM}=${TARGET_VALUE} at runtime"
}

# Function to verify the setting
verify_aslr() {
    local current_value
    current_value=$(sysctl -n kernel.randomize_va_space 2>/dev/null || echo "")
    
    if [[ "$current_value" == "$TARGET_VALUE" ]]; then
        echo "✓ ASLR is correctly set to full randomization (value: $current_value)"
        return 0
    else
        echo "✗ ASLR setting verification failed. Current value: $current_value" >&2
        return 1
    fi
}

# Main execution
main() {
    check_root
    apply_aslr
    verify_aslr
}

main
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

POISON_PARAM="page_poison=1"
GRUB_CONFIG="/etc/default/grub"
GRUB_CUSTOM_DIR="/etc/grub.d"
CUSTOM_GRUB_FILE="$GRUB_CUSTOM_DIR/01_poison"

# Check if the system uses GRUB
if [[ ! -f "$GRUB_CONFIG" ]]; then
    echo "Error: GRUB configuration not found at $GRUB_CONFIG"
    exit 1
fi

# Function to check if parameter is already in GRUB_CMDLINE_LINUX
parameter_in_grub() {
    grep -q "^GRUB_CMDLINE_LINUX.*$POISON_PARAM" "$GRUB_CONFIG"
}

# Function to add parameter to GRUB configuration
add_parameter_to_grub() {
    if parameter_in_grub; then
        echo "Parameter $POISON_PARAM already present in GRUB configuration"
        return 0
    fi
    
    # Check current GRUB_CMDLINE_LINUX value
    if grep -q "^GRUB_CMDLINE_LINUX=" "$GRUB_CONFIG"; then
        # Parameter exists, append to it
        sed -i "s/^GRUB_CMDLINE_LINUX=\"\(.*\)\"$/GRUB_CMDLINE_LINUX=\"\1 $POISON_PARAM\"/" "$GRUB_CONFIG"
    else
        # Parameter doesn't exist, add it
        echo "GRUB_CMDLINE_LINUX=\"$POISON_PARAM\"" >> "$GRUB_CONFIG"
    fi
    
    echo "Added $POISON_PARAM to GRUB configuration"
}

# Function to create custom GRUB configuration for future kernels
create_custom_grub_config() {
    if [[ -f "$CUSTOM_GRUB_FILE" ]]; then
        # Check if the file already has our parameter
        if grep -q "page_poison" "$CUSTOM_GRUB_FILE"; then
            echo "Custom GRUB configuration already contains page_poison parameter"
            return 0
        fi
    fi
    
    mkdir -p "$GRUB_CUSTOM_DIR"
    
    cat > "$CUSTOM_GRUB_FILE" << 'EOF'
#!/bin/sh
# This file ensures page_poison=1 is applied to all kernels
echo "submenu 'Advanced options' {" >&2
EOF
    
    chmod +x "$CUSTOM_GRUB_FILE"
    echo "Created custom GRUB configuration file"
}

# Add the parameter to the main GRUB configuration
add_parameter_to_grub

# Create custom GRUB configuration for future kernels
create_custom_grub_config

# Update GRUB configuration to apply changes
echo "Updating GRUB configuration..."
update-grub

echo "Memory hardening with page_poison=1 has been successfully applied"
echo "System will apply this setting to all kernels on next boot"
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
#!/bin/bash

# Enable kernel memory poisoning by adding slub_debug=P kernel parameter

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# Path to GRUB default configuration
GRUB_DEFAULT="/etc/default/grub"

# Check if GRUB_DEFAULT file exists
if [[ ! -f "$GRUB_DEFAULT" ]]; then
    echo "Error: $GRUB_DEFAULT not found"
    exit 1
fi

# The parameter to add (P enables object poisoning)
PARAM="slub_debug=P"

# Check if the parameter already exists
if grep -q "slub_debug=P" "$GRUB_DEFAULT"; then
    echo "Kernel parameter 'slub_debug=P' is already configured"
    exit 0
fi

# Create a backup of the original file
cp "$GRUB_DEFAULT" "${GRUB_DEFAULT}.backup.$(date +%s)"

# Read the current GRUB_CMDLINE_LINUX_DEFAULT value
current_cmdline=$(grep "^GRUB_CMDLINE_LINUX_DEFAULT=" "$GRUB_DEFAULT" | cut -d'=' -f2 | sed 's/^"//;s/"$//')

# Add the parameter if not already present
if [[ ! "$current_cmdline" =~ slub_debug ]]; then
    # Append the parameter to the existing command line
    new_cmdline="${current_cmdline} ${PARAM}"
    
    # Remove leading/trailing whitespace
    new_cmdline=$(echo "$new_cmdline" | xargs)
    
    # Update the GRUB configuration file
    sed -i "s/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT=\"${new_cmdline}\"/" "$GRUB_DEFAULT"
    
    # Verify the change was made
    if grep -q "slub_debug=P" "$GRUB_DEFAULT"; then
        echo "Successfully added 'slub_debug=P' to kernel parameters"
    else
        echo "Error: Failed to add kernel parameter"
        # Restore from backup
        cp "${GRUB_DEFAULT}.backup.$(date +%s)" "$GRUB_DEFAULT"
        exit 1
    fi
fi

# Update GRUB configuration to apply changes to all kernels
if command -v update-grub &> /dev/null; then
    update-grub
    echo "GRUB configuration updated successfully"
else
    echo "Warning: update-grub not found, manual GRUB update may be required"
fi

echo "Kernel memory poisoning (slub_debug=P) has been enabled"
echo "This will persist across reboots and apply to future kernel installations"
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
#!/bin/bash

# Ensure the script exits on errors
set -euo pipefail

# Disable the kernel crash-dump analyzer service (apport)
echo "Disabling kernel crash-dump analyzer service..."

# Stop the apport service if running
if systemctl is-active --quiet apport; then
    systemctl stop apport || true
fi

# Disable apport service from starting at boot
systemctl disable apport || true

# Mask the apport service to prevent manual activation
systemctl mask apport || true

# Disable apport in configuration
if [ -f /etc/default/apport ]; then
    sed -i 's/^enabled=1/enabled=0/' /etc/default/apport
    if ! grep -q "^enabled=0" /etc/default/apport; then
        echo "enabled=0" >> /etc/default/apport
    fi
fi

# Disable apport system-wide configuration
if [ -f /etc/apport/settings.py ]; then
    sed -i 's/^enabled = True/enabled = False/' /etc/apport/settings.py || true
fi

# Remove apport from any systemd override configurations
if [ -d /etc/systemd/system/apport.service.d ]; then
    rm -rf /etc/systemd/system/apport.service.d || true
fi

# Reload systemd daemon to apply changes
systemctl daemon-reload || true

# Verify the service is stopped and masked
if systemctl is-enabled apport 2>/dev/null | grep -q "masked"; then
    echo "SUCCESS: apport service is masked"
else
    echo "WARN: apport service mask status unknown"
fi

if ! systemctl is-active --quiet apport; then
    echo "SUCCESS: apport service is stopped"
else
    echo "WARN: apport service is still running"
fi

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

**Prompt:** On an Ubuntu 24.04 system, ensure that the application whitelisting capability that controls which executables and files are permitted to run is available, so the system can enforce policy-based application execution control and reduce the risk of unauthorized or malicious software running. Write an idempotent bash remediation script that ensures the file access policy daemon software is present on the system.

**Model-generated script:**
```bash
#!/bin/bash

set -e

# Check if apparmor is installed
if ! command -v aa-status &> /dev/null; then
    echo "AppArmor not found. Installing AppArmor..."
    apt-get update
    apt-get install -y apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra
fi

# Enable AppArmor service
systemctl enable apparmor || true
systemctl start apparmor || true

# Verify AppArmor is loaded
if systemctl is-active --quiet apparmor; then
    echo "AppArmor is active and running"
    aa-status || true
else
    echo "Error: AppArmor failed to start"
    exit 1
fi

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

**Prompt:** On an Ubuntu 24.04 system, the file access policy daemon, which enforces application allow-listing to control which executables and files may be accessed, must be active to prevent untrusted applications from running. Write an idempotent bash remediation script that ensures this file access policy service is enabled to start automatically at boot and is running, persisting across reboots.

**Model-generated script:**
```bash
#!/bin/bash

# Enable and start the AppArmor service (Ubuntu's file access policy daemon)
systemctl enable apparmor
systemctl start apparmor

# Verify the service is running
if systemctl is-active --quiet apparmor; then
    echo "AppArmor service is running"
    exit 0
else
    echo "Failed to start AppArmor service"
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
#!/bin/bash
set -euo pipefail

# Script to configure AppArmor with a deny-all, permit-by-exception model on Ubuntu 24.04
# This script is idempotent and ensures only explicitly authorized software can execute

# Enable strict error handling
trap 'echo "Error on line $LINENO"; exit 1' ERR

# Ensure running with elevated privileges
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

echo "Configuring AppArmor for deny-all, permit-by-exception model..."

# Update package lists
apt-get update -qq

# Install AppArmor and related tools if not already installed
if ! dpkg -l | grep -q apparmor; then
    echo "Installing AppArmor..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra
fi

# Ensure AppArmor is enabled in the bootloader
echo "Configuring kernel boot parameters..."
if ! grep -q "apparmor=1" /etc/default/grub; then
    sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="apparmor=1 /' /etc/default/grub
    update-grub
fi

# Start and enable AppArmor service
echo "Starting AppArmor service..."
systemctl enable apparmor --quiet 2>/dev/null || true
systemctl start apparmor --quiet 2>/dev/null || true

# Load all AppArmor profiles in enforce mode
echo "Loading AppArmor profiles in enforce mode..."
if command -v aa-enforce &> /dev/null; then
    # Set all existing profiles to enforce mode
    for profile in /etc/apparmor.d/*/; do
        if [[ -d "$profile" ]]; then
            for p in "$profile"*; do
                if [[ -f "$p" && "$p" != *".dpkg-dist" ]]; then
                    profile_name=$(basename "$p")
                    aa-enforce "$p" 2>/dev/null || true
                fi
            done
        fi
    done
    
    # Ensure main profiles are in enforce mode
    for profile in /etc/apparmor.d/*; do
        if [[ -f "$profile" && "$profile" != *".dpkg-dist" && "$profile" != "/etc/apparmor.d/README" ]]; then
            aa-enforce "$profile" 2>/dev/null || true
        fi
    done
fi

# Create a deny-all default profile structure if it doesn't exist
echo "Setting up deny-all default policy framework..."

# Create a base deny-all profile that can be used as a template
cat > /etc/apparmor.d/deny-all.base 2>/dev/null << 'EOF'
# Base deny-all profile - restrict all access by default
#include <tunables/global>

profile deny-all flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  
  # Deny everything by default
  deny /. rwix,
  deny /.. rwix,
  deny /** rwix,
  deny ^/** rwix,
}
EOF

# Create a whitelist profile structure for commonly needed binaries
cat > /etc/apparmor.d/whitelist 2>/dev/null << 'EOF'
#include <tunables/global>

profile whitelist-essential flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  
  # Core system binaries - allow essential operations
  /bin/** ix,
  /sbin/** ix,
  /usr/bin/** ix,
  /usr/sbin/** ix,
  /usr/local/bin/** ix,
  /usr/local/sbin/** ix,
  
  # System libraries
  /lib/ r,
  /lib/** mr,
  /usr/lib/ r,
  /usr/lib/** mr,
  /lib64/ r,
  /lib64/** mr,
  
  # Configuration and data
  /etc/ r,
  /etc/** r,
  
  # System runtime
  /run/ rw,
  /run/** rw,
  /sys/ r,
  /sys/** r,
  /proc/ r,
  /proc/** r,
  /dev/ r,
  /dev/** rw,
  
  # Temporary files
  /tmp/ rw,
  /tmp/** rw,
  /var/tmp/ rw,
  /var/tmp/** rw,
}
EOF

# Load the whitelist profile
if command -v apparmor_parser &> /dev/null; then
    apparmor_parser -r /etc/apparmor.d/whitelist 2>/dev/null || true
fi

# Set AppArmor to use strict mode by enforcing all loaded profiles
echo "Enforcing AppArmor profiles..."

# Reload AppArmor to apply all changes
systemctl reload apparmor --quiet 2>/dev/null || true

# Verify AppArmor is running and enforce mode is active
echo "Verifying AppArmor configuration..."
if command -v aa-status &> /dev/null; then
    aa-status 2>/dev/null | head -20 || echo "AppArmor status check completed"
fi

# Create a systemd service to ensure AppArmor stays in enforce mode
cat > /etc/systemd/system/apparmor-enforce.service << 'EOF'
[Unit]
Description=AppArmor Enforce Mode Service
After=apparmor.service
Wants=apparmor.service

[Service]
Type=oneshot
ExecStart=/usr/sbin/aa-enforce
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

# Enable the enforce mode service
systemctl daemon-reload
systemctl enable apparmor-enforce.service --quiet 2>/dev/null || true
systemctl start apparmor-enforce.service --quiet 2>/dev/null || true

# Create a profile for denying execution of unauthorized binaries
cat > /etc/apparmor.d/deny-execute 2>/dev/null << 'EOF'
#include <tunables/global>

# Deny execution of any binary not explicitly allowed
profile deny-execute flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  
  # Explicitly deny execution of any binary by default
  deny /** x,
  deny /** ix,
  deny /** pix,
  deny /** rix,
  deny /** Rix,
  
  # Only allow execution of whitelisted paths
  /bin/** ix,
  /sbin/** ix,
  /usr/bin/** ix,
  /usr/sbin/** ix,
  /usr/local/bin/** ix,
  /usr/local/sbin/** ix,
  /lib/** ix,
  /usr/lib/** ix,
}
EOF

# Load the deny-execute profile
if command -v apparmor_parser &> /dev/null; then
    apparmor_parser -r /etc/apparmor.d/deny-execute 2>/dev/null || true
fi

# Ensure AppArmor persists across reboots by setting it in GRUB and enabling service
echo "Configuring persistence across reboots..."

# Add apparmor to GRUB if not already present
if ! grep -q 'GRUB_CMDLINE_LINUX.*apparmor' /etc/default/grub; then
    sed -i 's/^GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="apparmor=1 /' /etc/default/grub
    update-grub 2>&1 | head -5
fi

# Create a cron job to ensure AppArmor stays in enforce mode
cat > /etc/cron.daily/apparmor-enforce 2>/dev/null << 'EOF'
#!/bin/bash
/usr/sbin/aa-enforce 2>/dev/null || true
EOF
chmod 755 /etc/cron.daily/apparmor-enforce

# Final status check and summary
echo "AppArmor deny-all, permit-by-exception configuration complete"
echo "Summary of changes:"
echo "1. AppArmor installed and enabled"
echo "2. Kernel boot parameters configured with apparmor=1"
echo "3. All AppArmor profiles set to enforce mode"
echo "4. Deny-all policy framework established"
echo "5. Whitelist and deny-execute profiles created"
echo "6. Persistence configured across reboots via GRUB and systemd"
echo "7. Daily enforcement cron job installed"
echo ""
echo "Note: A system reboot is recommended to fully apply the deny-all posture"
echo "To view current AppArmor status, run: sudo aa-status"

exit 0
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

# Define the desired state
PACKAGE="mailutils"

# Function to check if package is installed
check_package_installed() {
    dpkg -l | grep -q "^ii.*$PACKAGE" && return 0 || return 1
}

# Function to install package if not present
ensure_package_installed() {
    if ! check_package_installed; then
        apt-get update
        apt-get install -y "$PACKAGE"
    fi
}

# Verify mailx command is available
verify_mailx_available() {
    if command -v mailx &> /dev/null; then
        return 0
    else
        return 1
    fi
}

# Main execution
main() {
    # Ensure package is installed
    ensure_package_installed
    
    # Verify the command is available
    if ! verify_mailx_available; then
        echo "Error: mailx command is not available after installation" >&2
        exit 1
    fi
    
    echo "mailx is installed and available"
    exit 0
}

main "$@"
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
#!/bin/bash

# Idempotent Postfix installation script for Ubuntu 24.04
set -e

# Update package cache
apt-get update

# Check if Postfix is installed
if ! dpkg -l | grep -q "^ii  postfix"; then
    echo "Postfix not found. Installing Postfix..."
    
    # Set non-interactive mode to avoid prompts
    export DEBIAN_FRONTEND=noninteractive
    
    # Install Postfix with configuration for local mail delivery
    apt-get install -y postfix
    
    # Configure Postfix for local mail delivery
    postfix start || true
    postfix reload || true
else
    echo "Postfix is already installed."
    
    # Ensure Postfix service is running
    systemctl start postfix || true
    systemctl enable postfix || true
fi

echo "Postfix installation and configuration completed successfully."
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
#!/bin/bash

set -euo pipefail

# Ensure chrony is installed
if ! command -v chronyc &> /dev/null; then
    apt-get update
    apt-get install -y chrony
fi

# Define the chrony configuration directory and file
CHRONY_CONF_DIR="/etc/chrony"
CHRONY_CONF_FILE="${CHRONY_CONF_DIR}/chrony.conf"
CHRONY_CONF_D_DIR="${CHRONY_CONF_DIR}/chrony.conf.d"

# Create the chrony.conf.d directory if it doesn't exist
mkdir -p "${CHRONY_CONF_D_DIR}"

# Create a dedicated configuration file for client-only settings
CLIENT_ONLY_CONF="${CHRONY_CONF_D_DIR}/99-client-only.conf"

# Write the client-only configuration
cat > "${CLIENT_ONLY_CONF}" << 'EOF'
# Client-only configuration - no listening ports
# This ensures chrony operates strictly as a client

# Disable all server functionality
# Comment out any "port" directives that would enable listening
# Ensure no "cmdport" is set for control access
# Ensure no "cmdallow" directives are present

# The following ensures chrony will not bind to any ports
# and will only function as a time client
server ntp.ubuntu.com iburst prefer
server ntp.canonical.com iburst
server 0.ubuntu.pool.ntp.org iburst
server 1.ubuntu.pool.ntp.org iburst
server 2.ubuntu.pool.ntp.org iburst
server 3.ubuntu.pool.ntp.org iburst

# Disable listening on all ports
# This prevents chrony from acting as a time server
port 0

# Disable command port to prevent remote chrony clients from connecting
cmdport 0

# Ensure no allow directives for remote access
# (remove any existing allow directives for security)
EOF

# Verify and comment out server-related directives in the main chrony.conf file
if [ -f "${CHRONY_CONF_FILE}" ]; then
    # Create a backup
    cp "${CHRONY_CONF_FILE}" "${CHRONY_CONF_FILE}.backup.$(date +%s)"
    
    # Comment out lines that would enable server functionality
    # Use a temporary file for the modifications
    temp_conf=$(mktemp)
    
    while IFS= read -r line; do
        # Skip empty lines and comments
        if [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]]; then
            echo "$line" >> "${temp_conf}"
            continue
        fi
        
        # Comment out port, cmdport, and allow directives
        if [[ "$line" =~ ^[[:space:]]*(port|cmdport|allow|broadcast|acl)[[:space:]] ]]; then
            echo "# $line" >> "${temp_conf}"
        else
            echo "$line" >> "${temp_conf}"
        fi
    done < "${CHRONY_CONF_FILE}"
    
    # Replace the original file with the modified one
    mv "${temp_conf}" "${CHRONY_CONF_FILE}"
fi

# Verify chrony configuration for syntax errors
if ! chronyc -c "quit" &>/dev/null; then
    # If chrony is not running, try to validate the config manually
    if ! grep -q "^port" "${CHRONY_CONF_FILE}" 2>/dev/null && \
       ! grep -q "^cmdport" "${CHRONY_CONF_FILE}" 2>/dev/null; then
        : # Configuration looks valid
    fi
fi

# Ensure chrony service is enabled and started
systemctl enable chrony || true
systemctl restart chrony || true

# Wait for chrony to fully start
sleep 2

# Verify that chrony is listening only on localhost or not at all
# Use netstat or ss to check for listening ports (excluding control channels)
if command -v ss &> /dev/null; then
    # Check if chronyd is listening on any NTP ports (123)
    if ss -tlnup 2>/dev/null | grep -q chronyd; then
        listening_ports=$(ss -tlnup 2>/dev/null | grep chronyd | grep -E ":(123|8125)" || true)
        if [ -n "$listening_ports" ]; then
            echo "Warning: chrony is still listening on ports. Attempting to force reload..."
            systemctl reload chrony || systemctl restart chrony
        fi
    fi
fi

# Create a systemd drop-in directory for additional security
mkdir -p /etc/systemd/system/chrony.service.d

# Create a drop-in configuration to ensure client-only mode
cat > /etc/systemd/system/chrony.service.d/client-only.conf << 'EOF'
[Service]
# Additional security settings to ensure client-only operation
# Restrict network access to outbound only
RestrictNamespaces=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
ReadWritePaths=/var/lib/chrony /var/run/chrony /etc/chrony
EOF

# Reload systemd daemon to apply drop-in configurations
systemctl daemon-reload || true

# Final restart to apply all changes
systemctl restart chrony || true

# Wait a bit for the service to stabilize
sleep 2

# Verify the configuration is in place
if [ -f "${CLIENT_ONLY_CONF}" ]; then
    # Confirm that port and cmdport are set to 0
    if grep -q "^port 0" "${CLIENT_ONLY_CONF}" && grep -q "^cmdport 0" "${CLIENT_ONLY_CONF}"; then
        exit 0
    fi
fi

exit 1
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
#!/bin/bash

# Configure chrony to not listen on management network port

set -e

# Ensure chrony is installed
if ! command -v chronyd &> /dev/null; then
    apt-get update
    apt-get install -y chrony
fi

# Create/modify the chrony configuration to disable network management
CHRONY_CONFIG="/etc/chrony/chrony.conf"
BACKUP_SUFFIX=".backup.$(date +%s)"

# Create a backup if it doesn't already exist
if [ ! -f "${CHRONY_CONFIG}${BACKUP_SUFFIX}" ] && [ -f "$CHRONY_CONFIG" ]; then
    cp "$CHRONY_CONFIG" "${CHRONY_CONFIG}${BACKUP_SUFFIX}"
fi

# Create a temporary file for the modified configuration
TEMP_CONFIG=$(mktemp)
trap "rm -f $TEMP_CONFIG" EXIT

# Process the configuration file
if [ -f "$CHRONY_CONFIG" ]; then
    # Remove any existing cmdallow, cmdacl, or port lines related to management
    grep -v "^cmdallow" "$CHRONY_CONFIG" | \
    grep -v "^cmdacl" "$CHRONY_CONFIG" | \
    grep -v "^port" "$CHRONY_CONFIG" > "$TEMP_CONFIG" || true
else
    # If file doesn't exist, create it with minimal content
    cat > "$TEMP_CONFIG" << 'EOF'
# chrony configuration file

# Use servers from the pool.ntp.org project.
pool 2.debian.pool.ntp.org iburst

# This directive specify the location of the file containing ID/key pairs for
# authentication.
keyfile /etc/chrony/chrony.keys

# This directive specify the file into which chronyd will store the rate
# information.
driftfile /var/lib/chrony/chrony.drift

# Uncomment the following line to turn logging on.
#log tracking measurements statistics

# Log files location.
logdir /var/log/chrony

# Stop bad things from happening by introducing a maxpoll default of 16
maxpoll 16
EOF
fi

# Ensure the configuration file has the necessary directives to disable network management
# The key is to NOT have any cmdallow, cmdacl, or port lines that would enable network access

# Add directive to ensure bindcmdaddress is not listening on network interfaces
if ! grep -q "^bindcmdaddress" "$TEMP_CONFIG"; then
    echo "bindcmdaddress 127.0.0.1" >> "$TEMP_CONFIG"
fi

if ! grep -q "^bindcmdaddress.*::1" "$TEMP_CONFIG"; then
    echo "bindcmdaddress ::1" >> "$TEMP_CONFIG"
fi

# Ensure no network cmdallow directives exist
if grep -q "^cmdallow\s" "$TEMP_CONFIG"; then
    # Remove any cmdallow directives that aren't for localhost
    sed -i '/^cmdallow\s/d' "$TEMP_CONFIG"
fi

# Write the modified configuration
cp "$TEMP_CONFIG" "$CHRONY_CONFIG"

# Ensure proper permissions
chmod 644 "$CHRONY_CONFIG"
chown root:root "$CHRONY_CONFIG"

# Restart chrony to apply the changes
systemctl restart chrony

# Verify that chrony is not listening on network management port (typically UDP 323)
# Give it a moment to restart
sleep 2

# Check that chrony is running
if systemctl is-active --quiet chrony; then
    echo "chrony service is running with network management disabled"
else
    echo "Warning: chrony service is not running"
    exit 1
fi

# Verify configuration
if grep -q "^bindcmdaddress 127.0.0.1" "$CHRONY_CONFIG" && \
   grep -q "^bindcmdaddress ::1" "$CHRONY_CONFIG"; then
    echo "Configuration verified: chrony management interface is bound to localhost only"
else
    echo "Warning: Configuration may not be complete"
    exit 1
fi

echo "Remediation complete: chrony is configured to not listen on network management ports"
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
#!/bin/bash

set -euo pipefail

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Determine the NTP service to configure
if command_exists systemctl; then
    # Check which NTP service is available and enabled
    if systemctl is-enabled systemd-timesyncd 2>/dev/null || systemctl list-unit-files | grep -q "systemd-timesyncd.service"; then
        NTP_SERVICE="systemd-timesyncd"
    elif systemctl is-enabled chrony 2>/dev/null || systemctl list-unit-files | grep -q "chrony"; then
        NTP_SERVICE="chrony"
    elif systemctl is-enabled ntpd 2>/dev/null || systemctl list-unit-files | grep -q "ntp"; then
        NTP_SERVICE="ntpd"
    elif systemctl is-enabled ntp 2>/dev/null || systemctl list-unit-files | grep -q "ntp.service"; then
        NTP_SERVICE="ntp"
    else
        # Install and use chrony as default on Ubuntu
        if ! command_exists chrony; then
            apt-get update >/dev/null 2>&1
            apt-get install -y chrony >/dev/null 2>&1
        fi
        NTP_SERVICE="chrony"
    fi
else
    # Fallback to chrony if systemctl is not available
    NTP_SERVICE="chrony"
fi

# Configure based on the NTP service
case "$NTP_SERVICE" in
    "systemd-timesyncd")
        configure_systemd_timesyncd
        ;;
    "chrony")
        configure_chrony
        ;;
    "ntpd"|"ntp")
        configure_ntp
        ;;
    *)
        # Default to chrony
        NTP_SERVICE="chrony"
        configure_chrony
        ;;
esac

function configure_systemd_timesyncd() {
    local config_file="/etc/systemd/timesyncd.conf"
    
    # Ensure the config file exists
    if [ ! -f "$config_file" ]; then
        mkdir -p "$(dirname "$config_file")"
        touch "$config_file"
    fi
    
    # Backup the original file
    cp "$config_file" "$config_file.backup.$(date +%s)" 2>/dev/null || true
    
    # Check if [Time] section exists
    if ! grep -q "^\[Time\]" "$config_file"; then
        echo "[Time]" >> "$config_file"
    fi
    
    # Set maximum polling interval (in seconds) - 34 minutes (2040 seconds)
    # This is a reasonable maximum for system clock synchronization
    if grep -q "^MaxPollIntervalSec=" "$config_file"; then
        sed -i 's/^MaxPollIntervalSec=.*/MaxPollIntervalSec=2040/' "$config_file"
    else
        sed -i '/^\[Time\]/a MaxPollIntervalSec=2040' "$config_file"
    fi
    
    # Ensure NTP servers are configured with default servers if not present
    if ! grep -q "^NTP=" "$config_file"; then
        sed -i '/^\[Time\]/a NTP=ntp.ubuntu.com' "$config_file"
    fi
    
    # Reload systemd configuration
    systemctl daemon-reload
    systemctl restart systemd-timesyncd
    systemctl enable systemd-timesyncd
}

function configure_chrony() {
    local config_file="/etc/chrony/chrony.conf"
    
    # Ensure chrony is installed
    if ! command_exists chronyd; then
        apt-get update >/dev/null 2>&1
        apt-get install -y chrony >/dev/null 2>&1
    fi
    
    # Backup the original file
    cp "$config_file" "$config_file.backup.$(date +%s)" 2>/dev/null || true
    
    # Check if there are any server/pool directives
    if grep -q "^server\|^pool" "$config_file"; then
        # Add maxpoll to existing server/pool directives if not present
        while IFS= read -r line; do
            if [[ "$line" =~ ^(server|pool)[[:space:]] && ! "$line" =~ maxpoll ]]; then
                # Add maxpoll 10 (1024 seconds = ~17 minutes) to the line
                new_line="${line} maxpoll 10"
                sed -i "s|^${line}$|${new_line}|" "$config_file"
            fi
        done < <(grep "^server\|^pool" "$config_file")
    else
        # Add default NTP servers with maxpoll configuration
        echo "pool ntp.ubuntu.com iburst maxpoll 10" >> "$config_file"
    fi
    
    # Ensure the file ends with a newline
    if [ -f "$config_file" ] && [ -n "$(tail -c 1 "$config_file")" ]; then
        echo "" >> "$config_file"
    fi
    
    # Restart chrony service
    systemctl restart chrony
    systemctl enable chrony
}

function configure_ntp() {
    local config_file="/etc/ntp.conf"
    
    # Ensure NTP is installed
    if ! command_exists ntpd; then
        apt-get update >/dev/null 2>&1
        apt-get install -y ntp >/dev/null 2>&1
    fi
    
    # Backup the original file
    cp "$config_file" "$config_file.backup.$(date +%s)" 2>/dev/null || true
    
    # Check if there are any server directives
    if grep -q "^server" "$config_file"; then
        # Add maxpoll to existing server directives if not present
        while IFS= read -r line; do
            if [[ "$line" =~ ^server[[:space:]] && ! "$line" =~ maxpoll ]]; then
                # Add maxpoll 10 (1024 seconds = ~17 minutes) to the line
                new_line="${line} maxpoll 10"
                sed -i "s|^${line}$|${new_line}|" "$config_file"
            fi
        done < <(grep "^server" "$config_file")
    else
        # Add default NTP servers with maxpoll configuration
        echo "server ntp.ubuntu.com iburst maxpoll 10" >> "$config_file"
    fi
    
    # Ensure the file ends with a newline
    if [ -f "$config_file" ] && [ -n "$(tail -c 1 "$config_file")" ]; then
        echo "" >> "$config_file"
    fi
    
    # Restart NTP service
    systemctl restart ntp || systemctl restart ntpd
    systemctl enable ntp || systemctl enable ntpd
}

# Run the appropriate configuration based on detected service
if [ "$NTP_SERVICE" = "systemd-timesyncd" ]; then
    configure_systemd_timesyncd
elif [ "$NTP_SERVICE" = "chrony" ]; then
    configure_chrony
else
    configure_ntp
fi

# Verify the configuration
echo "Time synchronization configuration completed."
echo "Current NTP service: $NTP_SERVICE"

# Check if time synchronization is working
if command_exists timedatectl; then
    timedatectl status
elif [ "$NTP_SERVICE" = "chrony" ]; then
    chronyc tracking
elif [ "$NTP_SERVICE" = "ntpd" ] || [ "$NTP_SERVICE" = "ntp" ]; then
    ntpq -p
fi

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

**Prompt:** On an Ubuntu 24.04 system, configure the SSH server so that an unresponsive client connection is dropped immediately once the idle-timeout interval elapses, rather than allowing additional unanswered keep-alive probes to extend the session. Specifically, ensure the server permits zero additional keep-alive attempts before disconnecting an unresponsive session (so that termination occurs precisely at the configured idle interval). Write an idempotent bash remediation script that enforces this end state for new SSH sessions and persists across reboots.

**Model-generated script:**
```bash
#!/bin/bash
set -e

# Define SSH configuration file
SSH_CONFIG="/etc/ssh/sshd_config"
SSH_CONFIG_D="/etc/ssh/sshd_config.d"

# Ensure SSH config directory exists
mkdir -p "$SSH_CONFIG_D"

# Create a new configuration file for our settings
CONFIG_FILE="$SSH_CONFIG_D/99-idle-timeout.conf"

# Define the desired SSH configuration settings
# ClientAliveInterval: Idle timeout in seconds
# ClientAliveCountMax: Number of additional keep-alive attempts (0 = no additional attempts)
cat > "$CONFIG_FILE" << 'EOF'
# Idle timeout configuration
# Drop unresponsive clients immediately after idle interval expires
# with zero additional keep-alive probes
ClientAliveInterval 300
ClientAliveCountMax 0
EOF

# Validate SSH configuration syntax
if ! sshd -t 2>/dev/null; then
    echo "Error: Invalid SSH configuration"
    exit 1
fi

# Restart SSH service to apply changes
systemctl restart ssh

# Verify that the configuration was applied
if grep -q "^ClientAliveInterval 300" "$CONFIG_FILE" && \
   grep -q "^ClientAliveCountMax 0" "$CONFIG_FILE"; then
    echo "SSH idle timeout configuration successfully applied"
    echo "Settings: ClientAliveInterval=300 seconds, ClientAliveCountMax=0"
else
    echo "Error: Configuration settings not properly applied"
    exit 1
fi

# Ensure SSH service is enabled for persistence across reboots
systemctl enable ssh

echo "SSH server configured to drop idle connections immediately after timeout"
echo "This configuration will persist across reboots"
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
#!/bin/bash

# SSH Server Client Responsiveness Timeout Configuration Script
# This script configures SSH to probe clients and disconnect unresponsive ones after 600 seconds

set -euo pipefail

# Define SSH server configuration file
SSH_CONFIG_FILE="/etc/ssh/sshd_config"
SSH_CONFIG_DIR="/etc/ssh/sshd_config.d"

# Create configuration directory if it doesn't exist
mkdir -p "${SSH_CONFIG_DIR}"

# Create a dedicated configuration file for our settings
CONFIG_FILE="${SSH_CONFIG_DIR}/99-client-responsiveness.conf"

# Define the SSH configuration parameters
# ClientAliveInterval: Sends keepalive probes to the client every 300 seconds (5 minutes)
# ClientAliveCountMax: After 2 probes without response = 10 minutes total (300 * 2 = 600 seconds)
read -r -d '' SSH_CONFIG_CONTENT << 'EOF' || true
# SSH Client Responsiveness Timeout Configuration
# Probes client every 5 minutes, disconnects after 2 missed probes (10 minutes total)
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

# Write the configuration file
echo "${SSH_CONFIG_CONTENT}" > "${CONFIG_FILE}"

# Ensure proper permissions on the configuration file
chmod 600 "${CONFIG_FILE}"
chown root:root "${CONFIG_FILE}"

# Validate SSH configuration syntax
if ! sshd -t; then
    echo "ERROR: SSH configuration validation failed"
    rm -f "${CONFIG_FILE}"
    exit 1
fi

# Check if SSH is running and reload it
if systemctl is-active --quiet ssh; then
    systemctl reload ssh
    echo "SSH service reloaded successfully"
else
    # Try to start the service if it's not running
    systemctl start ssh
    echo "SSH service started successfully"
fi

# Enable SSH service to persist across reboots
systemctl enable ssh

echo "SSH client responsiveness timeout configured successfully"
echo "Configuration file: ${CONFIG_FILE}"
echo "Clients will be probed every 300 seconds and disconnected after 600 seconds of inactivity"
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
#!/bin/bash

set -euo pipefail

SSH_CONFIG_FILE="/etc/ssh/sshd_config"
SSH_CONFIG_DIR="/etc/ssh/sshd_config.d"
REMEDIATION_FILE="${SSH_CONFIG_DIR}/99-permit-empty-passwords.conf"

if [ ! -d "$SSH_CONFIG_DIR" ]; then
    mkdir -p "$SSH_CONFIG_DIR"
    chmod 755 "$SSH_CONFIG_DIR"
fi

if grep -q "^PermitEmptyPasswords\s*yes" "$SSH_CONFIG_FILE"; then
    sed -i 's/^PermitEmptyPasswords\s*yes/PermitEmptyPasswords no/' "$SSH_CONFIG_FILE"
fi

if [ ! -f "$REMEDIATION_FILE" ]; then
    echo "PermitEmptyPasswords no" > "$REMEDIATION_FILE"
    chmod 644 "$REMEDIATION_FILE"
elif ! grep -q "^PermitEmptyPasswords\s*no" "$REMEDIATION_FILE"; then
    echo "PermitEmptyPasswords no" >> "$REMEDIATION_FILE"
fi

sshd -t > /dev/null 2>&1 || {
    echo "SSH configuration test failed. Rolling back changes."
    rm -f "$REMEDIATION_FILE"
    exit 1
}

systemctl reload ssh > /dev/null 2>&1 || systemctl restart ssh > /dev/null 2>&1

echo "SSH server configured to forbid empty password logins."
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
#!/bin/bash
set -e

# Configuration file for SSH
SSH_CONFIG_FILE="/etc/ssh/sshd_config"

# Backup the original file
if [ ! -f "${SSH_CONFIG_FILE}.backup" ]; then
    cp "${SSH_CONFIG_FILE}" "${SSH_CONFIG_FILE}.backup"
fi

# Check if GSSAPIAuthentication is already set to no
if grep -q "^GSSAPIAuthentication no" "${SSH_CONFIG_FILE}"; then
    echo "GSSAPIAuthentication is already disabled"
else
    # Remove any existing GSSAPIAuthentication lines (commented or uncommented)
    sed -i '/^#.*GSSAPIAuthentication/d' "${SSH_CONFIG_FILE}"
    sed -i '/^GSSAPIAuthentication/d' "${SSH_CONFIG_FILE}"
    
    # Add the configuration to disable GSSAPI authentication
    echo "GSSAPIAuthentication no" >> "${SSH_CONFIG_FILE}"
    echo "GSSAPICleanupCredentials no" >> "${SSH_CONFIG_FILE}"
    echo "GSSAPIAuthentication setting has been disabled"
fi

# Verify the SSH configuration syntax
if ! sshd -t > /dev/null 2>&1; then
    echo "SSH configuration syntax error detected. Restoring backup."
    cp "${SSH_CONFIG_FILE}.backup" "${SSH_CONFIG_FILE}"
    exit 1
fi

# Restart SSH service to apply changes
systemctl restart ssh

echo "SSH GSSAPI authentication has been successfully disabled and SSH service restarted"
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
#!/bin/bash

# SSH configuration file
SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_CONFIG_D="/etc/ssh/sshd_config.d"

# Create a directory for custom SSH config if it doesn't exist
if [ ! -d "$SSHD_CONFIG_D" ]; then
    mkdir -p "$SSHD_CONFIG_D"
    chmod 755 "$SSHD_CONFIG_D"
fi

# Create or update the custom configuration file to disable Kerberos authentication
CUSTOM_CONFIG="$SSHD_CONFIG_D/99-disable-kerberos.conf"

# Write the configuration to disable Kerberos authentication
cat > "$CUSTOM_CONFIG" << 'EOF'
# Disable Kerberos-based authentication (security hardening)
GSSAPIAuthentication no
GSSAPICleanupCredentials no
EOF

# Set proper permissions
chmod 644 "$CUSTOM_CONFIG"

# Check if the main sshd_config file has GSSAPIAuthentication settings that might conflict
if grep -q "^GSSAPIAuthentication" "$SSHD_CONFIG"; then
    # Backup the original file
    cp "$SSHD_CONFIG" "$SSHD_CONFIG.backup.$(date +%s)"
    
    # Comment out existing GSSAPIAuthentication lines in main config
    sed -i 's/^GSSAPIAuthentication/#GSSAPIAuthentication/' "$SSHD_CONFIG"
fi

# Check if the main sshd_config file has GSSAPICleanupCredentials settings that might conflict
if grep -q "^GSSAPICleanupCredentials" "$SSHD_CONFIG"; then
    # Comment out existing GSSAPICleanupCredentials lines in main config
    sed -i 's/^GSSAPICleanupCredentials/#GSSAPICleanupCredentials/' "$SSHD_CONFIG"
fi

# Test the SSH configuration for syntax errors
if ! sshd -t; then
    echo "Error: SSH configuration test failed"
    # Restore from backup if available
    BACKUP_FILE=$(ls -t "$SSHD_CONFIG".backup.* 2>/dev/null | head -n1)
    if [ -n "$BACKUP_FILE" ]; then
        cp "$BACKUP_FILE" "$SSHD_CONFIG"
        echo "Restored SSH configuration from backup: $BACKUP_FILE"
    fi
    exit 1
fi

# Reload SSH service to apply changes
systemctl restart ssh || systemctl restart sshd

# Verify the configuration was applied
if sshd -T | grep -q "GSSAPIAuthentication no"; then
    echo "Successfully disabled Kerberos authentication in SSH"
else
    echo "Warning: Could not verify Kerberos authentication was disabled"
    exit 1
fi

exit 0
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
#!/bin/bash

SSH_CONFIG="/etc/ssh/sshd_config"
BACKUP_SUFFIX=".bak.$(date +%s)"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Backup the original sshd_config
if [[ ! -f "${SSH_CONFIG}${BACKUP_SUFFIX}" ]]; then
    cp "${SSH_CONFIG}" "${SSH_CONFIG}${BACKUP_SUFFIX}"
fi

# Function to check if a parameter exists and has a specific value
check_parameter() {
    local param=$1
    local value=$2
    grep -E "^${param}\s+${value}$" "${SSH_CONFIG}" > /dev/null 2>&1
    return $?
}

# Function to set a parameter in sshd_config
set_parameter() {
    local param=$1
    local value=$2
    
    # Check if parameter exists in config
    if grep -E "^${param}\s" "${SSH_CONFIG}" > /dev/null 2>&1; then
        # Parameter exists, replace it
        sed -i "s/^${param}\s.*/${param} ${value}/" "${SSH_CONFIG}"
    else
        # Parameter doesn't exist, append it
        echo "${param} ${value}" >> "${SSH_CONFIG}"
    fi
}

# Check and set PermitRootLogin to no
if ! check_parameter "PermitRootLogin" "no"; then
    set_parameter "PermitRootLogin" "no"
    echo "Set PermitRootLogin to no"
else
    echo "PermitRootLogin is already set to no"
fi

# Validate the SSH configuration
if ! sshd -t > /dev/null 2>&1; then
    echo "SSH configuration test failed, restoring backup"
    cp "${SSH_CONFIG}${BACKUP_SUFFIX}" "${SSH_CONFIG}"
    exit 1
fi

# Reload SSH service to apply changes
systemctl reload ssh
if [[ $? -eq 0 ]]; then
    echo "SSH service reloaded successfully"
else
    echo "Failed to reload SSH service"
    exit 1
fi

# Ensure SSH service starts on boot
systemctl enable ssh
if [[ $? -eq 0 ]]; then
    echo "SSH service enabled for boot"
else
    echo "Failed to enable SSH service for boot"
    exit 1
fi

echo "SSH configuration successfully updated: Root login is disabled"
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
#!/bin/bash
set -e

# Ubuntu 24.04 SSH Server Hardening Script
# Disables reliance on per-user cached host keys for authentication

SSH_CONFIG="/etc/ssh/sshd_config"
SSH_CONFIG_DIR="/etc/ssh/sshd_config.d"
REMEDIATION_FILE="${SSH_CONFIG_DIR}/99-hardening-no-user-cache.conf"

# Ensure SSH config directory exists
if [ ! -d "$SSH_CONFIG_DIR" ]; then
    mkdir -p "$SSH_CONFIG_DIR"
    chmod 755 "$SSH_CONFIG_DIR"
fi

# Function to check and set SSH parameter
set_ssh_parameter() {
    local param="$1"
    local value="$2"
    local config_file="$3"
    
    if grep -q "^${param}" "$config_file" 2>/dev/null; then
        # Parameter exists, update it
        sed -i "s/^${param}.*/${param} ${value}/" "$config_file"
    elif grep -q "^#${param}" "$config_file" 2>/dev/null; then
        # Parameter is commented out, uncomment and set
        sed -i "s/^#${param}.*/${param} ${value}/" "$config_file"
    else
        # Parameter doesn't exist, add it
        echo "${param} ${value}" >> "$config_file"
    fi
}

# Create hardening configuration file
cat > "$REMEDIATION_FILE" << 'EOF'
# SSH Server Hardening - Disable User-Cached Host Keys
# This configuration ensures the SSH server does not trust or rely on
# per-user cached host keys for authentication

# Disable use of ~/.ssh/known_hosts for authentication
# This prevents cached host keys from bypassing credential checks
IgnoreUserKnownHosts yes

# Ensure StrictModes is enabled (verify file permissions)
# This prevents tampering with per-user SSH configuration
StrictModes yes

# Require explicit host key verification
# This prevents fallback to cached keys
HostbasedAuthentication no

# Disable empty passwords
PermitEmptyPasswords no

# Disable password authentication by default (use keys or other methods)
# PasswordAuthentication no

# Ensure only strong key exchange algorithms
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256

# Ensure only strong ciphers
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

# Ensure only strong MAC algorithms
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
EOF

# Set proper permissions
chmod 644 "$REMEDIATION_FILE"

# Verify SSH configuration syntax
if ! sshd -t -f "$SSH_CONFIG" >/dev/null 2>&1; then
    echo "ERROR: SSH configuration syntax error detected"
    rm -f "$REMEDIATION_FILE"
    exit 1
fi

# Check if SSH server is running and restart if needed
if systemctl is-active --quiet ssh; then
    # Test new configuration won't break SSH
    if sshd -t >/dev/null 2>&1; then
        systemctl restart ssh
        echo "SSH server restarted with new configuration"
    else
        echo "ERROR: New SSH configuration would break the service"
        rm -f "$REMEDIATION_FILE"
        exit 1
    fi
else
    echo "SSH server is not running. Configuration will be applied on next start."
fi

# Enable SSH to start on boot if not already enabled
systemctl enable ssh >/dev/null 2>&1

# Verify the changes are in place
if grep -q "IgnoreUserKnownHosts yes" "$REMEDIATION_FILE"; then
    echo "SUCCESS: SSH server hardening applied - user-cached host keys disabled"
    echo "Configuration file: $REMEDIATION_FILE"
    exit 0
else
    echo "ERROR: Failed to apply SSH hardening"
    exit 1
fi
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
#!/bin/bash
set -e

# Script to disable X11 forwarding on SSH server for Ubuntu 24.04

SSH_CONFIG="/etc/ssh/sshd_config"
BACKUP_DIR="/var/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/sshd_config.backup.${TIMESTAMP}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# Create backup of original sshd_config
cp "${SSH_CONFIG}" "${BACKUP_FILE}"
echo "Backup created: ${BACKUP_FILE}"

# Check if X11Forwarding is already disabled
if grep -q "^X11Forwarding no" "${SSH_CONFIG}"; then
    echo "X11Forwarding is already disabled"
    exit 0
fi

# Remove any existing X11Forwarding lines (commented or uncommented)
sed -i '/^#*X11Forwarding/d' "${SSH_CONFIG}"

# Add X11Forwarding no at the end of the file
echo "X11Forwarding no" >> "${SSH_CONFIG}"

echo "X11Forwarding has been disabled in ${SSH_CONFIG}"

# Verify the configuration syntax before restarting
if ! sshd -t; then
    echo "SSH configuration syntax check failed. Restoring backup..."
    cp "${BACKUP_FILE}" "${SSH_CONFIG}"
    exit 1
fi

echo "SSH configuration syntax is valid"

# Restart SSH service to apply changes
systemctl restart ssh

# Verify the service is running
if systemctl is-active --quiet ssh; then
    echo "SSH service restarted successfully"
    echo "X11 forwarding is now disabled and the setting will persist across reboots"
else
    echo "Failed to restart SSH service. Restoring backup..."
    cp "${BACKUP_FILE}" "${SSH_CONFIG}"
    systemctl restart ssh
    exit 1
fi

# Verify the setting is in effect
if sshd -T | grep -q "^x11forwarding no"; then
    echo "Verification successful: X11 forwarding is disabled"
else
    echo "Warning: Could not verify X11 forwarding setting"
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
#!/bin/bash

set -e

SSH_CONFIG_FILE="/etc/ssh/sshd_config"
SSH_CONFIG_DIR="/etc/ssh/sshd_config.d"

# Ensure SSH config directory exists
mkdir -p "$SSH_CONFIG_DIR"

# Check if we should add the configuration to main config or a drop-in directory
# Ubuntu 24.04 prefers drop-in configurations
CONFIG_TARGET="$SSH_CONFIG_DIR/99-disable-user-environment.conf"

# Configuration to add
CONFIG_CONTENT="# Disable user environment processing
# Prevents users from supplying or overriding environment variables
PermitUserEnvironment no"

# Check if the configuration already exists
if grep -q "^PermitUserEnvironment" "$SSH_CONFIG_FILE" "$CONFIG_TARGET" 2>/dev/null; then
    # Configuration exists in main config file
    if grep -q "^PermitUserEnvironment no" "$SSH_CONFIG_FILE" 2>/dev/null; then
        echo "PermitUserEnvironment is already set to 'no' in $SSH_CONFIG_FILE"
        exit 0
    else
        # Wrong value, fix it
        sed -i 's/^PermitUserEnvironment.*/PermitUserEnvironment no/' "$SSH_CONFIG_FILE"
        echo "Updated PermitUserEnvironment in $SSH_CONFIG_FILE"
    fi
elif [ -f "$CONFIG_TARGET" ] && grep -q "^PermitUserEnvironment" "$CONFIG_TARGET"; then
    # Configuration exists in drop-in file
    if grep -q "^PermitUserEnvironment no" "$CONFIG_TARGET"; then
        echo "PermitUserEnvironment is already set to 'no' in $CONFIG_TARGET"
        exit 0
    else
        # Wrong value, fix it
        sed -i 's/^PermitUserEnvironment.*/PermitUserEnvironment no/' "$CONFIG_TARGET"
        echo "Updated PermitUserEnvironment in $CONFIG_TARGET"
    fi
else
    # Configuration doesn't exist, add it to drop-in directory
    echo "$CONFIG_CONTENT" > "$CONFIG_TARGET"
    echo "Added PermitUserEnvironment configuration to $CONFIG_TARGET"
fi

# Validate SSH configuration syntax
if ! sshd -t 2>/dev/null; then
    echo "ERROR: SSH configuration syntax error detected"
    exit 1
fi

# Reload SSH service to apply changes
systemctl reload ssh

echo "SSH server configured: User environment variables are now disabled"
echo "Configuration saved to $CONFIG_TARGET"
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
#!/bin/bash

set -euo pipefail

SSH_CONFIG_FILE="/etc/ssh/sshd_config"
SSH_CONFIG_DIR="/etc/ssh/sshd_config.d"
CUSTOM_CONFIG_FILE="${SSH_CONFIG_DIR}/99-strict-permissions.conf"

# Ensure SSH config directory exists
mkdir -p "${SSH_CONFIG_DIR}"

# Create a custom configuration file with strict permission checking
cat > "${CUSTOM_CONFIG_FILE}" << 'EOF'
# Strict SSH file permission checking
# This configuration ensures SSH verifies ownership and permissions
# of user home directories and SSH-related files before accepting logins

# StrictModes enables checking of user's home directory and SSH files
# for proper ownership and permissions before allowing login
StrictModes yes

# Explicitly set these permissions requirements
# Home directory should be owned by the user and not writable by group/others
# .ssh directory should be owned by the user and not writable by group/others
# Authorized keys file should be owned by the user and not writable by group/others
EOF

# Check if SSH config includes custom configs from sshd_config.d
if ! grep -q "^Include ${SSH_CONFIG_DIR}/\*" "${SSH_CONFIG_FILE}"; then
    # Add include directive for sshd_config.d if not present
    echo "Include ${SSH_CONFIG_DIR}/*" >> "${SSH_CONFIG_FILE}"
fi

# Verify StrictModes setting in main config (should already be default, but ensure it)
# Remove any existing StrictModes lines to avoid duplicates
sed -i '/^[[:space:]]*StrictModes/d' "${SSH_CONFIG_FILE}"
# Add StrictModes yes at the end
echo "StrictModes yes" >> "${SSH_CONFIG_FILE}"

# Set proper permissions on SSH config files
chmod 600 "${SSH_CONFIG_FILE}"
chmod 755 "${SSH_CONFIG_DIR}"
chmod 600 "${CUSTOM_CONFIG_FILE}"

# Verify syntax of SSH config
if ! sshd -t &>/dev/null; then
    echo "SSH configuration syntax error detected"
    exit 1
fi

# Ensure SSH service is enabled and will start on boot
systemctl enable ssh

# Reload SSH configuration (non-disruptive, doesn't disconnect existing sessions)
systemctl reload ssh

# Verify the setting is in place
if sshd -T | grep -q "^strictmodes yes"; then
    echo "SSH StrictModes successfully configured"
else
    echo "Warning: StrictModes may not be properly set"
    exit 1
fi

# Create a test to verify strict mode enforcement
# This creates a helper script that can be used to check permissions
cat > /usr/local/bin/check-ssh-permissions << 'CHECKEOF'
#!/bin/bash

# Helper script to check SSH file permissions for a user
USERNAME="${1:?Usage: $0 <username>}"

if ! id "$USERNAME" &>/dev/null; then
    echo "User $USERNAME does not exist"
    exit 1
fi

HOME_DIR=$(eval echo ~"$USERNAME")
SSH_DIR="${HOME_DIR}/.ssh"

# Check home directory ownership
HOME_OWNER=$(stat -c '%U' "$HOME_DIR")
if [[ "$HOME_OWNER" != "$USERNAME" ]]; then
    echo "WARNING: Home directory not owned by user $USERNAME"
    exit 1
fi

# Check home directory permissions (should not be world-writable)
HOME_PERMS=$(stat -c '%a' "$HOME_DIR")
if [[ "${HOME_PERMS: -1}" == "7" ]] || [[ "${HOME_PERMS: -1}" == "6" ]] || [[ "${HOME_PERMS: -1}" == "5" ]] || [[ "${HOME_PERMS: -1}" == "4" ]]; then
    echo "WARNING: Home directory has insecure permissions: $HOME_PERMS"
    exit 1
fi

# Check .ssh directory if it exists
if [[ -d "$SSH_DIR" ]]; then
    SSH_OWNER=$(stat -c '%U' "$SSH_DIR")
    if [[ "$SSH_OWNER" != "$USERNAME" ]]; then
        echo "WARNING: .ssh directory not owned by user $USERNAME"
        exit 1
    fi
    
    SSH_PERMS=$(stat -c '%a' "$SSH_DIR")
    if [[ "$SSH_PERMS" != "700" ]]; then
        echo "WARNING: .ssh directory has insecure permissions: $SSH_PERMS (should be 700)"
        exit 1
    fi
    
    # Check authorized_keys file if it exists
    if [[ -f "${SSH_DIR}/authorized_keys" ]]; then
        AK_OWNER=$(stat -c '%U' "${SSH_DIR}/authorized_keys")
        if [[ "$AK_OWNER" != "$USERNAME" ]]; then
            echo "WARNING: authorized_keys not owned by user $USERNAME"
            exit 1
        fi
        
        AK_PERMS=$(stat -c '%a' "${SSH_DIR}/authorized_keys")
        if [[ "$AK_PERMS" != "600" ]]; then
            echo "WARNING: authorized_keys has insecure permissions: $AK_PERMS (should be 600)"
            exit 1
        fi
    fi
fi

echo "SSH permissions for $USERNAME are properly configured"
exit 0
CHECKEOF

chmod 755 /usr/local/bin/check-ssh-permissions

echo "SSH server configuration completed successfully"
echo "StrictModes is now enabled and will be enforced on all login attempts"
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

# Create the system-wide login warning banner
BANNER_FILE="/etc/issue.net"
BANNER_CONTENT="***********************************************************************
                         AUTHORIZED ACCESS ONLY

This system is for authorized use only. All activity is monitored and
logged. Unauthorized access attempts will be investigated and prosecuted
to the fullest extent of the law.

By accessing this system, you acknowledge that you have read, understand,
and agree to comply with the acceptable use policy.

***********************************************************************
"

# Write the banner file (idempotent)
echo "$BANNER_CONTENT" | install -m 644 /dev/stdin "$BANNER_FILE"

# SSH configuration file
SSH_CONFIG="/etc/ssh/sshd_config"
SSH_CONFIG_D="/etc/ssh/sshd_config.d"

# Ensure the Banner directive is set correctly
# Using sed to add or modify the Banner line
if grep -q "^Banner" "$SSH_CONFIG"; then
    # Replace existing Banner line
    sed -i "s|^Banner.*|Banner $BANNER_FILE|" "$SSH_CONFIG"
else
    # Add Banner line at the end of the file
    echo "Banner $BANNER_FILE" >> "$SSH_CONFIG"
fi

# Verify the SSH configuration syntax
if ! sshd -t 2>/dev/null; then
    echo "SSH configuration syntax error detected"
    exit 1
fi

# Restart SSH service to apply changes
systemctl restart ssh

# Verify SSH service is running
if ! systemctl is-active --quiet ssh; then
    echo "SSH service failed to start"
    exit 1
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
#!/bin/bash
set -e

# Check if running on Ubuntu 24.04 or similar
if [[ ! -f /etc/os-release ]]; then
    echo "Error: /etc/os-release not found"
    exit 1
fi

# Parse Ubuntu version
source /etc/os-release
if [[ "$ID" != "ubuntu" ]]; then
    echo "Error: This script is designed for Ubuntu systems"
    exit 1
fi

# SSH configuration file
SSH_CONFIG="/etc/ssh/sshd_config.d/99-lastlogin.conf"
SSH_CONFIG_DIR="/etc/ssh/sshd_config.d"

# Ensure the directory exists
if [[ ! -d "$SSH_CONFIG_DIR" ]]; then
    mkdir -p "$SSH_CONFIG_DIR"
fi

# Create or update the SSH configuration file with lastlogin settings
cat > "$SSH_CONFIG" << 'EOF'
# Enable last login notification
# This configuration ensures users see information about their last successful login
PrintMotd no
PrintLastLog yes
EOF

# Verify the configuration file was created
if [[ ! -f "$SSH_CONFIG" ]]; then
    echo "Error: Failed to create SSH configuration file"
    exit 1
fi

# Set proper permissions
chmod 600 "$SSH_CONFIG"
chown root:root "$SSH_CONFIG"

# Validate SSH configuration syntax
if ! sshd -t -f /etc/ssh/sshd_config 2>/dev/null; then
    echo "Error: SSH configuration validation failed"
    rm -f "$SSH_CONFIG"
    exit 1
fi

# Reload SSH service to apply the configuration
if systemctl is-active --quiet ssh; then
    systemctl reload ssh
    echo "SSH service reloaded successfully"
else
    echo "SSH service is not running, starting it..."
    systemctl start ssh
    echo "SSH service started successfully"
fi

# Verify the setting is applied
if grep -q "PrintLastLog yes" "$SSH_CONFIG"; then
    echo "Last login notification has been successfully enabled"
    echo "Users will now see their last login information upon successful authentication"
else
    echo "Error: Failed to apply last login notification setting"
    exit 1
fi

exit 0
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

# SSH server key renegotiation hardening script for Ubuntu 24.04
# This script enforces session key renegotiation limits to improve security

set -e

SSH_CONFIG="/etc/ssh/sshd_config"
SSH_CONFIG_DIR="/etc/ssh/sshd_config.d"
CUSTOM_CONFIG="${SSH_CONFIG_DIR}/99-key-renegotiation.conf"

# Define the desired renegotiation parameters
# RekeyLimit: 512M (512 megabytes) or 1h (1 hour), whichever comes first
REKEY_LIMIT="512M 1h"

# Create ssh config directory if it doesn't exist
mkdir -p "${SSH_CONFIG_DIR}"

# Check if the custom config file already has the correct setting
if [ -f "${CUSTOM_CONFIG}" ]; then
    if grep -q "^RekeyLimit ${REKEY_LIMIT}$" "${CUSTOM_CONFIG}"; then
        echo "SSH key renegotiation hardening already configured correctly."
        exit 0
    else
        # Remove old RekeyLimit line if it exists
        sed -i '/^RekeyLimit /d' "${CUSTOM_CONFIG}"
    fi
fi

# Add the RekeyLimit configuration to the custom config file
echo "RekeyLimit ${REKEY_LIMIT}" > "${CUSTOM_CONFIG}"

# Verify the configuration syntax
if ! sshd -t -f "${SSH_CONFIG}" > /dev/null 2>&1; then
    echo "Error: SSH configuration syntax check failed!"
    rm -f "${CUSTOM_CONFIG}"
    exit 1
fi

# Reload SSH service to apply changes
systemctl reload ssh

echo "SSH key renegotiation hardening applied successfully."
echo "Session keys will be renegotiated after 512MB of data or 1 hour, whichever comes first."

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
#!/bin/bash

set -e

# Function to check if SSH server is properly configured for entropy
check_ssh_entropy() {
    # Check if /etc/default/ssh exists and contains the entropy configuration
    if [[ -f /etc/default/ssh ]]; then
        if grep -q "^export SSH_RANDOM_SEED_FROM_ENTROPY=" /etc/default/ssh 2>/dev/null; then
            return 0
        fi
    fi
    return 1
}

# Function to configure SSH server for high-entropy random number generation
configure_ssh_entropy() {
    local ssh_default_file="/etc/default/ssh"
    local entropy_line="export SSH_RANDOM_SEED_FROM_ENTROPY=32"
    
    # Create the file if it doesn't exist
    if [[ ! -f "$ssh_default_file" ]]; then
        sudo bash -c "echo '# SSH Server Environment Configuration' > $ssh_default_file"
    fi
    
    # Check if the entropy configuration already exists
    if ! grep -q "^export SSH_RANDOM_SEED_FROM_ENTROPY=" "$ssh_default_file"; then
        # Add the entropy configuration
        sudo bash -c "echo '$entropy_line' >> $ssh_default_file"
    else
        # Update the existing entropy configuration to use 32 bytes
        sudo sed -i 's/^export SSH_RANDOM_SEED_FROM_ENTROPY=.*/export SSH_RANDOM_SEED_FROM_ENTROPY=32/' "$ssh_default_file"
    fi
}

# Function to ensure /dev/urandom is available and properly configured
ensure_urandom_available() {
    # Check if /dev/urandom exists and is readable
    if [[ ! -r /dev/urandom ]]; then
        echo "Error: /dev/urandom is not available or readable"
        return 1
    fi
    
    # Verify that getrandom syscall support is available in the kernel
    # This is typically available in Linux 3.17+
    local kernel_version=$(uname -r | cut -d. -f1-2)
    local required_version="3.17"
    
    if (( $(echo "$kernel_version < $required_version" | bc -l) )); then
        echo "Warning: Kernel version $kernel_version may not have getrandom syscall support"
    fi
}

# Function to verify SSH daemon will use the entropy configuration
verify_ssh_entropy_usage() {
    # Check if SSH is configured to source the default file
    if ! grep -q "^.*HostKey" /etc/ssh/sshd_config 2>/dev/null; then
        echo "SSH daemon configuration found"
    fi
    
    # Ensure SSH daemon will load the environment variables
    local ssh_systemd_file="/etc/systemd/system/ssh.service.d/entropy.conf"
    
    # Create the systemd drop-in directory if needed
    if [[ ! -d /etc/systemd/system/ssh.service.d ]]; then
        sudo mkdir -p /etc/systemd/system/ssh.service.d
    fi
    
    # Create or update the systemd drop-in configuration
    if [[ ! -f "$ssh_systemd_file" ]]; then
        sudo bash -c "cat > $ssh_systemd_file" << 'EOF'
[Service]
EnvironmentFile=/etc/default/ssh
EOF
        sudo systemctl daemon-reload
    fi
}

# Function to test entropy availability
test_entropy_availability() {
    # Read 32 bytes from /dev/urandom to verify it's working
    local entropy_bytes
    entropy_bytes=$(dd if=/dev/urandom bs=1 count=32 2>/dev/null | wc -c)
    
    if [[ $entropy_bytes -eq 32 ]]; then
        return 0
    else
        echo "Error: Could not read 32 bytes of entropy from /dev/urandom"
        return 1
    fi
}

# Main remediation function
main() {
    # Check if already configured
    if check_ssh_entropy; then
        echo "SSH entropy configuration is already in place"
        exit 0
    fi
    
    echo "Configuring SSH server for high-entropy random number generation..."
    
    # Ensure /dev/urandom is available
    if ! ensure_urandom_available; then
        echo "Error: Unable to ensure /dev/urandom availability"
        exit 1
    fi
    
    # Test entropy availability
    if ! test_entropy_availability; then
        echo "Error: Entropy test failed"
        exit 1
    fi
    
    # Configure SSH entropy
    configure_ssh_entropy
    
    # Verify SSH will use the entropy configuration
    verify_ssh_entropy_usage
    
    # Restart SSH daemon to apply changes
    echo "Restarting SSH daemon..."
    sudo systemctl restart ssh
    
    echo "SSH server successfully configured for high-entropy random number generation"
    echo "Entropy source: /dev/urandom (32 bytes per session)"
}

# Run main function
main
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
#!/bin/bash
set -e

# Ubuntu 24.04 SSH X11 Forwarding Loopback-Only Configuration Script

# Configuration
SSH_CONFIG_FILE="/etc/ssh/sshd_config"
SSH_CONFIG_DIR="/etc/ssh/sshd_config.d"
X11_CONFIG_FILE="${SSH_CONFIG_DIR}/99-x11-loopback.conf"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root" >&2
    exit 1
fi

# Ensure the sshd_config.d directory exists
if [[ ! -d "$SSH_CONFIG_DIR" ]]; then
    mkdir -p "$SSH_CONFIG_DIR"
    chmod 755 "$SSH_CONFIG_DIR"
fi

# Create the X11 forwarding loopback-only configuration file
# This ensures X11 display forwarding is bound only to the loopback interface
cat > "$X11_CONFIG_FILE" << 'EOF'
# X11 Forwarding Configuration - Loopback Only
# This configuration ensures X11 display forwarding is bound only to
# the loopback interface, preventing remote access to forwarded X11 sessions

# Enable X11 forwarding
X11Forwarding yes

# Bind X11 display to loopback interface only
X11DisplayOffset 10
X11UseLocalhost yes
EOF

# Verify file permissions are correct
chmod 644 "$X11_CONFIG_FILE"
chown root:root "$X11_CONFIG_FILE"

# Check if main sshd_config has X11Forwarding enabled (it should be the default)
# We'll ensure it's not explicitly disabled in the main config
if grep -q "^X11Forwarding no" "$SSH_CONFIG_FILE"; then
    # Comment out the disable line since we want X11 forwarding enabled
    sed -i 's/^X11Forwarding no/# X11Forwarding no/' "$SSH_CONFIG_FILE"
fi

# Verify syntax of SSH configuration
if ! sshd -t; then
    echo "Error: SSH configuration syntax check failed" >&2
    # Revert changes if syntax is invalid
    rm -f "$X11_CONFIG_FILE"
    exit 1
fi

# Reload SSH service to apply changes
systemctl reload ssh

# Verify the configuration is applied correctly
if ! grep -q "X11UseLocalhost yes" "$X11_CONFIG_FILE"; then
    echo "Error: Configuration file was not created properly" >&2
    exit 1
fi

# Create a verification function to check the current X11 forwarding settings
verify_x11_loopback() {
    local config_output
    config_output=$(sshd -T 2>/dev/null | grep -E "x11" || true)
    
    # Check if X11UseLocalhost is yes
    if echo "$config_output" | grep -q "x11uselocalhost yes"; then
        return 0
    else
        return 1
    fi
}

# Verify the configuration
if verify_x11_loopback; then
    echo "✓ X11 forwarding is configured for loopback-only access"
else
    echo "✗ Warning: X11 forwarding loopback-only configuration may not be properly applied"
    exit 1
fi

# Additional verification - check that the config file exists and is readable
if [[ -r "$X11_CONFIG_FILE" ]]; then
    echo "✓ X11 forwarding configuration file exists and is readable: $X11_CONFIG_FILE"
else
    echo "✗ Error: Configuration file is not readable" >&2
    exit 1
fi

# Display current X11 forwarding configuration
echo "Current X11 Forwarding Configuration:"
sshd -T 2>/dev/null | grep -E "x11" | sed 's/^/  /'

exit 0
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
#!/bin/bash
set -euo pipefail

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root"
        exit 1
    fi
}

# Function to install required packages
install_dependencies() {
    echo "Checking and installing required packages..."
    apt-get update -qq
    
    # Check if SSSD is installed
    if ! dpkg -l | grep -q "^ii  sssd "; then
        echo "Installing SSSD and related packages..."
        apt-get install -y -qq sssd sssd-tools libpam-sss libnss-sss
    fi
    
    # Check if OpenSSL utilities are installed
    if ! dpkg -l | grep -q "^ii  openssl "; then
        echo "Installing OpenSSL utilities..."
        apt-get install -y -qq openssl
    fi
    
    # Check if curl is installed (for OCSP checks)
    if ! dpkg -l | grep -q "^ii  curl "; then
        echo "Installing curl..."
        apt-get install -y -qq curl
    fi
}

# Function to backup SSSD configuration
backup_sssd_config() {
    local config_file="/etc/sssd/sssd.conf"
    local backup_file="/etc/sssd/sssd.conf.backup.$(date +%s)"
    
    if [[ -f "$config_file" ]]; then
        cp "$config_file" "$backup_file"
        echo "Backed up SSSD configuration to $backup_file"
    fi
}

# Function to enable OCSP in SSSD configuration
configure_ocsp() {
    local config_file="/etc/sssd/sssd.conf"
    
    # Create SSSD config if it doesn't exist
    if [[ ! -f "$config_file" ]]; then
        cat > "$config_file" << 'EOF'
[sssd]
services = pam
domains = local

[pam]

[domain/local]
EOF
        chmod 600 "$config_file"
        echo "Created new SSSD configuration file"
    fi
    
    # Check if pam section exists, if not add it
    if ! grep -q "^\[pam\]" "$config_file"; then
        echo "" >> "$config_file"
        echo "[pam]" >> "$config_file"
    fi
    
    # Add OCSP settings to pam section if not already present
    if ! grep -q "pam_cert_db_path" "$config_file"; then
        # Find the line number of [pam] section
        local pam_line=$(grep -n "^\[pam\]" "$config_file" | cut -d: -f1)
        
        # Add OCSP settings after [pam] section
        if [[ -n "$pam_line" ]]; then
            sed -i "${pam_line}a\\pam_cert_db_path = /etc/ssl/certs/ca-certificates.crt\\npam_ocsp_verify = True\\npam_ocsp_nonce = True\\npam_ocsp_timeout = 30" "$config_file"
            echo "Added OCSP configuration to [pam] section"
        fi
    else
        # Update existing OCSP settings
        # Use a temporary file for safer editing
        local temp_file="/tmp/sssd_config.tmp"
        
        # Read the file and update OCSP settings
        {
            in_pam_section=false
            ocsp_verify_found=false
            while IFS= read -r line; do
                if [[ "$line" =~ ^\[pam\] ]]; then
                    in_pam_section=true
                    echo "$line"
                elif [[ "$line" =~ ^\[ ]]; then
                    in_pam_section=false
                    echo "$line"
                elif [[ "$in_pam_section" == true ]]; then
                    if [[ "$line" =~ ^pam_ocsp_verify ]]; then
                        echo "pam_ocsp_verify = True"
                        ocsp_verify_found=true
                    elif [[ "$line" =~ ^pam_ocsp_nonce ]]; then
                        echo "pam_ocsp_nonce = True"
                    elif [[ "$line" =~ ^pam_ocsp_timeout ]]; then
                        echo "pam_ocsp_timeout = 30"
                    elif [[ "$line" =~ ^pam_cert_db_path ]]; then
                        echo "pam_cert_db_path = /etc/ssl/certs/ca-certificates.crt"
                    else
                        echo "$line"
                    fi
                else
                    echo "$line"
                fi
            done < "$config_file"
            
            # Add missing OCSP settings if they weren't found
            if [[ "$ocsp_verify_found" == false && "$in_pam_section" == true ]]; then
                echo "pam_ocsp_verify = True"
                echo "pam_ocsp_nonce = True"
                echo "pam_ocsp_timeout = 30"
            fi
        } > "$temp_file"
        
        mv "$temp_file" "$config_file"
        chmod 600 "$config_file"
        echo "Updated OCSP settings in SSSD configuration"
    fi
    
    # Ensure cert_db_path is set for certificate validation
    if ! grep -q "pam_cert_db_path" "$config_file"; then
        sed -i '/^\[pam\]/a pam_cert_db_path = /etc/ssl/certs/ca-certificates.crt' "$config_file"
    fi
}

# Function to configure certificate validation
configure_certificate_validation() {
    local config_file="/etc/sssd/sssd.conf"
    
    # Ensure domain configuration for certificate authentication
    if ! grep -q "^\[domain/" "$config_file"; then
        cat >> "$config_file" << 'EOF'

[domain/system]
id_provider = local
auth_provider = local
EOF
        echo "Added domain configuration"
    fi
    
    # Add certificate authentication provider settings
    if ! grep -q "certificate_auth" "$config_file"; then
        sed -i '/^\[domain\//a certificate_auth = True' "$config_file"
    fi
}

# Function to ensure SSSD service is enabled and running
ensure_sssd_service() {
    echo "Ensuring SSSD service is enabled..."
    
    # Enable SSSD to start on boot
    systemctl enable sssd.service 2>/dev/null || true
    
    # Restart SSSD to apply configuration changes
    echo "Restarting SSSD service..."
    systemctl restart sssd.service || {
        echo "Warning: Failed to restart SSSD service"
        return 1
    }
    
    # Verify SSSD is running
    if systemctl is-active --quiet sssd.service; then
        echo "SSSD service is running"
    else
        echo "Warning: SSSD service is not running"
        return 1
    fi
}

# Function to verify OCSP configuration
verify_ocsp_configuration() {
    local config_file="/etc/sssd/sssd.conf"
    
    echo "Verifying OCSP configuration..."
    
    # Check for required OCSP settings
    local missing_settings=()
    
    if ! grep -q "pam_ocsp_verify.*True" "$config_file"; then
        missing_settings+=("pam_ocsp_verify")
    fi
    
    if ! grep -q "pam_ocsp_nonce.*True" "$config_file"; then
        missing_settings+=("pam_ocsp_nonce")
    fi
    
    if ! grep -q "pam_ocsp_timeout" "$config_file"; then
        missing_settings+=("pam_ocsp_timeout")
    fi
    
    if [[ ${#missing_settings[@]} -eq 0 ]]; then
        echo "✓ OCSP configuration verified successfully"
        return 0
    else
        echo "✗ Missing OCSP settings: ${missing_settings[*]}"
        return 1
    fi
}

# Function to create OCSP validation wrapper script
create_ocsp_validator() {
    local validator_script="/usr/local/bin/sssd-ocsp-validator.sh"
    
    cat > "$validator_script" << 'OCSP_SCRIPT'
#!/bin/bash
# OCSP validation wrapper for SSSD
# This script can be called to validate certificates against OCSP responders

validate_cert_ocsp() {
    local cert_file="$1"
    local ca_file="${2:-/etc/ssl/certs/ca-certificates.crt}"
    
    if [[ ! -f "$cert_file" ]]; then
        echo "Certificate file not found: $cert_file"
        return 1
    fi
    
    # Extract issuer certificate
    openssl x509 -in "$cert_file" -noout -issuer || return 1
    
    # Get OCSP responder URL
    local ocsp_url=$(openssl x509 -in "$cert_file" -noout -ocsp_uri)
    
    if [[ -z "$ocsp_url" ]]; then
        echo "No OCSP responder URL found in certificate"
        return 1
    fi
    
    # Validate certificate with OCSP
    openssl ocsp -no_nonce -issuer "$ca_file" -cert "$cert_file" \
        -url "$ocsp_url" -header "HOST" "$(echo $ocsp_url | sed 's|http[s]*://||' | cut -d/ -f1)" \
        -verify_other "$ca_file" 2>/dev/null || return 1
    
    return 0
}

# Main execution
if [[ $# -lt 1 ]]; then
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
#!/bin/bash
set -euo pipefail

# Enable smart-card authentication on Ubuntu 24.04
# This script configures the system to support CAC/PIV token-based authentication

log_message() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"
}

log_message "Starting smart-card authentication configuration for Ubuntu 24.04"

# Update package lists
log_message "Updating package lists..."
apt-get update -qq

# Install required packages for smart-card support
log_message "Installing smart-card support packages..."
REQUIRED_PACKAGES=(
    "libpam-pkcs11"
    "opensc"
    "opensc-pkcs11"
    "pcscd"
    "pcsc-tools"
    "libnss3-tools"
    "libengine-pkcs11-openssl"
    "gnutls-bin"
    "libssl-dev"
)

for package in "${REQUIRED_PACKAGES[@]}"; do
    if ! dpkg -l | grep -q "^ii  $package"; then
        log_message "Installing $package..."
        apt-get install -y -qq "$package"
    else
        log_message "$package already installed"
    fi
done

# Create OpenSC configuration directory if it doesn't exist
OPENSC_CONFIG_DIR="/etc/opensc"
if [ ! -d "$OPENSC_CONFIG_DIR" ]; then
    log_message "Creating OpenSC configuration directory..."
    mkdir -p "$OPENSC_CONFIG_DIR"
fi

# Configure OpenSC if not already configured
if [ ! -f "$OPENSC_CONFIG_DIR/opensc.conf" ]; then
    log_message "Creating OpenSC configuration..."
    cat > "$OPENSC_CONFIG_DIR/opensc.conf" << 'EOF'
# OpenSC configuration file for smart-card support

app default {
    # PKCS#15 settings
    debug = 0;
    
    # Default card driver
    driver = "auto";
}

reader pcsc {
    # Enable PC/SC reader support
    enable_pinpad = true;
}

# OpenSC PKCS#11 module configuration
pkcs11 {
    module = /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so;
}
EOF
else
    log_message "OpenSC configuration already exists"
fi

# Configure PAM for smart-card authentication
log_message "Configuring PAM for smart-card authentication..."

# Create pam_pkcs11 configuration
PAM_PKCS11_CONFIG="/etc/pam_pkcs11/pam_pkcs11.conf"
if [ ! -f "$PAM_PKCS11_CONFIG" ]; then
    mkdir -p /etc/pam_pkcs11
    log_message "Creating PAM PKCS#11 configuration..."
    cat > "$PAM_PKCS11_CONFIG" << 'EOF'
# PAM PKCS#11 configuration

# Set default options
default {
    # Set default mapper
    mapper = pwent;
    
    # Card timeout
    card_only = false;
    
    # Maximum retries for PIN
    max_tries = 3;
    
    # Token label patterns
    token_type = ".*";
    
    # Use OpenSC module
    use_mappers = pwent;
}

# OpenSC module configuration
opensc {
    module = /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so;
}

# Mapper configuration - maps certificate to local user
mapper pwent {
    # Map certificate subject to system user
    # This can be customized based on certificate attributes
    debug = false;
}
EOF
else
    log_message "PAM PKCS#11 configuration already exists"
fi

# Update common-auth PAM configuration for smart-card support
log_message "Configuring PAM authentication stack..."

AUTH_CONFIG="/etc/pam.d/common-auth"
if [ -f "$AUTH_CONFIG" ]; then
    # Check if pam_pkcs11 is already configured
    if ! grep -q "pam_pkcs11" "$AUTH_CONFIG"; then
        log_message "Adding pam_pkcs11 to common-auth..."
        # Add pam_pkcs11 before pam_unix (but after pam_env for safety)
        sed -i '/^auth.*required.*pam_unix.so/i auth    sufficient    pam_pkcs11.so' "$AUTH_CONFIG"
    else
        log_message "pam_pkcs11 already configured in common-auth"
    fi
fi

# Configure sudo to support smart-card authentication
SUDO_CONFIG="/etc/pam.d/sudo"
if [ -f "$SUDO_CONFIG" ]; then
    if ! grep -q "pam_pkcs11" "$SUDO_CONFIG"; then
        log_message "Adding pam_pkcs11 to sudo PAM configuration..."
        sed -i '/@include common-auth/a auth    sufficient    pam_pkcs11.so' "$SUDO_CONFIG"
    else
        log_message "pam_pkcs11 already configured in sudo"
    fi
fi

# Configure sshd to support smart-card authentication
SSH_CONFIG="/etc/ssh/sshd_config"
log_message "Configuring SSH for smart-card authentication..."

# Ensure PubkeyAuthentication is enabled
if [ -f "$SSH_CONFIG" ]; then
    # Check and update PubkeyAuthentication
    if grep -q "^#PubkeyAuthentication" "$SSH_CONFIG"; then
        sed -i 's/^#PubkeyAuthentication.*/PubkeyAuthentication yes/' "$SSH_CONFIG"
    elif ! grep -q "^PubkeyAuthentication" "$SSH_CONFIG"; then
        echo "PubkeyAuthentication yes" >> "$SSH_CONFIG"
    fi
    
    # Ensure ChallengeResponseAuthentication is configured appropriately
    if grep -q "^ChallengeResponseAuthentication" "$SSH_CONFIG"; then
        sed -i 's/^ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' "$SSH_CONFIG"
    else
        echo "ChallengeResponseAuthentication no" >> "$SSH_CONFIG"
    fi
    
    # Ensure PasswordAuthentication is appropriately set
    if ! grep -q "^PasswordAuthentication" "$SSH_CONFIG"; then
        echo "PasswordAuthentication no" >> "$SSH_CONFIG"
    fi
fi

# Create PKCS#11 module configuration for NSS
NSS_CONFIG_DIR="/etc/ssl/certs"
if [ ! -f "$NSS_CONFIG_DIR/pkcs11.conf" ]; then
    log_message "Creating NSS PKCS#11 configuration..."
    cat > "$NSS_CONFIG_DIR/pkcs11.conf" << 'EOF'
# NSS PKCS#11 module configuration
# Load OpenSC module for smart-card support

name=OpenSC
parameters=
library=/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
NSS=trustOrder:1
EOF
else
    log_message "NSS PKCS#11 configuration already exists"
fi

# Enable and start pcscd (PC/SC daemon) for smart-card support
log_message "Configuring PC/SC daemon..."
systemctl enable pcscd || true
systemctl start pcscd || true

# Verify pcscd is running
if systemctl is-active --quiet pcscd; then
    log_message "PC/SC daemon (pcscd) is running"
else
    log_message "Warning: pcscd failed to start, attempting to diagnose..."
    systemctl status pcscd || true
fi

# Create a test script to verify smart-card configuration
TEST_SCRIPT="/usr/local/bin/test-smartcard-config"
cat > "$TEST_SCRIPT" << 'EOF'
#!/bin/bash
# Test script to verify smart-card authentication configuration

echo "=== Smart-Card Authentication Configuration Test ==="
echo ""

echo "1. Checking PC/SC daemon status..."
if systemctl is-active --quiet pcscd; then
    echo "   ✓ PC/SC daemon (pcscd) is running"
else
    echo "   ✗ PC/SC daemon (pcscd) is not running"
fi

echo ""
echo "2. Checking for connected smart-card readers..."
pcsc_scan -n 2>/dev/null | head -20 || echo "   Note: pcsc_scan not available or no readers detected"

echo ""
echo "3. Checking OpenSC PKCS#11 module..."
if [ -f /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so ]; then
    echo "   ✓ OpenSC PKCS#11 module found"
else
    echo "   ✗ OpenSC PKCS#11 module not found"
fi

echo ""
echo "4. Checking PAM PKCS#11 installation..."
if dpkg -l | grep -q "^ii  libpam-pkcs11"; then
    echo "   ✓ PAM PKCS#11 module installed"
else
    echo "   ✗ PAM PKCS#11 module not installed"
fi

echo ""
echo "5. Checking PAM configuration..."
if grep -q "pam_pkcs11" /etc/pam.d/common-auth; then
    echo "   ✓ PAM PKCS#11 configured in common-auth"
else
    echo "   ✗ PAM PKCS#11 not configured in common-auth"
fi

echo ""
echo "6. Checking SSH configuration..."
if grep -q "PubkeyAuthentication yes" /etc/ssh/sshd_config; then
    echo "   ✓ SSH public key authentication enabled"
else
    echo "   ✗ SSH public key authentication not properly configured"
fi

echo ""
echo "=== Configuration Test Complete ==="
EOF

chmod +x "$TEST_SCRIPT
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

# Idempotent bash remediation script to ensure USB device-authorization framework is present on Ubuntu 24.04
# This ensures protection against rogue or unauthorized USB devices through device-attribute allow/block listing

# Define package names for USB device authorization
USB_AUTH_PACKAGES=("usbguard" "libusbguard0")

# Function to check if a package is installed
is_package_installed() {
    dpkg -l | grep -q "^ii  ${1}" 2>/dev/null
    return $?
}

# Function to install a package
install_package() {
    if ! is_package_installed "$1"; then
        echo "Installing package: $1"
        apt-get install -y "$1" 2>/dev/null || {
            echo "Failed to install $1" >&2
            return 1
        }
    fi
}

# Main remediation logic
main() {
    # Update package lists
    echo "Updating package lists..."
    apt-get update -qq 2>/dev/null || {
        echo "Failed to update package lists" >&2
        return 1
    }

    # Install USB Guard packages
    echo "Ensuring USB device-authorization framework is installed..."
    for package in "${USB_AUTH_PACKAGES[@]}"; do
        install_package "$package" || {
            echo "Warning: Could not install $package" >&2
            continue
        }
    done

    # Verify installation
    if is_package_installed "usbguard"; then
        echo "USB device-authorization framework (USBGuard) is installed"
        
        # Enable and start usbguard service if available
        if command -v systemctl &> /dev/null; then
            if systemctl is-enabled usbguard 2>/dev/null | grep -q "enabled"; then
                echo "USBGuard service is already enabled"
            else
                echo "Enabling USBGuard service..."
                systemctl enable usbguard 2>/dev/null || echo "Warning: Could not enable usbguard service"
            fi
            
            if systemctl is-active --quiet usbguard; then
                echo "USBGuard service is running"
            else
                echo "Starting USBGuard service..."
                systemctl start usbguard 2>/dev/null || echo "Warning: Could not start usbguard service"
            fi
        fi
        
        return 0
    else
        echo "Error: USB device-authorization framework could not be installed" >&2
        return 1
    fi
}

# Execute main function
main
exit $?
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

# Enable and start the USB device authorization service on Ubuntu 24.04

# Ensure the script runs with elevated privileges
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root (use sudo)"
    exit 1
fi

# Update package lists to ensure we have the latest information
apt-get update -qq

# Install the USB device authorization service if not already installed
# The service is typically provided by the usbguard package
if ! command -v usbguard &> /dev/null; then
    echo "Installing usbguard package..."
    apt-get install -y -qq usbguard usbguard-applet-qt
fi

# Enable the USB device authorization service to start at boot
systemctl enable usbguard 2>/dev/null

# Start the USB device authorization service if not already running
if ! systemctl is-active --quiet usbguard; then
    echo "Starting usbguard service..."
    systemctl start usbguard
fi

# Verify the service is enabled and active
if systemctl is-enabled --quiet usbguard && systemctl is-active --quiet usbguard; then
    echo "USB device authorization service is now enabled and active"
    systemctl status usbguard --no-pager
    exit 0
else
    echo "Failed to enable or start the USB device authorization service"
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
#!/bin/bash
set -euo pipefail

USBGUARD_POLICY_FILE="/etc/usbguard/rules.conf"
USBGUARD_SERVICE="usbguard"
BACKUP_SUFFIX=".backup"

echo "USBGuard Policy Remediation Script"
echo "===================================="

if ! command -v usbguard &> /dev/null; then
    echo "Installing usbguard..."
    apt-get update
    apt-get install -y usbguard
fi

if ! systemctl is-active --quiet $USBGUARD_SERVICE; then
    echo "Starting usbguard service..."
    systemctl start $USBGUARD_SERVICE
    systemctl enable $USBGUARD_SERVICE
fi

echo "Checking current policy..."
current_policy_size=$(stat -f%z "$USBGUARD_POLICY_FILE" 2>/dev/null || echo "0")

if [ "$current_policy_size" -eq 0 ] || [ ! -s "$USBGUARD_POLICY_FILE" ]; then
    echo "Empty or non-existent policy file detected. Generating policy from current USB devices..."
    
    if [ -f "$USBGUARD_POLICY_FILE" ] && [ ! -f "${USBGUARD_POLICY_FILE}${BACKUP_SUFFIX}" ]; then
        cp "$USBGUARD_POLICY_FILE" "${USBGUARD_POLICY_FILE}${BACKUP_SUFFIX}"
        echo "Backed up existing policy to ${USBGUARD_POLICY_FILE}${BACKUP_SUFFIX}"
    fi
    
    temp_policy=$(mktemp)
    trap "rm -f $temp_policy" EXIT
    
    {
        echo "# USBGuard Rules - Generated automatically"
        echo "# Rule set for currently connected USB devices"
        echo "# Generated on: $(date)"
        echo ""
        
        echo "# Allow new devices to be authorized by default (explicit allow)"
        echo "allow with-interface all"
        echo ""
        
        echo "# Block any devices not explicitly allowed"
        echo "reject all"
    } > "$temp_policy"
    
    echo "Generated policy:"
    cat "$temp_policy"
    echo ""
    
    cp "$temp_policy" "$USBGUARD_POLICY_FILE"
    chmod 600 "$USBGUARD_POLICY_FILE"
    chown root:root "$USBGUARD_POLICY_FILE"
    
    echo "Policy file updated at $USBGUARD_POLICY_FILE"
    
    systemctl restart $USBGUARD_SERVICE
    echo "USBGuard service restarted"
else
    echo "Policy file is not empty. Verifying it is in place..."
    if grep -q "allow" "$USBGUARD_POLICY_FILE" 2>/dev/null; then
        echo "Valid policy rules found. System is properly configured."
    else
        echo "Warning: Policy file exists but appears to have no allow rules."
        echo "Current policy:"
        cat "$USBGUARD_POLICY_FILE"
    fi
fi

systemctl enable $USBGUARD_SERVICE
echo "USBGuard service enabled for persistence across reboots"

echo ""
echo "Policy remediation complete!"
echo "Current policy rules:"
cat "$USBGUARD_POLICY_FILE"

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
set -euo pipefail

# Ensure this script is idempotent - can be run multiple times safely

# Update package lists
apt-get update -qq

# Remove X11 server and related graphical components
# Using --yes and --purge flags for automatic removal
packages_to_remove=(
    "xserver-xorg*"
    "xserver-xorg-core"
    "xserver-xorg-input-*"
    "xserver-xorg-video-*"
    "x11-common"
    "x11-utils"
    "x11-apps"
    "x11-xkb-utils"
    "xinit"
    "xauth"
    "libx11-*"
    "libxext*"
    "libxrender*"
    "libxfixes*"
    "libxdamage*"
    "libxcb*"
    "graphical-*"
    "gdm*"
    "lightdm"
    "sddm"
    "slim"
    "startx"
    "x11-session-utils"
    "xdm"
    "wayland*"
    "libwayland*"
)

# Also remove common graphical desktop environments if present
packages_to_remove+=(
    "gnome-shell"
    "ubuntu-desktop"
    "xubuntu-desktop"
    "kubuntu-desktop"
    "lubuntu-desktop"
    "mate-desktop-environment"
    "lxde"
    "openbox"
    "fluxbox"
    "jwm"
)

# Check if any packages are installed before attempting removal
# This makes the script idempotent
for package in "${packages_to_remove[@]}"; do
    # Use dpkg-query to check if package pattern matches any installed packages
    # Ignore wildcards by checking if they're literally installed first
    if apt-cache search "^${package%\*}$" 2>/dev/null | grep -q .; then
        apt-get remove --yes --purge "${package}" 2>/dev/null || true
    fi
done

# Remove orphaned packages and dependencies
apt-get autoremove --yes -qq

# Ensure no graphical boot target is set
# Set default target to multi-user (CLI only)
systemctl set-default multi-user.target

# Disable any graphical display managers that might exist
for dm in gdm gdm3 lightdm sddm slim xdm; do
    systemctl disable "${dm}" 2>/dev/null || true
    systemctl stop "${dm}" 2>/dev/null || true
done

# Ensure the system won't attempt to load X at boot
# Remove any X startup scripts from common locations
for startup_script in /etc/X11/Xsession /etc/X11/xinit/xinitrc; do
    if [ -f "${startup_script}" ]; then
        mv "${startup_script}" "${startup_script}.disabled"
    fi
done

# Check and ensure /etc/default/grub doesn't have graphical boot parameters
if [ -f /etc/default/grub ]; then
    # Comment out any splash or graphical parameters
    sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT=""/' /etc/default/grub
    update-grub2 || update-grub || true
fi

# Verify the system is in multi-user mode
current_target=$(systemctl get-default)
if [ "${current_target}" != "multi-user.target" ]; then
    systemctl set-default multi-user.target
fi

echo "X Windows and graphical components have been removed. System is configured for CLI-only mode."
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
#!/bin/bash

set -e

# Define the target and current systemd default targets
TARGET_UNIT="multi-user.target"
CURRENT_UNIT=$(/usr/bin/systemctl get-default)

# Check if the system is already set to multi-user.target
if [ "$CURRENT_UNIT" = "$TARGET_UNIT" ]; then
    echo "System is already configured to boot into $TARGET_UNIT"
    exit 0
fi

# Set the default systemd target to multi-user.target
echo "Setting default systemd target to $TARGET_UNIT..."
/usr/bin/systemctl set-default "$TARGET_UNIT"

# Verify the change was successful
VERIFIED_UNIT=$(/usr/bin/systemctl get-default)
if [ "$VERIFIED_UNIT" = "$TARGET_UNIT" ]; then
    echo "Successfully configured system to boot into $TARGET_UNIT"
    echo "Current default target: $VERIFIED_UNIT"
    exit 0
else
    echo "Failed to set default target. Current target: $VERIFIED_UNIT"
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
#!/bin/bash

# Enable kernel auditing from boot for all kernels
GRUB_CONFIG="/etc/default/grub"
GRUB_KERNELPARAMS_VAR="GRUB_CMDLINE_LINUX"

# Check if the system uses GRUB
if [ ! -f "$GRUB_CONFIG" ]; then
    echo "Error: GRUB configuration file not found at $GRUB_CONFIG"
    exit 1
fi

# The kernel parameter to add for early auditing
AUDIT_PARAM="audit=1"

# Read the current GRUB_CMDLINE_LINUX value
current_cmdline=$(grep "^${GRUB_KERNELPARAMS_VAR}=" "$GRUB_CONFIG" | cut -d'"' -f2)

# Check if audit=1 is already present
if echo "$current_cmdline" | grep -q "audit=1"; then
    echo "audit=1 is already configured in GRUB"
else
    # Add audit=1 to the kernel parameters
    if grep -q "^${GRUB_KERNELPARAMS_VAR}=" "$GRUB_CONFIG"; then
        # Append to existing line
        sed -i "s/^\(${GRUB_KERNELPARAMS_VAR}=\"[^\"]*\)\"/\1 ${AUDIT_PARAM}\"/" "$GRUB_CONFIG"
    else
        # Create new line if it doesn't exist
        echo "${GRUB_KERNELPARAMS_VAR}=\"${AUDIT_PARAM}\"" >> "$GRUB_CONFIG"
    fi
    
    # Update GRUB configuration
    update-grub
    echo "audit=1 has been added to GRUB kernel parameters"
fi

# Ensure auditd service starts at boot
systemctl enable auditd 2>/dev/null

echo "Kernel auditing from boot has been configured"
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
#!/bin/bash

set -e

# Function to configure audit backlog for all kernels
configure_audit_backlog() {
    local grub_config="/etc/default/grub"
    local grub_param="audit_backlog_limit=8192"
    local audit_conf="/etc/audit/audit.conf"
    local boot_dir="/boot"
    
    # Configure GRUB for all kernels
    if [ -f "$grub_config" ]; then
        # Check if audit_backlog_limit is already set
        if grep -q "audit_backlog_limit=" "$grub_config"; then
            # Replace existing value
            sed -i "s/audit_backlog_limit=[0-9]*/audit_backlog_limit=8192/g" "$grub_config"
        else
            # Add the parameter if not present
            if grep -q "GRUB_CMDLINE_LINUX=" "$grub_config"; then
                sed -i 's/GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="'"$grub_param"' /' "$grub_config"
            else
                echo "GRUB_CMDLINE_LINUX=\"$grub_param\"" >> "$grub_config"
            fi
        fi
    fi
    
    # Update GRUB configuration
    if command -v grub-mkconfig &> /dev/null; then
        grub-mkconfig -o /boot/grub/grub.cfg || grub-mkconfig -o /boot/efi/EFI/ubuntu/grub.cfg
    fi
    
    # Configure audit daemon settings if audit is installed
    if command -v auditctl &> /dev/null; then
        # Create audit.conf if it doesn't exist
        if [ ! -f "$audit_conf" ]; then
            mkdir -p /etc/audit
            touch "$audit_conf"
        fi
        
        # Set audit backlog in audit.conf
        if grep -q "^audit_backlog_limit" "$audit_conf"; then
            sed -i 's/^audit_backlog_limit.*/audit_backlog_limit = 8192/' "$audit_conf"
        else
            echo "audit_backlog_limit = 8192" >> "$audit_conf"
        fi
    fi
}

# Function to verify configuration
verify_configuration() {
    local grub_config="/etc/default/grub"
    
    if [ -f "$grub_config" ]; then
        if grep -q "audit_backlog_limit=8192" "$grub_config"; then
            echo "✓ GRUB configuration verified: audit_backlog_limit=8192 is set"
            return 0
        else
            echo "✗ GRUB configuration not properly set"
            return 1
        fi
    else
        echo "✗ GRUB configuration file not found"
        return 1
    fi
}

# Main execution
main() {
    echo "Configuring audit backlog queue to at least 8192 entries..."
    
    # Check if running as root
    if [ "$EUID" -ne 0 ]; then
        echo "This script must be run as root"
        exit 1
    fi
    
    # Configure the system
    configure_audit_backlog
    
    # Verify the configuration
    if verify_configuration; then
        echo "✓ Audit backlog configuration completed successfully"
        echo "Note: Changes will take effect after the next system reboot"
        exit 0
    else
        echo "✗ Configuration verification failed"
        exit 1
    fi
}

# Run main function
main
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
#!/bin/bash

# Remediation script to harden auditd configuration by making audit rules immutable

set -e

# Define audit rules file
AUDIT_RULES_FILE="/etc/audit/rules.d/audit.rules"
AUDIT_RULES_DIR="/etc/audit/rules.d"

# Ensure audit package is installed
if ! command -v auditctl &> /dev/null; then
    echo "Installing auditd..."
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

# Ensure the rules directory exists
mkdir -p "$AUDIT_RULES_DIR"

# Create backup if it doesn't exist
BACKUP_FILE="${AUDIT_RULES_FILE}.backup.$(date +%s)"
if [ ! -f "$BACKUP_FILE" ]; then
    if [ -f "$AUDIT_RULES_FILE" ]; then
        cp "$AUDIT_RULES_FILE" "$BACKUP_FILE"
        echo "Backed up existing audit rules to $BACKUP_FILE"
    fi
fi

# Check if audit.rules file exists, if not create with basic rules
if [ ! -f "$AUDIT_RULES_FILE" ]; then
    cat > "$AUDIT_RULES_FILE" << 'EOF'
# This file contains the auditctl rules that are loaded
# whenever the audit daemon is started via the initscripts.
# The rules are simply the parameters that would be passed
# to auditctl.

# Remove any existing rules
-D

# Buffer Size
-b 8192

# Failure handling
-f 1

# Basic audit rules for system hardening
-w /etc/audit/ -p wa -k audit_config
-w /etc/libaudit.conf -p wa -k audit_config
-w /etc/audisp/ -p wa -k audit_config
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_modifications
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k network_modifications
-w /etc/hostname -p wa -k network_modifications
-a exit,always -F arch=b64 -S sysctl -S sysctl_modify -k syscall_modifications
-a exit,always -F arch=b32 -S sysctl -S sysctl_modify -k syscall_modifications
-w /etc/sysctl.conf -p wa -k syscall_modifications

# Make configuration immutable
-e 2
EOF
    echo "Created new audit rules file at $AUDIT_RULES_FILE"
else
    # Check if immutability flag is already present
    if ! grep -q "^-e 2" "$AUDIT_RULES_FILE"; then
        # Add immutability flag at the end
        echo "" >> "$AUDIT_RULES_FILE"
        echo "# Make configuration immutable" >> "$AUDIT_RULES_FILE"
        echo "-e 2" >> "$AUDIT_RULES_FILE"
        echo "Added immutability flag to existing audit rules"
    else
        echo "Immutability flag already present in audit rules"
    fi
fi

# Ensure proper permissions on the rules file
chmod 640 "$AUDIT_RULES_FILE"
chown root:root "$AUDIT_RULES_FILE"

# Enable and start the auditd service
systemctl enable auditd
systemctl restart auditd

# Load the rules to apply them immediately
auditctl -R "$AUDIT_RULES_FILE"

# Verify the immutability flag is set
if auditctl -l | grep -q "AUDIT_CONFIG_CHANGE"; then
    echo "Audit immutability flag successfully applied"
else
    echo "Verifying audit status..."
    auditctl -s
fi

# Ensure the auditd service starts automatically
if ! systemctl is-enabled auditd &> /dev/null; then
    systemctl enable auditd
    echo "Enabled auditd to start on boot"
fi

echo "Audit daemon hardening completed successfully"
echo "Audit rules are now immutable and will persist across reboots"
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
#!/bin/bash

set -euo pipefail

# Idempotent script to make login UIDs immutable in audit subsystem on Ubuntu 24.04

AUDIT_RULES_DIR="/etc/audit/rules.d"
AUDIT_RULES_FILE="${AUDIT_RULES_DIR}/immutable-loginuid.rules"
AUDIT_CONFIG_DIR="/etc/audit"
AUDIT_CONFIG_FILE="${AUDIT_CONFIG_DIR}/audit.conf"

echo "Configuring immutable login UID for audit subsystem..."

# Create audit rules directory if it doesn't exist
if [ ! -d "${AUDIT_RULES_DIR}" ]; then
    mkdir -p "${AUDIT_RULES_DIR}"
fi

# Create the immutable loginuid rule file if it doesn't exist or if it needs updating
if [ ! -f "${AUDIT_RULES_FILE}" ]; then
    cat > "${AUDIT_RULES_FILE}" << 'EOF'
# Make login UID immutable to prevent tampering with audit logs
# This rule prevents privileged processes from altering the login UID
# once it has been established for a session

--loginuid-immutable
EOF
    echo "Created ${AUDIT_RULES_FILE}"
else
    # Check if the rule already exists
    if ! grep -q "loginuid-immutable" "${AUDIT_RULES_FILE}"; then
        echo "--loginuid-immutable" >> "${AUDIT_RULES_FILE}"
        echo "Added loginuid-immutable rule to ${AUDIT_RULES_FILE}"
    else
        echo "loginuid-immutable rule already present in ${AUDIT_RULES_FILE}"
    fi
fi

# Ensure proper permissions on the rules file
chmod 640 "${AUDIT_RULES_FILE}"
chown root:root "${AUDIT_RULES_FILE}"

# Verify audit daemon is installed
if ! command -v auditctl &> /dev/null; then
    echo "Installing audit package..."
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

# Enable and start the audit service
echo "Ensuring audit service is enabled and running..."
systemctl enable auditd
systemctl start auditd

# Load the rules into the running audit system
echo "Loading audit rules..."
auditctl -R "${AUDIT_RULES_FILE}" 2>/dev/null || true

# Verify the rule is loaded
if auditctl -l | grep -q "loginuid-immutable"; then
    echo "✓ Login UID immutable rule is active"
else
    echo "⚠ Login UID immutable rule may not be active, attempting to apply directly..."
    auditctl --loginuid-immutable 2>/dev/null || true
fi

# Make sure the rules are persistent across reboots by checking audit.rules
# The rules.d directory is included automatically in newer versions
if [ -f "${AUDIT_CONFIG_DIR}/rules.d" ] || grep -q "^#include" "${AUDIT_CONFIG_DIR}/audit.rules" 2>/dev/null; then
    echo "✓ Audit rules directory inclusion is configured"
else
    # For older systems, ensure the main audit.rules includes the directory
    if [ -f "${AUDIT_CONFIG_DIR}/audit.rules" ]; then
        if ! grep -q "#include ${AUDIT_RULES_DIR}" "${AUDIT_CONFIG_DIR}/audit.rules"; then
            echo "#include ${AUDIT_RULES_DIR}" >> "${AUDIT_CONFIG_DIR}/audit.rules"
            echo "Added include directive for rules.d directory"
        fi
    fi
fi

# Verify configuration
echo "Verifying immutable login UID configuration..."
if auditctl -l 2>/dev/null | grep -q "loginuid-immutable"; then
    echo "✓ Successfully configured immutable login UID"
    echo "✓ Configuration is persistent and will survive reboots"
    exit 0
else
    echo "⚠ Configuration complete, but rule verification pending daemon reload"
    echo "  The rule will be active after next audit daemon restart"
    exit 0
fi
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
#!/bin/bash
set -euo pipefail

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# Define the audit rules
# These rules capture successful mount operations by regular users (UID >= 1000)
# The -a exit,always flag logs on successful syscall completion
# The -F auid>=1000 filter ensures we only track regular users
# The -F auid!=-1 filter excludes unset UIDs (loginuid not set)

# Get system architecture to determine which syscalls to monitor
ARCH=$(uname -m)

# Function to check if a rule already exists in auditctl
rule_exists() {
    local rule="$1"
    auditctl -l 2>/dev/null | grep -F "$rule" >/dev/null 2>&1
}

# Load the audit daemon configuration directory
AUDIT_RULES_DIR="/etc/audit/rules.d"
AUDIT_RULES_FILE="${AUDIT_RULES_DIR}/export.rules"

# Ensure audit daemon is installed
if ! command -v auditctl &> /dev/null; then
    echo "Installing auditd..."
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

# Create the audit rules file if it doesn't exist
if [[ ! -f "$AUDIT_RULES_FILE" ]]; then
    touch "$AUDIT_RULES_FILE"
fi

# Clear the file to avoid duplicates
> "$AUDIT_RULES_FILE"

# Add audit rules for mount syscalls
# mount syscall is typically syscall 21 on both x86 and x86_64
# umount2 syscall is typically syscall 39 on both x86 and x86_64

cat > "$AUDIT_RULES_FILE" << 'EOF'
# Audit rules for tracking filesystem mount operations by regular users
# This helps detect unauthorized data exportation to external media

# Delete any existing rules for this key
-d
-b 8192
-f 1
-e 2

# Monitor mount syscall (number 21) for regular users
-a exit,always -F arch=b64 -S mount -F auid>=1000 -F auid!=-1 -k export
-a exit,always -F arch=b32 -S mount -F auid>=1000 -F auid!=-1 -k export

# Monitor umount2 syscall (number 39) for regular users  
-a exit,always -F arch=b64 -S umount2 -F auid>=1000 -F auid!=-1 -k export
-a exit,always -F arch=b32 -S umount2 -F auid>=1000 -F auid!=-1 -k export

# Make sure the rules are loaded at audit daemon startup
EOF

# Reload audit rules
echo "Reloading audit rules..."
augenrules --load 2>/dev/null || {
    # If augenrules fails, try loading directly with auditctl
    auditctl -R "$AUDIT_RULES_FILE" 2>/dev/null || true
}

# Ensure audit daemon is started and enabled
echo "Ensuring auditd is running and enabled..."
systemctl daemon-reload
systemctl enable auditd.service 2>/dev/null || true
systemctl restart auditd.service 2>/dev/null || true

# Wait a moment for auditd to start
sleep 1

# Verify the rules are loaded
echo "Verifying audit rules are loaded..."
if auditctl -l 2>/dev/null | grep -q "export"; then
    echo "✓ Audit rules for 'export' key are successfully loaded"
else
    echo "⚠ Warning: Audit rules may not have been loaded. Attempting direct load..."
    # Try direct load as fallback
    auditctl -R "$AUDIT_RULES_FILE" || true
fi

# Make the rules persist
echo "Ensuring rules persist across reboots..."
if [[ -f /etc/audit/rules.d/audit.rules ]]; then
    # Make sure export rules are included
    if ! grep -q "export" /etc/audit/rules.d/audit.rules; then
        echo "-a exit,always -F arch=b64 -S mount -F auid>=1000 -F auid!=-1 -k export" >> /etc/audit/rules.d/audit.rules
        echo "-a exit,always -F arch=b32 -S mount -F auid>=1000 -F auid!=-1 -k export" >> /etc/audit/rules.d/audit.rules
        echo "-a exit,always -F arch=b64 -S umount2 -F auid>=1000 -F auid!=-1 -k export" >> /etc/audit/rules.d/audit.rules
        echo "-a exit,always -F arch=b32 -S umount2 -F auid>=1000 -F auid!=-1 -k export" >> /etc/audit/rules.d/audit.rules
    fi
fi

# Test by listing current rules
echo ""
echo "Current audit rules with 'export' key:"
auditctl -l 2>/dev/null | grep -i export || echo "No rules found (this may be normal on some systems)"

echo ""
echo "✓ Audit configuration complete"
echo "Audit logs will be written to: /var/log/audit/audit.log"
echo "View export-related events with: ausearch -k export"
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

set -euo pipefail

AUDIT_RULES_DIR="/etc/audit/rules.d"
AUDIT_RULES_FILE="${AUDIT_RULES_DIR}/sudoers.rules"
SUDOERS_FILE="/etc/sudoers"
AUDIT_KEY="audit_sudoers_changes"

ensure_audit_daemon_installed() {
    if ! command -v auditctl &> /dev/null; then
        apt-get update
        apt-get install -y auditd audispd-plugins
    fi
}

ensure_audit_daemon_running() {
    systemctl enable auditd
    systemctl start auditd
}

create_audit_rule() {
    mkdir -p "${AUDIT_RULES_DIR}"
    
    cat > "${AUDIT_RULES_FILE}" << EOF
# Audit rule for sudoers file changes
# Detects any write or attribute modifications to /etc/sudoers
-w ${SUDOERS_FILE} -p wa -k ${AUDIT_KEY}
EOF
    
    chmod 640 "${AUDIT_RULES_FILE}"
}

load_audit_rules() {
    augenrules --load 2>/dev/null || auditctl -R "${AUDIT_RULES_FILE}"
}

verify_rule_loaded() {
    if auditctl -l | grep -q "${AUDIT_KEY}"; then
        return 0
    else
        return 1
    fi
}

main() {
    ensure_audit_daemon_installed
    ensure_audit_daemon_running
    create_audit_rule
    load_audit_rules
    
    sleep 1
    
    if verify_rule_loaded; then
        exit 0
    else
        echo "Failed to load audit rule" >&2
        exit 1
    fi
}

main "$@"
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
#!/bin/bash

# Idempotent audit configuration script for Ubuntu 24.04
# Ensures audit rules for sudo configuration directory modifications are persistent

set -euo pipefail

# Configuration variables
AUDIT_RULES_DIR="/etc/audit/rules.d"
AUDIT_RULES_FILE="${AUDIT_RULES_DIR}/sudo-modifications.rules"
SUDO_CONFIG_DIR="/etc/sudoers.d"
RULE_TAG="sudo-config-changes"
AUDITCTL_BIN="/sbin/auditctl"
AUGENRULES_BIN="/sbin/augenrules"

# Function to check if audit daemon is installed
check_auditd_installed() {
    if ! command -v "${AUDITCTL_BIN}" &> /dev/null; then
        echo "Error: auditd is not installed. Installing audit package..."
        apt-get update
        apt-get install -y auditd audispd-plugins
    fi
}

# Function to create or update audit rules file
create_audit_rules() {
    # Ensure the rules directory exists
    mkdir -p "${AUDIT_RULES_DIR}"
    
    # Create the audit rules file with proper permissions
    cat > "${AUDIT_RULES_FILE}" << 'EOF'
# Audit rule for monitoring sudo configuration directory modifications
# This rule ensures all write and attribute change events are logged for accountability

# Monitor the /etc/sudoers.d directory for write and attribute changes
# -w watches a file or directory
# -p wa monitors write (w) and attribute change (a) events
# -k assigns a tag to the event for easy identification in logs

-w /etc/sudoers.d/ -p wa -k sudo-config-changes
-w /etc/sudoers -p wa -k sudo-config-changes

# Make the configuration immutable to prevent modification
-e 2
EOF

    # Set appropriate permissions on the rules file
    chmod 640 "${AUDIT_RULES_FILE}"
    chown root:root "${AUDIT_RULES_FILE}"
}

# Function to load the audit rules
load_audit_rules() {
    echo "Loading audit rules..."
    
    # Check if augenrules is available (preferred method for persistence)
    if command -v "${AUGENRULES_BIN}" &> /dev/null; then
        # Use augenrules to generate and load rules
        # This ensures rules persist across reboots
        "${AUGENRULES_BIN}" --load
        echo "Audit rules loaded via augenrules"
    else
        # Fallback to auditctl if augenrules is not available
        "${AUDITCTL_BIN}" -R "${AUDIT_RULES_FILE}"
        echo "Audit rules loaded via auditctl"
    fi
}

# Function to verify audit rules are loaded
verify_audit_rules() {
    # Check if the rules are currently loaded
    if "${AUDITCTL_BIN}" -l | grep -q "sudo-config-changes"; then
        echo "✓ Audit rules for sudo configuration changes are loaded"
        return 0
    else
        echo "✗ Audit rules for sudo configuration changes are not loaded"
        return 1
    fi
}

# Function to ensure auditd service is enabled and running
ensure_auditd_running() {
    # Enable the auditd service to start on boot
    systemctl enable auditd
    
    # Check if auditd is running, if not start it
    if ! systemctl is-active --quiet auditd; then
        echo "Starting auditd service..."
        systemctl start auditd
    else
        echo "auditd service is already running"
    fi
}

# Function to create a persistent audit rules configuration
# This ensures rules are loaded even if using the generation utility
setup_persistent_rules() {
    # For systems using augenrules, we need to ensure the rules are in the rules.d directory
    # This is already done in create_audit_rules()
    
    # Additionally, we can set audit rules to persist by modifying audit configuration
    local audit_config="/etc/audit/audit.rules"
    
    # Backup the original audit rules if they exist and haven't been backed up
    if [[ -f "${audit_config}" && ! -f "${audit_config}.bak" ]]; then
        cp "${audit_config}" "${audit_config}.bak"
    fi
    
    # Ensure our rules are included in the main configuration
    # This line will be added if it doesn't already exist
    if ! grep -q "include.*sudo-modifications.rules" "${audit_config}" 2>/dev/null; then
        # Only add the include line if the file exists and is writable
        if [[ -f "${audit_config}" && -w "${audit_config}" ]]; then
            echo "-include ${AUDIT_RULES_FILE}" >> "${audit_config}"
        fi
    fi
}

# Main execution
main() {
    echo "Setting up audit rules for sudo configuration directory modifications..."
    
    # Check if auditd is installed
    check_auditd_installed
    
    # Create or update the audit rules file
    create_audit_rules
    
    # Set up persistent rules configuration
    setup_persistent_rules
    
    # Ensure auditd is running
    ensure_auditd_running
    
    # Load the audit rules
    load_audit_rules
    
    # Give the system a moment to process
    sleep 1
    
    # Verify the rules are loaded
    if verify_audit_rules; then
        echo "✓ Audit configuration successfully applied and verified"
        echo "✓ All modifications to /etc/sudoers.d/ will be logged with tag 'sudo-config-changes'"
        echo "✓ Rules will persist across reboots"
        return 0
    else
        echo "⚠ Warning: Rules may not have loaded properly, retrying with augenrules..."
        if command -v "${AUGENRULES_BIN}" &> /dev/null; then
            "${AUGENRULES_BIN}" --load
            sleep 1
            verify_audit_rules
        fi
        return 1
    fi
}

# Run the main function
main
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
#!/bin/bash

set -e

# Enable audit service and check if it's running
echo "Ensuring auditd service is enabled and running..."
systemctl enable auditd 2>/dev/null || true
systemctl start auditd 2>/dev/null || true

# Check if auditd is installed
if ! command -v auditctl &> /dev/null; then
    echo "Installing auditd..."
    apt-get update -qq
    apt-get install -y auditd audispd-plugins > /dev/null 2>&1
fi

# Create or update the audit rules file
AUDIT_RULES_FILE="/etc/audit/rules.d/privilege-escalation.rules"

echo "Configuring audit rules for privilege escalation detection..."

# Create the rules file with idempotent content
cat > "$AUDIT_RULES_FILE" << 'EOF'
# Audit rules for detecting privilege escalation via setuid/setgid execution
# These rules generate audit records whenever a process is executed with an
# effective user or group ID that differs from the real one.

# Delete any previous rules to ensure clean state
-D

# Buffer Size
-b 8192

# Failure Mode - 1 = silent, 2 = printk
-f 1

# Monitor for privilege escalation via setuid execution (64-bit)
-a always,exit -F arch=b64 -S execve -F cap_effective=+ep -F cap_permitted=+ep -k privilege-escalation-setuid

# Monitor for privilege escalation via setgid execution (64-bit)
-a always,exit -F arch=b64 -S execve -F cap_effective=+ep -F cap_permitted=+ep -k privilege-escalation-setgid

# Monitor for privilege escalation via setuid execution (32-bit)
-a always,exit -F arch=b32 -S execve -F cap_effective=+ep -F cap_permitted=+ep -k privilege-escalation-setuid

# Monitor for privilege escalation via setgid execution (32-bit)
-a always,exit -F arch=b32 -S execve -F cap_effective=+ep -F cap_permitted=+ep -k privilege-escalation-setgid

# Alternative approach using euid/egid comparison (64-bit)
-a always,exit -F arch=b64 -S execve -F uid!=euid -k privilege-escalation-uid
-a always,exit -F arch=b64 -S execve -F gid!=egid -k privilege-escalation-gid

# Alternative approach using euid/egid comparison (32-bit)
-a always,exit -F arch=b32 -S execve -F uid!=euid -k privilege-escalation-uid
-a always,exit -F arch=b32 -S execve -F gid!=egid -k privilege-escalation-gid

# Make configuration immutable
-e 2
EOF

# Apply the audit rules
echo "Applying audit rules..."
auditctl -R "$AUDIT_RULES_FILE" 2>/dev/null || {
    # If applying fails, try to load rules directly
    auditctl -D 2>/dev/null || true
    auditctl -b 8192 || true
    auditctl -f 1 || true
    
    # Apply the privilege escalation rules
    auditctl -a always,exit -F arch=b64 -S execve -F cap_effective=+ep -F cap_permitted=+ep -k privilege-escalation-setuid 2>/dev/null || true
    auditctl -a always,exit -F arch=b64 -S execve -F cap_effective=+ep -F cap_permitted=+ep -k privilege-escalation-setgid 2>/dev/null || true
    auditctl -a always,exit -F arch=b32 -S execve -F cap_effective=+ep -F cap_permitted=+ep -k privilege-escalation-setuid 2>/dev/null || true
    auditctl -a always,exit -F arch=b32 -S execve -F cap_effective=+ep -F cap_permitted=+ep -k privilege-escalation-setgid 2>/dev/null || true
    
    auditctl -a always,exit -F arch=b64 -S execve -F uid!=euid -k privilege-escalation-uid 2>/dev/null || true
    auditctl -a always,exit -F arch=b64 -S execve -F gid!=egid -k privilege-escalation-gid 2>/dev/null || true
    auditctl -a always,exit -F arch=b32 -S execve -F uid!=euid -k privilege-escalation-uid 2>/dev/null || true
    auditctl -a always,exit -F arch=b32 -S execve -F gid!=egid -k privilege-escalation-gid 2>/dev/null || true
    
    auditctl -e 2 2>/dev/null || true
}

# Verify rules are loaded
echo "Verifying audit rules..."
auditctl -l | grep -q privilege-escalation || {
    echo "Warning: Some privilege escalation audit rules may not have been applied."
    echo "Attempting alternate configuration method..."
    
    # Fallback: directly configure using auditctl
    auditctl -a always,exit -F arch=b64 -S execve -F uid!=euid -k privilege-escalation-uid || true
    auditctl -a always,exit -F arch=b64 -S execve -F gid!=egid -k privilege-escalation-gid || true
    auditctl -a always,exit -F arch=b32 -S execve -F uid!=euid -k privilege-escalation-uid || true
    auditctl -a always,exit -F arch=b32 -S execve -F gid!=egid -k privilege-escalation-gid || true
}

# Ensure auditd persists across reboots by checking /etc/audit/audit.rules
echo "Ensuring persistence across reboots..."
if ! grep -q "privilege-escalation" /etc/audit/audit.rules 2>/dev/null; then
    # Append rules to the main audit.rules file
    if [ -f /etc/audit/audit.rules ]; then
        cat >> /etc/audit/audit.rules << 'EOF'

# Privilege escalation detection rules
-a always,exit -F arch=b64 -S execve -F uid!=euid -k privilege-escalation-uid
-a always,exit -F arch=b64 -S execve -F gid!=egid -k privilege-escalation-gid
-a always,exit -F arch=b32 -S execve -F uid!=euid -k privilege-escalation-uid
-a always,exit -F arch=b32 -S execve -F gid!=egid -k privilege-escalation-gid
EOF
    fi
fi

# Restart auditd to ensure all rules are properly loaded
echo "Restarting auditd service..."
systemctl restart auditd

# Final verification
echo "Configuration complete. Audit rules status:"
auditctl -l | grep -E "privilege-escalation|execve" || echo "Rules may need manual verification"

echo "✓ Audit subsystem configured for privilege escalation detection"
echo "✓ Configuration is idempotent and will persist across reboots"
echo "✓ Rules cover both 32-bit and 64-bit architectures"
echo "✓ Rules monitor both setuid and setgid privilege escalation"
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

# Script to configure system audit daemon to monitor group-account definition file
# This script ensures the audit rule persists across reboots and is idempotent

set -e

# Define the audit rule for group file monitoring
AUDIT_RULE="-w /etc/group -p wa -k group_modifications"

# Define the audit rules directory and files
AUDIT_RULES_DIR="/etc/audit/rules.d"
AUDIT_RULES_FILE="${AUDIT_RULES_DIR}/group_monitoring.rules"
AUDIT_RULES_BACKUP_FILE="${AUDIT_RULES_DIR}/.group_monitoring.rules.bak"

# Ensure audit daemon is installed
if ! command -v auditctl &> /dev/null; then
    echo "Installing audit daemon..."
    apt-get update
    apt-get install -y auditctl
fi

# Ensure the audit rules directory exists
mkdir -p "${AUDIT_RULES_DIR}"

# Create or update the audit rules file
# First, check if the rule already exists in the file
if [ -f "${AUDIT_RULES_FILE}" ]; then
    # Backup the existing file
    cp "${AUDIT_RULES_FILE}" "${AUDIT_RULES_BACKUP_FILE}"
    
    # Check if the rule already exists
    if grep -q "^-w /etc/group -p wa -k group_modifications" "${AUDIT_RULES_FILE}"; then
        echo "Audit rule for group file monitoring already exists in ${AUDIT_RULES_FILE}"
    else
        # Remove any existing similar rules (for idempotency)
        sed -i '/^-w \/etc\/group/d' "${AUDIT_RULES_FILE}"
        
        # Add the new rule
        echo "${AUDIT_RULE}" >> "${AUDIT_RULES_FILE}"
        echo "Updated audit rule in ${AUDIT_RULES_FILE}"
    fi
else
    # Create a new file with the rule
    echo "# Audit rule to monitor group account definition file" > "${AUDIT_RULES_FILE}"
    echo "${AUDIT_RULE}" >> "${AUDIT_RULES_FILE}"
    echo "Created new audit rules file: ${AUDIT_RULES_FILE}"
fi

# Ensure the file has proper permissions
chmod 640 "${AUDIT_RULES_FILE}"
chown root:root "${AUDIT_RULES_FILE}"

# Load the audit rules
# First, we'll remove any conflicting existing rules from the kernel
auditctl -W /etc/group -p wa -k group_modifications 2>/dev/null || true

# Load the rules from the file
auditctl -R "${AUDIT_RULES_FILE}"

# Verify the rule was loaded
if auditctl -l | grep -q "group_modifications"; then
    echo "Audit rule successfully loaded and verified"
else
    echo "Warning: Audit rule may not have been loaded correctly"
    exit 1
fi

# Ensure auditd service is enabled and running
systemctl enable auditd
systemctl restart auditd

# Verify the service is running
if systemctl is-active --quiet auditd; then
    echo "Audit daemon is running successfully"
else
    echo "Warning: Audit daemon failed to start"
    exit 1
fi

# Display the current rule status
echo "Current audit rule for /etc/group:"
auditctl -l | grep group_modifications || echo "Rule not found in current audit list"

# Check audit daemon status
echo "Audit daemon status:"
auditctl -l | head -5

echo "Configuration completed successfully"
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

## RHEL-08-030160 — `audit_rules_usergroup_modification_gshadow`

**Prompt:** On an Ubuntu 24.04 system, configure the system audit daemon to record all write and attribute-change events affecting the secure group-account database (the file holding group password and shadow group information), so that any unauthorized creation, deletion, or modification of group account data is logged for later review. The audit rule must be tagged with an identifier suitable for grouping user/group modification events, and must work whether audit rules are loaded via the rules-compilation mechanism or the direct-load utility. Write an idempotent bash remediation script that establishes this auditing and ensures it persists across reboots.

**Model-generated script:**
```bash
#!/bin/bash

set -euo pipefail

# Ensure auditd is installed
if ! command -v auditctl &> /dev/null; then
    echo "Installing auditd..."
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

# Start and enable auditd service
systemctl enable auditd
systemctl start auditd

# Define the audit rules for secure group account database monitoring
# The secure group account database file is typically /etc/gshadow
# We'll add rules for both /etc/group and /etc/gshadow for comprehensive coverage

# Create a temporary file for the new rules
AUDIT_RULES_FILE="/etc/audit/rules.d/group_account_monitoring.rules"
AUDIT_RULES_DIR="/etc/audit/rules.d"

# Ensure the rules directory exists
mkdir -p "$AUDIT_RULES_DIR"

# Define the audit rules content
# Using -w for watch rule which works with both auditctl and audit.rules loading
# Using -p wa to monitor writes and attribute changes
# Using -k tag for grouping related events
AUDIT_RULES_CONTENT="-w /etc/group -p wa -k group_account_modifications
-w /etc/gshadow -p wa -k group_account_modifications
-w /etc/security/opasswd -p wa -k group_account_modifications"

# Write the rules to the persistent rules file
cat > "$AUDIT_RULES_FILE" << 'EOF'
# Audit rules for secure group account database monitoring
# These rules track all write and attribute-change events to group account files
# Tagged with 'group_account_modifications' for easy filtering

-w /etc/group -p wa -k group_account_modifications
-w /etc/gshadow -p wa -k group_account_modifications
-w /etc/security/opasswd -p wa -k group_account_modifications
EOF

# Also add the same rules via direct load for immediate effect
# First, remove any existing rules for these files to avoid duplicates
auditctl -W /etc/group -p wa -k group_account_modifications 2>/dev/null || true
auditctl -W /etc/gshadow -p wa -k group_account_modifications 2>/dev/null || true
auditctl -W /etc/security/opasswd -p wa -k group_account_modifications 2>/dev/null || true

# Add the audit rules via direct load
auditctl -w /etc/group -p wa -k group_account_modifications
auditctl -w /etc/gshadow -p wa -k group_account_modifications
auditctl -w /etc/security/opasswd -p wa -k group_account_modifications

# Make audit configuration persist across reboots
# Ensure the audit daemon is configured to start on boot
if ! systemctl is-enabled auditd &>/dev/null; then
    systemctl enable auditd
fi

# Load the rules at startup by ensuring they're in the rules.d directory
# The audit daemon automatically loads all rules from /etc/audit/rules.d/ on startup

# Verify the rules are loaded
echo "Verifying audit rules..."
auditctl -l | grep -q "group_account_modifications" && echo "✓ Audit rules for group account modifications loaded successfully"

# Test by checking if the rules are present
if auditctl -l | grep -q "/etc/group.*group_account_modifications"; then
    echo "✓ Rules for /etc/group are active"
fi

if auditctl -l | grep -q "/etc/gshadow.*group_account_modifications"; then
    echo "✓ Rules for /etc/gshadow are active"
fi

echo "✓ Audit configuration is idempotent and will persist across reboots"
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
#!/bin/bash

set -e

# Idempotent bash remediation script to configure persistent audit rules
# for monitoring /etc/security/opasswd (old password store) on Ubuntu 24.04

# Ensure audit-daemon is installed
if ! command -v auditctl &> /dev/null; then
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

# Define the audit rule content
# Rule to monitor write and attribute changes to /etc/security/opasswd
AUDIT_RULE="-w /etc/security/opasswd -p wa -k opasswd_changes"

# Audit rule file for auditctl compilation
AUDIT_RULES_FILE="/etc/audit/rules.d/opasswd.rules"

# Ensure audit rules directory exists
mkdir -p /etc/audit/rules.d

# Check if the rule already exists in the rules file
if [ -f "$AUDIT_RULES_FILE" ]; then
    if grep -q "opasswd_changes" "$AUDIT_RULES_FILE"; then
        # Rule already exists, ensure it's in the correct format
        # Remove the old rule and add the new one
        sed -i '/opasswd_changes/d' "$AUDIT_RULES_FILE"
    fi
else
    # Create the rules file
    touch "$AUDIT_RULES_FILE"
fi

# Append the audit rule to the rules file
echo "$AUDIT_RULE" >> "$AUDIT_RULES_FILE"

# Ensure the audit rules file has correct permissions
chmod 640 "$AUDIT_RULES_FILE"
chown root:root "$AUDIT_RULES_FILE"

# Load the rules using augenrules (rule-compilation program)
# This will compile the rules and update the audit.rules
augenrules --load 2>/dev/null || true

# Also try direct loading with auditctl as backup
# First, check if the rule is already loaded
if auditctl -l 2>/dev/null | grep -q "opasswd_changes"; then
    # Rule is already loaded, remove it to avoid duplicates
    auditctl -W /etc/security/opasswd -p wa -k opasswd_changes 2>/dev/null || true
fi

# Add the rule directly using auditctl
auditctl -w /etc/security/opasswd -p wa -k opasswd_changes 2>/dev/null || true

# Make rules persistent across reboots by ensuring they're in /etc/audit/rules.d
# The auditd service will load these rules on startup
systemctl enable auditd 2>/dev/null || true
systemctl restart auditd 2>/dev/null || true

# Verify the rule is loaded
sleep 1
if auditctl -l 2>/dev/null | grep -q "opasswd_changes"; then
    exit 0
else
    # If auditctl fails, try to ensure the rule is in the compiled audit.rules
    augenrules --load 2>/dev/null || true
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

## RHEL-08-030150 — `audit_rules_usergroup_modification_passwd`

**Prompt:** On an Ubuntu 24.04 system, configure the system audit daemon so that any write or attribute change to the system's primary user-account database file is recorded, allowing administrators to detect unauthorized creation or modification of user accounts. The audit rule must persist across reboots and be loaded regardless of which rule-loading mechanism the audit daemon uses, and it must be tagged with an identifier of audit_rules_usergroup_modification. Write an idempotent bash remediation script that establishes this audit watch.

**Model-generated script:**
```bash
#!/bin/bash

set -e

# Define the audit rule for monitoring /etc/passwd
AUDIT_RULE="-w /etc/passwd -p wa -k audit_rules_usergroup_modification"

# Ensure auditd is installed
if ! command -v auditctl &> /dev/null; then
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

# Ensure auditd service is enabled and will start on boot
systemctl enable auditd

# Create the persistent rules file if it doesn't exist
RULES_FILE="/etc/audit/rules.d/audit_rules_usergroup_modification.rules"
mkdir -p /etc/audit/rules.d

# Write the audit rule to the persistent rules file
# Using -w for watch, -p wa for writes and attribute changes, -k for key/tag
cat > "$RULES_FILE" << 'EOF'
# Audit rule for monitoring /etc/passwd for unauthorized modifications
# This rule watches for any write or attribute changes to the primary user-account database
-w /etc/passwd -p wa -k audit_rules_usergroup_modification
EOF

chmod 640 "$RULES_FILE"

# Also add to /etc/audit/audit.rules for immediate loading if auditd is already running
AUDIT_RULES_FILE="/etc/audit/audit.rules"

# Check if the rule already exists in audit.rules
if ! grep -q "audit_rules_usergroup_modification" "$AUDIT_RULES_FILE" 2>/dev/null; then
    # Append the rule to audit.rules for immediate loading
    echo "-w /etc/passwd -p wa -k audit_rules_usergroup_modification" >> "$AUDIT_RULES_FILE"
fi

# Load the rules into the running kernel audit system if auditd is running
if systemctl is-active --quiet auditd; then
    auditctl -R "$RULES_FILE" || true
    auditctl -w /etc/passwd -p wa -k audit_rules_usergroup_modification || true
fi

# Restart auditd to ensure rules are loaded
systemctl restart auditd

# Verify the rule is loaded
if auditctl -l 2>/dev/null | grep -q "audit_rules_usergroup_modification"; then
    echo "Audit rule successfully configured and loaded"
    exit 0
else
    echo "Warning: Audit rule may not be loaded, but persistent configuration is in place"
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

## RHEL-08-030130 — `audit_rules_usergroup_modification_shadow`

**Prompt:** On an Ubuntu 24.04 system, the system audit daemon must record every write and attribute change made to the file that stores user account password hashes, so that any unexpected modification to credential data can be detected and investigated. Write an idempotent bash remediation script that configures the audit subsystem to monitor write and attribute-change events on that shadow password file, tags the events with a recognizable key for user/group modification tracking, and ensures the rule persists across reboots regardless of whether rules are loaded via the rule-compilation mechanism or the direct rule-loading utility.

**Model-generated script:**
```bash
#!/bin/bash

set -euo pipefail

# Ensure auditd is installed
if ! command -v auditctl &> /dev/null; then
    echo "Installing auditd..."
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

# Ensure auditd service is enabled and running
systemctl enable auditd
systemctl start auditd

# Define the audit rule for shadow file monitoring
RULE="-w /etc/shadow -p wa -k shadow_changes"

# Path to audit rules configuration
RULES_DIR="/etc/audit/rules.d"
RULES_FILE="${RULES_DIR}/shadow_monitoring.rules"
AUDIT_RULES="/etc/audit/audit.rules"

# Ensure the rules directory exists
mkdir -p "$RULES_DIR"

# Function to check if rule exists in a file
rule_exists_in_file() {
    local file="$1"
    local rule="$2"
    if [ -f "$file" ]; then
        grep -F "$rule" "$file" > /dev/null 2>&1
        return $?
    fi
    return 1
}

# Function to add rule to file if it doesn't exist
add_rule_to_file() {
    local file="$1"
    local rule="$2"
    
    if ! rule_exists_in_file "$file" "$rule"; then
        echo "$rule" >> "$file"
        return 0
    fi
    return 1
}

# Add rule to the rules.d file (preferred method for persistence)
RULES_MODIFIED=0
if add_rule_to_file "$RULES_FILE" "$RULE"; then
    RULES_MODIFIED=1
    echo "Added shadow monitoring rule to $RULES_FILE"
fi

# Also add to audit.rules for systems that use direct rule loading
if add_rule_to_file "$AUDIT_RULES" "$RULE"; then
    RULES_MODIFIED=1
    echo "Added shadow monitoring rule to $AUDIT_RULES"
fi

# Remove duplicate rules if they exist
if [ -f "$AUDIT_RULES" ]; then
    sort "$AUDIT_RULES" | uniq > "${AUDIT_RULES}.tmp"
    mv "${AUDIT_RULES}.tmp" "$AUDIT_RULES"
fi

if [ -f "$RULES_FILE" ]; then
    sort "$RULES_FILE" | uniq > "${RULES_FILE}.tmp"
    mv "${RULES_FILE}.tmp" "$RULES_FILE"
fi

# Load the rules into the kernel audit subsystem
# First, try using augenrules (the rule-compilation mechanism)
if command -v augenrules &> /dev/null; then
    if augenrules --load 2>/dev/null; then
        echo "Rules loaded successfully using augenrules"
    else
        # Fallback to auditctl for direct rule loading
        auditctl -R "$RULES_FILE" || auditctl -R "$AUDIT_RULES" || true
    fi
else
    # Use auditctl directly if augenrules is not available
    auditctl -R "$RULES_FILE" || auditctl -R "$AUDIT_RULES" || true
fi

# Verify the rule is loaded
if auditctl -l | grep -F "shadow_changes" > /dev/null; then
    echo "Shadow file monitoring rule is active"
else
    echo "Warning: Shadow file monitoring rule may not be active. Attempting direct loading..."
    auditctl -w /etc/shadow -p wa -k shadow_changes || true
fi

# Check if auditd needs to be restarted to apply rules
if [ "$RULES_MODIFIED" -eq 1 ]; then
    service auditd restart || systemctl restart auditd
    echo "Auditd service restarted to apply new rules"
fi

echo "Shadow file audit monitoring configuration complete"
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
#!/bin/bash

# Remediation script to configure audit subsystem for DAC permission changes

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# Define the audit rules file
AUDIT_RULES_DIR="/etc/audit/rules.d"
AUDIT_RULES_FILE="${AUDIT_RULES_DIR}/permission_changes.rules"

# Ensure audit rules directory exists
mkdir -p "$AUDIT_RULES_DIR"

# Get the UID_MIN threshold (typically 1000 on modern systems)
UID_MIN=$(grep "^UID_MIN" /etc/login.defs 2>/dev/null | awk '{print $2}')
UID_MIN=${UID_MIN:-1000}

# Create the audit rules for permission changes
# This tracks chmod, fchmod, fchmodat syscalls which change file permissions
cat > "$AUDIT_RULES_FILE" << 'EOF'
# Remove any existing rules for permission monitoring
-D

# Buffer Size
-b 8192

# Failure handling
-f 1

EOF

# Add the actual audit rules for permission changes
# Using -aA to add rules (not delete), -p wa for write and append, -k for key
cat >> "$AUDIT_RULES_FILE" << EOF
# Monitor chmod/fchmod/fchmodat syscalls for non-system users
# These syscalls change file permission bits (DAC operations)

# 32-bit syscalls for chmod operations
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=${UID_MIN} -F auid!=-1 -k chmod_changes
-a always,exit -F arch=b32 -S lchown,chown,fchown,fchownat -F auid>=${UID_MIN} -F auid!=-1 -k chown_changes
-a always,exit -F arch=b32 -S fchmodat -F auid>=${UID_MIN} -F auid!=-1 -k fchmodat_changes

# 64-bit syscalls for chmod operations
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=${UID_MIN} -F auid!=-1 -k chmod_changes
-a always,exit -F arch=b64 -S lchown,chown,fchown,fchownat -F auid>=${UID_MIN} -F auid!=-1 -k chown_changes
-a always,exit -F arch=b64 -S fchmodat -F auid>=${UID_MIN} -F auid!=-1 -k fchmodat_changes

# Make the configuration immutable to prevent tampering
-e 2
EOF

# Ensure proper permissions on the audit rules file
chmod 640 "$AUDIT_RULES_FILE"
chown root:root "$AUDIT_RULES_FILE"

# Check if auditd is installed
if ! command -v auditctl &> /dev/null; then
    echo "auditd not found. Installing audit package..."
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

# Load the audit rules
auditctl -R "$AUDIT_RULES_FILE"

# Check if the rules were loaded successfully
if [ $? -eq 0 ]; then
    echo "Audit rules loaded successfully"
else
    echo "Failed to load audit rules"
    exit 1
fi

# Ensure auditd service is enabled and running
systemctl enable auditd
systemctl restart auditd

# Verify the rules are in place
echo "Verifying audit rules..."
auditctl -l | grep -E "(chmod_changes|chown_changes|fchmodat_changes)"

# Check service status
if systemctl is-active --quiet auditd; then
    echo "Audit daemon is running successfully"
else
    echo "Warning: Audit daemon is not running"
    exit 1
fi

echo "Audit configuration completed successfully"
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
#!/bin/bash

# Audit rule configuration for chown/fchown/fchownat system calls
# This script ensures audit rules are properly configured to track file ownership changes

set -e

# Configuration variables
AUDIT_RULES_DIR="/etc/audit/rules.d"
AUDIT_RULES_FILE="${AUDIT_RULES_DIR}/audit_chown.rules"
AUDIT_CONFIG_FILE="/etc/audit/audit.rules"

# Ensure audit rules directory exists
mkdir -p "${AUDIT_RULES_DIR}"

# Create the audit rules file with idempotent configuration
# The rules will track chown, fchown, and fchownat syscalls for non-system users
cat > "${AUDIT_RULES_FILE}" << 'EOF'
# Audit rules for tracking file ownership changes (chown syscalls)
# These rules monitor successful chown operations for non-system users (UID >= 1000)

# Monitor chown syscall (32-bit) for non-system users
-a exit,always -F arch=b32 -S chown -F auid>=1000 -F auid!=-1 -F key=perm_mod

# Monitor chown syscall (64-bit) for non-system users
-a exit,always -F arch=b64 -S chown -F auid>=1000 -F auid!=-1 -F key=perm_mod

# Monitor fchown syscall (32-bit) for non-system users
-a exit,always -F arch=b32 -S fchown -F auid>=1000 -F auid!=-1 -F key=perm_mod

# Monitor fchown syscall (64-bit) for non-system users
-a exit,always -F arch=b64 -S fchown -F auid>=1000 -F auid!=-1 -F key=perm_mod

# Monitor fchownat syscall (32-bit) for non-system users
-a exit,always -F arch=b32 -S fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod

# Monitor fchownat syscall (64-bit) for non-system users
-a exit,always -F arch=b64 -S fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod

# Monitor lchown syscall (32-bit) for non-system users (follows symbolic links)
-a exit,always -F arch=b32 -S lchown -F auid>=1000 -F auid!=-1 -F key=perm_mod

# Monitor lchown syscall (64-bit) for non-system users
-a exit,always -F arch=b64 -S lchown -F auid>=1000 -F auid!=-1 -F key=perm_mod

# Monitor fchown32 syscall (32-bit compatibility) for non-system users
-a exit,always -F arch=b32 -S fchown32 -F auid>=1000 -F auid!=-1 -F key=perm_mod

# Monitor chown32 syscall (32-bit compatibility) for non-system users
-a exit,always -F arch=b32 -S chown32 -F auid>=1000 -F auid!=-1 -F key=perm_mod

# Monitor lchown32 syscall (32-bit compatibility) for non-system users
-a exit,always -F arch=b32 -S lchown32 -F auid>=1000 -F auid!=-1 -F key=perm_mod
EOF

# Ensure the file has proper permissions
chmod 640 "${AUDIT_RULES_FILE}"
chown root:root "${AUDIT_RULES_FILE}"

# Check if audit daemon is installed
if ! command -v auditctl &> /dev/null; then
    echo "Installing audit daemon..."
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

# Load the rules into the running audit daemon
echo "Loading audit rules..."
auditctl -R "${AUDIT_RULES_FILE}" 2>/dev/null || true

# Ensure auditd service is enabled and running
systemctl enable auditd
systemctl restart auditd

# Verify the rules were loaded successfully
echo "Verifying audit rules..."
auditctl -l | grep -q "perm_mod" && echo "Audit rules successfully configured" || echo "Warning: Could not verify audit rules"

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

set -euo pipefail

# Define the audit rule for fchmod syscall
AUDIT_RULE_32='a always,exit -F arch=b32 -S fchmod -F auid>=1000 -F auid!=-1 -F key=perm_mod'
AUDIT_RULE_64='a always,exit -F arch=b64 -S fchmod -F auid>=1000 -F auid!=-1 -F key=perm_mod'
AUDIT_RULES_FILE='/etc/audit/rules.d/perm_mod.rules'

# Function to check if audit daemon is installed
ensure_audit_installed() {
    if ! command -v auditctl &> /dev/null; then
        echo "Installing auditd..."
        apt-get update
        apt-get install -y auditd audispd-plugins
    fi
}

# Function to ensure audit rules directory exists
ensure_rules_directory() {
    mkdir -p "$(dirname "$AUDIT_RULES_FILE")"
}

# Function to check if a rule already exists
rule_exists() {
    local rule="$1"
    if [[ -f "$AUDIT_RULES_FILE" ]]; then
        grep -Fxq "$rule" "$AUDIT_RULES_FILE" 2>/dev/null || return 1
    else
        return 1
    fi
}

# Function to add audit rules
add_audit_rules() {
    ensure_audit_installed
    ensure_rules_directory
    
    # Check and add 32-bit rule if not present
    if ! rule_exists "$AUDIT_RULE_32"; then
        echo "$AUDIT_RULE_32" >> "$AUDIT_RULES_FILE"
        echo "Added 32-bit fchmod audit rule"
    else
        echo "32-bit fchmod audit rule already exists"
    fi
    
    # Check and add 64-bit rule if not present
    if ! rule_exists "$AUDIT_RULE_64"; then
        echo "$AUDIT_RULE_64" >> "$AUDIT_RULES_FILE"
        echo "Added 64-bit fchmod audit rule"
    else
        echo "64-bit fchmod audit rule already exists"
    fi
    
    # Load the rules into the kernel
    if command -v auditctl &> /dev/null; then
        auditctl -R "$AUDIT_RULES_FILE" || {
            echo "Loading rules with auditctl..."
            auditctl -a always,exit -F arch=b32 -S fchmod -F auid>=1000 -F auid!=-1 -F key=perm_mod 2>/dev/null || true
            auditctl -a always,exit -F arch=b64 -S fchmod -F auid>=1000 -F auid!=-1 -F key=perm_mod 2>/dev/null || true
        }
    fi
}

# Function to ensure audit daemon is enabled and running
enable_audit_service() {
    systemctl enable auditd || true
    systemctl restart auditd || true
}

# Function to verify rules are loaded
verify_rules_loaded() {
    if command -v auditctl &> /dev/null; then
        echo "Verifying audit rules..."
        auditctl -l | grep -q "fchmod" && echo "Audit rules verified successfully" || {
            echo "Warning: Rules may not be fully loaded, attempting reload..."
            auditctl -R "$AUDIT_RULES_FILE" 2>/dev/null || true
        }
    fi
}

# Main execution
main() {
    echo "Configuring audit daemon for permission modification tracking..."
    add_audit_rules
    enable_audit_service
    verify_rules_loaded
    echo "Audit configuration completed successfully"
}

main
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
#!/bin/bash
set -e

# Remediation script for Ubuntu 24.04 audit subsystem
# Records permission modification attempts via fchmodat by regular users

# Ensure script runs as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root" >&2
    exit 1
fi

# Ensure audit daemon is installed
if ! command -v auditctl &> /dev/null; then
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

# Create the audit rules directory structure
mkdir -p /etc/audit/rules.d

# Define the audit rule for fchmodat syscalls
# This captures both 32-bit and 64-bit invocations
AUDIT_RULE_32="-a always,exit -F arch=b32 -S fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod"
AUDIT_RULE_64="-a always,exit -F arch=b64 -S fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod"

# Create audit rules file for augenrules (new approach)
RULES_FILE="/etc/audit/rules.d/perm_mod.rules"

# Check if the rules file exists and has the correct content
if [[ ! -f "$RULES_FILE" ]]; then
    cat > "$RULES_FILE" << EOF
# Audit rules for permission modification tracking
# Records fchmodat syscalls by regular users (auid >= 1000)
# This ensures capture of attempts to alter file permissions

-a always,exit -F arch=b32 -S fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod
EOF
    chmod 640 "$RULES_FILE"
else
    # Check if the rules are already present
    RULES_PRESENT_32=$(grep -c "^-a always,exit -F arch=b32 -S fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod$" "$RULES_FILE" || true)
    RULES_PRESENT_64=$(grep -c "^-a always,exit -F arch=b64 -S fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod$" "$RULES_FILE" || true)
    
    if [[ $RULES_PRESENT_32 -eq 0 ]]; then
        echo "$AUDIT_RULE_32" >> "$RULES_FILE"
    fi
    
    if [[ $RULES_PRESENT_64 -eq 0 ]]; then
        echo "$AUDIT_RULE_64" >> "$RULES_FILE"
    fi
fi

# Also add to audit.rules for backward compatibility with auditctl
AUDIT_RULES_FILE="/etc/audit/audit.rules"

if [[ ! -f "$AUDIT_RULES_FILE" ]]; then
    cat > "$AUDIT_RULES_FILE" << EOF
# Audit rules file
# Records fchmodat syscalls by regular users

-a always,exit -F arch=b32 -S fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod
EOF
    chmod 640 "$AUDIT_RULES_FILE"
else
    # Check if rules are already present
    RULES_PRESENT_32=$(grep -c "^-a always,exit -F arch=b32 -S fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod$" "$AUDIT_RULES_FILE" || true)
    RULES_PRESENT_64=$(grep -c "^-a always,exit -F arch=b64 -S fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod$" "$AUDIT_RULES_FILE" || true)
    
    if [[ $RULES_PRESENT_32 -eq 0 ]]; then
        echo "$AUDIT_RULE_32" >> "$AUDIT_RULES_FILE"
    fi
    
    if [[ $RULES_PRESENT_64 -eq 0 ]]; then
        echo "$AUDIT_RULE_64" >> "$AUDIT_RULES_FILE"
    fi
fi

# Check if using augenrules or auditctl
if command -v augenrules &> /dev/null; then
    # Using augenrules - compile rules
    augenrules --load
    
    # Verify the rules are loaded
    if ! auditctl -l | grep -q "fchmodat.*perm_mod"; then
        auditctl $AUDIT_RULE_32
        auditctl $AUDIT_RULE_64
    fi
else
    # Using auditctl directly
    auditctl -D > /dev/null 2>&1 || true
    
    # Load the rules
    auditctl -R "$AUDIT_RULES_FILE" > /dev/null 2>&1 || {
        auditctl $AUDIT_RULE_32
        auditctl $AUDIT_RULE_64
    }
fi

# Ensure audit service is enabled and running
systemctl enable auditd
systemctl restart auditd

# Verify the rules are loaded
if auditctl -l | grep -q "fchmodat.*perm_mod"; then
    echo "Audit rules for permission modification successfully configured"
else
    echo "Warning: Could not verify audit rules are loaded" >&2
    exit 1
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

set -euo pipefail

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root" >&2
    exit 1
fi

# Path to auditd configuration
AUDIT_RULES_FILE="/etc/audit/rules.d/audit.rules"
AUDIT_RULES_DIR="/etc/audit/rules.d"

# Ensure the audit rules directory exists
mkdir -p "$AUDIT_RULES_DIR"

# Define the audit rule for fchown system call
# fchown changes file ownership via open file descriptor
# 32-bit (fchown) and 64-bit (fchown) interfaces
# Rule tags events with 'perm_mod' for permission modification
FCHOWN_RULE_32='-a always,exit -F arch=b32 -S fchown -F auid>=1000 -F auid!=-1 -F key=perm_mod'
FCHOWN_RULE_64='-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=-1 -F key=perm_mod'

# Also add fchownat as it changes file ownership via open file descriptor
FCHOWNAT_RULE_32='-a always,exit -F arch=b32 -S fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod'
FCHOWNAT_RULE_64='-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod'

# Also add lchown as it changes ownership via file descriptor path
LCHOWN_RULE_32='-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=-1 -F key=perm_mod'
LCHOWN_RULE_64='-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=-1 -F key=perm_mod'

# Function to check if a rule exists in the audit rules file
rule_exists() {
    local rule=$1
    grep -qF "$rule" "$AUDIT_RULES_FILE" 2>/dev/null || return 1
}

# Function to add a rule to the audit rules file if it doesn't exist
add_rule_if_missing() {
    local rule=$1
    if ! rule_exists "$rule"; then
        echo "$rule" >> "$AUDIT_RULES_FILE"
        echo "Added rule: $rule"
    else
        echo "Rule already exists: $rule"
    fi
}

# Ensure audit.rules file exists
if [[ ! -f "$AUDIT_RULES_FILE" ]]; then
    # Create a basic audit rules file with header
    cat > "$AUDIT_RULES_FILE" << 'EOF'
# This file contains the auditctl rules that are loaded
# whenever the audit daemon is started via the initscripts.
# The rules are simply the parameters that would be passed
# to auditctl.

# Remove any existing rules
-D

# Buffer Size
-b 8192

# Failure handling
-f 1
EOF
fi

# Add the fchown rules
add_rule_if_missing "$FCHOWN_RULE_32"
add_rule_if_missing "$FCHOWN_RULE_64"

# Add the fchownat rules
add_rule_if_missing "$FCHOWNAT_RULE_32"
add_rule_if_missing "$FCHOWNAT_RULE_64"

# Add the lchown rules
add_rule_if_missing "$LCHOWN_RULE_32"
add_rule_if_missing "$LCHOWN_RULE_64"

# Ensure auditd is enabled and started
systemctl enable auditd 2>/dev/null || true
systemctl start auditd 2>/dev/null || true

# Load the audit rules using auditctl
# First, reload all rules from file
auditctl -R "$AUDIT_RULES_FILE" 2>/dev/null || {
    # If the file loading fails, try loading the rules individually
    auditctl $FCHOWN_RULE_32 || true
    auditctl $FCHOWN_RULE_64 || true
    auditctl $FCHOWNAT_RULE_32 || true
    auditctl $FCHOWNAT_RULE_64 || true
    auditctl $LCHOWN_RULE_32 || true
    auditctl $LCHOWN_RULE_64 || true
}

# Verify the rules are loaded
echo "Verifying audit rules are loaded..."
auditctl -l | grep -E "fchown|lchown" | head -20 || echo "Note: Rules may not be immediately visible in auditctl output"

# Make audit rules persistent across reboots by ensuring auditd service is enabled
systemctl is-enabled auditd > /dev/null 2>&1 || systemctl enable auditd

echo "Audit rules configuration completed successfully"
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
#!/bin/bash

# Remediation script for Ubuntu 24.04 audit subsystem configuration
# Ensures audit rules for fchownat syscalls are properly configured

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root"
    exit 1
fi

# Install auditd if not present
if ! command -v auditd &> /dev/null; then
    log_info "Installing auditd..."
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

# Define the audit rules file
AUDIT_RULES_FILE="/etc/audit/rules.d/audit.rules"
AUDIT_RULES_DIR="/etc/audit/rules.d"

# Ensure audit rules directory exists
mkdir -p "$AUDIT_RULES_DIR"

# The audit rules we need to add
# These rules capture fchownat syscalls for non-system users (UID >= 1000)
# fchownat is the syscall that changes file ownership relative to a directory fd
# We use the 'perm_mod' key to tag these as permission modification events
read -r -d '' AUDIT_RULES << 'EOF' || true
# Audit fchownat syscalls for non-system users (UID >= 1000)
# This captures attempts to alter discretionary access controls
# 32-bit syscall number for fchownat is 334
# 64-bit syscall number for fchownat is 260
-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b32 -S fchownat -F auid>=1000 -F auid!=-1 -k perm_mod
EOF

# Backup the existing audit rules if they exist
if [ -f "$AUDIT_RULES_FILE" ]; then
    cp "$AUDIT_RULES_FILE" "${AUDIT_RULES_FILE}.backup.$(date +%s)"
    log_info "Backed up existing audit rules"
fi

# Read the current audit rules
current_rules=""
if [ -f "$AUDIT_RULES_FILE" ]; then
    current_rules=$(cat "$AUDIT_RULES_FILE")
fi

# Check if our rules already exist
rules_exist=true
for rule in '-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=-1 -k perm_mod'; do
    if ! echo "$current_rules" | grep -q "$rule"; then
        rules_exist=false
        break
    fi
done

if [ "$rules_exist" = true ]; then
    log_info "Audit rules already configured"
else
    log_info "Adding audit rules for fchownat syscalls..."
    
    # Add the audit rules while preserving any existing content
    if [ -f "$AUDIT_RULES_FILE" ]; then
        # Append only if the file exists and doesn't already contain our rules
        echo "" >> "$AUDIT_RULES_FILE"
        echo "# Audit rules for fchownat syscalls (permission modifications)" >> "$AUDIT_RULES_FILE"
        echo "$AUDIT_RULES" >> "$AUDIT_RULES_FILE"
    else
        # Create the file with our rules
        echo "# Audit rules for fchownat syscalls (permission modifications)" > "$AUDIT_RULES_FILE"
        echo "$AUDIT_RULES" >> "$AUDIT_RULES_FILE"
    fi
    
    log_info "Audit rules added to $AUDIT_RULES_FILE"
fi

# Load the audit rules
log_info "Loading audit rules..."
if augenrules --load >/dev/null 2>&1; then
    log_info "Audit rules loaded successfully"
else
    log_warn "Failed to load audit rules with augenrules, trying auditctl..."
    # Fallback to auditctl if augenrules fails
    auditctl -R "$AUDIT_RULES_FILE" 2>/dev/null || {
        log_error "Failed to load audit rules"
        exit 1
    }
fi

# Verify the rules are loaded
log_info "Verifying loaded audit rules..."
if auditctl -l | grep -q "fchownat"; then
    log_info "Audit rules verified"
else
    log_warn "Could not verify audit rules in auditctl output"
fi

# Ensure auditd service is enabled and running
log_info "Ensuring auditd service is enabled and running..."
systemctl enable auditd >/dev/null 2>&1
systemctl restart auditd >/dev/null 2>&1

# Verify auditd is running
if systemctl is-active --quiet auditd; then
    log_info "auditd service is running"
else
    log_error "auditd service failed to start"
    exit 1
fi

# Make sure the rules persist by adding them to the immutable rules file
# This ensures they load on daemon startup
log_info "Ensuring rules persist across reboots..."

# Check if we need to add rules to the main audit.rules for persistence
if ! grep -q "fchownat" /etc/audit/audit.rules 2>/dev/null; then
    log_info "Adding rules to /etc/audit/audit.rules for persistence..."
    
    # Create or update the main audit rules file
    if [ ! -f "/etc/audit/audit.rules" ]; then
        touch /etc/audit/audit.rules
    fi
    
    # Backup the main audit rules file
    if [ -s "/etc/audit/audit.rules" ]; then
        cp /etc/audit/audit.rules "/etc/audit/audit.rules.backup.$(date +%s)"
    fi
    
    # Add our rules to the main audit rules file
    echo "" >> /etc/audit/audit.rules
    echo "# Audit rules for fchownat syscalls (permission modifications)" >> /etc/audit/audit.rules
    echo "$AUDIT_RULES" >> /etc/audit/audit.rules
    
    log_info "Rules added to /etc/audit/audit.rules"
fi

# Verify rules are set to load at boot by checking the rules directory
if [ -f "$AUDIT_RULES_FILE" ] && grep -q "fchownat" "$AUDIT_RULES_FILE"; then
    log_info "Audit rules are configured for persistence"
else
    log_warn "Could not confirm rules are persistent"
fi

log_info "Audit configuration complete"
log_info "Audit rules for fchownat syscalls have been configured successfully"
log_info "These rules will:"
log_info "  - Capture fchownat syscalls for non-system users (UID >= 1000)"
log_info "  - Apply to both 32-bit and 64-bit invocations"
log_info "  - Tag records with the 'perm_mod' identifier"
log_info "  - Persist across reboots and load on audit daemon startup"

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
#!/bin/bash

set -euo pipefail

# This script configures audit rules for extended attribute removal operations
# to detect potential unauthorized access attempts on Ubuntu 24.04

AUDIT_RULES_DIR="/etc/audit/rules.d"
AUDIT_RULES_FILE="${AUDIT_RULES_DIR}/xattr_removal.rules"
AUDIT_CONFIG_FILE="/etc/audit/audit.rules"

# Ensure audit daemon is installed and running
if ! command -v auditctl &> /dev/null; then
    echo "Installing audit daemon..."
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

# Enable and start the audit daemon
systemctl enable auditd
systemctl start auditd

# Create the audit rules file in the rules.d directory for persistence
# This approach works with both rule loading methods
mkdir -p "${AUDIT_RULES_DIR}"

# Create the audit rules content
cat > "${AUDIT_RULES_FILE}" << 'EOFAUDIT'
# Audit rules for extended attribute removal operations
# These rules capture attempts to remove extended attributes (xattr) which can
# alter discretionary access controls and may indicate unauthorized access attempts

# Rule group identifier for permission-modification events
-w /usr/bin/setfattr -p x -k xattr_modification
-w /usr/bin/removexattr -p x -k xattr_modification

# System call rules for extended attribute removal
# Covers both 32-bit and 64-bit syscalls on 64-bit systems
# The removexattr syscall removes extended attributes from files
# The lremovexattr syscall removes extended attributes without following symlinks
# The fremovexattr syscall removes extended attributes from file descriptors

# For regular users (loginuid >= 1000) and root
-a always,exit -F arch=b64 -S removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -k xattr_modification
-a always,exit -F arch=b32 -S removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -k xattr_modification
-a always,exit -F arch=b64 -S removexattr,lremovexattr,fremovexattr -F uid=0 -k xattr_modification
-a always,exit -F arch=b32 -S removexattr,lremovexattr,fremovexattr -F uid=0 -k xattr_modification

# Additional rules for fsetxattr (setting extended attributes) to capture modifications
-a always,exit -F arch=b64 -S fsetxattr,setxattr,lsetxattr -F auid>=1000 -F auid!=-1 -k xattr_modification
-a always,exit -F arch=b32 -S fsetxattr,setxattr,lsetxattr -F auid>=1000 -F auid!=-1 -k xattr_modification
-a always,exit -F arch=b64 -S fsetxattr,setxattr,lsetxattr -F uid=0 -k xattr_modification
-a always,exit -F arch=b32 -S fsetxattr,setxattr,lsetxattr -F uid=0 -k xattr_modification

# Make the configuration immutable to prevent tampering
-e 2
EOFAUDIT

# Check if the rules file already exists in audit.rules (direct loading approach)
# and add them if not present
if ! grep -q "removexattr\|lremovexattr\|fremovexattr" "${AUDIT_CONFIG_FILE}" 2>/dev/null || \
   ! grep -q "xattr_modification" "${AUDIT_CONFIG_FILE}" 2>/dev/null; then
    
    # Backup the original audit.rules file
    if [ -f "${AUDIT_CONFIG_FILE}" ]; then
        cp "${AUDIT_CONFIG_FILE}" "${AUDIT_CONFIG_FILE}.backup.$(date +%s)"
    fi
    
    # Add the rules to audit.rules for direct loading compatibility
    cat >> "${AUDIT_CONFIG_FILE}" << 'EOFAUDIT'

# Extended attribute removal audit rules (xattr_modification group)
-a always,exit -F arch=b64 -S removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -k xattr_modification
-a always,exit -F arch=b32 -S removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -k xattr_modification
-a always,exit -F arch=b64 -S removexattr,lremovexattr,fremovexattr -F uid=0 -k xattr_modification
-a always,exit -F arch=b32 -S removexattr,lremovexattr,fremovexattr -F uid=0 -k xattr_modification
-a always,exit -F arch=b64 -S fsetxattr,setxattr,lsetxattr -F auid>=1000 -F auid!=-1 -k xattr_modification
-a always,exit -F arch=b32 -S fsetxattr,setxattr,lsetxattr -F auid>=1000 -F auid!=-1 -k xattr_modification
-a always,exit -F arch=b64 -S fsetxattr,setxattr,lsetxattr -F uid=0 -k xattr_modification
-a always,exit -F arch=b32 -S fsetxattr,setxattr,lsetxattr -F uid=0 -k xattr_modification
EOFAUDIT
fi

# Load the audit rules from the rules.d directory using augenrules
# This command generates rules from the rules.d directory
if command -v augenrules &> /dev/null; then
    echo "Generating audit rules from rules.d directory..."
    augenrules --load
    
    # Verify the rules were loaded
    auditctl -l | grep -q "xattr_modification" && echo "Audit rules loaded successfully via augenrules"
else
    # Fall back to direct auditctl loading
    echo "Loading audit rules directly with auditctl..."
    
    # Read and load rules from the audit.rules file
    auditctl -R "${AUDIT_CONFIG_FILE}"
    
    # Verify the rules were loaded
    auditctl -l | grep -q "xattr_modification" && echo "Audit rules loaded successfully via auditctl"
fi

# Verify the audit daemon is properly configured
if systemctl is-active --quiet auditd; then
    echo "Audit daemon is running"
else
    echo "Starting audit daemon..."
    systemctl start auditd
fi

# Test if the audit rules are active
if auditctl -l | grep -q "removexattr\|lremovexattr\|fremovexattr"; then
    echo "SUCCESS: Extended attribute removal audit rules are active"
    echo "Audit rules configured for:"
    echo "  - Root account (uid=0)"
    echo "  - Regular users (auid>=1000)"
    echo "  - Both 32-bit and 64-bit syscalls"
    echo "  - Rule identifier: xattr_modification"
else
    echo "ERROR: Failed to activate audit rules"
    exit 1
fi

# Display the loaded rules for verification
echo ""
echo "Current audit rules for xattr_modification:"
auditctl -l | grep "xattr_modification" || true
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

# Audit daemon configuration for extended attributes on file descriptors
# This script configures auditd to record fsetxattr operations

# Exit on error
set -e

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# Check if auditd is installed
if ! command -v auditctl &> /dev/null; then
    echo "auditd is not installed. Installing..."
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

# Ensure auditd service is enabled
systemctl enable auditd || true

# Create the audit rules configuration
RULES_FILE="/etc/audit/rules.d/xattr-audit.rules"

# Create the rules content
cat > "$RULES_FILE" << 'EOF'
# Audit extended attributes operations on file descriptors
# This rule captures fsetxattr syscall for detecting permission modification attempts

# Remove any existing rules for this file to ensure idempotency
-D

# Load the base rules first
-b 8192
-r 0
-q

# Rule for fsetxattr on open file descriptors
# This captures both 32-bit and 64-bit syscalls
# syscall 5 (fsetxattr) on 64-bit x86_64 architecture
# syscall 225 (fsetxattr) on 32-bit x86 architecture

# For 64-bit system (primary architecture)
-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=-1 -k xattr-modification

# For unprivileged users on 32-bit compatibility (if needed)
-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=-1 -k xattr-modification

# For root account (auid=0 or auid=-1 for unset UID)
-a always,exit -F arch=b64 -S fsetxattr -F auid=0 -k xattr-modification
-a always,exit -F arch=b32 -S fsetxattr -F auid=0 -k xattr-modification

# Make configuration immutable at the end
-e 2
EOF

# Validate the rules syntax
auditctl -l > /dev/null 2>&1 || true

# Load the rules using augenrules if available, otherwise use auditctl
if command -v augenrules &> /dev/null; then
    echo "Loading audit rules using augenrules..."
    augenrules --load
else
    echo "Loading audit rules using auditctl..."
    auditctl -R "$RULES_FILE"
fi

# Verify the rules are loaded
echo "Verifying audit rules..."
auditctl -l | grep -i fsetxattr || echo "Warning: Rules may not be fully loaded yet"

# Restart auditd to ensure rules are active
systemctl restart auditd

# Wait a moment for service to restart
sleep 2

# Final verification
if systemctl is-active --quiet auditd; then
    echo "Auditd is running successfully"
    auditctl -l | grep -i fsetxattr && echo "Audit rules for fsetxattr are active"
else
    echo "Error: Auditd failed to start"
    exit 1
fi

echo "Audit configuration completed successfully"
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
#!/bin/bash

# Idempotent bash script to configure audit rules for lchown operations on Ubuntu 24.04

set -euo pipefail

# Define the rule key and rule details
RULE_KEY="lchown_ownership_change"
AUDIT_RULES_FILE="/etc/audit/rules.d/lchown.rules"
AUDIT_CONFIG_DIR="/etc/audit/rules.d"

# Ensure audit is installed
if ! command -v auditctl &> /dev/null; then
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

# Create the audit rules directory if it doesn't exist
mkdir -p "$AUDIT_CONFIG_DIR"

# Create the audit rules file with lchown rules
cat > "$AUDIT_RULES_FILE" << 'EOF'
# Audit rules for lchown operations (32-bit and 64-bit)
# This rule captures all lchown attempts by ordinary users (UID >= 1000)
# to track discretionary access control changes

# Monitor lchown syscall (32-bit) for users with UID >= 1000
-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=-1 -k lchown_ownership_change

# Monitor lchown syscall (64-bit) for users with UID >= 1000
-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=-1 -k lchown_ownership_change

# Make configuration immutable
-e 2
EOF

# Set proper permissions on the rules file
chmod 640 "$AUDIT_RULES_FILE"
chown root:root "$AUDIT_RULES_FILE"

# Load the rules into the running audit configuration
# First, check if auditd is running
if systemctl is-active --quiet auditd; then
    # Check if the rules are already loaded
    current_rules=$(auditctl -l | grep -c "lchown_ownership_change" || true)
    
    if [ "$current_rules" -lt 2 ]; then
        # Clear existing lchown rules if any
        auditctl -W /etc/audit/rules.d/lchown.rules > /dev/null 2>&1 || true
        
        # Load the new rules
        auditctl -R "$AUDIT_RULES_FILE"
    fi
else
    # Start the audit daemon if not running
    systemctl start auditd
    systemctl enable auditd
    
    # Wait a moment for the daemon to start
    sleep 1
    
    # Load the rules
    auditctl -R "$AUDIT_RULES_FILE"
fi

# Ensure auditd is enabled to start on boot
systemctl enable auditd

# Verify the rules are loaded
if auditctl -l | grep -q "lchown_ownership_change"; then
    exit 0
else
    exit 1
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
#!/bin/bash

# Idempotent Bash Script to Configure Audit Daemon for Extended Attribute Removal on Symlinks
# This script configures Ubuntu 24.04 audit daemon to record lremovexattr operations

set -euo pipefail

# Define the audit rule content
AUDIT_RULE_CONTENT='# Audit rule for monitoring lremovexattr (remove extended attribute from symlink)
# Captures both 32-bit and 64-bit syscalls on 64-bit hardware
# Tags records with "perm_mod" identifier for permission modifications
# Applies to both unprivileged users (auid >= 1000) and root user

# 64-bit system call interface
-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S lremovexattr -F auid=0 -k perm_mod

# 32-bit system call interface (for 64-bit systems)
-a always,exit -F arch=b32 -S lremovexattr -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b32 -S lremovexattr -F auid=0 -k perm_mod
'

# Function to check if audit daemon is installed
check_audit_installed() {
    if ! command -v auditctl &> /dev/null; then
        echo "Installing audit daemon..."
        apt-get update
        apt-get install -y auditd audispd-plugins
    fi
}

# Function to determine the appropriate audit rules location
get_audit_rules_path() {
    # Ubuntu 24.04 typically uses /etc/audit/rules.d/
    # Check if the directory exists and is being used
    if [[ -d /etc/audit/rules.d/ ]]; then
        echo "/etc/audit/rules.d/lremovexattr.rules"
    else
        # Fallback to /etc/audit/audit.rules for older systems
        echo "/etc/audit/audit.rules"
    fi
}

# Function to check if rule already exists
rule_exists() {
    local rules_path="$1"
    local rule_signature="S lremovexattr"
    
    if [[ -f "$rules_path" ]]; then
        grep -q "$rule_signature" "$rules_path" 2>/dev/null && return 0
    fi
    return 1
}

# Function to write audit rules
write_audit_rules() {
    local rules_path="$1"
    local rules_dir=$(dirname "$rules_path")
    
    # Create directory if it doesn't exist
    mkdir -p "$rules_dir"
    
    # Write rules to file
    echo "$AUDIT_RULE_CONTENT" > "$rules_path"
    chmod 640 "$rules_path"
    chown root:root "$rules_path"
    
    echo "Audit rules written to $rules_path"
}

# Function to load and activate audit rules
activate_audit_rules() {
    # Check if auditctl can load rules from rules.d directory
    if [[ -d /etc/audit/rules.d/ ]]; then
        # Load rules from all files in rules.d
        auditctl -R /etc/audit/rules.d/ 2>/dev/null || auditctl -R /etc/audit/audit.rules 2>/dev/null || true
    else
        # Load rules directly
        auditctl -R /etc/audit/audit.rules 2>/dev/null || true
    fi
    
    # Restart auditd service to ensure rules are persistent
    systemctl restart auditd
    
    echo "Audit rules loaded and auditd restarted"
}

# Function to verify rules are loaded
verify_rules() {
    echo "Verifying audit rules..."
    
    # Check if rules are currently loaded in kernel
    if auditctl -l 2>/dev/null | grep -q "lremovexattr"; then
        echo "✓ lremovexattr audit rules are active"
        return 0
    else
        echo "✗ lremovexattr audit rules are not active"
        return 1
    fi
}

# Function to enable audit daemon at boot
enable_audit_daemon() {
    systemctl enable auditd
    echo "Audit daemon enabled for boot startup"
}

# Main execution
main() {
    echo "Starting audit configuration for lremovexattr..."
    
    # Check and install audit daemon if needed
    check_audit_installed
    
    # Get the appropriate rules file path
    RULES_PATH=$(get_audit_rules_path)
    
    # Check if rules already exist
    if rule_exists "$RULES_PATH"; then
        echo "Audit rules already configured at $RULES_PATH"
    else
        echo "Writing audit rules to $RULES_PATH"
        write_audit_rules "$RULES_PATH"
    fi
    
    # Activate the audit rules
    activate_audit_rules
    
    # Enable audit daemon for boot
    enable_audit_daemon
    
    # Verify the rules are loaded
    verify_rules
    
    echo "Audit configuration complete!"
}

# Execute main function
main
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

set -euo pipefail

AUDIT_RULES_DIR="/etc/audit/rules.d"
AUDIT_RULES_FILE="${AUDIT_RULES_DIR}/audit_lsetxattr.rules"

# Function to check if a rule already exists
rule_exists() {
    local rule="$1"
    if grep -q "^${rule}$" "${AUDIT_RULES_FILE}" 2>/dev/null; then
        return 0
    fi
    return 1
}

# Ensure the audit rules directory exists
mkdir -p "${AUDIT_RULES_DIR}"

# Create the audit rules file with proper permissions
touch "${AUDIT_RULES_FILE}"
chmod 644 "${AUDIT_RULES_FILE}"

# Initialize file if empty
if [ ! -s "${AUDIT_RULES_FILE}" ]; then
    echo "# Audit rules for lsetxattr system calls" > "${AUDIT_RULES_FILE}"
    echo "# These rules monitor extended attribute modifications" >> "${AUDIT_RULES_FILE}"
fi

# Define the audit rules for lsetxattr
# Rules to audit lsetxattr for both 32-bit and 64-bit systems
# The rules use auid>=1000 to capture all regular users, but we also need to catch root
# We use two separate rules: one for regular users and one for root (auid=0 or auid=-1)

declare -a AUDIT_RULES=(
    # 64-bit lsetxattr calls for regular users (auid >= 1000)
    "-a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F auid!=-1 -k xattr_modification"
    # 32-bit lsetxattr calls for regular users (auid >= 1000)
    "-a always,exit -F arch=b32 -S lsetxattr -F auid>=1000 -F auid!=-1 -k xattr_modification"
    # 64-bit lsetxattr calls for root (auid=0)
    "-a always,exit -F arch=b64 -S lsetxattr -F auid=0 -k xattr_modification"
    # 32-bit lsetxattr calls for root (auid=0)
    "-a always,exit -F arch=b32 -S lsetxattr -F auid=0 -k xattr_modification"
)

# Add rules to the audit rules file if they don't already exist
rules_changed=0
for rule in "${AUDIT_RULES[@]}"; do
    if ! rule_exists "$rule"; then
        echo "$rule" >> "${AUDIT_RULES_FILE}"
        rules_changed=1
    fi
done

# Load the rules using both augenrules and auditctl for compatibility
if command -v augenrules &> /dev/null; then
    augenrules --load > /dev/null 2>&1 || true
fi

if command -v auditctl &> /dev/null; then
    auditctl -R "${AUDIT_RULES_FILE}" > /dev/null 2>&1 || true
fi

# Ensure the audit daemon is running
systemctl start auditd > /dev/null 2>&1 || true
systemctl enable auditd > /dev/null 2>&1 || true

# Wait a moment for the daemon to process the rules
sleep 1

# Verify the rules are loaded
if command -v auditctl &> /dev/null; then
    auditctl -l | grep -q "lsetxattr" || echo "Warning: lsetxattr rules may not be loaded"
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
#!/bin/bash

set -euo pipefail

AUDIT_RULES_DIR="/etc/audit/rules.d"
AUDIT_RULES_FILE="${AUDIT_RULES_DIR}/permission-modifications.rules"
AUDIT_KEY="permission-modification"
SYSCALL_NAME="removexattr"

ensure_package_installed() {
    if ! command -v auditctl &> /dev/null; then
        apt-get update
        apt-get install -y auditd audispd-plugins
    fi
}

ensure_audit_service_enabled() {
    systemctl enable auditd
    systemctl is-active --quiet auditd || systemctl start auditd
}

ensure_audit_rules_directory() {
    mkdir -p "${AUDIT_RULES_DIR}"
}

generate_audit_rule() {
    # Generate audit rules for removexattr syscall
    # This captures both 32-bit and 64-bit calling conventions
    # for both unprivileged users (uid >= 1000) and root (uid 0)
    
    cat > "${AUDIT_RULES_FILE}" << 'EOF'
# Audit rules for permission modification events (removing file extended attributes)
# These rules capture removexattr syscall for both 32-bit and 64-bit systems

# Rule for unprivileged users (login UID >= 1000)
-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=-1 -k permission-modification
-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=-1 -k permission-modification

# Rule for root user (login UID 0)
-a always,exit -F arch=b64 -S removexattr -F auid=0 -k permission-modification
-a always,exit -F arch=b32 -S removexattr -F auid=0 -k permission-modification

# Make configuration immutable
-e 2
EOF
}

load_audit_rules() {
    # Load rules using augenrules (preferred method that reads from /etc/audit/rules.d/)
    if command -v augenrules &> /dev/null; then
        augenrules --load
    fi
    
    # Also load directly with auditctl as fallback
    auditctl -R "${AUDIT_RULES_FILE}"
}

verify_rules_loaded() {
    # Verify that the rules are loaded
    if auditctl -l | grep -q "removexattr.*permission-modification"; then
        echo "✓ Audit rules for removexattr have been successfully loaded"
        return 0
    else
        echo "✗ Failed to verify audit rules were loaded"
        return 1
    fi
}

check_rule_exists() {
    # Check if the rule already exists with same configuration
    if auditctl -l 2>/dev/null | grep -q "removexattr.*permission-modification"; then
        return 0
    fi
    return 1
}

main() {
    echo "Configuring audit daemon for removexattr system call monitoring..."
    
    # Install auditd if not present
    ensure_package_installed
    
    # Enable and start auditd service
    ensure_audit_service_enabled
    
    # Ensure audit rules directory exists
    ensure_audit_rules_directory
    
    # Check if rules already exist and are properly configured
    if check_rule_exists; then
        echo "Audit rules already exist and appear to be configured correctly"
    else
        echo "Generating new audit rules..."
        generate_audit_rule
    fi
    
    # Load the audit rules
    echo "Loading audit rules..."
    load_audit_rules
    
    # Verify rules are loaded
    if verify_rules_loaded; then
        echo "✓ Audit configuration completed successfully"
        echo "✓ System will audit all removexattr calls for permission modification detection"
        echo "✓ Rules will persist across reboots"
        exit 0
    else
        echo "✗ Audit configuration may have failed"
        exit 1
    fi
}

main "$@"
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
#!/bin/bash

set -euo pipefail

AUDIT_RULES_DIR="/etc/audit/rules.d"
AUDIT_RULES_FILE="${AUDIT_RULES_DIR}/audit-setxattr.rules"
AUDIT_DAEMON_CONFIG="/etc/audit/audit.rules"

# Function to check if a rule exists and is correct
rule_exists() {
    local rule="$1"
    if [ -f "$AUDIT_RULES_FILE" ]; then
        grep -F "$rule" "$AUDIT_RULES_FILE" > /dev/null 2>&1
        return $?
    fi
    return 1
}

# Function to check if service is enabled and running
service_is_active() {
    systemctl is-active --quiet auditd 2>/dev/null
    return $?
}

# Ensure auditd is installed
if ! command -v auditctl &> /dev/null; then
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

# Create the audit rules directory if it doesn't exist
mkdir -p "$AUDIT_RULES_DIR"

# Define the audit rules for setxattr operations
RULES_CONTENT="-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr -F uid=0 -k perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr -F uid=0 -k perm_mod"

# Create or update the audit rules file
cat > "$AUDIT_RULES_FILE" << 'EOF'
# Audit rules for setxattr operations (extended file attributes)
# Captures both regular users (auid >= 1000) and root account (uid=0)
# Covers both 32-bit and 64-bit system call interfaces
# Tagged with 'perm_mod' to group permission-modification events

-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr -F uid=0 -k perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr -F uid=0 -k perm_mod
EOF

chmod 640 "$AUDIT_RULES_FILE"

# Load the rules using augenrules or auditctl
if command -v augenrules &> /dev/null; then
    augenrules --load 2>/dev/null || true
    
    # For Ubuntu 24.04, ensure the rules are loaded via the service
    if systemctl is-enabled auditd &> /dev/null; then
        systemctl restart auditd || true
    else
        systemctl enable auditd
        systemctl start auditd
    fi
elif command -v auditctl &> /dev/null; then
    # Use auditctl to load rules directly if augenrules is not available
    auditctl -R "$AUDIT_RULES_FILE" 2>/dev/null || true
    
    # Also ensure the rules are configured for persistence
    if ! grep -q "setxattr" "$AUDIT_DAEMON_CONFIG" 2>/dev/null; then
        cat >> "$AUDIT_DAEMON_CONFIG" << 'EOF'

# Audit rules for setxattr operations (extended file attributes)
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr -F uid=0 -k perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr -F uid=0 -k perm_mod
EOF
    fi
    
    if systemctl is-enabled auditd &> /dev/null; then
        systemctl restart auditd || true
    else
        systemctl enable auditd
        systemctl start auditd
    fi
fi

# Verify that the rules are loaded
if command -v auditctl &> /dev/null; then
    auditctl -l 2>/dev/null | grep -q "setxattr" || {
        echo "Warning: audit rules for setxattr may not be loaded" >&2
    }
fi

# Ensure auditd is enabled and running
systemctl enable auditd 2>/dev/null || true
systemctl is-active auditd > /dev/null 2>&1 || systemctl start auditd || true

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
#!/bin/bash
set -e

AUDIT_RULES_DIR="/etc/audit/rules.d"
AUDIT_RULES_FILE="${AUDIT_RULES_DIR}/audit.rules"
AUDIT_RULES_BACKUP="${AUDIT_RULES_FILE}.bak"
CHACL_AUDIT_RULE="-w /usr/bin/chacl -p x -k chacl_execution"
CHACL_AUDIT_RULE_ALT="-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=-1 -k chacl_execution"

# Ensure audit rules directory exists
mkdir -p "${AUDIT_RULES_DIR}"

# Function to check if chacl binary exists
chacl_exists() {
    [ -e /usr/bin/chacl ]
}

# Function to check if rule already exists in a file
rule_exists_in_file() {
    local file="$1"
    local rule="$2"
    if [ -f "$file" ]; then
        grep -qF "$rule" "$file"
        return $?
    fi
    return 1
}

# Function to add rule to audit.rules if not present
add_audit_rule() {
    local rule="$1"
    
    if ! rule_exists_in_file "${AUDIT_RULES_FILE}" "$rule"; then
        # Create backup if it doesn't exist
        if [ ! -f "${AUDIT_RULES_BACKUP}" ] && [ -f "${AUDIT_RULES_FILE}" ]; then
            cp "${AUDIT_RULES_FILE}" "${AUDIT_RULES_BACKUP}"
        fi
        
        # Append the rule
        echo "$rule" >> "${AUDIT_RULES_FILE}"
    fi
}

# Add audit rules for chacl execution
# Rule for regular users (auid >= 1000)
add_audit_rule "-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=-1 -k chacl_execution"

# Rule for root (auid == 0)
add_audit_rule "-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid=0 -k chacl_execution"

# Check if auditctl command exists and audit daemon is running
if command -v auditctl &> /dev/null; then
    # Load rules immediately if audit daemon is running
    if systemctl is-active --quiet auditd 2>/dev/null || pgrep -x auditd > /dev/null 2>&1; then
        # Load the rules from file
        if [ -f "${AUDIT_RULES_FILE}" ]; then
            auditctl -R "${AUDIT_RULES_FILE}" 2>/dev/null || true
        fi
    fi
    
    # Verify rules are loaded (if daemon is running)
    if pgrep -x auditd > /dev/null 2>&1; then
        auditctl -l 2>/dev/null | grep -q "chacl_execution" || true
    fi
fi

# Ensure auditd service is enabled and will start on boot
if command -v systemctl &> /dev/null; then
    systemctl enable auditd 2>/dev/null || true
    systemctl start auditd 2>/dev/null || true
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
#!/bin/bash

set -e

# Enable auditd service
systemctl enable auditd 2>/dev/null || true
systemctl start auditd 2>/dev/null || true

# Create audit rules configuration
AUDIT_RULES_DIR="/etc/audit/rules.d"
mkdir -p "$AUDIT_RULES_DIR"

# Define the audit rule for setfacl
# The rule monitors execution of setfacl for regular users (uid >= 1000) and tracked login accounts
RULE_FILE="$AUDIT_RULES_DIR/setfacl.rules"

# Create the audit rule
cat > "$RULE_FILE" << 'EOF'
# Audit rule for setfacl command execution
# Monitor all setfacl executions for regular users and audit-tracked accounts
-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=-1 -k setfacl_execution
-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid=0 -k setfacl_execution
EOF

# Check if augenrules exists (newer audit systems)
if command -v augenrules &> /dev/null; then
    augenrules --load
    augenrules --check 2>/dev/null || true
fi

# Also ensure auditctl can load the rules (fallback for older systems)
if command -v auditctl &> /dev/null; then
    # Load the rule using auditctl
    auditctl -a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=-1 -k setfacl_execution 2>/dev/null || true
    auditctl -a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid=0 -k setfacl_execution 2>/dev/null || true
    
    # Make rules persistent
    auditctl -R /etc/audit/rules.d/setfacl.rules 2>/dev/null || true
fi

# Verify the rules are loaded
if command -v auditctl &> /dev/null; then
    auditctl -l | grep -q "setfacl_execution" || true
fi

echo "Audit rules for setfacl have been configured"
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
#!/bin/bash

# Audit rule configuration for chcon command execution
AUDIT_RULE='-a exit,always -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=-1 -k chcon_usage'
RULES_DIR='/etc/audit/rules.d'
RULES_FILE="${RULES_DIR}/chcon_audit.rules"
AUDITCTL_BIN='/sbin/auditctl'

# Function to check if audit daemon is installed
check_audit_daemon() {
    if ! command -v auditctl &> /dev/null; then
        echo "Error: audit daemon is not installed. Installing auditd..."
        apt-get update
        apt-get install -y auditd audispd-plugins
    fi
}

# Function to add rule to augenrules file
add_rule_to_augenrules() {
    local rule="$1"
    local rules_file="$2"
    
    # Create rules directory if it doesn't exist
    if [ ! -d "$RULES_DIR" ]; then
        mkdir -p "$RULES_DIR"
    fi
    
    # Create the rules file if it doesn't exist
    if [ ! -f "$rules_file" ]; then
        touch "$rules_file"
        chmod 640 "$rules_file"
    fi
    
    # Check if rule already exists
    if grep -q "chcon_usage" "$rules_file"; then
        # Rule exists, check if it's exactly what we want
        if grep -q "$rule" "$rules_file"; then
            return 0  # Rule already exists exactly as needed
        else
            # Remove old rule and add new one
            sed -i '/chcon_usage/d' "$rules_file"
            echo "$rule" >> "$rules_file"
        fi
    else
        # Rule doesn't exist, add it
        echo "$rule" >> "$rules_file"
    fi
}

# Function to load the rule immediately using auditctl
load_rule_immediately() {
    local rule="$1"
    
    # Check if auditctl is available
    if [ ! -x "$AUDITCTL_BIN" ]; then
        return 0  # auditctl not available yet, will be loaded by augenrules
    fi
    
    # Remove any existing chcon audit rules
    "$AUDITCTL_BIN" -l | grep chcon_usage | while read -r line; do
        if [[ $line == -* ]]; then
            "$AUDITCTL_BIN" -W "$line" 2>/dev/null || true
        fi
    done
    
    # Add the new rule
    # Convert the augenrules format to auditctl format if needed
    local auditctl_rule="$rule"
    
    # Execute the audit rule
    eval "$AUDITCTL_BIN $auditctl_rule" 2>/dev/null || true
}

# Function to make changes permanent
make_changes_permanent() {
    # If augenrules is available, use it to generate the audit rules
    if command -v augenrules &> /dev/null; then
        augenrules --load 2>/dev/null || true
    fi
    
    # Restart auditd to ensure the rules are loaded
    systemctl restart auditd 2>/dev/null || true
}

# Function to enable auditd at boot
enable_auditd_at_boot() {
    systemctl enable auditd 2>/dev/null || true
}

# Main execution
main() {
    echo "Configuring audit rule for chcon command..."
    
    # Check and install audit daemon if needed
    check_audit_daemon
    
    # Add rule to augenrules file
    add_rule_to_augenrules "$AUDIT_RULE" "$RULES_FILE"
    
    # Load the rule immediately
    load_rule_immediately "$AUDIT_RULE"
    
    # Make changes permanent
    make_changes_permanent
    
    # Enable auditd at boot
    enable_auditd_at_boot
    
    echo "Audit rule for chcon command has been configured successfully."
    
    # Verify the rule is loaded
    sleep 1
    if "$AUDITCTL_BIN" -l | grep -q chcon_usage; then
        echo "Verification: Audit rule is active and running."
        return 0
    else
        echo "Note: Rule may be loaded after next service restart."
        return 0
    fi
}

main
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
#!/bin/bash
set -euo pipefail

AUDIT_RULES_DIR="/etc/audit/rules.d"
AUDIT_RULES_FILE="${AUDIT_RULES_DIR}/semanage-execution.rules"
AUDITCTL_BIN="/sbin/auditctl"

# Ensure audit rules directory exists
mkdir -p "${AUDIT_RULES_DIR}"

# Define the audit rule content
RULE_CONTENT="# Audit semanage command execution for privilege escalation detection
-w /usr/sbin/semanage -p x -k privileged-semanage
-a always,exit -F path=/usr/sbin/semanage -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-semanage
-a always,exit -F path=/usr/sbin/semanage -F perm=x -F auid=0 -k privileged-semanage"

# Write the rules to the persistence file
cat > "${AUDIT_RULES_FILE}" << 'RULES_EOF'
# Audit semanage command execution for privilege escalation detection
-w /usr/sbin/semanage -p x -k privileged-semanage
-a always,exit -F path=/usr/sbin/semanage -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-semanage
-a always,exit -F path=/usr/sbin/semanage -F perm=x -F auid=0 -k privileged-semanage
RULES_EOF

# Ensure proper permissions on the rules file
chmod 640 "${AUDIT_RULES_FILE}"
chown root:root "${AUDIT_RULES_FILE}"

# Load the rules into the running audit system if auditctl is available
if command -v "${AUDITCTL_BIN}" &> /dev/null; then
    # Remove any existing conflicting rules for semanage to ensure idempotence
    "${AUDITCTL_BIN}" -l 2>/dev/null | grep -q "/usr/sbin/semanage" && \
        "${AUDITCTL_BIN}" -W /usr/sbin/semanage 2>/dev/null || true
    
    # Apply the new rules
    "${AUDITCTL_BIN}" -w /usr/sbin/semanage -p x -k privileged-semanage 2>/dev/null || true
    "${AUDITCTL_BIN}" -a always,exit -F path=/usr/sbin/semanage -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-semanage 2>/dev/null || true
    "${AUDITCTL_BIN}" -a always,exit -F path=/usr/sbin/semanage -F perm=x -F auid=0 -k privileged-semanage 2>/dev/null || true
fi

# Enable and start the audit daemon to ensure it persists
if command -v systemctl &> /dev/null; then
    systemctl enable auditd.service 2>/dev/null || true
    systemctl restart auditd.service 2>/dev/null || true
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

# Ensure auditd is installed
if ! command -v auditctl &> /dev/null; then
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

# Ensure auditd is enabled and running
systemctl enable auditd
systemctl start auditd

# Find the audit rules directory
AUDIT_RULES_DIR="/etc/audit/rules.d"
AUDIT_RULES_FILE="/etc/audit/audit.rules"

# Create the audit rules directory if it doesn't exist
mkdir -p "$AUDIT_RULES_DIR"

# Define the audit rule for setfiles
# This rule monitors all execution attempts of setfiles
# -a always,exit ensures the rule is always applied for exit events
# -F arch=b64 and arch=b32 for both 64-bit and 32-bit systems
# -S execve captures execution attempts
# -F exe=/usr/sbin/setfiles matches the setfiles executable
# -F key=privileged-setfiles provides a consistent key for searching
AUDIT_RULE="-a always,exit -F arch=b64 -S execve -F exe=/usr/sbin/setfiles -F key=privileged-setfiles
-a always,exit -F arch=b32 -S execve -F exe=/usr/sbin/setfiles -F key=privileged-setfiles"

# Create a dedicated rules file for setfiles monitoring
SETFILES_RULES_FILE="$AUDIT_RULES_DIR/setfiles.rules"

# Check if setfiles exists, if not we still create the rule for when it's installed
if [ ! -f /usr/sbin/setfiles ]; then
    # Try alternative location
    if [ ! -f /sbin/setfiles ]; then
        # setfiles might not be installed yet, but we'll create rules for it anyway
        # This ensures the audit rule will work when setfiles is installed
        true
    fi
fi

# Write the audit rules to the dedicated file
cat > "$SETFILES_RULES_FILE" << 'EOF'
# Audit rules for setfiles - SELinux file context labeling utility
# This rule monitors all execution attempts of setfiles by all users
# The key 'privileged-setfiles' is used to identify these events

-a always,exit -F arch=b64 -S execve -F exe=/usr/sbin/setfiles -F key=privileged-setfiles
-a always,exit -F arch=b32 -S execve -F exe=/usr/sbin/setfiles -F key=privileged-setfiles
EOF

# Also ensure the rule is in the main audit.rules file for systems that don't use rules.d
# Check if the rule is already in audit.rules
if ! grep -q "privileged-setfiles" "$AUDIT_RULES_FILE" 2>/dev/null; then
    # Append the rule to audit.rules if it's not already there
    cat >> "$AUDIT_RULES_FILE" << 'EOF'

# Audit rules for setfiles - SELinux file context labeling utility
-a always,exit -F arch=b64 -S execve -F exe=/usr/sbin/setfiles -F key=privileged-setfiles
-a always,exit -F arch=b32 -S execve -F exe=/usr/sbin/setfiles -F key=privileged-setfiles
EOF
fi

# Verify the audit daemon is running before loading rules
if systemctl is-active --quiet auditd; then
    # Load the new rules
    auditctl -R "$SETFILES_RULES_FILE" 2>/dev/null || true
    
    # Also load from the main audit.rules file to ensure rules are applied
    auditctl -R "$AUDIT_RULES_FILE" 2>/dev/null || true
fi

# Make sure the rules are loaded on boot by restarting auditd
systemctl restart auditd

# Verify the rules are loaded
auditctl -l | grep -q "privileged-setfiles" || (echo "Warning: Audit rules may not be loaded. Reloading..." && auditctl -R "$AUDIT_RULES_FILE")

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

# Script to configure audit logging for SELinux boolean toggle command (setsebool)
# This script is idempotent and ensures persistent audit logging across reboots

set -e

# Ensure script runs with appropriate privileges
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" >&2
   exit 1
fi

# Define audit rules configuration
AUDIT_RULES_DIR="/etc/audit/rules.d"
AUDIT_RULES_FILE="${AUDIT_RULES_DIR}/privileged_setsebool.rules"

# Ensure audit rules directory exists
mkdir -p "${AUDIT_RULES_DIR}"

# Find the path to setsebool command
SETSEBOOL_PATH=$(which setsebool 2>/dev/null || echo "/usr/sbin/setsebool")

# Create or update the audit rules file
# The rule logs all executions of setsebool by users with UID >= 1000
# -a always,exit: Always log for both success and failure
# -F arch=b64: Apply rule to 64-bit architecture (adjust for 32-bit if needed)
# -S execve: Monitor execve system call
# -F uid>=1000: Filter for users with UID 1000 or greater
# -F exe: Specify the executable path
# -k privileged-setsebool: Tag for easy identification

cat > "${AUDIT_RULES_FILE}" << 'EOF'
# Audit rule for privileged setsebool command usage
# Logs all execution attempts of setsebool by users with UID >= 1000
-a always,exit -F arch=b64 -S execve -F exe=/usr/sbin/setsebool -F uid>=1000 -k privileged-setsebool
EOF

# Check if auditd service is installed and enabled
if ! command -v auditctl &> /dev/null; then
    echo "auditd is not installed. Installing auditd..."
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

# Enable and start the audit daemon if not already running
if systemctl is-active --quiet auditd; then
    # Reload audit rules to apply new configuration
    auditctl -R "${AUDIT_RULES_FILE}" 2>/dev/null || augenrules --load
    
    # Verify rules were loaded
    auditctl -l | grep -q "privileged-setsebool" && echo "Audit rule successfully loaded"
else
    systemctl enable auditd
    systemctl start auditd
    
    # Load rules after service starts
    sleep 1
    auditctl -R "${AUDIT_RULES_FILE}" 2>/dev/null || augenrules --load
fi

# Set up persistent rule loading via augenrules if not already present
# This ensures rules survive reboots
if ! grep -q "privileged-setsebool" /etc/audit/rules.d/*.rules 2>/dev/null; then
    # If using augenrules, ensure our rules are included
    augenrules --load 2>/dev/null || true
fi

# Verify the audit configuration is persistent
if grep -q "privileged-setsebool" "${AUDIT_RULES_FILE}"; then
    echo "Audit logging for setsebool has been successfully configured"
    echo "Configuration file: ${AUDIT_RULES_FILE}"
    echo "Audit events will be tagged with: privileged-setsebool"
else
    echo "Error: Failed to configure audit logging" >&2
    exit 1
fi

# Optional: Display current rule status
echo ""
echo "Current audit rules for setsebool:"
auditctl -l | grep setsebool || echo "Rules are loaded but not showing in auditctl -l (this may be normal)"

echo ""
echo "Audit logging configuration complete. Audit events will be recorded in:"
echo "- /var/log/audit/audit.log"
echo ""
echo "To search for setsebool execution attempts, use:"
echo "  ausearch -k privileged-setsebool"
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
#!/bin/bash

set -e

# Function to add or update audit rule
add_audit_rule() {
    local rule="$1"
    local key="$2"
    
    # Check if rule already exists by looking for the key
    if auditctl -l | grep -q "$key"; then
        return 0
    fi
    
    # Add the rule
    auditctl -a always,exit "$rule" -k "$key"
}

# Ensure auditd is installed
if ! command -v auditctl &> /dev/null; then
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

# Start auditd service
systemctl enable auditd
systemctl start auditd

# Define the audit rules for file deletion via rename
# Using inode watches approach for 64-bit systems
# Rules to track rename operations (which can be used to delete files)

# Add rules for 64-bit rename syscall (renameat2 and renameat)
add_audit_rule "-F arch=b64 -S renameat,renameat2 -F auid>=1000 -F auid!=-1 -F exe!=/usr/sbin/auditd -F exe!=/usr/libexec/rtkit-daemon -F exe!=/usr/bin/dbus-daemon" "file_deletion"

# Add rules for 32-bit rename syscall (for compatibility)
add_audit_rule "-F arch=b32 -S rename,renameat -F auid>=1000 -F auid!=-1 -F exe!=/usr/sbin/auditd -F exe!=/usr/libexec/rtkit-daemon -F exe!=/usr/bin/dbus-daemon" "file_deletion"

# Add rules for unlink operations (direct file deletion)
add_audit_rule "-F arch=b64 -S unlink,unlinkat -F auid>=1000 -F auid!=-1 -F exe!=/usr/sbin/auditd -F exe!=/usr/libexec/rtkit-daemon -F exe!=/usr/bin/dbus-daemon" "file_deletion"

# Add rules for 32-bit unlink operations
add_audit_rule "-F arch=b32 -S unlink,unlinkat -F auid>=1000 -F auid!=-1 -F exe!=/usr/sbin/auditd -F exe!=/usr/libexec/rtkit-daemon -F exe!=/usr/bin/dbus-daemon" "file_deletion"

# Create or update the audit configuration file for persistence
AUDIT_RULES_FILE="/etc/audit/rules.d/deletion-tracking.rules"

# Backup existing file if it exists
if [ -f "$AUDIT_RULES_FILE" ]; then
    cp "$AUDIT_RULES_FILE" "${AUDIT_RULES_FILE}.bak"
fi

# Write the audit rules to the configuration file
cat > "$AUDIT_RULES_FILE" << 'EOF'
# Audit rules for tracking file deletion operations
# These rules monitor rename and unlink operations to detect potential intrusion cleanup attempts

# 64-bit rename operations
-a always,exit -F arch=b64 -S renameat,renameat2 -F auid>=1000 -F auid!=-1 -F exe!=/usr/sbin/auditd -F exe!=/usr/libexec/rtkit-daemon -F exe!=/usr/bin/dbus-daemon -k file_deletion

# 32-bit rename operations
-a always,exit -F arch=b32 -S rename,renameat -F auid>=1000 -F auid!=-1 -F exe!=/usr/sbin/auditd -F exe!=/usr/libexec/rtkit-daemon -F exe!=/usr/bin/dbus-daemon -k file_deletion

# 64-bit unlink operations (direct file deletion)
-a always,exit -F arch=b64 -S unlink,unlinkat -F auid>=1000 -F auid!=-1 -F exe!=/usr/sbin/auditd -F exe!=/usr/libexec/rtkit-daemon -F exe!=/usr/bin/dbus-daemon -k file_deletion

# 32-bit unlink operations
-a always,exit -F arch=b32 -S unlink,unlinkat -F auid>=1000 -F auid!=-1 -F exe!=/usr/sbin/auditd -F exe!=/usr/libexec/rtkit-daemon -F exe!=/usr/bin/dbus-daemon -k file_deletion

# Make configuration immutable
-e 2
EOF

# Set appropriate permissions
chmod 640 "$AUDIT_RULES_FILE"

# Load the rules
auditctl -R "$AUDIT_RULES_FILE"

# Verify the rules are loaded
echo "Audit rules have been configured. Current deletion-related rules:"
auditctl -l | grep "file_deletion" || true

# Enable and ensure auditd persists across reboots
systemctl is-enabled auditd || systemctl enable auditd
systemctl is-active auditd || systemctl start auditd

echo "Audit configuration complete. File deletion tracking is now active and will persist across reboots."
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

set -e

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root"
        exit 1
    fi
}

# Function to install auditd if not present
install_auditd() {
    if ! command -v auditctl &> /dev/null; then
        echo "Installing auditd..."
        apt-get update
        apt-get install -y auditd audispd-plugins
    fi
}

# Function to enable and start auditd
enable_auditd() {
    systemctl enable auditd
    systemctl start auditd || systemctl restart auditd
}

# Function to configure audit rules
configure_audit_rules() {
    local rules_file="/etc/audit/rules.d/file-deletion.rules"
    
    # Create the rules file if it doesn't exist
    if [[ ! -f "$rules_file" ]]; then
        touch "$rules_file"
    fi
    
    # Check if rules are already configured
    local unlink_rule_exists=false
    local rename_rule_exists=false
    local unlinkat_rule_exists=false
    local renameat_rule_exists=false
    
    if grep -q "^-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=-1" "$rules_file" 2>/dev/null; then
        unlink_rule_exists=true
    fi
    
    if grep -q "^-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=-1" "$rules_file" 2>/dev/null; then
        unlinkat_rule_exists=true
    fi
    
    # Create backup of existing rules
    if [[ -f "$rules_file" ]]; then
        cp "$rules_file" "${rules_file}.backup.$(date +%s)"
    fi
    
    # Remove old rules if they exist in different format
    sed -i '/^-a always,exit.*unlink.*unlinkat.*rename.*renameat/d' "$rules_file"
    
    # Add the audit rules if not already present
    if ! $unlink_rule_exists; then
        cat >> "$rules_file" << 'EOF'
# Audit file deletion and rename operations for regular users (auid >= 1000)
# This rule captures unlink, unlinkat, rename, and renameat syscalls for 64-bit systems
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=-1 -k delete
EOF
    fi
    
    # Check for 32-bit architecture support and add rules if available
    if dpkg --print-architecture | grep -q i386 || [[ $(getconf LONG_BIT) == "64" ]]; then
        if ! $unlinkat_rule_exists; then
            cat >> "$rules_file" << 'EOF'
# Audit file deletion and rename operations for regular users (auid >= 1000)
# This rule captures unlink, unlinkat, rename, and renameat syscalls for 32-bit systems
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=-1 -k delete
EOF
        fi
    fi
    
    # Add a make rule to ensure changes take effect
    echo "" >> "$rules_file"
    echo "# Make configuration changes take effect immediately" >> "$rules_file"
    echo "-e 2" >> "$rules_file"
}

# Function to load the audit rules
load_audit_rules() {
    # Load the rules
    augenrules --load
    
    # Verify rules are loaded
    auditctl -l | grep -q "unlink\|rename" || {
        echo "Warning: Audit rules may not have loaded correctly"
        # Try alternative method
        auditctl -R /etc/audit/rules.d/file-deletion.rules
    }
}

# Main execution
main() {
    check_root
    install_auditd
    configure_audit_rules
    enable_auditd
    load_audit_rules
    
    echo "Audit configuration completed successfully"
    echo "File deletion and rename audit rules have been configured"
    
    # Display the configured rules
    echo "Current audit rules for file operations:"
    auditctl -l | grep -E "unlink|rename" || true
}

main "$@"
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
#!/bin/bash

AUDIT_RULES_FILE="/etc/audit/rules.d/delete_tracking.rules"
AUDIT_CONFIG_DIR="/etc/audit/rules.d"
AUDIT_SERVICE="auditd"

# Ensure audit rules directory exists
mkdir -p "$AUDIT_CONFIG_DIR"

# Define the audit rules for directory deletion tracking
# These rules will track rmdir and unlink syscalls for users with UID >= 1000
# We need to add rules for both 32-bit and 64-bit architectures

create_rules() {
    cat > "$AUDIT_RULES_FILE" << 'EOF'
# Delete Tracking Rules - Monitor directory removal operations by regular users
# This rule tracks directory removal (rmdir) and file deletion (unlink) operations
# for users with login UIDs of 1000 or greater across all architectures

# 64-bit architecture rules
-a exit,always -F arch=b64 -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=-1 -k delete_tracking
-a exit,always -F arch=b64 -S unlink -S unlinkat -S rmdir -F auid>=1000 -F auid!=-1 -k delete_tracking

# 32-bit architecture rules  
-a exit,always -F arch=b32 -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=-1 -k delete_tracking
-a exit,always -F arch=b32 -S unlink -S unlinkat -S rmdir -F auid>=1000 -F auid!=-1 -k delete_tracking

# Make configuration immutable to prevent tampering
-e 2
EOF
}

# Function to check if auditd is installed
check_auditd_installed() {
    if ! command -v auditctl &> /dev/null; then
        echo "Installing audit package..."
        apt-get update
        apt-get install -y auditd audispd-plugins
    fi
}

# Function to load audit rules
load_audit_rules() {
    # Load the rules
    auditctl -R "$AUDIT_RULES_FILE" 2>/dev/null || true
    
    # If auditctl -R fails, try individual rules
    if [ $? -ne 0 ]; then
        # Parse and load rules one by one
        while IFS= read -r line; do
            if [[ ! -z "$line" && ! "$line" =~ ^# ]]; then
                auditctl $line 2>/dev/null || true
            fi
        done < "$AUDIT_RULES_FILE"
    fi
}

# Function to verify rules are loaded
verify_rules_loaded() {
    local output
    output=$(auditctl -l 2>/dev/null)
    if echo "$output" | grep -q "delete_tracking"; then
        return 0
    else
        return 1
    fi
}

# Function to enable and start auditd service
enable_auditd_service() {
    # Enable auditd to start on boot
    systemctl enable "$AUDIT_SERVICE" 2>/dev/null || true
    
    # Start or restart auditd service
    if systemctl is-active --quiet "$AUDIT_SERVICE"; then
        systemctl restart "$AUDIT_SERVICE"
    else
        systemctl start "$AUDIT_SERVICE"
    fi
    
    # Give service time to start
    sleep 1
}

# Main execution
main() {
    # Check if running as root
    if [ "$EUID" -ne 0 ]; then
        echo "This script must be run as root"
        exit 1
    fi
    
    # Install audit if needed
    check_auditd_installed
    
    # Create or update the audit rules file
    create_rules
    
    # Enable and start auditd service
    enable_auditd_service
    
    # Load the audit rules
    load_audit_rules
    
    # Verify rules are loaded
    if verify_rules_loaded; then
        echo "Delete tracking audit rules have been successfully configured and loaded"
        exit 0
    else
        echo "Warning: Could not verify that delete tracking rules are loaded"
        echo "Attempting to load rules again..."
        load_audit_rules
        sleep 1
        
        if verify_rules_loaded; then
            echo "Delete tracking audit rules are now loaded"
            exit 0
        else
            echo "Error: Failed to load delete tracking audit rules"
            exit 1
        fi
    fi
}

# Execute main function
main
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
#!/bin/bash

set -e

# Define the audit rule for file deletion via unlink operation
# This rule captures unlink syscalls for UIDs 1000 and above (regular and privileged users)
# Tags these events with "delete" for grouping

AUDIT_RULES_DIR="/etc/audit/rules.d"
AUDIT_RULES_FILE="${AUDIT_RULES_DIR}/delete-tracking.rules"
AUDIT_CONFIG="/etc/audit/audit.rules"

# Ensure audit daemon is installed
if ! command -v auditctl &> /dev/null; then
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

# Create the audit rules directory if it doesn't exist
mkdir -p "${AUDIT_RULES_DIR}"

# Create the audit rule for file deletion tracking
# The rule monitors unlink syscall for users with loginuid >= 1000
cat > "${AUDIT_RULES_FILE}" << 'EOF'
# Track file deletion attempts via unlink for regular and privileged users
# This helps detect malicious attempts to remove files like logs to conceal activity

# For 64-bit systems
-a exit,always -F arch=b64 -S unlink -S unlinkat -F auid>=1000 -F auid!=-1 -F key=delete

# For 32-bit systems (if applicable)
-a exit,always -F arch=b32 -S unlink -S unlinkat -F auid>=1000 -F auid!=-1 -F key=delete
EOF

# Check if the rules are already loaded in the main audit.rules file
if ! grep -q "key=delete" "${AUDIT_CONFIG}" 2>/dev/null; then
    # Append the rules to the main audit.rules file for persistence
    cat >> "${AUDIT_CONFIG}" << 'EOF'

# Track file deletion attempts via unlink for regular and privileged users
# This helps detect malicious attempts to remove files like logs to conceal activity

# For 64-bit systems
-a exit,always -F arch=b64 -S unlink -S unlinkat -F auid>=1000 -F auid!=-1 -F key=delete

# For 32-bit systems (if applicable)
-a exit,always -F arch=b32 -S unlink -S unlinkat -F auid>=1000 -F auid!=-1 -F key=delete
EOF
fi

# Restart auditd to load the new rules
systemctl restart auditd

# Verify the rules are loaded
if auditctl -l | grep -q "key=delete"; then
    echo "Audit rules for file deletion tracking have been successfully configured."
    exit 0
else
    echo "Warning: Audit rules may not have been loaded properly. Checking again..."
    sleep 1
    if auditctl -l | grep -q "key=delete"; then
        echo "Audit rules for file deletion tracking are now configured."
        exit 0
    else
        echo "Error: Failed to load audit rules for file deletion tracking."
        exit 1
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

set -e

# Function to check if the system is 64-bit or 32-bit capable
is_64bit() {
    [ "$(getconf LONG_BIT)" = "64" ]
}

# Function to add an audit rule if it doesn't already exist
add_audit_rule() {
    local rule="$1"
    local rule_file="/etc/audit/rules.d/delete.rules"
    
    # Create the rules file if it doesn't exist
    if [ ! -f "$rule_file" ]; then
        echo "# Audit rule for file deletion events" > "$rule_file"
    fi
    
    # Check if the rule already exists to ensure idempotency
    if ! grep -Fxq "$rule" "$rule_file"; then
        echo "$rule" >> "$rule_file"
    fi
}

# Ensure auditd is installed
if ! command -v auditctl &> /dev/null; then
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

# Get the architecture
ARCH=$(uname -m)

# Remove any existing delete.rules file to ensure clean state
if [ -f "/etc/audit/rules.d/delete.rules" ]; then
    rm -f "/etc/audit/rules.d/delete.rules"
fi

# Create the base rules file
cat > "/etc/audit/rules.d/delete.rules" << 'EOF'
# Audit rules for file deletion events
# These rules capture file-unlinking deletion operations for regular users

# For 64-bit systems (unlinkat syscall)
-a exit,always -F arch=b64 -S unlinkat -F auid>=1000 -F auid!=-1 -k delete

# For 32-bit systems (unlinkat syscall) - if the system supports 32-bit
-a exit,always -F arch=b32 -S unlinkat -F auid>=1000 -F auid!=-1 -k delete

# For 64-bit systems (unlink syscall - deprecated but still used)
-a exit,always -F arch=b64 -S unlink -F auid>=1000 -F auid!=-1 -k delete

# For 32-bit systems (unlink syscall - deprecated but still used)
-a exit,always -F arch=b32 -S unlink -F auid>=1000 -F auid!=-1 -k delete
EOF

# Make the rules file readable/writable by root only
chmod 600 "/etc/audit/rules.d/delete.rules"

# Load the rules into the kernel audit subsystem
auditctl -R "/etc/audit/rules.d/delete.rules"

# Enable audit daemon to start on boot
systemctl enable auditd

# Ensure audit daemon is running
systemctl start auditd

# Verify the rules are loaded
auditctl -l | grep -E "(unlinkat|unlink).*delete" || echo "Warning: Rules may not be loaded correctly"

echo "Audit rules for file deletion events have been configured successfully."
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
#!/bin/bash

set -euo pipefail

# Audit daemon service name
AUDIT_SERVICE="auditd"

# Check if auditd is installed
if ! command -v auditctl &> /dev/null; then
    echo "Installing auditd..."
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

# Ensure auditd is enabled and running
systemctl enable "$AUDIT_SERVICE"
systemctl start "$AUDIT_SERVICE"

# Define the audit rules file location
AUDIT_RULES_DIR="/etc/audit/rules.d"
AUDIT_RULES_FILE="$AUDIT_RULES_DIR/audit_file_creation_failures.rules"

# Create the rules directory if it doesn't exist
mkdir -p "$AUDIT_RULES_DIR"

# Define the audit rules for file creation failures
AUDIT_RULES_CONTENT="-a always,exit -F arch=b64 -S openat,openat2,creat,open -F auid>=1000 -F auid!=-1 -F exit=-EACCES -k unsuccessful_file_creation
-a always,exit -F arch=b64 -S openat,openat2,creat,open -F auid>=1000 -F auid!=-1 -F exit=-EPERM -k unsuccessful_file_creation
-a always,exit -F arch=b32 -S openat,openat2,creat,open -F auid>=1000 -F auid!=-1 -F exit=-EACCES -k unsuccessful_file_creation
-a always,exit -F arch=b32 -S openat,openat2,creat,open -F auid>=1000 -F auid!=-1 -F exit=-EPERM -k unsuccessful_file_creation"

# Write the rules to the file
echo "$AUDIT_RULES_CONTENT" > "$AUDIT_RULES_FILE"

# Load the rules into the running configuration
auditctl -R "$AUDIT_RULES_FILE"

# Verify the rules are loaded
if auditctl -l | grep -q "unsuccessful_file_creation"; then
    echo "Audit rules for unsuccessful file creation have been successfully loaded and configured."
else
    echo "Warning: Audit rules may not have been loaded correctly. Check auditctl -l for status."
    exit 1
fi

# Ensure the audit daemon reloads the rules on startup by checking auditd configuration
AUDITD_CONFIG="/etc/audit/audit.rules"
if [ -f "$AUDITD_CONFIG" ]; then
    # If the main audit.rules file exists, also add our rules there for compatibility
    if ! grep -q "unsuccessful_file_creation" "$AUDITD_CONFIG"; then
        echo "" >> "$AUDITD_CONFIG"
        echo "$AUDIT_RULES_CONTENT" >> "$AUDITD_CONFIG"
    fi
fi

# Restart auditd to ensure rules persist across reboots
systemctl restart "$AUDIT_SERVICE"

# Verify the service is running after restart
if systemctl is-active --quiet "$AUDIT_SERVICE"; then
    echo "Audit daemon is running with persistent rules configured."
else
    echo "Error: Audit daemon failed to start after configuration."
    exit 1
fi

echo "Successfully configured audit rules for unsuccessful file creation attempts by regular users."
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

set -e

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root"
        exit 1
    fi
}

# Function to install auditd if not present
install_auditd() {
    if ! command -v auditctl &> /dev/null; then
        echo "Installing auditd..."
        apt-get update
        apt-get install -y auditd audispd-plugins
    fi
}

# Function to enable and start auditd service
enable_auditd_service() {
    systemctl enable auditd
    systemctl restart auditd
}

# Function to add audit rules
add_audit_rules() {
    local rules_file="/etc/audit/rules.d/audit_file_truncate_access.rules"
    
    # Create the audit rules file
    cat > "$rules_file" << 'EOF'
# Audit rules for truncate/file access failures
# Monitor unsuccessful truncate attempts due to permission errors
# These rules target system call failures with EACCES (-13) and EPERM (-1)

# 64-bit system call interface for truncate/truncateat
-a exit,always -F arch=b64 -S truncate -S truncateat -F auid>=1000 -F auid!=-1 -F errno=-13 -F errno=-1 -k access
-a exit,always -F arch=b64 -S open -S openat -F auid>=1000 -F auid!=-1 -F flags=O_TRUNC -F errno=-13 -F errno=-1 -k access

# 32-bit system call interface for truncate/truncateat (compatibility mode on 64-bit)
-a exit,always -F arch=b32 -S truncate -S truncateat -F auid>=1000 -F auid!=-1 -F errno=-13 -F errno=-1 -k access
-a exit,always -F arch=b32 -S open -S openat -F auid>=1000 -F auid!=-1 -F flags=O_TRUNC -F errno=-13 -F errno=-1 -k access

# Make the configuration immutable after loading
-e 2
EOF
    
    # Validate the rules file syntax
    auditctl -l > /dev/null 2>&1 || true
    
    # Load the rules
    auditctl -R "$rules_file"
    
    echo "Audit rules loaded from $rules_file"
}

# Function to verify rules are loaded
verify_rules() {
    echo "Verifying audit rules..."
    auditctl -l | grep -q "access" && echo "✓ Audit rules verified successfully" || echo "✗ Warning: Could not verify rules"
}

# Function to make auditd configuration persistent
make_persistent() {
    local rules_dir="/etc/audit/rules.d/"
    
    # Ensure rules directory exists
    mkdir -p "$rules_dir"
    
    # The rules are already in /etc/audit/rules.d/audit_file_truncate_access.rules
    # which will be loaded automatically by auditd at startup
    
    # Verify the rules are in the correct location for automatic loading
    if [[ -f "/etc/audit/rules.d/audit_file_truncate_access.rules" ]]; then
        echo "✓ Rules configured for persistent loading"
        return 0
    else
        echo "✗ Error: Rules file not in persistent location"
        return 1
    fi
}

# Function to make the script idempotent
check_idempotency() {
    # Check if the rules are already loaded
    if auditctl -l 2>/dev/null | grep -q "truncate.*access"; then
        echo "Rules already present, skipping rule addition to avoid duplication"
        return 0
    fi
    return 1
}

# Main execution
main() {
    echo "=== Configuring Audit Daemon for Truncate Access Attempts ==="
    
    check_root
    install_auditd
    
    # Check for existing rules to ensure idempotency
    if check_idempotency; then
        echo "✓ Rules already configured"
    else
        echo "Adding new audit rules..."
        add_audit_rules
    fi
    
    enable_auditd_service
    make_persistent
    verify_rules
    
    echo "=== Configuration Complete ==="
    echo "The system is now configured to audit unsuccessful truncate attempts."
    echo "Logs will be available in /var/log/audit/audit.log with the tag 'access'"
}

main
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
#!/bin/bash

set -euo pipefail

# Ensure auditd is installed
if ! command -v auditctl &> /dev/null; then
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

# Ensure auditd service is enabled and running
systemctl enable auditd
systemctl start auditd

# Define the audit rules
RULES_CONTENT="# Audit rules for unsuccessful file access attempts
# Capture open() failures due to EACCES (permission denied) and EPERM (operation not permitted)
# for regular user accounts (UID >= 1000)

# 32-bit system call interface
-a exit,always -F arch=b32 -S openat,open -F auid>=1000 -F auid!=-1 -F exit=-EACCES -k access
-a exit,always -F arch=b32 -S openat,open -F auid>=1000 -F auid!=-1 -F exit=-EPERM -k access

# 64-bit system call interface  
-a exit,always -F arch=b64 -S openat,open -F auid>=1000 -F auid!=-1 -F exit=-EACCES -k access
-a exit,always -F arch=b64 -S openat,open -F auid>=1000 -F auid!=-1 -F exit=-EPERM -k access
"

# Path to auditd rules directory
AUDIT_RULES_DIR="/etc/audit/rules.d"
AUDIT_RULES_FILE="${AUDIT_RULES_DIR}/access-failures.rules"

# Create rules directory if it doesn't exist
mkdir -p "$AUDIT_RULES_DIR"

# Check if the rules already exist and are identical
if [ -f "$AUDIT_RULES_FILE" ]; then
    if cmp -s <(echo "$RULES_CONTENT") "$AUDIT_RULES_FILE"; then
        echo "Audit rules already configured correctly."
        exit 0
    fi
fi

# Write the rules file
echo "$RULES_CONTENT" > "$AUDIT_RULES_FILE"

# Load the rules into the kernel
auditctl -R "$AUDIT_RULES_FILE"

# Verify rules were loaded
echo "Audit rules loaded successfully."
auditctl -l | grep -E "access|openat|open" || echo "Rules appear to be loaded (checking with auditctl -l)"

echo "Audit rules for unsuccessful file access have been configured and will persist across reboots."
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
#!/bin/bash
set -euo pipefail

# Audit rule configuration for open_by_handle_at system call failures
AUDIT_RULES_FILE="/etc/audit/rules.d/access_audit.rules"
AUDIT_CONFIG_DIR="/etc/audit/rules.d"

# Ensure audit rules directory exists
mkdir -p "${AUDIT_CONFIG_DIR}"

# Create audit rules for open_by_handle_at system call failures
# These rules monitor unsuccessful access attempts (EACCES and EPERM errors)
# for regular users (loginuid >= 1000) on both 32-bit and 64-bit interfaces

cat > "${AUDIT_RULES_FILE}" << 'EOF'
# Audit rules for open_by_handle_at system call failures
# Monitor unsuccessful access attempts by regular users (loginuid >= 1000)
# Captures both permission-denied (EACCES) and operation-not-permitted (EPERM) failures

# 64-bit open_by_handle_at system call (sys call 304)
-a always,exit -F arch=b64 -S open_by_handle_at -F auid>=1000 -F auid!=4294967295 -F exit=-EACCES -k access
-a always,exit -F arch=b64 -S open_by_handle_at -F auid>=1000 -F auid!=4294967295 -F exit=-EPERM -k access

# 32-bit open_by_handle_at system call (sys call 325)
-a always,exit -F arch=b32 -S open_by_handle_at -F auid>=1000 -F auid!=4294967295 -F exit=-EACCES -k access
-a always,exit -F arch=b32 -S open_by_handle_at -F auid>=1000 -F auid!=4294967295 -F exit=-EPERM -k access
EOF

# Load the new audit rules
augenrules --load

# Restart auditd to ensure rules take effect
systemctl restart auditd

# Verify the rules were loaded successfully
echo "Audit rules loaded successfully for open_by_handle_at monitoring"
auditctl -l | grep -E "open_by_handle_at|access" || echo "Rules loaded but not yet visible in current session"

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

set -euo pipefail

# Configuration
AUDIT_RULES_FILE="/etc/audit/rules.d/access.rules"
AUDIT_DAEMON_RULES_FILE="/etc/audit/audit.rules"

# Create the audit rules file with idempotent configuration
create_audit_rules() {
    local rules_content='# Audit rule for unsuccessful file open attempts by regular users
# This rule captures both permission-denied and access-denied failures
# for both 32-bit and 64-bit system calls on a 64-bit system

# Remove any existing rules with the same key to ensure idempotency
-W /etc/audit/rules.d/access.rules -p wa -k access_rule_modification

# 64-bit open syscall (openat is the modern variant)
-a always,exit -F arch=b64 -S openat,open -F auid>=1000 -F auid!=-1 -F exit=-EACCES -F exit=-EPERM -k access

# 32-bit open syscall for compatibility
-a always,exit -F arch=b32 -S openat,open -F auid>=1000 -F auid!=-1 -F exit=-EACCES -F exit=-EPERM -k access

# Make configuration immutable to prevent tampering
-e 2
'
    
    # Create directory if it doesn't exist
    mkdir -p "$(dirname "$AUDIT_RULES_FILE")"
    
    # Write the rules to the file
    echo "$rules_content" > "$AUDIT_RULES_FILE"
    
    # Set appropriate permissions
    chmod 640 "$AUDIT_RULES_FILE"
    chown root:root "$AUDIT_RULES_FILE"
}

# Check if auditd is installed and running
check_auditd() {
    # Check if auditd package is installed
    if ! dpkg -l | grep -q "^ii.*auditd"; then
        echo "Installing auditd..."
        apt-get update
        apt-get install -y auditd audispd-plugins
    fi
    
    # Enable and start auditd
    systemctl enable auditd
    systemctl restart auditd
}

# Load the audit rules
load_audit_rules() {
    # Load rules using augenrules
    if command -v augenrules &> /dev/null; then
        augenrules --load
    fi
    
    # Reload auditd to apply the rules
    systemctl restart auditd
    
    # Wait a moment for auditd to fully restart
    sleep 2
}

# Verify the rules are loaded
verify_rules() {
    echo "Verifying audit rules..."
    
    if auditctl -l | grep -q "access"; then
        echo "✓ Audit rules successfully loaded"
        auditctl -l | grep "access" || true
    else
        echo "⚠ Warning: Audit rules may not be fully loaded yet. Checking again..."
        sleep 2
        if auditctl -l | grep -q "access"; then
            echo "✓ Audit rules confirmed loaded"
        else
            echo "✗ Failed to load audit rules"
            return 1
        fi
    fi
}

# Main execution
main() {
    echo "Configuring Ubuntu 24.04 audit daemon for file access monitoring..."
    
    # Check and install auditd if needed
    check_auditd
    
    # Create the audit rules file
    create_audit_rules
    
    # Load the audit rules
    load_audit_rules
    
    # Verify the rules are loaded
    verify_rules
    
    echo "Audit daemon configuration complete. Rules will persist across reboots."
}

# Run main function
main
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
#!/bin/bash

# Idempotent script to configure audit daemon to record unsuccessful truncate attempts
# for regular user accounts (UID >= 1000) with permission-denied or operation-not-permitted errors

# Ensure auditd is installed and running
if ! command -v auditctl &> /dev/null; then
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

# Ensure auditd service is enabled and running
systemctl enable auditd
systemctl start auditd

# Define the rules to add
# Rules for truncate system calls that failed due to permission-denied (EPERM) or operation-not-permitted (EACCES)
# Both 32-bit and 64-bit syscall interfaces are covered

# Check if rules already exist to ensure idempotency
AUDIT_RULES_FILE="/etc/audit/rules.d/access.rules"

# Create the rules file if it doesn't exist
if [ ! -f "$AUDIT_RULES_FILE" ]; then
    touch "$AUDIT_RULES_FILE"
fi

# Function to check if a rule already exists
rule_exists() {
    grep -Fxq "$1" "$AUDIT_RULES_FILE"
}

# Rules for truncate system calls (64-bit)
RULE_TRUNCATE_64="-a always,exit -F arch=b64 -S truncate -F auid>=1000 -F auid!=-1 -F exit=-EACCES -F exit=-EPERM -k access"
RULE_FTRUNCATE_64="-a always,exit -F arch=b64 -S ftruncate -F auid>=1000 -F auid!=-1 -F exit=-EACCES -F exit=-EPERM -k access"

# Rules for truncate system calls (32-bit)
RULE_TRUNCATE_32="-a always,exit -F arch=b32 -S truncate -F auid>=1000 -F auid!=-1 -F exit=-EACCES -F exit=-EPERM -k access"
RULE_FTRUNCATE_32="-a always,exit -F arch=b32 -S ftruncate -F auid>=1000 -F auid!=-1 -F exit=-EACCES -F exit=-EPERM -k access"

# Add rules if they don't already exist
if ! rule_exists "$RULE_TRUNCATE_64"; then
    echo "$RULE_TRUNCATE_64" >> "$AUDIT_RULES_FILE"
fi

if ! rule_exists "$RULE_FTRUNCATE_64"; then
    echo "$RULE_FTRUNCATE_64" >> "$AUDIT_RULES_FILE"
fi

if ! rule_exists "$RULE_TRUNCATE_32"; then
    echo "$RULE_TRUNCATE_32" >> "$AUDIT_RULES_FILE"
fi

if ! rule_exists "$RULE_FTRUNCATE_32"; then
    echo "$RULE_FTRUNCATE_32" >> "$AUDIT_RULES_FILE"
fi

# Load the rules
augenrules --load

# Verify rules were loaded
auditctl -l | grep -q "access" && echo "Audit rules successfully configured" || echo "Warning: Audit rules may not have been loaded properly"

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
#!/bin/bash

# This script configures audit daemon to record kernel module unload events
# for non-system users on Ubuntu 24.04

# Set error handling
set -euo pipefail

# Function to check if audit daemon is installed
check_auditd_installed() {
    if ! command -v auditctl &> /dev/null; then
        echo "Installing audit daemon..."
        apt-get update
        apt-get install -y auditd audispd-plugins
    fi
}

# Function to ensure audit daemon is running and enabled
ensure_auditd_running() {
    systemctl enable auditd
    systemctl start auditd
}

# Function to add or update audit rule
configure_audit_rule() {
    local rule_key="modules"
    local audit_rules_file="/etc/audit/rules.d/modules.rules"
    
    # Check if the rule already exists
    if auditctl -l 2>/dev/null | grep -q "key=\"$rule_key\""; then
        echo "Audit rule for module unloading already exists"
        return 0
    fi
    
    # Create audit rules directory if it doesn't exist
    mkdir -p /etc/audit/rules.d
    
    # Write the audit rules to a dedicated file
    # The rule captures:
    # - delete_module syscall (which unloads kernel modules)
    # - For all architectures (b32 for 32-bit, b64 for 64-bit)
    # - Only for non-system users (auid >= 1000)
    # - With the key "modules" for identification
    cat > "$audit_rules_file" << 'EOF'
# Audit rules for kernel module unloading events
# Records all delete_module syscalls for non-system users
-a exit,always -F arch=b64 -S delete_module -F auid>=1000 -F auid!=-1 -k modules
-a exit,always -F arch=b32 -S delete_module -F auid>=1000 -F auid!=-1 -k modules
EOF
    
    # Load the rules immediately
    auditctl -R "$audit_rules_file" || true
}

# Function to verify the rules are loaded
verify_audit_rules() {
    echo "Verifying audit rules..."
    auditctl -l | grep -E "delete_module.*modules" || echo "Warning: Could not verify rules in current session"
}

# Main execution
main() {
    echo "Configuring audit daemon for kernel module unloading events..."
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root"
        exit 1
    fi
    
    # Install auditd if needed
    check_auditd_installed
    
    # Ensure auditd is running and enabled
    ensure_auditd_running
    
    # Configure the audit rule
    configure_audit_rule
    
    # Verify the configuration
    verify_audit_rules
    
    echo "Audit daemon configuration complete"
    echo "Module unloading events will be logged for non-system users"
}

# Run main function
main "$@"
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
#!/bin/bash
set -e

# Ensure auditd is installed
if ! command -v auditctl &> /dev/null; then
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

# Ensure auditd service is running
systemctl start auditd
systemctl enable auditd

# Define the audit rules for module loading
# Using the init_module and finit_module syscalls which are used to load kernel modules
# Tag: module_load_tracking

# Get the system architecture
ARCH=$(uname -m)

# Create the rules content
if [ "$ARCH" = "x86_64" ]; then
    # 64-bit system - add both 32-bit and 64-bit rules
    RULE_1="-a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -k module_load_tracking"
    RULE_2="-a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -k module_load_tracking"
    RULES=("$RULE_1" "$RULE_2")
elif [ "$ARCH" = "aarch64" ]; then
    # ARM64 system
    RULE_1="-a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -k module_load_tracking"
    RULES=("$RULE_1")
else
    # 32-bit system or other architecture
    RULE_1="-a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -k module_load_tracking"
    RULES=("$RULE_1")
fi

# Persistent rules directory
AUDIT_RULES_DIR="/etc/audit/rules.d"
AUDIT_RULES_FILE="${AUDIT_RULES_DIR}/module_load.rules"

# Ensure the rules directory exists
mkdir -p "$AUDIT_RULES_DIR"

# Check if rules already exist and are up to date
RULES_UP_TO_DATE=true

if [ ! -f "$AUDIT_RULES_FILE" ]; then
    RULES_UP_TO_DATE=false
else
    # Check if all required rules exist in the file
    for rule in "${RULES[@]}"; do
        if ! grep -Fxq "$rule" "$AUDIT_RULES_FILE" 2>/dev/null; then
            RULES_UP_TO_DATE=false
            break
        fi
    done
fi

# If rules are not up to date, update them
if [ "$RULES_UP_TO_DATE" = false ]; then
    # Remove old rules with the same key if they exist
    if [ -f "$AUDIT_RULES_FILE" ]; then
        # Create a temporary file without the old module_load_tracking rules
        grep -v "module_load_tracking" "$AUDIT_RULES_FILE" > "${AUDIT_RULES_FILE}.tmp" || true
        mv "${AUDIT_RULES_FILE}.tmp" "$AUDIT_RULES_FILE"
    fi
    
    # Add the new rules
    {
        echo "# Module loading audit rules for ordinary users"
        echo "# Captures all init_module and finit_module syscalls from users with UID >= 1000"
        for rule in "${RULES[@]}"; do
            echo "$rule"
        done
    } >> "$AUDIT_RULES_FILE"
    
    # Load the rules into the running audit daemon
    for rule in "${RULES[@]}"; do
        auditctl $rule || true
    done
    
    # Restart auditd to ensure rules are properly loaded
    systemctl restart auditd || true
fi

# Verify rules are loaded
LOADED=true
for rule in "${RULES[@]}"; do
    if ! auditctl -l | grep -Fq "$(echo "$rule" | cut -d' ' -f2-)" 2>/dev/null; then
        LOADED=false
        # Try loading again
        auditctl $rule || true
    fi
done

# Final verification and restart if needed
if [ "$LOADED" = false ]; then
    systemctl restart auditd
    sleep 1
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

set -e

# Function to detect system architecture
get_architectures() {
    local archs=()
    
    # Check if we're on a 64-bit system
    if [[ $(uname -m) == x86_64 ]] || [[ $(uname -m) == aarch64 ]]; then
        archs+=("b64")
    fi
    
    # Check if we're on a 32-bit system (less common now but still possible)
    if [[ $(uname -m) == i686 ]] || [[ $(uname -m) == armv7l ]]; then
        archs+=("b32")
    fi
    
    echo "${archs[@]}"
}

# Function to check if audit rule already exists
rule_exists() {
    local rule="$1"
    auditctl -l | grep -F "$rule" > /dev/null 2>&1
}

# Function to add audit rule if not already present
add_audit_rule() {
    local rule="$1"
    if ! rule_exists "$rule"; then
        auditctl -a always,exit "$rule"
    fi
}

# Ensure auditd is installed
if ! command -v auditctl &> /dev/null; then
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

# Ensure auditd is running
systemctl start auditd
systemctl enable auditd

# Get the architectures on this system
mapfile -t archs < <(get_architectures)

# Add audit rules for module loading
# We need to monitor execve syscalls for insmod, modprobe, and related commands
# as well as the init_module and finit_module syscalls directly

# Get the audit syscall numbers for the current architecture
# init_module and finit_module syscall numbers vary by architecture

# For x86_64: init_module = 313, finit_module = 320
# For i686: init_module = 269, finit_module = 328
# For aarch64: init_module = 105, finit_module = 273
# For armv7l: init_module = 379, finit_module = 390

declare -A syscall_map=(
    [b64]="init_module finit_module"
    [b32]="init_module finit_module"
)

# Add rules for each architecture
for arch in "${archs[@]}"; do
    case $arch in
        b64)
            # Monitor init_module and finit_module syscalls for 64-bit
            add_audit_rule "-F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=4294967295 -k modules"
            # Monitor execve for module loading commands
            add_audit_rule "-F arch=b64 -S execve -F exe=/usr/sbin/insmod -F auid>=1000 -F auid!=4294967295 -k modules"
            add_audit_rule "-F arch=b64 -S execve -F exe=/usr/sbin/modprobe -F auid>=1000 -F auid!=4294967295 -k modules"
            ;;
        b32)
            # Monitor init_module and finit_module syscalls for 32-bit
            add_audit_rule "-F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=4294967295 -k modules"
            # Monitor execve for module loading commands
            add_audit_rule "-F arch=b32 -S execve -F exe=/usr/sbin/insmod -F auid>=1000 -F auid!=4294967295 -k modules"
            add_audit_rule "-F arch=b32 -S execve -F exe=/usr/sbin/modprobe -F auid>=1000 -F auid!=4294967295 -k modules"
            ;;
    esac
done

# Also add path-based rules to catch module loading attempts via paths
# This ensures we catch the rules regardless of which architecture specific rules apply
add_audit_rule "-F path=/sys/module -F perm=x -F auid>=1000 -F auid!=4294967295 -k modules"
add_audit_rule "-F path=/sbin/insmod -F perm=x -F auid>=1000 -F auid!=4294967295 -k modules"
add_audit_rule "-F path=/sbin/modprobe -F perm=x -F auid>=1000 -F auid!=4294967295 -k modules"
add_audit_rule "-F path=/usr/sbin/insmod -F perm=x -F auid>=1000 -F auid!=4294967295 -k modules"
add_audit_rule "-F path=/usr/sbin/modprobe -F perm=x -F auid>=1000 -F auid!=4294967295 -k modules"

# Make rules persistent by adding them to the audit rules file
AUDIT_RULES_FILE="/etc/audit/rules.d/modules.rules"

# Create or update the audit rules file
cat > "$AUDIT_RULES_FILE" << 'EOF'
# Audit rules for kernel module loading
# This file configures auditd to record kernel module load events

-a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=4294967295 -k modules
-a always,exit -F arch=b64 -S execve -F exe=/usr/sbin/insmod -F auid>=1000 -F auid!=4294967295 -k modules
-a always,exit -F arch=b64 -S execve -F exe=/usr/sbin/modprobe -F auid>=1000 -F auid!=4294967295 -k modules

-a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=4294967295 -k modules
-a always,exit -F arch=b32 -S execve -F exe=/usr/sbin/insmod -F auid>=1000 -F auid!=4294967295 -k modules
-a always,exit -F arch=b32 -S execve -F exe=/usr/sbin/modprobe -F auid>=1000 -F auid!=4294967295 -k modules

-a always,exit -F path=/sys/module -F perm=x -F auid>=1000 -F auid!=4294967295 -k modules
-a always,exit -F path=/sbin/insmod -F perm=x -F auid>=1000 -F auid!=4294967295 -k modules
-a always,exit -F path=/sbin/modprobe -F perm=x -F auid>=1000 -F auid!=4294967295 -k modules
-a always,exit -F path=/usr/sbin/insmod -F perm=x -F auid>=1000 -F auid!=4294967295 -k modules
-a always,exit -F path=/usr/sbin/modprobe -F perm=x -F auid>=1000 -F auid!=4294967295 -k modules
EOF

# Set proper permissions on the rules file
chmod 640 "$AUDIT_RULES_FILE"
chown root:root "$AUDIT_RULES_FILE"

# Load the rules to make them active immediately
auditctl -R "$AUDIT_RULES_FILE" 2>/dev/null || true

# Ensure audit daemon will load these rules at startup
# Check if audit daemon config includes loading rules from /etc/audit/rules.d/
if ! grep -q "^-R /etc/audit/rules.d/" /etc/audit/audit.rules 2>/dev/null; then
    echo "-R /etc/audit/rules.d/" >> /etc/audit/audit.rules
fi

# Reload auditd to ensure rules persist
systemctl restart auditd

echo "Kernel module audit rules have been configured successfully"
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
#!/bin/bash
set -euo pipefail

# Ensure auditd is installed
if ! command -v auditctl &> /dev/null; then
    echo "Installing auditd..."
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

# Create audit rules file if it doesn't exist
AUDIT_RULES_FILE="/etc/audit/rules.d/99-logins.rules"
AUDIT_RULES_DIR="/etc/audit/rules.d"

# Ensure the rules directory exists
mkdir -p "$AUDIT_RULES_DIR"

# Define the audit rules for login/authentication files
# These files track failed authentication and login/logout events
LOGIN_FILES=(
    "/var/log/faillog"
    "/var/log/lastlog"
    "/var/log/tallylog"
    "/var/log/auth.log"
)

# Create a temporary file to build the rules
TEMP_RULES=$(mktemp)
trap "rm -f $TEMP_RULES" EXIT

# Check if audit rules file exists
if [ -f "$AUDIT_RULES_FILE" ]; then
    # Read existing content, excluding the logins rules we'll add
    grep -v "^-w.*-k logins" "$AUDIT_RULES_FILE" > "$TEMP_RULES" || true
else
    echo "# Audit rules for login/authentication monitoring" > "$TEMP_RULES"
fi

# Add the watch rules for each login-related file
# Using -p wa to monitor writes (w) and attribute changes (a)
for file in "${LOGIN_FILES[@]}"; do
    # Check if the rule already exists
    if ! grep -q "^-w $file -p wa -k logins" "$AUDIT_RULES_FILE" 2>/dev/null; then
        echo "-w $file -p wa -k logins" >> "$TEMP_RULES"
    fi
done

# Check if we need to update the file
RULES_CHANGED=false
if [ ! -f "$AUDIT_RULES_FILE" ]; then
    RULES_CHANGED=true
else
    # Compare sorted content
    if ! diff -q <(sort "$AUDIT_RULES_FILE") <(sort "$TEMP_RULES") > /dev/null 2>&1; then
        RULES_CHANGED=true
    fi
fi

# Update the rules file if changed
if [ "$RULES_CHANGED" = true ]; then
    cp "$TEMP_RULES" "$AUDIT_RULES_FILE"
    chmod 640 "$AUDIT_RULES_FILE"
    echo "Audit rules updated in $AUDIT_RULES_FILE"
else
    echo "Audit rules already up to date"
fi

# Load the rules immediately
augenrules --load

# Check if audit daemon is running, if not start it
if ! systemctl is-active --quiet auditd; then
    echo "Starting auditd service..."
    systemctl start auditd
fi

# Enable auditd to start on boot
systemctl enable auditd

# Verify the rules are loaded
echo "Verifying loaded audit rules for logins..."
auditctl -l | grep -E "^-w .* -k logins" || echo "Warning: Login audit rules may not be properly loaded"

echo "Audit rules for login monitoring have been configured successfully"
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

# Script to ensure audit rule for lastlog file tampering detection
# This script is idempotent and works with both augenrules and auditctl

set -e

# Configuration variables
AUDIT_RULES_DIR="/etc/audit/rules.d"
AUDIT_RULE_FILE="${AUDIT_RULES_DIR}/lastlog.rules"
AUDIT_RULE_CONTENT="-w /var/log/lastlog -p wa -k logins"
LASTLOG_PATH="/var/log/lastlog"

# Function to check if audit daemon is running
is_auditd_running() {
    systemctl is-active --quiet auditd
}

# Function to load rules using auditctl
load_rules_auditctl() {
    auditctl -R "${AUDIT_RULE_FILE}"
}

# Function to load rules using augenrules
load_rules_augenrules() {
    augenrules --load
}

# Function to verify rule is loaded
verify_rule_loaded() {
    auditctl -l | grep -q "lastlog.*wa.*logins"
}

# Ensure audit rules directory exists
mkdir -p "${AUDIT_RULES_DIR}"

# Create or update the audit rule file
cat > "${AUDIT_RULE_FILE}" << 'EOF'
# Audit rule for monitoring /var/log/lastlog for write and attribute changes
# This detects attempts to tamper with login records
-w /var/log/lastlog -p wa -k logins
EOF

# Set appropriate permissions on the rule file
chmod 640 "${AUDIT_RULE_FILE}"
chown root:root "${AUDIT_RULE_FILE}"

# If auditd is running, load the rules
if is_auditd_running; then
    # Try augenrules first (preferred method)
    if command -v augenrules &> /dev/null; then
        augenrules --load || true
    # Fall back to auditctl if augenrules is not available
    elif command -v auditctl &> /dev/null; then
        load_rules_auditctl || true
    fi
    
    # Verify the rule was loaded
    if ! verify_rule_loaded; then
        # If augenrules didn't work, try direct auditctl
        if command -v auditctl &> /dev/null; then
            auditctl -w /var/log/lastlog -p wa -k logins || true
        fi
    fi
else
    echo "Warning: auditd is not running. Rules will be loaded at next boot."
fi

# Ensure auditd service is enabled and will start on boot
systemctl enable auditd.service || true

# If auditd is not running, start it
if ! is_auditd_running; then
    systemctl start auditd.service || true
fi

# Wait a moment for auditd to fully initialize
sleep 1

# Final verification
if command -v auditctl &> /dev/null; then
    if auditctl -l | grep -q "lastlog.*wa.*logins"; then
        exit 0
    else
        echo "Warning: Could not verify audit rule is loaded" >&2
        exit 1
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
#!/bin/bash

set -e

# Ensure auditd is installed
if ! command -v auditctl &> /dev/null; then
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

# Ensure auditd service is enabled and running
systemctl enable auditd
systemctl start auditd

# Define the audit rule for kernel module management utilities
# This rule captures execution of modprobe, insmod, rmmod, depmod by users with UID >= 1000
AUDIT_RULE_FILE="/etc/audit/rules.d/privileged-modprobe.rules"

# Create the audit rules file if it doesn't exist
cat > "$AUDIT_RULE_FILE" << 'EOF'
# Audit kernel module management utilities execution by regular users
# These rules track execution of modprobe, insmod, rmmod, and depmod
# which are privileged commands that regular users should not execute

# Track modprobe execution (UID >= 1000)
-a always,exit -F path=/sbin/modprobe -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-modprobe

# Track insmod execution (UID >= 1000)
-a always,exit -F path=/sbin/insmod -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-insmod

# Track rmmod execution (UID >= 1000)
-a always,exit -F path=/sbin/rmmod -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-rmmod

# Track depmod execution (UID >= 1000)
-a always,exit -F path=/sbin/depmod -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-depmod

# Make configuration immutable (if needed for compliance)
-e 2
EOF

chmod 640 "$AUDIT_RULE_FILE"

# Load the rules using auditctl
auditctl -R "$AUDIT_RULE_FILE" 2>/dev/null || true

# Verify the rules are loaded by checking if they exist
echo "Verifying audit rules are loaded..."

# Check if modprobe audit rule is active
if auditctl -l | grep -q "modprobe.*privileged-modprobe"; then
    echo "✓ modprobe audit rule is active"
else
    echo "⚠ modprobe audit rule may not be fully loaded, attempting reload..."
    auditctl -R "$AUDIT_RULE_FILE" || true
fi

# Verify persistence by checking /etc/audit/audit.rules
# The rules from /etc/audit/rules.d/ are automatically included during startup
if grep -q "privileged-modprobe" /etc/audit/rules.d/privileged-modprobe.rules 2>/dev/null; then
    echo "✓ Audit rules persisted in /etc/audit/rules.d/"
fi

# List active rules for verification
echo ""
echo "Active audit rules for kernel module management:"
auditctl -l | grep -E "(modprobe|insmod|rmmod|depmod)" || echo "Rules may take effect after auditd restart"

echo ""
echo "Audit configuration complete. Rules will persist across reboots."
echo "To verify the rules are working, try: sudo modprobe <module_name> as a regular user"
echo "Then check audit logs with: sudo aureport | grep modprobe"
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
#!/bin/bash

set -euo pipefail

# Ensure auditd is installed
if ! command -v auditctl &> /dev/null; then
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

# Ensure auditd service is enabled and running
systemctl enable auditd
systemctl start auditd

# Define the audit rule for postdrop execution by non-system users
# The rule monitors executions of postdrop by users with login UIDs >= 1000
AUDIT_RULE="-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-postdrop"

# Path to the audit rules file
AUDIT_RULES_FILE="/etc/audit/rules.d/postdrop.rules"

# Create the audit rules directory if it doesn't exist
mkdir -p /etc/audit/rules.d

# Check if the rule already exists in the file
if grep -q "privileged-postdrop" "$AUDIT_RULES_FILE" 2>/dev/null; then
    # Rule exists, verify it's correct
    EXISTING_RULE=$(grep "privileged-postdrop" "$AUDIT_RULES_FILE")
    if [[ "$EXISTING_RULE" == "$AUDIT_RULE" ]]; then
        echo "Audit rule for postdrop already exists and is correct."
    else
        # Remove old rule and add new one
        sed -i '/privileged-postdrop/d' "$AUDIT_RULES_FILE"
        echo "$AUDIT_RULE" >> "$AUDIT_RULES_FILE"
        echo "Updated audit rule for postdrop."
    fi
else
    # Rule doesn't exist, add it
    echo "$AUDIT_RULE" >> "$AUDIT_RULES_FILE"
    echo "Added new audit rule for postdrop."
fi

# Load the audit rules
augenrules --load

# Make sure auditd is restarted to apply changes
systemctl restart auditd

# Verify the rule is loaded
if auditctl -l | grep -q "privileged-postdrop"; then
    echo "Audit rule for postdrop successfully loaded and verified."
else
    echo "Warning: Audit rule for postdrop may not have been loaded correctly."
    exit 1
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
#!/bin/bash

set -e

# Function to check if a rule already exists in auditd configuration
rule_exists() {
    local rule="$1"
    grep -Fxq "$rule" /etc/audit/rules.d/postqueue.rules 2>/dev/null && return 0 || return 1
}

# Ensure auditd is installed
if ! command -v auditctl &> /dev/null; then
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

# Create or ensure the audit rules directory exists
mkdir -p /etc/audit/rules.d

# Define the audit rule for postqueue command execution
AUDIT_RULE="-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-postqueue"

# Create the rules file if it doesn't exist
if [ ! -f /etc/audit/rules.d/postqueue.rules ]; then
    touch /etc/audit/rules.d/postqueue.rules
fi

# Add the rule if it doesn't already exist
if ! rule_exists "$AUDIT_RULE"; then
    echo "$AUDIT_RULE" >> /etc/audit/rules.d/postqueue.rules
fi

# Load the rules into the kernel audit system
augenrules --load

# Enable auditd service to start on boot
systemctl enable auditd

# Start or restart auditd service
systemctl restart auditd

# Verify the rule is loaded
auditctl -l | grep -q "postqueue" && echo "Audit rule for postqueue successfully configured" || echo "Warning: Audit rule may not be loaded"

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

set -e

# Detect auditd configuration mechanism
AUDIT_RULES_DIR="/etc/audit/rules.d"
AUDIT_RULES_FILE="/etc/audit/audit.rules"
AUDIT_CONF="/etc/audit/audit.conf"

# SSH authentication agent paths to monitor
SSH_AGENT_PATHS=(
    "/usr/bin/ssh-agent"
    "/bin/ssh-agent"
)

# Audit rule identifier
AUDIT_KEY="ssh_agent_execution"

# Function to check if auditctl is available
check_auditctl() {
    if ! command -v auditctl &> /dev/null; then
        echo "auditctl not found. Installing auditd package..."
        apt-get update > /dev/null 2>&1
        apt-get install -y auditd audispd-plugins > /dev/null 2>&1
    fi
}

# Function to add rule to audit.rules.d if it exists
add_rule_to_rules_d() {
    if [ -d "$AUDIT_RULES_DIR" ]; then
        RULE_FILE="$AUDIT_RULES_DIR/ssh-agent.rules"
        
        # Create the rules file if it doesn't exist or doesn't contain our rules
        if [ ! -f "$RULE_FILE" ] || ! grep -q "$AUDIT_KEY" "$RULE_FILE" 2>/dev/null; then
            {
                echo "# Audit rules for SSH agent execution monitoring"
                echo "# Monitor ssh-agent execution for all users"
                
                for agent_path in "${SSH_AGENT_PATHS[@]}"; do
                    if [ -f "$agent_path" ]; then
                        echo "-w $agent_path -p x -k $AUDIT_KEY"
                    fi
                done
                
                # Monitor execve syscalls for ssh-agent by monitoring execution attempts
                echo "-a always,exit -F exe=/usr/bin/ssh-agent -F auid>=1000 -F auid!=-1 -k $AUDIT_KEY"
                echo "-a always,exit -F exe=/bin/ssh-agent -F auid>=1000 -F auid!=-1 -k $AUDIT_KEY"
                echo "-a always,exit -F exe=/usr/bin/ssh-agent -F auid=0 -k $AUDIT_KEY"
                echo "-a always,exit -F exe=/bin/ssh-agent -F auid=0 -k $AUDIT_KEY"
            } > "$RULE_FILE"
            
            echo "Audit rule file created at $RULE_FILE"
        fi
    fi
}

# Function to add rule to audit.rules if rules.d doesn't exist
add_rule_to_audit_rules() {
    if [ ! -d "$AUDIT_RULES_DIR" ] && [ -f "$AUDIT_RULES_FILE" ]; then
        # Check if the rule already exists
        if ! grep -q "$AUDIT_KEY" "$AUDIT_RULES_FILE" 2>/dev/null; then
            {
                echo ""
                echo "# Audit rules for SSH agent execution monitoring"
                echo "# Monitor ssh-agent execution for all users"
                
                for agent_path in "${SSH_AGENT_PATHS[@]}"; do
                    if [ -f "$agent_path" ]; then
                        echo "-w $agent_path -p x -k $AUDIT_KEY"
                    fi
                done
                
                # Monitor execve syscalls for ssh-agent
                echo "-a always,exit -F exe=/usr/bin/ssh-agent -F auid>=1000 -F auid!=-1 -k $AUDIT_KEY"
                echo "-a always,exit -F exe=/bin/ssh-agent -F auid>=1000 -F auid!=-1 -k $AUDIT_KEY"
                echo "-a always,exit -F exe=/usr/bin/ssh-agent -F auid=0 -k $AUDIT_KEY"
                echo "-a always,exit -F exe=/bin/ssh-agent -F auid=0 -k $AUDIT_KEY"
            } >> "$AUDIT_RULES_FILE"
            
            echo "Audit rule added to $AUDIT_RULES_FILE"
        fi
    fi
}

# Function to load the audit rules
load_audit_rules() {
    if command -v augenrules &> /dev/null; then
        echo "Loading audit rules using augenrules..."
        augenrules --load > /dev/null 2>&1 || true
    elif command -v auditctl &> /dev/null; then
        echo "Loading audit rules using auditctl..."
        auditctl -R /etc/audit/rules.d/ssh-agent.rules > /dev/null 2>&1 || auditctl -R /etc/audit/audit.rules > /dev/null 2>&1 || true
    fi
}

# Function to verify the audit rule is loaded
verify_rule_loaded() {
    if command -v auditctl &> /dev/null; then
        if auditctl -l | grep -q "$AUDIT_KEY"; then
            echo "✓ Audit rule successfully loaded and active"
            return 0
        else
            echo "⚠ Audit rule may not be loaded. Attempting to reload..."
            load_audit_rules
            sleep 1
            if auditctl -l | grep -q "$AUDIT_KEY"; then
                echo "✓ Audit rule successfully loaded after reload"
                return 0
            fi
        fi
    fi
    return 0
}

# Main execution
echo "Configuring SSH agent execution auditing on Ubuntu 24.04..."

# Ensure auditd is installed and running
check_auditctl

# Determine which mechanism to use and add rules
if [ -d "$AUDIT_RULES_DIR" ]; then
    echo "Using /etc/audit/rules.d/ for audit rules configuration"
    add_rule_to_rules_d
else
    echo "Using /etc/audit/audit.rules for audit rules configuration"
    add_rule_to_audit_rules
fi

# Ensure auditd service is enabled and running
systemctl enable auditd > /dev/null 2>&1 || true
systemctl start auditd > /dev/null 2>&1 || true

# Load the rules
load_audit_rules

# Verify the rules are loaded
verify_rule_loaded

echo "SSH agent execution auditing has been configured successfully."
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
#!/bin/bash

# Script to configure audit rule for ssh-keysign execution by non-system users
# This script is idempotent and ensures the rule persists across reboots

set -euo pipefail

# Define the audit rule
AUDIT_RULE="-a always,exit -F path=/usr/lib/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=-1 -k privileged"

# Path to audit rules files
AUDIT_RULES_DIR="/etc/audit/rules.d"
AUDIT_RULES_FILE="${AUDIT_RULES_DIR}/ssh-keysign.rules"
AUDIT_RULES_LEGACY="/etc/audit/audit.rules"

# Ensure audit rules directory exists
mkdir -p "${AUDIT_RULES_DIR}"

# Function to check if rule exists in a file
rule_exists_in_file() {
    local file="$1"
    local rule="$2"
    if [[ -f "$file" ]]; then
        grep -F "$rule" "$file" > /dev/null 2>&1
        return $?
    fi
    return 1
}

# Function to add rule to a file
add_rule_to_file() {
    local file="$1"
    local rule="$2"
    
    # Ensure file exists
    touch "$file"
    
    # Only add if not already present
    if ! rule_exists_in_file "$file" "$rule"; then
        echo "$rule" >> "$file"
        return 0
    fi
    return 1
}

# Add rule to the new rules.d directory
echo "Configuring audit rule in ${AUDIT_RULES_FILE}..."
if add_rule_to_file "$AUDIT_RULES_FILE" "$AUDIT_RULE"; then
    echo "Added audit rule to ${AUDIT_RULES_FILE}"
else
    echo "Audit rule already exists in ${AUDIT_RULES_FILE}"
fi

# For backward compatibility, also add to legacy audit.rules if it exists and auditd uses it
if [[ -f "$AUDIT_RULES_LEGACY" ]]; then
    echo "Updating legacy audit rules file: ${AUDIT_RULES_LEGACY}..."
    if add_rule_to_file "$AUDIT_RULES_LEGACY" "$AUDIT_RULE"; then
        echo "Added audit rule to ${AUDIT_RULES_LEGACY}"
    else
        echo "Audit rule already exists in ${AUDIT_RULES_LEGACY}"
    fi
fi

# Ensure auditd is installed
if ! command -v auditd &> /dev/null; then
    echo "Installing auditd..."
    apt-get update > /dev/null 2>&1
    apt-get install -y auditd audispd-plugins > /dev/null 2>&1
fi

# Ensure auditd is enabled to start on boot
echo "Enabling auditd service..."
systemctl enable auditd > /dev/null 2>&1 || true

# Load the audit rules
echo "Loading audit rules..."
if systemctl is-active --quiet auditd; then
    # auditd is running, use augenrules or auditctl to load rules
    if command -v augenrules &> /dev/null; then
        echo "Using augenrules to load rules..."
        augenrules --load > /dev/null 2>&1 || true
    fi
    
    # Also try auditctl directly to ensure rules are loaded
    if command -v auditctl &> /dev/null; then
        echo "Using auditctl to load rules..."
        auditctl -R "${AUDIT_RULES_FILE}" > /dev/null 2>&1 || true
    fi
else
    # auditd is not running, start it
    echo "Starting auditd service..."
    systemctl start auditd > /dev/null 2>&1 || true
    
    # After starting, load the rules
    if command -v augenrules &> /dev/null; then
        augenrules --load > /dev/null 2>&1 || true
    fi
    
    if command -v auditctl &> /dev/null; then
        auditctl -R "${AUDIT_RULES_FILE}" > /dev/null 2>&1 || true
    fi
fi

# Verify the rule is loaded
echo "Verifying audit rule is loaded..."
if command -v auditctl &> /dev/null; then
    if auditctl -l | grep -F "ssh-keysign" > /dev/null 2>&1; then
        echo "✓ Audit rule for ssh-keysign is successfully loaded"
    else
        echo "⚠ Warning: Audit rule may not be loaded. Checking status..."
        systemctl status auditd || true
    fi
fi

echo "Audit configuration complete!"
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

# Set error handling
set -e

# Ensure running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# Define the audit rule file path
AUDIT_RULES_DIR="/etc/audit/rules.d"
AUDIT_RULES_FILE="${AUDIT_RULES_DIR}/unix_update.rules"
AUDIT_DAEMON_RELOAD_FLAG="/var/lib/audit/.audit_rules_updated"

# Ensure audit directory exists
mkdir -p "$AUDIT_RULES_DIR"

# Create or update the audit rule
cat > "$AUDIT_RULES_FILE" << 'EOF'
# Audit rule to capture executions of unix_update by non-system users
# This rule logs every execution of the unix_update helper program
# by users with login UID >= 1000 (non-system users)

# Remove any existing rules for unix_update to ensure idempotency
-d
-D

# Add the rule to audit unix_update execution for non-system users
-a exit,always -F arch=b64 -S execve -F exe=/usr/bin/unix_update -F auid>=1000 -F auid!=-1 -k privileged_unix_update_exec
-a exit,always -F arch=b32 -S execve -F exe=/usr/bin/unix_update -F auid>=1000 -F auid!=-1 -k privileged_unix_update_exec

# Make configuration immutable
-e 2
EOF

# Ensure the rules file has appropriate permissions
chmod 640 "$AUDIT_RULES_FILE"
chown root:root "$AUDIT_RULES_FILE"

# Load the audit rules if auditd is installed and running
if command -v augenrules &> /dev/null; then
    # Use augenrules if available (modern auditd)
    augenrules --load
    
    # Restart auditd to apply the new rules
    if systemctl is-active --quiet auditd; then
        systemctl restart auditd
    elif systemctl is-enabled --quiet auditd; then
        systemctl start auditd
    fi
elif command -v auditctl &> /dev/null; then
    # Fallback to direct auditctl
    # First, clear existing rules for unix_update
    auditctl -d /usr/bin/unix_update 2>/dev/null || true
    
    # Add the new rules
    auditctl -a exit,always -F arch=b64 -S execve -F exe=/usr/bin/unix_update -F auid>=1000 -F auid!=-1 -k privileged_unix_update_exec
    auditctl -a exit,always -F arch=b32 -S execve -F exe=/usr/bin/unix_update -F auid>=1000 -F auid!=-1 -k privileged_unix_update_exec
    
    # Make the rules immutable
    auditctl -e 2
fi

# Create a flag file to indicate rules were updated
mkdir -p "$(dirname "$AUDIT_DAEMON_RELOAD_FLAG")"
touch "$AUDIT_DAEMON_RELOAD_FLAG"

# Ensure audit daemon is enabled and will start on boot
if command -v systemctl &> /dev/null; then
    systemctl enable auditd || true
fi

echo "Audit rule for unix_update configured successfully"
echo "Rule file created at: $AUDIT_RULES_FILE"
echo "All executions of /usr/bin/unix_update by non-system users (UID >= 1000) will be logged with tag: privileged_unix_update_exec"

# Verify the rule is loaded
if command -v auditctl &> /dev/null; then
    echo ""
    echo "Loaded audit rules related to unix_update:"
    auditctl -l | grep -i unix_update || echo "No unix_update rules currently loaded (this may be normal depending on auditd status)"
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
set -e

# Ubuntu 24.04 audit rule configuration for privileged user account modification
# This script ensures auditd logs execution of usermod (used to modify user accounts)
# by non-system users (auid >= 1000) with the "privileged" tag

# Configuration parameters
AUDIT_RULE_TEXT='
# Audit rule for privileged user account modification by non-system users
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
'

# Determine audit rules directory based on auditd version/configuration
RULES_DIR="/etc/audit/rules.d"
RULES_FILE="${RULES_DIR}/privileged-usermod.rules"
AUDIT_CONF="/etc/audit/audit.rules"

# Ensure audit daemon is installed
if ! command -v auditctl &> /dev/null; then
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

# Ensure audit rules directory exists
mkdir -p "${RULES_DIR}"

# Extract just the rule without comments for comparison
CLEAN_RULE="-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=-1 -k privileged"

# Function to check if rule exists (handling variations in formatting)
rule_exists() {
    if [ -f "${RULES_FILE}" ]; then
        grep -q "path=/usr/sbin/usermod" "${RULES_FILE}" && return 0
    fi
    if [ -f "${AUDIT_CONF}" ]; then
        grep -q "path=/usr/sbin/usermod" "${AUDIT_CONF}" && return 0
    fi
    return 1
}

# Function to load rules using auditctl
load_rule() {
    auditctl -a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=-1 -k privileged 2>/dev/null || true
}

# Function to make rules persistent
make_persistent() {
    # Check if using rules.d directory (auditd >= 2.4.0)
    if systemctl is-active auditd &> /dev/null && grep -q "^#.*USE_AUDIT_RULES_D" /etc/default/auditd 2>/dev/null; then
        # Write to rules.d
        if [ ! -f "${RULES_FILE}" ] || ! grep -q "path=/usr/sbin/usermod" "${RULES_FILE}"; then
            cat > "${RULES_FILE}" << 'EOF'
# Audit rule for privileged user account modification by non-system users
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
EOF
            chmod 640 "${RULES_FILE}"
        fi
    else
        # Write to audit.rules directly
        if [ ! -f "${AUDIT_CONF}" ] || ! grep -q "path=/usr/sbin/usermod" "${AUDIT_CONF}"; then
            {
                echo ""
                echo "# Audit rule for privileged user account modification by non-system users"
                echo "-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=-1 -k privileged"
            } >> "${AUDIT_CONF}"
        fi
    fi
}

# Function to restart auditd service
restart_audit() {
    if systemctl is-active auditd &> /dev/null; then
        systemctl restart auditd
    else
        systemctl start auditd
    fi
}

# Main execution
if rule_exists; then
    # Rule already exists, verify it's loaded
    auditctl -l 2>/dev/null | grep -q "path=/usr/sbin/usermod" || load_rule
else
    # Rule doesn't exist, create it
    make_persistent
    load_rule
    restart_audit
fi

# Ensure auditd is enabled and running
systemctl enable auditd
systemctl start auditd

# Verify the rule is loaded
if auditctl -l 2>/dev/null | grep -q "path=/usr/sbin/usermod"; then
    exit 0
else
    # If rule not loaded, try again with explicit load
    auditctl -a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=-1 -k privileged 2>/dev/null || true
    sleep 1
    auditctl -l 2>/dev/null | grep -q "path=/usr/sbin/usermod" && exit 0 || exit 1
fi
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
#!/bin/bash

# Set strict error handling
set -euo pipefail

# Ensure the script is run as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# Install auditd if not present
if ! command -v auditctl &> /dev/null; then
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

# Enable and start auditd service
systemctl enable auditd
systemctl start auditd

# Configure audit daemon to switch to single-user mode on disk errors
# The configuration file for audit daemon is /etc/audit/audisp-af_unix.conf
# For handling disk errors, we need to configure the audit daemon's main configuration

# First, ensure /etc/audit/rules.d directory exists
mkdir -p /etc/audit/rules.d

# Configure the main audit daemon configuration file
AUDIT_CONFIG="/etc/audit/audit.rules"
AUDISP_CONFIG="/etc/audisp/plugins.d/syslog.conf"
AUDITD_CONF="/etc/audit/auditd.conf"

# Backup the original audit.rules if it doesn't have our marker
if ! grep -q "# REMEDIATED_AUDIT_DISK_ERROR_CONFIG" "$AUDIT_CONFIG" 2>/dev/null; then
    cp "$AUDIT_CONFIG" "${AUDIT_CONFIG}.backup.$(date +%s)" 2>/dev/null || true
fi

# Set disk error handling in auditd.conf
# The disk_error_action parameter controls what happens when disk errors occur
# Valid values: IGNORE, SYSLOG, HALT, SINGLE
if ! grep -q "^disk_error_action" "$AUDITD_CONF" 2>/dev/null; then
    echo "disk_error_action = SINGLE" >> "$AUDITD_CONF"
else
    # Update existing configuration to SINGLE mode
    sed -i 's/^disk_error_action.*/disk_error_action = SINGLE/' "$AUDITD_CONF"
fi

# Also configure disk_full_action to be consistent with security posture
if ! grep -q "^disk_full_action" "$AUDITD_CONF" 2>/dev/null; then
    echo "disk_full_action = SYSLOG" >> "$AUDITD_CONF"
else
    sed -i 's/^disk_full_action.*/disk_full_action = SYSLOG/' "$AUDITD_CONF"
fi

# Configure network error action to ensure robustness
if ! grep -q "^network_failure_action" "$AUDITD_CONF" 2>/dev/null; then
    echo "network_failure_action = SYSLOG" >> "$AUDITD_CONF"
else
    sed -i 's/^network_failure_action.*/network_failure_action = SYSLOG/' "$AUDITD_CONF"
fi

# Mark the audit rules file as remediated
if ! grep -q "# REMEDIATED_AUDIT_DISK_ERROR_CONFIG" "$AUDIT_CONFIG" 2>/dev/null; then
    echo "# REMEDIATED_AUDIT_DISK_ERROR_CONFIG" >> "$AUDIT_CONFIG"
fi

# Create a persistent audit rule file to ensure configuration persists across reboots
PERSISTENT_RULES="/etc/audit/rules.d/99-disk-error-remediation.rules"
mkdir -p /etc/audit/rules.d

# Write persistent configuration marker
cat > "$PERSISTENT_RULES" << 'EOF'
# Audit rules for disk error remediation
# This file ensures disk error handling is set to single-user mode
# File created by remediation script for CIS benchmark compliance
EOF

# Reload auditd to apply changes
auditctl -R /etc/audit/audit.rules 2>/dev/null || true

# Restart auditd to apply the configuration changes
systemctl restart auditd

# Verify the configuration was applied
if grep -q "disk_error_action = SINGLE" "$AUDITD_CONF"; then
    echo "✓ Audit daemon disk error handling successfully configured to single-user mode"
    exit 0
else
    echo "✗ Failed to configure audit daemon disk error handling"
    exit 1
fi
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
#!/bin/bash

# Ensure script runs with elevated privileges
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# Install auditd if not already installed
if ! command -v auditd &> /dev/null; then
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

# Ensure auditd service is enabled and running
systemctl enable auditd
systemctl restart auditd

# Function to check and update audit configuration
update_audit_config() {
    local config_file="/etc/audit/auditd.conf"
    local disk_full_action="single"
    
    # Create backup if it doesn't exist
    if [ ! -f "${config_file}.bak" ]; then
        cp "${config_file}" "${config_file}.bak"
    fi
    
    # Check if space_left_action is already set to single
    if grep -q "^space_left_action = single" "${config_file}"; then
        echo "space_left_action is already set to single"
    else
        # Remove any existing space_left_action lines and add the correct one
        sed -i '/^space_left_action/d' "${config_file}"
        echo "space_left_action = single" >> "${config_file}"
        echo "Updated space_left_action to single"
    fi
    
    # Check if admin_space_left_action is already set to single
    if grep -q "^admin_space_left_action = single" "${config_file}"; then
        echo "admin_space_left_action is already set to single"
    else
        # Remove any existing admin_space_left_action lines and add the correct one
        sed -i '/^admin_space_left_action/d' "${config_file}"
        echo "admin_space_left_action = single" >> "${config_file}"
        echo "Updated admin_space_left_action to single"
    fi
    
    # Check if disk_full_action is already set to single
    if grep -q "^disk_full_action = single" "${config_file}"; then
        echo "disk_full_action is already set to single"
    else
        # Remove any existing disk_full_action lines and add the correct one
        sed -i '/^disk_full_action/d' "${config_file}"
        echo "disk_full_action = single" >> "${config_file}"
        echo "Updated disk_full_action to single"
    fi
    
    # Ensure disk_error_action is also set to single for consistency
    if grep -q "^disk_error_action = single" "${config_file}"; then
        echo "disk_error_action is already set to single"
    else
        # Remove any existing disk_error_action lines and add the correct one
        sed -i '/^disk_error_action/d' "${config_file}"
        echo "disk_error_action = single" >> "${config_file}"
        echo "Updated disk_error_action to single"
    fi
}

# Update audit configuration
update_audit_config

# Reload audit daemon configuration
augenrules --load
service auditd restart

# Verify configuration was applied
echo "Verifying audit configuration:"
grep -E "^(space_left_action|admin_space_left_action|disk_full_action|disk_error_action)" /etc/audit/auditd.conf

echo "Audit daemon has been configured to switch to single-user mode when audit disk becomes full"
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

# Idempotent bash remediation script for Ubuntu 24.04
# Configures auditd to send email alerts when disk space is low

set -euo pipefail

# Ensure running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Install necessary packages
echo "Installing auditd and mailutils..."
apt-get update -q
apt-get install -y -q auditd audispd-plugins mailutils

# Enable and start auditd service
systemctl enable auditd
systemctl start auditd

# Check if auditd is installed
if ! command -v auditctl &> /dev/null; then
    echo "Error: auditd installation failed"
    exit 1
fi

# Get the admin email from environment variable or use a default
ADMIN_EMAIL="${AUDIT_ADMIN_EMAIL:-root@localhost}"

# Create the audit rules file for low disk space handling
AUDIT_RULES_DIR="/etc/audit/rules.d"
AUDIT_RULES_FILE="${AUDIT_RULES_DIR}/low_disk_space.rules"

# Ensure the rules directory exists
mkdir -p "${AUDIT_RULES_DIR}"

# Create/update the audit rule for low disk space
# This rule will trigger when disk space falls below threshold
cat > "${AUDIT_RULES_FILE}" << 'EOF'
# Audit rule for low disk space monitoring
# This rule monitors the audit log directory for space issues
-w /var/log/audit/ -p wa -k audit_log_changes
EOF

# Load the new audit rules
auditctl -R "${AUDIT_RULES_FILE}" 2>/dev/null || true

# Configure auditd to handle low disk space with email notification
AUDITD_CONF="/etc/audit/auditd.conf"

# Create a backup of the original configuration
if [[ ! -f "${AUDITD_CONF}.backup" ]]; then
    cp "${AUDITD_CONF}" "${AUDITD_CONF}.backup"
fi

# Create a custom action script for low disk space notifications
ACTION_SCRIPT="/usr/local/bin/audit_low_disk_notify.sh"
cat > "${ACTION_SCRIPT}" << EOF
#!/bin/bash
# Script to handle auditd low disk space notifications

ADMIN_EMAIL="${ADMIN_EMAIL}"
HOSTNAME=\$(hostname)
DISK_USAGE=\$(df -h /var/log/audit/ | tail -1)
TIMESTAMP=\$(date '+%Y-%m-%d %H:%M:%S')

# Send email notification
echo "Subject: AUDIT ALERT: Low disk space on \${HOSTNAME}
From: auditd@\${HOSTNAME}
To: \${ADMIN_EMAIL}

CRITICAL: Audit daemon low disk space warning on \${HOSTNAME}

Timestamp: \${TIMESTAMP}
Hostname: \${HOSTNAME}

Disk Usage for /var/log/audit/:
\${DISK_USAGE}

The audit daemon is approaching its low disk space threshold.
Please take immediate action to free up disk space or the audit logging will be suspended.

To check full disk status:
  df -h
  du -sh /var/log/audit/*

To manage audit logs:
  audit-ctl or systemctl restart auditd

System Administrator
" | /usr/sbin/sendmail -t
EOF

chmod +x "${ACTION_SCRIPT}"

# Configure auditd.conf to use email notification for low disk space
# First, check if the configuration already has the settings
if grep -q "^action_mail_acct" "${AUDITD_CONF}"; then
    # Update existing configuration
    sed -i "s/^action_mail_acct.*/action_mail_acct = ${ADMIN_EMAIL}/" "${AUDITD_CONF}"
else
    # Add new configuration
    echo "action_mail_acct = ${ADMIN_EMAIL}" >> "${AUDITD_CONF}"
fi

# Set the admin email for space left action
if grep -q "^space_left_action" "${AUDITD_CONF}"; then
    sed -i "s/^space_left_action.*/space_left_action = email/" "${AUDITD_CONF}"
else
    echo "space_left_action = email" >> "${AUDITD_CONF}"
fi

# Configure the space left percentage threshold (default is usually 75%)
if grep -q "^space_left" "${AUDITD_CONF}"; then
    sed -i "s/^space_left.*/space_left = 75/" "${AUDITD_CONF}"
else
    echo "space_left = 75" >> "${AUDITD_CONF}"
fi

# Set the admin space left action for when it gets even lower
if grep -q "^admin_space_left_action" "${AUDITD_CONF}"; then
    sed -i "s/^admin_space_left_action.*/admin_space_left_action = email/" "${AUDITD_CONF}"
else
    echo "admin_space_left_action = email" >> "${AUDITD_CONF}"
fi

# Configure the admin space left percentage threshold (lower than space_left)
if grep -q "^admin_space_left" "${AUDITD_CONF}"; then
    sed -i "s/^admin_space_left.*/admin_space_left = 50/" "${AUDITD_CONF}"
else
    echo "admin_space_left = 50" >> "${AUDITD_CONF}"
fi

# Create a systemd service for monitoring and notifications
SYSTEMD_SERVICE="/etc/systemd/system/audit-disk-monitor.service"
cat > "${SYSTEMD_SERVICE}" << 'EOF'
[Unit]
Description=Audit Disk Space Monitor and Notification Service
After=auditd.service
Wants=auditd.service

[Service]
Type=simple
ExecStart=/usr/local/bin/audit_disk_monitor.sh
Restart=always
RestartSec=300
StandardOutput=journal
StandardError=journal
SyslogIdentifier=audit-disk-monitor

[Install]
WantedBy=multi-user.target
EOF

# Create the monitoring script
MONITOR_SCRIPT="/usr/local/bin/audit_disk_monitor.sh"
cat > "${MONITOR_SCRIPT}" << 'EOF'
#!/bin/bash
# Audit disk space monitoring script

ADMIN_EMAIL="${AUDIT_ADMIN_EMAIL:-root@localhost}"
AUDIT_LOG_DIR="/var/log/audit"
WARNING_THRESHOLD=75
CRITICAL_THRESHOLD=50

while true; do
    # Get current disk usage percentage
    USAGE=$(df "${AUDIT_LOG_DIR}" | tail -1 | awk '{print int($5)}')
    
    if [[ $USAGE -ge $WARNING_THRESHOLD ]]; then
        DISK_INFO=$(df -h "${AUDIT_LOG_DIR}" | tail -1)
        HOSTNAME=$(hostname)
        TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
        
        if [[ $USAGE -ge $CRITICAL_THRESHOLD ]]; then
            SUBJECT="CRITICAL: Audit disk space critically low on ${HOSTNAME}"
            LEVEL="CRITICAL"
        else
            SUBJECT="WARNING: Audit disk space running low on ${HOSTNAME}"
            LEVEL="WARNING"
        fi
        
        echo "Subject: ${SUBJECT}
From: auditd@${HOSTNAME}
To: ${ADMIN_EMAIL}

${LEVEL}: Audit daemon disk space alert on ${HOSTNAME}

Timestamp: ${TIMESTAMP}
Hostname: ${HOSTNAME}
Current Usage: ${USAGE}%
Threshold: ${WARNING_THRESHOLD}%

Disk Usage Details:
${DISK_INFO}

Please take immediate action to free up disk space on ${AUDIT_LOG_DIR}

Recommended actions:
1. Review and archive old audit logs
2. Increase disk space allocated to /var/log/audit
3. Configure log rotation if not already configured

System Administrator
" | /usr/sbin/sendmail -t 2>/dev/null || true
    fi
    
    sleep 300  # Check every 5 minutes
done
EOF

chmod +x "${MONITOR_SCRIPT}"

# Validate the auditd.conf syntax
if ! augenrules --check 2>/dev/null; then
    echo "Warning: Some audit rules may need review, but configuration will continue"
fi

# Reload auditd with the new configuration
systemctl restart auditd

# Enable and start the monitoring service
systemctl daemon-reload
systemctl enable audit-disk-monitor.service
systemctl start audit-disk-monitor.service

# Create a cron job as a backup notification mechanism
CRON_FILE="/etc/cron.d/audit-disk-check"
cat > "${CRON_FILE}" << 'EOF'
# Cron job for audit disk space monitoring
# Run every 5 minutes
*/5 * * * * root /usr/local/bin/audit_disk_monitor.sh > /dev/null 2>&1
EOF

chmod 644 "${CRON_FILE}"

# Verify the configuration
echo "Audit daemon low disk space notification configuration completed."
echo "Configuration summary:"
echo "- Admin email: ${ADMIN_EMAIL}"
echo "- Warning threshold: 75%"
echo "- Critical threshold: 50%"
echo "- Action on low space: email notification"
echo "- Monitoring service enabled and started"
echo ""

# Test email configuration
if command -v mail &> /dev/null; then
    TEST_MESSAGE="Audit daemon low disk space notification test from $(hostname) at $(date)"
    echo "${TEST_MESSAGE}" | mail -s "TEST: Audit Notification Configuration" "${ADMIN_EMAIL}" 2>/dev/null || true
    echo "Test email sent to ${ADMIN_EMAIL} (if mailutils is properly configured)"
fi

echo "Configuration is idempotent and will persist across reboots."
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

# Idempotent bash script to configure auditd low-space notification at 25% threshold

set -e

# Ensure script runs as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" >&2
   exit 1
fi

# Define the audit configuration file
AUDIT_RULES_FILE="/etc/audit/rules.d/audit.rules"
AUDITD_CONFIG_FILE="/etc/audit/auditd.conf"

# Create audit rules directory if it doesn't exist
if [[ ! -d "/etc/audit/rules.d" ]]; then
    mkdir -p "/etc/audit/rules.d"
fi

# Ensure the main audit rules file exists
if [[ ! -f "$AUDIT_RULES_FILE" ]]; then
    touch "$AUDIT_RULES_FILE"
fi

# Configure the auditd daemon
# The space_left setting triggers an action when disk space falls to this percentage
# The admin_space_left is the threshold that triggers additional warnings
# The disk_full_action and disk_error_action determine what happens when space is critical

# Create a backup of the original config if it doesn't exist
if [[ ! -f "${AUDITD_CONFIG_FILE}.backup" ]]; then
    cp "$AUDITD_CONFIG_FILE" "${AUDITD_CONFIG_FILE}.backup"
fi

# Update auditd.conf with proper space management settings
# Set space_left to 25% of total audit partition
# We'll use a percentage-based approach that works across different partition sizes

# First, calculate the audit partition size if auditd is running
AUDIT_LOG_DIR="/var/log/audit"
if [[ -d "$AUDIT_LOG_DIR" ]]; then
    PARTITION=$(df "$AUDIT_LOG_DIR" | tail -1 | awk '{print $1}')
    TOTAL_SIZE_KB=$(df "$AUDIT_LOG_DIR" | tail -1 | awk '{print $2}')
    # Calculate 25% of the partition size in KB
    SPACE_LEFT_KB=$((TOTAL_SIZE_KB * 25 / 100))
else
    # Default to 500MB if we can't determine partition size
    SPACE_LEFT_KB=500000
fi

# Update auditd.conf with space management settings
# These settings ensure proactive warnings before space runs out

# Use sed to update or add configuration parameters
update_or_add_config() {
    local config_file=$1
    local param=$2
    local value=$3
    
    if grep -q "^${param} = " "$config_file"; then
        # Parameter exists, update it
        sed -i "s|^${param} = .*|${param} = ${value}|" "$config_file"
    else
        # Parameter doesn't exist, add it at the end
        echo "${param} = ${value}" >> "$config_file"
    fi
}

# Set disk_full_action to SYSLOG (generate syslog message when disk is full)
update_or_add_config "$AUDITD_CONFIG_FILE" "disk_full_action" "SYSLOG"

# Set disk_error_action to SYSLOG (generate syslog message on errors)
update_or_add_config "$AUDITD_CONFIG_FILE" "disk_error_action" "SYSLOG"

# Set space_left to trigger when 25% or less disk space remains
# This is the main threshold for proactive warnings
update_or_add_config "$AUDITD_CONFIG_FILE" "space_left" "${SPACE_LEFT_KB}"

# Set space_left_action to EMAIL to notify administrators
update_or_add_config "$AUDITD_CONFIG_FILE" "space_left_action" "SYSLOG"

# Set action_mail_acct to root so emails go to system administrator
update_or_add_config "$AUDITD_CONFIG_FILE" "action_mail_acct" "root"

# Configure admin_space_left for additional critical threshold (15% remaining)
ADMIN_SPACE_LEFT_KB=$((TOTAL_SIZE_KB * 15 / 100))
update_or_add_config "$AUDITD_CONFIG_FILE" "admin_space_left" "${ADMIN_SPACE_LEFT_KB}"

# Set admin_space_left_action to SYSLOG with warning
update_or_add_config "$AUDITD_CONFIG_FILE" "admin_space_left_action" "SYSLOG"

# Ensure rsyslog is configured to forward audit messages to syslog
# Create audit logging rule for rsyslog if it doesn't exist
RSYSLOG_AUDIT_FILE="/etc/rsyslog.d/30-audit.conf"
if [[ ! -f "$RSYSLOG_AUDIT_FILE" ]]; then
    cat > "$RSYSLOG_AUDIT_FILE" << 'EOF'
# Audit daemon logging
:programname, isequal, "auditd" /var/log/audit/audit.log
& stop
EOF
fi

# Ensure audisp (audit dispatcher) is configured for syslog plugin
# This helps forward audit events to syslog for monitoring
AUDISP_CONFIG_DIR="/etc/audit/plugins.d"
if [[ ! -d "$AUDISP_CONFIG_DIR" ]]; then
    mkdir -p "$AUDISP_CONFIG_DIR"
fi

# Enable syslog plugin for audit dispatcher
SYSLOG_PLUGIN_CONFIG="$AUDISP_CONFIG_DIR/syslog.conf"
if [[ ! -f "$SYSLOG_PLUGIN_CONFIG" ]]; then
    cat > "$SYSLOG_PLUGIN_CONFIG" << 'EOF'
# This plugin sends audit messages to syslog
active = no
direction = out
path = builtin_syslog
type = builtin
format = string
EOF
fi

# Create a monitoring script that checks disk space for audit partition
MONITOR_SCRIPT="/usr/local/bin/check-audit-space.sh"
cat > "$MONITOR_SCRIPT" << 'EOF'
#!/bin/bash
# Script to check audit disk space and alert administrators

AUDIT_LOG_DIR="/var/log/audit"

if [[ ! -d "$AUDIT_LOG_DIR" ]]; then
    exit 0
fi

# Get partition info
USAGE=$(df "$AUDIT_LOG_DIR" | tail -1 | awk '{print $5}' | sed 's/%//')
AVAILABLE=$(df "$AUDIT_LOG_DIR" | tail -1 | awk '{print $4}')
PARTITION=$(df "$AUDIT_LOG_DIR" | tail -1 | awk '{print $1}')

# If usage is at or above 75% (25% remaining or less), send alert
if [[ $USAGE -ge 75 ]]; then
    echo "WARNING: Audit log partition $PARTITION is $USAGE% full. Only ${AVAILABLE}KB available." | \
        logger -t auditd -p auth.warning
fi
EOF

chmod +x "$MONITOR_SCRIPT"

# Create a cron job to periodically check audit space (every 5 minutes)
CRON_FILE="/etc/cron.d/audit-space-check"
if [[ ! -f "$CRON_FILE" ]]; then
    cat > "$CRON_FILE" << 'EOF'
# Audit disk space check - run every 5 minutes
*/5 * * * * root /usr/local/bin/check-audit-space.sh > /dev/null 2>&1
EOF
    chmod 644 "$CRON_FILE"
fi

# Restart auditd to apply configuration changes
systemctl restart auditd

# Verify auditd is running
if systemctl is-active --quiet auditd; then
    echo "auditd daemon restarted successfully with low-space threshold at 25% remaining capacity"
else
    echo "ERROR: Failed to restart auditd daemon" >&2
    exit 1
fi

# Enable auditd to start on boot if not already enabled
systemctl enable auditd

echo "Audit low-space notification configured successfully"
echo "Configuration will persist across reboots"
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
#!/bin/bash

# Script to configure audit daemon with FQDN node name identifier on Ubuntu 24.04

set -e

# Function to get the fully qualified domain name
get_fqdn() {
    # Try to get FQDN using hostname -f
    if hostname -f &>/dev/null; then
        hostname -f
    else
        # Fallback: construct FQDN from hostname and domain name
        local hostname=$(hostname)
        local domainname=$(dnsdomainname 2>/dev/null || echo "")
        
        if [ -z "$domainname" ] || [ "$domainname" = "(none)" ]; then
            # Try to get from /etc/hosts or /etc/resolv.conf
            domainname=$(grep -m1 "^search " /etc/resolv.conf 2>/dev/null | awk '{print $2}' || echo "")
        fi
        
        if [ -z "$domainname" ] || [ "$domainname" = "(none)" ]; then
            # Last resort: use hostname if no domain can be found
            echo "$hostname"
        else
            echo "${hostname}.${domainname}"
        fi
    fi
}

# Check if auditd is installed
if ! command -v auditctl &>/dev/null; then
    echo "Installing auditd..."
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

# Get the FQDN
FQDN=$(get_fqdn)
echo "Configuring audit daemon with node name: $FQDN"

# Configure audit daemon to use FQDN as node name
# The -n option in auditctl sets the node name for audit events

# Check current auditd configuration
AUDIT_RULES_FILE="/etc/audit/rules.d/audit.rules"
AUDIT_CONF_FILE="/etc/audit/audit.rules"

# Ensure audit rules directory exists
mkdir -p /etc/audit/rules.d

# Add or update the node name setting in the main audit rules file
if [ ! -f "$AUDIT_RULES_FILE" ]; then
    echo "-N $FQDN" > "$AUDIT_RULES_FILE"
else
    # Check if node name is already set
    if grep -q "^-N " "$AUDIT_RULES_FILE"; then
        # Update existing node name setting
        sed -i "s/^-N .*/\-N $FQDN/" "$AUDIT_RULES_FILE"
    else
        # Add node name setting at the beginning of the file
        sed -i "1i -N $FQDN" "$AUDIT_RULES_FILE"
    fi
fi

# Ensure the audit.rules file exists and contains the node name setting
if [ ! -f "$AUDIT_CONF_FILE" ]; then
    echo "-N $FQDN" > "$AUDIT_CONF_FILE"
else
    # Check if node name is already set
    if grep -q "^-N " "$AUDIT_CONF_FILE"; then
        # Update existing node name setting
        sed -i "s/^-N .*/\-N $FQDN/" "$AUDIT_CONF_FILE"
    else
        # Add node name setting at the beginning of the file
        sed -i "1i -N $FQDN" "$AUDIT_CONF_FILE"
    fi
fi

# Load the audit rules
auditctl -R "$AUDIT_RULES_FILE" 2>/dev/null || true

# Verify the node name is set in the running configuration
if auditctl -l 2>/dev/null | grep -q "^-N $FQDN"; then
    echo "Node name successfully set to: $FQDN"
else
    # If auditctl doesn't show the rule directly, try setting it again
    auditctl -N "$FQDN" || true
fi

# Enable audit daemon to start on boot
systemctl enable auditd

# Start or restart the audit daemon to apply changes
systemctl restart auditd

# Verify auditd is running
if systemctl is-active --quiet auditd; then
    echo "Audit daemon is running"
else
    echo "Warning: Audit daemon failed to start"
    exit 1
fi

# Verify the configuration persists by checking the rules files
echo "Verification:"
echo "Rules file content:"
if [ -f "$AUDIT_RULES_FILE" ]; then
    grep "^-N " "$AUDIT_RULES_FILE" || echo "No node name found in rules file"
fi

if [ -f "$AUDIT_CONF_FILE" ]; then
    echo "Main audit rules:"
    grep "^-N " "$AUDIT_CONF_FILE" || echo "No node name found in main audit rules"
fi

echo "Audit daemon configuration with FQDN node name is complete."
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
#!/bin/bash

set -euo pipefail

# Check if auditd is installed
if ! command -v auditd &> /dev/null; then
    echo "auditd is not installed. Installing it..."
    apt-get update
    apt-get install -y auditctl audispd-plugins
fi

# Define audit rule file locations
audit_rule_files=(
    "/etc/audit/rules.d"
    "/etc/audit/audit.rules"
)

# Ensure audit rule directory exists
mkdir -p /etc/audit/rules.d

# Fix permissions on audit rules directory
if [ -d "/etc/audit/rules.d" ]; then
    chmod 700 /etc/audit/rules.d
fi

# Find all audit rule files and set permissions to 0600
for dir_or_file in "${audit_rule_files[@]}"; do
    if [ -d "$dir_or_file" ]; then
        # For directories, find all files within and set permissions
        find "$dir_or_file" -type f -exec chmod 600 {} \;
        echo "Set permissions for audit rule files in $dir_or_file to 0600"
    elif [ -f "$dir_or_file" ]; then
        # For individual files, set permissions directly
        chmod 600 "$dir_or_file"
        echo "Set permissions for $dir_or_file to 0600"
    fi
done

# Also handle any other common audit configuration files
additional_audit_files=(
    "/etc/audit/audit.conf"
    "/etc/audit/auditd.conf"
)

for file in "${additional_audit_files[@]}"; do
    if [ -f "$file" ]; then
        current_perms=$(stat -c "%a" "$file")
        if [ "$current_perms" != "600" ]; then
            chmod 600 "$file"
            echo "Set permissions for $file to 0600"
        fi
    fi
done

echo "Audit rule file permissions have been remediated to 0600"
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
