#!/bin/bash

# ============================================================
#  CIS Check Point Firewall Benchmark v1.1.0 Audit Script
#  Based on: CIS Check Point Firewall Benchmark v1.1.0
#  Target:   Check Point Gaia OS (R80.x / R81.x)
#  Input:    Gaia configuration file (output of 'show configuration')
#
#  Usage:    ./checkpoint_cis_audit.sh <config_file>
#
#  Sections:
#    1   - Password Policy
#    2.1 - System Settings
#    2.2 - SNMP Settings
#    2.3 - NTP / Time Settings
#    2.4 - Backup & Recovery
#    2.5 - Authentication Settings
#    2.6 - Logging Settings
#    3   - Firewall Secure Settings
# ============================================================

# ---- Colour codes (disabled if not a tty) ------------------
if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; RESET=''
fi

# ---- Logging helper ----------------------------------------
log() {
    echo "$(date +"%Y-%m-%d %H:%M:%S") | $1" | tee -a "$LOG_FILE"
}

# ---- Result helpers ----------------------------------------
pass()   { local m="PASS: $1";   echo -e "${GREEN}${m}${RESET}" >&2; echo "$m" >> "$LOG_FILE"; echo "$m"; }
fail()   { local m="FAIL: $1";   echo -e "${RED}${m}${RESET}"   >&2; echo "$m" >> "$LOG_FILE"; echo "$m"; }
manual() { local m="MANUAL: $1"; echo -e "${YELLOW}${m}${RESET}" >&2; echo "$m" >> "$LOG_FILE"; echo "$m"; }
info()   { local m="INFO: $1";   echo -e "${CYAN}${m}${RESET}"  >&2; echo "$m" >> "$LOG_FILE"; echo "$m"; }

# Helper: extract value after a keyword in the config file
# Usage: get_val "keyword" "$config_file"
get_val() {
    grep -i "$1" "$2" | head -1 | awk '{print $NF}' | tr -d '"'
}

# Helper: check if a line/pattern exists in config
has_line() {
    grep -qi "$1" "$2"
}

# ============================================================
# SECTION 1 – PASSWORD POLICY
# ============================================================

# 1.1 Ensure Minimum Password Length is set to 14 or higher (Automated)
check_min_password_length() {
    local cfg="$1"
    local val
    val=$(grep -i "password-controls min-password-length" "$cfg" | awk '{print $NF}')
    if [ -z "$val" ]; then
        fail "1.1 Minimum password length not configured (password-controls min-password-length missing)"
    elif [ "$val" -ge 14 ] 2>/dev/null; then
        pass "1.1 Minimum password length is $val (>= 14)"
    else
        fail "1.1 Minimum password length is $val (CIS requires >= 14)"
    fi
}

# 1.2 Ensure Disallow Palindromes is selected (Automated)
check_palindrome_check() {
    local cfg="$1"
    local val
    val=$(grep -i "password-controls palindrome-check" "$cfg" | awk '{print $NF}')
    if echo "$val" | grep -qi "on\|true\|yes\|enable"; then
        pass "1.2 Palindrome check is enabled"
    else
        fail "1.2 Palindrome check is not enabled (password-controls palindrome-check on missing; current: ${val:-not set})"
    fi
}

# 1.3 Ensure Password Complexity is set to 3 (Automated)
check_password_complexity() {
    local cfg="$1"
    local val
    val=$(grep -i "password-controls complexity" "$cfg" | awk '{print $NF}')
    if [ -z "$val" ]; then
        fail "1.3 Password complexity not configured (password-controls complexity missing)"
    elif [ "$val" -ge 3 ] 2>/dev/null; then
        pass "1.3 Password complexity is $val (>= 3)"
    else
        fail "1.3 Password complexity is $val (CIS requires 3 - three character types)"
    fi
}

# 1.4 Ensure Check for Password Reuse is enabled and History Length >= 12 (Automated)
check_password_history() {
    local cfg="$1"
    local hist_check hist_len
    hist_check=$(grep -i "password-controls history-checking" "$cfg" | awk '{print $NF}')
    hist_len=$(grep -i "password-controls history-length" "$cfg" | awk '{print $NF}')
    local ok=true
    if ! echo "$hist_check" | grep -qi "on\|true\|yes\|enable"; then
        ok=false
        fail "1.4 Password history checking is not enabled (password-controls history-checking on missing; current: ${hist_check:-not set})"
    fi
    if [ -z "$hist_len" ] || [ "$hist_len" -lt 12 ] 2>/dev/null; then
        ok=false
        fail "1.4 Password history length is ${hist_len:-not set} (CIS requires >= 12)"
    fi
    if $ok; then
        pass "1.4 Password history enabled with length $hist_len (>= 12)"
    fi
}

# 1.5 Ensure Password Expiration is set to 90 days (Automated)
check_password_expiration() {
    local cfg="$1"
    local val
    val=$(grep -i "password-controls expiration-date\|password-controls password-expiration" "$cfg" | awk '{print $NF}')
    if [ -z "$val" ]; then
        val=$(grep -i "password-controls expiration" "$cfg" | grep -v "warning\|lockout" | awk '{print $NF}')
    fi
    if [ -z "$val" ]; then
        fail "1.5 Password expiration not configured"
    elif [ "$val" -le 90 ] && [ "$val" -gt 0 ] 2>/dev/null; then
        pass "1.5 Password expiration is $val days (<= 90)"
    else
        fail "1.5 Password expiration is $val days (CIS requires <= 90 days)"
    fi
}

# 1.6 Ensure Warn users before password expiration is set to 7 days (Automated)
check_password_expiry_warning() {
    local cfg="$1"
    local val
    val=$(grep -i "password-controls expiration-warning-days\|password-controls warn" "$cfg" | awk '{print $NF}')
    if [ -z "$val" ]; then
        fail "1.6 Password expiry warning not configured"
    elif [ "$val" -ge 7 ] 2>/dev/null; then
        pass "1.6 Password expiry warning is $val days (>= 7)"
    else
        fail "1.6 Password expiry warning is $val days (CIS requires >= 7 days)"
    fi
}

# 1.7 Ensure Lockout users after password expiration is set to 1 (Automated)
check_lockout_after_expiry() {
    local cfg="$1"
    local val
    val=$(grep -i "password-controls expiration-lockout-days\|password-controls lockout-after-expire" "$cfg" | awk '{print $NF}')
    if [ -z "$val" ]; then
        fail "1.7 Lockout after password expiry not configured"
    elif [ "$val" -le 1 ] && [ "$val" -ge 0 ] 2>/dev/null; then
        pass "1.7 Lockout after password expiry is $val day(s) (<= 1)"
    else
        fail "1.7 Lockout after password expiry is $val day(s) (CIS requires <= 1)"
    fi
}

# 1.8 Ensure Deny access to unused accounts is selected (Automated)
check_deny_unused_accounts() {
    local cfg="$1"
    local val
    val=$(grep -i "password-controls deny-on-nonuse\|password-controls unused-account" "$cfg" | awk '{print $NF}')
    if echo "$val" | grep -qi "on\|true\|yes\|enable"; then
        pass "1.8 Deny access to unused accounts is enabled"
    else
        fail "1.8 Deny access to unused accounts is not enabled (password-controls deny-on-nonuse on missing; current: ${val:-not set})"
    fi
}

# 1.9 Ensure Days of non-use before lock-out is set to 30 (Automated)
check_nonuse_lockout_days() {
    local cfg="$1"
    local val
    val=$(grep -i "password-controls deny-on-nonuse-days\|password-controls nonuse-days" "$cfg" | awk '{print $NF}')
    if [ -z "$val" ]; then
        fail "1.9 Days of non-use before lockout not configured"
    elif [ "$val" -le 30 ] && [ "$val" -gt 0 ] 2>/dev/null; then
        pass "1.9 Non-use lockout is $val days (<= 30)"
    else
        fail "1.9 Non-use lockout is $val days (CIS requires <= 30 days)"
    fi
}

# 1.10 Ensure Force users to change password at first login is selected (Automated)
check_force_password_change() {
    local cfg="$1"
    local val
    val=$(grep -i "password-controls force-change-at-first-login\|password-controls change-on-first" "$cfg" | awk '{print $NF}')
    if echo "$val" | grep -qi "on\|true\|yes\|enable"; then
        pass "1.10 Force password change at first login is enabled"
    else
        fail "1.10 Force password change at first login is not enabled (password-controls force-change-at-first-login on missing; current: ${val:-not set})"
    fi
}

# 1.11 Ensure Deny access after failed login attempts is selected (Automated)
check_deny_after_failed_logins() {
    local cfg="$1"
    local val
    val=$(grep -i "password-controls deny-on-fail\|password-controls lockout-on-fail" "$cfg" | awk '{print $NF}')
    if echo "$val" | grep -qi "on\|true\|yes\|enable"; then
        pass "1.11 Deny access after failed login attempts is enabled"
    else
        fail "1.11 Deny access after failed login attempts is not enabled (password-controls deny-on-fail on missing; current: ${val:-not set})"
    fi
}

# 1.12 Ensure Maximum number of failed attempts is set to 5 or fewer (Automated)
check_max_failed_attempts() {
    local cfg="$1"
    local val
    val=$(grep -i "password-controls deny-on-fail-count\|password-controls max-fail" "$cfg" | awk '{print $NF}')
    if [ -z "$val" ]; then
        fail "1.12 Maximum failed login attempts not configured"
    elif [ "$val" -le 5 ] && [ "$val" -gt 0 ] 2>/dev/null; then
        pass "1.12 Maximum failed login attempts is $val (<= 5)"
    else
        fail "1.12 Maximum failed login attempts is $val (CIS requires <= 5)"
    fi
}

# 1.13 Ensure Allow access again after time is set to 300 or more seconds (Automated)
check_lockout_duration() {
    local cfg="$1"
    local val
    val=$(grep -i "password-controls deny-on-fail-interval\|password-controls lockout-duration\|password-controls fail-lock-time" "$cfg" | awk '{print $NF}')
    if [ -z "$val" ]; then
        fail "1.13 Lockout duration after failed attempts not configured"
    elif [ "$val" -ge 300 ] 2>/dev/null; then
        pass "1.13 Lockout duration is $val seconds (>= 300)"
    else
        fail "1.13 Lockout duration is $val seconds (CIS requires >= 300 seconds)"
    fi
}

# ============================================================
# SECTION 2.1 – SYSTEM SETTINGS
# ============================================================

# 2.1.1 Ensure Login Banner is set (Automated)
check_login_banner() {
    local cfg="$1"
    local banner_on banner_msg
    banner_on=$(grep -i "set message banner on\|message banner on" "$cfg" | head -1)
    banner_msg=$(grep -i "set message banner msgvalue\|message banner msgvalue" "$cfg" | head -1)
    if [ -n "$banner_on" ] && [ -n "$banner_msg" ]; then
        pass "2.1.1 Login Banner is configured"
    elif [ -n "$banner_on" ]; then
        fail "2.1.1 Login Banner is enabled but no message text configured (message banner msgvalue missing)"
    else
        fail "2.1.1 Login Banner is not configured (message banner on and/or msgvalue missing)"
    fi
}

# 2.1.2 Ensure Message Of The Day (MOTD) is set (Automated)
check_motd() {
    local cfg="$1"
    local motd_on motd_msg
    motd_on=$(grep -i "set motd banner on\|motd banner on" "$cfg" | head -1)
    motd_msg=$(grep -i "set motd banner msgvalue\|motd banner msgvalue" "$cfg" | head -1)
    if [ -n "$motd_on" ] && [ -n "$motd_msg" ]; then
        pass "2.1.2 MOTD (Message Of The Day) is configured"
    elif [ -n "$motd_on" ]; then
        fail "2.1.2 MOTD is enabled but no message text configured (motd banner msgvalue missing)"
    else
        fail "2.1.2 MOTD is not configured (motd banner on and/or msgvalue missing)"
    fi
}

# 2.1.3 Ensure Core Dump is enabled (Automated)
check_core_dump() {
    local cfg="$1"
    local val
    val=$(grep -i "set core-dump\|core-dump" "$cfg" | head -1 | awk '{print $NF}')
    if echo "$val" | grep -qi "on\|enable\|true\|yes"; then
        pass "2.1.3 Core Dump is enabled"
    else
        fail "2.1.3 Core Dump is not enabled (set core-dump on missing; current: ${val:-not set})"
    fi
}

# 2.1.4 Ensure Config-state is saved (Automated)
check_config_state_saved() {
    local cfg="$1"
    # In Gaia, 'show config-state' returns 'saved' if last config was saved
    if grep -qi "config-state.*saved\|configuration.*saved\|set config-state saved" "$cfg"; then
        pass "2.1.4 Configuration state is saved"
    else
        fail "2.1.4 Configuration state is not confirmed as saved (verify with 'show config-state' on device)"
    fi
}

# 2.1.5 Ensure unused interfaces are disabled (Automated)
check_unused_interfaces() {
    local cfg="$1"
    local unused_up
    # Find interfaces with 'state on' or 'link-speed' but no IP address configured
    unused_up=$(grep -i "set interface.*state on" "$cfg" | grep -v "lo\|Loopback" | wc -l)
    local with_ip
    with_ip=$(grep -i "set interface.*ipv4-address\|set interface.*ip" "$cfg" | grep -v "ipv6" | wc -l)
    if [ "$unused_up" -le "$with_ip" ]; then
        pass "2.1.5 Interface count check: $unused_up active interfaces, $with_ip with IPs configured (verify unused ones are disabled)"
    else
        fail "2.1.5 Possible unused interfaces up: $unused_up interfaces are active but only $with_ip have IPs - review and disable unused interfaces"
    fi
}

# 2.1.6 Ensure DNS server is configured – primary, secondary, tertiary (Automated)
check_dns_configured() {
    local cfg="$1"
    local primary secondary
    primary=$(grep -i "set dns primary\|dns primary" "$cfg" | awk '{print $NF}')
    secondary=$(grep -i "set dns secondary\|dns secondary" "$cfg" | awk '{print $NF}')
    if [ -n "$primary" ] && [ -n "$secondary" ]; then
        pass "2.1.6 DNS configured: primary=$primary, secondary=$secondary"
    elif [ -n "$primary" ]; then
        fail "2.1.6 DNS primary is set ($primary) but secondary DNS server is missing (CIS requires at least two)"
    else
        fail "2.1.6 DNS server(s) not configured (set dns primary and secondary missing)"
    fi
}

# 2.1.7 Ensure IPv6 is disabled if not used (Automated)
check_ipv6_disabled() {
    local cfg="$1"
    local ipv6_state
    ipv6_state=$(grep -i "set ipv6-state\|ipv6.*enable\|set ipv6 on" "$cfg" | head -1)
    if [ -z "$ipv6_state" ]; then
        pass "2.1.7 IPv6 does not appear to be explicitly enabled (verify with 'show ipv6-state' on device)"
    elif echo "$ipv6_state" | grep -qi "off\|disable\|false"; then
        pass "2.1.7 IPv6 is explicitly disabled"
    else
        fail "2.1.7 IPv6 appears to be enabled - disable if not required ($ipv6_state)"
    fi
}

# 2.1.8 Ensure Host Name is set (Automated)
check_hostname_set() {
    local cfg="$1"
    local val
    val=$(grep -i "set hostname\|hostname" "$cfg" | head -1 | awk '{print $NF}')
    if [ -n "$val" ] && [ "$val" != "hostname" ]; then
        pass "2.1.8 Hostname is set to: $val"
    else
        fail "2.1.8 Hostname is not configured (set hostname missing)"
    fi
}

# 2.1.9 Ensure Telnet is disabled (Automated)
check_telnet_disabled() {
    local cfg="$1"
    if grep -qi "set telnet enabled true\|set telnet on\|telnet.*enable" "$cfg"; then
        fail "2.1.9 Telnet is enabled - it must be disabled (set telnet enabled false)"
    else
        pass "2.1.9 Telnet is not explicitly enabled (assumed disabled)"
    fi
}

# 2.1.10 Ensure DHCP is disabled (Automated)
check_dhcp_disabled() {
    local cfg="$1"
    if grep -qi "set dhcp server enable\|set dhcp server on\|dhcp.*enable" "$cfg"; then
        fail "2.1.10 DHCP server is enabled - disable if not required"
    else
        pass "2.1.10 DHCP server is not explicitly enabled (assumed disabled)"
    fi
}

# 2.1.11 (Additional) Ensure allowed-client is set to those necessary for management
check_allowed_client() {
    local cfg="$1"
    if grep -qi "set allowed-client\|allowed-client host\|allowed-client network" "$cfg"; then
        pass "2.1.11 Allowed-client restriction is configured (verify only management IPs are listed)"
    else
        fail "2.1.11 No allowed-client restrictions found - management access may not be restricted by source IP"
    fi
}

# ============================================================
# SECTION 2.2 – SNMP SETTINGS
# ============================================================

# 2.2.1 Ensure SNMP agent is disabled if not required (Automated)
check_snmp_agent_status() {
    local cfg="$1"
    local val
    val=$(grep -i "set snmp agent\|snmp agent" "$cfg" | head -1 | awk '{print $NF}')
    if echo "$val" | grep -qi "on\|enable\|true\|yes"; then
        # SNMP is on – check that it is v3-only (2.2.2 covers this)
        info "2.2.1 SNMP agent is enabled - ensure it is required and only SNMPv3 is used (see 2.2.2)"
    else
        pass "2.2.1 SNMP agent is not enabled (or not explicitly configured)"
    fi
}

# 2.2.2 Ensure SNMP version is set to v3-Only (Automated)
check_snmp_v3_only() {
    local cfg="$1"
    local v1_enabled v2_enabled
    v1_enabled=$(grep -i "snmp.*v1\|snmp.*version.*1" "$cfg" | grep -iv "disable\|off\|false" | head -1)
    v2_enabled=$(grep -i "snmp.*v2c\|snmp.*version.*2" "$cfg" | grep -iv "disable\|off\|false" | head -1)
    local v3_set
    v3_set=$(grep -i "snmp.*v3\|snmp.*usm\|set snmp.*v3" "$cfg" | head -1)
    if [ -n "$v1_enabled" ] || [ -n "$v2_enabled" ]; then
        fail "2.2.2 SNMPv1 or SNMPv2c appears to be enabled - only SNMPv3 is permitted"
    elif [ -n "$v3_set" ]; then
        pass "2.2.2 SNMPv3 is configured and v1/v2c not detected"
    else
        info "2.2.2 SNMP version configuration not clearly detected - verify only SNMPv3 is in use on device"
    fi
}

# 2.2.3 Ensure SNMP traps are enabled for key events (Automated)
check_snmp_traps() {
    local cfg="$1"
    local traps=("authorizationError" "coldStart" "configurationChange" "configurationSave" "linkUpLinkDown" "lowDiskSpace")
    local missing=()
    for trap in "${traps[@]}"; do
        if ! grep -qi "snmp.*trap.*$trap\|trap.*$trap" "$cfg"; then
            missing+=("$trap")
        fi
    done
    if [ ${#missing[@]} -eq 0 ]; then
        pass "2.2.3 All required SNMP traps are configured"
    else
        fail "2.2.3 Missing SNMP traps: ${missing[*]}"
    fi
}

# 2.2.4 Ensure SNMP trap receivers are configured (Automated)
check_snmp_trap_receivers() {
    local cfg="$1"
    if grep -qi "set snmp traps.*receiver\|snmp trap.*host\|snmp.*receiver" "$cfg"; then
        pass "2.2.4 SNMP trap receiver(s) are configured"
    else
        fail "2.2.4 No SNMP trap receiver configured (verify with 'show snmp' on device)"
    fi
}

# ============================================================
# SECTION 2.3 – NTP / TIME SETTINGS
# ============================================================

# 2.3.1 Ensure NTP is enabled with Primary and Secondary server (Automated)
check_ntp_configured() {
    local cfg="$1"
    local ntp_active primary secondary
    ntp_active=$(grep -i "set ntp active\|ntp active" "$cfg" | awk '{print $NF}')
    primary=$(grep -i "set ntp server primary\|ntp.*primary" "$cfg" | awk '{print $NF}')
    secondary=$(grep -i "set ntp server secondary\|ntp.*secondary" "$cfg" | awk '{print $NF}')
    local ok=true
    if ! echo "$ntp_active" | grep -qi "on\|enable\|true\|yes"; then
        ok=false
        fail "2.3.1 NTP is not enabled (set ntp active on missing; current: ${ntp_active:-not set})"
    fi
    if [ -z "$primary" ]; then
        ok=false
        fail "2.3.1 NTP primary server not configured"
    fi
    if [ -z "$secondary" ]; then
        ok=false
        fail "2.3.1 NTP secondary server not configured (CIS requires both primary and secondary)"
    fi
    if $ok; then
        pass "2.3.1 NTP is enabled with primary=$primary and secondary=$secondary"
    fi
}

# 2.3.2 Ensure timezone is properly configured (Automated)
check_timezone() {
    local cfg="$1"
    local val
    val=$(grep -i "set timezone\|timezone" "$cfg" | head -1 | awk '{$1=$2=""; print $0}' | sed 's/^ *//')
    if [ -n "$val" ]; then
        pass "2.3.2 Timezone is configured: $val"
    else
        fail "2.3.2 Timezone is not configured (set timezone missing)"
    fi
}

# ============================================================
# SECTION 2.4 – BACKUP & RECOVERY
# ============================================================

# 2.4.1 Ensure System Backup is set (Automated)
check_system_backup() {
    local cfg="$1"
    if grep -qi "backup\|set backup" "$cfg"; then
        pass "2.4.1 Backup configuration references found (verify backups are regularly executed and stored offsite)"
    else
        fail "2.4.1 No backup configuration found - configure system backups"
    fi
}

# 2.4.2 Ensure Snapshot is set (Automated)
check_snapshot_configured() {
    local cfg="$1"
    if grep -qi "snapshot\|set snapshot" "$cfg"; then
        pass "2.4.2 Snapshot configuration references found"
    else
        fail "2.4.2 No snapshot configuration found (configure snapshots before major changes)"
    fi
}

# 2.4.3 Configuring Scheduled Backups (Manual)
check_scheduled_backups() {
    if grep -qi "scheduled.*backup\|backup.*schedule\|cron.*backup" "$1" 2>/dev/null; then
        pass "2.4.3 Scheduled backup configuration detected"
    else
        manual "2.4.3 Scheduled backups: Verify that automatic scheduled backups are configured and tested"
    fi
}

# ============================================================
# SECTION 2.5 – AUTHENTICATION SETTINGS
# ============================================================

# 2.5.1 Ensure CLI session timeout <= 10 minutes (Automated)
check_cli_timeout() {
    local cfg="$1"
    local val
    val=$(grep -i "set cli.*timeout\|cli.*idle-timeout\|cli.*session-timeout" "$cfg" | awk '{print $NF}')
    if [ -z "$val" ]; then
        fail "2.5.1 CLI session timeout not configured"
    elif [ "$val" -le 600 ] && [ "$val" -gt 0 ] 2>/dev/null; then
        pass "2.5.1 CLI session timeout is ${val}s (<= 600s / 10 minutes)"
    else
        fail "2.5.1 CLI session timeout is ${val}s (CIS requires <= 600 seconds / 10 minutes)"
    fi
}

# 2.5.2 Ensure Web session timeout <= 10 minutes (Automated)
check_web_timeout() {
    local cfg="$1"
    local val
    val=$(grep -i "set web session-timeout\|web.*idle-timeout\|webui.*timeout\|set web idle" "$cfg" | awk '{print $NF}')
    if [ -z "$val" ]; then
        fail "2.5.2 Web session timeout not configured"
    elif [ "$val" -le 600 ] && [ "$val" -gt 0 ] 2>/dev/null; then
        pass "2.5.2 Web session timeout is ${val}s (<= 600s / 10 minutes)"
    else
        fail "2.5.2 Web session timeout is ${val}s (CIS requires <= 600 seconds / 10 minutes)"
    fi
}

# 2.5.3 Ensure Client Authentication is secured (Automated)
check_client_auth_secured() {
    local cfg="$1"
    # Check that HTTP client auth is not enabled (it should be HTTPS/encrypted)
    if grep -qi "client-auth.*http[^s]\|client-auth.*port 900\b" "$cfg"; then
        fail "2.5.3 Client Authentication over plain HTTP (port 900) detected - migrate to HTTPS"
    else
        pass "2.5.3 No plain HTTP client authentication detected (verify client auth uses HTTPS)"
    fi
}

# 2.5.4 Ensure Radius or TACACS+ server is configured (Automated)
check_radius_tacacs() {
    local cfg="$1"
    local radius tacacs
    radius=$(grep -i "set aaa radius\|radius-server\|aaa server.*radius" "$cfg" | head -1)
    tacacs=$(grep -i "set tacacs\|tacacs-server\|set aaa tacacs" "$cfg" | head -1)
    if [ -n "$radius" ] || [ -n "$tacacs" ]; then
        pass "2.5.4 RADIUS or TACACS+ server is configured (centralized authentication)"
    else
        fail "2.5.4 No RADIUS or TACACS+ server configured - centralized authentication not set up"
    fi
}

# ============================================================
# SECTION 2.6 – LOGGING SETTINGS
# ============================================================

# 2.6.1 Ensure mgmtauditlogs is set to on (Automated)
check_mgmt_audit_logs() {
    local cfg="$1"
    local val
    val=$(grep -i "set syslog mgmtauditlogs\|mgmtauditlogs" "$cfg" | awk '{print $NF}')
    if echo "$val" | grep -qi "on\|enable\|true"; then
        pass "2.6.1 Management audit logs (mgmtauditlogs) are enabled"
    else
        fail "2.6.1 Management audit logs not enabled (set syslog mgmtauditlogs on missing; current: ${val:-not set})"
    fi
}

# 2.6.2 Ensure auditlog is set to permanent (Automated)
check_auditlog_permanent() {
    local cfg="$1"
    local val
    val=$(grep -i "set auditlog\|auditlog.*permanent" "$cfg" | awk '{print $NF}')
    if echo "$val" | grep -qi "permanent\|on\|enable"; then
        pass "2.6.2 Audit log is set to permanent"
    else
        fail "2.6.2 Audit log not set to permanent (set auditlog permanent missing; current: ${val:-not set})"
    fi
}

# 2.6.3 Ensure cplogs is set to on (Automated)
check_cplogs_enabled() {
    local cfg="$1"
    local val
    val=$(grep -i "set syslog cplogs\|cplogs" "$cfg" | awk '{print $NF}')
    if echo "$val" | grep -qi "on\|enable\|true"; then
        pass "2.6.3 CP logs (cplogs) are enabled"
    else
        fail "2.6.3 CP logs not enabled (set syslog cplogs on missing; current: ${val:-not set})"
    fi
}

# ============================================================
# SECTION 3 – FIREWALL SECURE SETTINGS
# ============================================================

# 3.1 Enable the Firewall Stealth Rule (Automated)
check_stealth_rule() {
    local cfg="$1"
    if grep -qi "stealth\|drop.*gateway\|any.*drop.*fw\|stealth.*rule" "$cfg"; then
        pass "3.1 Firewall Stealth Rule appears to be configured (verify in SmartConsole)"
    else
        manual "3.1 Firewall Stealth Rule: Verify a stealth rule dropping traffic destined to the gateway is in place in SmartConsole"
    fi
}

# 3.2 Configure a Default Drop/Cleanup Rule (Automated)
check_default_drop_rule() {
    local cfg="$1"
    if grep -qi "cleanup.*rule\|default.*drop\|any any drop\|cleanup-rule" "$cfg"; then
        pass "3.2 Default Drop/Cleanup Rule appears to be configured"
    else
        manual "3.2 Default Drop/Cleanup Rule: Verify a cleanup rule dropping all unmatched traffic is the last rule in SmartConsole policy"
    fi
}

# 3.3 Use Checkpoint Sections and Titles (Manual)
check_policy_sections() {
    manual "3.3 Policy Sections & Titles: Verify the rulebase is organized into sections with descriptive titles in SmartConsole"
}

# 3.4 Ensure Hit Count is enabled for rules (Automated)
check_hit_count_enabled() {
    local cfg="$1"
    if grep -qi "hit-count\|track.*count\|rule.*hit" "$cfg"; then
        pass "3.4 Hit Count configuration detected (verify it is enabled on all rules in SmartConsole)"
    else
        manual "3.4 Hit Count: Verify that Hit Count tracking is enabled for all firewall rules in SmartConsole > Global Properties"
    fi
}

# 3.5 Ensure no Allow Rule with Any in Destination (Automated)
check_no_any_destination() {
    local cfg="$1"
    if grep -qi "destination.*any\|dst.*any\|set rule.*destination any" "$cfg"; then
        fail "3.5 Allow rules with 'Any' in Destination detected - restrict to specific destinations"
    else
        pass "3.5 No Allow rules with 'Any' in Destination detected (verify in SmartConsole rulebase)"
    fi
}

# 3.6 Ensure no Allow Rule with Any in Source (Automated)
check_no_any_source() {
    local cfg="$1"
    if grep -qi "source.*any\|src.*any\|set rule.*source any" "$cfg" | grep -vi "drop\|reject\|deny"; then
        fail "3.6 Allow rules with 'Any' in Source detected - restrict to specific source addresses"
    else
        pass "3.6 No Allow rules with 'Any' in Source clearly detected (verify in SmartConsole rulebase)"
    fi
}

# 3.7 Ensure no Allow Rule with Any in Services (Automated)
check_no_any_service() {
    local cfg="$1"
    if grep -qi "service.*any\|services.*any\|set rule.*service any" "$cfg" | grep -vi "drop\|reject\|deny"; then
        fail "3.7 Allow rules with 'Any' in Services detected - restrict to required services only"
    else
        pass "3.7 No Allow rules with 'Any' in Services clearly detected (verify in SmartConsole rulebase)"
    fi
}

# 3.8 Logging should be enabled for all Firewall Rules (Manual)
check_logging_all_rules() {
    manual "3.8 Rule Logging: Verify that logging (Log or Alert) is enabled for all firewall rules in SmartConsole"
}

# 3.9 Review and Log Implied Rules (Automated)
check_implied_rules_logged() {
    local cfg="$1"
    if grep -qi "log.*implied\|implied.*rule.*log\|log-implied" "$cfg"; then
        pass "3.9 Implied rules logging appears to be configured"
    else
        fail "3.9 Log Implied Rules not detected - enable in SmartConsole > Global Properties > Firewall > Log Implied Rules"
    fi
}

# 3.10 Ensure Drop Out of State TCP Packets is enabled (Automated)
check_drop_out_of_state_tcp() {
    local cfg="$1"
    if grep -qi "drop.*out-of-state.*tcp\|out-of-state-tcp.*drop\|tcp.*stateful\|stateful.*tcp" "$cfg"; then
        pass "3.10 Drop out-of-state TCP packets appears to be enabled"
    else
        manual "3.10 Out-of-State TCP: Verify 'Drop out of state TCP packets' is enabled in SmartConsole > Global Properties > Stateful Inspection"
    fi
}

# 3.11 Ensure Drop Out of State ICMP Packets is enabled (Automated)
check_drop_out_of_state_icmp() {
    local cfg="$1"
    if grep -qi "drop.*out-of-state.*icmp\|out-of-state-icmp.*drop\|icmp.*stateful" "$cfg"; then
        pass "3.11 Drop out-of-state ICMP packets appears to be enabled"
    else
        manual "3.11 Out-of-State ICMP: Verify 'Drop out of state ICMP packets' is enabled in SmartConsole > Global Properties > Stateful Inspection"
    fi
}

# 3.12 Ensure Anti-Spoofing is enabled with action set to Prevent for all interfaces (Automated)
check_anti_spoofing() {
    local cfg="$1"
    local spoof_count prevent_count
    spoof_count=$(grep -ci "anti-spoofing\|antispoofing\|spoof-tracking" "$cfg" 2>/dev/null || echo 0)
    prevent_count=$(grep -ci "spoof.*prevent\|anti-spoofing.*prevent\|spoofing.*action.*prevent" "$cfg" 2>/dev/null || echo 0)
    if [ "$spoof_count" -gt 0 ] && [ "$prevent_count" -gt 0 ]; then
        pass "3.12 Anti-spoofing with 'Prevent' action is configured on interfaces"
    elif [ "$spoof_count" -gt 0 ]; then
        fail "3.12 Anti-spoofing is referenced but 'Prevent' action not confirmed - verify all interfaces use Prevent, not Detect"
    else
        fail "3.12 Anti-spoofing not detected - enable on all interfaces with action set to Prevent in SmartConsole"
    fi
}

# 3.13 Ensure Disk Space Alert is set (Automated)
check_disk_space_alert() {
    local cfg="$1"
    if grep -qi "disk.*alert\|alert.*disk\|set disk-space\|disk-space-alert" "$cfg"; then
        pass "3.13 Disk space alert is configured"
    else
        fail "3.13 Disk space alert not configured (set disk-space-alert threshold missing)"
    fi
}

# 3.14 Ensure Access Control (Accept) rules have logging set to Log or Alert (Manual)
check_accept_rules_logged() {
    manual "3.14 Accept Rule Logging: Verify all Accept/Allow rules have tracking set to 'Log' or an Alert type in SmartConsole"
}

# 3.15 Ensure Track options are configured in Global Properties Log and Alert (Manual)
check_global_track_options() {
    manual "3.15 Global Track Options: In SmartConsole > Global Properties > Log and Alert > Track Options, verify logging is set for: VPN key exchange, VPN errors, IP Options drop, Administrative notifications, SAM connections, Packet tagging events, and authenticated HTTP connections"
}

# ============================================================
# MAIN ENTRY POINT
# ============================================================

if [ $# -ne 1 ]; then
    echo "Usage: $0 <checkpoint_config_file>"
    echo "       Config file = output of 'show configuration' on Gaia OS"
    exit 1
fi

CONFIG_FILE="$1"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "ERROR: Config file '$CONFIG_FILE' not found."
    exit 1
fi

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="CHECKPOINT_CIS_BENCHMARK_v1.1.0_AUDIT_${TIMESTAMP}.log"
CSV_FILE="CHECKPOINT_CIS_BENCHMARK_v1.1.0_AUDIT_${TIMESTAMP}.csv"
HTML_FILE="CHECKPOINT_CIS_BENCHMARK_v1.1.0_AUDIT_${TIMESTAMP}.html"

touch "$LOG_FILE"
echo "Benchmark,Result" > "$CSV_FILE"

echo ""
echo -e "${BOLD}============================================================${RESET}"
echo -e "${BOLD}  CIS Check Point Firewall Benchmark v1.1.0 Audit${RESET}"
echo -e "${BOLD}============================================================${RESET}"
echo "  Config file : $CONFIG_FILE"
# echo "  Log file    : $LOG_FILE"
echo "  Started     : $(date)"
echo ""

log "====== CIS Check Point Firewall Benchmark v1.1.0 Audit Started ======"

# Helper: run a check, capture result, write to CSV
run_check() {
    local id="$1"
    local desc="$2"
    local func="$3"
    shift 3

    echo -e "${CYAN}[${id}] ${desc}${RESET}" >&2
    local result
    result=$("$func" "$@" 2>/dev/null | head -1)
    echo "${id} ${desc},${result}" >> "$CSV_FILE"
    echo "" >&2
}

# ---- Section 1: Password Policy ----
echo -e "${BOLD}--- Section 1: Password Policy ---${RESET}"
run_check "1.1"  "Minimum Password Length >= 14"                         check_min_password_length     "$CONFIG_FILE"
run_check "1.2"  "Disallow Palindromes"                                  check_palindrome_check        "$CONFIG_FILE"
run_check "1.3"  "Password Complexity = 3"                               check_password_complexity     "$CONFIG_FILE"
run_check "1.4"  "Password Reuse check + History Length >= 12"           check_password_history        "$CONFIG_FILE"
run_check "1.5"  "Password Expiration <= 90 days"                        check_password_expiration     "$CONFIG_FILE"
run_check "1.6"  "Password Expiry Warning >= 7 days"                     check_password_expiry_warning "$CONFIG_FILE"
run_check "1.7"  "Lockout after password expiry <= 1 day"                check_lockout_after_expiry    "$CONFIG_FILE"
run_check "1.8"  "Deny access to unused accounts"                        check_deny_unused_accounts    "$CONFIG_FILE"
run_check "1.9"  "Non-use lockout days <= 30"                            check_nonuse_lockout_days     "$CONFIG_FILE"
run_check "1.10" "Force password change at first login"                  check_force_password_change   "$CONFIG_FILE"
run_check "1.11" "Deny access after failed login attempts"               check_deny_after_failed_logins "$CONFIG_FILE"
run_check "1.12" "Maximum failed login attempts <= 5"                    check_max_failed_attempts     "$CONFIG_FILE"
run_check "1.13" "Lockout duration >= 300 seconds after failed logins"   check_lockout_duration        "$CONFIG_FILE"

# ---- Section 2.1: System Settings ----
echo -e "${BOLD}--- Section 2.1: System Settings ---${RESET}"
run_check "2.1.1"  "Login Banner configured"                             check_login_banner            "$CONFIG_FILE"
run_check "2.1.2"  "MOTD (Message Of The Day) configured"                check_motd                    "$CONFIG_FILE"
run_check "2.1.3"  "Core Dump enabled"                                   check_core_dump               "$CONFIG_FILE"
run_check "2.1.4"  "Config-state is saved"                               check_config_state_saved      "$CONFIG_FILE"
run_check "2.1.5"  "Unused interfaces are disabled"                      check_unused_interfaces       "$CONFIG_FILE"
run_check "2.1.6"  "DNS servers configured (primary + secondary)"        check_dns_configured          "$CONFIG_FILE"
run_check "2.1.7"  "IPv6 disabled if not in use"                         check_ipv6_disabled           "$CONFIG_FILE"
run_check "2.1.8"  "Hostname is set"                                     check_hostname_set            "$CONFIG_FILE"
run_check "2.1.9"  "Telnet is disabled"                                  check_telnet_disabled         "$CONFIG_FILE"
run_check "2.1.10" "DHCP is disabled"                                    check_dhcp_disabled           "$CONFIG_FILE"
run_check "2.1.11" "Allowed-client restrictions configured"              check_allowed_client          "$CONFIG_FILE"

# ---- Section 2.2: SNMP ----
echo -e "${BOLD}--- Section 2.2: SNMP Settings ---${RESET}"
run_check "2.2.1"  "SNMP agent disabled (if not required)"               check_snmp_agent_status       "$CONFIG_FILE"
run_check "2.2.2"  "SNMP version is v3-Only"                             check_snmp_v3_only            "$CONFIG_FILE"
run_check "2.2.3"  "SNMP traps enabled for required events"              check_snmp_traps              "$CONFIG_FILE"
run_check "2.2.4"  "SNMP trap receivers configured"                      check_snmp_trap_receivers     "$CONFIG_FILE"

# ---- Section 2.3: NTP / Time ----
echo -e "${BOLD}--- Section 2.3: NTP / Time Settings ---${RESET}"
run_check "2.3.1"  "NTP enabled with Primary and Secondary servers"      check_ntp_configured          "$CONFIG_FILE"
run_check "2.3.2"  "Timezone properly configured"                        check_timezone                "$CONFIG_FILE"

# ---- Section 2.4: Backup & Recovery ----
echo -e "${BOLD}--- Section 2.4: Backup & Recovery ---${RESET}"
run_check "2.4.1"  "System Backup configured"                            check_system_backup           "$CONFIG_FILE"
run_check "2.4.2"  "Snapshot configured"                                 check_snapshot_configured     "$CONFIG_FILE"
run_check "2.4.3"  "Scheduled Backups configured"                        check_scheduled_backups       "$CONFIG_FILE"

# ---- Section 2.5: Authentication ----
echo -e "${BOLD}--- Section 2.5: Authentication Settings ---${RESET}"
run_check "2.5.1"  "CLI session timeout <= 10 minutes (600 seconds)"    check_cli_timeout             "$CONFIG_FILE"
run_check "2.5.2"  "Web session timeout <= 10 minutes (600 seconds)"    check_web_timeout             "$CONFIG_FILE"
run_check "2.5.3"  "Client Authentication secured (no plain HTTP)"       check_client_auth_secured     "$CONFIG_FILE"
run_check "2.5.4"  "RADIUS or TACACS+ server configured"                 check_radius_tacacs           "$CONFIG_FILE"

# ---- Section 2.6: Logging ----
echo -e "${BOLD}--- Section 2.6: Logging Settings ---${RESET}"
run_check "2.6.1"  "Management audit logs (mgmtauditlogs) enabled"       check_mgmt_audit_logs         "$CONFIG_FILE"
run_check "2.6.2"  "Audit log set to permanent"                          check_auditlog_permanent      "$CONFIG_FILE"
run_check "2.6.3"  "CP logs (cplogs) enabled"                            check_cplogs_enabled          "$CONFIG_FILE"

# ---- Section 3: Firewall Secure Settings ----
echo -e "${BOLD}--- Section 3: Firewall Secure Settings ---${RESET}"
run_check "3.1"  "Firewall Stealth Rule configured"                       check_stealth_rule            "$CONFIG_FILE"
run_check "3.2"  "Default Drop/Cleanup Rule configured"                   check_default_drop_rule       "$CONFIG_FILE"
run_check "3.3"  "Policy Sections and Titles in use (Manual)"             check_policy_sections
run_check "3.4"  "Hit Count enabled for all rules"                        check_hit_count_enabled       "$CONFIG_FILE"
run_check "3.5"  "No Allow rules with Any in Destination"                 check_no_any_destination      "$CONFIG_FILE"
run_check "3.6"  "No Allow rules with Any in Source"                      check_no_any_source           "$CONFIG_FILE"
run_check "3.7"  "No Allow rules with Any in Services"                    check_no_any_service          "$CONFIG_FILE"
run_check "3.8"  "Logging enabled for all Firewall Rules (Manual)"        check_logging_all_rules
run_check "3.9"  "Implied Rules are logged"                               check_implied_rules_logged    "$CONFIG_FILE"
run_check "3.10" "Drop Out-of-State TCP Packets enabled"                  check_drop_out_of_state_tcp   "$CONFIG_FILE"
run_check "3.11" "Drop Out-of-State ICMP Packets enabled"                 check_drop_out_of_state_icmp  "$CONFIG_FILE"
run_check "3.12" "Anti-Spoofing enabled with Prevent action"              check_anti_spoofing           "$CONFIG_FILE"
run_check "3.13" "Disk Space Alert configured"                            check_disk_space_alert        "$CONFIG_FILE"
run_check "3.14" "Accept rules have logging enabled (Manual)"             check_accept_rules_logged
run_check "3.15" "Global Track Options in Log and Alert (Manual)"         check_global_track_options

log "====== CIS Check Point Firewall Benchmark v1.1.0 Audit Completed ======"

# ---- Calculate totals ----
total_checks=$(( $(wc -l < "$CSV_FILE") - 1 ))
total_pass=$(grep -c "^[^,]*,PASS"   "$CSV_FILE" 2>/dev/null || true)
total_fail=$(grep -c "^[^,]*,FAIL"   "$CSV_FILE" 2>/dev/null || true)
total_manual=$(grep -c "^[^,]*,MANUAL" "$CSV_FILE" 2>/dev/null || true)
total_info=$(grep -c "^[^,]*,INFO"   "$CSV_FILE" 2>/dev/null || true)

# ---- HTML Report ----
cat > "$HTML_FILE" <<HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Check Point CIS Benchmark v1.1.0 Audit Report</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body  { font-family: 'Segoe UI', Arial, sans-serif; background: #f0f2f5; color: #222; padding: 24px; }
  h1    { color: #c8102e; margin-bottom: 4px; font-size: 1.6em; }
  .meta { color: #555; margin-bottom: 22px; font-size: .88em; }
  .summary { display: flex; gap: 20px; flex-wrap: wrap; margin-bottom: 28px; }
  .stat { background: #fff; border-radius: 8px; padding: 16px 24px;
          box-shadow: 0 2px 6px rgba(0,0,0,.1); text-align: center; min-width: 110px; }
  .stat .num   { font-size: 2.4em; font-weight: 700; }
  .stat .label { font-size: .75em; text-transform: uppercase; letter-spacing: .06em; color: #666; margin-top: 2px; }
  .s-total .num  { color: #1a1a2e; }
  .s-pass  .num  { color: #2d8a4e; }
  .s-fail  .num  { color: #c8102e; }
  .s-manual .num { color: #d97706; }
  .s-info  .num  { color: #4a6fa5; }
  .section-header { background: #c8102e; color: #fff; padding: 8px 16px;
                    font-weight: 600; font-size: .95em; margin: 18px 0 0; border-radius: 6px 6px 0 0; }
  table  { width: 100%; border-collapse: collapse; background: #fff;
           box-shadow: 0 2px 6px rgba(0,0,0,.08); margin-bottom: 4px; }
  th     { background: #2c2c54; color: #fff; padding: 9px 14px;
           text-align: left; font-size: .82em; font-weight: 600; }
  td     { padding: 8px 14px; border-bottom: 1px solid #eee; font-size: .84em; vertical-align: top; }
  /* ---- Row number ---- */
  td.row-num { color: #999; font-size: .78em; width: 36px; text-align: center; }
  /* ---- Check ID ---- */
  td.check-id { font-weight: 600; white-space: nowrap; width: 150px; }
  td.check-desc { white-space: nowrap; width: 450px; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: #f7f7fb; }
  .r-PASS   { color: #2d8a4e; font-weight: 600; }
  .r-FAIL   { color: #c8102e; font-weight: 600; }
  .r-MANUAL { color: #d97706; font-weight: 600; }
  .r-INFO   { color: #4a6fa5; font-style: italic; }
  .badge    { display:inline-block; padding:2px 9px; border-radius:10px;
              font-size:.72em; font-weight:700; color:#fff; text-transform:uppercase; }
  .b-auto   { background:#2c2c54; }
  .b-manual { background:#6b6b6b; }
  footer    { margin-top: 32px; text-align: center; font-size: .76em; color: #aaa; }
</style>
</head>
<body>
<h1>&#x1F6E1; CIS Check Point Firewall Benchmark v1.1.0 &ndash; Audit Report</h1>
<div class="meta">
  Config file audited: <strong>$(basename "$CONFIG_FILE")</strong> &nbsp;|&nbsp;
  Generated: $(date) &nbsp;|&nbsp;
  Benchmark: CIS Check Point Firewall v1.1.0
</div>

<div class="summary">
  <div class="stat s-total"><div class="num">$total_checks</div><div class="label">Total Checks</div></div>
  <div class="stat s-pass"><div class="num">$total_pass</div><div class="label">Pass</div></div>
  <div class="stat s-fail"><div class="num">$total_fail</div><div class="label">Fail</div></div>
  <div class="stat s-manual"><div class="num">$total_manual</div><div class="label">Manual Review</div></div>
  <div class="stat s-info"><div class="num">$total_info</div><div class="label">Informational</div></div>
</div>

<div class="section-header">Section 1 &ndash; Password Policy</div>
<table><tr><th>#</th><th>Check ID</th><th>Description / CIS Benchmark</th><th>Result</th></tr>
HTMLEOF

prev_section=""
row=0
while IFS="," read -r benchmark result; do
    [ "$benchmark" = "Benchmark" ] && continue
    row=$((row+1))

    # Determine result class
    if echo "$result" | grep -q "^PASS"; then
        cls="PASS"
    elif echo "$result" | grep -q "^FAIL"; then
        cls="FAIL"
    elif echo "$result" | grep -q "^MANUAL"; then
        cls="MANUAL"
    else
        cls="INFO"
    fi

    # Section breaks in HTML
    check_id=$(echo "$benchmark" | awk '{print $1}')
    section=$(echo "$check_id" | cut -d. -f1)
    if [ "$section" != "$prev_section" ] && [ -n "$prev_section" ]; then
        case "$section" in
            2) section_name="Section 2 &ndash; System, SNMP, NTP, Backup, Authentication &amp; Logging" ;;
            3) section_name="Section 3 &ndash; Firewall Secure Settings" ;;
            *) section_name="Section $section" ;;
        esac
        echo "</table><div class=\"section-header\">$section_name</div><table><tr><th>#</th><th>Check ID</th><th>Description / CIS Benchmark</th><th>Result</th></tr>" >> "$HTML_FILE"
    fi
    prev_section="$section"

    desc=$(echo "$benchmark" | cut -d' ' -f2-)
    printf '<tr><td class="row-num">%s</td><td class="check-id"><strong>%s</strong></td><td class="check-desc">%s</td><td class="r-%s">%s</td></tr>\n' \
        "$row" "$check_id" "$desc" "$cls" "$result" >> "$HTML_FILE"
done < "$CSV_FILE"

cat >> "$HTML_FILE" <<HTMLEOF
</table>

<footer>
  CIS Check Point Firewall Benchmark v1.1.0 &bull;
  Audit script: checkpoint_cis_audit.sh &bull;
  Note: Checks marked MANUAL require verification in SmartConsole / SmartDashboard
</footer>
</body>
</html>
HTMLEOF

# ---- Console summary ----
echo ""
echo -e "${BOLD}============================================================${RESET}"
echo -e "${BOLD}  CIS Check Point Firewall v1.1.0 Audit Complete${RESET}"
echo "  Total Checks  : $total_checks"
echo -e "  ${GREEN}PASS${RESET}          : $total_pass"
echo -e "  ${RED}FAIL${RESET}          : $total_fail"
echo -e "  ${YELLOW}Manual/Review${RESET} : $total_manual"
echo -e "  ${CYAN}Informational${RESET} : $total_info"

# echo "  Log  : $LOG_FILE"
# echo "  CSV  : $CSV_FILE"

echo "  HTML : $HTML_FILE"
echo -e "${BOLD}============================================================${RESET}"
echo ""
echo "NOTE: Several checks (3.x firewall rules, SmartConsole settings) require"
echo "      manual verification in SmartConsole as they cannot be fully derived"
echo "      from the Gaia OS 'show configuration' output alone."

# rm -f "$CSV_FILE"
# rm -f "$LOG_FILE"
