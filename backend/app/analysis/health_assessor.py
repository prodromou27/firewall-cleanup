"""
Firewall Health & Best Practice Assessment.

Performs configuration-level health checks beyond policy rule analysis.
Reads the raw config file stored on disk (file_path on FirewallPolicy).

SAFETY NOTE: Read-only analysis. No firewall configuration is modified.
"""
from __future__ import annotations
import re
import ipaddress
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from app.models.policy import FirewallPolicy, FirewallRule, FirewallObject

# ── Status constants ──────────────────────────────────────────────────────────

PASS    = "pass"
WARN    = "warn"
FAIL    = "fail"
INFO    = "info"
UNKNOWN = "unknown"


def _check(
    check_id: str,
    category: str,
    title: str,
    status: str,
    severity: str,
    detail: str,
    recommendation: str = "",
    evidence: dict | None = None,
    requires_live: bool = False,
) -> dict:
    return {
        "check_id": check_id,
        "category": category,
        "title": title,
        "status": status,
        "severity": severity,
        "detail": detail,
        "recommendation": recommendation,
        "evidence": evidence or {},
        "requires_live_data": requires_live,
    }


# ── Generic config parser helpers ─────────────────────────────────────────────

def _parse_set_fields(section_text: str) -> Dict[str, str]:
    """Parse a flat config section (not edit/next) into {key: value}."""
    result = {}
    for line in section_text.splitlines():
        line = line.strip()
        if line.startswith("set "):
            parts = line[4:].split(None, 1)
            if parts:
                key = parts[0]
                val = parts[1].strip('"') if len(parts) > 1 else ""
                result[key] = val
    return result


def _parse_edit_blocks(section_text: str) -> List[Dict[str, Any]]:
    """Parse edit/next blocks into list of {_id, fields}."""
    entries = []
    lines = section_text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line.startswith("edit "):
            eid = line[5:].strip().strip('"')
            fields: Dict[str, str] = {}
            i += 1
            while i < len(lines):
                l = lines[i].strip()
                if l == "next":
                    break
                if l.startswith("set "):
                    parts = l[4:].split(None, 1)
                    if parts:
                        fields[parts[0]] = (parts[1].strip('"') if len(parts) > 1 else "")
                i += 1
            entries.append({"_id": eid, "fields": fields})
        i += 1
    return entries


def _extract_all_sections(content: str) -> Dict[str, str]:
    """Extract all top-level 'config ...' sections from a FortiGate config."""
    sections: Dict[str, str] = {}
    lines = content.splitlines()
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        if stripped.startswith("config "):
            name = stripped
            depth = 1
            body: List[str] = []
            i += 1
            while i < len(lines) and depth > 0:
                l = lines[i]
                s = l.strip()
                if s.startswith("config "):
                    depth += 1
                elif s == "end":
                    depth -= 1
                    if depth == 0:
                        break
                body.append(l)
                i += 1
            sections[name] = "\n".join(body)
        i += 1
    return sections


# ── FortiGate health checks ───────────────────────────────────────────────────

_RISKY_MGMT_PORTS   = {"80", "8080"}          # plain HTTP management
_WEAK_PROTOCOLS     = {"telnet", "http"}
_RISKY_ADMIN_PROTOS = {"telnet-no-banner", "http"}
_PUBLIC_PREFIXES    = (
    # anything that is NOT RFC1918 / loopback / link-local is "public"
)

def _is_rfc1918(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True   # can't parse → assume private, err on safe side


def run_fortigate_health(policy: FirewallPolicy, db: Session) -> List[dict]:
    checks: List[dict] = []

    # ── Load raw config ──────────────────────────────────────────────────────
    content = ""
    if policy.file_path:
        import os
        # Resolve relative paths against the backend working directory
        fpath = policy.file_path
        if not os.path.isabs(fpath):
            # Try relative to the module's package root
            base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            fpath = os.path.join(base, fpath)
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError:
            pass

    has_config = bool(content.strip())
    sections: Dict[str, str] = _extract_all_sections(content) if has_config else {}

    # ── Helper: add unknown check when data unavailable ──────────────────────
    def _no_data(check_id: str, category: str, title: str, severity: str = "Low") -> dict:
        return _check(
            check_id, category, title, UNKNOWN, severity,
            "Configuration data not available from static import.",
            "Run a live device sync or upload a full configuration export to enable this check.",
            requires_live=True,
        )

    # ──────────────────────────────────────────────────────────────────────────
    # 1. Firmware version
    # ──────────────────────────────────────────────────────────────────────────
    version_match = re.search(r'#config-version[=:]?\s*(\S+)', content) or \
                    re.search(r'version\s+(\d[\d.]+)', content[:2000], re.IGNORECASE)
    if version_match:
        ver = version_match.group(1)
        checks.append(_check(
            "fw_firmware_version", "Infrastructure", "Firmware Version",
            INFO, "Low",
            f"Detected firmware version: {ver}. Manually verify against FortiGate's current stable release.",
            "Keep firmware updated to the latest stable release to receive security patches.",
            evidence={"version": ver},
        ))
    else:
        checks.append(_no_data("fw_firmware_version", "Infrastructure", "Firmware Version", "Low"))

    # ──────────────────────────────────────────────────────────────────────────
    # 2–3. Admin access exposure & management protocols
    # ──────────────────────────────────────────────────────────────────────────
    sys_global = _parse_set_fields(sections.get("config system global", ""))

    if sys_global:
        # HTTPS admin port
        https_port = sys_global.get("admin-sport", "443")
        if https_port == "443":
            checks.append(_check(
                "fw_admin_https_port", "Access Control", "Admin HTTPS Port",
                WARN, "Medium",
                f"Admin HTTPS is on the standard port 443. "
                "Using a non-standard port reduces automated scanning exposure.",
                "Change the admin HTTPS port to a non-standard port (e.g. 8443) to reduce exposure.",
                evidence={"port": https_port},
            ))
        else:
            checks.append(_check(
                "fw_admin_https_port", "Access Control", "Admin HTTPS Port",
                PASS, "Medium",
                f"Admin HTTPS is on a non-standard port ({https_port}).",
                evidence={"port": https_port},
            ))

        # Telnet access
        telnet_en = sys_global.get("admin-telnet", "disable")
        checks.append(_check(
            "fw_telnet_disabled", "Access Control", "Telnet Management",
            PASS if telnet_en.lower() in ("disable", "disabled") else FAIL,
            "High",
            f"Telnet management: {telnet_en}. "
            + ("Telnet transmits credentials in clear text." if telnet_en.lower() not in ("disable", "disabled") else "Telnet is disabled ✓"),
            "Ensure Telnet is disabled. Use SSH for CLI access.",
            evidence={"admin-telnet": telnet_en},
        ))

        # HTTP access
        http_port = sys_global.get("admin-port", "0")
        if http_port not in ("0", ""):
            checks.append(_check(
                "fw_http_mgmt_disabled", "Access Control", "HTTP Management Interface",
                FAIL, "High",
                f"HTTP management interface is enabled on port {http_port}. "
                "HTTP transmits credentials in clear text.",
                "Disable HTTP management. Set 'admin-port 0' in system global.",
                evidence={"admin-port": http_port},
            ))
        else:
            checks.append(_check(
                "fw_http_mgmt_disabled", "Access Control", "HTTP Management Interface",
                PASS, "High", "HTTP management interface is disabled ✓",
            ))

        # Admin timeout
        timeout = sys_global.get("admintimeout", "5")
        try:
            to_val = int(timeout)
            status = PASS if to_val <= 15 else WARN
            checks.append(_check(
                "fw_admin_timeout", "Access Control", "Admin Session Timeout",
                status, "Low",
                f"Admin session timeout is {timeout} minutes. "
                + ("" if to_val <= 15 else "Consider reducing to 5–15 minutes."),
                "Set admintimeout to 5–15 minutes to limit exposure from unattended sessions.",
                evidence={"admintimeout": timeout},
            ))
        except ValueError:
            pass

    else:
        for cid, title, sev in [
            ("fw_admin_https_port", "Admin HTTPS Port", "Medium"),
            ("fw_telnet_disabled",  "Telnet Management", "High"),
            ("fw_http_mgmt_disabled", "HTTP Management Interface", "High"),
            ("fw_admin_timeout", "Admin Session Timeout", "Low"),
        ]:
            checks.append(_no_data(cid, "Access Control", title, sev))

    # ──────────────────────────────────────────────────────────────────────────
    # 4. Local admin accounts & trusted hosts
    # ──────────────────────────────────────────────────────────────────────────
    admin_section = sections.get("config system admin", "")
    if admin_section:
        admins = _parse_edit_blocks(admin_section)
        admin_count = len(admins)
        admins_no_trusted = []
        admins_default_pw = []
        admins_no_2fa = []
        accprofiles = []

        for a in admins:
            f = a["fields"]
            name = a["_id"]
            # Trusted hosts
            trusted = f.get("trusthost1", "0.0.0.0 0.0.0.0")
            if trusted in ("0.0.0.0 0.0.0.0", "0.0.0.0/0", ""):
                admins_no_trusted.append(name)
            # 2FA
            two_factor = f.get("two-factor", "disable")
            if two_factor.lower() in ("disable", ""):
                admins_no_2fa.append(name)
            # Profile
            prof = f.get("accprofile", "")
            if prof:
                accprofiles.append(f"{name}:{prof}")

        checks.append(_check(
            "fw_admin_count", "Authentication", "Local Admin Accounts",
            PASS if admin_count <= 3 else WARN,
            "Medium",
            f"{admin_count} local admin account{'s' if admin_count != 1 else ''} defined. "
            + ("Review whether all accounts are still required." if admin_count > 3 else ""),
            "Minimise the number of local admin accounts. Use RADIUS/LDAP for centralised auth where possible.",
            evidence={"count": admin_count, "accounts": [a["_id"] for a in admins]},
        ))

        if admins_no_trusted:
            checks.append(_check(
                "fw_trusted_hosts", "Access Control", "Trusted Hosts for Admin Accounts",
                FAIL, "High",
                f"Admin account(s) with no trusted-host restriction: {', '.join(admins_no_trusted)}. "
                "Without trusted hosts, management access is allowed from any IP.",
                "Configure 'trusthost1' on every admin account to restrict management access to known IPs.",
                evidence={"unrestricted_admins": admins_no_trusted},
            ))
        else:
            checks.append(_check(
                "fw_trusted_hosts", "Access Control", "Trusted Hosts for Admin Accounts",
                PASS, "High",
                "All admin accounts have trusted-host restrictions configured ✓",
            ))

        if admins_no_2fa:
            checks.append(_check(
                "fw_admin_2fa", "Authentication", "Admin Two-Factor Authentication",
                WARN, "Medium",
                f"Admin account(s) without 2FA: {', '.join(admins_no_2fa[:5])}{'…' if len(admins_no_2fa) > 5 else ''}.",
                "Enable two-factor authentication for all admin accounts that have remote access.",
                evidence={"no_2fa": admins_no_2fa},
            ))
        else:
            checks.append(_check(
                "fw_admin_2fa", "Authentication", "Admin Two-Factor Authentication",
                PASS, "Medium",
                "All admin accounts have two-factor authentication configured ✓",
            ))

    else:
        for cid, title, sev in [
            ("fw_admin_count",   "Local Admin Accounts", "Medium"),
            ("fw_trusted_hosts", "Trusted Hosts for Admin Accounts", "High"),
            ("fw_admin_2fa",     "Admin Two-Factor Authentication", "Medium"),
        ]:
            checks.append(_no_data(cid, "Authentication" if "admin_2fa" in cid or "admin_count" in cid else "Access Control", title, sev))

    # ──────────────────────────────────────────────────────────────────────────
    # 5. Password policy
    # ──────────────────────────────────────────────────────────────────────────
    pw_section = sections.get("config system password-policy", "")
    if pw_section:
        pw = _parse_set_fields(pw_section)
        pw_status = pw.get("status", "disable")
        if pw_status.lower() in ("enable", "enabled"):
            min_len = pw.get("min-length", "8")
            checks.append(_check(
                "fw_password_policy", "Authentication", "Password Policy",
                PASS, "Medium",
                f"Password policy is enabled. Minimum length: {min_len}.",
                evidence={"status": pw_status, "min-length": min_len},
            ))
        else:
            checks.append(_check(
                "fw_password_policy", "Authentication", "Password Policy",
                FAIL, "Medium",
                "Password policy is disabled. No minimum length or complexity is enforced.",
                "Enable the password policy under 'config system password-policy'.",
                evidence={"status": pw_status},
            ))
    else:
        checks.append(_no_data("fw_password_policy", "Authentication", "Password Policy", "Medium"))

    # ──────────────────────────────────────────────────────────────────────────
    # 6. NTP configuration
    # ──────────────────────────────────────────────────────────────────────────
    ntp_section = sections.get("config system ntp", "")
    if ntp_section:
        ntp = _parse_set_fields(ntp_section)
        ntpsync = ntp.get("ntpsync", "disable")
        if ntpsync.lower() in ("enable", "enabled"):
            checks.append(_check(
                "fw_ntp", "Infrastructure", "NTP Configuration",
                PASS, "Low",
                "NTP synchronisation is enabled ✓. Accurate time is essential for log correlation.",
                evidence={"ntpsync": ntpsync, "server": ntp.get("server", "")},
            ))
        else:
            checks.append(_check(
                "fw_ntp", "Infrastructure", "NTP Configuration",
                FAIL, "Medium",
                "NTP synchronisation is disabled. Log timestamps may be inaccurate or inconsistent.",
                "Enable NTP under 'config system ntp' and configure at least two reliable NTP servers.",
                evidence={"ntpsync": ntpsync},
            ))
    else:
        checks.append(_no_data("fw_ntp", "Infrastructure", "NTP Configuration", "Medium"))

    # ──────────────────────────────────────────────────────────────────────────
    # 7. DNS configuration
    # ──────────────────────────────────────────────────────────────────────────
    dns_section = sections.get("config system dns", "")
    if dns_section:
        dns = _parse_set_fields(dns_section)
        primary = dns.get("primary", "")
        secondary = dns.get("secondary", "")
        issues = []
        # Check for public/Google DNS being used (might indicate no internal DNS)
        for label, val in [("primary", primary), ("secondary", secondary)]:
            if val in ("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"):
                issues.append(f"{label} DNS is a public resolver ({val})")
        if not primary:
            issues.append("No primary DNS configured")

        if issues:
            checks.append(_check(
                "fw_dns", "Infrastructure", "DNS Configuration",
                WARN, "Low",
                f"DNS configuration concern: {'; '.join(issues)}. "
                "Using public DNS resolvers may leak internal hostnames.",
                "Configure internal or on-premises DNS servers. Avoid using public resolvers for device DNS.",
                evidence={"primary": primary, "secondary": secondary, "issues": issues},
            ))
        else:
            checks.append(_check(
                "fw_dns", "Infrastructure", "DNS Configuration",
                PASS, "Low",
                f"DNS configured: primary={primary or 'not set'}, secondary={secondary or 'not set'}.",
                evidence={"primary": primary, "secondary": secondary},
            ))
    else:
        checks.append(_no_data("fw_dns", "Infrastructure", "DNS Configuration", "Low"))

    # ──────────────────────────────────────────────────────────────────────────
    # 8. Logging configuration
    # ──────────────────────────────────────────────────────────────────────────
    log_syslog = sections.get("config log syslogd setting", "") or sections.get("config log syslog setting", "")
    log_fortianalyzer = sections.get("config log fortianalyzer setting", "")
    log_memory = sections.get("config log memory setting", "")

    log_destinations = []
    if log_syslog:
        s = _parse_set_fields(log_syslog)
        if s.get("status", "disable").lower() in ("enable", "enabled"):
            log_destinations.append(f"Syslog → {s.get('server', 'unknown')}")
    if log_fortianalyzer:
        s = _parse_set_fields(log_fortianalyzer)
        if s.get("status", "disable").lower() in ("enable", "enabled"):
            log_destinations.append(f"FortiAnalyzer → {s.get('server', 'unknown')}")
    if log_memory:
        s = _parse_set_fields(log_memory)
        if s.get("status", "disable").lower() in ("enable", "enabled"):
            log_destinations.append("Local memory")

    if log_destinations:
        checks.append(_check(
            "fw_logging", "Logging & Monitoring", "Log Forwarding",
            PASS, "High",
            f"Active log destinations: {', '.join(log_destinations)} ✓",
            evidence={"destinations": log_destinations},
        ))
    elif log_syslog or log_fortianalyzer or log_memory:
        checks.append(_check(
            "fw_logging", "Logging & Monitoring", "Log Forwarding",
            FAIL, "High",
            "No active log forwarding destination found. Logs may only be stored locally.",
            "Configure Syslog or FortiAnalyzer log forwarding for centralised log management.",
        ))
    else:
        checks.append(_no_data("fw_logging", "Logging & Monitoring", "Log Forwarding", "High"))

    # ──────────────────────────────────────────────────────────────────────────
    # 9. SNMP configuration
    # ──────────────────────────────────────────────────────────────────────────
    snmp_section = sections.get("config system snmp sysinfo", "") or sections.get("config system snmp community", "")
    if snmp_section:
        snmp_fields = _parse_set_fields(snmp_section)
        snmp_status = snmp_fields.get("status", "disable")
        if snmp_status.lower() in ("enable", "enabled"):
            # Check for SNMPv1/v2 (less secure)
            communities = _parse_edit_blocks(sections.get("config system snmp community", ""))
            v1v2_communities = [c["_id"] for c in communities if c["fields"].get("status", "disable").lower() in ("enable", "enabled")]
            if v1v2_communities:
                checks.append(_check(
                    "fw_snmp", "Logging & Monitoring", "SNMP Configuration",
                    WARN, "Medium",
                    f"SNMPv1/v2 communities enabled: {', '.join(v1v2_communities[:3])}. "
                    "SNMPv1/v2 community strings are sent in clear text.",
                    "Use SNMPv3 with authentication and encryption. Restrict SNMP access by source IP.",
                    evidence={"communities": v1v2_communities},
                ))
            else:
                checks.append(_check(
                    "fw_snmp", "Logging & Monitoring", "SNMP Configuration",
                    INFO, "Medium",
                    "SNMP is enabled. Verify SNMPv3 is used with auth/encryption.",
                    "Ensure SNMP community strings are not using default values ('public'/'private').",
                ))
        else:
            checks.append(_check(
                "fw_snmp", "Logging & Monitoring", "SNMP Configuration",
                INFO, "Low", "SNMP is disabled.",
                "If SNMP monitoring is not required, disabling it reduces the attack surface.",
            ))
    else:
        checks.append(_no_data("fw_snmp", "Logging & Monitoring", "SNMP Configuration", "Low"))

    # ──────────────────────────────────────────────────────────────────────────
    # 10. Central management (FortiManager)
    # ──────────────────────────────────────────────────────────────────────────
    cm_section = sections.get("config system central-management", "")
    if cm_section:
        cm = _parse_set_fields(cm_section)
        cm_type = cm.get("type", "")
        if cm_type.lower() in ("fortimanager", "fortiguard"):
            checks.append(_check(
                "fw_central_mgmt", "Network Management", "Central Management",
                PASS, "Low",
                f"Device is registered to a central management platform: {cm_type}. "
                f"Server: {cm.get('fmg', cm.get('fmg-ip', 'unknown'))}.",
                evidence={"type": cm_type},
            ))
        else:
            checks.append(_check(
                "fw_central_mgmt", "Network Management", "Central Management",
                INFO, "Low",
                "No central management platform (FortiManager) detected. "
                "Central management provides policy consistency and audit trails.",
                "Consider deploying FortiManager for centralised management, audit logging, and configuration backup.",
            ))
    else:
        checks.append(_no_data("fw_central_mgmt", "Network Management", "Central Management", "Low"))

    # ──────────────────────────────────────────────────────────────────────────
    # 11. HA status
    # ──────────────────────────────────────────────────────────────────────────
    ha_section = sections.get("config system ha", "")
    if ha_section:
        ha = _parse_set_fields(ha_section)
        ha_mode = ha.get("mode", "standalone")
        if ha_mode.lower() in ("a-a", "a-p", "active-active", "active-passive"):
            checks.append(_check(
                "fw_ha_status", "Infrastructure", "High Availability",
                PASS, "Low",
                f"HA mode: {ha_mode}. Group: {ha.get('group-name', 'N/A')}.",
                evidence={"mode": ha_mode, "group": ha.get("group-name", "")},
            ))
        else:
            checks.append(_check(
                "fw_ha_status", "Infrastructure", "High Availability",
                INFO, "Low",
                "Device is operating in standalone mode (no HA configured). "
                "A single point of failure exists.",
                "Consider deploying in Active-Passive HA for perimeter firewalls.",
                evidence={"mode": ha_mode},
            ))
    else:
        checks.append(_no_data("fw_ha_status", "Infrastructure", "High Availability", "Low"))

    # ──────────────────────────────────────────────────────────────────────────
    # 12. Interface management access & unused interfaces
    # ──────────────────────────────────────────────────────────────────────────
    intf_section = sections.get("config system interface", "")
    if intf_section:
        interfaces = _parse_edit_blocks(intf_section)
        mgmt_interfaces = []
        risky_mgmt = []
        up_interfaces = []

        for intf in interfaces:
            f = intf["fields"]
            name = intf["_id"]
            allowaccess = f.get("allowaccess", "")
            status = f.get("status", "up")
            ip = f.get("ip", "")

            if status.lower() == "up":
                up_interfaces.append(name)

            if allowaccess:
                protocols = allowaccess.split()
                mgmt_interfaces.append(f"{name} [{allowaccess}]")
                risky = [p for p in protocols if p.lower() in ("http", "telnet")]
                if risky:
                    risky_mgmt.append(f"{name}: {', '.join(risky)}")

        if risky_mgmt:
            checks.append(_check(
                "fw_interface_mgmt", "Access Control", "Interface Management Protocols",
                FAIL, "High",
                f"Insecure management protocols enabled on interfaces: {'; '.join(risky_mgmt)}.",
                "Remove 'http' and 'telnet' from 'allowaccess' on all interfaces. Use HTTPS and SSH only.",
                evidence={"risky_interfaces": risky_mgmt},
            ))
        elif mgmt_interfaces:
            checks.append(_check(
                "fw_interface_mgmt", "Access Control", "Interface Management Protocols",
                PASS, "High",
                f"No insecure management protocols on interfaces. Management enabled on: {len(mgmt_interfaces)} interface(s).",
                evidence={"count": len(mgmt_interfaces)},
            ))
        else:
            checks.append(_check(
                "fw_interface_mgmt", "Access Control", "Interface Management Protocols",
                INFO, "High",
                "No interface management access configuration found in config.",
            ))

        # Interface count
        total_intfs = len(interfaces)
        checks.append(_check(
            "fw_interface_count", "Infrastructure", "Interface Inventory",
            INFO, "Low",
            f"{total_intfs} interfaces defined, {len(up_interfaces)} active.",
            "Review interfaces periodically to ensure unused interfaces are administratively down.",
            evidence={"total": total_intfs, "up": len(up_interfaces)},
        ))
    else:
        checks.append(_no_data("fw_interface_mgmt", "Access Control", "Interface Management Protocols", "High"))
        checks.append(_no_data("fw_interface_count", "Infrastructure", "Interface Inventory", "Low"))

    # ──────────────────────────────────────────────────────────────────────────
    # 13. Security profiles on rules (IPS/AV/Web Filtering)
    # ──────────────────────────────────────────────────────────────────────────
    rules = db.query(FirewallRule).filter(
        FirewallRule.policy_id == policy.id,
        FirewallRule.enabled == True,
    ).all()
    allow_rules = [r for r in rules if (r.action or "").lower() in ("accept", "allow", "permit")]

    if allow_rules:
        raw_fields_with_profiles = []
        profile_keys = {"utm-status", "ips-sensor", "av-profile", "webfilter-profile",
                        "application-list", "ssl-ssh-profile", "profile-group",
                        "profile-type", "dnsfilter-profile", "emailfilter-profile"}

        rules_with_profiles = []
        rules_without_profiles = []

        for r in allow_rules:
            rd = r.raw_data or {}
            has_profile = any(k in rd for k in profile_keys) and \
                          rd.get("utm-status", "disable").lower() not in ("disable", "")
            # Check applications list (Check Point style)
            has_app = bool(r.applications)
            if has_profile or has_app:
                rules_with_profiles.append(r.rule_id or str(r.rule_number))
            else:
                rules_without_profiles.append(r.rule_id or str(r.rule_number))

        pct_with = round(len(rules_with_profiles) / max(len(allow_rules), 1) * 100)
        status = PASS if pct_with >= 80 else (WARN if pct_with >= 40 else FAIL)
        checks.append(_check(
            "fw_security_profiles", "Security Controls", "Security Profile Usage (IPS/AV/Web Filter)",
            status, "High",
            f"{len(rules_with_profiles)}/{len(allow_rules)} allow rules ({pct_with}%) have security profiles applied. "
            + (f"{len(rules_without_profiles)} rules have no UTM inspection." if rules_without_profiles else ""),
            "Apply IPS, AV, and web-filtering profiles to all internet-facing allow rules.",
            evidence={
                "total_allow": len(allow_rules),
                "with_profiles": len(rules_with_profiles),
                "without_profiles": len(rules_without_profiles),
                "pct": pct_with,
            },
        ))
    else:
        checks.append(_check(
            "fw_security_profiles", "Security Controls", "Security Profile Usage (IPS/AV/Web Filter)",
            UNKNOWN, "High", "No enabled allow rules found to assess.",
        ))

    # ──────────────────────────────────────────────────────────────────────────
    # 14. Backup configuration status
    # ──────────────────────────────────────────────────────────────────────────
    # FortiGate doesn't expose backup schedule in config text — note as live data
    checks.append(_check(
        "fw_backup", "Network Management", "Configuration Backup",
        UNKNOWN, "Medium",
        "Configuration backup schedule cannot be assessed from a static config export.",
        "Verify automated configuration backups are scheduled via FortiManager or scheduled scripts. "
        "Test restoration regularly.",
        requires_live=True,
    ))

    return checks


# ── Check Point health checks ─────────────────────────────────────────────────

_CLEANUP_KEYWORDS  = {"cleanup", "drop all", "deny all", "block all", "catch-all", "default deny"}
_STEALTH_KEYWORDS  = {"stealth", "protect mgmt", "protect management", "fw mgmt", "management access"}


def run_checkpoint_health(policy: FirewallPolicy, db: Session) -> List[dict]:
    checks: List[dict] = []

    rules = db.query(FirewallRule).filter(
        FirewallRule.policy_id == policy.id
    ).order_by(FirewallRule.rule_number).all()

    objects = db.query(FirewallObject).filter(
        FirewallObject.policy_id == policy.id
    ).all()

    enabled_rules = [r for r in rules if r.enabled]
    allow_rules = [r for r in enabled_rules if (r.action or "").lower() in ("accept", "allow", "permit")]

    # ──────────────────────────────────────────────────────────────────────────
    # 1. Cleanup rule presence
    # ──────────────────────────────────────────────────────────────────────────
    def _is_cleanup(r: FirewallRule) -> bool:
        name = (r.rule_name or "").lower()
        comment = (r.comments or "").lower()
        action = (r.action or "").lower()
        sources = [s.lower() for s in (r.sources or [])]
        dests   = [d.lower() for d in (r.destinations or [])]
        is_deny = action in ("drop", "deny", "reject", "block")
        is_any  = any(s in ("any", "all") for s in sources) and any(d in ("any", "all") for d in dests)
        has_kw  = any(kw in name or kw in comment for kw in _CLEANUP_KEYWORDS)
        return (is_deny and is_any) or has_kw

    cleanup_rules = [r for r in rules if _is_cleanup(r)]
    # Check if last enabled rule is cleanup
    last_rule = enabled_rules[-1] if enabled_rules else None
    last_is_cleanup = last_rule and _is_cleanup(last_rule)

    if cleanup_rules and last_is_cleanup:
        checks.append(_check(
            "cp_cleanup_rule", "Policy Hygiene", "Cleanup Rule (Drop All) Presence",
            PASS, "High",
            f"Cleanup/drop-all rule found at position {last_rule.rule_number} (last rule) ✓",
            evidence={"rule_name": last_rule.rule_name, "rule_number": last_rule.rule_number},
        ))
    elif cleanup_rules:
        checks.append(_check(
            "cp_cleanup_rule", "Policy Hygiene", "Cleanup Rule (Drop All) Presence",
            WARN, "High",
            f"Cleanup rule found but it is not the last rule. "
            f"Rules after the cleanup rule will never be reached.",
            "Ensure the cleanup/drop-all rule is the final rule in the policy.",
            evidence={"positions": [r.rule_number for r in cleanup_rules]},
        ))
    else:
        checks.append(_check(
            "cp_cleanup_rule", "Policy Hygiene", "Cleanup Rule (Drop All) Presence",
            FAIL, "High",
            "No cleanup (drop-all) rule found. Without an explicit deny-all, "
            "the implicit cleanup rule may allow unintended traffic or not log dropped packets.",
            "Add an explicit drop-all rule as the last rule in the policy with logging enabled.",
        ))

    # ──────────────────────────────────────────────────────────────────────────
    # 2. Stealth rule presence
    # ──────────────────────────────────────────────────────────────────────────
    def _is_stealth(r: FirewallRule) -> bool:
        name = (r.rule_name or "").lower()
        comment = (r.comments or "").lower()
        return any(kw in name or kw in comment for kw in _STEALTH_KEYWORDS)

    stealth_rules = [r for r in rules if _is_stealth(r)]
    if stealth_rules:
        first_stealth = stealth_rules[0]
        checks.append(_check(
            "cp_stealth_rule", "Policy Hygiene", "Stealth Rule (Management Protection)",
            PASS if first_stealth.rule_number and first_stealth.rule_number <= 5 else WARN,
            "High",
            f"Stealth rule found at position {first_stealth.rule_number}. "
            + ("Positioned early in policy ✓" if first_stealth.rule_number and first_stealth.rule_number <= 5
               else "Consider moving it to the top of the policy."),
            evidence={"rule_name": first_stealth.rule_name, "rule_number": first_stealth.rule_number},
        ))
    else:
        checks.append(_check(
            "cp_stealth_rule", "Policy Hygiene", "Stealth Rule (Management Protection)",
            WARN, "High",
            "No stealth rule detected. The firewall management interface may be reachable through the policy.",
            "Add a stealth rule early in the policy to block all traffic to the firewall's own IP addresses "
            "except from authorised management hosts.",
        ))

    # ──────────────────────────────────────────────────────────────────────────
    # 3. Logging on allow rules
    # ──────────────────────────────────────────────────────────────────────────
    allow_no_log = [r for r in allow_rules if not r.logging_enabled]
    log_pct = round((1 - len(allow_no_log) / max(len(allow_rules), 1)) * 100)
    checks.append(_check(
        "cp_logging", "Logging & Monitoring", "Rule Logging Coverage",
        PASS if log_pct >= 90 else (WARN if log_pct >= 70 else FAIL),
        "High",
        f"Logging enabled on {log_pct}% of allow rules ({len(allow_rules) - len(allow_no_log)}/{len(allow_rules)}).",
        "Enable logging on all allow rules. Disable rules should also log to detect policy bypass attempts.",
        evidence={"log_pct": log_pct, "no_log_count": len(allow_no_log)},
    ))

    # ──────────────────────────────────────────────────────────────────────────
    # 4. Policy sections / layers
    # ──────────────────────────────────────────────────────────────────────────
    sections_found = set(r.section for r in rules if r.section)
    if sections_found:
        checks.append(_check(
            "cp_rulebase_layers", "Policy Hygiene", "Rulebase Layers / Sections",
            INFO, "Low",
            f"{len(sections_found)} policy section(s)/layer(s) found: {', '.join(sorted(sections_found)[:5])}.",
            "Ensure each layer has a clear purpose and appropriate logging. "
            "Inline layers should have explicit cleanup rules.",
            evidence={"sections": sorted(sections_found)},
        ))
    else:
        checks.append(_check(
            "cp_rulebase_layers", "Policy Hygiene", "Rulebase Layers / Sections",
            INFO, "Low", "No rulebase sections/layers detected.",
        ))

    # ──────────────────────────────────────────────────────────────────────────
    # 5. Implied rules visibility
    # ──────────────────────────────────────────────────────────────────────────
    checks.append(_check(
        "cp_implied_rules", "Policy Hygiene", "Implied Rules",
        INFO, "Low",
        "Check Point implied rules (control, management, IKE) are not visible in the exported policy. "
        "Verify implied rules are set to 'Log' or 'Last' in SmartConsole policy properties.",
        "Review implied rules in SmartConsole → Policy Properties → Implied Rules. "
        "Ensure they are logged and minimally permissive.",
        requires_live=True,
    ))

    # ──────────────────────────────────────────────────────────────────────────
    # 6. Threat Prevention policy usage
    # ──────────────────────────────────────────────────────────────────────────
    rules_with_tp = [r for r in allow_rules if r.applications or
                     any(s in (r.raw_data or {}).get("content", "").lower()
                         for s in ("ips", "av", "threat", "inspection"))
                     ]
    tp_pct = round(len(rules_with_tp) / max(len(allow_rules), 1) * 100)
    checks.append(_check(
        "cp_threat_prevention", "Security Controls", "Threat Prevention Policy",
        INFO if not allow_rules else (PASS if tp_pct >= 70 else WARN),
        "High",
        f"Application/content inspection data available for {tp_pct}% of allow rules. "
        "Verify a Threat Prevention policy (IPS/AV/URL filtering) is installed on the gateway.",
        "Ensure a Threat Prevention profile is applied to all internet-facing allow rules. "
        "Enable Application Control, IPS, and Anti-Bot blades.",
        evidence={"rules_with_inspection": len(rules_with_tp), "total_allow": len(allow_rules)},
    ))

    # ──────────────────────────────────────────────────────────────────────────
    # 7. Anti-spoofing (from objects / interfaces)
    # ──────────────────────────────────────────────────────────────────────────
    checks.append(_check(
        "cp_anti_spoofing", "Security Controls", "Anti-Spoofing Configuration",
        UNKNOWN, "High",
        "Anti-spoofing topology cannot be assessed from a static policy export.",
        "Verify anti-spoofing is enabled on all gateway interfaces in SmartConsole → Topology. "
        "Each interface should have topology defined to 'This Network Behind This Interface'.",
        requires_live=True,
    ))

    # ──────────────────────────────────────────────────────────────────────────
    # 8. Policy install targets
    # ──────────────────────────────────────────────────────────────────────────
    install_targets = set()
    for r in rules:
        for t in (r.install_on or []):
            install_targets.add(t)
    if install_targets:
        checks.append(_check(
            "cp_install_targets", "Policy Hygiene", "Policy Install Targets",
            INFO, "Low",
            f"Policy install targets found: {', '.join(sorted(install_targets)[:5])}.",
            "Verify all install targets are still active gateways. Remove obsolete targets.",
            evidence={"targets": sorted(install_targets)},
        ))
    else:
        checks.append(_check(
            "cp_install_targets", "Policy Hygiene", "Policy Install Targets",
            INFO, "Low",
            "No explicit install targets found in policy data. Applies to all gateways by default.",
            requires_live=True,
        ))

    # ──────────────────────────────────────────────────────────────────────────
    # 9. Administrator roles
    # ──────────────────────────────────────────────────────────────────────────
    checks.append(_check(
        "cp_admin_roles", "Authentication", "Administrator Roles",
        UNKNOWN, "Medium",
        "Administrator role configuration is not available from a static policy export.",
        "Review SmartConsole → Manage & Settings → Administrators. "
        "Ensure least-privilege roles are assigned and unused accounts are removed.",
        requires_live=True,
    ))

    # ──────────────────────────────────────────────────────────────────────────
    # 10. Cluster/HA status
    # ──────────────────────────────────────────────────────────────────────────
    checks.append(_check(
        "cp_cluster_status", "Infrastructure", "Gateway Cluster Status",
        UNKNOWN, "Low",
        "Gateway cluster status requires a live device connection.",
        "Monitor cluster state via SmartConsole or cphaprob stat. Investigate any 'down' or 'problem' state.",
        requires_live=True,
    ))

    # ──────────────────────────────────────────────────────────────────────────
    # 11. Management / gateway version
    # ──────────────────────────────────────────────────────────────────────────
    checks.append(_check(
        "cp_version", "Infrastructure", "Management & Gateway Version",
        UNKNOWN, "Medium",
        "Version information is not available from a static policy export.",
        "Verify the management server and all gateways are running a supported version (R80.40+). "
        "Apply hotfixes and jumbo take recommended by Check Point.",
        requires_live=True,
    ))

    return checks


# ── NAT Review ────────────────────────────────────────────────────────────────

_RISKY_EXPOSED_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    389: "LDAP", 443: "HTTPS", 445: "SMB",
    1433: "MSSQL", 1521: "Oracle DB", 3306: "MySQL/MariaDB",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP Alt", 8443: "HTTPS Alt",
    27017: "MongoDB",
}

_HIGH_RISK_PORTS = {3389, 445, 1433, 1521, 3306, 5432, 5900, 6379, 27017, 23}


def run_nat_review(policy: FirewallPolicy, db: Session) -> dict:
    """Analyse NAT rules and build a NAT inventory."""
    rules = db.query(FirewallRule).filter(
        FirewallRule.policy_id == policy.id
    ).order_by(FirewallRule.rule_number).all()

    nat_rules = [r for r in rules if r.nat_enabled]
    enabled_nat = [r for r in nat_rules if r.enabled]

    # Build NAT entries from raw_data
    nat_entries = []
    for r in nat_rules:
        rd = r.raw_data or {}
        entry = {
            "rule_id": r.rule_id or str(r.rule_number),
            "rule_number": r.rule_number,
            "rule_name": r.rule_name or f"Rule {r.rule_id}",
            "enabled": r.enabled,
            "action": r.action,
            "sources": r.sources or [],
            "destinations": r.destinations or [],
            "services": r.services or [],
            "nat_type": rd.get("nat_type", rd.get("nat", "snat")),
            "nat_ip": rd.get("nat-ip", rd.get("ippool", "")),
            "nat_port": rd.get("nat-port", ""),
            "comments": r.comments or "",
            "hit_count": r.hit_count,
        }
        nat_entries.append(entry)

    # Detect unused NAT rules (zero hits where data exists)
    unused_nat = [e for e in nat_entries if e["enabled"] and e["hit_count"] == 0]

    # Detect duplicate NAT (same sources + destinations + services)
    seen_nat: Dict[str, list] = {}
    for e in nat_entries:
        key = (
            tuple(sorted(e["sources"])),
            tuple(sorted(e["destinations"])),
            tuple(sorted(e["services"])),
        )
        seen_nat.setdefault(str(key), []).append(e)
    duplicate_nat = [entries for entries in seen_nat.values() if len(entries) > 1]

    # Public IP exposure — destinations that look like public IPs
    public_exposures = []
    objects = db.query(FirewallObject).filter(
        FirewallObject.policy_id == policy.id
    ).all()
    obj_map = {o.object_name: o for o in objects}

    for rule in rules:
        if not rule.enabled:
            continue
        action = (rule.action or "").lower()
        if action not in ("accept", "allow", "permit"):
            continue

        # Check sources — if any is public-looking, this might be internet-facing
        for svc_name in (rule.services or []):
            obj = obj_map.get(svc_name)
            if obj and obj.port_start:
                port = obj.port_start
                if port in _HIGH_RISK_PORTS and rule.nat_enabled:
                    dst_str = ", ".join((rule.destinations or [])[:3])
                    public_exposures.append({
                        "rule_id": rule.rule_id or str(rule.rule_number),
                        "rule_name": rule.rule_name or f"Rule {rule.rule_id}",
                        "service": svc_name,
                        "port": port,
                        "port_label": _RISKY_EXPOSED_PORTS.get(port, str(port)),
                        "destinations": rule.destinations or [],
                        "risk": "High" if port in _HIGH_RISK_PORTS else "Medium",
                    })

    return {
        "total_nat_rules": len(nat_rules),
        "enabled_nat_rules": len(enabled_nat),
        "disabled_nat_rules": len(nat_rules) - len(enabled_nat),
        "unused_nat_rules": unused_nat,
        "duplicate_nat_groups": [
            {"rules": [e["rule_name"] for e in grp], "count": len(grp)}
            for grp in duplicate_nat
        ],
        "nat_entries": nat_entries,
        "public_exposures": public_exposures,
    }


# ── Attack Surface ────────────────────────────────────────────────────────────

_INTERNET_NAMES = {
    "any", "all", "internet", "external", "wan", "untrust",
    "outside", "public", "ext", "inet", "0.0.0.0/0",
}

_EXPOSED_SERVICES = {
    "rdp": 3389, "ssh": 22, "telnet": 23, "ftp": 21,
    "smb": 445, "http": 80, "https": 443,
    "smtp": 25, "dns": 53, "ldap": 389, "ldaps": 636,
    "mssql": 1433, "mysql": 3306, "postgresql": 5432,
    "vnc": 5900, "redis": 6379, "mongodb": 27017,
    "oracle": 1521, "snmp": 161, "nfs": 2049, "rpc": 111,
}

_HIGH_RISK_SERVICE_NAMES = {"rdp", "smb", "telnet", "mssql", "mysql", "oracle",
                              "postgresql", "vnc", "redis", "mongodb"}


def run_attack_surface(policy: FirewallPolicy, db: Session) -> dict:
    """Identify internet-facing rules and build an exposure inventory."""
    rules = db.query(FirewallRule).filter(
        FirewallRule.policy_id == policy.id,
        FirewallRule.enabled == True,
    ).all()

    allow_rules = [r for r in rules if (r.action or "").lower() in ("accept", "allow", "permit")]

    objects = db.query(FirewallObject).filter(
        FirewallObject.policy_id == policy.id
    ).all()
    obj_map = {o.object_name.lower(): o for o in objects}

    def _is_internet_facing(names: List[str]) -> bool:
        for n in names:
            if n.lower() in _INTERNET_NAMES:
                return True
            obj = obj_map.get(n.lower())
            if obj and obj.value:
                try:
                    net = ipaddress.ip_network(obj.value, strict=False)
                    if not net.is_private and not net.is_loopback:
                        return True
                except ValueError:
                    pass
        return False

    def _svc_label(name: str) -> tuple[str, int | None, str]:
        """Returns (label, port, risk_level)."""
        n = name.lower()
        for svc, port in _EXPOSED_SERVICES.items():
            if svc in n:
                risk = "High" if svc in _HIGH_RISK_SERVICE_NAMES else "Medium"
                return svc.upper(), port, risk
        # Check object port
        obj = obj_map.get(n)
        if obj and obj.port_start:
            port = obj.port_start
            label = _RISKY_EXPOSED_PORTS.get(port, f"Port {port}")
            risk = "High" if port in _HIGH_RISK_PORTS else "Medium"
            return label, port, risk
        return name, None, "Low"

    internet_rules = []
    exposed_services: Dict[str, dict] = {}

    for rule in allow_rules:
        src_internet = _is_internet_facing(rule.sources or [])
        dst_internet = _is_internet_facing(rule.destinations or [])

        if not (src_internet or dst_internet):
            continue

        direction = "inbound" if src_internet else "outbound"
        rule_svcs = rule.services or []

        svc_details = []
        for svc_name in rule_svcs:
            label, port, risk = _svc_label(svc_name)
            svc_details.append({"name": svc_name, "label": label, "port": port, "risk": risk})
            svc_key = label or svc_name
            if svc_key not in exposed_services:
                exposed_services[svc_key] = {
                    "service": label or svc_name,
                    "port": port,
                    "risk": risk,
                    "rule_count": 0,
                    "rules": [],
                }
            exposed_services[svc_key]["rule_count"] += 1
            exposed_services[svc_key]["rules"].append(
                rule.rule_id or str(rule.rule_number)
            )

        # If no specific service — "any"
        if not rule_svcs:
            svc_key = "Any"
            if svc_key not in exposed_services:
                exposed_services[svc_key] = {
                    "service": "Any",
                    "port": None,
                    "risk": "High",
                    "rule_count": 0,
                    "rules": [],
                }
            exposed_services[svc_key]["rule_count"] += 1
            exposed_services[svc_key]["rules"].append(rule.rule_id or str(rule.rule_number))

        internet_rules.append({
            "rule_id": rule.rule_id or str(rule.rule_number),
            "rule_name": rule.rule_name or f"Rule {rule.rule_id}",
            "rule_number": rule.rule_number,
            "direction": direction,
            "sources": rule.sources or [],
            "destinations": rule.destinations or [],
            "services": svc_details,
            "nat_enabled": rule.nat_enabled,
            "logging_enabled": rule.logging_enabled,
            "hit_count": rule.hit_count,
        })

    # Risk summary
    high_risk = [r for r in internet_rules if any(s.get("risk") == "High" for s in r["services"])]
    no_log    = [r for r in internet_rules if not r["logging_enabled"]]

    exposed_svc_list = sorted(
        exposed_services.values(),
        key=lambda x: (0 if x["risk"] == "High" else 1 if x["risk"] == "Medium" else 2)
    )

    return {
        "total_internet_rules": len(internet_rules),
        "high_risk_rules": len(high_risk),
        "rules_without_logging": len(no_log),
        "internet_rules": internet_rules,
        "exposed_services": exposed_svc_list,
        "risky_services": [s for s in exposed_svc_list if s["risk"] == "High"],
    }


# ── Orchestrator ──────────────────────────────────────────────────────────────

def run_health_assessment(policy_id: str, db: Session) -> dict:
    """Run the full health assessment for a policy."""
    policy = db.query(FirewallPolicy).filter(FirewallPolicy.id == policy_id).first()
    if not policy:
        raise ValueError(f"Policy {policy_id} not found")

    vendor = (policy.vendor or "").lower()

    if "fortigate" in vendor or "forti" in vendor:
        checks = run_fortigate_health(policy, db)
    elif "checkpoint" in vendor or "check point" in vendor or "cp" in vendor:
        checks = run_checkpoint_health(policy, db)
    else:
        checks = run_fortigate_health(policy, db)  # best-effort generic

    # Summary counts
    by_status = {}
    by_category = {}
    for c in checks:
        by_status[c["status"]] = by_status.get(c["status"], 0) + 1
        cat = c["category"]
        if cat not in by_category:
            by_category[cat] = {"pass": 0, "warn": 0, "fail": 0, "unknown": 0, "info": 0}
        by_category[cat][c["status"]] = by_category[cat].get(c["status"], 0) + 1

    # Overall health score — weighted by severity, only checks with real data
    sev_weight = {"High": 3, "Medium": 2, "Low": 1}
    scored = [c for c in checks if c["status"] in (PASS, WARN, FAIL)]
    score_map = {PASS: 100, WARN: 60, FAIL: 0}
    if scored:
        total_w = sum(sev_weight.get(c["severity"], 1) for c in scored)
        health_score = round(
            sum(score_map[c["status"]] * sev_weight.get(c["severity"], 1) for c in scored)
            / max(total_w, 1)
        )
    else:
        health_score = None   # not enough data
    scored_count = len(scored)
    data_coverage = round(scored_count / max(len(checks), 1) * 100)

    nat_data = run_nat_review(policy, db)
    surface_data = run_attack_surface(policy, db)

    return {
        "policy_id": policy_id,
        "vendor": policy.vendor,
        "firewall_name": policy.firewall_name,
        "health_score": health_score,
        "data_coverage_pct": data_coverage,
        "checks": checks,
        "summary": {
            "total": len(checks),
            "pass": by_status.get(PASS, 0),
            "warn": by_status.get(WARN, 0),
            "fail": by_status.get(FAIL, 0),
            "info": by_status.get(INFO, 0),
            "unknown": by_status.get(UNKNOWN, 0),
        },
        "by_category": by_category,
        "nat": nat_data,
        "attack_surface": surface_data,
    }
