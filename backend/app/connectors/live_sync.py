"""
Live-sync orchestrator.

Pulls data from a live firewall via connector, translates to the normalised
ParseResult schema, persists to DB, runs analysis, and records a revision.

Flow:
  1. Connect to firewall
  2. Fetch rules + objects + hit counts
  3. Translate connector output → normalised format (same as file-upload parsers)
  4. Persist rules / objects to DB
  5. Run analysis engine
  6. Save PolicyRevision with per-rule change diff
  7. Update FirewallDevice.sync_status

SAFETY: This module is strictly read-only.  It never calls any connector
method that modifies a firewall object or policy.
"""
import hashlib
import json
import re
import logging
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from app.models.device import FirewallDevice
from app.models.policy import FirewallPolicy, FirewallRule, FirewallObject, ObjectMember
from app.analysis.engine import run_analysis

logger = logging.getLogger(__name__)


def _fgt_model_from_serial(serial: str) -> str:
    """
    Derive a human-readable model string from a FortiGate serial number.
    FortiGate serials typically start with a model prefix, e.g.:
      FGT60F -> FortiGate 60F
      FG100E -> FortiGate 100E
      FGT200D -> FortiGate 200D
      FWF61E -> FortiWiFi 61E
      FG-VM64 -> FortiGate VM64 (virtual)
    """
    import re
    s = serial.upper().split("-")[0]  # strip trailing serial digits
    prefixes = {
        "FGTVML": "FortiGate VM (Large)",
        "FGTVMS": "FortiGate VM (Small)",
        "FGTVM":  "FortiGate VM",
        "FG-VM":  "FortiGate VM",
        "FGVM":   "FortiGate VM",
        "FWF":    "FortiWiFi",
        "FGT":    "FortiGate",
        "FG":     "FortiGate",
    }
    for prefix, label in prefixes.items():
        if s.startswith(prefix):
            suffix = s[len(prefix):]
            # Keep only alphanumeric model suffix
            model_suffix = re.sub(r"[^A-Z0-9]", "", suffix)
            return f"{label} {model_suffix}" if model_suffix else label
    return serial


# ════════════════════════════════════════════════════════════════════════════
# FortiGate translation
# ════════════════════════════════════════════════════════════════════════════

def _fgt_translate(raw: dict) -> dict:
    """
    Translate FortiGate connector output (from FortiGateConnector.get_all())
    into the normalised policy dict consumed by the DB writer and analysis engine.

    Normalised rule schema:
      rule_id, rule_name, section, sequence_number
      sources, destinations, services, applications
      source_interfaces, destination_interfaces
      action, enabled, logging_enabled, nat_enabled, schedule, comments
      hit_count, bytes, pkts, active_sessions, first_hit, last_hit
    """
    policies       = raw.get("policies", [])
    hit_counts     = raw.get("hit_counts", {})   # {policyid (int): {...}}

    # Build indexed lookups
    addresses      = {a["name"]: a for a in raw.get("addresses", [])}
    addr_groups    = {g["name"]: g for g in raw.get("address_groups", [])}
    addresses6     = {a["name"]: a for a in raw.get("addresses6", [])}
    addr_groups6   = {g["name"]: g for g in raw.get("address_groups6", [])}
    services       = {s["name"]: s for s in raw.get("services", [])}
    svc_groups     = {g["name"]: g for g in raw.get("service_groups", [])}
    vips           = {v["name"]: v for v in raw.get("vips", [])}
    vip_groups     = {g["name"]: g for g in raw.get("vip_groups", [])}
    ip_pools       = {p["name"]: p for p in raw.get("ip_pools", [])}

    # ── Object map ─────────────────────────────────────────────────────────
    obj_map: dict[str, dict] = {}

    for name, a in addresses.items():
        obj_map[name] = _fgt_addr_obj(a)

    for name, g in addr_groups.items():
        members = [m["name"] for m in g.get("member", [])]
        obj_map[name] = {
            "type": "group", "value": None, "members": members,
            "comment": g.get("comment", ""),
        }

    # IPv6
    for name, a in addresses6.items():
        obj_map.setdefault(name, _fgt_addr6_obj(a))

    for name, g in addr_groups6.items():
        members = [m["name"] for m in g.get("member", [])]
        obj_map.setdefault(name, {
            "type": "group", "value": None, "members": members, "comment": g.get("comment", ""),
        })

    for name, s in services.items():
        obj_map[name] = _fgt_svc_obj(s)

    for name, g in svc_groups.items():
        members = [m["name"] for m in g.get("member", [])]
        obj_map[name] = {
            "type": "service-group", "value": None, "members": members,
            "comment": g.get("comment", ""),
        }

    # VIPs — treated as host/network objects with a NAT annotation in the comment
    for name, v in vips.items():
        ext_ip = v.get("extip", "")
        map_ip = v.get("mappedip", [])
        mapped = map_ip[0].get("range", "") if map_ip else ""
        comment = f"VIP: {ext_ip} → {mapped}" + (f" | {v.get('comment', '')}" if v.get("comment") else "")
        obj_map[name] = {
            "type": "vip", "value": ext_ip, "members": [], "comment": comment,
        }

    for name, g in vip_groups.items():
        members = [m["name"] for m in g.get("member", [])]
        obj_map[name] = {
            "type": "group", "value": None, "members": members, "comment": "VIP group",
        }

    for name, p in ip_pools.items():
        obj_map.setdefault(name, {
            "type": "host", "value": p.get("startip", ""), "members": [],
            "comment": f"IP Pool: {p.get('startip', '')}–{p.get('endip', '')}",
        })

    # ── Rules ──────────────────────────────────────────────────────────────
    rules: list[dict] = []
    for seq, p in enumerate(policies):
        pid   = p.get("policyid", seq + 1)
        stats = hit_counts.get(int(pid), {})
        # Determine section: FGT uses special policies as section dividers.
        # A policy with name matching "--- Section Name ---" is a section marker.
        # For regular policies, section stays empty.  We'll populate it in a
        # second pass below.
        rule_name = p.get("name", f"policy_{pid}")
        comments  = p.get("comments", "")

        # FortiGate logtraffic: "disable"|"none" = no logging; "utm"|"all" = logging on.
        # The CMDB default when unset is "utm" (log UTM events = logging ON).
        # We explicitly fall back to "utm" (not "disable") when the field is absent.
        logtraffic = p.get("logtraffic", "utm")

        rule = {
            "rule_id":               str(pid),
            "rule_name":             rule_name,
            "section":               "",         # filled in second pass if applicable
            "sources":               [s["name"] for s in p.get("srcaddr", [])],
            "destinations":          [d["name"] for d in p.get("dstaddr", [])],
            "services":              [s["name"] for s in p.get("service", [])],
            "source_interfaces":     [i["name"] for i in p.get("srcintf", [])],
            "destination_interfaces":[i["name"] for i in p.get("dstintf", [])],
            "applications":          [a["name"] for a in p.get("application", [])],
            "action":                _fgt_action(p.get("action", "accept")),
            "enabled":               p.get("status", "enable") == "enable",
            "logging_enabled":       logtraffic.lower() not in ("disable", "none", ""),
            "nat_enabled":           p.get("nat", "disable") == "enable",
            "schedule":              p.get("schedule", "always"),
            "comments":              comments,
            # Live hit stats — prefer monitor API stats, fall back to CMDB fields
            "hit_count":             stats.get("hit_count", 0) or 0,
            "bytes":                 stats.get("bytes", 0) or 0,
            "pkts":                  stats.get("pkts", 0) or 0,
            "active_sessions":       stats.get("active_sessions", 0) or 0,
            "first_hit":             _fgt_ts(stats.get("first_used")) or _fgt_ts(p.get("first-used")),
            "last_hit":              _fgt_ts(stats.get("last_used"))  or _fgt_ts(p.get("last-used")),
        }
        rules.append(rule)

    # ── Section second pass ────────────────────────────────────────────────
    # FortiGate marks section boundaries with policies whose names follow
    # the pattern "--- Section Name ---".  Tag subsequent rules with that
    # section name until the next section marker.
    current_section = ""
    clean_rules: list[dict] = []
    for rule in rules:
        name = rule.get("rule_name", "")
        section_m = re.match(r'^-+\s*(.+?)\s*-+$', name)
        if section_m:
            current_section = section_m.group(1).strip()
            # Section-marker policies are real (but implicit deny) entries in
            # FGT; include them so rule numbering stays consistent.
        rule["section"] = current_section
        clean_rules.append(rule)

    return {"rules": clean_rules, "objects": obj_map, "warnings": []}


def _fgt_action(action_str: str) -> str:
    a = str(action_str).lower()
    if a in ("deny", "drop", "reject"):
        return "deny"
    return "accept"


def _fgt_ts(ts) -> Optional[str]:
    """Convert FortiGate unix timestamp (or ISO string) to ISO-8601 string."""
    if ts is None:
        return None
    if isinstance(ts, str):
        return ts if ts else None
    try:
        t = int(ts)
        if t <= 0:
            return None
        return datetime.utcfromtimestamp(t).isoformat() + "Z"
    except (ValueError, TypeError, OSError):
        return None


def _fgt_addr_obj(a: dict) -> dict:
    t = a.get("type", "ipmask")
    comment = a.get("comment", "")
    if t == "ipmask":
        from app.connectors.fortigate import fgt_subnet_to_cidr
        value = fgt_subnet_to_cidr(a.get("subnet", "0.0.0.0 0.0.0.0"))
        return {"type": "network", "value": value, "members": [], "comment": comment}
    elif t == "iprange":
        value = f"{a.get('start-ip', '')}-{a.get('end-ip', '')}"
        return {"type": "range", "value": value, "members": [], "comment": comment}
    elif t == "fqdn":
        return {"type": "fqdn", "value": a.get("fqdn", ""), "members": [], "comment": comment}
    elif t == "geography":
        return {"type": "geo", "value": a.get("country", ""), "members": [], "comment": comment}
    elif t == "wildcard":
        return {"type": "wildcard", "value": a.get("wildcard", ""), "members": [], "comment": comment}
    elif t == "wildcard-fqdn":
        return {"type": "fqdn", "value": a.get("wildcard-fqdn", ""), "members": [], "comment": comment}
    else:
        return {"type": "host", "value": a.get("ip", ""), "members": [], "comment": comment}


def _fgt_addr6_obj(a: dict) -> dict:
    t = a.get("type", "ipprefix")
    comment = a.get("comment", "")
    if t == "ipprefix":
        return {"type": "network", "value": a.get("ip6", ""), "members": [], "comment": comment}
    elif t == "iprange":
        return {"type": "range", "value": f"{a.get('start-ip', '')}-{a.get('end-ip', '')}", "members": [], "comment": comment}
    elif t == "fqdn":
        return {"type": "fqdn", "value": a.get("fqdn", ""), "members": [], "comment": comment}
    else:
        return {"type": "host", "value": a.get("ip6", ""), "members": [], "comment": comment}


def _fgt_svc_obj(s: dict) -> dict:
    comment = s.get("comment", "")
    proto_str = s.get("protocol", "TCP/UDP/SCTP").upper()
    tcp_range = s.get("tcp-portrange", "")
    udp_range = s.get("udp-portrange", "")

    # Prefer TCP, fall back to UDP
    active_range = tcp_range or udp_range
    proto = "TCP" if tcp_range else ("UDP" if udp_range else proto_str.split("/")[0])

    lo, hi = 0, 65535
    if active_range:
        # FortiGate format: "dstLow-dstHigh:srcLow-srcHigh" — take dst part
        dst_part = active_range.split(":")[0].split()[0]  # handle multiple ranges → take first
        lo, hi = _parse_port_range(dst_part)

    if proto_str == "ICMP" or s.get("protocol-number") == 1:
        return {"type": "service", "protocol": "ICMP", "port_start": 0, "port_end": 0, "members": [], "comment": comment}
    if proto_str == "IP":
        proto_num = s.get("protocol-number", 0)
        return {"type": "service", "protocol": f"IP/{proto_num}", "port_start": 0, "port_end": 0, "members": [], "comment": comment}

    return {
        "type": "service", "protocol": proto,
        "port_start": lo, "port_end": hi,
        "members": [], "comment": comment,
    }


# ════════════════════════════════════════════════════════════════════════════
# Huawei USG translation
# ════════════════════════════════════════════════════════════════════════════

def _huawei_translate(raw: dict) -> dict:
    """
    Translate HuaweiUSGConnector.get_all() output to the normalised policy dict.

    Raw keys:
      rules           — already normalised by connector._normalize_rules()
      addresses       — list of {name, type, value, members}
      address_groups  — list of {name, type, members}
      services        — list of {name, protocol, port_start, port_end}
      service_groups  — list of {name, members}
      zones           — list of {name, priority, interfaces}
    """
    rules_raw      = raw.get("rules", [])
    addresses_raw  = raw.get("addresses", [])
    addr_groups    = raw.get("address_groups", [])
    services_raw   = raw.get("services", [])
    svc_groups     = raw.get("service_groups", [])

    # ── Build object map ────────────────────────────────────────────────────
    obj_map: dict[str, dict] = {}

    for addr in addresses_raw:
        name = addr.get("name", "")
        if not name:
            continue
        atype = addr.get("type", "host")
        value = addr.get("value", "")
        members = addr.get("members", [])
        obj_map[name] = {
            "type":    atype,
            "value":   value,
            "members": members,
            "comment": addr.get("comment", ""),
        }

    for grp in addr_groups:
        name = grp.get("name", "")
        if not name:
            continue
        obj_map[name] = {
            "type":    "group",
            "value":   None,
            "members": grp.get("members", []),
            "comment": grp.get("comment", ""),
        }

    for svc in services_raw:
        name = svc.get("name", "")
        if not name:
            continue
        proto = (svc.get("protocol") or "TCP").upper()
        obj_map[name] = {
            "type":       "service",
            "protocol":   proto,
            "port_start": svc.get("port_start", 0),
            "port_end":   svc.get("port_end", 65535),
            "members":    [],
            "comment":    svc.get("comment", ""),
        }

    for sg in svc_groups:
        name = sg.get("name", "")
        if not name:
            continue
        obj_map[name] = {
            "type":    "service-group",
            "value":   None,
            "members": sg.get("members", []),
            "comment": sg.get("comment", ""),
        }

    # ── Normalise rules ─────────────────────────────────────────────────────
    rules: list[dict] = []
    for r in rules_raw:
        rules.append({
            "rule_id":                r.get("rule_id", ""),
            "rule_uid":               r.get("rule_uid") or r.get("rule_id", ""),
            "rule_number":            r.get("rule_number") or r.get("sequence_number") or 0,
            "rule_name":              r.get("rule_name", ""),
            "section":                r.get("section"),
            "sources":                r.get("sources", []),
            "destinations":           r.get("destinations", []),
            "services":               r.get("services", []),
            # Zone-based interfaces (populated by parser/SSH connector)
            "source_interfaces":      r.get("source_interfaces") or r.get("src_zones", []),
            "destination_interfaces": r.get("destination_interfaces") or r.get("dst_zones", []),
            "applications":           r.get("applications", []),
            "users":                  r.get("users", []),
            "vpn":                    r.get("vpn", []),
            "install_on":             r.get("install_on", []),
            "action":                 r.get("action", "deny"),
            "enabled":                r.get("enabled", True),
            "logging_enabled":        r.get("logging_enabled", True),
            "nat_enabled":            r.get("nat_enabled", False),
            "schedule":               r.get("schedule") or "always",
            "comments":               r.get("comments", ""),
            "hit_count":              r.get("hit_count") or 0,
            "bytes":                  r.get("bytes") or 0,
            "pkts":                   r.get("pkts") or 0,
            "active_sessions":        r.get("active_sessions") or 0,
            "first_hit":              r.get("first_hit"),
            "last_hit":               r.get("last_hit"),
        })

    return {"rules": rules, "objects": obj_map, "warnings": raw.get("warnings", [])}


# ════════════════════════════════════════════════════════════════════════════
# Check Point translation
# ════════════════════════════════════════════════════════════════════════════

def _cp_translate(raw: dict) -> dict:
    """
    Translate Check Point connector output (from CheckPointConnector.get_all())
    to the normalised policy dict consumed by the DB writer and analysis engine.

    Sources used:
      rules            — from access rulebase (all layers, inline layers expanded)
      nat_rules        — from NAT rulebase (stored as warnings/annotations)
      objects          — from show-hosts/networks/ranges/groups/services/etc.
      inline_objects   — from objects-dictionary embedded in rulebase responses
      time_objects     — from show-times/show-time-groups
      application_objects — from show-application-site-categories/groups
      vpn_communities  — from show-vpn-communities-star/meshed
    """
    rules_raw           = raw.get("rules", [])
    nat_rules_raw       = raw.get("nat_rules", [])
    objects_raw         = raw.get("objects", [])
    inline_objects      = raw.get("inline_objects", [])
    time_objects_raw    = raw.get("time_objects", [])
    app_objects_raw     = raw.get("application_objects", [])
    vpn_communities_raw = raw.get("vpn_communities", [])

    # ── Build object lookups ────────────────────────────────────────────────
    # Merge inline objects (higher priority — they are "full" detail level) with db objects
    uid_map:  dict[str, dict] = {}
    name_map: dict[str, dict] = {}

    for obj in (objects_raw + inline_objects):
        if isinstance(obj, dict):
            uid = obj.get("uid", "")
            name = obj.get("name", "")
            if uid:
                uid_map[uid] = obj
            if name:
                name_map[name] = obj

    def resolve(ref) -> str:
        """Resolve a rule field reference to an object name."""
        if isinstance(ref, dict):
            uid = ref.get("uid", "")
            if uid and uid in uid_map:
                return uid_map[uid].get("name", ref.get("name", uid))
            return ref.get("name", uid)
        if isinstance(ref, str):
            if ref in uid_map:
                return uid_map[ref].get("name", ref)
            return ref
        return str(ref)

    def resolve_list(lst) -> list[str]:
        if not lst:
            return []
        if isinstance(lst, str):
            return [resolve(lst)]
        return [resolve(item) for item in lst if item]

    # ── Build object map ────────────────────────────────────────────────────
    obj_map: dict[str, dict] = {}

    # Track which objects are CP-predefined (should not appear as unused objects).
    # These are fetched because rules reference them by name, but they are system
    # objects — not user-managed — so they must not be stored in the objects table.
    cp_predefined_names: set[str] = set()

    def _is_cp_predefined(raw_obj: dict) -> bool:
        """
        Return True if the object belongs to the built-in Check Point system domain.
        Predefined objects have domain.name == "Check Point" or similar system values.
        They include built-in services (HTTP, HTTPS, FTP, SSH, DNS, …), application
        signatures, built-in host groups (RFC1918_*), etc.
        """
        domain = raw_obj.get("domain", {})
        if not isinstance(domain, dict):
            return False
        domain_name = domain.get("name", "").strip()
        # "Check Point" is the canonical predefined domain on all R80+ servers.
        # Some older/MDS installs use "cpms-domain" or "CPMS" as domain-type.
        if domain_name.lower() in ("check point", "checkpoint"):
            return True
        domain_type = domain.get("domain-type", "").lower()
        if domain_type in ("cpms-domain", "cpms domain"):
            return True
        return False

    all_objects = objects_raw + [o for o in inline_objects if o not in objects_raw]
    for obj in all_objects:
        if not isinstance(obj, dict):
            continue
        name = obj.get("name", "")
        if not name:
            continue

        # Skip predefined Check Point system objects — they are not user-managed
        # and must not appear as "unused objects" in the analysis results.
        if _is_cp_predefined(obj):
            cp_predefined_names.add(name)
            continue

        t = obj.get("type", "")
        comment = obj.get("comments", obj.get("comment", ""))

        if t == "host":
            ip = obj.get("ipv4-address", obj.get("ip-address", ""))
            obj_map[name] = {"type": "host", "value": ip, "members": [], "comment": comment}

        elif t == "network":
            subnet  = obj.get("subnet4", obj.get("subnet", ""))
            masklen = obj.get("mask-length4", obj.get("mask-length", "32"))
            value   = f"{subnet}/{masklen}" if subnet else ""
            obj_map[name] = {"type": "network", "value": value, "members": [], "comment": comment}

        elif t == "address-range":
            value = f"{obj.get('ipv4-address-first', '')}-{obj.get('ipv4-address-last', '')}"
            obj_map[name] = {"type": "range", "value": value, "members": [], "comment": comment}

        elif t == "multicast-address-range":
            value = f"{obj.get('ipv4-address-first', '')}-{obj.get('ipv4-address-last', '')}"
            obj_map[name] = {"type": "range", "value": value, "members": [], "comment": comment}

        elif t in ("group", "address-range-group"):
            members = [resolve(m) for m in obj.get("members", [])]
            obj_map[name] = {"type": "group", "value": None, "members": members, "comment": comment}

        elif t == "wildcard":
            obj_map[name] = {"type": "wildcard", "value": obj.get("ipv4-address", ""), "members": [], "comment": comment}

        elif t in ("dns-domain",):
            obj_map[name] = {"type": "fqdn", "value": obj.get("domains-attribute", ""), "members": [], "comment": comment}

        elif t == "service-tcp":
            lo, hi = _parse_port_range(str(obj.get("port", "0")))
            obj_map[name] = {"type": "service", "protocol": "TCP", "port_start": lo, "port_end": hi, "members": [], "comment": comment}

        elif t == "service-udp":
            lo, hi = _parse_port_range(str(obj.get("port", "0")))
            obj_map[name] = {"type": "service", "protocol": "UDP", "port_start": lo, "port_end": hi, "members": [], "comment": comment}

        elif t == "service-icmp":
            obj_map[name] = {"type": "service", "protocol": "ICMP", "port_start": 0, "port_end": 0, "members": [], "comment": comment}

        elif t == "service-icmp6":
            obj_map[name] = {"type": "service", "protocol": "ICMPv6", "port_start": 0, "port_end": 0, "members": [], "comment": comment}

        elif t == "service-other":
            proto_num = obj.get("ip-protocol", 0)
            obj_map[name] = {"type": "service", "protocol": f"IP/{proto_num}", "port_start": 0, "port_end": 0, "members": [], "comment": comment}

        elif t == "service-group":
            members = [resolve(m) for m in obj.get("members", [])]
            obj_map[name] = {"type": "service-group", "value": None, "members": members, "comment": comment}

        else:
            # Unknown type — store as generic host for completeness
            obj_map.setdefault(name, {"type": "host", "value": "", "members": [], "comment": comment})

    # ── Time objects (schedules) ────────────────────────────────────────────
    # Build a set of time-restricted object names for use in rule analysis
    time_object_names: set[str] = set()
    for t_obj in (time_objects_raw + [o for o in inline_objects if o.get("type") in ("time", "time-group")]):
        if isinstance(t_obj, dict):
            name = t_obj.get("name", "")
            if name:
                time_object_names.add(name)
                obj_map.setdefault(name, {
                    "type": "time", "value": None, "members": [], "comment": t_obj.get("comments", ""),
                })

    # ── Application/URL objects ─────────────────────────────────────────────
    for a_obj in app_objects_raw:
        if isinstance(a_obj, dict):
            name = a_obj.get("name", "")
            if name:
                members = [resolve(m) for m in a_obj.get("application-signature", a_obj.get("members", []))]
                obj_map.setdefault(name, {
                    "type": "application", "value": None, "members": members,
                    "comment": a_obj.get("description", a_obj.get("comments", "")),
                })

    # ── VPN community objects ───────────────────────────────────────────────
    vpn_warnings: list[str] = []
    for comm in vpn_communities_raw:
        if isinstance(comm, dict):
            name = comm.get("name", "")
            if name:
                ctype  = comm.get("type", "")
                gws    = [resolve(g) for g in comm.get("gateways", [])]
                comment = f"VPN {ctype}: {', '.join(gws[:5])}" if gws else f"VPN community ({ctype})"
                obj_map.setdefault(name, {
                    "type": "vpn-community", "value": None, "members": gws, "comment": comment,
                })

    # ── NAT rules → warnings ────────────────────────────────────────────────
    # NAT rules are not added to the access rules list but recorded as warnings
    # so engineers know to review them alongside access policy findings.
    nat_count = len([r for r in nat_rules_raw if isinstance(r, dict) and r.get("type") != "nat-section"])
    if nat_count:
        vpn_warnings.append(f"{nat_count} NAT rules found in package '{raw.get('policy_package', '')}' — review alongside access policy.")

    # ── Build rules list ────────────────────────────────────────────────────
    rules: list[dict] = []
    for i, r in enumerate(rules_raw):
        if not isinstance(r, dict):
            continue
        # Skip section headers and placeholder rows
        rtype = r.get("type", "")
        if rtype in ("access-section",):
            continue
        # Skip inline-layer marker rules (they're just pointers to sub-policies;
        # the sub-policy rules are already fetched and present in the flat list)
        if rtype == "access-rule" and _cp_action(r.get("action", {})) == "inline-layer":
            continue

        hits = r.get("hits", {}) or {}

        # Resolve schedule/time object name
        time_ref   = r.get("time")
        schedule   = resolve(time_ref) if time_ref else "Any"
        # Flag whether this rule is time-restricted (affects zero-hit analysis)
        time_restricted = schedule not in ("Any", "", None) and schedule in time_object_names

        # Section: prefer _section tag (set during flattening), fall back to layer
        section = r.get("_section", r.get("section", r.get("_layer", "")))

        rule = {
            "rule_id":               str(r.get("rule-number", r.get("uid", i + 1))),
            "rule_name":             r.get("name", f"rule_{i + 1}"),
            "section":               section,
            "sources":               resolve_list(r.get("source", [])),
            "destinations":          resolve_list(r.get("destination", [])),
            "services":              resolve_list(r.get("service", [])),
            "source_interfaces":     [],   # CP uses src/dst objects, not interface refs in rules
            "destination_interfaces": [],
            "applications":          resolve_list(r.get("content", [])),
            "action":                _cp_action_norm(r.get("action", {})),
            "enabled":               r.get("enabled", True),
            "logging_enabled":       _cp_logging(r.get("track", {})),
            "nat_enabled":           False,
            "schedule":              schedule,
            "comments":              r.get("comments", ""),
            # Hit counts (from management server — reflect gateway enforcement)
            "hit_count":             _cp_hit_value(hits),
            "bytes":                 0,
            "pkts":                  0,
            "active_sessions":       0,
            "first_hit":             _cp_date(hits.get("first-date")),
            "last_hit":              _cp_date(hits.get("last-date")),
            # Metadata
            "_layer":                r.get("_layer", ""),
            "_time_restricted":      time_restricted,
        }
        rules.append(rule)

    return {"rules": rules, "objects": obj_map, "warnings": vpn_warnings}


def _cp_hit_value(hits: dict) -> int:
    """Extract hit count from CP hits dict — handles both int and nested dict forms."""
    v = hits.get("value", hits.get("hits", 0))
    if isinstance(v, dict):
        v = v.get("value", 0)
    try:
        return int(v) if v else 0
    except (ValueError, TypeError):
        return 0


def _cp_date(date_val) -> Optional[str]:
    """Parse a CP date value — may be ISO string, dict with 'iso-8601', or None."""
    if date_val is None:
        return None
    if isinstance(date_val, str):
        return date_val if date_val else None
    if isinstance(date_val, dict):
        return date_val.get("iso-8601") or date_val.get("posix")
    return None


def _cp_action(action) -> str:
    """Raw action string extraction from action field."""
    if isinstance(action, dict):
        return action.get("name", "").lower()
    return str(action).lower()


def _cp_action_norm(action) -> str:
    """Normalise CP action to 'accept' / 'deny'."""
    name = _cp_action(action)
    if any(x in name for x in ("drop", "reject", "deny", "block")):
        return "deny"
    if name in ("inline-layer",):
        return "accept"   # inline layer = sub-policy, treated as accept
    return "accept"


def _cp_logging(track) -> bool:
    """Determine if logging is enabled from CP track field."""
    if isinstance(track, dict):
        track_type = track.get("type", {})
        if isinstance(track_type, dict):
            name = track_type.get("name", "").lower()
        else:
            name = str(track_type).lower()
        return name not in ("none", "")
    return bool(track)


# ════════════════════════════════════════════════════════════════════════════
# Shared utilities
# ════════════════════════════════════════════════════════════════════════════

def _parse_port_range(port_str: str) -> tuple[int, int]:
    s = str(port_str).strip()
    if "-" in s:
        parts = s.split("-", 1)
        try:
            return int(parts[0] or 0), int(parts[1] or 65535)
        except ValueError:
            pass
    try:
        p = int(s)
        return p, p
    except ValueError:
        return 0, 65535


# ════════════════════════════════════════════════════════════════════════════
# DB writer
# ════════════════════════════════════════════════════════════════════════════

def _write_to_db(parsed: dict, policy: FirewallPolicy, db: Session):
    """
    Persist normalised rules and objects into the DB.
    Deletes existing data for this policy then re-inserts fresh from the sync.
    """
    vendor = policy.vendor or "Unknown"

    # Remove old data — delete ObjectMembers first to satisfy FK constraint,
    # then objects and rules (bulk DELETE bypasses ORM cascade).
    obj_ids = db.query(FirewallObject.id).filter(FirewallObject.policy_id == policy.id).subquery()
    db.query(ObjectMember).filter(ObjectMember.parent_id.in_(obj_ids)).delete(synchronize_session=False)
    db.query(FirewallObject).filter(FirewallObject.policy_id == policy.id).delete(synchronize_session=False)
    db.query(FirewallRule).filter(FirewallRule.policy_id == policy.id).delete(synchronize_session=False)
    db.commit()

    # Write objects
    for name, obj in parsed["objects"].items():
        members = obj.get("members", [])
        db_obj = FirewallObject(
            policy_id=policy.id,
            vendor=vendor,
            object_name=name,
            object_type=obj.get("type", "host"),
            value=obj.get("value"),
            protocol=obj.get("protocol"),
            port_start=obj.get("port_start"),
            port_end=obj.get("port_end"),
            comment=str(obj.get("comment", "") or ""),
        )
        db.add(db_obj)
        db.flush()
        for m in members:
            db.add(ObjectMember(parent_id=db_obj.id, member_name=m))

    # Write rules
    for seq, r in enumerate(parsed["rules"]):
        db_rule = FirewallRule(
            policy_id=policy.id,
            vendor=vendor,
            rule_id=r.get("rule_id", str(seq + 1)),
            rule_name=r.get("rule_name", ""),
            section=r.get("section", ""),
            rule_number=seq + 1,
            source_interfaces=json.dumps(r.get("source_interfaces", [])),
            destination_interfaces=json.dumps(r.get("destination_interfaces", [])),
            sources=json.dumps(r.get("sources", [])),
            destinations=json.dumps(r.get("destinations", [])),
            services=json.dumps(r.get("services", [])),
            applications=json.dumps(r.get("applications", [])),
            action=r.get("action", "accept"),
            schedule=r.get("schedule", "always"),
            enabled=r.get("enabled", True),
            logging_enabled=r.get("logging_enabled", False),
            nat_enabled=r.get("nat_enabled", False),
            comments=r.get("comments", ""),
            hit_count=r.get("hit_count", 0),
            last_hit=r.get("last_hit"),
            first_hit=r.get("first_hit"),
        )
        db.add(db_rule)

    policy.rule_count = len(parsed["rules"])
    policy.object_count = len(parsed["objects"])
    policy.analysis_status = "completed"
    db.commit()


# ════════════════════════════════════════════════════════════════════════════
# Revision / change tracking
# ════════════════════════════════════════════════════════════════════════════

def _rule_signature(r: dict) -> dict:
    """Stable fingerprint of a rule for hash and diff computation."""
    return {
        "id":      r.get("rule_id", ""),
        "name":    r.get("rule_name", ""),
        "action":  r.get("action", ""),
        "src":     sorted(r.get("sources", [])),
        "dst":     sorted(r.get("destinations", [])),
        "svc":     sorted(r.get("services", [])),
        "enabled": r.get("enabled", True),
    }


def _policy_hash(rules: list[dict]) -> str:
    """SHA-256 of the sorted rule signatures — changes when any rule changes."""
    sig = [_rule_signature(r) for r in sorted(rules, key=lambda x: x.get("rule_id", ""))]
    return hashlib.sha256(json.dumps(sig, sort_keys=True).encode()).hexdigest()


def _compute_diff(prev_rules: list[dict], new_rules: list[dict]) -> tuple[int, int, int, list[dict]]:
    """
    Compare two rule lists and return:
      (added_count, removed_count, modified_count, change_detail_list)

    change_detail entry:
      {"rule_id", "change_type": "added"|"removed"|"modified", "before"?, "after"?}
    """
    prev_by_id = {r["rule_id"]: r for r in prev_rules}
    new_by_id  = {r["rule_id"]: r for r in new_rules}

    prev_ids = set(prev_by_id.keys())
    new_ids  = set(new_by_id.keys())

    added_ids   = new_ids  - prev_ids
    removed_ids = prev_ids - new_ids
    common_ids  = prev_ids & new_ids

    change_detail: list[dict] = []

    for rid in sorted(added_ids):
        r = new_by_id[rid]
        change_detail.append({
            "rule_id":     rid,
            "change_type": "added",
            "after": {
                "name":   r.get("rule_name"),
                "action": r.get("action"),
                "src":    r.get("sources"),
                "dst":    r.get("destinations"),
                "svc":    r.get("services"),
            },
        })

    for rid in sorted(removed_ids):
        r = prev_by_id[rid]
        change_detail.append({
            "rule_id":     rid,
            "change_type": "removed",
            "before": {
                "name":   r.get("rule_name"),
                "action": r.get("action"),
                "src":    r.get("sources"),
                "dst":    r.get("destinations"),
                "svc":    r.get("services"),
            },
        })

    modified_count = 0
    for rid in sorted(common_ids):
        prev_sig = json.dumps(_rule_signature(prev_by_id[rid]), sort_keys=True)
        new_sig  = json.dumps(_rule_signature(new_by_id[rid]),  sort_keys=True)
        if prev_sig != new_sig:
            modified_count += 1
            pr = prev_by_id[rid]
            nr = new_by_id[rid]
            change_detail.append({
                "rule_id":     rid,
                "change_type": "modified",
                "before": {
                    "name":    pr.get("rule_name"),
                    "action":  pr.get("action"),
                    "src":     pr.get("sources"),
                    "dst":     pr.get("destinations"),
                    "svc":     pr.get("services"),
                    "enabled": pr.get("enabled"),
                },
                "after": {
                    "name":    nr.get("rule_name"),
                    "action":  nr.get("action"),
                    "src":     nr.get("sources"),
                    "dst":     nr.get("destinations"),
                    "svc":     nr.get("services"),
                    "enabled": nr.get("enabled"),
                },
            })

    # Limit detail list to 500 entries to avoid huge JSON blobs
    if len(change_detail) > 500:
        change_detail = change_detail[:500]
        change_detail.append({"note": "Detail truncated at 500 entries"})

    return len(added_ids), len(removed_ids), modified_count, change_detail


def _save_revision(
    policy_id: str,
    device_id: str,
    parsed: dict,
    finding_count: int,
    high_count: int,
    db: Session,
):
    from app.models.revision import PolicyRevision

    rules     = parsed["rules"]
    new_hash  = _policy_hash(rules)

    # Load previous revision
    prev = (
        db.query(PolicyRevision)
        .filter(PolicyRevision.policy_id == policy_id)
        .order_by(PolicyRevision.revision_number.desc())
        .first()
    )
    rev_number = (prev.revision_number + 1) if prev else 1

    added = removed = modified = 0
    change_summary = "Initial sync"
    change_detail: list = []

    if prev:
        if prev.policy_hash == new_hash:
            change_summary = "No changes detected"
        else:
            # Reconstruct previous rule list from DB for per-rule diff
            prev_rules_db = (
                db.query(FirewallRule)
                .filter(FirewallRule.policy_id == policy_id)
                .order_by(FirewallRule.rule_number)
                .all()
            )
            prev_rules = [
                {
                    "rule_id":      r.rule_id,
                    "rule_name":    r.rule_name,
                    "action":       r.action,
                    "sources":      json.loads(r.sources or "[]"),
                    "destinations": json.loads(r.destinations or "[]"),
                    "services":     json.loads(r.services or "[]"),
                    "enabled":      r.enabled,
                }
                for r in prev_rules_db
            ]
            added, removed, modified, change_detail = _compute_diff(prev_rules, rules)
            parts = []
            if added:    parts.append(f"+{added} added")
            if removed:  parts.append(f"-{removed} removed")
            if modified: parts.append(f"~{modified} modified")
            change_summary = ", ".join(parts) if parts else "Policy hash changed"

    rev = PolicyRevision(
        policy_id=policy_id,
        device_id=device_id,
        revision_number=rev_number,
        sync_source="live_sync",
        rule_count=len(rules),
        object_count=len(parsed.get("objects", {})),
        finding_count=finding_count,
        high_finding_count=high_count,
        rules_added=added,
        rules_removed=removed,
        rules_modified=modified,
        policy_hash=new_hash,
        change_summary=change_summary,
        change_detail=change_detail,
    )
    db.add(rev)
    db.commit()
    logger.info(
        "Revision #%d saved for policy %s: %s",
        rev_number, policy_id, change_summary,
    )


# ════════════════════════════════════════════════════════════════════════════
# Main sync entry point
# ════════════════════════════════════════════════════════════════════════════

def sync_device(device: FirewallDevice, db: Session) -> dict:
    """
    Full live sync for a FirewallDevice.

    Returns: {"policy_id", "rules", "objects", "findings", "warnings", "errors"}
    Raises on fatal connection or auth failure.
    """
    errors: list[str] = []
    policy_id = None

    try:
        device.sync_status = "running"
        device.last_error  = None
        db.commit()

        # Decrypt credentials before passing to connectors
        from app.security.crypto import decrypt_credential as _dec
        _token    = _dec(device.api_token) or None
        _password = _dec(device.password)  or ""

        # ── Connect & fetch ────────────────────────────────────────────────
        if device.vendor == "FortiGate":
            from app.connectors.fortigate import FortiGateConnector
            conn = FortiGateConnector(
                host=device.host,
                api_token=_token,
                username=device.username or None,
                password=_password or None,
                port=device.port or 443,
                use_ssl=device.use_ssl,
                verify_ssl=device.verify_ssl,
                vdom=device.vdom or "root",
            )
            info = conn.connect()
            raw  = conn.get_all()
            conn.disconnect()
            parsed = _fgt_translate(raw)
            vendor_label = "FortiGate"

        elif device.vendor == "CheckPoint":
            from app.connectors.checkpoint import CheckPointConnector
            conn = CheckPointConnector(
                host=device.host,
                username=device.username or "",
                password=_password,
                api_key=_token,   # Smart-1 Cloud / API-key auth when api_token is set
                port=device.port or 443,
                use_ssl=device.use_ssl,
                verify_ssl=device.verify_ssl,
                domain=device.cp_domain,
                policy_package=device.cp_policy_package,
                management_type=device.cp_management_type or "SmartCenter",
            )
            info = conn.connect()
            raw  = conn.get_all()
            conn.disconnect()
            parsed = _cp_translate(raw)
            vendor_label = "CheckPoint"

        elif device.vendor == "PaloAlto":
            from app.connectors.paloalto import PaloAltoConnector, translate as pa_translate
            conn = PaloAltoConnector(
                host=device.host,
                api_key=_token,
                username=device.username or None,
                password=_password or None,
                port=device.port or 443,
                use_ssl=device.use_ssl,
                verify_ssl=device.verify_ssl,
                vsys=device.vdom or "vsys1",
            )
            info   = conn.connect()
            raw    = conn.get_all()
            parsed = pa_translate(raw)
            vendor_label = "PaloAlto"

        elif device.vendor == "CiscoASA":
            from app.connectors.cisco_asa import CiscoASAConnector, translate as asa_translate
            conn = CiscoASAConnector(
                host=device.host,
                username=device.username or "",
                password=_password,
                port=device.port or 443,
                use_ssl=device.use_ssl,
                verify_ssl=device.verify_ssl,
            )
            info   = conn.connect()
            raw    = conn.get_all()
            conn.disconnect()
            parsed = asa_translate(raw)
            vendor_label = "CiscoASA"

        elif device.vendor == "HuaweiUSG":
            _hw_port = device.port or 22
            _use_ssh = (_hw_port == 22)

            if _use_ssh:
                # ── SSH path (primary for live Huawei devices) ──────────────
                from app.connectors.huawei_ssh import HuaweiSSHConnector
                conn = HuaweiSSHConnector(
                    host=device.host,
                    username=device.username or "",
                    password=_password,
                    port=_hw_port,
                )
                info = conn.connect()
                raw  = conn.get_all()
                conn.disconnect()
            else:
                # ── REST API path (HTTPS, port 443 or 8443) ─────────────────
                from app.connectors.huawei_usg import HuaweiUSGConnector
                conn = HuaweiUSGConnector(
                    host=device.host,
                    username=device.username or "",
                    password=_password,
                    port=_hw_port,
                    use_ssl=device.use_ssl,
                    verify_ssl=device.verify_ssl,
                )
                info = conn.connect()
                raw  = conn.get_all()
                conn.disconnect()

            parsed = _huawei_translate(raw)
            vendor_label = "HuaweiUSG"

        else:
            raise ValueError(f"Unknown vendor: {device.vendor!r}")

        # ── Create or update policy record ─────────────────────────────────
        policy = (
            db.query(FirewallPolicy)
            .filter(FirewallPolicy.id == device.last_policy_id)
            .first()
        ) if device.last_policy_id else None

        if not policy:
            policy = FirewallPolicy(
                id=str(uuid.uuid4()),
                customer_id=device.customer_id,
                device_id=device.id,
                firewall_name=device.name,
                vendor=vendor_label,
                policy_package=(
                    device.cp_policy_package
                    or raw.get("policy_package", "Default")
                ),
                original_filename=f"[live:{device.host}]",
                analysis_status="pending",
            )
            db.add(policy)
            db.commit()
            db.refresh(policy)
        else:
            # Stamp device_id on existing policies that predate this column
            if not policy.device_id:
                policy.device_id = device.id

        policy_id = policy.id
        device.last_policy_id = policy_id
        db.commit()

        # ── Persist to DB ──────────────────────────────────────────────────
        _write_to_db(parsed, policy, db)

        # ── Analysis engine ────────────────────────────────────────────────
        run_analysis(policy_id, db)

        # ── Record revision ────────────────────────────────────────────────
        from app.models.finding import Finding
        finding_count = db.query(Finding).filter(Finding.policy_id == policy_id).count()
        high_count    = db.query(Finding).filter(
            Finding.policy_id == policy_id,
            Finding.severity.in_(["High", "Critical"]),
        ).count()
        _save_revision(policy_id, device.id, parsed, finding_count, high_count, db)

        # ── Capture device metadata from connect info ──────────────────────
        if device.vendor == "FortiGate":
            # info = {"version": "v7.4.1", "serial": "FGT100F...", "hostname": "...", "vdom": "..."}
            raw_version = info.get("version", "")
            raw_serial  = info.get("serial",  "")
            if raw_version:
                device.os_version = raw_version
            if raw_serial:
                device.serial_number = raw_serial
                # Derive model from serial prefix (e.g. FGT100F-ABC → FortiGate 100F)
                model = _fgt_model_from_serial(raw_serial)
                device.fw_model = model or raw_serial
            # ── Capture interface list from already-fetched raw data ──
            try:
                iface_list = raw.get("interfaces") or []
                interfaces = []
                for iface in iface_list:
                    ip_val = (iface.get("ip") or "").strip()
                    # FortiGate returns "x.x.x.x y.y.y.y" (IP space netmask)
                    if ip_val and ip_val not in ("0.0.0.0 0.0.0.0", "0.0.0.0"):
                        interfaces.append({
                            "name":   iface.get("name", ""),
                            "ip":     ip_val.split()[0],
                            "mask":   ip_val.split()[1] if " " in ip_val else "",
                            "type":   iface.get("type", ""),
                            "status": iface.get("status", "up"),
                        })
                if interfaces:
                    device.device_interfaces = json.dumps(interfaces)
            except Exception:
                pass  # Interface capture is best-effort

        elif device.vendor == "CheckPoint":
            # info = {"api_server_version": "1.9.1", "uid": "...", ...}
            api_ver = info.get("api_server_version", "")
            if api_ver:
                device.management_platform = f"Check Point Management R{api_ver.split('.')[0]}" if api_ver else None
            # gateway versions come from raw["gateways"] — prefer GW OS version
            gateways = raw.get("gateways", [])
            if gateways:
                gw_versions = list({g.get("version") for g in gateways if g.get("version")})
                if gw_versions:
                    sorted_gw = sorted(gw_versions)
                    device.os_version = sorted_gw[0]   # e.g. "R81.20"
                    device.fw_model   = f"GW: {', '.join(sorted_gw[:3])}"
                elif api_ver:
                    device.os_version = f"API {api_ver}"  # fallback when no GW version
                # Store gateway IPs as "interfaces" for display
                ifaces = [{"name": g.get("name",""), "ip": g.get("ipv4-address",""),
                           "type": g.get("type","gateway"), "status": "up"}
                          for g in gateways if g.get("ipv4-address")]
                if ifaces:
                    device.device_interfaces = json.dumps(ifaces)
            elif api_ver:
                device.os_version = f"API {api_ver}"  # fallback when no GW data

        elif device.vendor == "PaloAlto":
            pa_ver = info.get("version") or info.get("sw-version", "")
            pa_model = info.get("model", "")
            if pa_ver:
                device.os_version = pa_ver
            if pa_model:
                device.fw_model = pa_model

        elif device.vendor == "CiscoASA":
            asa_ver = info.get("version") or info.get("software_version", "")
            asa_model = info.get("model", "")
            if asa_ver:
                device.os_version = asa_ver
            if asa_model:
                device.fw_model = asa_model

        elif device.vendor == "HuaweiUSG":
            hw_ver    = info.get("version", "")
            hw_model  = info.get("model", "")
            hw_serial = info.get("serial", "")
            hw_sysname = info.get("sysname", "")
            if hw_ver:
                device.os_version = hw_ver
            if hw_model:
                device.fw_model = hw_model
            if hw_serial:
                device.serial_number = hw_serial
            # Use sysname as friendly name if device name hasn't been customised
            if hw_sysname and device.name in (device.host, ""):
                device.name = hw_sysname

        # ── Mark success ───────────────────────────────────────────────────
        device.sync_status  = "ok"
        device.last_sync_at = datetime.utcnow()
        device.last_error   = None
        db.commit()

        # ── Fire notifications (non-blocking) ──────────────────────────────
        try:
            from app.services.notifications import notify_sync_completed, notify_high_findings
            from app.models.customer import Customer
            from app.models.revision import PolicyRevision

            customer = db.query(Customer).filter(Customer.id == device.customer_id).first()
            customer_name = customer.name if customer else device.customer_id

            # Get last revision's change_summary
            last_rev = (
                db.query(PolicyRevision)
                .filter(PolicyRevision.device_id == device.id)
                .order_by(PolicyRevision.revision_number.desc())
                .first()
            )
            change_summary = last_rev.change_summary if last_rev else "Initial sync"

            notify_sync_completed(
                db=db,
                device_id=device.id,
                device_name=device.name,
                vendor=device.vendor,
                customer_name=customer_name,
                policy_id=policy_id or "",
                rule_count=len(parsed["rules"]),
                finding_count=finding_count,
                high_finding_count=high_count,
                change_summary=change_summary,
            )

            if high_count > 0:
                from app.models.finding import Finding
                top_findings = [
                    {"type": f.finding_type, "title": f.title, "severity": f.severity}
                    for f in db.query(Finding)
                    .filter(Finding.policy_id == policy_id, Finding.severity.in_(["High", "Critical"]))
                    .limit(5)
                    .all()
                ]
                notify_high_findings(
                    db=db,
                    policy_id=policy_id or "",
                    firewall_name=device.name,
                    customer_name=customer_name,
                    high_count=high_count,
                    new_high_count=high_count,
                    top_findings=top_findings,
                )
        except Exception as _notify_err:
            logger.debug("Notification fire failed (non-fatal): %s", _notify_err)

        return {
            "policy_id": policy_id,
            "rules":     len(parsed["rules"]),
            "objects":   len(parsed["objects"]),
            "findings":  finding_count,
            "warnings":  parsed.get("warnings", []),
            "errors":    errors,
        }

    except Exception as e:
        logger.exception("Live sync failed for device %s (%s): %s", device.id, device.name, e)
        device.sync_status = "error"
        device.last_error  = str(e)
        db.commit()

        # Notify on sync error
        try:
            from app.services.notifications import notify_sync_error
            from app.models.customer import Customer
            customer = db.query(Customer).filter(Customer.id == device.customer_id).first()
            notify_sync_error(
                db=db,
                device_id=device.id,
                device_name=device.name,
                vendor=device.vendor,
                customer_name=customer.name if customer else device.customer_id,
                error_message=str(e),
            )
        except Exception:
            pass

        raise
