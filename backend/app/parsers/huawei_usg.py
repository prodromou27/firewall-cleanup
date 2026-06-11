"""
Huawei USG Config Parser  —  Phase 1: File-Based Import
=========================================================
Supports all Huawei USG platform families:
  USG2000 / USG5000 / USG6000 / USG6000E / USG6000F / USG9000

Accepted input formats
----------------------
Full configuration exports
  display current-configuration
  display current-configuration configuration security-policy

Security policy outputs
  display security-policy
  display security-policy all
  display security-policy rule <name>

Object / zone outputs
  display zone
  display ip address-set
  display service-set

NAT policy
  display nat-policy
  display nat-policy all

Statistics / hit counts
  display traffic policy statistics
  display security-policy statistics

Raw CLI command output pasted into a text file.

Normalized rule model (per specification)
------------------------------------------
{
  vendor, tenant_id, firewall_id, policy_package, policy_layer,
  rule_id, rule_number, rule_name, description,
  source_zones, destination_zones,
  source_addresses, destination_addresses,
  users, services, applications, time_range,
  action, logging_enabled, enabled,
  hit_count, last_hit, first_hit, raw_data
}

Normalized object model
-----------------------
{
  vendor, object_name, object_type, value,
  members, used_by_rules, raw_data
}
"""
from __future__ import annotations

import re
from typing import List, Dict, Tuple, Any, Optional
from app.parsers.base import BaseParser


# ── helpers ──────────────────────────────────────────────────────────────────

def _mask_to_prefix(mask: str) -> int:
    """Convert dotted-decimal subnet mask to CIDR prefix length."""
    try:
        return sum(bin(int(o)).count("1") for o in mask.split("."))
    except Exception:
        return 32


def _is_indented(line: str) -> bool:
    return line.startswith(" ") or line.startswith("\t")


def _strip_quotes(s: str) -> str:
    return s.strip().strip('"').strip("'")


# ── main parser ───────────────────────────────────────────────────────────────

class HuaweiUSGParser(BaseParser):
    """
    Flexible, tolerant parser for Huawei USG firewall configuration and
    CLI output exports.  Handles slight differences between platform
    generations (USG6000 vs USG6000E/F) and software versions.
    """

    VENDOR = "HuaweiUSG"

    def parse(self, content: str) -> Tuple[List[dict], List[dict], List[str]]:
        warnings: List[str] = []
        lines = content.splitlines()

        # ── Detection ────────────────────────────────────────────────────────
        markers = (
            "security-policy", "ip address-set", "ip service-set",
            "firewall zone", "sysname", "nat-policy",
            "display security-policy", "display zone",
            "display ip address-set", "display nat-policy",
        )
        if not any(m in content for m in markers):
            warnings.append(
                "File does not appear to be a Huawei USG export. "
                "Expected output from 'display current-configuration', "
                "'display security-policy', 'display zone', or similar commands."
            )

        # ── Extract firewall identity ─────────────────────────────────────────
        sysname = self._extract_sysname(lines)
        version  = self._extract_version(lines)

        # ── Parse all sections ────────────────────────────────────────────────
        zones         = self._parse_zones(lines, warnings)
        addr_objects  = self._parse_address_sets(lines, warnings)
        svc_objects   = self._parse_service_sets(lines, warnings)
        app_objects   = self._parse_app_groups(lines, warnings)
        time_objects  = self._parse_time_ranges(lines, warnings)
        nat_rules     = self._parse_nat_policy(lines, warnings)
        sec_rules     = self._parse_security_policy(lines, warnings)

        # Enrich hit counts from statistics output
        hit_map = self._parse_statistics(lines)
        for r in sec_rules:
            if r["rule_name"] in hit_map:
                r["hit_count"] = hit_map[r["rule_name"]].get("hit_count")
                r["last_hit"]  = hit_map[r["rule_name"]].get("last_hit")
                r["first_hit"] = hit_map[r["rule_name"]].get("first_hit")

        # ── Deduplicate rules by rule_name ────────────────────────────────────
        # SSH output may include the same rule from multiple commands
        # (display current-configuration all AND display security-policy all).
        # Strategy: ALWAYS keep the structurally richest entry (one with real
        # src/dst/svc data), but MERGE hit-count/timestamp from whichever entry
        # has better statistics.  Never replace a complete rule with a statistics-
        # only stub (a stub has sources==["any"] and action=="deny" by default
        # because it was parsed from "display security-policy statistics" output).
        def _rule_is_stub(r: dict) -> bool:
            """True if the rule entry was created from statistics output (no real config data)."""
            srcs = r.get("sources") or []
            dsts = r.get("destinations") or []
            svcs = r.get("services") or []
            src_zones = r.get("src_zones") or []
            dst_zones = r.get("dst_zones") or []
            # A real rule has at least one specific source/dest/zone or service.
            # A stats stub has all defaults: sources=["any"], dsts=["any"], no zones.
            return (
                srcs in ([], ["any"])
                and dsts in ([], ["any"])
                and svcs in ([], ["any"])
                and not src_zones
                and not dst_zones
            )

        seen: Dict[str, dict] = {}
        for r in sec_rules:
            name = r.get("rule_name") or r.get("rule_id", "")
            if name not in seen:
                seen[name] = r
            else:
                existing = seen[name]
                r_is_stub    = _rule_is_stub(r)
                ex_is_stub   = _rule_is_stub(existing)

                if r_is_stub and not ex_is_stub:
                    # New entry is a stats stub — keep existing real rule but
                    # absorb any hit-count data from the stub.
                    if (r.get("hit_count") or 0) > (existing.get("hit_count") or 0):
                        existing["hit_count"] = r["hit_count"]
                    if r.get("last_hit") and not existing.get("last_hit"):
                        existing["last_hit"] = r["last_hit"]
                    if r.get("first_hit") and not existing.get("first_hit"):
                        existing["first_hit"] = r["first_hit"]
                elif ex_is_stub and not r_is_stub:
                    # Existing is a stub — replace with real rule, carrying stats over.
                    hit = max((r.get("hit_count") or 0), (existing.get("hit_count") or 0))
                    seen[name] = r
                    if hit:
                        seen[name]["hit_count"] = hit
                    if existing.get("last_hit") and not r.get("last_hit"):
                        seen[name]["last_hit"] = existing["last_hit"]
                    if existing.get("first_hit") and not r.get("first_hit"):
                        seen[name]["first_hit"] = existing["first_hit"]
                else:
                    # Both real (or both stubs) — merge stats, keep existing structure.
                    if (r.get("hit_count") or 0) > (existing.get("hit_count") or 0):
                        existing["hit_count"] = r["hit_count"]
                    if r.get("last_hit") and not existing.get("last_hit"):
                        existing["last_hit"] = r["last_hit"]
                    if r.get("first_hit") and not existing.get("first_hit"):
                        existing["first_hit"] = r["first_hit"]
                    # Merge any non-empty fields missing from existing
                    for k, v in r.items():
                        if k not in ("hit_count", "last_hit", "first_hit") and v and not existing.get(k):
                            existing[k] = v
        sec_rules = list(seen.values())

        if not sec_rules:
            if not nat_rules:
                warnings.append(
                    "No security policy rules found. "
                    "Ensure the export includes 'security-policy' section "
                    "or the output of 'display security-policy'."
                )

        # ── Build combined objects list ───────────────────────────────────────
        objects: List[dict] = []
        objects.extend(zones)
        objects.extend(addr_objects)
        objects.extend(svc_objects)
        objects.extend(app_objects)
        objects.extend(time_objects)
        # NAT rules are appended as special objects
        for nr in nat_rules:
            objects.append({
                "object_name":  nr.get("rule_name", "nat-rule"),
                "object_type":  f"nat-{nr.get('nat_type', 'policy')}",
                "value":        nr.get("translated_address", ""),
                "members":      [],
                "vendor":       self.VENDOR,
                "raw_data":     nr,
            })

        # Normalise rule objects to upload.py expected schema
        norm_rules   = [self._normalise_rule(r, idx) for idx, r in enumerate(sec_rules)]
        norm_objects = [self._normalise_object(o) for o in objects]

        if version:
            # prepend an informational warning/note with version info
            warnings.insert(0, f"Detected firmware version: {version}")
        if sysname:
            warnings.insert(0, f"Detected device name: {sysname}")

        return norm_rules, norm_objects, warnings

    # ── sysname / version ────────────────────────────────────────────────────

    def _extract_sysname(self, lines: List[str]) -> Optional[str]:
        for line in lines:
            m = re.match(r'^\s*sysname\s+(\S+)', line)
            if m:
                return m.group(1)
        return None

    def _extract_version(self, lines: List[str]) -> Optional[str]:
        for line in lines:
            m = re.match(r'^\s*version\s+(V\S+)', line, re.IGNORECASE)
            if m:
                return m.group(1)
        return None

    # ── Zone parsing ─────────────────────────────────────────────────────────

    def _parse_zones(self, lines: List[str], warnings: List[str]) -> List[dict]:
        """
        Parse 'firewall zone <name>' blocks and
        'display zone' output.
        """
        zones: List[dict] = []
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            # firewall zone <name>  — config style
            m = re.match(r'^firewall zone\s+(\S+)', line)
            # display zone output style: "Zone name: trust"
            m2 = re.match(r'^Zone(?:\s+name)?\s*[:\s]\s*(\S+)', line, re.IGNORECASE)
            if m or m2:
                name = (m or m2).group(1)
                priority = None
                interfaces: List[str] = []
                i += 1
                while i < len(lines):
                    inner = lines[i]
                    stripped = inner.strip()
                    if stripped == "#" or (stripped and not _is_indented(inner) and not stripped.startswith("set ") and not stripped.startswith("add ")):
                        break
                    pm = re.match(r'^\s+set priority\s+(\d+)', inner)
                    im = re.match(r'^\s+add interface\s+(\S+)', inner)
                    # display zone style
                    pm2 = re.match(r'^\s*Priority\s*:\s*(\d+)', inner, re.IGNORECASE)
                    im2 = re.match(r'^\s*Interface\s*:\s*(\S+)', inner, re.IGNORECASE)
                    if pm:  priority = int(pm.group(1))
                    elif pm2: priority = int(pm2.group(1))
                    elif im:  interfaces.append(im.group(1))
                    elif im2: interfaces.append(im2.group(1))
                    i += 1
                zones.append({
                    "object_type": "zone",
                    "name":        name,
                    "priority":    priority,
                    "interfaces":  interfaces,
                    "members":     interfaces,
                    "value":       f"priority={priority}" if priority else "",
                })
                continue
            i += 1
        return zones

    # ── Address set parsing ──────────────────────────────────────────────────

    def _parse_address_sets(self, lines: List[str], warnings: List[str]) -> List[dict]:
        """
        Parse 'ip address-set <name> type object|group' blocks and
        'display ip address-set' output.
        """
        objects: List[dict] = []
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            # Config style: ip address-set LAN type object
            m = re.match(r'^ip address-set\s+(\S+)\s+type\s+(object|group)', line)
            # display output: "Address set: LAN_SERVERS"
            m2 = re.match(r'^(?:IP\s+)?[Aa]ddress[\s-]set(?:\s+name)?\s*[:\s]\s*(.+)', line)
            if m:
                name  = m.group(1)
                kind  = m.group(2)    # "object" or "group"
                members, value_list = self._collect_address_members(lines, i + 1)
                obj_type = "address_group" if kind == "group" else (
                    "network" if any("/" in v or " mask " in str(v) for v in value_list) else "host"
                )
                objects.append({
                    "object_type": obj_type,
                    "name":        name,
                    "members":     members,
                    "value":       ", ".join(value_list[:1]) if value_list else "",
                    "_all_values": value_list,
                })
                # advance past block
                while i < len(lines) and not (lines[i].strip() == "#" and i > 0):
                    i += 1
                i += 1
                continue

            elif m2 and line and not line.startswith("--"):
                raw_name = m2.group(1).strip()
                name = raw_name.split()[0]   # first token is the name
                members, value_list = self._collect_address_members(lines, i + 1)
                objects.append({
                    "object_type": "address_group" if len(members) > 1 else "host",
                    "name":        name,
                    "members":     members,
                    "value":       ", ".join(value_list[:1]) if value_list else "",
                    "_all_values": value_list,
                })
            i += 1
        return objects

    def _collect_address_members(
        self, lines: List[str], start: int
    ) -> Tuple[List[str], List[str]]:
        """Collect address entries from an address-set block."""
        members: List[str] = []
        values: List[str] = []
        for j in range(start, min(start + 200, len(lines))):
            inner = lines[j]
            stripped = inner.strip()
            if stripped == "#" or (stripped and not _is_indented(inner)):
                break
            # address N A.B.C.D mask M.M.M.M
            am = re.match(r'^\s+address\s+\d+\s+([\d.]+)\s+mask\s+([\d.]+)', inner)
            # address N A.B.C.D/P
            pm = re.match(r'^\s+address\s+\d+\s+([\d.]+)/(\d+)', inner)
            # address N range A.B.C.D A.B.C.D
            rm = re.match(r'^\s+address\s+\d+\s+range\s+([\d.]+)\s+([\d.]+)', inner)
            # address address-set <name>
            gm = re.match(r'^\s+address\s+address-set\s+(\S+)', inner)
            # address N A.B.C.D (host, no mask)
            hm = re.match(r'^\s+address\s+\d+\s+([\d.]+)\s*$', inner)
            # FQDN
            fm = re.match(r'^\s+fqdn\s+(\S+)', inner)
            # display output: "  0: 192.168.1.0/24" or "  IP: 10.0.0.1"
            dm = re.match(r'^\s+(?:\d+|IP)\s*:\s*([\d./\-]+)', inner, re.IGNORECASE)

            if am:
                cidr = f"{am.group(1)}/{_mask_to_prefix(am.group(2))}"
                members.append(cidr); values.append(cidr)
            elif pm:
                cidr = f"{pm.group(1)}/{pm.group(2)}"
                members.append(cidr); values.append(cidr)
            elif rm:
                rng = f"{rm.group(1)}-{rm.group(2)}"
                members.append(rng); values.append(rng)
            elif gm:
                members.append(gm.group(1))
            elif hm:
                members.append(hm.group(1) + "/32"); values.append(hm.group(1) + "/32")
            elif fm:
                members.append(fm.group(1)); values.append(fm.group(1))
            elif dm:
                members.append(dm.group(1)); values.append(dm.group(1))
        return members, values

    # ── Service set parsing ──────────────────────────────────────────────────

    def _parse_service_sets(self, lines: List[str], warnings: List[str]) -> List[dict]:
        objects: List[dict] = []
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            # ip service-set <name> type object|group
            m = re.match(r'^ip service-set\s+(\S+)\s+type\s+(object|group)', line)
            if m:
                name = m.group(1)
                kind = m.group(2)
                members: List[str] = []
                protos: List[str] = []
                i += 1
                while i < len(lines):
                    inner = lines[i]
                    stripped = inner.strip()
                    if stripped == "#" or (stripped and not _is_indented(inner)):
                        break
                    # service N protocol tcp/udp source-port P destination-port P
                    sm = re.match(
                        r'^\s+service\s+\d+\s+protocol\s+(\S+)'
                        r'(?:\s+source-port\s+([\d -]+))?'
                        r'(?:\s+destination-port\s+([\d -]+))?',
                        inner
                    )
                    # service-set <member> (group reference)
                    gm = re.match(r'^\s+service\s+service-set\s+(\S+)', inner)
                    # display style: "Protocol: TCP  Port: 443"
                    dm = re.match(
                        r'^\s+Protocol\s*:\s*(\S+).*Port(?:\s+range)?\s*:\s*([\d -]+)',
                        inner, re.IGNORECASE
                    )
                    if sm:
                        proto = sm.group(1).upper()
                        src_port = sm.group(2) or "any"
                        dst_port = sm.group(3) or "any"
                        entry = f"{proto}/{dst_port}"
                        members.append(entry); protos.append(entry)
                    elif gm:
                        members.append(gm.group(1))
                    elif dm:
                        entry = f"{dm.group(1).upper()}/{dm.group(2).strip()}"
                        members.append(entry); protos.append(entry)
                    i += 1
                objects.append({
                    "object_type": "service_group" if kind == "group" else "service",
                    "name":        name,
                    "members":     members,
                    "value":       ", ".join(protos[:1]) if protos else "",
                })
                continue
            i += 1
        return objects

    # ── Application group parsing ─────────────────────────────────────────────

    def _parse_app_groups(self, lines: List[str], warnings: List[str]) -> List[dict]:
        """Parse 'app-group <name>' blocks and application references."""
        objects: List[dict] = []
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            m = re.match(r'^app-group\s+(\S+)', line)
            if m:
                name = m.group(1)
                members: List[str] = []
                i += 1
                while i < len(lines):
                    inner = lines[i].strip()
                    if inner == "#" or (inner and not _is_indented(lines[i])):
                        break
                    am = re.match(r'^\s*app\s+(\S+)', lines[i])
                    if am:
                        members.append(am.group(1))
                    i += 1
                objects.append({
                    "object_type": "application_group",
                    "name":        name,
                    "members":     members,
                    "value":       "",
                })
                continue
            i += 1
        return objects

    # ── Time range parsing ────────────────────────────────────────────────────

    def _parse_time_ranges(self, lines: List[str], warnings: List[str]) -> List[dict]:
        """Parse 'time-range <name>' blocks."""
        objects: List[dict] = []
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            m = re.match(r'^time-range\s+(\S+)', line)
            if m:
                name = m.group(1)
                schedule_parts: List[str] = []
                i += 1
                while i < len(lines):
                    inner = lines[i].strip()
                    if inner == "#" or (inner and not _is_indented(lines[i])):
                        break
                    if inner:
                        schedule_parts.append(inner)
                    i += 1
                objects.append({
                    "object_type": "time_range",
                    "name":        name,
                    "members":     schedule_parts,
                    "value":       "; ".join(schedule_parts[:2]),
                })
                continue
            i += 1
        return objects

    # ── NAT policy parsing ────────────────────────────────────────────────────

    def _parse_nat_policy(self, lines: List[str], warnings: List[str]) -> List[dict]:
        """
        Parse 'nat-policy' blocks:
          nat-policy
            rule name <name>
              source-zone <z>
              egress-interface <if>
              action nat address-group <pool>
              action nat static address <ip>
              action nat easy-ip
        """
        nat_rules: List[dict] = []
        in_nat = False
        in_rule = False
        current: Dict[str, Any] = {}
        rule_idx = 0

        for raw_line in lines:
            stripped = raw_line.strip()

            # Enter nat-policy block
            if re.match(r'^nat-policy\s*$', stripped) or re.match(r'^display nat-policy', stripped, re.IGNORECASE):
                in_nat = True
                continue
            if in_nat and stripped == "#":
                if in_rule and current:
                    nat_rules.append(self._finalise_nat_rule(current, rule_idx))
                    rule_idx += 1
                in_rule = False
                current = {}
                in_nat = False
                continue
            if not in_nat:
                continue

            # New nat rule
            m_rule = re.match(r'^\s+rule name\s+(.+)$', raw_line)
            if m_rule:
                if in_rule and current:
                    nat_rules.append(self._finalise_nat_rule(current, rule_idx))
                    rule_idx += 1
                current = {
                    "rule_name": m_rule.group(1).strip(),
                    "src_zones": [], "dst_zones": [],
                    "src_addrs": [], "dst_addrs": [],
                    "services":  [],
                    "action": "nat", "nat_type": "source",
                    "translated_address": "", "enabled": True,
                    "comments": "",
                }
                in_rule = True
                continue

            if not in_rule:
                continue

            # Populate rule fields
            if re.match(r'^\s+source-zone\s+', raw_line):
                current["src_zones"].append(re.sub(r'^\s+source-zone\s+', '', raw_line).strip())
            elif re.match(r'^\s+destination-zone\s+', raw_line):
                current["dst_zones"].append(re.sub(r'^\s+destination-zone\s+', '', raw_line).strip())
            elif re.match(r'^\s+source-address\s+', raw_line):
                val = re.sub(r'^\s+source-address\s+(address-set\s+)?', '', raw_line).strip()
                current["src_addrs"].append(val)
            elif re.match(r'^\s+destination-address\s+', raw_line):
                val = re.sub(r'^\s+destination-address\s+(address-set\s+)?', '', raw_line).strip()
                current["dst_addrs"].append(val)
            elif re.match(r'^\s+service\s+', raw_line):
                val = re.sub(r'^\s+service\s+(service-set\s+)?', '', raw_line).strip()
                current["services"].append(val)
            elif re.match(r'^\s+action nat static', raw_line, re.IGNORECASE):
                current["nat_type"] = "static"
                am = re.search(r'address\s+([\d.]+)', raw_line)
                if am: current["translated_address"] = am.group(1)
            elif re.match(r'^\s+action nat easy-ip', raw_line, re.IGNORECASE):
                current["nat_type"] = "easy-ip"
                current["translated_address"] = "interface-ip"
            elif re.match(r'^\s+action nat address-group', raw_line, re.IGNORECASE):
                current["nat_type"] = "source"
                gm = re.search(r'address-group\s+(\S+)', raw_line)
                if gm: current["translated_address"] = gm.group(1)
            elif re.match(r'^\s+action destination nat', raw_line, re.IGNORECASE):
                current["nat_type"] = "destination"
                am = re.search(r'address\s+([\d.]+)', raw_line)
                if am: current["translated_address"] = am.group(1)
            elif stripped == "disable":
                current["enabled"] = False
            elif re.match(r'^\s+description\s+', raw_line):
                current["comments"] = re.sub(r'^\s+description\s+', '', raw_line).strip()

        if in_rule and current:
            nat_rules.append(self._finalise_nat_rule(current, rule_idx))

        return nat_rules

    @staticmethod
    def _finalise_nat_rule(r: Dict[str, Any], idx: int) -> dict:
        return {
            "rule_name":           r.get("rule_name", f"nat-rule-{idx}"),
            "nat_type":            r.get("nat_type", "source"),
            "source_zones":        r.get("src_zones", []),
            "destination_zones":   r.get("dst_zones", []),
            "source_addresses":    r.get("src_addrs", []) or ["any"],
            "destination_addresses": r.get("dst_addrs", []) or ["any"],
            "services":            r.get("services", []),
            "translated_address":  r.get("translated_address", ""),
            "enabled":             r.get("enabled", True),
            "comments":            r.get("comments", ""),
        }

    # ── Statistics / hit count parsing ────────────────────────────────────────

    def _parse_statistics(self, lines: List[str]) -> Dict[str, dict]:
        """
        Parse hit-count statistics from multiple VRP command outputs:

        1. display security-policy statistics (most reliable):
              Rule Name: block_all
               Forward  Match count  :      12345
               Forward  Last match time   :2024-01-15 14:23:45

        2. display security-policy all / rule all (inline stats, some firmware):
              rule name block_all
               match count: 12345 packet(s)
               last match time: 2024-01-15 14:23:45

        3. display traffic policy statistics:
              Rule name  : block_all
               Forward   Match count        :        0

        Returns { rule_name: {hit_count, last_hit, first_hit} }.
        """
        hit_map: Dict[str, dict] = {}
        current_name: Optional[str] = None

        # Patterns for rule name detection across VRP firmware generations:
        #   V500R001C30:  " Rule Name: trust_to_untrust"
        #   V500R001C60:  "Rule Name : trust_to_untrust"
        #   V600R007+:    "Rule name : trust_to_untrust"
        #   Some builds:  " Name: trust_to_untrust"  (no "Rule" prefix)
        #   Config style: "  rule name trust_to_untrust"
        _rule_name_pats = [
            re.compile(r'^\s*Rule\s+[Nn]ame\s*[:\s]+(.+)', re.IGNORECASE),
            re.compile(r'^\s*Rule-name\s*[:\s]+(.+)', re.IGNORECASE),
            re.compile(r'^\s+rule\s+name\s+(.+)$'),          # config / display inline (indented)
            # "  Name: trust_to_untrust"  (some VRP builds omit "Rule" prefix)
            # Guard against matching section headers: only if indented and short value
            re.compile(r'^\s{1,4}Name\s*:\s*(\S.{0,128})$', re.IGNORECASE),
        ]
        # Patterns for match count — all known VRP variants:
        #   "Forward  Match count             :  12345"  (single-line, stats output)
        #   "   Match count                   :  12345"  (next-line after Forward/Backward)
        #   "match count: 12345 packet(s)"               (inline display output)
        #   "Hit count : 12345"                          (some VRP variants)
        #   "Match  12345 time(s)"                       (display rule <name> style)
        _count_pats = [
            re.compile(r'(?:(?:Forward|Backward)\s+)?Match\s+count\s*:\s*(\d+)', re.IGNORECASE),
            re.compile(r'match\s+count\s*:\s*(\d+)', re.IGNORECASE),
            re.compile(r'[Hh]it\s*(?:count|times?)?\s*:\s*(\d+)'),
            re.compile(r'^\s*Match\s+(\d+)\s+time', re.IGNORECASE),
            re.compile(r'[Mm]atched\s*:\s*(\d+)'),
        ]
        _last_pats = [
            re.compile(r'[Ll]ast\s+match(?:\s+time)?\s*:\s*(.+)'),
            re.compile(r'[Ll]ast\s+[Hh]it(?:\s+[Tt]ime)?\s*:\s*(.+)'),
        ]
        _first_pats = [
            re.compile(r'[Ff]irst\s+match(?:\s+time)?\s*:\s*(.+)'),
            re.compile(r'[Ff]irst\s+[Hh]it(?:\s+[Tt]ime)?\s*:\s*(.+)'),
        ]

        for line in lines:
            # Try to detect a rule name line
            for pat in _rule_name_pats:
                m = pat.match(line)
                if m:
                    candidate = m.group(1).strip()
                    # Filter out noise: skip lines that are clearly not rule names.
                    # Use \b so "ALLOW_INTERNET" is not excluded by the "all" prefix match.
                    if candidate and not re.match(
                        r'^(all|statistics|verbose|brief|total|policy|forward|backward)\b|-{2,}',
                        candidate, re.IGNORECASE
                    ):
                        current_name = candidate
                        hit_map.setdefault(current_name, {})
                    break

            if current_name is None:
                continue

            # Match count
            if "hit_count" not in hit_map[current_name]:
                for pat in _count_pats:
                    m = pat.search(line)
                    if m:
                        try:
                            hit_map[current_name]["hit_count"] = int(m.group(1))
                        except (ValueError, IndexError):
                            pass
                        break

            # Last match time
            if "last_hit" not in hit_map[current_name]:
                for pat in _last_pats:
                    m = pat.search(line)
                    if m:
                        val = m.group(1).strip()
                        if val and val not in ("--", "N/A", "none", ""):
                            hit_map[current_name]["last_hit"] = val
                        break

            # First match time
            if "first_hit" not in hit_map[current_name]:
                for pat in _first_pats:
                    m = pat.search(line)
                    if m:
                        val = m.group(1).strip()
                        if val and val not in ("--", "N/A", "none", ""):
                            hit_map[current_name]["first_hit"] = val
                        break

        return hit_map

    # ── Security policy parsing ────────────────────────────────────────────────

    def _parse_security_policy(self, lines: List[str], warnings: List[str]) -> List[dict]:
        """
        Main security policy parser.
        Handles both full-config 'security-policy' block and
        'display security-policy' CLI output.
        """
        rules: List[dict] = []
        in_sec_policy = False
        in_rule = False
        current: Dict[str, Any] = {}
        rule_idx = 0

        for i, raw_line in enumerate(lines):
            stripped = raw_line.strip()

            # ── Enter security-policy block ───────────────────────────────────
            if re.match(r'^security-policy\s*$', stripped):
                in_sec_policy = True
                continue
            # display security-policy [all|rule ...] — rule definitions, enter parse mode.
            # But NOT for "display security-policy statistics" / "rule all statistics"
            # which contain only hit-count data, not rule definitions.  Parsing those
            # as rules creates spurious stub entries that corrupt real rule data.
            if re.match(r'^display security-policy', stripped, re.IGNORECASE):
                if re.search(r'\bstatistics\b', stripped, re.IGNORECASE):
                    continue   # statistics output — skip, handled by _parse_statistics()
                in_sec_policy = True
                continue

            # ── Exit block ────────────────────────────────────────────────────
            # Config style terminator
            _exit_sec_policy = False
            if stripped == "#":
                _exit_sec_policy = True
            # VRP prompt line: <hostname> or [hostname] — marks end of command output
            elif re.match(r'^[<\[][A-Za-z0-9][A-Za-z0-9_\-\.]*[\]>]\s*$', stripped):
                _exit_sec_policy = True
            # Another top-level display command starts — previous section ended
            elif re.match(r'^display\s+', stripped, re.IGNORECASE) and in_rule:
                _exit_sec_policy = True
            # Top-level config section that is not security-policy
            elif re.match(r'^(?:ip address-set|ip service-set|firewall zone|nat-policy|ike|ipsec|interface|bgp|ospf|isis|route-policy)\b', stripped):
                _exit_sec_policy = True

            if in_sec_policy and _exit_sec_policy:
                if in_rule and current:
                    rules.append(self._finalise_rule(current, rule_idx))
                    rule_idx += 1
                in_rule = False
                current = {}
                in_sec_policy = False
                continue

            if not in_sec_policy:
                continue

            # ── New rule  ─────────────────────────────────────────────────────
            # Config style:  "  rule name <name>"
            m_rule = re.match(r'^\s+rule name\s+(.+)$', raw_line)
            # Display style: "Rule <N>:" or "rule-name <name>"
            m_disp = re.match(r'^\s*(?:rule[-\s]?name|Rule\s+\d+)\s*[:\s]+(.+)$', raw_line, re.IGNORECASE)
            # Statistics header style: "Rule: <name>"
            m_stat = re.match(r'^\s*Rule\s*:\s*(.+)$', raw_line, re.IGNORECASE)

            rule_match = m_rule or m_disp or m_stat
            if rule_match:
                if in_rule and current:
                    rules.append(self._finalise_rule(current, rule_idx))
                    rule_idx += 1
                name = rule_match.group(1).strip()
                # Skip "Rule name : <name>" display output headers that repeat
                if re.match(r'^rule name', name, re.IGNORECASE):
                    continue
                current = {
                    "rule_name":    name,
                    "src_zones":    [], "dst_zones":    [],
                    "sources":      [], "destinations": [],
                    "services":     [], "applications": [],
                    "users":        [], "time_range":   None,
                    "action":       "deny",
                    "enabled":      True,
                    "logging":      False,  # Huawei default: no logging unless explicit
                    "comments":     "",
                    "hit_count":    None,
                    "last_hit":     None,
                    "first_hit":    None,
                    "raw_lines":    [],
                    "policy_layer": "security-policy",
                }
                in_rule = True
                continue

            if not in_rule:
                continue

            current["raw_lines"].append(raw_line)

            # ── Rule attributes ───────────────────────────────────────────────

            # Zones
            if re.match(r'^\s+source-zone\s+', raw_line):
                z = re.sub(r'^\s+source-zone\s+', '', raw_line).strip()
                if z: current["src_zones"].append(z)
            elif re.match(r'^\s+destination-zone\s+', raw_line):
                z = re.sub(r'^\s+destination-zone\s+', '', raw_line).strip()
                if z: current["dst_zones"].append(z)

            # Source address (object ref or inline)
            elif re.match(r'^\s+source-address\s+', raw_line):
                val = re.sub(r'^\s+source-address\s+(address-set\s+)?', '', raw_line).strip()
                if val: current["sources"].append(val)

            # Destination address
            elif re.match(r'^\s+destination-address\s+', raw_line):
                val = re.sub(r'^\s+destination-address\s+(address-set\s+)?', '', raw_line).strip()
                if val: current["destinations"].append(val)

            # Service
            elif re.match(r'^\s+service\s+', raw_line):
                val = re.sub(r'^\s+service\s+(service-set\s+)?', '', raw_line).strip()
                if val: current["services"].append(val)

            # Application
            elif re.match(r'^\s+application\s+', raw_line):
                val = re.sub(r'^\s+application\s+(app\s+|app-group\s+)?', '', raw_line).strip()
                if val: current["applications"].append(val)

            # User / user group
            elif re.match(r'^\s+user\s+', raw_line):
                val = re.sub(r'^\s+user\s+(group\s+)?', '', raw_line).strip()
                if val: current["users"].append(val)

            # Time range / schedule
            elif re.match(r'^\s+time-range\s+', raw_line):
                current["time_range"] = re.sub(r'^\s+time-range\s+', '', raw_line).strip()
            elif re.match(r'^\s+schedule\s+', raw_line):
                current["time_range"] = re.sub(r'^\s+schedule\s+', '', raw_line).strip()

            # Action
            elif re.match(r'^\s+action\s+', raw_line):
                action_raw = re.sub(r'^\s+action\s+', '', raw_line).strip().lower()
                if action_raw in ("permit", "allow", "accept"):
                    current["action"] = "accept"
                elif action_raw.startswith("deny") or action_raw in ("drop", "discard"):
                    current["action"] = "deny"
                else:
                    current["action"] = action_raw  # e.g. "nat" — preserve

            # Disable keyword
            elif stripped == "disable":
                current["enabled"] = False
            elif re.match(r'^\s+status\s+disabled?\s*$', raw_line, re.IGNORECASE):
                current["enabled"] = False
            elif re.match(r'^\s+status\s+enabled?\s*$', raw_line, re.IGNORECASE):
                current["enabled"] = True

            # Logging
            elif re.match(r'^\s+(?:policy\s+)?logging\b', raw_line, re.IGNORECASE):
                current["logging"] = True
            elif re.match(r'^\s+undo\s+(?:policy\s+)?logging\b', raw_line, re.IGNORECASE):
                current["logging"] = False

            # Description
            elif re.match(r'^\s+description\s+', raw_line):
                current["comments"] = re.sub(r'^\s+description\s+', '', raw_line).strip()

            # Display output: "Action   : permit"
            elif re.match(r'^\s*Action\s*:\s*', raw_line, re.IGNORECASE):
                a = re.sub(r'^\s*Action\s*:\s*', '', raw_line).strip().lower()
                current["action"] = "accept" if a in ("permit", "allow", "accept") else "deny"
            elif re.match(r'^\s*Status\s*:\s*', raw_line, re.IGNORECASE):
                s = re.sub(r'^\s*Status\s*:\s*', '', raw_line).strip().lower()
                current["enabled"] = "dis" not in s
            elif re.match(r'^\s*(?:Logging|Log)\s*:\s*', raw_line, re.IGNORECASE):
                val = re.sub(r'^\s*(?:Logging|Log)\s*:\s*', '', raw_line).strip().lower()
                current["logging"] = "enable" in val or "on" in val
            elif re.match(r'^\s*Description\s*:\s*', raw_line, re.IGNORECASE):
                current["comments"] = re.sub(r'^\s*Description\s*:\s*', '', raw_line).strip()

            # Hit count from inline display
            elif re.match(r'^\s*(?:Match\s+count|Hit count|Hits)\s*:\s*', raw_line, re.IGNORECASE):
                m = re.search(r':\s*(\d+)', raw_line)
                if m: current["hit_count"] = int(m.group(1))
            elif re.match(r'^\s*Last\s+match\s+time\s*:\s*', raw_line, re.IGNORECASE):
                current["last_hit"] = re.sub(r'^\s*Last\s+match\s+time\s*:\s*', '', raw_line).strip()

        # Flush trailing rule
        if in_rule and current:
            rules.append(self._finalise_rule(current, rule_idx))

        return rules

    # ── Finalise / normalise ──────────────────────────────────────────────────

    @staticmethod
    def _make_rule_id(name: str) -> str:
        """
        Derive a stable, deterministic rule ID from the rule name.
        Huawei rule names are unique within a security policy and are the
        canonical identifier — using them as IDs keeps revision diffs stable
        when rules are inserted or reordered.
        """
        # Lowercase, replace whitespace/special chars with underscores
        safe = re.sub(r'[^a-zA-Z0-9_\-]', '_', name.strip()).lower()
        return f"hw_{safe}" if safe else f"huawei-rule-unknown"

    def _finalise_rule(self, r: Dict[str, Any], idx: int) -> dict:
        """Build a raw rule dict from the parse state."""
        # Fall back: if no explicit source/dest addresses, use zones
        srcs  = r["sources"]      or r.get("src_zones")  or ["any"]
        dsts  = r["destinations"] or r.get("dst_zones")  or ["any"]
        svcs  = r["services"]     or ["any"]
        rule_name = r.get("rule_name", f"Rule-{idx+1}")
        return {
            # Identity — use rule NAME as stable ID (unique per policy on VRP)
            "rule_id":     self._make_rule_id(rule_name),
            "rule_number": idx + 1,
            "rule_name":   rule_name,
            # Zones (for segmentation analysis)
            "src_zones":   r.get("src_zones", []),
            "dst_zones":   r.get("dst_zones", []),
            # Addresses / services / applications
            "sources":        srcs,
            "destinations":   dsts,
            "services":       svcs,
            "applications":   r.get("applications", []),
            "users":          r.get("users", []),
            "time_range":     r.get("time_range"),
            # Policy attributes
            "action":          r.get("action", "deny"),
            "enabled":         r.get("enabled", True),
            "logging_enabled": r.get("logging", False),
            # Stats
            "hit_count":  r.get("hit_count"),
            "last_hit":   r.get("last_hit"),
            "first_hit":  r.get("first_hit"),
            # Meta
            "section":        r.get("policy_layer", "security-policy"),
            "comments":       r.get("comments", ""),
            "raw_data":       {"raw_lines": r.get("raw_lines", [])},
        }

    @staticmethod
    def _normalise_rule(r: dict, idx: int) -> dict:
        """
        Map the internal rule dict to the upload.py / FirewallRule ORM
        expected schema (mirrors the normalized rule model in the spec).
        """
        rule_name = r.get("rule_name", f"Rule-{idx+1}")
        # Use the stable name-based ID that was set in _finalise_rule;
        # fall back to deriving it here so _normalise_rule is self-contained.
        rule_id = r.get("rule_id") or HuaweiUSGParser._make_rule_id(rule_name)
        return {
            # ORM columns
            "rule_id":       rule_id,
            "rule_uid":      rule_id,
            "rule_number":   r.get("rule_number", idx + 1),
            "rule_name":     rule_name,
            "section":       r.get("section",     "security-policy"),
            # Source / destination
            "sources":       r.get("sources",      ["any"]),
            "destinations":  r.get("destinations", ["any"]),
            "services":      r.get("services",     ["any"]),
            "applications":  r.get("applications", []),
            "users":         r.get("users",        []),
            "vpn":           [],
            "install_on":    [],
            # Zones (stored in source_interfaces / destination_interfaces)
            "source_interfaces":      r.get("src_zones", []),
            "destination_interfaces": r.get("dst_zones", []),
            # Flags
            "action":          r.get("action",          "deny"),
            "enabled":         r.get("enabled",         True),
            "logging_enabled": r.get("logging_enabled", False),
            "nat_enabled":     False,
            # Stats
            "hit_count": r.get("hit_count"),
            "last_hit":  r.get("last_hit"),
            "first_hit": r.get("first_hit"),
            # Meta
            "schedule": r.get("time_range") or "",
            "comments": r.get("comments",  ""),
            "raw_data": r.get("raw_data",  {}),
        }

    @staticmethod
    def _normalise_object(o: dict) -> dict:
        """
        Map internal object dict to the upload.py / FirewallObject ORM
        expected schema (mirrors the normalized object model in the spec).
        """
        otype = o.get("object_type", "host")
        name  = o.get("name", "")
        value = o.get("value", "")
        members = o.get("members", [])

        # Determine ORM object_type mapping
        orm_type_map = {
            "zone":              "zone",
            "address_group":     "address_group",
            "network":           "network",
            "host":              "host",
            "range":             "range",
            "service":           "service",
            "service_group":     "service-group",
            "application_group": "application-group",
            "time_range":        "time-range",
            "nat-source":        "nat-source",
            "nat-destination":   "nat-destination",
            "nat-static":        "nat-static",
            "nat-easy-ip":       "nat-easy-ip",
        }
        mapped_type = orm_type_map.get(otype, otype)

        return {
            "object_uid":    name,
            "object_name":   name,
            "object_type":   mapped_type,
            "value":         value,
            "members":       members,
            "comment":       o.get("comments", ""),
            "raw_data":      o.get("raw_data", {}),
            # ORM columns not used by Huawei parser
            "protocol": None,
            "port_start": None,
            "port_end": None,
        }
