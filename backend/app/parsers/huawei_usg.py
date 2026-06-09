"""
Huawei USG Config Parser
=========================
Parses ``display current-configuration`` / ``display saved-configuration``
text output from Huawei USG2000 / USG5000 / USG6000 / USG9000 series.

Huawei VRP CLI config structure (relevant sections):
  firewall zone <name>              → security zone definitions
    set priority <n>
    add interface <if>

  ip address-set <name> type object  → address objects
    address <n> <ip> mask <prefix>
    address <n> range <start> <end>

  ip address-set <name> type group   → address groups
    address address-set <member>

  ip service-set <name> type object  → service objects
    service <n> protocol tcp source-port <p1> destination-port <p2>

  security-policy                    → the main security policy block
    rule name <name>                 → individual rule
      source-zone <zone>
      destination-zone <zone>
      source-address address-set <name>
      destination-address address-set <name>
      service service-set <name>
      action permit | deny
      profile ...
      description <text>

This parser handles the most common forms. Degenerate / partial exports
will produce warnings.
"""
from __future__ import annotations

import re
from typing import List, Dict, Tuple, Any, Optional
from app.parsers.base import BaseParser


class HuaweiUSGParser(BaseParser):
    """Parser for Huawei USG firewall text config exports."""

    def parse(self, content: str) -> Tuple[List[dict], List[dict], List[str]]:
        warnings: List[str] = []
        lines = content.splitlines()

        rules: List[dict] = []
        objects: List[dict] = []

        # Detect if this looks like a Huawei config
        has_huawei_marker = any(
            kw in content
            for kw in ("firewall zone", "security-policy", "ip address-set", "sysname", "#\nversion")
        )
        if not has_huawei_marker:
            warnings.append(
                "File does not appear to be a Huawei USG config. "
                "Export using 'display current-configuration' or 'display saved-configuration'."
            )

        # Parse address objects
        addr_objects = self._parse_address_sets(lines, warnings)
        objects.extend(addr_objects)

        # Parse security policy rules
        rules = self._parse_security_policy(lines, warnings)

        if not rules:
            warnings.append(
                "No security policy rules found. "
                "Ensure the export includes the 'security-policy' section."
            )

        return rules, objects, warnings

    # ── Address set parsing ────────────────────────────────────────────────

    def _parse_address_sets(self, lines: List[str], warnings: List[str]) -> List[dict]:
        objects: List[dict] = []
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            m = re.match(r'^ip address-set\s+(\S+)\s+type\s+(object|group)', line)
            if m:
                name = m.group(1)
                kind = m.group(2)
                members: List[str] = []
                i += 1
                while i < len(lines):
                    inner = lines[i].strip()
                    if inner == "#" or (inner and not inner.startswith(" ") and not inner.startswith("address") and inner != "#"):
                        break
                    am = re.match(r'address\s+\d+\s+([\d.]+)\s+mask\s+([\d.]+)', inner)
                    rm = re.match(r'address\s+\d+\s+range\s+([\d.]+)\s+([\d.]+)', inner)
                    gm = re.match(r'address\s+address-set\s+(\S+)', inner)
                    hm = re.match(r'address\s+\d+\s+([\d.]+)/([\d]+)', inner)
                    if am:
                        members.append(f"{am.group(1)}/{self._mask_to_prefix(am.group(2))}")
                    elif rm:
                        members.append(f"{rm.group(1)}-{rm.group(2)}")
                    elif gm:
                        members.append(gm.group(1))
                    elif hm:
                        members.append(f"{hm.group(1)}/{hm.group(2)}")
                    i += 1
                objects.append({
                    "type": "address_group" if kind == "group" else "host",
                    "name": name,
                    "members": members,
                })
                continue
            i += 1
        return objects

    @staticmethod
    def _mask_to_prefix(mask: str) -> int:
        """Convert dotted-decimal mask to prefix length."""
        try:
            return bin(int(''.join(mask.split(".")), 2) if mask.replace(".", "").isdigit()
                       else sum(bin(int(o)).count("1") for o in mask.split("."))).count("1")
        except Exception:
            return 32

    # ── Security policy parsing ────────────────────────────────────────────

    def _parse_security_policy(self, lines: List[str], warnings: List[str]) -> List[dict]:
        rules: List[dict] = []
        in_sec_policy = False
        in_rule = False
        current_rule: Dict[str, Any] = {}
        rule_idx = 0

        for i, raw_line in enumerate(lines):
            stripped = raw_line.strip()

            # Enter / exit security-policy block
            if stripped == "security-policy":
                in_sec_policy = True
                continue
            if in_sec_policy and stripped == "#":
                if in_rule and current_rule:
                    rules.append(self._finalise_rule(current_rule, rule_idx))
                    rule_idx += 1
                in_rule = False
                current_rule = {}
                in_sec_policy = False
                continue

            if not in_sec_policy:
                continue

            # New rule
            m_rule = re.match(r'^\s+rule name\s+(.+)$', raw_line)
            if m_rule:
                if in_rule and current_rule:
                    rules.append(self._finalise_rule(current_rule, rule_idx))
                    rule_idx += 1
                current_rule = {
                    "rule_name": m_rule.group(1).strip(),
                    "sources": [], "destinations": [], "services": [],
                    "src_zones": [], "dst_zones": [], "applications": [],
                    "action": "deny", "enabled": True, "logging": True,
                    "comments": "",
                }
                in_rule = True
                continue

            if not in_rule:
                continue

            # Source / destination zones
            if re.match(r'^\s+source-zone\s+', raw_line):
                zone = re.sub(r'^\s+source-zone\s+', '', raw_line).strip()
                current_rule["src_zones"].append(zone)
            elif re.match(r'^\s+destination-zone\s+', raw_line):
                zone = re.sub(r'^\s+destination-zone\s+', '', raw_line).strip()
                current_rule["dst_zones"].append(zone)

            # Source address
            elif re.match(r'^\s+source-address\s+', raw_line):
                val = re.sub(r'^\s+source-address\s+(address-set\s+)?', '', raw_line).strip()
                current_rule["sources"].append(val)

            # Destination address
            elif re.match(r'^\s+destination-address\s+', raw_line):
                val = re.sub(r'^\s+destination-address\s+(address-set\s+)?', '', raw_line).strip()
                current_rule["destinations"].append(val)

            # Service
            elif re.match(r'^\s+service\s+', raw_line):
                val = re.sub(r'^\s+service\s+(service-set\s+)?', '', raw_line).strip()
                current_rule["services"].append(val)

            # Application
            elif re.match(r'^\s+application\s+', raw_line):
                val = re.sub(r'^\s+application\s+(app\s+)?', '', raw_line).strip()
                current_rule["applications"].append(val)

            # Action
            elif re.match(r'^\s+action\s+', raw_line):
                action_raw = re.sub(r'^\s+action\s+', '', raw_line).strip().lower()
                current_rule["action"] = "accept" if action_raw == "permit" else action_raw

            # Disable
            elif stripped == "disable":
                current_rule["enabled"] = False

            # Logging
            elif re.match(r'^\s+policy logging\b', raw_line):
                current_rule["logging"] = True
            elif stripped == "undo policy logging":
                current_rule["logging"] = False

            # Description
            elif re.match(r'^\s+description\s+', raw_line):
                current_rule["comments"] = re.sub(r'^\s+description\s+', '', raw_line).strip()

        # Flush last rule if file ends without #
        if in_rule and current_rule:
            rules.append(self._finalise_rule(current_rule, rule_idx))

        return rules

    @staticmethod
    def _finalise_rule(r: Dict[str, Any], idx: int) -> dict:
        srcs = r["sources"] or (r.get("src_zones") or ["any"])
        dsts = r["destinations"] or (r.get("dst_zones") or ["any"])
        svcs = r["services"] or ["any"]
        return {
            "rule_id":        f"huawei-rule-{idx}",
            "rule_number":    idx + 1,
            "rule_name":      r.get("rule_name", f"Rule-{idx+1}"),
            "section":        None,
            "sources":        srcs,
            "destinations":   dsts,
            "services":       svcs,
            "applications":   r.get("applications", []),
            "action":         r.get("action", "deny"),
            "enabled":        r.get("enabled", True),
            "logging_enabled": r.get("logging", True),
            "hit_count":      None,
            "last_hit":       None,
            "comments":       r.get("comments", ""),
            "src_zones":      r.get("src_zones", []),
            "dst_zones":      r.get("dst_zones", []),
        }
