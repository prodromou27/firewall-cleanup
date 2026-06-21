"""
Palo Alto Networks (PAN-OS / Panorama) Config Parser  —  File-Based Import
==========================================================================
Parses PAN-OS device and Panorama XML configuration exports:

  - Device config:   config/devices/entry/vsys/entry/rulebase/security/rules
  - Panorama config: .../device-group/entry/{pre|post}-rulebase/security/rules

Supported objects
-----------------
  address        entry/ip-netmask | ip-range | fqdn
  address-group  entry/static/member | dynamic/filter
  service        entry/protocol/{tcp|udp}/port
  service-group  entry/members/member

Security rules: from/to (zones), source, destination, service, application,
action (allow/deny/drop/reset), disabled, log-setting, description, tag.

Output schema mirrors app.parsers.base / FirewallRule + FirewallObject.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import List, Dict, Tuple, Any, Optional
from app.parsers.base import BaseParser


def _members(elem: Optional[ET.Element], path: str) -> List[str]:
    """Return text of all <member> children at the given relative path."""
    if elem is None:
        return []
    container = elem.find(path)
    if container is None:
        return []
    vals = [m.text.strip() for m in container.findall("member") if m.text and m.text.strip()]
    return vals


def _text(elem: Optional[ET.Element], path: str, default: str = "") -> str:
    if elem is None:
        return default
    node = elem.find(path)
    if node is not None and node.text:
        return node.text.strip()
    return default


def _raw_xml(elem: ET.Element) -> dict:
    return {"xml": ET.tostring(elem, encoding="unicode")}


class PaloAltoParser(BaseParser):
    """Parser for PAN-OS / Panorama XML configuration exports."""

    VENDOR = "PaloAlto"

    def parse(self, content: str) -> Tuple[List[dict], List[dict], List[str]]:
        warnings: List[str] = []

        stripped = content.lstrip()
        if not stripped.startswith("<"):
            warnings.append(
                "File does not look like PAN-OS XML. Export the configuration as "
                "XML (Panorama/device config) — 'set'-format CLI output is not supported."
            )
            return [], [], warnings

        try:
            root = ET.fromstring(content)
        except ET.ParseError as e:
            warnings.append(f"XML parse error: {e}. Verify the file is a complete PAN-OS XML export.")
            return [], [], warnings

        objects: List[dict] = []
        objects.extend(self._parse_addresses(root))
        objects.extend(self._parse_address_groups(root))
        objects.extend(self._parse_services(root))
        objects.extend(self._parse_service_groups(root))

        rules = self._parse_security_rules(root, warnings)

        if not rules:
            warnings.append(
                "No security rules found. Ensure the export contains a "
                "rulebase/security/rules section (device vsys or Panorama device-group)."
            )
        return rules, objects, warnings

    # ── objects ────────────────────────────────────────────────────────────────
    def _parse_addresses(self, root: ET.Element) -> List[dict]:
        out: List[dict] = []
        seen = set()
        for addr in root.iter("address"):
            for entry in addr.findall("./entry"):
                name = entry.get("name")
                if not name or name in seen:
                    continue
                seen.add(name)
                if entry.find("ip-netmask") is not None:
                    value = _text(entry, "ip-netmask")
                    otype = "network" if "/" in value and not value.endswith("/32") else "host"
                elif entry.find("ip-range") is not None:
                    value, otype = _text(entry, "ip-range"), "range"
                elif entry.find("fqdn") is not None:
                    value, otype = _text(entry, "fqdn"), "fqdn"
                else:
                    value, otype = "", "host"
                out.append(self._obj(name, otype, value, [],
                                      comment=_text(entry, "description"), raw_data=_raw_xml(entry)))
        return out

    def _parse_address_groups(self, root: ET.Element) -> List[dict]:
        out: List[dict] = []
        seen = set()
        for grp in root.iter("address-group"):
            for entry in grp.findall("./entry"):
                name = entry.get("name")
                if not name or name in seen:
                    continue
                seen.add(name)
                members = _members(entry, "static")
                value = ""
                if entry.find("dynamic") is not None:
                    value = "dynamic: " + _text(entry, "dynamic/filter")
                out.append(self._obj(name, "address_group", value, members,
                                      comment=_text(entry, "description"), raw_data=_raw_xml(entry)))
        return out

    def _parse_services(self, root: ET.Element) -> List[dict]:
        out: List[dict] = []
        seen = set()
        for svc in root.iter("service"):
            for entry in svc.findall("./entry"):
                name = entry.get("name")
                if not name or name in seen:
                    continue
                seen.add(name)
                proto, port = None, ""
                if entry.find("protocol/tcp") is not None:
                    proto, port = "tcp", _text(entry, "protocol/tcp/port")
                elif entry.find("protocol/udp") is not None:
                    proto, port = "udp", _text(entry, "protocol/udp/port")
                ps, pe = self._port_range(port)
                out.append({
                    "object_uid": name, "object_name": name, "object_type": "service",
                    "value": f"{proto}/{port}" if proto else port, "members": [],
                    "comment": _text(entry, "description"),
                    "protocol": proto, "port_start": ps, "port_end": pe, "raw_data": _raw_xml(entry),
                })
        return out

    def _parse_service_groups(self, root: ET.Element) -> List[dict]:
        out: List[dict] = []
        seen = set()
        for grp in root.iter("service-group"):
            for entry in grp.findall("./entry"):
                name = entry.get("name")
                if not name or name in seen:
                    continue
                seen.add(name)
                members = _members(entry, "members")
                out.append(self._obj(name, "service-group", "", members, raw_data=_raw_xml(entry)))
        return out

    @staticmethod
    def _port_range(port: str):
        if not port:
            return None, None
        first = port.split(",")[0].strip()
        try:
            if "-" in first:
                a, b = first.split("-", 1)
                return int(a), int(b)
            return int(first), int(first)
        except ValueError:
            return None, None

    @staticmethod
    def _obj(name: str, otype: str, value: str, members: List[str], comment: str = "", raw_data: Optional[dict] = None) -> dict:
        return {
            "object_uid": name, "object_name": name, "object_type": otype,
            "value": value, "members": members, "comment": comment,
            "protocol": None, "port_start": None, "port_end": None, "raw_data": raw_data or {},
        }

    # ── security rules ───────────────────────────────────────────────────────────
    def _parse_security_rules(self, root: ET.Element, warnings: List[str]) -> List[dict]:
        rules: List[dict] = []
        idx = 0
        for sec in root.iter("security"):
            rules_container = sec.find("./rules")
            if rules_container is None:
                continue
            # Determine rulebase scope (pre/post) for the section label.
            for entry in rules_container.findall("./entry"):
                name = entry.get("name") or f"rule-{idx + 1}"
                action_raw = _text(entry, "action", "allow").lower()
                action = "accept" if action_raw in ("allow", "permit") else "deny"
                disabled = _text(entry, "disabled", "no").lower() in ("yes", "true")
                log_end = _text(entry, "log-end", "no").lower() in ("yes", "true")
                log_start = _text(entry, "log-start", "no").lower() in ("yes", "true")
                log_setting = _text(entry, "log-setting")
                logging = log_end or log_start or bool(log_setting)

                sources = _members(entry, "source") or ["any"]
                destinations = _members(entry, "destination") or ["any"]
                services = _members(entry, "service") or ["any"]
                applications = _members(entry, "application")
                if applications == ["any"]:
                    applications = []
                from_zones = _members(entry, "from")
                to_zones = _members(entry, "to")
                users = _members(entry, "source-user")
                if users == ["any"]:
                    users = []
                tags = _members(entry, "tag")

                idx += 1
                rules.append({
                    "rule_id": name,
                    "rule_uid": entry.get("uuid") or name,
                    "rule_number": idx,
                    "rule_name": name,
                    "section": "security",
                    "sources": sources,
                    "destinations": destinations,
                    "services": services,
                    "applications": applications,
                    "users": users,
                    "vpn": [],
                    "install_on": [],
                    "source_interfaces": from_zones,
                    "destination_interfaces": to_zones,
                    "action": action,
                    "enabled": not disabled,
                    "logging_enabled": logging,
                    "nat_enabled": False,
                    "hit_count": None,
                    "last_hit": None,
                    "first_hit": None,
                    "schedule": _text(entry, "schedule"),
                    "comments": _text(entry, "description"),
                    "raw_data": {**_raw_xml(entry), "tags": tags, "rule_type": _text(entry, "rule-type")},
                })
        return rules
