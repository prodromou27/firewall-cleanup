"""
FortiGate configuration file parser.
Supports FortiGate full config exports (.conf) and firewall policy exports.
"""
import re
import json
from datetime import datetime
from typing import List, Dict, Tuple, Any, Optional
from app.parsers.base import BaseParser


def _fgt_parse_ts(value) -> Optional[str]:
    """
    Convert a FortiGate timestamp to ISO-8601 string.
    FortiGate uses Unix epoch integers (e.g. 1705320000) in config file exports
    and ISO strings in API responses.  Returns None for zero / absent values.
    """
    if value is None or value == "" or value == "0":
        return None
    if isinstance(value, str):
        # Might be an ISO string already
        if re.match(r'^\d{4}-\d{2}-\d{2}', value):
            return value
        # Try parsing as integer unix timestamp string
        try:
            t = int(value)
            if t <= 0:
                return None
            return datetime.utcfromtimestamp(t).isoformat() + "Z"
        except (ValueError, OSError):
            return None
    try:
        t = int(value)
        if t <= 0:
            return None
        return datetime.utcfromtimestamp(t).isoformat() + "Z"
    except (ValueError, TypeError, OSError):
        return None


class FortiGateParser(BaseParser):
    """Parser for FortiGate configuration files."""

    def parse(self, content: str) -> Tuple[List[dict], List[dict], List[str]]:
        warnings = []

        # Try JSON first
        if content.strip().startswith("{") or content.strip().startswith("["):
            try:
                data = json.loads(content)
                return self._parse_json(data, warnings)
            except json.JSONDecodeError:
                pass

        # Parse as FortiGate config text
        return self._parse_config(content, warnings)

    def _parse_config(self, content: str, warnings: List[str]) -> Tuple[List[dict], List[dict], List[str]]:
        """Parse FortiGate text configuration file."""
        rules = []
        objects = []

        # Extract all config sections
        sections = self._extract_sections(content)

        # Parse address objects
        addr_section = sections.get("config firewall address", "")
        if addr_section:
            objects.extend(self._parse_addresses(addr_section))

        # Parse address groups
        addrgrp_section = sections.get("config firewall addrgrp", "")
        if addrgrp_section:
            objects.extend(self._parse_address_groups(addrgrp_section))

        # Parse service objects
        svc_section = sections.get("config firewall service custom", "")
        if svc_section:
            objects.extend(self._parse_services(svc_section))

        # Parse service groups
        svcgrp_section = sections.get("config firewall service group", "")
        if svcgrp_section:
            objects.extend(self._parse_service_groups(svcgrp_section))

        # Parse policies
        policy_section = sections.get("config firewall policy", "")
        if policy_section:
            rules = self._parse_policies(policy_section)
        else:
            warnings.append("No 'config firewall policy' section found in configuration file.")

        if not rules and not objects:
            warnings.append("No rules or objects were parsed. Please verify the file format.")

        return rules, objects, warnings

    def _extract_sections(self, content: str) -> Dict[str, str]:
        """Extract named config sections from FortiGate config."""
        sections = {}
        lines = content.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if line.startswith("config "):
                section_name = line
                depth = 1
                section_lines = []
                i += 1
                while i < len(lines) and depth > 0:
                    l = lines[i]
                    stripped = l.strip()
                    if stripped.startswith("config "):
                        depth += 1
                    elif stripped == "end":
                        depth -= 1
                        if depth == 0:
                            break
                    section_lines.append(l)
                    i += 1
                sections[section_name] = "\n".join(section_lines)
            i += 1
        return sections

    def _parse_entries(self, content: str) -> List[Dict[str, Any]]:
        """Parse 'edit N ... next' blocks into list of dicts."""
        entries = []
        lines = content.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if line.startswith("edit "):
                entry_id = line[5:].strip().strip('"')
                entry = {"_id": entry_id, "_fields": {}}
                i += 1
                depth = 1
                while i < len(lines):
                    l = lines[i].strip()
                    if l == "next":
                        break
                    if l.startswith("set "):
                        # Parse: set key value...
                        parts = l[4:].split(None, 1)
                        if parts:
                            key = parts[0]
                            val = parts[1] if len(parts) > 1 else ""
                            entry["_fields"][key] = val.strip('"')
                    elif l.startswith("config "):
                        # Nested config — skip for now
                        depth2 = 1
                        i += 1
                        while i < len(lines) and depth2 > 0:
                            nl = lines[i].strip()
                            if nl.startswith("config "):
                                depth2 += 1
                            elif nl == "end":
                                depth2 -= 1
                            i += 1
                        continue
                    i += 1
                entries.append(entry)
            i += 1
        return entries

    def _parse_addresses(self, content: str) -> List[dict]:
        objects = []
        entries = self._parse_entries(content)
        for entry in entries:
            f = entry["_fields"]
            name = entry["_id"]
            subnet = f.get("subnet", "")
            obj_type = f.get("type", "ipmask")

            if obj_type in ("ipmask", "subnet") or subnet:
                # Convert "IP MASK" format to CIDR
                value = self._subnet_to_cidr(subnet) if subnet else ""
                objects.append({
                    "object_name": name,
                    "object_type": "network" if "/" in (value or "") and not value.endswith("/32") else "host",
                    "value": value,
                    "protocol": None,
                    "port_start": None,
                    "port_end": None,
                    "members": [],
                    "comment": f.get("comment", ""),
                    "raw_data": f,
                })
            elif obj_type == "iprange":
                start = f.get("start-ip", "")
                end = f.get("end-ip", "")
                objects.append({
                    "object_name": name,
                    "object_type": "range",
                    "value": f"{start}-{end}" if start and end else "",
                    "protocol": None,
                    "port_start": None,
                    "port_end": None,
                    "members": [],
                    "comment": f.get("comment", ""),
                    "raw_data": f,
                })
            elif obj_type == "fqdn":
                objects.append({
                    "object_name": name,
                    "object_type": "fqdn",
                    "value": f.get("fqdn", ""),
                    "protocol": None,
                    "port_start": None,
                    "port_end": None,
                    "members": [],
                    "comment": f.get("comment", ""),
                    "raw_data": f,
                })
            else:
                objects.append({
                    "object_name": name,
                    "object_type": obj_type or "host",
                    "value": subnet or f.get("fqdn", "") or "",
                    "protocol": None,
                    "port_start": None,
                    "port_end": None,
                    "members": [],
                    "comment": f.get("comment", ""),
                    "raw_data": f,
                })
        return objects

    def _parse_address_groups(self, content: str) -> List[dict]:
        objects = []
        entries = self._parse_entries(content)
        for entry in entries:
            f = entry["_fields"]
            name = entry["_id"]
            # Members are space-separated quoted names
            member_str = f.get("member", "")
            members = self._parse_space_list(member_str)
            objects.append({
                "object_name": name,
                "object_type": "group",
                "value": None,
                "protocol": None,
                "port_start": None,
                "port_end": None,
                "members": members,
                "comment": f.get("comment", ""),
                "raw_data": f,
            })
        return objects

    def _parse_services(self, content: str) -> List[dict]:
        objects = []
        entries = self._parse_entries(content)
        for entry in entries:
            f = entry["_fields"]
            name = entry["_id"]
            protocol = f.get("protocol", "TCP/UDP/SCTP").upper()

            # Parse port ranges
            tcp_portrange = f.get("tcp-portrange", "")
            udp_portrange = f.get("udp-portrange", "")

            if tcp_portrange:
                ps, pe = self._parse_portrange(tcp_portrange)
                objects.append({
                    "object_name": name,
                    "object_type": "service",
                    "value": f"tcp/{ps}-{pe}",
                    "protocol": "tcp",
                    "port_start": ps,
                    "port_end": pe,
                    "members": [],
                    "comment": f.get("comment", ""),
                    "raw_data": f,
                })
            elif udp_portrange:
                ps, pe = self._parse_portrange(udp_portrange)
                objects.append({
                    "object_name": name,
                    "object_type": "service",
                    "value": f"udp/{ps}-{pe}",
                    "protocol": "udp",
                    "port_start": ps,
                    "port_end": pe,
                    "members": [],
                    "comment": f.get("comment", ""),
                    "raw_data": f,
                })
            elif "ICMP" in protocol:
                objects.append({
                    "object_name": name,
                    "object_type": "service",
                    "value": "icmp",
                    "protocol": "icmp",
                    "port_start": 0,
                    "port_end": 0,
                    "members": [],
                    "comment": f.get("comment", ""),
                    "raw_data": f,
                })
            else:
                objects.append({
                    "object_name": name,
                    "object_type": "service",
                    "value": "any",
                    "protocol": "any",
                    "port_start": 0,
                    "port_end": 65535,
                    "members": [],
                    "comment": f.get("comment", ""),
                    "raw_data": f,
                })
        return objects

    def _parse_service_groups(self, content: str) -> List[dict]:
        objects = []
        entries = self._parse_entries(content)
        for entry in entries:
            f = entry["_fields"]
            name = entry["_id"]
            member_str = f.get("member", "")
            members = self._parse_space_list(member_str)
            objects.append({
                "object_name": name,
                "object_type": "service-group",
                "value": None,
                "protocol": None,
                "port_start": None,
                "port_end": None,
                "members": members,
                "comment": f.get("comment", ""),
                "raw_data": f,
            })
        return objects

    def _parse_policies(self, content: str) -> List[dict]:
        rules = []
        entries = self._parse_entries(content)
        current_section = ""

        for idx, entry in enumerate(entries):
            f = entry["_fields"]
            rule_id = entry["_id"]
            rule_name = f.get("name", f"Policy {rule_id}")

            # FortiGate section markers: policy names matching "--- Section Name ---"
            # These are special policies used as visual dividers; tag following rules.
            section_m = re.match(r'^-+\s*(.+?)\s*-+$', rule_name)
            if section_m:
                current_section = section_m.group(1).strip()

            # Parse source/dest/service lists
            srcaddr = self._parse_space_list(f.get("srcaddr", ""))
            dstaddr = self._parse_space_list(f.get("dstaddr", ""))
            service = self._parse_space_list(f.get("service", ""))
            srcintf = self._parse_space_list(f.get("srcintf", ""))
            dstintf = self._parse_space_list(f.get("dstintf", ""))

            # Normalize "all" to "any"
            srcaddr = ["any" if s.lower() == "all" else s for s in srcaddr]
            dstaddr = ["any" if d.lower() == "all" else d for d in dstaddr]
            service = ["any" if s.lower() == "all" else s for s in service]

            action = f.get("action", "accept").lower()
            status = f.get("status", "enable")
            # logtraffic defaults to "utm" (FGT built-in default = log UTM events = ON).
            # "disable" and "none" both mean logging OFF.
            logtraffic = f.get("logtraffic", "utm")
            nat = f.get("nat", "disable")

            # Hit count — present in some config exports (get system performance stat /
            # backup with statistics), rarely in standard backups.
            hit_count = None
            hc = f.get("hitc", f.get("hit-count", f.get("hit_count", "")))
            if hc:
                try:
                    hit_count = int(hc)
                except (ValueError, TypeError):
                    pass

            # Timestamps: first-used / last-used may appear as unix timestamps
            last_hit = _fgt_parse_ts(f.get("last-used") or f.get("last_used"))
            first_hit = _fgt_parse_ts(f.get("first-used") or f.get("first_used"))

            rules.append({
                "vendor": "FortiGate",
                "rule_id": rule_id,
                "rule_uid": f.get("uuid", ""),
                "rule_number": idx + 1,
                "rule_name": rule_name,
                "section": current_section,
                "source_interfaces": srcintf,
                "destination_interfaces": dstintf,
                "sources": srcaddr,
                "destinations": dstaddr,
                "services": service,
                "applications": self._parse_space_list(f.get("application", "")),
                "users": self._parse_space_list(f.get("users", "")),
                "vpn": [],
                "action": action,
                "schedule": f.get("schedule", "always"),
                "enabled": status.lower() == "enable",
                "logging_enabled": logtraffic.lower() not in ("disable", "none"),
                "nat_enabled": nat.lower() == "enable",
                "comments": f.get("comments", ""),
                "hit_count": hit_count,
                "last_hit": last_hit,
                "first_hit": first_hit,
                "install_on": [],
                "raw_data": f,
            })
        return rules

    def _parse_json(self, data: Any, warnings: List[str]) -> Tuple[List[dict], List[dict], List[str]]:
        """Parse FortiGate JSON export."""
        rules = []
        objects = []

        if isinstance(data, list):
            # Assume list of policies
            for idx, item in enumerate(data):
                if isinstance(item, dict):
                    rules.append(self._json_rule_to_normalized(item, idx))
        elif isinstance(data, dict):
            if "results" in data:
                for idx, item in enumerate(data["results"]):
                    rules.append(self._json_rule_to_normalized(item, idx))
            else:
                rules.append(self._json_rule_to_normalized(data, 0))

        return rules, objects, warnings

    def _json_rule_to_normalized(self, item: dict, idx: int) -> dict:
        def get_names(field) -> List[str]:
            if isinstance(field, list):
                return [x.get("name", str(x)) if isinstance(x, dict) else str(x) for x in field]
            if isinstance(field, str):
                return [field]
            return []

        return {
            "vendor": "FortiGate",
            "rule_id": str(item.get("policyid", idx + 1)),
            "rule_uid": item.get("uuid", ""),
            "rule_number": idx + 1,
            "rule_name": item.get("name", f"Policy {idx + 1}"),
            "section": "",
            "source_interfaces": get_names(item.get("srcintf", [])),
            "destination_interfaces": get_names(item.get("dstintf", [])),
            "sources": get_names(item.get("srcaddr", [])),
            "destinations": get_names(item.get("dstaddr", [])),
            "services": get_names(item.get("service", [])),
            "applications": get_names(item.get("application", [])),
            "users": get_names(item.get("users", [])),
            "vpn": [],
            "action": item.get("action", "accept"),
            "schedule": item.get("schedule", "always"),
            "enabled": item.get("status", "enable") == "enable",
            "logging_enabled": (item.get("logtraffic", "utm") or "utm").lower() not in ("disable", "none"),
            "nat_enabled": item.get("nat", "disable") == "enable",
            "comments": item.get("comments", ""),
            "hit_count": item.get("hitc", item.get("hit_count", None)),
            "last_hit": _fgt_parse_ts(item.get("last-used") or item.get("last_used")),
            "first_hit": _fgt_parse_ts(item.get("first-used") or item.get("first_used")),
            "install_on": [],
            "raw_data": item,
        }

    def _subnet_to_cidr(self, subnet: str) -> str:
        """Convert 'IP MASK' or 'IP/PREFIX' to CIDR notation."""
        subnet = subnet.strip()
        if "/" in subnet:
            return subnet
        parts = subnet.split()
        if len(parts) == 2:
            import ipaddress
            try:
                network = ipaddress.IPv4Network(f"{parts[0]}/{parts[1]}", strict=False)
                return str(network)
            except ValueError:
                return subnet
        return subnet

    def _parse_portrange(self, portrange: str) -> Tuple[int, int]:
        """Parse FortiGate port range like '80', '80-443', '80:443'."""
        portrange = portrange.strip().split()[0]  # Take first range if multiple
        portrange = portrange.replace(":", "-")
        if "-" in portrange:
            parts = portrange.split("-")
            try:
                return int(parts[0]), int(parts[1])
            except (ValueError, IndexError):
                return 0, 65535
        try:
            p = int(portrange)
            return p, p
        except ValueError:
            return 0, 65535

    def _parse_space_list(self, value: str) -> List[str]:
        """Parse space-separated quoted list from FortiGate config."""
        if not value:
            return []
        # Remove quotes and split
        items = re.findall(r'"([^"]+)"|(\S+)', value)
        return [a or b for a, b in items if (a or b)]
