"""
Check Point policy parser.
Supports Check Point JSON policy package exports and management API output.
"""
import json
import re
from typing import List, Dict, Tuple, Any, Optional
from app.parsers.base import BaseParser


class CheckPointParser(BaseParser):
    """Parser for Check Point policy exports."""

    def parse(self, content: str) -> Tuple[List[dict], List[dict], List[str]]:
        warnings = []

        if not (content.strip().startswith("{") or content.strip().startswith("[")):
            warnings.append("Check Point parser expects JSON format. The uploaded file does not appear to be JSON.")
            return [], [], warnings

        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            warnings.append(f"Failed to parse JSON: {e}")
            return [], [], warnings

        return self._parse_json(data, warnings)

    def _parse_json(self, data: Any, warnings: List[str]) -> Tuple[List[dict], List[dict], List[str]]:
        rules = []
        objects = []

        if isinstance(data, list):
            # Assume list of rules
            for idx, item in enumerate(data):
                if isinstance(item, dict):
                    rules.append(self._normalize_rule(item, idx))
        elif isinstance(data, dict):
            # Check for management API structure
            if "rulebase" in data:
                rb = data["rulebase"]
                rules, objects = self._parse_rulebase(rb, data.get("objects", {}), warnings)
            elif "data" in data and isinstance(data["data"], list):
                for idx, item in enumerate(data["data"]):
                    rules.append(self._normalize_rule(item, idx))
            elif "objects" in data:
                objects = self._parse_objects(data["objects"], warnings)
                if "access-rules" in data:
                    for idx, item in enumerate(data["access-rules"]):
                        rules.append(self._normalize_rule(item, idx))
            else:
                rules.append(self._normalize_rule(data, 0))

        if not rules and not objects:
            warnings.append("No rules or objects were found in the Check Point export.")

        return rules, objects, warnings

    def _parse_rulebase(
        self, rulebase: Any, objects_data: Any, warnings: List[str]
    ) -> Tuple[List[dict], List[dict]]:
        rules = []
        objects = []

        if isinstance(objects_data, dict):
            for uid, obj in objects_data.items():
                parsed_obj = self._normalize_object(obj)
                if parsed_obj:
                    objects.append(parsed_obj)
        elif isinstance(objects_data, list):
            for obj in objects_data:
                parsed_obj = self._normalize_object(obj)
                if parsed_obj:
                    objects.append(parsed_obj)

        if isinstance(rulebase, list):
            rule_num = 1
            for item in rulebase:
                if isinstance(item, dict):
                    if item.get("type") == "access-section":
                        section_name = item.get("name", "")
                        for rule in item.get("rulebase", []):
                            r = self._normalize_rule(rule, rule_num - 1, section=section_name)
                            rules.append(r)
                            rule_num += 1
                    else:
                        r = self._normalize_rule(item, rule_num - 1)
                        rules.append(r)
                        rule_num += 1

        return rules, objects

    def _parse_objects(self, objects_data: Any, warnings: List[str]) -> List[dict]:
        objects = []
        if isinstance(objects_data, list):
            for obj in objects_data:
                parsed = self._normalize_object(obj)
                if parsed:
                    objects.append(parsed)
        elif isinstance(objects_data, dict):
            for uid, obj in objects_data.items():
                parsed = self._normalize_object(obj)
                if parsed:
                    objects.append(parsed)
        return objects

    def _normalize_rule(self, item: dict, idx: int, section: str = "") -> dict:
        """Normalize a Check Point rule to common format."""
        def get_names(field) -> List[str]:
            if field is None:
                return ["any"]
            if isinstance(field, str):
                return [field]
            if isinstance(field, list):
                result = []
                for x in field:
                    if isinstance(x, dict):
                        result.append(x.get("name", x.get("uid", str(x))))
                    else:
                        result.append(str(x))
                return result or ["any"]
            if isinstance(field, dict):
                return [field.get("name", field.get("uid", "any"))]
            return ["any"]

        def get_action(field) -> str:
            if isinstance(field, dict):
                name = field.get("name", "").lower()
            elif isinstance(field, str):
                name = field.lower()
            else:
                return "unknown"
            if name in ("accept", "allow"):
                return "accept"
            if name in ("drop", "deny", "reject"):
                return "deny"
            return name

        def get_bool(field, default=True) -> bool:
            if isinstance(field, bool):
                return field
            if isinstance(field, str):
                return field.lower() in ("true", "yes", "enabled", "enable", "1")
            return default

        track = item.get("track", {})
        if isinstance(track, dict):
            log_type = track.get("type", {})
            if isinstance(log_type, dict):
                log_name = log_type.get("name", "")
            else:
                log_name = str(log_type)
            logging_enabled = log_name.lower() not in ("none", "")
        else:
            logging_enabled = True

        hit_count = None
        hc = item.get("hits", item.get("hit-count", {}))
        if isinstance(hc, dict):
            hit_count = hc.get("value", hc.get("count", None))
        elif isinstance(hc, (int, float)):
            hit_count = int(hc)

        last_hit = None
        lh = item.get("hits", {})
        if isinstance(lh, dict):
            last_hit = lh.get("last-date", {})
            if isinstance(last_hit, dict):
                last_hit = last_hit.get("iso-8601", last_hit.get("posix", None))

        return {
            "vendor": "CheckPoint",
            "rule_id": str(item.get("rule-number", item.get("rule_number", idx + 1))),
            "rule_uid": item.get("uid", ""),
            "rule_number": int(item.get("rule-number", item.get("rule_number", idx + 1))),
            "rule_name": item.get("name", f"Rule {idx + 1}"),
            "section": section or item.get("section", ""),
            "source_interfaces": [],
            "destination_interfaces": [],
            "sources": get_names(item.get("source")),
            "destinations": get_names(item.get("destination")),
            "services": get_names(item.get("service")),
            "applications": get_names(item.get("application")),
            "users": get_names(item.get("content-match", {}).get("users", [])),
            "vpn": get_names(item.get("vpn")),
            "action": get_action(item.get("action")),
            "schedule": self._get_name(item.get("time")),
            "enabled": get_bool(item.get("enabled"), True),
            "logging_enabled": logging_enabled,
            "nat_enabled": False,
            "comments": item.get("comments", item.get("comment", "")),
            "hit_count": hit_count,
            "last_hit": last_hit,
            "first_hit": None,
            "install_on": get_names(item.get("install-on")),
            "raw_data": item,
        }

    def _normalize_object(self, obj: dict) -> Optional[dict]:
        """Normalize a Check Point object."""
        if not isinstance(obj, dict):
            return None

        obj_type = obj.get("type", "").lower()
        name = obj.get("name", "")
        uid = obj.get("uid", "")

        if not name:
            return None

        if obj_type in ("host", "simple-gateway", "checkpoint-host"):
            return {
                "object_name": name,
                "object_uid": uid,
                "object_type": "host",
                "value": obj.get("ipv4-address", obj.get("ip-address", "")),
                "protocol": None,
                "port_start": None,
                "port_end": None,
                "members": [],
                "comment": obj.get("comments", ""),
                "raw_data": obj,
            }

        if obj_type in ("network", "subnet"):
            subnet = obj.get("subnet4", obj.get("subnet", ""))
            mask = obj.get("mask-length4", obj.get("mask-length", ""))
            value = f"{subnet}/{mask}" if subnet and mask else subnet
            return {
                "object_name": name,
                "object_uid": uid,
                "object_type": "network",
                "value": value,
                "protocol": None,
                "port_start": None,
                "port_end": None,
                "members": [],
                "comment": obj.get("comments", ""),
                "raw_data": obj,
            }

        if obj_type == "address-range":
            return {
                "object_name": name,
                "object_uid": uid,
                "object_type": "range",
                "value": f"{obj.get('ipv4-address-first', '')}-{obj.get('ipv4-address-last', '')}",
                "protocol": None,
                "port_start": None,
                "port_end": None,
                "members": [],
                "comment": obj.get("comments", ""),
                "raw_data": obj,
            }

        if obj_type in ("group", "multicast-address-range"):
            members = []
            for m in obj.get("members", []):
                if isinstance(m, dict):
                    members.append(m.get("name", ""))
                elif isinstance(m, str):
                    members.append(m)
            return {
                "object_name": name,
                "object_uid": uid,
                "object_type": "group",
                "value": None,
                "protocol": None,
                "port_start": None,
                "port_end": None,
                "members": [m for m in members if m],
                "comment": obj.get("comments", ""),
                "raw_data": obj,
            }

        if obj_type in ("service-tcp", "tcp"):
            port = str(obj.get("port", "0-65535"))
            ps, pe = self._parse_port(port)
            return {
                "object_name": name,
                "object_uid": uid,
                "object_type": "service",
                "value": f"tcp/{ps}-{pe}",
                "protocol": "tcp",
                "port_start": ps,
                "port_end": pe,
                "members": [],
                "comment": obj.get("comments", ""),
                "raw_data": obj,
            }

        if obj_type in ("service-udp", "udp"):
            port = str(obj.get("port", "0-65535"))
            ps, pe = self._parse_port(port)
            return {
                "object_name": name,
                "object_uid": uid,
                "object_type": "service",
                "value": f"udp/{ps}-{pe}",
                "protocol": "udp",
                "port_start": ps,
                "port_end": pe,
                "members": [],
                "comment": obj.get("comments", ""),
                "raw_data": obj,
            }

        if obj_type in ("service-group", "group-with-exclusion"):
            members = []
            for m in obj.get("members", []):
                if isinstance(m, dict):
                    members.append(m.get("name", ""))
                elif isinstance(m, str):
                    members.append(m)
            return {
                "object_name": name,
                "object_uid": uid,
                "object_type": "service-group",
                "value": None,
                "protocol": None,
                "port_start": None,
                "port_end": None,
                "members": [m for m in members if m],
                "comment": obj.get("comments", ""),
                "raw_data": obj,
            }

        return None

    def _get_name(self, field) -> str:
        if isinstance(field, dict):
            return field.get("name", "")
        if isinstance(field, str):
            return field
        return ""

    def _parse_port(self, port_str: str) -> Tuple[int, int]:
        port_str = str(port_str).strip()
        if "-" in port_str:
            parts = port_str.split("-")
            try:
                return int(parts[0]), int(parts[1])
            except (ValueError, IndexError):
                return 0, 65535
        try:
            p = int(port_str)
            return p, p
        except ValueError:
            return 0, 65535
