"""
Check Point policy parser.
Supports Check Point JSON policy package exports and management API output.
"""
import json
import re
from typing import List, Dict, Tuple, Any, Optional
from app.parsers.base import BaseParser
from app.parsers.checkpoint_semantics import reference_name, normalize_action, negated_fields


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
        dictionary = data.get("objects-dictionary", data.get("objects", [])) if isinstance(data, dict) else []
        entries = list(dictionary.values()) if isinstance(dictionary, dict) else dictionary
        self._references = {o["uid"]: o for o in entries if isinstance(o, dict) and o.get("uid")}

        if isinstance(data, list):
            # Assume list of rules
            for idx, item in enumerate(data):
                if isinstance(item, dict):
                    rules.append(self._normalize_rule(item, idx))
        elif isinstance(data, dict):
            # Check for management API structure
            if "rulebase" in data:
                rb = data["rulebase"]
                rules, objects = self._parse_rulebase(rb, dictionary, warnings)
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

        if isinstance(data, dict) and "rulebase" in data:
            layer = data.get("uid") or data.get("name") or data.get("_layer")
            for rule in rules:
                rule["raw_data"] = {**rule["raw_data"], "_layer": rule["raw_data"].get("_layer") or layer or ""}
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
            pending = [(item, "", False) for item in reversed(rulebase)]
            while pending:
                item, section, inline = pending.pop()
                if not isinstance(item, dict):
                    continue
                if item.get("type") == "access-section":
                    pending.extend((child, item.get("name", section), inline)
                                   for child in reversed(item.get("rulebase") or []))
                    continue
                rule = self._normalize_rule(item, len(rules), section=section)
                if inline:
                    rule["raw_data"]["_inline_parent_unmodeled"] = True
                rules.append(rule)
                if isinstance(item.get("rulebase"), list):
                    warnings.append("Inline-layer parent scope is not modeled; child traffic comparisons are suppressed.")
                    pending.extend((child, section, True) for child in reversed(item["rulebase"]))

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
                return []
            if isinstance(field, str):
                return [reference_name(getattr(self, "_references", {}).get(field, field))]
            if isinstance(field, list):
                result = []
                for x in field:
                    if isinstance(x, dict):
                        result.extend(get_names(reference_name(x)))
                    else:
                        result.extend(get_names(str(x)))
                return result
            if isinstance(field, dict):
                return get_names(reference_name(field))
            return []

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
            "rule_number": int(str(item.get("rule-number", item.get("rule_number", idx + 1))))
                if str(item.get("rule-number", item.get("rule_number", idx + 1))).isdigit() else idx + 1,
            "rule_name": item.get("name", f"Rule {idx + 1}"),
            "section": section or item.get("section", ""),
            "source_interfaces": [],
            "destination_interfaces": [],
            "sources": get_names(item.get("source")),
            "destinations": get_names(item.get("destination")),
            "services": get_names(item.get("service")),
            "applications": get_names(item.get("application")),
            "users": get_names(item.get("users") or (item.get("content-match") or {}).get("users", []))
                if isinstance(item.get("content-match") or {}, dict) else get_names(item.get("users")),
            "vpn": get_names(item.get("vpn")),
            "action": "inline-layer" if item.get("inline-layer") else normalize_action((get_names(item.get("action")) or ["unknown"])[0]),
            "schedule": ", ".join(get_names(item.get("time"))),
            "enabled": get_bool(item.get("enabled"), True),
            "logging_enabled": logging_enabled,
            "nat_enabled": False,
            "comments": item.get("comments", item.get("comment", "")),
            "hit_count": hit_count,
            "last_hit": last_hit,
            "first_hit": None,
            "install_on": get_names(item.get("install-on")),
            "raw_data": {**item, "negated": bool(negated_fields(item)), "negate_fields": negated_fields(item)},
            "negated": bool(negated_fields(item)),
            "negate_fields": negated_fields(item),
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
            value = f"{subnet}/{mask}" if subnet and mask != "" and mask is not None else subnet
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

        if obj_type in ("address-range", "multicast-address-range"):
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

        if obj_type in ("group", "group-with-exclusion"):
            members = []
            refs = ([obj.get("include"), obj.get("except")] if obj_type == "group-with-exclusion" else obj.get("members", []))
            for m in refs:
                if isinstance(m, dict):
                    members.append(reference_name(m))
                elif isinstance(m, str):
                    members.append(m)
            return {
                "object_name": name,
                "object_uid": uid,
                "object_type": obj_type,
                "value": None,
                "protocol": None,
                "port_start": None,
                "port_end": None,
                "members": [m for m in members if m],
                "comment": obj.get("comments", ""),
                "raw_data": obj,
            }

        if obj_type in ("service-tcp", "tcp"):
            port = str(obj.get("port", ""))
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
            port = str(obj.get("port", ""))
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

        if obj_type == "service-group":
            members = []
            for m in obj.get("members", []):
                if isinstance(m, dict):
                    members.append(reference_name(m))
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

    def _parse_port(self, port_str: str) -> Tuple[Optional[int], Optional[int]]:
        from app.analysis.service_ports import checkpoint_service_terms
        terms = checkpoint_service_terms({"type": "service-tcp", "port": port_str}, "")
        first = terms[0]
        return first["port_start"], first["port_end"]
