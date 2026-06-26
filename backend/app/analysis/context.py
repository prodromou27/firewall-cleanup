"""Central analysis context and detector execution policy.

The findings engine handles multiple data sources with different completeness
levels. This module keeps detector gating explicit so cleanup-style detectors do
not infer facts from incomplete imports.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from app.analysis import prerequisites
from app.analysis.ip_utils import parse_ip_network
from app.analysis.normalizer import _ref_name


_ANY_NAMES = {"any", "all", "any4", "any6"}


def _is_literal_reference(name: str) -> bool:
    text = (name or "").strip()
    if parse_ip_network(text) is not None:
        return True
    return "-" in text and all(
        parse_ip_network(part.strip()) is not None
        for part in text.split("-", 1)
        if part.strip()
    )


def named_rule_references(rules: List[dict], fields: tuple[str, ...]) -> set[str]:
    refs: set[str] = set()
    for rule in rules or []:
        for field in fields:
            for ref in rule.get(field, []) or []:
                name = _ref_name(ref)
                if name and name.strip().lower() not in _ANY_NAMES:
                    refs.add(name)
    return refs


def unresolved_references(
    rules: List[dict],
    obj_map: dict,
    fields: tuple[str, ...] = ("sources", "destinations"),
) -> List[str]:
    unresolved = []
    for name in sorted(named_rule_references(rules, fields)):
        if obj_map.get(name) is None and not _is_literal_reference(name):
            unresolved.append(name)
    return unresolved


def _member_refs(obj: dict) -> list:
    members = obj.get("members") or []
    if members:
        return members
    raw = obj.get("raw_data") or {}
    if isinstance(raw, dict):
        for key in ("members", "member", "groups"):
            raw_members = raw.get(key)
            if raw_members:
                return raw_members if isinstance(raw_members, list) else [raw_members]
    return []


def unresolved_group_member_references(objects: List[dict], obj_map: dict) -> List[str]:
    unresolved: set[str] = set()
    for obj in objects or []:
        obj_type = (obj.get("object_type") or "").lower().replace("-", "_")
        if "group" not in obj_type:
            continue
        for member in _member_refs(obj):
            name = _ref_name(member)
            if name and obj_map.get(name) is None:
                unresolved.add(name)
    return sorted(unresolved)


@dataclass(frozen=True)
class DetectorDecision:
    detector: str
    run: bool
    reason: str = ""


@dataclass(frozen=True)
class AnalysisContext:
    rules: List[dict]
    objects: List[dict]
    obj_map: dict
    policy: Any
    availability: Dict[str, bool]
    unresolved_address_refs: List[str]
    unresolved_group_member_refs: List[str]

    @property
    def object_graph_complete(self) -> bool:
        return bool(self.availability.get("group_graph"))

    def decide(self, detector: str) -> DetectorDecision:
        if detector in {"unused_objects", "empty_groups", "large_groups", "broad_networks", "service_ranges", "duplicate_objects", "overlapping_objects"}:
            if not self.rules:
                return DetectorDecision(detector, False, "no_rules_imported")
            if not self.objects:
                return DetectorDecision(detector, False, "no_objects_imported")
            if not self.object_graph_complete:
                return DetectorDecision(detector, False, "object_graph_incomplete")

        if detector == "usage":
            if not self.availability.get("hit_counts") and not self.availability.get("last_hit"):
                return DetectorDecision(detector, False, "usage_data_missing")

        if detector == "public_exposure":
            if not self.availability.get("nat") and not self.availability.get("interfaces"):
                return DetectorDecision(detector, False, "nat_and_interface_data_missing")

        if detector == "application_controls":
            if not self.availability.get("applications"):
                return DetectorDecision(detector, False, "application_data_missing")

        return DetectorDecision(detector, True)


def build_context(
    rules: List[dict],
    objects: List[dict],
    obj_map: dict,
    policy: Any,
    device_interfaces: Optional[list] = None,
) -> AnalysisContext:
    unresolved_addr = unresolved_references(rules, obj_map, ("sources", "destinations"))
    unresolved_members = unresolved_group_member_references(objects, obj_map)
    availability = prerequisites.assess(
        rules,
        objects,
        obj_map,
        getattr(policy, "nat_rules", None),
        getattr(policy, "vendor", ""),
        device_interfaces=device_interfaces,
    )
    # Cleanup semantics require a complete graph. The more permissive import
    # quality score may still grade partial imports, but detectors that declare
    # objects as cleanup candidates must be strict.
    if unresolved_addr or unresolved_members:
        availability = dict(availability)
        availability["group_graph"] = False
    return AnalysisContext(
        rules=rules,
        objects=objects,
        obj_map=obj_map,
        policy=policy,
        availability=availability,
        unresolved_address_refs=unresolved_addr,
        unresolved_group_member_refs=unresolved_members,
    )


def run_if_allowed(
    ctx: AnalysisContext,
    detector: str,
    callback: Callable[[], List[dict]],
    diagnostic: Callable[[DetectorDecision], List[dict]] | None = None,
) -> List[dict]:
    decision = ctx.decide(detector)
    if decision.run:
        return callback()
    if diagnostic:
        return diagnostic(decision)
    return []
