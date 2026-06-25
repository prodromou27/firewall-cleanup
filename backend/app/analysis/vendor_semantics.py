"""Vendor evaluation semantics for context-aware analysis.

Rules from different evaluation contexts (Check Point layers / install-on
targets, Palo Alto Pre/Local/Post + zones, Cisco ASA ACL interface bindings,
FortiGate interface pairs, Huawei zone pairs) are NOT evaluated against each
other by the firewall, so shadowing/duplicate analysis must not compare across
them. This module derives the context key per vendor from data already
normalized into the rule (section/layer, interfaces/zones, install-on).

References: docs/analysis-vendor-semantics.md
"""
from __future__ import annotations

from typing import Any, Tuple


def _fz(values) -> frozenset:
    return frozenset(str(v).strip().lower() for v in (values or []) if str(v).strip())


def context_key(rule: dict, vendor: str) -> Tuple[Any, ...]:
    """Return the evaluation-context key for a rule.

    Two rules may only be compared for shadowing/duplication when their context
    keys are equal. Falls back to a single global context for vendors/data where
    no separating context is available (documented limitation).
    """
    v = (vendor or "").strip().lower()
    section = (rule.get("section") or "").strip().lower()
    src_if = _fz(rule.get("source_interfaces"))
    dst_if = _fz(rule.get("destination_interfaces"))
    install = _fz(rule.get("install_on"))

    if "check" in v:           # Check Point: ordered/inline layer + install-on target
        return ("checkpoint", section, install)
    if "palo" in v:            # Palo Alto: Pre/Local/Post scope + zone pair
        return ("paloalto", section, src_if, dst_if)
    if "huawei" in v:          # Huawei USG: source-zone / destination-zone
        return ("huawei", src_if, dst_if)
    if "cisco" in v or "asa" in v:   # Cisco ASA: ACL bound to an interface/direction
        return ("ciscoasa", section, src_if)
    if "forti" in v:           # FortiGate: incoming/outgoing interface pair
        return ("fortigate", src_if, dst_if)
    return ("generic", section)


def context_label(rule: dict, vendor: str) -> str:
    """Human-readable context, for finding evidence."""
    v = (vendor or "").strip().lower()
    section = rule.get("section") or ""
    src = ", ".join(rule.get("source_interfaces") or []) or "any"
    dst = ", ".join(rule.get("destination_interfaces") or []) or "any"
    if "check" in v:
        inst = ", ".join(rule.get("install_on") or []) or "all gateways"
        return f"layer '{section or 'Network'}', install-on {inst}"
    if "palo" in v:
        return f"{section or 'rulebase'} ({src} → {dst})"
    if "huawei" in v:
        return f"zones {src} → {dst}"
    if "cisco" in v or "asa" in v:
        return f"ACL '{section}' on {src}"
    if "forti" in v:
        return f"interfaces {src} → {dst}"
    return section or "policy"
