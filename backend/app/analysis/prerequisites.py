"""Detector prerequisite matrix (read-only).

Every detector depends on certain data being present and trustworthy. This module
makes those dependencies **declarative and inspectable** rather than scattered as
ad-hoc guards: it assesses what data a policy actually has, declares each
detector's required capabilities + missing-data behaviour, and produces a single
transparency finding listing the detectors that were suppressed or downgraded.

The individual detectors still self-gate (and are independently tested); this
matrix formalises and surfaces that gating so reviewers can judge how complete the
analysis was. See docs/analysis-accuracy-model.md §7-9.

Missing-data behaviour:
  * skip       — detector cannot run at all; produces nothing.
  * downgrade  — detector runs but with reduced confidence / broader scope.
  * diagnostic — detector is replaced by an informational data-availability note.
"""
from __future__ import annotations

from typing import Dict, List, Optional

# Capability keys describing the data available for a policy.
CAPABILITIES = (
    "rules", "objects", "group_graph", "nat", "interfaces",
    "applications", "hit_counts", "last_hit", "layer_context",
)


# ── detector prerequisite declarations ──────────────────────────────────────
# vendors=None means vendor-agnostic. Only detectors whose vendor applies are
# reported as "suppressed"; a detector that is simply not applicable to the
# policy's vendor is silently skipped (not a data gap).
DETECTOR_PREREQUISITES: Dict[str, dict] = {
    "zero_hit_rule": {
        "label": "Zero-hit rules", "requires": {"rules", "hit_counts"},
        "missing": "skip", "vendors": None,
    },
    "low_usage_rule": {
        "label": "Low-usage rules", "requires": {"rules", "last_hit"},
        "missing": "skip", "vendors": None,
    },
    "unattached_object": {
        "label": "Unattached objects", "requires": {"rules", "objects", "group_graph"},
        "missing": "diagnostic", "vendors": None,
    },
    "duplicate_rule": {
        "label": "Duplicate rules", "requires": {"rules", "objects", "layer_context"},
        "missing": "downgrade", "vendors": None,
    },
    "shadowed_rule": {
        "label": "Shadowed / redundant / inoperative rules",
        "requires": {"rules", "objects", "layer_context"},
        "missing": "downgrade", "vendors": None,
    },
    "public_exposure": {
        "label": "Public exposure (NAT-corroborated)",
        "requires": {"rules", "nat", "interfaces"},
        "missing": "downgrade", "vendors": None,
    },
    "application_controls": {
        "label": "Application-control analysis",
        "requires": {"rules", "applications"},
        "missing": "diagnostic", "vendors": {"paloalto", "fortigate", "checkpoint"},
    },
}

# Vendor name normalisation helpers.
_VENDOR_ALIASES = {
    "paloalto": ("palo",), "fortigate": ("forti",), "checkpoint": ("check",),
    "ciscoasa": ("cisco", "asa"), "huawei": ("huawei",),
}


def _vendor_matches(vendor: str, vendors: Optional[set]) -> bool:
    if not vendors:
        return True
    v = (vendor or "").strip().lower()
    for canonical in vendors:
        if canonical in v or any(a in v for a in _VENDOR_ALIASES.get(canonical, ())):
            return True
    return False


# ── data availability assessment ────────────────────────────────────────────
def _is_literal(name: str) -> bool:
    from app.analysis.ip_utils import parse_ip_network
    n = (name or "").strip()
    if parse_ip_network(n) is not None:
        return True
    return "-" in n and all(parse_ip_network(p.strip()) is not None
                            for p in n.split("-", 1) if p.strip())


def _group_graph_complete(rules: List[dict], obj_map: dict) -> bool:
    """True unless the majority of named address references can't be resolved
    (mirrors the unattached-object completeness gate)."""
    referenced = set()
    for r in rules:
        for field in ("sources", "destinations"):
            for ref in r.get(field, []) or []:
                nm = str(ref.get("name") if isinstance(ref, dict) else ref or "").strip()
                if nm and nm.lower() not in ("any", "all", "any4", "any6"):
                    referenced.add(nm)
    if not referenced:
        return True
    unresolved = [n for n in referenced if (obj_map or {}).get(n) is None and not _is_literal(n)]
    return (len(unresolved) / len(referenced)) <= 0.5


def _app_data_present(rules: List[dict], vendor: str) -> bool:
    v = (vendor or "").strip().lower()
    if "palo" in v:
        return True  # application is always a parsed Palo match field
    if "forti" in v:
        return any(r.get("_cli_parsed") for r in rules)
    if "check" in v:
        return any(r.get("applications") for r in rules)
    return False


def assess(rules: List[dict], objects: List[dict], obj_map: dict,
           nat_rules, vendor: str, device_interfaces=None) -> Dict[str, bool]:
    """Return the capability availability map for a policy."""
    enabled = [r for r in rules if r.get("enabled", True)]
    has_vip = any((o.get("object_type") or "").lower() == "vip" for o in (objects or []))
    return {
        "rules": bool(rules),
        "objects": bool(objects),
        "group_graph": bool(objects) and _group_graph_complete(rules, obj_map),
        "nat": bool(nat_rules) or has_vip,
        "interfaces": any(r.get("source_interfaces") or r.get("destination_interfaces")
                          for r in rules) or bool(device_interfaces),
        "applications": _app_data_present(rules, vendor),
        "hit_counts": any(r.get("hit_count") is not None for r in enabled),
        "last_hit": any(r.get("last_hit") for r in rules),
        "layer_context": any(r.get("section") or r.get("source_interfaces")
                             or r.get("install_on") for r in rules),
    }


# Relative importance of each capability for the 0-100 import-quality score
# (weights sum to 100, so earned weight == score).
_QUALITY_WEIGHTS = {
    "rules": 20, "objects": 15, "group_graph": 15, "hit_counts": 12,
    "nat": 10, "interfaces": 8, "applications": 8, "last_hit": 6, "layer_context": 6,
}


def _grade(score: int) -> str:
    return "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 50 else "D"


def import_quality(rules: List[dict], objects: List[dict], obj_map: dict,
                   nat_rules, vendor: str, device_interfaces=None,
                   parser_warnings: int = 0) -> dict:
    """Consolidated 0-100 data-import-quality score + breakdown for a policy.

    The score is the weighted share of data capabilities actually present, lightly
    penalised by parser warnings. It is read-only metadata so the UI/report can
    state how complete the import was — it never changes severities."""
    avail = assess(rules, objects, obj_map, nat_rules, vendor, device_interfaces)
    earned = sum(w for cap, w in _QUALITY_WEIGHTS.items() if avail.get(cap))
    score = earned - min(10, max(0, int(parser_warnings)) * 2)  # cap penalty at 10
    score = max(0, min(100, score))
    return {
        "score": score,
        "grade": _grade(score),
        "capabilities": avail,
        "weights": _QUALITY_WEIGHTS,
        "missing": [c for c in _QUALITY_WEIGHTS if not avail.get(c)],
        "parser_warnings": int(parser_warnings or 0),
    }


def evaluate(availability: Dict[str, bool], vendor: str) -> List[dict]:
    """Return one entry per detector whose prerequisites are not fully met (and
    that applies to this vendor): {detector, label, decision, unmet}."""
    out: List[dict] = []
    for name, spec in DETECTOR_PREREQUISITES.items():
        if not _vendor_matches(vendor, spec.get("vendors")):
            continue
        unmet = sorted(c for c in spec["requires"] if not availability.get(c))
        if unmet:
            out.append({
                "detector": name, "label": spec["label"],
                "decision": spec["missing"], "unmet": unmet,
            })
    return out


def summary_finding(availability: Dict[str, bool], vendor: str) -> Optional[dict]:
    """One informational finding summarising suppressed/downgraded detectors, or
    None when every detector's prerequisites are satisfied."""
    unmet_detectors = evaluate(availability, vendor)
    if not unmet_detectors:
        return None
    skipped = [d for d in unmet_detectors if d["decision"] in ("skip", "diagnostic")]
    downgraded = [d for d in unmet_detectors if d["decision"] == "downgrade"]
    parts = []
    if skipped:
        parts.append("suppressed: " + ", ".join(d["label"] for d in skipped))
    if downgraded:
        parts.append("reduced confidence: " + ", ".join(d["label"] for d in downgraded))
    return {
        "finding_type": "detector_prerequisites_unmet",
        "severity": "Informational",
        "confidence": "High",
        "title": "Some detectors were limited by missing data",
        "description": (
            "Based on the data imported for this policy, some analyses could not run "
            "at full strength (" + "; ".join(parts) + "). This is a transparency note "
            "so findings can be judged against data completeness — it is not itself a "
            "policy issue."
        ),
        "affected_rules": [],
        "evidence": {
            "data_available": availability,
            "detectors": unmet_detectors,
            "vendor": vendor,
        },
        "recommendation": (
            "Read-only data-availability note. To lift these limitations, re-import / "
            "re-sync the missing data (hit counts, full object database, NAT, interfaces, "
            "or application data) as indicated."
        ),
    }
