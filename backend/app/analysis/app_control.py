"""Vendor-aware Application Control analysis (read-only).

PolicyInsight never writes to a firewall. Application findings are produced only
where the vendor exposes Layer-7 application data **and** it was actually parsed;
otherwise an informational diagnostic is emitted instead of a misleading finding.

Vendor handling (this module):
  * Palo Alto — `application` is a first-class match field (parsed). Implements
    Policy-Optimizer-style categories: rules without app controls and port-based
    rule candidates. `application:any` with a *restricted service* is NOT treated
    as Any/Any/Any (that stays the L3/L4 over-permissive detector's job).
  * Cisco ASA — no L7 application concept → `application_analysis_not_supported_for_vendor`.
  * Risky named applications — for any vendor that explicitly lists a high-risk
    App-ID in a rule (data-available), `risky_application_allowed`.
  * Check Point / FortiGate / Huawei — handled in their own slices (App-Control
    layer awareness; FortiGate security-profile parsing). Not emitted here to
    avoid premature/noisy notes.

Usage-dependent categories (Unused-Apps-in-Rule, Over-Provisioned-Application-Rule)
require per-application traffic data PolicyInsight does not ingest, so they are
intentionally not produced. See docs/analysis-accuracy-model.md §5.
"""
from __future__ import annotations

from typing import Dict, List

_ALLOW = ("accept", "allow", "permit")

# Conservative catalogue of high-risk App-IDs (anonymizers / proxies, P2P,
# unmanaged remote access). Matched only when a rule explicitly names the
# application — never inferred. Exact match or "<token>-..." variant (e.g.
# "teamviewer-base") so substrings like "mentor" never match.
RISKY_APPS = {
    "tor", "tor2web", "ultrasurf", "psiphon", "hotspot-shield", "freegate",
    "bittorrent", "utorrent", "emule", "gnutella", "edonkey",
    "teamviewer", "anydesk", "logmein", "gotomypc", "ammyy", "ultravnc",
}

_REC = {
    "rule_without_app_controls":
        "Identify the real applications this rule carries (App-ID logs / Policy "
        "Optimizer) and convert it to application-based rules so traffic is "
        "controlled at Layer 7, via change management.",
    "palo_alto_port_based_rule_candidate":
        "Use Policy Optimizer's application visibility to migrate this port-based "
        "rule to specific App-IDs, then tighten or remove the port-based rule.",
    "risky_application_allowed":
        "Confirm the high-risk application is a sanctioned business requirement. If "
        "not, raise a change request to remove it from the rule or block it.",
    "application_analysis_not_supported_for_vendor":
        "Read-only data-availability note; no action implied.",
}


def _is_allow(rule: dict) -> bool:
    return (rule.get("action") or "").lower() in _ALLOW


def _app_is_any(rule: dict) -> bool:
    apps = [str(a).strip().lower() for a in (rule.get("applications") or [])]
    return (not apps) or ("any" in apps)


def _services(rule: dict) -> List[str]:
    return [str(s).strip().lower() for s in (rule.get("services") or [])]


def _service_is_any(rule: dict) -> bool:
    s = _services(rule)
    return (not s) or ("any" in s) or ("all" in s)


def _service_app_default(rule: dict) -> bool:
    s = _services(rule)
    return bool(s) and all(x in ("application-default", "app-default") for x in s)


def _risky_match(name: str) -> bool:
    n = name.strip().lower()
    if n in RISKY_APPS:
        return True
    return any(n.startswith(tok + "-") for tok in RISKY_APPS)


def _finding(ftype, severity, confidence, title, desc, rule, extra) -> dict:
    rid = rule.get("rule_id") or rule.get("rule_number", "?")
    ev: Dict = {
        "rule": f"Rule {rid} ({rule.get('rule_name') or rid})",
        "applications_original": rule.get("applications") or [],
        "services_original": rule.get("services") or [],
    }
    ev.update(extra)
    return {
        "finding_type": ftype, "severity": severity, "confidence": confidence,
        "title": title, "description": desc,
        "affected_rules": [rule.get("id")] if rule.get("id") else [],
        "evidence": ev,
        "recommendation": _REC.get(ftype, "Read-only observation; review via change management."),
    }


def analyze(rules: List[dict], vendor: str, obj_map: dict | None = None) -> List[dict]:
    """Return application-control findings for a policy (read-only)."""
    v = (vendor or "").strip().lower()
    findings: List[dict] = []

    if "palo" in v:
        findings.extend(_palo_alto(rules))
    elif "cisco" in v or "asa" in v:
        findings.append({
            "finding_type": "application_analysis_not_supported_for_vendor",
            "severity": "Informational", "confidence": "High",
            "title": f"Application-control analysis not applicable for {vendor or 'this vendor'}",
            "description": (
                f"{vendor or 'This vendor'} security rules do not include a Layer-7 "
                "application match field, so application-control findings were not generated."
            ),
            "affected_rules": [],
            "evidence": {"vendor": vendor, "rule_count": len(rules)},
            "recommendation": _REC["application_analysis_not_supported_for_vendor"],
        })

    # Risky named applications are data-available for any vendor that lists them.
    findings.extend(_risky_named_apps(rules, vendor))
    return findings


def _palo_alto(rules: List[dict]) -> List[dict]:
    out: List[dict] = []
    for r in rules:
        if not r.get("enabled", True) or not _is_allow(r):
            continue
        if not _app_is_any(r):
            continue  # rule already constrains by App-ID
        rid = r.get("rule_id") or r.get("rule_number", "?")
        rname = r.get("rule_name") or f"Rule {rid}"
        if _service_is_any(r):
            out.append(_finding(
                "rule_without_app_controls", "Medium", "High",
                f"{rname}: no application controls (application 'any')",
                f"{rname} permits traffic with application 'any' and no service "
                "restriction, so it is enforced only at Layer 3/4 with no App-ID "
                "control. Convert to application-based rules once the real "
                "applications are known.",
                r, {"application": "any", "service": "any"}))
        elif _service_app_default(r):
            continue  # application:any + application-default is contradictory; skip
        else:
            out.append(_finding(
                "palo_alto_port_based_rule_candidate", "Low", "High",
                f"{rname}: port-based rule (App-ID conversion candidate)",
                f"{rname} matches specific ports with application 'any'. Policy "
                "Optimizer would flag this as a port-based rule that can be "
                "converted to an application-based rule to tighten control.",
                r, {"application": "any"}))
    return out


def _risky_named_apps(rules: List[dict], vendor: str) -> List[dict]:
    out: List[dict] = []
    for r in rules:
        if not r.get("enabled", True) or not _is_allow(r):
            continue
        apps = [str(a).strip() for a in (r.get("applications") or []) if str(a).strip()]
        hits = sorted({a for a in apps if _risky_match(a)})
        if not hits:
            continue
        rid = r.get("rule_id") or r.get("rule_number", "?")
        rname = r.get("rule_name") or f"Rule {rid}"
        out.append(_finding(
            "risky_application_allowed", "High", "High",
            f"{rname}: high-risk application(s) allowed ({', '.join(hits)})",
            f"{rname} explicitly permits high-risk application(s) "
            f"({', '.join(hits)}) — anonymizers/proxies, peer-to-peer, or unmanaged "
            "remote-access tools that are common exfiltration and malware vectors.",
            r, {"risky_applications": hits, "vendor": vendor}))
    return out
