"""NAT & Public Exposure analysis (read-only).

PolicyInsight never writes to a firewall. This module only *reads* already-stored
security rules and normalized NAT rules and reports observations.

It produces:
  * findings (the 14 NAT / public-exposure checks), and
  * a public-exposure inventory consumed by the Public Exposure page and reports.

Data-availability gating
------------------------
NAT-specific checks run ONLY when normalized NAT data exists for the policy. When
it does not, ``nat_available`` is False, the NAT findings/inventory are empty, and
the UI shows "NAT Analysis Not Available" rather than inventing findings. The
public-exposure checks that can be derived from the security policy alone (a
public/any source reaching an internal destination on a sensitive port) still run
and are clearly attributed to "security policy" rather than NAT.

Normalized NAT rule shape (vendor-agnostic)
-------------------------------------------
{
  "rule_number": int|str, "name": str,
  "nat_type": "static"|"destination"|"source"|"hide"|"unknown",
  "original_src": [str], "original_dst": [str], "original_service": [str],
  "translated_src": [str], "translated_dst": [str], "translated_service": [str],
  "enabled": bool, "auto": bool,
}
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.analysis.ip_utils import is_public_network, is_any, parse_ip_network, is_routable_public
from app.analysis.normalizer import expand_service_object

# Sensitive TCP ports → (label, exposure finding_type). Mirrors the security-rule
# exposure detector so NAT-published and policy-exposed services line up.
SENSITIVE_PORTS: Dict[int, tuple] = {
    3389: ("RDP", "rdp_public_exposure"),
    22:   ("SSH", "ssh_public_exposure"),
    23:   ("Telnet", "telnet_public_exposure"),
    445:  ("SMB", "smb_public_exposure"),
    139:  ("SMB/NetBIOS", "smb_public_exposure"),
    5985: ("WinRM", "winrm_public_exposure"),
    5986: ("WinRM/HTTPS", "winrm_public_exposure"),
    5900: ("VNC", "vnc_public_exposure"),
    5901: ("VNC", "vnc_public_exposure"),
    1433: ("Microsoft SQL Server", "database_public_exposure"),
    1521: ("Oracle DB", "database_public_exposure"),
    3306: ("MySQL", "database_public_exposure"),
    5432: ("PostgreSQL", "database_public_exposure"),
    27017: ("MongoDB", "database_public_exposure"),
    6379: ("Redis", "database_public_exposure"),
}

# Administrative / cleartext protocols where any internet exposure is Critical.
_CRITICAL_EXPOSURE_PORTS = {3389, 22, 23, 445, 139, 5985, 5986, 5900, 5901}


# ── helpers ───────────────────────────────────────────────────────────────────
def nat_available(nat_rules: Optional[list]) -> bool:
    """True only when usable NAT data is present for the policy."""
    return bool(nat_rules) and isinstance(nat_rules, list)


def _as_list(v) -> List[str]:
    if v is None:
        return []
    if isinstance(v, (list, tuple, set)):
        return [str(x) for x in v if str(x).strip()]
    return [str(v)] if str(v).strip() else []


def _any_public(values: List[str]) -> bool:
    return any(is_public_network(v) or is_any(v) for v in values)


def _all_private(values: List[str]) -> bool:
    """True if every value is a concrete, non-public, non-any address."""
    if not values:
        return False
    for v in values:
        if is_any(v) or is_public_network(v):
            return False
        if parse_ip_network(v) is None:
            return False
    return True


def _ports_from_services(services: List[str], obj_map: dict) -> List[int]:
    """Resolve service names/strings to concrete TCP ports (narrow ranges only)."""
    ports: List[int] = []
    for s in services:
        for svc in expand_service_object(str(s), obj_map or {}):
            proto = (svc.get("protocol") or "").lower()
            if proto not in ("tcp", "any", ""):
                continue
            start, end = svc.get("port_start"), svc.get("port_end")
            if start is None or end is None:
                continue
            # Ignore the full 0-65535 "any" range here; service_any handles it.
            if start == 0 and end >= 65535:
                continue
            if (end - start) <= 1024:
                ports.extend(range(start, end + 1))
    return ports


def _service_is_any(services: List[str]) -> bool:
    return not services or any(is_any(s) for s in services)


def _norm(nat: dict) -> dict:
    """Coerce a stored NAT rule into the documented shape with list fields."""
    return {
        "rule_number": nat.get("rule_number", nat.get("rule_id", "?")),
        "name": nat.get("name", ""),
        "nat_type": (nat.get("nat_type") or "unknown").lower(),
        "original_src": _as_list(nat.get("original_src")),
        "original_dst": _as_list(nat.get("original_dst")),
        "original_service": _as_list(nat.get("original_service")),
        "translated_src": _as_list(nat.get("translated_src")),
        "translated_dst": _as_list(nat.get("translated_dst")),
        "translated_service": _as_list(nat.get("translated_service")),
        "enabled": nat.get("enabled", True),
        "auto": bool(nat.get("auto", False)),
    }


def _finding(ftype, severity, confidence, title, description, evidence, recommendation=""):
    return {
        "finding_type": ftype, "severity": severity, "confidence": confidence,
        "title": title, "description": description, "affected_rules": [],
        "evidence": evidence,
        "recommendation": recommendation or (
            "Read-only observation. Any change should be validated and applied "
            "through the approved change-management process, outside this tool."
        ),
    }


# ── classification ────────────────────────────────────────────────────────────
def _classify(nat: dict) -> str:
    """Return one of static / destination / source / hide / unknown."""
    t = nat["nat_type"]
    if t in ("static", "destination", "source", "hide"):
        return t
    has_dst_xlate = bool(nat["translated_dst"])
    has_src_xlate = bool(nat["translated_src"])
    if has_dst_xlate and _any_public(nat["original_dst"]):
        return "destination"
    if has_dst_xlate and not has_src_xlate:
        return "static"
    if has_src_xlate and not has_dst_xlate:
        return "source"
    return "unknown"


# ── main entry point ─────────────────────────────────────────────────────────
def analyze(security_rules: List[dict], nat_rules: Optional[list], obj_map: dict) -> Dict[str, Any]:
    """Return {nat_available, findings, exposure} for a policy."""
    available = nat_available(nat_rules)
    nats = [_norm(n) for n in (nat_rules or []) if isinstance(n, dict)]
    findings: List[dict] = []

    # ── NAT-specific checks (only when NAT data is available) ────────────────
    if available:
        findings.extend(_nat_findings(nats, security_rules))

    # ── Public-exposure inventory (NAT-published + policy-derived) ───────────
    exposure = _build_exposure(security_rules, nats, available, obj_map)
    findings.extend(_exposure_findings(exposure))

    return {"nat_available": available, "findings": findings, "exposure": exposure}


# ── NAT findings (#1-#8) ─────────────────────────────────────────────────────
def _nat_findings(nats: List[dict], security_rules: List[dict]) -> List[dict]:
    out: List[dict] = []
    seen_dupe = {}
    for n in nats:
        if not n["enabled"]:
            continue
        kind = _classify(n)
        ref = f"NAT rule {n['rule_number']}"

        # #1 Public IP mapped to internal system + #2 DNAT/port-forward + #3 static
        if kind == "destination" or (_any_public(n["original_dst"]) and _all_private(n["translated_dst"])):
            pub = ", ".join(n["original_dst"])
            internal = ", ".join(n["translated_dst"])
            out.append(_finding(
                "nat_public_to_internal", "High", "High",
                f"{ref}: public address mapped to internal system",
                f"{ref} translates public destination {pub or 'n/a'} to internal "
                f"{internal or 'n/a'} (destination NAT / port forwarding). Confirm "
                "the published service is intended and access is restricted.",
                {"nat_rule": n["rule_number"], "original_dst": n["original_dst"],
                 "translated_dst": n["translated_dst"], "service": n["original_service"], "kind": kind},
            ))
        elif kind == "static" and _all_private(n["translated_dst"]):
            out.append(_finding(
                "nat_static", "Informational", "Medium",
                f"{ref}: static (1:1) NAT mapping",
                f"{ref} is a static NAT mapping ({', '.join(n['original_dst']) or 'n/a'} → "
                f"{', '.join(n['translated_dst']) or 'n/a'}). Review that the 1:1 mapping is still required.",
                {"nat_rule": n["rule_number"], "kind": kind},
            ))
        elif kind in ("source", "hide"):
            out.append(_finding(
                "nat_source", "Informational", "Medium",
                f"{ref}: source / hide NAT",
                f"{ref} performs source NAT (outbound address translation). Informational — "
                "review only if egress identity matters for this environment.",
                {"nat_rule": n["rule_number"], "kind": kind},
            ))

        # #5 Duplicate NAT
        key = (
            tuple(sorted(n["original_src"])), tuple(sorted(n["original_dst"])),
            tuple(sorted(n["original_service"])), tuple(sorted(n["translated_src"])),
            tuple(sorted(n["translated_dst"])), tuple(sorted(n["translated_service"])),
        )
        if key in seen_dupe:
            out.append(_finding(
                "nat_duplicate", "Low", "High",
                f"{ref}: duplicate of NAT rule {seen_dupe[key]}",
                f"{ref} has the same original and translated tuples as NAT rule "
                f"{seen_dupe[key]}. Duplicate NAT rules add complexity and may be redundant.",
                {"nat_rule": n["rule_number"], "duplicate_of": seen_dupe[key]},
            ))
        else:
            seen_dupe[key] = n["rule_number"]

    # #6 Overlapping NAT — same original dst+service, different translated dst
    out.extend(_overlapping_nat(nats))
    # #7 NAT without matching security policy
    out.extend(_nat_without_policy(nats, security_rules))
    # #8 Security rule without clear NAT relationship
    out.extend(_policy_without_nat(nats, security_rules))
    return out


def _overlapping_nat(nats: List[dict]) -> List[dict]:
    out, by_match = [], {}
    for n in nats:
        if not n["enabled"]:
            continue
        match = (tuple(sorted(n["original_dst"])), tuple(sorted(n["original_service"])))
        if not any(match):
            continue
        prev = by_match.get(match)
        if prev is not None and tuple(sorted(prev["translated_dst"])) != tuple(sorted(n["translated_dst"])):
            out.append(_finding(
                "nat_overlap", "Medium", "Medium",
                f"NAT rule {n['rule_number']}: overlaps NAT rule {prev['rule_number']}",
                f"NAT rule {n['rule_number']} matches the same original destination/service as "
                f"rule {prev['rule_number']} but translates to a different target. Overlapping "
                "NAT can cause non-deterministic translation depending on rule order.",
                {"nat_rule": n["rule_number"], "overlaps": prev["rule_number"]},
            ))
        else:
            by_match[match] = n
    return out


def _security_allows(security_rules: List[dict], dests: List[str], services: List[str]) -> bool:
    """True if some enabled allow rule plausibly covers these dests/services."""
    dset = {d.lower() for d in dests}
    for r in security_rules:
        if not r.get("enabled", True):
            continue
        if (r.get("action") or "").lower() not in ("accept", "allow", "permit"):
            continue
        rdests = {str(d).lower() for d in (r.get("destinations") or [])}
        if "any" in rdests or (dset & rdests) or not dests:
            return True
    return False


def _nat_without_policy(nats: List[dict], security_rules: List[dict]) -> List[dict]:
    out = []
    for n in nats:
        if not n["enabled"] or _classify(n) != "destination":
            continue
        if not _security_allows(security_rules, n["translated_dst"], n["translated_service"] or n["original_service"]):
            out.append(_finding(
                "nat_without_policy", "Medium", "Medium",
                f"NAT rule {n['rule_number']}: no matching security policy",
                f"NAT rule {n['rule_number']} publishes {', '.join(n['translated_dst']) or 'an internal host'} "
                "but no enabled security rule appears to permit the translated traffic. The mapping may be "
                "dormant, or the security policy may rely on data not captured here.",
                {"nat_rule": n["rule_number"], "translated_dst": n["translated_dst"]},
            ))
    return out


def _policy_without_nat(nats: List[dict], security_rules: List[dict]) -> List[dict]:
    out = []
    nat_dsts = {d.lower() for n in nats for d in n["translated_dst"] + n["original_dst"]}
    for r in security_rules:
        if not r.get("enabled", True):
            continue
        if (r.get("action") or "").lower() not in ("accept", "allow", "permit"):
            continue
        srcs = _as_list(r.get("sources"))
        dsts = _as_list(r.get("destinations"))
        if not _any_public(srcs):
            continue
        if _all_private(dsts) and not any(d.lower() in nat_dsts for d in dsts):
            out.append(_finding(
                "policy_without_nat", "Informational", "Low",
                f"Rule {r.get('rule_id', r.get('rule_number', '?'))}: inbound allow with no clear NAT relationship",
                "An inbound rule permits a public/any source to an internal destination but no NAT rule "
                "references that destination. Verify whether translation happens elsewhere (e.g. upstream device).",
                {"rule_id": r.get("rule_id"), "destinations": dsts},
            ))
    return out


# ── Public-exposure inventory + findings (#9-#14) ────────────────────────────
def _build_exposure(security_rules: List[dict], nats: List[dict], available: bool, obj_map: dict) -> dict:
    """Build the public-exposure inventory: published services and exposed ports."""
    exposures: List[dict] = []

    # Policy-derived exposure (public/any source → internal dst on sensitive ports).
    # We see the actual allow rule, so confidence is High and logging is known.
    policy_targets: Dict[str, list] = {}
    for r in security_rules:
        if not r.get("enabled", True):
            continue
        if (r.get("action") or "").lower() not in ("accept", "allow", "permit"):
            continue
        srcs = _as_list(r.get("sources"))
        if not _any_public(srcs):
            continue
        dsts = _as_list(r.get("destinations"))
        ports = _ports_from_services(_as_list(r.get("services")), obj_map)
        svc_any = _service_is_any(_as_list(r.get("services")))
        if not _all_private(dsts):
            continue
        rid = r.get("rule_id", r.get("rule_number", "?"))
        for d in dsts:
            policy_targets.setdefault(d.lower(), []).append(rid)
        exposures.append({
            "public_ip": "Any/Internet" if any(is_any(s) for s in srcs) else ", ".join(srcs),
            "internal_target": ", ".join(dsts),
            "ports": sorted(set(ports)),
            "service_any": svc_any,
            "source": "policy",
            "logging": bool(r.get("logging_enabled", True)),
            "confidence": "High",
            "nat_rules": [],
            "security_rules": [rid],
        })

    # NAT-published services (public original_dst → internal translated_dst).
    # Inferred from NAT; confidence is High only when a security rule corroborates
    # the same internal target, otherwise Medium (mapping not fully confirmed).
    if available:
        for n in nats:
            if not n["enabled"] or _classify(n) != "destination":
                continue
            ports = _ports_from_services(n["translated_service"] or n["original_service"], obj_map)
            svc_any = _service_is_any(n["translated_service"] or n["original_service"])
            corroborating = sorted({rid for d in n["translated_dst"] for rid in policy_targets.get(d.lower(), [])})
            for pub in n["original_dst"] or ["(public interface)"]:
                exposures.append({
                    "public_ip": pub,
                    "internal_target": ", ".join(n["translated_dst"]) or "n/a",
                    "ports": sorted(set(ports)),
                    "service_any": svc_any,
                    "source": "nat",
                    "logging": None,  # NAT rule logging not correlated here
                    "confidence": "High" if corroborating else "Medium",
                    "nat_rules": [n["rule_number"]],
                    "security_rules": corroborating,
                })

    # Aggregate exposed ports + public IP inventory.
    exposed_ports = sorted({p for e in exposures for p in e["ports"]})
    public_ips = sorted({e["public_ip"] for e in exposures})
    risk = _exposure_risk(exposures)
    return {
        "exposures": exposures,
        "public_ips": public_ips,
        "exposed_ports": exposed_ports,
        "risk_score": risk,
    }


def _exposure_risk(exposures: List[dict]) -> int:
    """0-100 exposure risk proxy from sensitive ports / any-service exposure."""
    score = 0
    for e in exposures:
        if e["service_any"]:
            score += 30
        for p in e["ports"]:
            if p in SENSITIVE_PORTS:
                score += 25
    return min(100, score)


def _exposure_findings(exposure: dict) -> List[dict]:
    out = []
    for e in exposure["exposures"]:
        attribution = "NAT-published" if e["source"] == "nat" else "security policy"
        conf = e.get("confidence", "Medium")
        ev = {"public_ip": e["public_ip"], "internal_target": e["internal_target"],
              "source": e["source"], "logging": e.get("logging")}
        # #13 Any service exposed
        if e["service_any"]:
            out.append(_finding(
                "any_service_public_exposure", "High", conf,
                f"Public exposure of Any service to {e['internal_target']}",
                f"{e['internal_target']} is reachable from a public source with no service restriction "
                f"({attribution}). Unrestricted public exposure is high risk.",
                ev,
            ))
        # #9-#12 sensitive ports (RDP/SSH/Telnet/SMB/WinRM/VNC/database)
        sensitive_hit = [p for p in e["ports"] if p in SENSITIVE_PORTS]
        for p in sensitive_hit:
            label, ftype = SENSITIVE_PORTS[p]
            out.append(_finding(
                ftype, "Critical" if p in _CRITICAL_EXPOSURE_PORTS else "High", conf,
                f"Public exposure of {label} to {e['internal_target']}",
                f"{label} (port {p}) on {e['internal_target']} is reachable from a public source "
                f"({attribution}). Administrative and database services must not be exposed to the internet.",
                {**ev, "port": p},
            ))
        # #14 sensitive destination (multiple sensitive admin/db ports on one host)
        if len(set(sensitive_hit)) >= 2:
            out.append(_finding(
                "sensitive_destination_exposure", "Critical", conf,
                f"Multiple sensitive services exposed on {e['internal_target']}",
                f"{e['internal_target']} exposes multiple administrative/database services "
                f"({', '.join(SENSITIVE_PORTS[p][0] for p in sorted(set(sensitive_hit)))}) to a public source. "
                "This concentrates risk on a sensitive internal host.",
                {"internal_target": e["internal_target"], "ports": sorted(set(sensitive_hit))},
            ))
        # Public exposure with logging disabled (only when we positively know logging is off)
        if e.get("logging") is False and (e["service_any"] or sensitive_hit):
            out.append(_finding(
                "public_exposure_no_logging", "Medium", conf,
                f"Public exposure of {e['internal_target']} without logging",
                f"The rule exposing {e['internal_target']} to a public source has logging disabled, "
                "reducing visibility of attacks against the exposed service.",
                ev,
            ))
    return out
