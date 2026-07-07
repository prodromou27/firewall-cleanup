"""Firewall version intelligence (read-only, advisory).

Normalizes a device's reported version and compares it against the
manually-managed Version Catalog to produce advisory findings. No live internet
is used; if the catalog is empty/unmatched, only an Informational finding is
produced. PolicyInsight never changes device firmware.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

_ADVISORY = (
    "Review the currently installed version against the vendor-supported release "
    "train and plan an upgrade through the approved maintenance and change "
    "management process if applicable."
)

_CHECKPOINT_OS_RE = re.compile(r"[Rr]\d+(?:\.\d+)?")

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_VERSION_LIKE_RE = re.compile(r"^(?:[Rr]?\d+(?:\.\d+)+|V\d+R\d+[A-Z0-9]*)$", re.IGNORECASE)


def peer_version_or_blank(value: str) -> str:
    """Return `value` only when it reads like an OS version.

    FirewallDevice.ha_peer stores the peer's hostname/IP, not its OS version.
    Comparing an IP against the local version made version_ha_mismatch fire on
    every HA device, so anything that isn't version-shaped is discarded.
    """
    v = (value or "").strip()
    if not v or _IPV4_RE.match(v):
        return ""
    return v if _VERSION_LIKE_RE.match(v) else ""


# ── version normalization ────────────────────────────────────────────────────
def _digits(v: str) -> tuple:
    """Numeric comparison key from a version string (e.g. 'R81.20' -> (81,20))."""
    return tuple(int(x) for x in re.findall(r"\d+", v or "")) or (0,)


def release_train(vendor: str, version: str) -> str:
    """Major release train for a version (vendor-aware)."""
    if not version:
        return ""
    v = version.strip()
    if vendor.lower() in ("checkpoint", "check point"):
        m = re.search(r"[Rr]\d+", v)
        return m.group(0).upper() if m else v
    m = re.search(r"(\d+\.\d+)", v)
    if m:
        return m.group(1)
    m = re.search(r"(V\d+R\d+)", v, re.IGNORECASE)  # Huawei
    return m.group(1).upper() if m else v


def is_management_api_version(vendor: str, version: Optional[str]) -> bool:
    """True when a stored version is a management/API version, not firewall OS."""
    raw = (version or "").strip()
    if not raw:
        return False
    return vendor.lower() in ("checkpoint", "check point") and raw.upper().startswith("API ")


def extract_checkpoint_gateway_version(*values: Optional[str]) -> str:
    """Extract a Check Point gateway OS version from inventory strings.

    Existing rows may have only stored gateway versions inside fw_model, e.g.
    "GW: R81.20" or "6500 (GW: R81.10, R81.20)". Prefer the highest numeric
    version when multiple gateway versions are present.
    """
    matches: list[str] = []
    for value in values:
        matches.extend(_CHECKPOINT_OS_RE.findall(value or ""))
    if not matches:
        return ""
    return sorted(matches, key=_digits, reverse=True)[0].upper()


def resolve_device_os_version(device) -> Dict[str, Any]:
    """Return the effective firewall OS version for advisory/CVE checks.

    This intentionally rejects Check Point management API versions such as
    "API 2.0.1"; those are not gateway OS versions and cannot be mapped safely
    to NVD CPEs.
    """
    vendor = getattr(device, "vendor", "") or ""
    raw_os = (getattr(device, "os_version", "") or "").strip()
    fw_model = getattr(device, "fw_model", "") or ""
    ha_peer = getattr(device, "ha_peer", "") or ""

    if is_management_api_version(vendor, raw_os):
        gateway_version = extract_checkpoint_gateway_version(fw_model, ha_peer)
        if gateway_version:
            return {
                "os_version": gateway_version,
                "source": "gateway_inventory",
                "raw_os_version": raw_os,
                "queryable": True,
            }
        return {
            "os_version": "",
            "source": "management_api_version",
            "raw_os_version": raw_os,
            "queryable": False,
        }

    return {
        "os_version": raw_os,
        "source": "device_os_version" if raw_os else "missing",
        "raw_os_version": raw_os,
        "queryable": bool(raw_os),
    }


def normalize_version(vendor: str, os_version: Optional[str], *, fw_model: str = "",
                      management_version: str = "", ha_peer_version: str = "") -> Dict[str, Any]:
    """Normalize reported version data into a common shape."""
    raw = (os_version or "").strip()
    # Check Point sync may store "API x.y" when the gateway OS wasn't discovered.
    parseable = bool(raw) and not raw.upper().startswith("API ")
    version = ""
    if parseable:
        m = re.search(r"[Rr]\d+(?:\.\d+)*|V\d+R\d+[A-Z0-9]*|\d+\.\d+(?:[.\(\)\d]*)", raw)
        version = m.group(0) if m else raw
    return {
        "vendor": vendor,
        "os_version": version,
        "release_train": release_train(vendor, version) if version else "",
        "fw_model": fw_model or "",
        "management_version": management_version or "",
        "ha_peer_version": ha_peer_version or "",
        "parseable": parseable and bool(version),
        "raw": raw,
    }


# ── catalog matching + evaluation ────────────────────────────────────────────
def _match(norm: dict, catalog: List[dict]) -> Optional[dict]:
    vendor = norm["vendor"].lower()
    train = norm["release_train"].upper()
    best = None
    for c in catalog:
        if (c.get("vendor") or "").lower() != vendor:
            continue
        ctrain = (c.get("release_train") or "").upper()
        if ctrain and ctrain == train:
            return c           # exact train match wins
        if not ctrain and best is None:
            best = c           # vendor-wide fallback entry
    return best


def _is_eol(norm: dict, entry: dict) -> bool:
    if (entry.get("support_status") or "").lower() in ("end-of-support", "eol"):
        # whole train EOL
        if not entry.get("eol_versions"):
            return True
    for eol in entry.get("eol_versions") or []:
        if norm["os_version"] == eol or norm["os_version"].startswith(str(eol)):
            return True
    return False


def _behind(norm: dict, entry: dict) -> bool:
    rec = entry.get("recommended_version")
    if not rec or not norm["os_version"]:
        return False
    return _digits(norm["os_version"]) < _digits(rec)


def _finding(ftype, severity, confidence, title, description, evidence):
    return {
        "finding_type": ftype, "severity": severity, "confidence": confidence,
        "title": title, "description": description, "affected_rules": [],
        "evidence": evidence, "recommendation": _ADVISORY,
    }


def evaluate(norm: dict, catalog: List[dict]) -> List[dict]:
    """Return advisory findings for a normalized version against the catalog."""
    findings: List[dict] = []

    # Unknown / unparsed version → low-confidence informational only.
    if not norm["parseable"]:
        findings.append(_finding(
            "version_unknown", "Informational", "Low",
            f"{norm['vendor']} version could not be determined",
            "The device did not report a parseable OS version (it may not have been "
            "synced, or only a management/API version is available). " + _ADVISORY,
            {"vendor": norm["vendor"], "raw": norm["raw"]},
        ))
        return findings

    entry = _match(norm, catalog) if catalog else None

    # No catalog data → Informational only (never invent outdated/EOL findings).
    if not entry:
        findings.append(_finding(
            "version_catalog_unavailable", "Informational", "Low",
            f"No version catalog data for {norm['vendor']} {norm['os_version']}",
            "No matching Version Catalog entry is available, so currency/end-of-support "
            "cannot be assessed. Import or maintain the version catalog to enable this. " + _ADVISORY,
            {"vendor": norm["vendor"], "os_version": norm["os_version"], "release_train": norm["release_train"]},
        ))
        return findings

    base_ev = {
        "vendor": norm["vendor"], "os_version": norm["os_version"],
        "release_train": norm["release_train"],
        "recommended_version": entry.get("recommended_version"),
        "advisory_url": entry.get("advisory_url"),
    }

    if _is_eol(norm, entry):
        findings.append(_finding(
            "version_end_of_support", "High", "High",
            f"{norm['vendor']} {norm['os_version']} is end-of-support",
            f"{norm['vendor']} {norm['os_version']} matches an end-of-support entry in the "
            "version catalog. End-of-support software no longer receives security fixes. " + _ADVISORY,
            base_ev,
        ))
    elif _behind(norm, entry):
        findings.append(_finding(
            "version_outdated", "Medium", "High",
            f"{norm['vendor']} {norm['os_version']} is behind the recommended version",
            f"{norm['vendor']} {norm['os_version']} is older than the catalog's recommended "
            f"version {entry.get('recommended_version')}. " + _ADVISORY,
            base_ev,
        ))

    # HA peer version mismatch.
    peer = norm.get("ha_peer_version")
    if peer and _digits(peer) != _digits(norm["os_version"]):
        findings.append(_finding(
            "version_ha_mismatch", "Medium", "High",
            f"HA peer version mismatch ({norm['os_version']} vs {peer})",
            "The HA cluster members report different OS versions. Version skew across an HA "
            "pair can cause unexpected failover behaviour. " + _ADVISORY,
            {"os_version": norm["os_version"], "ha_peer_version": peer},
        ))

    return findings


def analyze_device(device, catalog: List[dict]) -> Dict[str, Any]:
    """Convenience wrapper for a FirewallDevice-like object."""
    resolved = resolve_device_os_version(device)
    norm = normalize_version(
        getattr(device, "vendor", ""), resolved["os_version"],
        fw_model=getattr(device, "fw_model", "") or "",
        management_version=getattr(device, "management_platform", "") or "",
        ha_peer_version=peer_version_or_blank(getattr(device, "ha_peer", "") or ""),
    )
    norm["source"] = resolved["source"]
    norm["raw_os_version"] = resolved["raw_os_version"]
    norm["queryable"] = resolved["queryable"]
    return {
        "normalized": norm,
        "catalog_available": bool(catalog),
        "findings": evaluate(norm, catalog),
    }
