"""
CVE Vulnerability Enrichment
==============================
Queries the NIST National Vulnerability Database (NVD) REST API v2 to find
known CVEs for a firewall's OS version.

Vendor-to-CPE mapping:
  FortiGate   os_version "7.2.5"       → CPE cpe:2.3:o:fortinet:fortios:7.2.5:*...
  CheckPoint  os_version "R81.20"      → CPE cpe:2.3:o:checkpoint:gaia_os:r81.20:*...
  PaloAlto    os_version "10.1.9"      → CPE cpe:2.3:o:paloaltonetworks:pan-os:10.1.9:*...
  CiscoASA    os_version "9.16(3)22"   → CPE cpe:2.3:o:cisco:adaptive_security_appliance_software:9.16...

Results are cached in the DeviceCVE table (TTL: 24 h) to avoid hammering NVD.

NVD API rate limits: 5 req/30 s without API key, 50 req/30 s with API key.
We use httpx with a polite delay to stay within limits.

SAFETY: Read-only API calls. No configuration is modified.
"""
from __future__ import annotations

import json
import logging
import re
import time
from datetime import datetime, timedelta
from typing import Optional, List

logger = logging.getLogger(__name__)

NVD_API_BASE  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_TTL_HRS = 24   # re-query NVD after 24 hours
MAX_RESULTS   = 20   # cap CVEs returned per device

# Human-readable reason for the most recent _query_nvd failure (None on success).
_query_nvd_error: Optional[str] = None


# ── CPE helpers ──────────────────────────────────────────────────────────────

def _normalise_fortigate_version(raw: str) -> str:
    """'v7.2.5' or 'FortiOS v7.2.5' → '7.2.5'"""
    m = re.search(r"(\d+\.\d+[\.\d]*)", raw)
    return m.group(1) if m else raw.strip().lstrip("vV")


def _normalise_checkpoint_version(raw: str) -> str:
    """'R81.20' → 'r81.20', 'API 1.9.1' → just skip (API version ≠ OS version)"""
    if raw.upper().startswith("API"):
        return ""  # API version, not OS version — can't map to CPE
    m = re.search(r"[Rr](\d+(?:\.\d+)?)", raw)
    if m:
        return f"r{m.group(1).lower()}"
    return raw.lower().strip()


def _normalise_paloalto_version(raw: str) -> str:
    """'PAN-OS 10.1.9' or '10.1.9' → '10.1.9'"""
    m = re.search(r"(\d+\.\d+[\.\d]*)", raw)
    return m.group(1) if m else raw.strip()


def _normalise_cisco_version(raw: str) -> str:
    """'9.16(3)22' → '9.16.3.22' (approximate, NVD is inconsistent)"""
    cleaned = re.sub(r"[().]", ".", raw).strip(".")
    return cleaned


def _normalise_huawei_version(raw: str) -> str:
    """
    'V500R001C30SPC200' → 'v500r001c30spc200'
    'V600R023C00' → 'v600r023c00'
    Huawei NVD CPE versions use lowercase VRP build strings.
    """
    m = re.search(r"(V\d+R\d+[A-Z0-9]*)", raw, re.IGNORECASE)
    if m:
        return m.group(1).lower()
    # Fallback: just lowercase and strip whitespace
    return raw.strip().lower()


def build_cpe_string(vendor: str, os_version: str) -> Optional[str]:
    """
    Convert vendor + os_version string to a CPE 2.3 string suitable for NVD query.
    Returns None if version cannot be mapped.
    """
    if not os_version:
        return None
    v = vendor.lower()

    if v in ("fortigate", "fortinet"):
        ver = _normalise_fortigate_version(os_version)
        if not ver:
            return None
        return f"cpe:2.3:o:fortinet:fortios:{ver}:*:*:*:*:*:*:*"

    if v == "checkpoint":
        ver = _normalise_checkpoint_version(os_version)
        if not ver:
            return None
        return f"cpe:2.3:o:checkpoint:gaia_os:{ver}:*:*:*:*:*:*:*"

    if v == "paloalto":
        ver = _normalise_paloalto_version(os_version)
        if not ver:
            return None
        return f"cpe:2.3:o:paloaltonetworks:pan-os:{ver}:*:*:*:*:*:*:*"

    if v in ("cisco", "ciscoasa"):
        ver = _normalise_cisco_version(os_version)
        if not ver:
            return None
        return f"cpe:2.3:o:cisco:adaptive_security_appliance_software:{ver}:*:*:*:*:*:*:*"

    if v in ("huawei", "huaweiusg", "huawei_usg"):
        ver = _normalise_huawei_version(os_version)
        if not ver:
            return None
        # Huawei USG6000 series firmware CPE
        return f"cpe:2.3:o:huawei:usg6000_firmware:{ver}:*:*:*:*:*:*:*"

    return None


def candidate_cpes(vendor: str, os_version: str) -> List[str]:
    """Return all CPE strings worth querying for a vendor+version.

    Some vendors register CVEs under more than one CPE — notably Check Point,
    whose advisories appear under both the Gaia OS and the Quantum Security
    Gateway product CPEs. Querying only one misses real CVEs. Returns an empty
    list if the version cannot be mapped.
    """
    base = build_cpe_string(vendor, os_version)
    if not base:
        return []
    cpes = [base]
    if vendor.lower() == "checkpoint":
        ver = _normalise_checkpoint_version(os_version)
        if ver:
            # Quantum Security Gateway is the product CPE many CP CVEs use.
            cpes.append(f"cpe:2.3:o:checkpoint:quantum_security_gateway:{ver}:*:*:*:*:*:*:*")
            cpes.append(f"cpe:2.3:a:checkpoint:quantum_security_gateway:{ver}:*:*:*:*:*:*:*")
    return cpes


# ── NVD query ─────────────────────────────────────────────────────────────────

def _query_nvd(cpe_string: str, nvd_api_key: Optional[str] = None):
    """
    Query NVD API for CVEs matching a CPE string.

    Returns a list of CVE dicts on success (possibly empty if NVD knows of no
    CVEs for the CPE). Returns None on failure (httpx missing, network error,
    rate-limit, or non-200) so callers can distinguish "no CVEs" from "lookup
    failed" instead of both looking like an empty list. ``_query_nvd_error``
    holds a human-readable reason for the last failure.
    """
    global _query_nvd_error
    _query_nvd_error = None
    try:
        import httpx
    except ImportError:
        logger.warning("httpx not installed — CVE lookup unavailable. Run: pip install httpx")
        _query_nvd_error = "CVE lookup dependency (httpx) is not installed on the server."
        return None

    headers: dict = {}
    if nvd_api_key:
        headers["apiKey"] = nvd_api_key

    params = {
        "cpeName": cpe_string,
        "resultsPerPage": MAX_RESULTS,
        "startIndex": 0,
    }

    try:
        time.sleep(0.7)  # polite delay to avoid rate limiting
        with httpx.Client(timeout=15) as client:
            resp = client.get(NVD_API_BASE, params=params, headers=headers)
            if resp.status_code == 403:
                logger.warning("NVD API rate-limited (403). CVE lookup skipped.")
                _query_nvd_error = (
                    "NVD rate-limited the request (HTTP 403). Configure an NVD API "
                    "key or retry shortly."
                )
                return None
            if resp.status_code != 200:
                logger.warning("NVD API returned %d for CPE %s", resp.status_code, cpe_string)
                _query_nvd_error = f"NVD API returned HTTP {resp.status_code}."
                return None
            data = resp.json()
    except Exception as exc:
        logger.warning("NVD API query failed: %s", exc)
        _query_nvd_error = (
            f"Could not reach the NVD API ({exc.__class__.__name__}). The server may "
            "have no outbound internet access to services.nvd.nist.gov."
        )
        return None

    results = []
    for vuln in data.get("vulnerabilities", []):
        cve_data = vuln.get("cve", {})
        cve_id   = cve_data.get("id", "")

        # Description
        descs = cve_data.get("descriptions", [])
        desc  = next((d["value"] for d in descs if d.get("lang") == "en"), "")

        # CVSS score — prefer v3.1, fallback to v3.0, then v2
        metrics  = cve_data.get("metrics", {})
        cvss_score   = None
        cvss_severity = "Unknown"
        cvss_vector   = None
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metric_key in metrics:
                m = metrics[metric_key][0].get("cvssData", {})
                cvss_score    = m.get("baseScore")
                cvss_severity = m.get("baseSeverity", metrics[metric_key][0].get("baseSeverity", "Unknown"))
                cvss_vector   = m.get("vectorString")
                break

        results.append({
            "cve_id":       cve_id,
            "description":  desc[:500] if desc else "",
            "cvss_score":   cvss_score,
            "cvss_severity": cvss_severity.upper() if cvss_severity else "UNKNOWN",
            "cvss_vector":  cvss_vector,
            "published":    cve_data.get("published", ""),
            "last_modified": cve_data.get("lastModified", ""),
            "url":          f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "cpe":          cpe_string,
        })

    return results


# ── DB-cached lookup ──────────────────────────────────────────────────────────

def keyword_queries(vendor: str, os_version: str) -> List[str]:
    """Fallback NVD keyword searches for vendors with inconsistent CPE naming."""
    v = vendor.lower()
    if v == "checkpoint":
        return [
            "Check Point Quantum Security Gateway",
            "Check Point Security Gateway",
            "Check Point Gaia",
        ]
    if v in ("fortigate", "fortinet"):
        return ["Fortinet FortiOS"]
    if v == "paloalto":
        return ["Palo Alto PAN-OS"]
    if v in ("cisco", "ciscoasa"):
        return ["Cisco Adaptive Security Appliance"]
    if v in ("huawei", "huaweiusg", "huawei_usg"):
        return ["Huawei USG firewall"]
    return []


def _version_tokens(vendor: str, os_version: str) -> List[str]:
    raw = (os_version or "").strip()
    if not raw:
        return []
    v = vendor.lower()
    if v == "checkpoint":
        m = re.search(r"[Rr]\d+(?:\.\d+)?", raw)
        if not m:
            return []
        version = m.group(0).lower()
        # If a minor train is known (for example R81.20), require that exact
        # train in keyword fallback results. Matching only "R81" is too broad
        # and can pull unrelated Check Point advisories into the report.
        return [version]
    if v in ("fortigate", "fortinet", "paloalto", "cisco", "ciscoasa"):
        m = re.search(r"\d+\.\d+(?:[.\d]*)", raw)
        if not m:
            return []
        version = m.group(0).lower()
        train = ".".join(version.split(".")[:2])
        return list(dict.fromkeys([version, train]))
    if v in ("huawei", "huaweiusg", "huawei_usg"):
        m = re.search(r"V\d+R\d+[A-Z0-9]*", raw, re.IGNORECASE)
        return [m.group(0).lower()] if m else []
    return [raw.lower()]


def _keyword_vuln_matches_version(vuln: dict, vendor: str, os_version: str) -> bool:
    tokens = _version_tokens(vendor, os_version)
    if not tokens:
        return False
    haystack = json.dumps(vuln, default=str).lower()
    return any(token in haystack for token in tokens)


def _query_nvd_keyword(query: str, vendor: str, os_version: str, nvd_api_key: Optional[str] = None):
    """Query NVD by keyword as a fallback when exact CPE names miss advisories."""
    global _query_nvd_error
    _query_nvd_error = None
    try:
        import httpx
    except ImportError:
        logger.warning("httpx not installed - CVE lookup unavailable. Run: pip install httpx")
        _query_nvd_error = "CVE lookup dependency (httpx) is not installed on the server."
        return None

    headers: dict = {}
    if nvd_api_key:
        headers["apiKey"] = nvd_api_key

    params = {
        "keywordSearch": query,
        "resultsPerPage": MAX_RESULTS,
        "startIndex": 0,
        "noRejected": "",
    }

    try:
        time.sleep(0.7)
        with httpx.Client(timeout=15) as client:
            resp = client.get(NVD_API_BASE, params=params, headers=headers)
            if resp.status_code == 403:
                _query_nvd_error = (
                    "NVD rate-limited the request (HTTP 403). Configure an NVD API "
                    "key or retry shortly."
                )
                return None
            if resp.status_code != 200:
                _query_nvd_error = f"NVD API returned HTTP {resp.status_code}."
                return None
            data = resp.json()
    except Exception as exc:
        _query_nvd_error = (
            f"Could not reach the NVD API ({exc.__class__.__name__}). The server may "
            "have no outbound internet access to services.nvd.nist.gov."
        )
        return None

    results = []
    for vuln in data.get("vulnerabilities", []):
        if not _keyword_vuln_matches_version(vuln, vendor, os_version):
            continue
        cve_data = vuln.get("cve", {})
        cve_id = cve_data.get("id", "")
        descs = cve_data.get("descriptions", [])
        desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
        metrics = cve_data.get("metrics", {})
        cvss_score = None
        cvss_severity = "Unknown"
        cvss_vector = None
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metric_key in metrics:
                m = metrics[metric_key][0].get("cvssData", {})
                cvss_score = m.get("baseScore")
                cvss_severity = m.get("baseSeverity", metrics[metric_key][0].get("baseSeverity", "Unknown"))
                cvss_vector = m.get("vectorString")
                break
        results.append({
            "cve_id": cve_id,
            "description": desc[:500] if desc else "",
            "cvss_score": cvss_score,
            "cvss_severity": cvss_severity.upper() if cvss_severity else "UNKNOWN",
            "cvss_vector": cvss_vector,
            "published": cve_data.get("published", ""),
            "last_modified": cve_data.get("lastModified", ""),
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "cpe": f"keyword:{query}",
            "match_source": "keyword",
        })
    return results


def get_device_cves(
    device_id: str,
    vendor: str,
    os_version: Optional[str],
    db,
    nvd_api_key: Optional[str] = None,
    force_refresh: bool = False,
) -> dict:
    """
    Return CVEs for a device. Uses DB cache (24 h TTL).

    Returns:
        {
            "device_id":   str,
            "os_version":  str | None,
            "cpe":         str | None,
            "cves":        list[CVEDict],
            "cached":      bool,
            "last_checked": str | None,
            "error":        str | None,
        }
    """
    # Try to import the DeviceCVECache model — may not exist yet
    try:
        from app.models.device_cve import DeviceCVECache
        model_available = True
    except ImportError:
        model_available = False

    cpe = build_cpe_string(vendor, os_version or "")
    cpes = candidate_cpes(vendor, os_version or "")

    # Check cache
    if model_available and not force_refresh:
        cached = db.query(DeviceCVECache).filter(DeviceCVECache.device_id == device_id).first()
        if cached:
            age = datetime.utcnow() - (cached.last_checked or datetime.min)
            if age < timedelta(hours=CACHE_TTL_HRS):
                import json
                cves = json.loads(cached.cve_data or "[]")
                return {
                    "device_id":   device_id,
                    "os_version":  os_version,
                    "cpe":         cached.cpe_string,
                    "cves":        cves,
                    "cached":      True,
                    "last_checked": cached.last_checked.isoformat() if cached.last_checked else None,
                    "error":       None,
                    "lookup_method": "cache",
                }

    # No cache — query NVD
    if not cpe:
        return {
            "device_id":   device_id,
            "os_version":  os_version,
            "cpe":         None,
            "cves":        [],
            "cached":      False,
            "last_checked": None,
            "error":       (
                "Cannot map OS version to CPE string. "
                "Ensure the device has been synced and reports a version number."
            ),
        }

    # Query every candidate CPE (e.g. Check Point gaia_os + quantum gateway) and
    # merge, de-duplicating by CVE id. A lookup counts as failed only if *every*
    # candidate query failed (so one bad CPE doesn't hide results from another).
    merged: dict = {}
    any_ok = False
    last_err = None
    lookup_methods = []
    for c in cpes:
        part = _query_nvd(c, nvd_api_key)
        if part is None:
            last_err = _query_nvd_error
            continue
        any_ok = True
        lookup_methods.append("cpe")
        for item in part:
            merged.setdefault(item.get("cve_id"), item)

    if not merged:
        for query in keyword_queries(vendor, os_version or ""):
            part = _query_nvd_keyword(query, vendor, os_version or "", nvd_api_key)
            if part is None:
                last_err = _query_nvd_error
                continue
            any_ok = True
            lookup_methods.append("keyword")
            for item in part:
                merged.setdefault(item.get("cve_id"), item)

    raw   = list(merged.values()) if any_ok else None
    error = None if raw is not None else (last_err or "NVD API unavailable.")
    cves  = raw or []

    # Save to cache only on a successful lookup — never cache a failure, so a
    # transient outage doesn't poison the 24h cache with an empty result.
    if model_available and raw is not None:
        import json
        cached_row = db.query(DeviceCVECache).filter(DeviceCVECache.device_id == device_id).first()
        if cached_row:
            cached_row.cve_data    = json.dumps(cves)
            cached_row.cpe_string  = cpe
            cached_row.last_checked = datetime.utcnow()
        else:
            import uuid
            db.add(DeviceCVECache(
                id=str(uuid.uuid4()),
                device_id=device_id,
                cpe_string=cpe,
                cve_data=json.dumps(cves),
                last_checked=datetime.utcnow(),
            ))
        try:
            db.commit()
        except Exception:
            db.rollback()

    return {
        "device_id":   device_id,
        "os_version":  os_version,
        "cpe":         cpe,
        "cves":        cves,
        "cached":      False,
        "last_checked": datetime.utcnow().isoformat(),
        "error":       error,
        "lookup_method": "+".join(dict.fromkeys(lookup_methods)) if lookup_methods else None,
    }
