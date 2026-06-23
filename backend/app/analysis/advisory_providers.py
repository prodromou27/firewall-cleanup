"""Vendor advisory/release-note source registry.

This module intentionally separates advisory source discovery from CVE matching.
Some vendors expose stable public machine-readable data; others primarily expose
human web pages or support-portal content. PolicyInsight should report that
difference explicitly instead of pretending every vendor has reliable automated
release-note retrieval.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Callable, Iterable, List, Optional
from urllib.parse import quote_plus


@dataclass(frozen=True)
class AdvisorySource:
    provider: str
    source_type: str
    url: str
    confidence: str
    machine_readable: bool
    notes: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class AdvisoryRecord:
    provider: str
    source_type: str
    title: str
    url: str
    cve_id: Optional[str] = None
    severity: Optional[str] = None
    published: Optional[str] = None
    updated: Optional[str] = None
    known_exploited: bool = False
    notes: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class ProviderResult:
    provider: str
    status: str
    machine_readable: bool
    fetched_at: Optional[str]
    source: AdvisorySource
    records: List[AdvisoryRecord]
    error: Optional[str] = None

    def to_dict(self) -> dict:
        data = asdict(self)
        data["source"] = self.source.to_dict()
        data["records"] = [r.to_dict() for r in self.records]
        return data


HttpGet = Callable[[str], object]


class AdvisoryProvider:
    """Base class for advisory sources.

    Providers are deliberately read-only. A provider may be a simple reference
    link, or it may fetch a machine-readable public feed when explicitly asked.
    """

    source: AdvisorySource

    def __init__(self, source: AdvisorySource):
        self.source = source

    @property
    def name(self) -> str:
        return self.source.provider

    def fetch(self, *, vendor: str, os_version: str = "", cve_ids: Optional[Iterable[str]] = None,
              http_get: Optional[HttpGet] = None) -> ProviderResult:
        return ProviderResult(
            provider=self.name,
            status="reference_only",
            machine_readable=self.source.machine_readable,
            fetched_at=None,
            source=self.source,
            records=[],
            error=None,
        )


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _http_json(url: str, http_get: Optional[HttpGet]) -> dict:
    if http_get is None:
        try:
            import httpx
        except ImportError as exc:
            raise RuntimeError("httpx is not installed") from exc
        with httpx.Client(timeout=15) as client:
            resp = client.get(url)
            resp.raise_for_status()
            return resp.json()
    response = http_get(url)
    if isinstance(response, dict):
        return response
    if hasattr(response, "json"):
        return response.json()
    raise RuntimeError("http_get must return a dict or an object with json()")


class NvdReferenceProvider(AdvisoryProvider):
    """NVD CVE lookup is handled by cve_checker; this provider advertises source metadata."""


class CisaKevProvider(AdvisoryProvider):
    """Fetch CISA KEV and filter by CVE IDs when provided."""

    def fetch(self, *, vendor: str, os_version: str = "", cve_ids: Optional[Iterable[str]] = None,
              http_get: Optional[HttpGet] = None) -> ProviderResult:
        target_ids = {c.upper() for c in (cve_ids or []) if c}
        try:
            data = _http_json(self.source.url, http_get)
            records = []
            for item in data.get("vulnerabilities", []):
                cve = (item.get("cveID") or item.get("cve_id") or "").upper()
                if target_ids and cve not in target_ids:
                    continue
                records.append(AdvisoryRecord(
                    provider=self.name,
                    source_type=self.source.source_type,
                    title=item.get("vulnerabilityName") or cve or "Known exploited vulnerability",
                    url=item.get("notes") or self.source.url,
                    cve_id=cve or None,
                    severity=None,
                    published=item.get("dateAdded"),
                    updated=item.get("dueDate"),
                    known_exploited=True,
                    notes=item.get("shortDescription") or "",
                ))
            return ProviderResult(
                provider=self.name,
                status="ok",
                machine_readable=True,
                fetched_at=_now_iso(),
                source=self.source,
                records=records,
            )
        except Exception as exc:
            return ProviderResult(
                provider=self.name,
                status="error",
                machine_readable=True,
                fetched_at=_now_iso(),
                source=self.source,
                records=[],
                error=str(exc),
            )


class VendorReferenceProvider(AdvisoryProvider):
    """Reference-only vendor provider for human verification links."""


def _nvd_query(vendor: str, os_version: str) -> str:
    query = f"{vendor} {os_version}".strip()
    return f"https://nvd.nist.gov/vuln/search/results?query={quote_plus(query)}"


def _vendor_search(vendor: str, os_version: str) -> str:
    query = quote_plus(f"{vendor} {os_version} security advisory release notes".strip())
    return f"https://www.google.com/search?q={query}"


def advisory_sources(vendor: str, os_version: str = "") -> List[dict]:
    """Return advisory/release-note sources to show or fetch for a vendor.

    The list is ordered by expected usefulness. ``machine_readable`` means the
    source can be queried programmatically with stable structure; when false,
    the source should be treated as a manual verification link.
    """
    v = (vendor or "").lower()
    version = os_version or ""
    sources = [
        AdvisorySource(
            provider="NVD",
            source_type="cve_database",
            url=_nvd_query(vendor, version),
            confidence="Medium",
            machine_readable=True,
            notes="Public CVE database. Good for CVE enrichment, but CPE naming can be inconsistent.",
        ),
        AdvisorySource(
            provider="CISA KEV",
            source_type="known_exploited",
            url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            confidence="High",
            machine_readable=True,
            notes="Public known-exploited-vulnerability catalog. Use as exploitation signal, not as release notes.",
        ),
    ]

    if v == "checkpoint":
        sources.extend([
            AdvisorySource(
                provider="Check Point",
                source_type="vendor_advisory",
                url="https://support.checkpoint.com/results/sk/sk182336",
                confidence="Medium",
                machine_readable=False,
                notes="Check Point advisories and Jumbo Hotfix details often require Support Center verification.",
            ),
            AdvisorySource(
                provider="Check Point Search",
                source_type="release_notes_search",
                url=_vendor_search("Check Point", version),
                confidence="Low",
                machine_readable=False,
                notes="Use to verify exact gateway train and Jumbo Hotfix applicability manually.",
            ),
        ])
    elif v in ("fortigate", "fortinet"):
        sources.extend([
            AdvisorySource(
                provider="Fortinet PSIRT",
                source_type="vendor_advisory",
                url="https://www.fortiguard.com/psirt",
                confidence="High",
                machine_readable=False,
                notes="Public Fortinet PSIRT portal. Firmware release notes may still require support access.",
            ),
            AdvisorySource(
                provider="Fortinet Release Notes",
                source_type="release_notes_search",
                url=_vendor_search("FortiOS", version),
                confidence="Medium",
                machine_readable=False,
                notes="Manual verification recommended for exact FortiOS build and upgrade path.",
            ),
        ])
    elif v == "paloalto":
        sources.extend([
            AdvisorySource(
                provider="Palo Alto Security Advisories",
                source_type="vendor_advisory",
                url="https://security.paloaltonetworks.com/",
                confidence="High",
                machine_readable=False,
                notes="Public advisory portal. Software release notes and downloads may require support access.",
            ),
            AdvisorySource(
                provider="PAN-OS Release Notes",
                source_type="release_notes_search",
                url=_vendor_search("PAN-OS", version),
                confidence="Medium",
                machine_readable=False,
                notes="Manual verification recommended for exact PAN-OS maintenance release.",
            ),
        ])
    elif v in ("cisco", "ciscoasa"):
        sources.extend([
            AdvisorySource(
                provider="Cisco Security Advisories",
                source_type="vendor_advisory",
                url="https://sec.cloudapps.cisco.com/security/center/publicationListing.x",
                confidence="High",
                machine_readable=True,
                notes="Cisco security advisory data is the best candidate for direct vendor ingestion.",
            ),
            AdvisorySource(
                provider="Cisco ASA Release Notes",
                source_type="release_notes_search",
                url=_vendor_search("Cisco ASA", version),
                confidence="Medium",
                machine_readable=False,
                notes="Use for release-note verification and fixed-release context.",
            ),
        ])
    elif v in ("huawei", "huaweiusg", "huawei_usg"):
        sources.extend([
            AdvisorySource(
                provider="Huawei PSIRT",
                source_type="vendor_advisory",
                url="https://www.huawei.com/en/psirt/security-advisories",
                confidence="Medium",
                machine_readable=False,
                notes="Public Huawei advisory portal. USG release-note structure is less consistent.",
            ),
            AdvisorySource(
                provider="Huawei USG Release Notes",
                source_type="release_notes_search",
                url=_vendor_search("Huawei USG", version),
                confidence="Low",
                machine_readable=False,
                notes="Manual verification recommended for exact VRP/build applicability.",
            ),
        ])
    else:
        sources.append(AdvisorySource(
            provider="Vendor Search",
            source_type="release_notes_search",
            url=_vendor_search(vendor, version),
            confidence="Low",
            machine_readable=False,
            notes="No vendor-specific provider is configured for this vendor.",
        ))

    return [s.to_dict() for s in sources]


def advisory_provider_objects(vendor: str, os_version: str = "") -> List[AdvisoryProvider]:
    """Return provider objects for source discovery and optional fetches."""
    providers: List[AdvisoryProvider] = []
    for raw in advisory_sources(vendor, os_version):
        source = AdvisorySource(**raw)
        if source.provider == "NVD":
            providers.append(NvdReferenceProvider(source))
        elif source.provider == "CISA KEV":
            providers.append(CisaKevProvider(source))
        else:
            providers.append(VendorReferenceProvider(source))
    return providers


def collect_advisory_context(
    vendor: str,
    os_version: str = "",
    *,
    cve_ids: Optional[Iterable[str]] = None,
    fetch: bool = False,
    http_get: Optional[HttpGet] = None,
) -> dict:
    """Return advisory provider metadata and optional fetched records.

    ``fetch=False`` is the safe default for API responses. It returns provider
    status/source metadata without network calls. ``fetch=True`` lets callers
    retrieve machine-readable public feeds such as CISA KEV; reference-only
    vendor providers remain links for manual verification.
    """
    providers = advisory_provider_objects(vendor, os_version)
    results = []
    for provider in providers:
        if fetch and provider.source.machine_readable and provider.source.provider != "NVD":
            results.append(provider.fetch(
                vendor=vendor,
                os_version=os_version,
                cve_ids=cve_ids,
                http_get=http_get,
            ))
        else:
            results.append(provider.fetch(
                vendor=vendor,
                os_version=os_version,
                cve_ids=cve_ids,
                http_get=None,
            ))

    records = []
    for result in results:
        records.extend(result.records)

    return {
        "vendor": vendor,
        "os_version": os_version,
        "fetched": fetch,
        "sources": [r.source.to_dict() for r in results],
        "providers": [r.to_dict() for r in results],
        "records": [r.to_dict() for r in records],
        "manual_verification_required": any(
            not r.machine_readable and r.source.source_type in {"vendor_advisory", "release_notes_search"}
            for r in results
        ),
    }
