"""Vendor advisory/release-note source registry.

This module intentionally separates advisory source discovery from CVE matching.
Some vendors expose stable public machine-readable data; others primarily expose
human web pages or support-portal content. PolicyInsight should report that
difference explicitly instead of pretending every vendor has reliable automated
release-note retrieval.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import List
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
