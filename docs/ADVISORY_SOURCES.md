# Advisory and Release-Note Sources

PolicyInsight uses multiple read-only sources for version and vulnerability
context. It must not treat every source as equally authoritative.

## Source Strategy

1. Use device-discovered firewall OS version as the primary matching key.
2. Query public machine-readable sources first:
   - NVD CVE API for CVE enrichment.
   - CISA KEV JSON feed for exploited-in-the-wild signal.
3. Add vendor advisory/release-note links for manual verification.
4. Use the manually managed Version Catalog for customer-specific recommended
   versions and support status.

## Provider Framework

The backend provider framework lives in
`backend/app/analysis/advisory_providers.py`.

It exposes:

- `advisory_sources(vendor, os_version)`: simple source/link metadata.
- `advisory_provider_objects(vendor, os_version)`: provider instances.
- `collect_advisory_context(...)`: structured provider status and optional
  fetched records.

Normal API responses use `collect_advisory_context(..., fetch=False)`, so device
views do not block on internet access. Machine-readable providers can be fetched
explicitly with `fetch=True`; currently CISA KEV is implemented as a fetchable
provider. Vendor release-note portals remain reference-only unless they expose a
stable public API or feed.

## Vendor Reliability

| Vendor | Public CVE Data | Vendor Advisory Data | Release Notes |
| --- | --- | --- | --- |
| Cisco ASA | Good via NVD/Cisco advisories | Best candidate for direct ingestion | Public pages, verify fixed train |
| Palo Alto PAN-OS | Good via NVD | Public advisory portal | Some software details may require support access |
| Fortinet FortiOS | Good via NVD/Fortinet PSIRT | Public PSIRT portal | Some firmware notes may require support access |
| Check Point Gaia/Quantum | CPE naming is inconsistent | Public/support articles, often SK based | Jumbo Hotfix applicability requires manual verification |
| Huawei USG/VRP | Variable | Public Huawei PSIRT | Release-note structure is inconsistent |

## Product Rule

PolicyInsight may display advisory links and enrichment automatically, but it
must not claim an upgrade is required unless the source includes affected/fixed
version data matching the detected OS version or a Version Catalog entry says so.

For Check Point, OS train and Jumbo Hotfix level are especially important. If the
device only reports a management API version, PolicyInsight should show
`manual verification required` instead of mapping it to gateway CVEs.
