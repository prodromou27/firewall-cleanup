from app.analysis.advisory_providers import (
    CisaKevProvider,
    VendorReferenceProvider,
    advisory_provider_objects,
    advisory_sources,
    collect_advisory_context,
)


def test_checkpoint_sources_include_public_databases_and_manual_vendor_verification():
    sources = advisory_sources("CheckPoint", "R81.20")
    providers = {s["provider"] for s in sources}

    assert {"NVD", "CISA KEV", "Check Point"}.issubset(providers)
    assert any(s["machine_readable"] for s in sources if s["provider"] == "NVD")
    assert any(not s["machine_readable"] for s in sources if s["provider"] == "Check Point")
    assert any("R81.20" in s["url"] or "R81.20" in s["notes"] for s in sources)


def test_cisco_marks_vendor_advisories_as_machine_readable_candidate():
    sources = advisory_sources("CiscoASA", "9.16(3)22")
    cisco = [s for s in sources if s["provider"] == "Cisco Security Advisories"]

    assert cisco
    assert cisco[0]["machine_readable"] is True
    assert cisco[0]["confidence"] == "High"


def test_unknown_vendor_gets_low_confidence_search_source():
    sources = advisory_sources("UnknownVendor", "1.2.3")

    assert sources[-1]["provider"] == "Vendor Search"
    assert sources[-1]["confidence"] == "Low"
    assert sources[-1]["machine_readable"] is False


def test_provider_objects_select_fetchable_and_reference_providers():
    providers = advisory_provider_objects("CheckPoint", "R81.20")

    assert any(isinstance(p, CisaKevProvider) for p in providers)
    assert any(isinstance(p, VendorReferenceProvider) for p in providers)


def test_collect_context_without_fetch_does_not_call_network():
    def fail_if_called(url):
        raise AssertionError(f"unexpected network call to {url}")

    context = collect_advisory_context("CheckPoint", "R81.20", cve_ids=["CVE-2024-0001"], http_get=fail_if_called)

    assert context["fetched"] is False
    assert context["records"] == []
    assert context["manual_verification_required"] is True


def test_collect_context_fetches_cisa_kev_and_filters_by_cve_id():
    def fake_get(url):
        return {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-0001",
                    "vulnerabilityName": "Relevant firewall issue",
                    "shortDescription": "Known exploited issue",
                    "dateAdded": "2024-01-01",
                    "dueDate": "2024-02-01",
                    "notes": "https://example.test/advisory",
                },
                {
                    "cveID": "CVE-2024-9999",
                    "vulnerabilityName": "Unrelated issue",
                },
            ]
        }

    context = collect_advisory_context(
        "CheckPoint",
        "R81.20",
        cve_ids=["CVE-2024-0001"],
        fetch=True,
        http_get=fake_get,
    )

    assert len(context["records"]) == 1
    assert context["records"][0]["cve_id"] == "CVE-2024-0001"
    assert context["records"][0]["known_exploited"] is True
    cisa = [p for p in context["providers"] if p["provider"] == "CISA KEV"][0]
    assert cisa["status"] == "ok"
