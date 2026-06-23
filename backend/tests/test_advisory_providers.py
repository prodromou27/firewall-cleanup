from app.analysis.advisory_providers import advisory_sources


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
