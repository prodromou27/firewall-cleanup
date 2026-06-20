"""Unit tests for per-vendor remediation templates."""
from app.analysis.remediation_templates import get, CATEGORY_OF, TEMPLATES, _vendor_key


def test_vendor_alias_normalization():
    assert _vendor_key("fortigate") == "FortiGate"
    assert _vendor_key("PAN-OS") == "PaloAlto"
    assert _vendor_key("Cisco ASA") == "CiscoASA"
    assert _vendor_key("huawei") == "HuaweiUSG"
    assert _vendor_key(None) is None


def test_vendor_specific_guidance_resolved():
    r = get("FortiGate", "no_logging")
    assert r["vendor"] == "FortiGate"
    assert r["category"] == "enable_logging"
    assert r["vendor_specific"] is True
    assert "logtraffic" in r["guidance"].lower() or "log allowed" in r["guidance"].lower()


def test_unknown_vendor_falls_back_generic():
    r = get("SomeOtherFW", "overly_permissive")
    assert r["vendor_specific"] is False
    assert "change-management" in r["guidance"].lower()


def test_every_vendor_covers_every_category():
    categories = set(CATEGORY_OF.values())
    for vendor, tmpl in TEMPLATES.items():
        missing = categories - set(tmpl.keys())
        assert not missing, f"{vendor} missing categories: {missing}"


def test_read_only_note_present():
    r = get("CheckPoint", "rdp_exposed")
    assert "does not modify" in r["read_only_note"].lower()


def test_uncategorized_type_is_generic():
    r = get("FortiGate", "import_quality")  # not in a remediation category
    assert r["category"] is None
    assert r["vendor_specific"] is False
