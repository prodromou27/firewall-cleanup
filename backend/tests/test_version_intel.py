"""Slice 3: firewall version intelligence (read-only, advisory)."""
from app.analysis import version_intel as V


def _types(fs):
    return {f["finding_type"] for f in fs}


# ── normalization / parsing ──────────────────────────────────────────────────
def test_version_parsing_per_vendor():
    assert V.normalize_version("FortiGate", "7.2.5")["release_train"] == "7.2"
    assert V.normalize_version("CheckPoint", "R81.20")["release_train"] == "R81"
    assert V.normalize_version("PaloAlto", "10.1.9")["release_train"] == "10.1"
    assert V.normalize_version("CiscoASA", "9.16(3)22")["release_train"] == "9.16"
    assert V.normalize_version("HuaweiUSG", "V500R001C30SPC200")["release_train"] == "V500R001"


def test_unparseable_version_is_unknown_informational():
    norm = V.normalize_version("CheckPoint", "API 1.9.1")
    assert norm["parseable"] is False
    fs = V.evaluate(norm, [{"vendor": "CheckPoint", "release_train": "R81"}])
    assert _types(fs) == {"version_unknown"}
    assert fs[0]["severity"] == "Informational"


class _Device:
    vendor = "CheckPoint"
    os_version = "API 2.0.1"
    fw_model = ""
    management_platform = "Check Point Management API 2.0.1"
    ha_peer = ""


def test_checkpoint_api_version_is_not_treated_as_gateway_os():
    resolved = V.resolve_device_os_version(_Device())
    assert resolved["os_version"] == ""
    assert resolved["queryable"] is False
    assert resolved["source"] == "management_api_version"


def test_checkpoint_gateway_version_can_be_recovered_from_inventory():
    d = _Device()
    d.fw_model = "6500 Plus (GW: R81.10, R81.20)"
    resolved = V.resolve_device_os_version(d)
    assert resolved["os_version"] == "R81.20"
    assert resolved["queryable"] is True
    assert resolved["source"] == "gateway_inventory"


# ── catalog matching ─────────────────────────────────────────────────────────
def _cat(**o):
    base = {"vendor": "CheckPoint", "release_train": "R81", "recommended_version": "R81.20",
            "support_status": "supported", "eol_versions": []}
    base.update(o); return base


def test_catalog_match_recommended_no_finding():
    norm = V.normalize_version("CheckPoint", "R81.20")
    fs = V.evaluate(norm, [_cat()])
    assert fs == []  # current == recommended → no version finding


def test_behind_recommended_is_medium():
    norm = V.normalize_version("CheckPoint", "R81.10")
    fs = V.evaluate(norm, [_cat(recommended_version="R81.20")])
    assert "version_outdated" in _types(fs)
    f = [x for x in fs if x["finding_type"] == "version_outdated"][0]
    assert f["severity"] == "Medium"


def test_end_of_support_is_high():
    norm = V.normalize_version("CheckPoint", "R80.40")
    fs = V.evaluate(norm, [_cat(release_train="R80", support_status="end-of-support")])
    f = [x for x in fs if x["finding_type"] == "version_end_of_support"]
    assert f and f[0]["severity"] == "High"


def test_eol_by_explicit_version_list():
    norm = V.normalize_version("FortiGate", "6.4.2")
    fs = V.evaluate(norm, [{"vendor": "FortiGate", "release_train": "6.4",
                            "support_status": "supported", "eol_versions": ["6.4"]}])
    assert "version_end_of_support" in _types(fs)


def test_catalog_unavailable_informational_only():
    norm = V.normalize_version("CheckPoint", "R81.20")
    fs = V.evaluate(norm, [])
    assert _types(fs) == {"version_catalog_unavailable"}
    assert all(f["severity"] == "Informational" for f in fs)
    # never fabricates outdated/EOL without catalog
    assert not any(f["finding_type"] in ("version_outdated", "version_end_of_support") for f in fs)


def test_ha_version_mismatch():
    norm = V.normalize_version("FortiGate", "7.2.5", ha_peer_version="7.2.3")
    fs = V.evaluate(norm, [{"vendor": "FortiGate", "release_train": "7.2",
                            "recommended_version": "7.2.5", "support_status": "supported"}])
    assert "version_ha_mismatch" in _types(fs)


def test_peer_version_or_blank_rejects_ip_and_hostname():
    """device.ha_peer stores the peer's address, not a version — an IP or
    hostname must never be compared against os_version (false HA mismatch)."""
    assert V.peer_version_or_blank("192.168.1.2") == ""
    assert V.peer_version_or_blank("fw-hq-02") == ""
    assert V.peer_version_or_blank("") == ""
    assert V.peer_version_or_blank("7.2.3") == "7.2.3"
    assert V.peer_version_or_blank("R81.20") == "R81.20"


def test_analyze_device_ignores_ip_ha_peer():
    class Dev:
        vendor = "FortiGate"
        os_version = "7.2.5"
        fw_model = "FortiGate-600F"
        ha_peer = "192.168.1.2"
        management_platform = ""

    result = V.analyze_device(Dev(), [{"vendor": "FortiGate", "release_train": "7.2",
                                       "recommended_version": "7.2.5",
                                       "support_status": "supported"}])
    assert "version_ha_mismatch" not in _types(result["findings"])


def test_advisory_wording_is_safe():
    norm = V.normalize_version("CheckPoint", "R81.10")
    for f in V.evaluate(norm, [_cat(recommended_version="R81.20")]):
        assert "change management process" in f["recommendation"].lower()
        assert "immediately" not in f["recommendation"].lower()
