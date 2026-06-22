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


def test_advisory_wording_is_safe():
    norm = V.normalize_version("CheckPoint", "R81.10")
    for f in V.evaluate(norm, [_cat(recommended_version="R81.20")]):
        assert "change management process" in f["recommendation"].lower()
        assert "immediately" not in f["recommendation"].lower()
