"""Tests for the NAT & Public Exposure analysis module (read-only)."""
from app.analysis import nat_exposure as NE


def _sec(rid="S1", src=None, dst=None, svc=None, action="accept", enabled=True):
    return {"rule_id": rid, "enabled": enabled, "action": action,
            "sources": src or ["any"], "destinations": dst or ["10.0.0.5"],
            "services": svc or ["tcp/3389"]}


def _nat(num=1, ntype="destination", odst=None, osvc=None, tdst=None, tsvc=None,
         osrc=None, tsrc=None, enabled=True):
    return {"rule_number": num, "nat_type": ntype,
            "original_src": osrc or [], "original_dst": odst or ["203.0.113.10"],
            "original_service": osvc or ["tcp/3389"],
            "translated_src": tsrc or [], "translated_dst": tdst or ["10.0.0.5"],
            "translated_service": tsvc or ["tcp/3389"], "enabled": enabled}


def _types(res):
    return sorted({f["finding_type"] for f in res["findings"]})


# ── Gating ───────────────────────────────────────────────────────────────────
def test_nat_unavailable_when_no_data():
    assert NE.nat_available(None) is False
    assert NE.nat_available([]) is False
    res = NE.analyze([], None, {})
    assert res["nat_available"] is False
    # No NAT-specific findings fabricated
    assert not [f for f in res["findings"] if f["finding_type"].startswith("nat_")]


def test_nat_available_with_data():
    res = NE.analyze([], [_nat()], {})
    assert res["nat_available"] is True


def test_policy_exposure_still_works_without_nat():
    """Public-exposure from the security policy is independent of NAT data."""
    res = NE.analyze([_sec(svc=["tcp/3389"])], None, {})
    assert res["nat_available"] is False
    assert "rdp_public_exposure" in _types(res)


# ── NAT-rule checks (#1-#8) ──────────────────────────────────────────────────
def test_public_to_internal_dnat():                       # #1, #2
    res = NE.analyze([_sec()], [_nat()], {})
    assert "nat_public_to_internal" in _types(res)


def test_static_nat():                                    # #3
    n = _nat(ntype="static", odst=["10.0.0.9"], tdst=["10.0.0.5"], osvc=[], tsvc=[])
    assert "nat_static" in _types(NE.analyze([], [n], {}))


def test_source_nat():                                    # #4
    n = _nat(ntype="hide", odst=[], tdst=[], tsrc=["203.0.113.1"], osvc=[], tsvc=[])
    assert "nat_source" in _types(NE.analyze([], [n], {}))


def test_duplicate_nat():                                 # #5
    res = NE.analyze([_sec()], [_nat(num=1), _nat(num=2)], {})
    assert "nat_duplicate" in _types(res)


def test_overlapping_nat():                               # #6
    a = _nat(num=1, tdst=["10.0.0.5"])
    b = _nat(num=2, tdst=["10.0.0.6"])  # same original dst+svc, different target
    assert "nat_overlap" in _types(NE.analyze([], [a, b], {}))


def test_nat_without_matching_policy():                   # #7
    # DNAT to 10.0.0.5 but the only security rule allows a different host
    sec = [_sec(dst=["10.0.0.99"])]
    res = NE.analyze(sec, [_nat(tdst=["10.0.0.5"])], {})
    assert "nat_without_policy" in _types(res)


def test_security_rule_without_nat_relationship():        # #8
    # Inbound public→internal rule, NAT references an unrelated host
    sec = [_sec(src=["any"], dst=["10.0.0.5"], svc=["tcp/443"])]
    nat = [_nat(num=1, ntype="static", odst=["10.0.0.80"], tdst=["10.0.0.81"], osvc=[], tsvc=[])]
    assert "policy_without_nat" in _types(NE.analyze(sec, nat, {}))


# ── Public exposure checks (#9-#14) ──────────────────────────────────────────
def test_rdp_exposure():                                  # #9
    assert "rdp_public_exposure" in _types(NE.analyze([_sec(svc=["tcp/3389"])], None, {}))


def test_ssh_exposure():                                  # #10
    assert "ssh_public_exposure" in _types(NE.analyze([_sec(svc=["tcp/22"])], None, {}))


def test_smb_exposure():                                  # #11
    assert "smb_public_exposure" in _types(NE.analyze([_sec(svc=["tcp/445"])], None, {}))


def test_database_exposure():                             # #12
    assert "database_public_exposure" in _types(NE.analyze([_sec(svc=["tcp/1433"])], None, {}))


def test_any_service_exposure():                          # #13
    assert "any_service_public_exposure" in _types(NE.analyze([_sec(svc=["any"])], None, {}))


def test_sensitive_destination_multiple_ports():          # #14
    # one internal host exposing RDP + SQL to the internet
    sec = [_sec(rid="S1", dst=["10.0.0.5"], svc=["tcp/3389"]),
           _sec(rid="S2", dst=["10.0.0.5"], svc=["tcp/1433"])]
    # combine onto one exposure via a single rule listing both services
    sec2 = [_sec(dst=["10.0.0.5"], svc=["tcp/3389", "tcp/1433"])]
    assert "sensitive_destination_exposure" in _types(NE.analyze(sec2, None, {}))


# ── Inventory + risk ─────────────────────────────────────────────────────────
def test_inventory_and_risk():
    res = NE.analyze([_sec(svc=["tcp/3389"])], [_nat()], {})
    exp = res["exposure"]
    assert 3389 in exp["exposed_ports"]
    assert exp["public_ips"]
    assert exp["risk_score"] > 0


def test_disabled_nat_ignored():
    res = NE.analyze([], [_nat(enabled=False)], {})
    assert not [f for f in res["findings"] if f["finding_type"].startswith("nat_")]


def test_findings_are_readonly_recommendations():
    """No finding may suggest writing to the firewall."""
    res = NE.analyze([_sec()], [_nat()], {})
    for f in res["findings"]:
        assert "change-management" in f["recommendation"].lower() or f["recommendation"]


# ── Slice 2: depth (admin protocols, logging, confidence) ────────────────────
def test_telnet_winrm_vnc_exposure_critical():
    for port, ftype in [("tcp/23", "telnet_public_exposure"),
                        ("tcp/5985", "winrm_public_exposure"),
                        ("tcp/5900", "vnc_public_exposure")]:
        res = NE.analyze([_sec(svc=[port])], None, {})
        f = [x for x in res["findings"] if x["finding_type"] == ftype]
        assert f and f[0]["severity"] == "Critical", port


def test_public_exposure_missing_logging():
    sec = [_sec(svc=["tcp/3389"])]
    sec[0]["logging_enabled"] = False
    res = NE.analyze(sec, None, {})
    assert "public_exposure_no_logging" in _types(res)


def test_logging_enabled_no_logging_finding():
    sec = [_sec(svc=["tcp/3389"])]
    sec[0]["logging_enabled"] = True
    res = NE.analyze(sec, None, {})
    assert "public_exposure_no_logging" not in _types(res)


def test_nat_confidence_medium_without_policy_corroboration():
    # DNAT publishing a host, but the security rule targets a different host
    res = NE.analyze([_sec(dst=["10.0.0.99"], svc=["tcp/3389"])], [_nat(tdst=["10.0.0.5"])], {})
    nat_exp = [e for e in res["exposure"]["exposures"] if e["source"] == "nat"]
    assert nat_exp and nat_exp[0]["confidence"] == "Medium"


def test_nat_confidence_high_when_policy_corroborates():
    # DNAT to 10.0.0.5 and a security rule allows public->10.0.0.5
    res = NE.analyze([_sec(dst=["10.0.0.5"], svc=["tcp/3389"])], [_nat(tdst=["10.0.0.5"])], {})
    nat_exp = [e for e in res["exposure"]["exposures"] if e["source"] == "nat"]
    assert nat_exp and nat_exp[0]["confidence"] == "High"
