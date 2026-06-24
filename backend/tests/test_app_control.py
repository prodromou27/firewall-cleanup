"""Vendor-aware Application Control analysis tests (read-only)."""
from app.analysis import app_control as AC


def _rule(rid="R1", action="allow", enabled=True, apps=None, services=None):
    return {
        "id": f"id-{rid}", "rule_id": rid, "rule_number": 1, "rule_name": rid,
        "action": action, "enabled": enabled,
        "applications": apps if apps is not None else [],
        "services": services if services is not None else ["any"],
    }


def _types(findings):
    return sorted({f["finding_type"] for f in findings})


# ── Palo Alto Policy-Optimizer categories ───────────────────────────────────
def test_palo_port_based_rule_candidate():
    """application:any + specific service = port-based rule (conversion candidate),
    NOT 'any service' / Any-Any-Any."""
    r = _rule(apps=[], services=["tcp-443"])
    f = AC.analyze([r], "PaloAlto")
    assert "palo_alto_port_based_rule_candidate" in _types(f)
    assert "rule_without_app_controls" not in _types(f)


def test_palo_rule_without_app_controls_when_service_any():
    r = _rule(apps=[], services=["any"])
    f = AC.analyze([r], "PaloAlto")
    assert "rule_without_app_controls" in _types(f)


def test_palo_app_constrained_rule_produces_no_app_control_finding():
    """A rule that already constrains by App-ID is clean."""
    r = _rule(apps=["ssl", "web-browsing"], services=["application-default"])
    f = AC.analyze([r], "PaloAlto")
    assert "rule_without_app_controls" not in _types(f)
    assert "palo_alto_port_based_rule_candidate" not in _types(f)


def test_palo_application_any_with_restricted_service_is_not_any_any_any():
    """Regression: application:any + restricted service must be a port-based
    candidate (Low), never escalated as unrestricted."""
    r = _rule(apps=[], services=["tcp-8443"])
    f = AC.analyze([r], "PaloAlto")
    pb = [x for x in f if x["finding_type"] == "palo_alto_port_based_rule_candidate"]
    assert pb and pb[0]["severity"] == "Low"


def test_palo_disabled_and_deny_rules_skipped():
    assert AC.analyze([_rule(enabled=False, apps=[], services=["any"])], "PaloAlto") == []
    assert AC.analyze([_rule(action="deny", apps=[], services=["any"])], "PaloAlto") == []


# ── Risky named applications (any vendor that lists them) ────────────────────
def test_risky_application_allowed_from_named_app():
    r = _rule(apps=["tor"], services=["any"])
    f = AC.analyze([r], "PaloAlto")
    risky = [x for x in f if x["finding_type"] == "risky_application_allowed"]
    assert risky and risky[0]["severity"] == "High"
    assert risky[0]["evidence"]["risky_applications"] == ["tor"]


def test_risky_application_variant_suffix_matches_but_substring_does_not():
    assert AC._risky_match("teamviewer-base") is True
    assert AC._risky_match("mentor") is False          # 'tor' substring must not match
    assert AC._risky_match("storage") is False


# ── Vendor support gating ────────────────────────────────────────────────────
def test_cisco_asa_reports_not_supported():
    f = AC.analyze([_rule()], "CiscoASA")
    assert "application_analysis_not_supported_for_vendor" in _types(f)


def test_checkpoint_fortigate_emit_nothing_here():
    """CP/FortiGate app-control is handled in their own slices — no premature notes."""
    assert AC.analyze([_rule(apps=[], services=["any"])], "CheckPoint") == []
    assert AC.analyze([_rule(apps=[], services=["any"])], "FortiGate") == []
