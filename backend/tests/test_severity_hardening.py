"""Slice 1: severity/criticality + false-positive hardening."""
from app.analysis.engine import _analyze_permissive
from app.analysis.ip_utils import classify_ip, is_routable_public


def _rule(**o):
    base = dict(id="r", rule_id="1", rule_name="R", enabled=True, action="accept",
                sources=["any"], destinations=["any"], services=["any"], applications=[])
    base.update(o); return base


def _types(rs):
    return {f["finding_type"] for f in rs}


# ── Any-to-Any criticality ───────────────────────────────────────────────────
def test_enabled_any_any_any_is_critical_dedicated_finding():
    out = _analyze_permissive([_rule()], {})
    f = [x for x in out if x["finding_type"] == "any_to_any_allow"]
    assert f and f[0]["severity"] == "Critical"
    assert f[0]["title"] == "Critical Any-to-Any Allow Rule Detected"
    # evidence proves why
    ev = f[0]["evidence"]
    assert ev["any_source"] and ev["any_destination"] and ev["any_service"]
    # Not double-reported as the graded overly_permissive
    assert "overly_permissive" not in _types(out)


def test_disabled_any_any_is_not_critical():
    out = _analyze_permissive([_rule(enabled=False)], {})
    assert out == []


def test_deny_any_any_is_not_flagged():
    out = _analyze_permissive([_rule(action="deny")], {})
    assert out == []


def test_partial_permissive_is_not_any_to_any():
    # any source + any dest but specific service → graded overly_permissive, not any_to_any
    out = _analyze_permissive([_rule(services=["tcp/443"])], {})
    assert "any_to_any_allow" not in _types(out)
    assert "overly_permissive" in _types(out)


def test_any_to_any_with_l7_app_constraint_not_critical():
    # service Any but constrained by application → not any-to-any
    out = _analyze_permissive([_rule(applications=["Facebook"])], {})
    assert "any_to_any_allow" not in _types(out)


# ── IP classification (FP reduction) ─────────────────────────────────────────
def test_ip_classification():
    assert classify_ip("any") == "any"
    assert classify_ip("0.0.0.0/0") == "any"
    assert classify_ip("127.0.0.1") == "loopback"
    assert classify_ip("169.254.1.1") == "link_local"
    assert classify_ip("10.0.0.0/8") == "private"
    assert classify_ip("192.168.1.0/24") == "private"
    assert classify_ip("8.8.8.8") == "public"
    assert classify_ip("not-an-ip") == "unknown"


def test_routable_public_excludes_nonroutable():
    assert is_routable_public("8.8.8.8")
    assert not is_routable_public("any")
    assert not is_routable_public("127.0.0.1")
    assert not is_routable_public("169.254.0.1")
    assert not is_routable_public("10.1.2.3")
