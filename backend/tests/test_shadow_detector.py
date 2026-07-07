"""Unit tests for shadow rule detection."""
import pytest
from app.analysis.shadow_detector import detect_shadows


def make_rule(n, sources, dests, services, action="accept", enabled=True):
    return {
        "id": f"rule-{n}",
        "rule_id": str(n),
        "rule_number": n,
        "rule_name": f"Rule {n}",
        "sources": sources,
        "destinations": dests,
        "services": services,
        "action": action,
        "enabled": enabled,
        "comments": "",
        "hit_count": None,
        "last_hit": None,
    }


@pytest.fixture
def obj_map():
    """A fresh object map per test so tests never share mutable state."""
    return {
        "any": {"object_name": "any", "object_type": "any", "value": "0.0.0.0/0", "members": []},
        "any-svc": {"object_name": "any", "object_type": "service", "value": "any", "protocol": "any", "port_start": 0, "port_end": 65535, "members": []},
        "HTTPS-SVC": {"object_name": "HTTPS-SVC", "object_type": "service", "value": "tcp/443-443", "protocol": "tcp", "port_start": 443, "port_end": 443, "members": []},
        "Net-16": {"object_name": "Net-16", "object_type": "network", "value": "10.10.0.0/16", "members": []},
        "Host-5": {"object_name": "Host-5", "object_type": "host", "value": "10.10.5.20", "members": []},
        "Server": {"object_name": "Server", "object_type": "host", "value": "172.16.1.10", "members": []},
    }


def test_full_shadow(obj_map):
    """Rule 2 is fully shadowed by Rule 1 (Any src, same dest, Any service)."""
    rules = [
        make_rule(1, ["Net-16"], ["Server"], ["any-svc"]),
        make_rule(2, ["Host-5"], ["Server"], ["HTTPS-SVC"]),
    ]
    findings = detect_shadows(rules, obj_map)
    assert len(findings) == 1
    # Full containment, same action → redundant (same-action) shadow.
    assert findings[0]["finding_type"] == "redundant_rule"
    assert "2" in findings[0]["title"]


def test_partial_shadow_different_dest(obj_map):
    """Source + service overlap but destination differs -> partial shadow.

    Rule 2's source Host-5 (10.10.5.20) is contained by Rule 1's Net-16
    (10.10.0.0/16), and Rule 1's 'any' service contains HTTPS, but Rule 2's
    destination Net-16 is broader than Rule 1's Server, so it is not fully
    contained. Two of three dimensions overlap -> a partial-shadow finding.
    """
    rules = [
        make_rule(1, ["Net-16"], ["Server"], ["any-svc"]),
        make_rule(2, ["Host-5"], ["Net-16"], ["HTTPS-SVC"]),
    ]
    findings = detect_shadows(rules, obj_map)
    assert len(findings) == 1
    assert findings[0]["finding_type"] == "partial_shadowed_rule"
    assert findings[0]["evidence"]["conflict_type"] == "partial"
    assert "partially shadowed" in findings[0]["title"]


def test_full_shadow_with_hits_reported_low_confidence(obj_map):
    """A 'fully shadowed' rule with recorded hits is contradicted by the
    device's own counters — keep the finding but at Low confidence."""
    rules = [
        make_rule(1, ["Net-16"], ["Server"], ["any-svc"]),
        make_rule(2, ["Host-5"], ["Server"], ["HTTPS-SVC"]),
    ]
    rules[1]["hit_count"] = 245
    findings = detect_shadows(rules, obj_map)
    assert len(findings) == 1
    assert findings[0]["finding_type"] == "redundant_rule"
    assert findings[0]["confidence"] == "Low"
    assert findings[0]["evidence"]["hit_count_contradicts_shadow"] is True
    assert "245" in findings[0]["description"]


def test_full_shadow_zero_hits_stays_high_confidence(obj_map):
    rules = [
        make_rule(1, ["Net-16"], ["Server"], ["any-svc"]),
        make_rule(2, ["Host-5"], ["Server"], ["HTTPS-SVC"]),
    ]
    rules[1]["hit_count"] = 0
    findings = detect_shadows(rules, obj_map)
    assert len(findings) == 1
    assert findings[0]["confidence"] == "High"


def test_conflicting_shadow_with_hits_reported_low_confidence(obj_map):
    """'Can never take effect' is disproved by a nonzero hit counter."""
    rules = [
        make_rule(1, ["Net-16"], ["Server"], ["any-svc"]),
        make_rule(2, ["Host-5"], ["Server"], ["HTTPS-SVC"], action="deny"),
    ]
    rules[1]["hit_count"] = 10
    findings = detect_shadows(rules, obj_map)
    assert len(findings) == 1
    assert findings[0]["finding_type"] == "shadowed_rule"
    assert findings[0]["confidence"] == "Low"


def test_disabled_rule_not_shadowed(obj_map):
    """Disabled rules are skipped."""
    rules = [
        make_rule(1, ["Net-16"], ["Server"], ["any-svc"]),
        make_rule(2, ["Host-5"], ["Server"], ["HTTPS-SVC"], enabled=False),
    ]
    findings = detect_shadows(rules, obj_map)
    assert len(findings) == 0


def test_first_shadowing_rule_reported(obj_map):
    """Only the first shadowing rule should be reported."""
    rules = [
        make_rule(1, ["Net-16"], ["Server"], ["any-svc"]),
        make_rule(2, ["any"], ["any"], ["any-svc"]),
        make_rule(3, ["Host-5"], ["Server"], ["HTTPS-SVC"]),
    ]
    findings = detect_shadows(rules, obj_map)
    # Rule 3 is shadowed by Rule 1 (first match)
    shadowed_titles = [f["title"] for f in findings]
    assert any("3" in t for t in shadowed_titles)
    # Should only report one finding per shadowed rule
    rule3_findings = [f for f in findings if "3" in f["title"]]
    assert len(rule3_findings) == 1


# ── Vendor-aware context scoping + split finding types (slice 1) ─────────────
def _ctx_rule(n, sources, dests, services, action="accept", enabled=True,
              section="", src_if=None, dst_if=None, install_on=None):
    r = make_rule(n, sources, dests, services, action, enabled)
    r["section"] = section
    r["source_interfaces"] = src_if or []
    r["destination_interfaces"] = dst_if or []
    r["install_on"] = install_on or []
    return r


def test_conflicting_action_full_shadow(obj_map):
    """Earlier any/any/any allow fully covers a later deny → conflicting shadow (High)."""
    rules = [
        make_rule(1, ["Net-16"], ["Server"], ["any-svc"], action="accept"),
        make_rule(2, ["Host-5"], ["Server"], ["HTTPS-SVC"], action="deny"),
    ]
    findings = detect_shadows(rules, obj_map)
    assert len(findings) == 1
    assert findings[0]["finding_type"] == "shadowed_rule"
    assert findings[0]["severity"] == "High"


def test_no_shadow_across_checkpoint_layers(obj_map):
    """Same traffic in different CP layers must NOT be compared."""
    rules = [
        _ctx_rule(1, ["Net-16"], ["Server"], ["any-svc"], section="Network"),
        _ctx_rule(2, ["Host-5"], ["Server"], ["HTTPS-SVC"], section="Applications & URL Filtering"),
    ]
    assert detect_shadows(rules, obj_map, vendor="CheckPoint") == []


def test_no_shadow_across_checkpoint_install_targets(obj_map):
    rules = [
        _ctx_rule(1, ["Net-16"], ["Server"], ["any-svc"], install_on=["GW-A"]),
        _ctx_rule(2, ["Host-5"], ["Server"], ["HTTPS-SVC"], install_on=["GW-B"]),
    ]
    assert detect_shadows(rules, obj_map, vendor="CheckPoint") == []


def test_no_shadow_across_fortigate_interface_pairs(obj_map):
    rules = [
        _ctx_rule(1, ["Net-16"], ["Server"], ["any-svc"], src_if=["wan1"], dst_if=["lan"]),
        _ctx_rule(2, ["Host-5"], ["Server"], ["HTTPS-SVC"], src_if=["wan2"], dst_if=["dmz"]),
    ]
    assert detect_shadows(rules, obj_map, vendor="FortiGate") == []


def test_shadow_within_same_context(obj_map):
    """Same interface pair → shadowing IS evaluated."""
    rules = [
        _ctx_rule(1, ["Net-16"], ["Server"], ["any-svc"], src_if=["wan1"], dst_if=["lan"]),
        _ctx_rule(2, ["Host-5"], ["Server"], ["HTTPS-SVC"], src_if=["wan1"], dst_if=["lan"]),
    ]
    findings = detect_shadows(rules, obj_map, vendor="FortiGate")
    assert len(findings) == 1
    assert findings[0]["finding_type"] == "redundant_rule"


def test_shadowing_not_evaluated_for_unknown_objects(obj_map):
    rules = [
        make_rule(1, ["Net-16"], ["Server"], ["any-svc"]),
        make_rule(2, ["UNRESOLVED-OBJ"], ["Server"], ["HTTPS-SVC"]),
    ]
    findings = detect_shadows(rules, obj_map)
    assert any(f["finding_type"] == "shadowing_not_evaluated" for f in findings)


def test_negated_rule_excluded_from_shadow_comparison(obj_map):
    """A rule with a negated cell ('Any except X') must not be called shadowed —
    its containment is inverted, so comparing it as an ordinary set is wrong."""
    rules = [
        make_rule(1, ["Net-16"], ["Server"], ["any-svc"]),
        make_rule(2, ["Host-5"], ["Server"], ["HTTPS-SVC"]),
    ]
    rules[1]["negated"] = True   # later rule negates a cell
    findings = detect_shadows(rules, obj_map)
    assert not any(f["finding_type"] in ("redundant_rule", "shadowed_rule") for f in findings)
    assert any(f["finding_type"] == "shadowing_not_evaluated" for f in findings)


def test_negated_earlier_rule_does_not_shadow(obj_map):
    rules = [
        make_rule(1, ["Net-16"], ["Server"], ["any-svc"]),
        make_rule(2, ["Host-5"], ["Server"], ["HTTPS-SVC"]),
    ]
    rules[0]["negated"] = True   # the broad earlier rule is negated → can't shadow
    findings = detect_shadows(rules, obj_map)
    assert not any(f["finding_type"] in ("redundant_rule", "shadowed_rule") for f in findings)
