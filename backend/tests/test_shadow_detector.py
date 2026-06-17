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
    assert findings[0]["finding_type"] == "shadowed_rule"
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
    assert findings[0]["finding_type"] == "shadowed_rule"
    assert findings[0]["evidence"]["conflict_type"] == "partial"
    assert "partially shadowed" in findings[0]["title"]


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
