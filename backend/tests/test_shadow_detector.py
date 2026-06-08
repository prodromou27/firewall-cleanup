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


ANY_SVC = {"object_name": "any", "object_type": "service", "value": "any", "protocol": "any", "port_start": 0, "port_end": 65535, "members": []}
HTTPS_SVC = {"object_name": "HTTPS-SVC", "object_type": "service", "value": "tcp/443-443", "protocol": "tcp", "port_start": 443, "port_end": 443, "members": []}
NET16 = {"object_name": "Net-16", "object_type": "network", "value": "10.10.0.0/16", "members": []}
HOST = {"object_name": "Host-5", "object_type": "host", "value": "10.10.5.20", "members": []}
SERVER = {"object_name": "Server", "object_type": "host", "value": "172.16.1.10", "members": []}

OBJ_MAP = {
    "any": {"object_name": "any", "object_type": "any", "value": "0.0.0.0/0", "members": []},
    "any-svc": ANY_SVC,
    "HTTPS-SVC": HTTPS_SVC,
    "Net-16": NET16,
    "Host-5": HOST,
    "Server": SERVER,
}


def test_full_shadow():
    """Rule 2 is fully shadowed by Rule 1 (Any src, same dest, Any service)."""
    rules = [
        make_rule(1, ["Net-16"], ["Server"], ["any-svc"]),
        make_rule(2, ["Host-5"], ["Server"], ["HTTPS-SVC"]),
    ]
    findings = detect_shadows(rules, OBJ_MAP)
    assert len(findings) == 1
    assert findings[0]["finding_type"] == "shadowed_rule"
    assert "2" in findings[0]["title"]


def test_no_shadow_different_dest():
    """Rules with different destinations should not shadow each other."""
    rules = [
        make_rule(1, ["Net-16"], ["Server"], ["any-svc"]),
        make_rule(2, ["Host-5"], ["Net-16"], ["HTTPS-SVC"]),
    ]
    findings = detect_shadows(rules, OBJ_MAP)
    # Net-16 (dest) is broader than Server, so not contained by Server
    assert len(findings) == 0


def test_disabled_rule_not_shadowed():
    """Disabled rules are skipped."""
    rules = [
        make_rule(1, ["Net-16"], ["Server"], ["any-svc"]),
        make_rule(2, ["Host-5"], ["Server"], ["HTTPS-SVC"], enabled=False),
    ]
    findings = detect_shadows(rules, OBJ_MAP)
    assert len(findings) == 0


def test_first_shadowing_rule_reported():
    """Only the first shadowing rule should be reported."""
    rules = [
        make_rule(1, ["Net-16"], ["Server"], ["any-svc"]),
        make_rule(2, ["any"], ["any"], ["any-svc"]),
        make_rule(3, ["Host-5"], ["Server"], ["HTTPS-SVC"]),
    ]
    findings = detect_shadows(rules, OBJ_MAP)
    # Rule 3 is shadowed by Rule 1 (first match)
    shadowed_titles = [f["title"] for f in findings]
    assert any("3" in t for t in shadowed_titles)
    # Should only report one finding per shadowed rule
    rule3_findings = [f for f in findings if "3" in f["title"]]
    assert len(rule3_findings) == 1
