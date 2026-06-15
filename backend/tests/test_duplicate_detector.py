"""Unit tests for duplicate rule detection."""
import pytest
from app.analysis.duplicate_detector import detect_duplicates


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


OBJ_MAP = {
    "Server_A": {"object_name": "Server_A", "object_type": "host", "value": "10.10.10.5", "members": []},
    "SRV-A": {"object_name": "SRV-A", "object_type": "host", "value": "10.10.10.5", "members": []},
    "Net-10": {"object_name": "Net-10", "object_type": "network", "value": "10.10.0.0/24", "members": []},
    "HTTPS-SVC": {"object_name": "HTTPS-SVC", "object_type": "service", "value": "tcp/443-443", "protocol": "tcp", "port_start": 443, "port_end": 443, "members": []},
}


def test_exact_duplicate():
    rules = [
        make_rule(1, ["Net-10"], ["Server_A"], ["HTTPS-SVC"]),
        make_rule(2, ["Net-10"], ["Server_A"], ["HTTPS-SVC"]),
    ]
    findings = detect_duplicates(rules, OBJ_MAP)
    assert len(findings) == 1
    assert findings[0]["finding_type"] == "duplicate_rule"


def test_different_objects_same_value():
    """Rules using different object names that resolve to the same IP."""
    rules = [
        make_rule(1, ["Server_A"], ["Net-10"], ["HTTPS-SVC"]),
        make_rule(2, ["SRV-A"], ["Net-10"], ["HTTPS-SVC"]),
    ]
    findings = detect_duplicates(rules, OBJ_MAP)
    assert len(findings) == 1


def test_different_action_not_duplicate():
    rules = [
        make_rule(1, ["Net-10"], ["Server_A"], ["HTTPS-SVC"], action="accept"),
        make_rule(2, ["Net-10"], ["Server_A"], ["HTTPS-SVC"], action="deny"),
    ]
    findings = detect_duplicates(rules, OBJ_MAP)
    assert len(findings) == 0


def test_no_false_positives():
    rules = [
        make_rule(1, ["Net-10"], ["Server_A"], ["HTTPS-SVC"]),
        make_rule(2, ["10.11.0.0/24"], ["Server_A"], ["HTTPS-SVC"]),
    ]
    # 10.11.0.0/24 is not in OBJ_MAP, treated as unknown
    findings = detect_duplicates(rules, OBJ_MAP)
    # Should not flag as duplicate since source IPs differ
    assert len(findings) == 0


def test_three_rules_two_duplicates():
    rules = [
        make_rule(1, ["Net-10"], ["Server_A"], ["HTTPS-SVC"]),
        make_rule(2, ["Net-10"], ["Server_A"], ["HTTPS-SVC"]),
        make_rule(3, ["Net-10"], ["Server_A"], ["HTTPS-SVC"]),
    ]
    findings = detect_duplicates(rules, OBJ_MAP)
    # Three identical rules are grouped into a single duplicate-group finding
    # rather than one finding per pair.
    assert len(findings) == 1
    assert findings[0]["finding_type"] == "duplicate_rule"
    assert len(findings[0]["affected_rules"]) == 3
