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


@pytest.fixture
def obj_map():
    """A fresh object map per test so tests never share mutable state."""
    return {
        "Server_A": {"object_name": "Server_A", "object_type": "host", "value": "10.10.10.5", "members": []},
        "SRV-A": {"object_name": "SRV-A", "object_type": "host", "value": "10.10.10.5", "members": []},
        "Net-10": {"object_name": "Net-10", "object_type": "network", "value": "10.10.0.0/24", "members": []},
        "HTTPS-SVC": {"object_name": "HTTPS-SVC", "object_type": "service", "value": "tcp/443-443", "protocol": "tcp", "port_start": 443, "port_end": 443, "members": []},
    }


def test_exact_duplicate(obj_map):
    rules = [
        make_rule(1, ["Net-10"], ["Server_A"], ["HTTPS-SVC"]),
        make_rule(2, ["Net-10"], ["Server_A"], ["HTTPS-SVC"]),
    ]
    findings = detect_duplicates(rules, obj_map)
    assert len(findings) == 1
    assert findings[0]["finding_type"] == "duplicate_rule"


def test_different_objects_same_value(obj_map):
    """Rules using different object names that resolve to the same IP."""
    rules = [
        make_rule(1, ["Server_A"], ["Net-10"], ["HTTPS-SVC"]),
        make_rule(2, ["SRV-A"], ["Net-10"], ["HTTPS-SVC"]),
    ]
    findings = detect_duplicates(rules, obj_map)
    assert len(findings) == 1


def test_different_action_not_duplicate(obj_map):
    rules = [
        make_rule(1, ["Net-10"], ["Server_A"], ["HTTPS-SVC"], action="accept"),
        make_rule(2, ["Net-10"], ["Server_A"], ["HTTPS-SVC"], action="deny"),
    ]
    findings = detect_duplicates(rules, obj_map)
    assert len(findings) == 0


def test_no_false_positives(obj_map):
    rules = [
        make_rule(1, ["Net-10"], ["Server_A"], ["HTTPS-SVC"]),
        make_rule(2, ["10.11.0.0/24"], ["Server_A"], ["HTTPS-SVC"]),
    ]
    # 10.11.0.0/24 is not in OBJ_MAP, treated as unknown
    findings = detect_duplicates(rules, obj_map)
    # Should not flag as duplicate since source IPs differ
    assert len(findings) == 0


def test_three_rules_two_duplicates(obj_map):
    rules = [
        make_rule(1, ["Net-10"], ["Server_A"], ["HTTPS-SVC"]),
        make_rule(2, ["Net-10"], ["Server_A"], ["HTTPS-SVC"]),
        make_rule(3, ["Net-10"], ["Server_A"], ["HTTPS-SVC"]),
    ]
    findings = detect_duplicates(rules, obj_map)
    # Three identical rules are grouped into a single duplicate-group finding
    # rather than one finding per pair.
    assert len(findings) == 1
    assert findings[0]["finding_type"] == "duplicate_rule"
    assert len(findings[0]["affected_rules"]) == 3


@pytest.mark.parametrize("field,left,right", [
    ("applications", ["web-browsing"], ["ssh"]),
    ("users", ["engineering"], ["finance"]),
    ("vpn", ["remote-access"], ["site-to-site"]),
    ("schedule", "business-hours", "always"),
    ("logging_enabled", True, False),
    ("nat_enabled", True, False),
    ("security_profiles", {"ips-sensor": "strict"}, {"ips-sensor": "default"}),
])
def test_different_match_or_inspection_semantics_are_not_duplicates(obj_map, field, left, right):
    first = make_rule(1, ["Net-10"], ["Server_A"], ["HTTPS-SVC"])
    second = make_rule(2, ["Net-10"], ["Server_A"], ["HTTPS-SVC"])
    first[field], second[field] = left, right
    assert detect_duplicates([first, second], obj_map) == []


def test_unresolved_group_is_not_a_confirmed_duplicate(obj_map):
    obj_map["Empty"] = {"object_name": "Empty", "object_type": "address_group", "members": []}
    rules = [make_rule(n, ["Empty"], ["Server_A"], ["HTTPS-SVC"]) for n in (1, 2)]
    assert detect_duplicates(rules, obj_map) == []


def test_any4_and_any6_are_not_equivalent_address_families(obj_map):
    first = make_rule(1, ["any4"], ["Server_A"], ["HTTPS-SVC"])
    second = make_rule(2, ["any6"], ["Server_A"], ["HTTPS-SVC"])
    assert detect_duplicates([first, second], obj_map) == []
