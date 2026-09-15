"""Regression checks for indexed comparisons and unsupported match semantics."""
import pytest
from app.analysis import duplicate_detector, shadow_detector


def rule(index, **overrides):
    return {"id": str(index), "rule_number": index, "enabled": True, "action": "allow",
            "sources": ["10.0.0.1"], "destinations": ["192.168.1.1"],
            "services": ["https"], **overrides}


@pytest.mark.parametrize("override, objects", [
    ({"sources": []}, {}),
    ({"services": []}, {}),
    ({"action": "continue"}, {}),
    ({"negate_fields": ["source"]}, {}),
    ({"sources": ["dynamic"]}, {"dynamic": {"object_type": "fqdn", "value": "example.com"}}),
    ({"services": ["broken"]}, {"broken": {"object_type": "service", "protocol": None,
                                           "port_start": None, "port_end": None}}),
])
def test_unsupported_matches_do_not_generate_cleanup_claims(override, objects):
    rules = [rule(1, **override), rule(2, **override)]
    assert duplicate_detector.detect_duplicates(rules, objects) == []
    findings = shadow_detector.detect_shadows(rules, objects)
    assert all(f["finding_type"] == "shadowing_not_evaluated" for f in findings)


def test_index_normalizes_hosts_and_repeated_members():
    rules = [rule(1, sources=["10.0.0.1", "10.0.0.1"]),
             rule(2, sources=["10.0.0.1/32"]),
             rule(3, sources=["10.0.0.2"])]
    findings = duplicate_detector.detect_duplicates(rules, {})
    assert len(findings) == 1
    assert findings[0]["affected_rules"] == ["1", "2"]


@pytest.mark.parametrize("override", [
    {"applications": ["web"]}, {"users": ["admins"]}, {"schedule": "weekends"},
    {"source_interfaces": ["other"]}, {"services": ["ssh"]}, {"action": "deny"},
])
def test_index_preserves_restrictions_and_context(override):
    assert duplicate_detector.detect_duplicates([rule(1), rule(2, **override)], {}, "FortiGate") == []


@pytest.mark.parametrize("detector", [duplicate_detector, shadow_detector])
def test_comparison_gates_are_computed_once_per_rule(monkeypatch, detector):
    original = detector.expansion_complete
    evaluated = []
    def counted(entry):
        evaluated.append(entry["rule"]["id"])
        return original(entry)
    monkeypatch.setattr(detector, "expansion_complete", counted)
    rules = [rule(i, sources=[f"10.0.0.{i}"]) for i in range(1, 81)]
    analyze = detector.detect_duplicates if detector is duplicate_detector else detector.detect_shadows
    assert analyze(rules, {}) == []
    assert len(evaluated) == len(rules)
