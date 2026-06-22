"""Accuracy regressions for the PolicyInsight findings engine."""

from app.analysis.duplicate_detector import detect_duplicates
from app.analysis.engine import (
    _analyze_empty_groups,
    _analyze_permissive,
    _analyze_risky_services,
    _analyze_unused_objects,
    _analyze_usage,
)
from app.analysis.normalizer import build_object_map
from app.analysis.shadow_detector import detect_shadows


def _rule(n, sources=None, destinations=None, services=None, **overrides):
    rule = {
        "id": f"rule-{n}",
        "rule_id": str(n),
        "rule_number": n,
        "rule_name": f"Rule {n}",
        "sources": sources or ["any"],
        "destinations": destinations or ["any"],
        "services": services or ["any"],
        "action": "accept",
        "enabled": True,
        "hit_count": None,
        "last_hit": None,
    }
    rule.update(overrides)
    return rule


def _object(name, object_type="host", value="10.0.0.1/32", members=None, **overrides):
    obj = {
        "id": f"obj-{name}",
        "vendor": "PaloAlto",
        "object_name": name,
        "object_type": object_type,
        "value": value,
        "members": members or [],
        "raw_data": {},
    }
    obj.update(overrides)
    return obj


def _assert_quality(findings):
    assert findings
    for finding in findings:
        assert finding["severity"]
        assert finding["confidence"]
        assert isinstance(finding["evidence"], dict)
        assert finding["recommendation"]


def test_zero_hit_requires_hit_count_data():
    assert _analyze_usage([_rule(1, hit_count=None)], {}) == []

    findings = _analyze_usage([_rule(2, hit_count=0)], {})

    assert len(findings) == 1
    assert findings[0]["finding_type"] == "zero_hit_rule"
    assert findings[0]["evidence"]["hit_count"] == 0
    _assert_quality(findings)


def test_overly_permissive_rule_reports_evidence_and_recommendation():
    findings = _analyze_permissive([_rule(1)], {})

    assert len(findings) == 1
    # A fully any/any/any allow is now reported as the dedicated Critical
    # any-to-any finding rather than the graded overly_permissive one.
    assert findings[0]["finding_type"] == "any_to_any_allow"
    assert findings[0]["severity"] == "Critical"
    assert findings[0]["evidence"]["any_source"] is True
    assert findings[0]["evidence"]["any_destination"] is True
    assert findings[0]["evidence"]["any_service"] is True
    _assert_quality(findings)

    assert _analyze_permissive([_rule(2, enabled=False)], {}) == []


def test_risky_service_uses_expanded_inline_vendor_service_names():
    findings = _analyze_risky_services(
        [_rule(1, sources=["10.0.0.0/24"], destinations=["10.1.0.0/24"], services=["SSH"])],
        {},
    )

    assert len(findings) == 1
    assert findings[0]["finding_type"] == "risky_service"
    assert findings[0]["evidence"]["risky_services"] == ["SSH"]
    _assert_quality(findings)

    disabled = _analyze_risky_services([_rule(2, services=["SSH"], enabled=False)], {})
    assert disabled == []


def test_duplicate_rules_require_identical_effective_traffic():
    findings = detect_duplicates([_rule(1, services=["https"]), _rule(2, services=["HTTPS"])], {})

    assert len(findings) == 1
    assert findings[0]["finding_type"] == "duplicate_rule"
    assert findings[0]["evidence"]["matching_fields"] == "source, destination, service, action"
    _assert_quality(findings)

    no_match = detect_duplicates([_rule(1, services=["https"]), _rule(2, services=["ssh"])], {})
    assert no_match == []

    disabled_match = detect_duplicates(
        [_rule(1, services=["https"]), _rule(2, services=["https"], enabled=False)],
        {},
    )
    assert disabled_match == []


def test_shadowed_rule_reports_first_enabled_shadowing_rule():
    rules = [
        _rule(1, sources=["any"], destinations=["any"], services=["any"]),
        _rule(2, sources=["10.0.0.5/32"], destinations=["any"], services=["https"]),
    ]

    findings = detect_shadows(rules, {})

    assert len(findings) == 1
    assert findings[0]["finding_type"] == "shadowed_rule"
    assert findings[0]["evidence"]["shadowed_rule"].startswith("Rule 2")
    _assert_quality(findings)


def test_unused_objects_follow_nested_vendor_group_usage_and_skip_builtins():
    objects = [
        _object("Parent", "address_group", "", ["Child"]),
        _object("Child", "address_group", "", ["UsedHost"]),
        _object("UsedHost"),
        _object("VendorDefault", raw_data={"predefined": True}),
        _object("Orphan", value="10.0.0.99/32"),
    ]
    obj_map = build_object_map(objects)
    findings = _analyze_unused_objects([_rule(1, sources=["Parent"])], objects, obj_map)

    names = {f["evidence"]["object_name"] for f in findings}
    assert names == {"Orphan"}
    _assert_quality(findings)


def test_empty_groups_include_customer_groups_and_suppress_vendor_builtins():
    objects = [
        _object("CustomerEmpty", "address_group", "", []),
        _object("VendorEmpty", "address_group", "", [], raw_data={"builtin": True}),
    ]

    findings = _analyze_empty_groups(objects)

    assert len(findings) == 1
    assert findings[0]["finding_type"] == "empty_group"
    assert findings[0]["evidence"]["object_name"] == "CustomerEmpty"
    _assert_quality(findings)
