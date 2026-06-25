"""Deeper analysis regressions using realistic firewall-policy edge cases."""

from app.analysis.duplicate_detector import detect_duplicates
from app.analysis.engine import (
    _analyze_permissive,
    _analyze_risky_services,
    _analyze_unused_objects,
    _analyze_usage,
)
from app.analysis.normalizer import build_object_map, expand_rule_destinations, expand_rule_services, expand_rule_sources
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
        "comments": "change CHG-1234",
    }
    rule.update(overrides)
    return rule


def _object(name, object_type="host", value="10.0.0.1/32", members=None, **overrides):
    obj = {
        "id": f"obj-{name}",
        "vendor": "FortiGate",
        "object_name": name,
        "object_type": object_type,
        "value": value,
        "members": members or [],
        "raw_data": {},
    }
    obj.update(overrides)
    return obj


def test_object_expansion_handles_nested_groups_and_circular_references_safely():
    objects = [
        _object("HQ-Net", "network", "10.20.0.0/16"),
        _object("App-Host", "host", "10.20.10.5/32"),
        _object("Nested", "address_group", "", ["HQ-Net", "App-Host"]),
        _object("Loop-A", "address_group", "", ["Loop-B", "HQ-Net"]),
        _object("Loop-B", "address_group", "", ["Loop-A"]),
        _object("SSH-SVC", "service", "tcp/22", protocol="tcp", port_start=22, port_end=22),
        _object("Mgmt-SVC", "service_group", "", ["SSH-SVC"]),
    ]
    obj_map = build_object_map(objects)
    rule = _rule(1, sources=["Nested"], destinations=["Loop-A"], services=["Mgmt-SVC"])

    assert [item["value"] for item in expand_rule_sources(rule, obj_map)] == ["10.20.0.0/16", "10.20.10.5/32"]
    assert "10.20.0.0/16" in [item["value"] for item in expand_rule_destinations(rule, obj_map)]
    expanded_services = expand_rule_services(rule, obj_map)
    assert len(expanded_services) == 1
    assert expanded_services[0]["port_start"] == 22


def test_duplicate_detection_expands_groups_without_flagging_distinct_services():
    objects = [
        _object("Branch-Net", "network", "10.30.0.0/24"),
        _object("Branch-Group", "address_group", "", ["Branch-Net"]),
        _object("Web-01", "host", "10.40.0.10/32"),
        _object("HTTPS", "service", "tcp/443", protocol="tcp", port_start=443, port_end=443),
        _object("SSH", "service", "tcp/22", protocol="tcp", port_start=22, port_end=22),
    ]
    obj_map = build_object_map(objects)

    duplicates = detect_duplicates([
        _rule(1, ["Branch-Group"], ["Web-01"], ["HTTPS"]),
        _rule(2, ["Branch-Net"], ["Web-01"], ["HTTPS"]),
    ], obj_map)
    assert len(duplicates) == 1

    no_duplicate = detect_duplicates([
        _rule(1, ["Branch-Group"], ["Web-01"], ["HTTPS"]),
        _rule(2, ["Branch-Net"], ["Web-01"], ["SSH"]),
    ], obj_map)
    assert no_duplicate == []


def test_shadow_detection_respects_rule_order_and_does_not_shadow_prior_rules():
    obj_map = build_object_map([
        _object("Corp-Net", "network", "10.0.0.0/8"),
        _object("Admin-Host", "host", "10.1.1.10/32"),
        _object("Server", "host", "172.16.0.10/32"),
        _object("Any-TCP", "service", "tcp/1-65535", protocol="tcp", port_start=1, port_end=65535),
        _object("SSH", "service", "tcp/22", protocol="tcp", port_start=22, port_end=22),
    ])

    findings = detect_shadows([
        _rule(1, ["Admin-Host"], ["Server"], ["SSH"]),
        _rule(2, ["Corp-Net"], ["Server"], ["Any-TCP"]),
    ], obj_map)
    assert findings == []

    findings = detect_shadows([
        _rule(1, ["Corp-Net"], ["Server"], ["Any-TCP"]),
        _rule(2, ["Admin-Host"], ["Server"], ["SSH"]),
    ], obj_map)
    assert len(findings) == 1
    assert findings[0]["evidence"]["shadowing_rule"].startswith("Rule 1")


def test_unused_object_detection_counts_direct_and_indirect_group_references_only():
    objects = [
        _object("Direct-Host"),
        _object("Indirect-Host", value="10.0.0.2/32"),
        _object("Used-Group", "address_group", "", ["Indirect-Host"]),
        _object("Builtin-Service", "service", "tcp/443", raw_data={"predefined": True}),
        _object("Unused-Host", value="10.0.0.99/32"),
    ]
    findings = _analyze_unused_objects(
        [_rule(1, sources=["Direct-Host", "Used-Group"], destinations=["any"], services=["any"])],
        objects,
        build_object_map(objects),
    )

    assert set(findings[0]["evidence"]["sample"]) == {"Unused-Host"}


def test_risky_permissive_and_zero_hit_detections_avoid_common_false_positives():
    obj_map = build_object_map([
        _object("Admin-Net", "network", "10.10.10.0/24"),
        _object("Firewall", "host", "10.20.20.1/32"),
        _object("SSH", "service", "tcp/22", protocol="tcp", port_start=22, port_end=22),
    ])
    scoped_admin_rule = _rule(1, ["Admin-Net"], ["Firewall"], ["SSH"], hit_count=5)

    risky = _analyze_risky_services([scoped_admin_rule], obj_map)
    assert len(risky) == 1
    assert risky[0]["evidence"]["risky_services"] == ["SSH"]

    assert _analyze_permissive([scoped_admin_rule], obj_map) == []
    assert _analyze_usage([_rule(2, hit_count=None)], obj_map) == []
    zero_hit = _analyze_usage([_rule(3, hit_count=0)], obj_map)
    assert len(zero_hit) == 1
    assert zero_hit[0]["finding_type"] == "zero_hit_rule"
