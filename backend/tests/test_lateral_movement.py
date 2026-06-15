"""Unit tests for the lateral-movement (broad internal east-west) detector."""
from app.analysis.engine import _analyze_lateral_movement
from app.analysis.normalizer import build_object_map


def _objs():
    return [
        {"object_name": "Corp-8", "object_type": "network", "value": "10.0.0.0/8"},
        {"object_name": "Site-16", "object_type": "network", "value": "172.16.0.0/16"},
        {"object_name": "Host", "object_type": "host", "value": "10.1.2.3"},
        {"object_name": "DMZ-24", "object_type": "network", "value": "192.168.10.0/24"},
        {"object_name": "Web", "object_type": "service", "protocol": "tcp", "port_start": 443, "port_end": 443},
        {"object_name": "AnySvc", "object_type": "service", "protocol": "any", "port_start": 0, "port_end": 65535},
    ]


def _rule(rid, sources, dests, services, action="accept", enabled=True):
    return {
        "id": f"rule-{rid}", "rule_id": str(rid), "rule_number": rid,
        "sources": sources, "destinations": dests, "services": services,
        "action": action, "enabled": enabled,
    }


def test_broad_internal_to_broad_internal_flagged():
    om = build_object_map(_objs())
    findings = _analyze_lateral_movement([_rule(1, ["Corp-8"], ["Site-16"], ["Web"])], om)
    assert len(findings) == 1
    assert findings[0]["finding_type"] == "lateral_movement_risk"
    assert findings[0]["severity"] == "Medium"


def test_any_service_raises_to_high():
    om = build_object_map(_objs())
    findings = _analyze_lateral_movement([_rule(2, ["Corp-8"], ["Site-16"], ["AnySvc"])], om)
    assert len(findings) == 1
    assert findings[0]["severity"] == "High"


def test_narrow_source_not_flagged():
    om = build_object_map(_objs())
    # Single host source is not a broad segment.
    assert _analyze_lateral_movement([_rule(3, ["Host"], ["Site-16"], ["Web"])], om) == []


def test_narrow_subnet_not_broad():
    om = build_object_map(_objs())
    # /24 destination is below the broad threshold.
    assert _analyze_lateral_movement([_rule(4, ["Corp-8"], ["DMZ-24"], ["Web"])], om) == []


def test_any_source_handled_elsewhere_not_here():
    om = build_object_map(_objs())
    # 'any' is public/0.0.0.0/0 -> not an internal segment; overly_permissive owns it.
    assert _analyze_lateral_movement([_rule(5, ["any"], ["Site-16"], ["Web"])], om) == []


def test_deny_rule_not_flagged():
    om = build_object_map(_objs())
    assert _analyze_lateral_movement([_rule(6, ["Corp-8"], ["Site-16"], ["Web"], action="deny")], om) == []


def test_disabled_rule_not_flagged():
    om = build_object_map(_objs())
    assert _analyze_lateral_movement([_rule(7, ["Corp-8"], ["Site-16"], ["Web"], enabled=False)], om) == []
