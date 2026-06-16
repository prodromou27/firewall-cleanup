"""Unit tests for the inbound-from-internet exposure detector (NIST 800-41 / PCI)."""
from app.analysis.engine import _analyze_inbound_exposure
from app.analysis.normalizer import build_object_map


def _objs():
    return [
        {"object_name": "Internal-Host", "object_type": "host", "value": "10.0.0.5"},
        {"object_name": "Internal-Net", "object_type": "network", "value": "10.1.0.0/24"},
        {"object_name": "Public-Host", "object_type": "host", "value": "8.8.8.8"},
        {"object_name": "Partner-Net", "object_type": "network", "value": "203.0.113.0/24"},
        {"object_name": "Web", "object_type": "service", "protocol": "tcp", "port_start": 443, "port_end": 443},
    ]


def _rule(rid, sources, dests, services, action="accept", enabled=True):
    return {
        "id": f"rule-{rid}", "rule_id": str(rid), "rule_number": rid,
        "sources": sources, "destinations": dests, "services": services,
        "action": action, "enabled": enabled,
    }


def test_any_source_to_internal_specific_service_is_high():
    om = build_object_map(_objs())
    f = _analyze_inbound_exposure([_rule(1, ["any"], ["Internal-Host"], ["Web"])], om)
    assert len(f) == 1
    assert f[0]["finding_type"] == "inbound_from_internet"
    assert f[0]["severity"] == "High"


def test_any_source_to_internal_any_service_is_critical():
    om = build_object_map(_objs())
    f = _analyze_inbound_exposure([_rule(2, ["any"], ["Internal-Net"], ["any"])], om)
    assert len(f) == 1
    assert f[0]["severity"] == "Critical"


def test_public_source_to_internal_flagged():
    om = build_object_map(_objs())
    f = _analyze_inbound_exposure([_rule(3, ["8.8.8.8"], ["Internal-Host"], ["Web"])], om)
    assert len(f) == 1
    assert f[0]["evidence"]["exposure"] == "public"


def test_internal_source_not_flagged():
    om = build_object_map(_objs())
    # internal -> internal is lateral movement's job, not inbound exposure.
    assert _analyze_inbound_exposure([_rule(4, ["Internal-Net"], ["Internal-Host"], ["Web"])], om) == []


def test_untrusted_to_public_dest_not_flagged():
    om = build_object_map(_objs())
    # No internal destination -> not an inbound-to-internal exposure.
    assert _analyze_inbound_exposure([_rule(5, ["any"], ["Public-Host"], ["Web"])], om) == []


def test_deny_and_disabled_not_flagged():
    om = build_object_map(_objs())
    assert _analyze_inbound_exposure([_rule(6, ["any"], ["Internal-Host"], ["Web"], action="deny")], om) == []
    assert _analyze_inbound_exposure([_rule(7, ["any"], ["Internal-Host"], ["Web"], enabled=False)], om) == []
