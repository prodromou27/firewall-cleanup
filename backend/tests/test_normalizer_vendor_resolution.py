"""Regression tests for vendor-specific object and inline service normalization."""
from app.analysis.engine import _analyze_exposed_services
from app.analysis.normalizer import (
    build_object_map,
    expand_address_object,
    expand_service_object,
)
from app.analysis.service_utils import identify_risky_service, service_contains, service_is_any


def test_address_group_like_types_expand_for_supported_vendors():
    objects = build_object_map([
        {"object_name": "DB1", "object_type": "host", "value": "10.0.0.5"},
        {"object_name": "PA-GRP", "object_type": "address_group", "members": ["DB1"]},
        {"object_name": "ASA-GRP", "object_type": "network_group", "members": ["DB1"]},
        {"object_name": "HW-GRP", "object_type": "address-set-group", "members": ["DB1"]},
    ])

    for name in ("PA-GRP", "ASA-GRP", "HW-GRP"):
        expanded = expand_address_object(name, objects)
        assert expanded == [{"type": "host", "value": "10.0.0.5", "name": "DB1"}]


def test_inline_vendor_services_resolve_to_structured_ports():
    assert expand_service_object("tcp/3389", {})[0]["port_start"] == 3389
    assert expand_service_object("tcp_1433", {})[0]["port_start"] == 1433
    assert expand_service_object("RDP", {})[0]["port_start"] == 3389
    assert expand_service_object("service-http", {})[0] == {
        "protocol": "tcp",
        "port_start": 80,
        "port_end": 80,
        "name": "service-http",
    }
    assert expand_service_object("www", {})[0]["port_start"] == 80
    assert expand_service_object("80", {})[0]["port_start"] == 80


def test_opaque_predefined_services_do_not_create_port_findings():
    svc = expand_service_object("application-default", {})[0]
    assert svc["opaque"] is True
    assert not svc.get("unknown")
    assert not service_is_any(svc)
    assert identify_risky_service(svc) is None
    assert service_contains(svc, {"protocol": "tcp", "port_start": 3389, "port_end": 3389}) is False


def test_inline_cisco_asa_rdp_service_is_detected_as_exposed():
    rule = {
        "id": "r1",
        "rule_id": "1",
        "enabled": True,
        "action": "permit",
        "sources": ["any"],
        "destinations": ["10.0.0.5"],
        "services": ["tcp/3389"],
    }

    findings = _analyze_exposed_services([rule], {})
    assert len(findings) == 1
    assert findings[0]["finding_type"] == "rdp_exposed"
    assert findings[0]["severity"] == "Critical"
