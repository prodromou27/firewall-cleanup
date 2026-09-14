"""Duplicate values must not erase typed or vendor-specific distinctions."""
import pytest

from app.analysis.engine import _analyze_duplicate_objects


def service():
    return dict(id="a", object_name="dns-a", vendor="FortiGate",
                object_type="service", value="53", protocol="tcp",
                port_start=53, port_end=53, raw_data={})


@pytest.mark.parametrize("change", [
    {"protocol": "udp"},
    {"port_end": 54},
    {"object_type": "host"},
    {"vendor": "CheckPoint"},
    {"raw_data": {"tcp-portrange": "53:1024-65535"}},
    {"protocol": None},
    {"port_start": None},
    {"port_end": 70000},
])
def test_same_display_value_is_not_enough(change):
    first = service()
    second = {**first, "id": "b", "object_name": "dns-b", **change}
    assert _analyze_duplicate_objects([first, second]) == []


def test_equal_typed_services_ignore_only_source_location():
    first = service()
    second = {**first, "id": "b", "object_name": "dns-b"}
    first["raw_data"] = {"source_ref": {"record_index": 1}}
    second["raw_data"] = {"source_ref": {"record_index": 2}}
    findings = _analyze_duplicate_objects([first, second])
    assert len(findings) == 1
    assert findings[0]["affected_objects"] == ["a", "b"]
    assert findings[0]["evidence"]["protocol"] == "tcp"


@pytest.mark.parametrize("fields", [
    {"protocol": "icmp", "port_start": None, "port_end": None},
    {"protocol": None, "port_start": None, "port_end": None},
    {"port_start": 100, "port_end": 50},
])
def test_identically_incomplete_services_are_not_certified(fields):
    first = {**service(), **fields}
    assert _analyze_duplicate_objects([first, {**first, "id": "b"}]) == []
