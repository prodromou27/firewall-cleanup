"""Unit tests for the exposed-service and cleartext-protocol detectors."""
from app.analysis.engine import _analyze_exposed_services, _analyze_cleartext_services
from app.analysis.normalizer import build_object_map


def _objs():
    return [
        {"object_name": "RDP", "object_type": "service", "protocol": "tcp", "port_start": 3389, "port_end": 3389},
        {"object_name": "SSH", "object_type": "service", "protocol": "tcp", "port_start": 22, "port_end": 22},
        {"object_name": "MSSQL", "object_type": "service", "protocol": "tcp", "port_start": 1433, "port_end": 1433},
        {"object_name": "HTTPS", "object_type": "service", "protocol": "tcp", "port_start": 443, "port_end": 443},
        {"object_name": "Telnet", "object_type": "service", "protocol": "tcp", "port_start": 23, "port_end": 23},
        {"object_name": "DB", "object_type": "host", "value": "10.0.0.5"},
    ]


def _rule(rid, sources, services, action="accept", enabled=True):
    return {
        "id": f"rule-{rid}", "rule_id": str(rid), "action": action, "enabled": enabled,
        "sources": sources, "destinations": ["DB"], "services": services,
    }


# ── Exposed services ─────────────────────────────────────────────────────────

def test_rdp_from_any_is_critical():
    om = build_object_map(_objs())
    findings = _analyze_exposed_services([_rule(1, ["any"], ["RDP"])], om)
    assert len(findings) == 1
    assert findings[0]["finding_type"] == "rdp_exposed"
    assert findings[0]["severity"] == "Critical"


def test_database_from_public_is_high():
    om = build_object_map(_objs())
    findings = _analyze_exposed_services([_rule(2, ["1.2.3.4"], ["MSSQL"])], om)
    assert len(findings) == 1
    assert findings[0]["finding_type"] == "database_exposed"
    assert findings[0]["severity"] == "High"


def test_ssh_from_any_is_high_not_critical():
    om = build_object_map(_objs())
    findings = _analyze_exposed_services([_rule(3, ["any"], ["SSH"])], om)
    assert len(findings) == 1
    assert findings[0]["finding_type"] == "ssh_exposed"
    assert findings[0]["severity"] == "High"


def test_internal_source_not_flagged():
    om = build_object_map(_objs())
    findings = _analyze_exposed_services([_rule(4, ["10.0.0.0/8"], ["RDP"])], om)
    assert findings == []


def test_non_sensitive_service_not_flagged():
    om = build_object_map(_objs())
    findings = _analyze_exposed_services([_rule(5, ["any"], ["HTTPS"])], om)
    assert findings == []


def test_disabled_rule_not_flagged():
    om = build_object_map(_objs())
    findings = _analyze_exposed_services([_rule(6, ["any"], ["RDP"], enabled=False)], om)
    assert findings == []


def test_deny_rule_not_flagged():
    om = build_object_map(_objs())
    findings = _analyze_exposed_services([_rule(7, ["any"], ["RDP"], action="deny")], om)
    assert findings == []


# ── Cleartext protocols ──────────────────────────────────────────────────────

def test_telnet_from_any_is_high():
    om = build_object_map(_objs())
    findings = _analyze_cleartext_services([_rule(8, ["any"], ["Telnet"])], om)
    assert len(findings) == 1
    assert findings[0]["finding_type"] == "cleartext_service"
    assert findings[0]["severity"] == "High"


def test_cleartext_internal_is_medium():
    om = build_object_map(_objs())
    findings = _analyze_cleartext_services([_rule(9, ["10.0.0.0/8"], ["Telnet"])], om)
    assert len(findings) == 1
    assert findings[0]["severity"] == "Medium"


def test_encrypted_service_not_flagged_as_cleartext():
    om = build_object_map(_objs())
    findings = _analyze_cleartext_services([_rule(10, ["any"], ["SSH"])], om)
    assert findings == []


# ── Any-service rules must not fabricate specific-service exposures ──────────

def test_any_service_rule_not_flagged_as_exposed():
    """any/any/any breadth is reported by any_to_any_allow / overly_permissive;
    claiming it 'exposes RDP/SSH/databases' is a false positive."""
    om = build_object_map(_objs())
    findings = _analyze_exposed_services([_rule(11, ["any"], ["any"])], om)
    assert findings == []


def test_any_service_rule_not_flagged_as_cleartext():
    om = build_object_map(_objs())
    findings = _analyze_cleartext_services([_rule(12, ["any"], ["any"])], om)
    assert findings == []
