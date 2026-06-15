"""End-to-end parser correctness tests for FortiGate, Check Point, and Huawei.

Each test parses a representative export, asserts the normalized rule/object
shape the analysis engine depends on, and runs a port-based detector to confirm
service analysis actually works for that vendor.
"""
import json

from app.parsers import get_parser
from app.analysis.normalizer import build_object_map
from app.analysis.engine import _analyze_exposed_services


def _svc_obj(objects, name):
    return next((o for o in objects if o["object_name"] == name), None)


# ── FortiGate ────────────────────────────────────────────────────────────────

FORTIGATE_CONF = """
config firewall address
    edit "DB-Server"
        set subnet 10.0.0.5 255.255.255.255
    next
end
config firewall service custom
    edit "RDP"
        set tcp-portrange 3389
    next
end
config firewall policy
    edit 1
        set name "allow-rdp-from-any"
        set srcintf "wan"
        set dstintf "lan"
        set srcaddr "all"
        set dstaddr "DB-Server"
        set service "RDP"
        set action accept
        set status enable
    next
end
"""


def test_fortigate_parse_and_exposure():
    rules, objects, warnings = get_parser("FortiGate").parse(FORTIGATE_CONF)
    assert len(rules) == 1
    r = rules[0]
    assert r["sources"] == ["any"]          # "all" -> "any"
    assert r["destinations"] == ["DB-Server"]
    assert r["services"] == ["RDP"]
    assert r["action"] == "accept" and r["enabled"] is True

    rdp = _svc_obj(objects, "RDP")
    assert rdp and rdp["protocol"] == "tcp" and rdp["port_start"] == 3389 and rdp["port_end"] == 3389

    findings = _analyze_exposed_services(rules, build_object_map(objects))
    assert any(f["finding_type"] == "rdp_exposed" for f in findings)


# ── Check Point ──────────────────────────────────────────────────────────────

CHECKPOINT_JSON = json.dumps({
    "rulebase": [
        {
            "type": "access-rule", "rule-number": 1, "name": "allow-rdp",
            "source": [{"name": "Any"}], "destination": [{"name": "DB-Server"}],
            "service": [{"name": "RDP"}], "action": {"name": "Accept"},
            "enabled": True, "track": {"type": {"name": "Log"}},
        }
    ],
    "objects": {
        "u1": {"type": "host", "name": "DB-Server", "ipv4-address": "10.0.0.5"},
        "u2": {"type": "service-tcp", "name": "RDP", "port": "3389"},
    },
})


def test_checkpoint_parse_and_exposure():
    rules, objects, warnings = get_parser("CheckPoint").parse(CHECKPOINT_JSON)
    assert len(rules) == 1
    r = rules[0]
    assert r["sources"] == ["Any"]
    assert r["destinations"] == ["DB-Server"]
    assert r["action"] == "accept" and r["enabled"] is True

    rdp = _svc_obj(objects, "RDP")
    assert rdp and rdp["protocol"] == "tcp" and rdp["port_start"] == 3389

    findings = _analyze_exposed_services(rules, build_object_map(objects))
    assert any(f["finding_type"] == "rdp_exposed" for f in findings)


# ── Huawei USG ───────────────────────────────────────────────────────────────

HUAWEI_CONF = """sysname HUAWEI-USG
#
ip address-set DB-Server type object
 address 0 10.0.0.5 mask 255.255.255.255
#
ip service-set RDP type object
 service 0 protocol tcp destination-port 3389
#
security-policy
 rule name allow-rdp
  source-zone untrust
  destination-zone trust
  source-address address-set Any
  destination-address address-set DB-Server
  service service-set RDP
  action permit
#
"""


def test_huawei_parse_and_exposure():
    rules, objects, warnings = get_parser("Huawei").parse(HUAWEI_CONF)
    assert len(rules) == 1
    r = rules[0]
    assert "Any" in r["sources"]
    assert "DB-Server" in r["destinations"]
    assert r["services"] == ["RDP"]
    assert r["action"] in ("accept", "permit")
    assert r["enabled"] is True

    # The core fix: the RDP service object must carry structured port data.
    rdp = _svc_obj(objects, "RDP")
    assert rdp is not None, "RDP service object missing"
    assert rdp["protocol"] == "tcp"
    assert rdp["port_start"] == 3389 and rdp["port_end"] == 3389

    # And port-based analysis must now fire for Huawei.
    findings = _analyze_exposed_services(rules, build_object_map(objects))
    assert any(f["finding_type"] == "rdp_exposed" for f in findings), \
        "Huawei service analysis did not detect RDP exposure"


def test_huawei_service_not_collapsed_to_any():
    """Regression guard: a concrete Huawei service must NOT resolve to 'any'."""
    from app.analysis.service_utils import service_is_any, normalize_service
    _, objects, _ = get_parser("Huawei").parse(HUAWEI_CONF)
    rdp = _svc_obj(objects, "RDP")
    assert not service_is_any(normalize_service(rdp))
