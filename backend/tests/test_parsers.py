"""End-to-end parser correctness tests for supported firewall vendors.

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


# Cisco ASA

CISCO_ASA_CONF = """
ASA Version 9.16
object network DB-Server
 host 10.0.0.5
object-group service RDP-GROUP tcp
 port-object eq 3389
access-group OUTSIDE in interface outside
access-list OUTSIDE extended permit tcp any object DB-Server eq 3389 log (hitcnt=12)
"""


def test_cisco_asa_parse_and_exposure():
    rules, objects, warnings = get_parser("CiscoASA").parse(CISCO_ASA_CONF)
    assert len(rules) == 1
    r = rules[0]
    assert r["sources"] == ["any"]
    assert r["destinations"] == ["DB-Server"]
    assert r["services"] == ["tcp/3389"]
    assert r["hit_count"] == 12
    assert r["source_interfaces"] == ["outside"]
    assert r["raw_data"]["raw"].startswith("access-list OUTSIDE")

    db = next((o for o in objects if o["object_name"] == "DB-Server"), None)
    assert db and db["raw_data"]["raw_lines"][0] == "object network DB-Server"

    findings = _analyze_exposed_services(rules, build_object_map(objects))
    assert any(f["finding_type"] == "rdp_exposed" for f in findings)


# Palo Alto

PALO_ALTO_XML = """
<config>
  <devices>
    <entry name="localhost.localdomain">
      <vsys>
        <entry name="vsys1">
          <address>
            <entry name="DB-Server">
              <ip-netmask>10.0.0.5/32</ip-netmask>
            </entry>
          </address>
          <service>
            <entry name="RDP">
              <protocol><tcp><port>3389</port></tcp></protocol>
            </entry>
          </service>
          <rulebase>
            <security>
              <rules>
                <entry name="allow-rdp">
                  <from><member>untrust</member></from>
                  <to><member>trust</member></to>
                  <source><member>any</member></source>
                  <destination><member>DB-Server</member></destination>
                  <service><member>RDP</member></service>
                  <application><member>any</member></application>
                  <action>allow</action>
                  <log-end>yes</log-end>
                </entry>
              </rules>
            </security>
          </rulebase>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>
"""


def test_paloalto_parse_and_exposure():
    rules, objects, warnings = get_parser("PaloAlto").parse(PALO_ALTO_XML)
    assert len(rules) == 1
    r = rules[0]
    assert r["sources"] == ["any"]
    assert r["destinations"] == ["DB-Server"]
    assert r["services"] == ["RDP"]
    assert r["action"] == "accept"
    assert "xml" in r["raw_data"]

    rdp = _svc_obj(objects, "RDP")
    assert rdp and rdp["protocol"] == "tcp" and rdp["port_start"] == 3389
    assert "xml" in rdp["raw_data"]

    findings = _analyze_exposed_services(rules, build_object_map(objects))
    assert any(f["finding_type"] == "rdp_exposed" for f in findings)


def test_all_vendor_parsers_tolerate_malformed_input():
    for vendor in ("FortiGate", "CheckPoint", "Huawei", "CiscoASA", "PaloAlto"):
        rules, objects, warnings = get_parser(vendor).parse("this is not a valid firewall export {{{")
        assert isinstance(rules, list)
        assert isinstance(objects, list)
        assert isinstance(warnings, list)
        assert warnings, f"{vendor} should explain why malformed input was not useful"


def test_parser_warnings_include_circular_group_references():
    conf = """
config firewall addrgrp
    edit "Group-A"
        set member "Group-B"
    next
    edit "Group-B"
        set member "Group-A"
    next
end
config firewall policy
    edit 1
        set srcaddr "Group-A"
        set dstaddr "all"
        set service "ALL"
        set action accept
    next
end
"""
    rules, objects, warnings = get_parser("FortiGate").parse(conf)
    assert len(rules) == 1
    assert any("circular group reference" in w.lower() for w in warnings)
    assert all(isinstance(o.get("raw_data"), dict) for o in objects)
