"""FortiGate parser regressions — Virtual IP (destination NAT) handling."""

from app.parsers.fortigate import FortiGateParser
from app.analysis.normalizer import build_object_map, expand_rule_destinations


FGT_CONFIG = """
config firewall address
    edit "WebSrv-Internal"
        set subnet 10.10.0.10 255.255.255.255
    next
end
config firewall vip
    edit "WebSrv-VIP"
        set extip 203.0.113.10
        set extintf "wan1"
        set portforward enable
        set mappedip "10.10.0.10"
        set protocol tcp
        set extport 443
        set mappedport 8443
        set comment "Public web entry"
    next
    edit "RangeVIP"
        set extip 203.0.113.20-203.0.113.22
        set mappedip "10.10.0.20"
    next
end
config firewall policy
    edit 1
        set name "Inbound-Web"
        set srcintf "wan1"
        set dstintf "lan"
        set srcaddr "all"
        set dstaddr "WebSrv-VIP"
        set service "HTTPS"
        set action accept
        set status enable
    next
end
"""


def _parse():
    rules, objects, warnings = FortiGateParser().parse(FGT_CONFIG)
    return rules, objects, warnings


def test_vip_parsed_as_destination_nat_object():
    _, objects, _ = _parse()
    vips = {o["object_name"]: o for o in objects if o["object_type"] == "vip"}

    assert set(vips) == {"WebSrv-VIP", "RangeVIP"}

    web = vips["WebSrv-VIP"]
    # Value is the external (pre-NAT, matched) IP, not the internal target.
    assert web["value"] == "203.0.113.10"
    assert web["nat_type"] == "destination"
    assert web["mapped_ip"] == "10.10.0.10"
    assert web["external_port"] == "443"
    assert web["mapped_port"] == "8443"
    assert web["external_interface"] == "wan1"
    # DNAT details also survive on raw_data (the DB-persisted channel).
    assert web["raw_data"]["mappedip"] == "10.10.0.10"


def test_vip_port_forward_disabled_has_no_ports():
    _, objects, _ = _parse()
    rng = next(o for o in objects if o["object_name"] == "RangeVIP")
    assert rng["value"] == "203.0.113.20-203.0.113.22"
    assert rng["external_port"] == ""   # portforward not enabled
    assert rng["mapped_ip"] == "10.10.0.20"


def test_policy_destination_resolves_vip_to_external_ip_not_unknown():
    """A policy whose destination is a VIP must resolve to the concrete external
    IP for overlap/exposure analysis — never an 'unknown' object."""
    rules, objects, _ = _parse()
    obj_map = build_object_map(objects)

    rule = next(r for r in rules if r["rule_name"] == "Inbound-Web")
    dests = expand_rule_destinations(rule, obj_map)

    types = {d["type"] for d in dests}
    values = {d["value"] for d in dests}
    assert "unknown" not in types
    assert values == {"203.0.113.10"}
