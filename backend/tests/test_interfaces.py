"""Slice 4: interface classification + public-IP inventory (read-only)."""
from app.analysis import interfaces as IF


def test_public_interface_detected():
    c = IF.classify_interface({"name": "wan1", "ip": "8.8.8.8", "mask": "/30"})
    assert c["has_public_ip"] and c["wan_facing"]


def test_private_interface_not_public():
    c = IF.classify_interface({"name": "lan", "ip": "10.0.0.1", "mask": "/24"})
    assert not c["has_public_ip"]


def test_wan_facing_by_name_without_public_ip():
    # unnumbered/zone-named WAN still flagged wan_facing by hint
    c = IF.classify_interface({"name": "untrust", "ip": "", "zone": "untrust"})
    assert c["wan_facing"]


def test_inventory_from_interfaces_nat_objects():
    interfaces = [{"name": "wan1", "ip": "8.8.8.8"}, {"name": "lan", "ip": "10.0.0.1"}]
    nat = [{"rule_number": 1, "nat_type": "destination", "original_dst": ["1.1.1.1"],
            "translated_dst": ["10.0.0.5"], "translated_service": ["tcp/443"]}]
    objects = {"pub-obj": {"value": "9.9.9.9"}, "priv-obj": {"value": "10.1.1.1"}}
    inv = IF.build_public_ip_inventory(interfaces, nat, objects, "FW1")
    by_type = {i["source_type"] for i in inv}
    assert by_type == {"interface", "nat", "object"}
    ips = {i["public_ip"] for i in inv}
    assert ips == {"8.8.8.8", "1.1.1.1", "9.9.9.9"}
    nat_item = [i for i in inv if i["source_type"] == "nat"][0]
    assert nat_item["mapped_internal"] == "10.0.0.5"


def test_no_interfaces_degrades_gracefully():
    res = IF.analyze([], None, {}, "FW1")
    assert res["interfaces_available"] is False
    assert res["public_interfaces"] == []
    assert res["public_ip_inventory"] == []
    assert res["findings"] == []


def test_mgmt_on_public_interface_is_critical():
    res = IF.analyze([{"name": "wan1", "ip": "8.8.8.8", "mgmt": True}], None, {}, "FW1")
    f = [x for x in res["findings"] if x["finding_type"] == "mgmt_on_public_interface"]
    assert f and f[0]["severity"] == "Critical"


def test_mgmt_on_private_interface_not_flagged():
    res = IF.analyze([{"name": "lan", "ip": "10.0.0.1", "mgmt": True}], None, {}, "FW1")
    assert not [x for x in res["findings"] if x["finding_type"] == "mgmt_on_public_interface"]
