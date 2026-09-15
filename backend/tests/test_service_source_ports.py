import pytest
from app.analysis.normalizer import build_object_map, expand_service_object
from app.analysis.duplicate_detector import detect_duplicates
from app.analysis.shadow_detector import detect_shadows
from app.analysis.service_utils import service_contains, services_equal, services_overlap, identify_risky_service
from app.analysis.engine import _rule_to_dict
from app.models.policy import FirewallRule
from app.parsers.fortigate import FortiGateParser


def rule(index, service):
    return {"id": str(index), "rule_number": index, "action": "allow", "enabled": True,
            "sources": ["10.0.0.1"], "destinations": ["10.0.0.2"], "services": [service]}


def test_fortigate_parser_retains_all_port_terms_for_analysis():
    config = '''config firewall service custom
    edit "combined"
        set tcp-portrange 443:1024-2048 8443
        set udp-portrange 53
    next
end
'''
    _, objects, _ = FortiGateParser().parse(config)
    obj = next(o for o in objects if o["object_name"] == "combined")
    assert (obj["port_start"], obj["port_end"]) == (443, 443)
    terms = expand_service_object("combined", build_object_map(objects))
    assert [(s["protocol"], s["port_start"], s["port_end"], s["source_port_start"], s["source_port_end"])
            for s in terms] == [("tcp", 443, 443, 1024, 2048),
                                 ("tcp", 8443, 8443, 0, 65535), ("udp", 53, 53, 0, 65535)]
    assert not any(s["port_start"] <= 3389 <= s["port_end"] for s in terms)


def test_disjoint_source_ports_are_neither_duplicates_nor_shadows():
    objects = build_object_map([
        {"object_name": name, "object_type": "service", "raw_data": {"tcp-portrange": spec}}
        for name, spec in [("a", "443:1000-2000"), ("b", "443:3000-4000")]
    ])
    assert detect_duplicates([rule(1, "a"), rule(2, "b")], objects) == []
    assert detect_shadows([rule(1, "a"), rule(2, "b")], objects) == []
    a, b = expand_service_object("a", objects)[0], expand_service_object("b", objects)[0]
    assert not service_contains(a, b)
    assert not services_equal(a, b)
    assert not services_overlap(a, b)


def test_unrestricted_source_ports_can_contain_restricted_source_ports():
    general = {"protocol": "tcp", "port_start": 443, "port_end": 443}
    restricted = {**general, "source_port_start": 1024, "source_port_end": 2048}
    assert service_contains(general, restricted)
    assert not service_contains(restricted, general)
    assert services_overlap(general, restricted)


@pytest.mark.parametrize("spec", ["443:", "443:70000", "443:2000-1000", "443 bad", "invalid"])
def test_invalid_port_terms_do_not_become_any_or_risky_services(spec):
    obj_map = {"bad": {"object_type": "service", "raw_data": {"tcp-portrange": spec}}}
    service = expand_service_object("bad", obj_map)[0]
    assert service["unknown"]
    assert identify_risky_service(service) is None
    assert detect_duplicates([rule(1, "bad"), rule(2, "bad")], obj_map) == []


def test_asa_source_port_restriction_survives_orm_normalization():
    rules = [_rule_to_dict(FirewallRule(id=str(i), rule_number=i, action="allow", enabled=True,
                sources=["10.0.0.1"], destinations=["10.0.0.2"], services=["https"],
                raw_data={"src_port": str(port)})) for i, port in [(1, 1024), (2, 2048)]]
    assert rules[0]["source_port_constraint"] == "1024"
    assert detect_duplicates(rules, {}) == []
    assert detect_shadows(rules, {}) == []
