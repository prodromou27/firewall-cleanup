import json
import pytest
from app.parsers.checkpoint import CheckPointParser
from app.connectors.live_sync import _cp_translate, _cp_action_norm, _write_to_db
from app.analysis.engine import _rule_to_dict, _analyze_inoperative_rules, _is_vendor_builtin_object
from app.analysis.normalizer import build_object_map, expand_rule_sources, expand_service_object
from app.analysis.duplicate_detector import detect_duplicates
from app.analysis.vendor_semantics import context_key


def test_export_dictionary_resolves_actions_and_members_and_keeps_negation():
    data = {"uid": "layer-a", "objects-dictionary": [
        {"uid": "accept", "name": "Accept", "type": "RulebaseAction"},
        {"uid": "host", "name": "Server", "type": "host", "ipv4-address": "10.0.0.1"},
        {"uid": "group", "name": "Servers", "type": "group", "members": [{"uid": "host"}]},
    ], "rulebase": [{"type": "access-rule", "uid": "r1", "action": "accept",
                     "source": ["group"], "destination": ["Any"], "service": ["Any"],
                     "source-negate": True}]}
    rules, objects, _ = CheckPointParser().parse(json.dumps(data))
    assert rules[0]["action"] == "accept"
    assert rules[0]["sources"] == ["Servers"]
    assert rules[0]["raw_data"]["negated"] is True
    assert rules[0]["raw_data"]["_layer"] == "layer-a"
    assert expand_rule_sources(rules[0], build_object_map(objects))[0]["type"] == "unknown"
    positive = {**rules[0], "negated": False, "negate_fields": []}
    assert expand_rule_sources(positive, build_object_map(objects))[0]["value"] == "10.0.0.1"


def test_exclusion_group_is_not_an_empty_service_group():
    parser = CheckPointParser()
    obj = parser._normalize_object({"type": "group-with-exclusion", "uid": "g", "name": "Except",
                                    "include": {"uid": "all-hosts"}, "except": {"uid": "excluded"}})
    assert obj["object_type"] == "group-with-exclusion"
    assert obj["members"] == ["all-hosts", "excluded"]
    rule = {"id": "r", "enabled": True, "sources": ["Except"], "destinations": ["Any"]}
    assert _analyze_inoperative_rules([rule], build_object_map([obj])) == []


def test_checkpoint_port_unions_and_source_ports_are_preserved():
    obj = CheckPointParser()._normalize_object({"type": "service-tcp", "uid": "s", "name": "Web",
                                               "port": "80,443", "source-port": "1024-2048"})
    terms = expand_service_object("Web", build_object_map([obj]))
    assert (obj["port_start"], obj["port_end"]) == (80, 80)
    assert [t["port_start"] for t in terms] == [80, 443]
    assert all(t["source_port_start"] == 1024 and t["source_port_end"] == 2048 for t in terms)


@pytest.mark.parametrize("port", ["invalid", "70000", "200-100"])
def test_invalid_checkpoint_ports_remain_unknown(port):
    raw = {"type": "service-tcp", "uid": "s", "name": "Broken", "port": port}
    obj = CheckPointParser()._normalize_object(raw)
    assert obj["port_start"] is None and obj["port_end"] is None
    assert expand_service_object("Broken", build_object_map([obj]))[0]["unknown"]
    live = _cp_translate({"objects": [raw]})
    assert live["objects"]["Broken"]["port_start"] is None


@pytest.mark.parametrize("action", ["inline-layer", "Apply Layer", "unknown", "action-uid", "Ask"])
def test_unknown_or_layer_actions_do_not_become_accept(action):
    assert _cp_action_norm({"name": action}) not in ("accept", "deny")


def test_layer_identity_is_independent_of_display_section():
    assert context_key({"evaluation_layer": "L1", "section": "A"}, "CheckPoint") == context_key(
        {"evaluation_layer": "L1", "section": "B"}, "CheckPoint")
    assert context_key({"evaluation_layer": "L1", "section": "A"}, "CheckPoint") != context_key(
        {"evaluation_layer": "L2", "section": "A"}, "CheckPoint")


def test_zero_mask_remains_default_route():
    obj = CheckPointParser()._normalize_object({"type": "network", "name": "Default", "subnet4": "0.0.0.0", "mask-length4": 0})
    assert obj["value"] == "0.0.0.0/0"


def test_missing_match_fields_are_not_filled_with_any():
    rules, _, _ = CheckPointParser().parse(json.dumps({"rulebase": [{"type": "access-rule", "action": "Accept"}]}))
    assert rules[0]["sources"] == []
    assert rules[0]["destinations"] == []
    assert rules[0]["services"] == []


def test_dictionary_objects_from_later_pages_are_preserved():
    from app.connectors.checkpoint import CheckPointConnector
    connector = CheckPointConnector.__new__(CheckPointConnector)
    def page(layer, offset, extra):
        return {"total": 501, "rulebase": [], "objects-dictionary": [
            {"uid": f"object-{offset}", "name": f"Object{offset}", "type": "host"}]}
    connector._get_rulebase_page = page
    _, objects = connector.get_access_rulebase("Layer", include_hits=False)
    assert len(objects) == 2
    assert len({o["uid"] for o in objects}) == 2


def test_nested_inline_export_is_tagged_unresolved():
    data = {"rulebase": [{"type": "access-section", "name": "Section", "rulebase": [
        {"type": "access-rule", "rule-number": 1, "inline-layer": "child", "rulebase": [
            {"type": "access-rule", "rule-number": "1.1", "source": ["Any"], "action": "Accept"}]}]}]}
    rules, _, warnings = CheckPointParser().parse(json.dumps(data))
    assert len(rules) == 2
    assert rules[0]["action"] == "inline-layer"
    assert rules[1]["raw_data"]["_inline_parent_unmodeled"]
    assert warnings


def test_live_translation_and_persistence_keep_enforcement_metadata():
    import app.models
    from app.database import Base
    from app.models.customer import Customer
    from app.models.policy import FirewallPolicy, FirewallRule
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    raw = {"rules": [{"uid": "r1", "_layer": "Layer1", "_section": "Display", "action": "Accept",
                      "source": ["Any"], "destination": ["Any"], "service": ["Any"],
                      "source-negate": "false", "install-on": [{"name": "GW1"}],
                      "vpn": [{"name": "VPN1"}], "users": [{"name": "User1"}],
                      "_inline_parent_unmodeled": True}], "objects": [
                          {"name": "BuiltIn", "type": "group", "members": [],
                           "domain": {"name": "Check Point"}}]}
    translated = _cp_translate(raw)
    assert translated["rules"][0]["negated"] is False
    assert "BuiltIn" in translated["objects"]
    assert _is_vendor_builtin_object({"object_name": "BuiltIn", "raw_data": raw["objects"][0]})
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add(Customer(id="c", name="Customer"))
        policy = FirewallPolicy(id="p", customer_id="c", vendor="CheckPoint", firewall_name="FW")
        db.add(policy)
        db.commit()
        _write_to_db(translated, policy, db)
        rule = _rule_to_dict(db.query(FirewallRule).one())
        assert rule["install_on"] == ["GW1"]
        assert rule["vpn"] == ["VPN1"]
        assert rule["users"] == ["User1"]
        assert rule["evaluation_layer"] == "Layer1"
        assert rule["rule_id"] == "r1"
        assert rule["scope_unresolved"] is True
        assert expand_rule_sources(rule, {})[0]["type"] == "unknown"
    engine.dispose()
