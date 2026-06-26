"""Accuracy regressions for the PolicyInsight findings engine."""

from app.analysis.duplicate_detector import detect_duplicates
from app.analysis.engine import (
    _analyze_empty_groups,
    _analyze_exposed_services,
    _analyze_inoperative_rules,
    _analyze_permissive,
    _analyze_risky_services,
    _analyze_service_ranges,
    _consolidate_findings,
    _analyze_unused_objects,
    _analyze_usage,
    _obj_to_dict,
    _rule_to_dict,
)
from app.analysis.normalizer import build_object_map
from app.analysis.shadow_detector import detect_shadows


def _unused_names(findings):
    """Unused objects are now reported as a single aggregate finding whose
    evidence['sample'] lists the object names."""
    return set(findings[0]["evidence"]["sample"]) if findings else set()


def _rule(n, sources=None, destinations=None, services=None, **overrides):
    rule = {
        "id": f"rule-{n}",
        "rule_id": str(n),
        "rule_number": n,
        "rule_name": f"Rule {n}",
        "sources": sources or ["any"],
        "destinations": destinations or ["any"],
        "services": services or ["any"],
        "action": "accept",
        "enabled": True,
        "hit_count": None,
        "last_hit": None,
    }
    rule.update(overrides)
    return rule


def _object(name, object_type="host", value="10.0.0.1/32", members=None, **overrides):
    obj = {
        "id": f"obj-{name}",
        "vendor": "PaloAlto",
        "object_name": name,
        "object_type": object_type,
        "value": value,
        "members": members or [],
        "raw_data": {},
    }
    obj.update(overrides)
    return obj


def _assert_quality(findings):
    assert findings
    for finding in findings:
        assert finding["severity"]
        assert finding["confidence"]
        assert isinstance(finding["evidence"], dict)
        assert finding["recommendation"]


def test_zero_hit_requires_hit_count_data():
    assert _analyze_usage([_rule(1, hit_count=None)], {}) == []

    findings = _analyze_usage([_rule(2, hit_count=0)], {})

    assert len(findings) == 1
    assert findings[0]["finding_type"] == "zero_hit_rule"
    assert findings[0]["evidence"]["hit_count"] == 0
    _assert_quality(findings)


def test_usage_observation_window_recorded_in_evidence():
    findings = _analyze_usage([_rule(2, hit_count=0)], {})
    assert findings[0]["evidence"]["observation_days"]  # window surfaced


def test_min_age_suppresses_usage_findings_for_new_policy():
    # A policy observed for fewer days than the minimum age → usage suppressed.
    assert _analyze_usage([_rule(1, hit_count=0)], {}, policy_age_days=1) == []
    # An old-enough policy still produces the zero-hit finding.
    assert _analyze_usage([_rule(1, hit_count=0)], {}, policy_age_days=400)


def test_low_hit_threshold_is_opt_in(monkeypatch):
    from app.config import settings
    # Disabled by default → a 3-hit rule is not flagged.
    assert _analyze_usage([_rule(1, hit_count=3)], {}) == []
    # Enable the threshold → 0 < hits <= threshold is a low-usage finding.
    monkeypatch.setattr(settings, "low_hit_threshold", 5)
    findings = _analyze_usage([_rule(1, hit_count=3)], {})
    assert len(findings) == 1
    assert findings[0]["finding_type"] == "low_usage_rule"
    assert findings[0]["evidence"]["hit_count"] == 3
    # Above the threshold → not flagged.
    assert _analyze_usage([_rule(2, hit_count=9)], {}) == []


def test_overly_permissive_rule_reports_evidence_and_recommendation():
    findings = _analyze_permissive([_rule(1)], {})

    assert len(findings) == 1
    # A fully any/any/any allow is now reported as the dedicated Critical
    # any-to-any finding rather than the graded overly_permissive one.
    assert findings[0]["finding_type"] == "any_to_any_allow"
    assert findings[0]["severity"] == "Critical"
    assert findings[0]["evidence"]["any_source"] is True
    assert findings[0]["evidence"]["any_destination"] is True
    assert findings[0]["evidence"]["any_service"] is True
    _assert_quality(findings)

    assert _analyze_permissive([_rule(2, enabled=False)], {}) == []


def test_risky_service_uses_expanded_inline_vendor_service_names():
    findings = _analyze_risky_services(
        [_rule(1, sources=["10.0.0.0/24"], destinations=["10.1.0.0/24"], services=["SSH"])],
        {},
    )

    assert len(findings) == 1
    assert findings[0]["finding_type"] == "risky_service"
    assert findings[0]["evidence"]["risky_services"] == ["SSH"]
    _assert_quality(findings)

    disabled = _analyze_risky_services([_rule(2, services=["SSH"], enabled=False)], {})
    assert disabled == []


def test_duplicate_rules_require_identical_effective_traffic():
    findings = detect_duplicates([_rule(1, services=["https"]), _rule(2, services=["HTTPS"])], {})

    assert len(findings) == 1
    assert findings[0]["finding_type"] == "duplicate_rule"
    assert findings[0]["evidence"]["matching_fields"] == "source, destination, service, action"
    _assert_quality(findings)

    no_match = detect_duplicates([_rule(1, services=["https"]), _rule(2, services=["ssh"])], {})
    assert no_match == []

    disabled_match = detect_duplicates(
        [_rule(1, services=["https"]), _rule(2, services=["https"], enabled=False)],
        {},
    )
    assert disabled_match == []


def test_shadowed_rule_reports_first_enabled_shadowing_rule():
    rules = [
        _rule(1, sources=["any"], destinations=["any"], services=["any"]),
        _rule(2, sources=["10.0.0.5/32"], destinations=["any"], services=["https"]),
    ]

    findings = detect_shadows(rules, {})

    assert len(findings) == 1
    assert findings[0]["finding_type"] == "redundant_rule"
    assert findings[0]["evidence"]["shadowed_rule"].startswith("Rule 2")
    _assert_quality(findings)


def test_unused_objects_follow_nested_vendor_group_usage_and_skip_builtins():
    objects = [
        _object("Parent", "address_group", "", ["Child"]),
        _object("Child", "address_group", "", ["UsedHost"]),
        _object("UsedHost"),
        _object("VendorDefault", raw_data={"predefined": True}),
        _object("Orphan", value="10.0.0.99/32"),
    ]
    obj_map = build_object_map(objects)
    findings = _analyze_unused_objects([_rule(1, sources=["Parent"])], objects, obj_map)

    assert findings[0]["finding_type"] == "unattached_object"
    names = _unused_names(findings)
    assert names == {"Orphan"}
    _assert_quality(findings)


def test_overlapping_objects_flags_network_containment_not_duplicates_or_hosts():
    from app.analysis.engine import _analyze_overlapping_objects
    objects = [
        _object("Net-16", "network", "10.10.0.0/16"),
        _object("Net-24", "network", "10.10.5.0/24"),     # contained in Net-16 → overlap
        _object("Other-16", "network", "192.168.0.0/16"),  # disjoint → no overlap
        _object("Host", "host", "10.10.5.20/32"),          # host inside Net-16 → excluded (noise)
        _object("Dup-A", "network", "172.16.0.0/24"),
        _object("Dup-B", "network", "172.16.0.0/24"),      # identical → duplicate, not overlap
        _object("Builtin", "network", "10.10.7.0/24", raw_data={"predefined": True}),
    ]
    findings = _analyze_overlapping_objects(objects)

    assert len(findings) == 1
    f = findings[0]
    assert f["finding_type"] == "overlapping_object"
    assert f["evidence"]["count"] == 1                     # only Net-24 ⊂ Net-16
    sample = " ".join(f["evidence"]["sample"])
    assert "Net-24" in sample and "Net-16" in sample
    assert "Host" not in sample and "Dup-" not in sample and "Builtin" not in sample
    _assert_quality(findings)


def test_inoperative_rule_when_source_is_empty_group():
    """An enabled rule whose source resolves to an empty group can never match —
    distinct from shadowing. Disabled rules, populated groups, and unknown
    (unresolved) objects must not trigger it."""
    objects = [
        _object("EmptyGrp", "address_group", "", []),
        _object("FullGrp", "address_group", "", ["RealHost"]),
        _object("RealHost", value="10.0.0.3/32"),
    ]
    obj_map = build_object_map(objects)

    inert = _analyze_inoperative_rules([_rule(1, sources=["EmptyGrp"])], obj_map)
    assert len(inert) == 1
    assert inert[0]["finding_type"] == "inoperative_rule"
    assert inert[0]["confidence"] == "High"
    assert inert[0]["evidence"]["empty_fields"][0]["field"] == "source"

    # Disabled → not inoperative; populated group → not inoperative.
    assert _analyze_inoperative_rules([_rule(2, sources=["EmptyGrp"], enabled=False)], obj_map) == []
    assert _analyze_inoperative_rules([_rule(3, sources=["FullGrp"])], obj_map) == []

    # Unknown / unresolved object is NOT empty — must not be flagged inoperative.
    assert _analyze_inoperative_rules([_rule(4, sources=["DoesNotExist"])], obj_map) == []


def test_object_used_only_through_nat_is_not_unattached():
    """An object referenced solely by a NAT rule must not be flagged unattached."""
    objects = [
        _object("NAT-Host", value="10.0.0.50/32"),
        _object("RealOrphan", value="10.0.0.99/32"),
    ]
    obj_map = build_object_map(objects)
    nat_rules = [{"nat_type": "destination", "original_dst": ["203.0.113.1"],
                  "translated_dst": ["NAT-Host"]}]
    findings = _analyze_unused_objects(
        [_rule(1, sources=["10.0.0.1/32"])], objects, obj_map, nat_rules)

    names = _unused_names(findings)
    assert names == {"RealOrphan"}            # NAT-Host is used via NAT


def test_incomplete_object_import_suppresses_unattached_and_diagnoses():
    """When most named references don't resolve, suppress cleanup and emit a
    data-availability diagnostic instead of flagging everything."""
    objects = [_object("LonelyObj", value="10.0.0.5/32")]
    obj_map = build_object_map(objects)
    rules = [
        _rule(1, sources=["Missing-A"], destinations=["Missing-B"]),
        _rule(2, sources=["Missing-C"], destinations=["Missing-D"]),
    ]
    findings = _analyze_unused_objects(rules, objects, obj_map)

    types = {f["finding_type"] for f in findings}
    assert "object_usage_unknown" in types
    assert "unattached_object" not in types


def test_circular_group_is_diagnosed_and_members_not_unattached():
    objects = [
        _object("G1", "address_group", "", ["G2"]),
        _object("G2", "address_group", "", ["G1", "MemberHost"]),
        _object("MemberHost", value="10.0.0.7/32"),
    ]
    obj_map = build_object_map(objects)
    # G1 is used by a rule; the cycle G1->G2->G1 must be diagnosed, not crash,
    # and MemberHost (inside the circular group) must not be unattached.
    findings = _analyze_unused_objects([_rule(1, sources=["G1"])], objects, obj_map)

    types = {f["finding_type"] for f in findings}
    assert "object_usage_unknown" in types     # circular diagnostic
    circ = [f for f in findings if f["finding_type"] == "object_usage_unknown"][0]
    assert "G1" in circ["evidence"].get("circular_groups", [])
    unattached = [f for f in findings if f["finding_type"] == "unattached_object"]
    assert not unattached or "MemberHost" not in unattached[0]["evidence"]["sample"]


def test_empty_groups_include_customer_groups_and_suppress_vendor_builtins():
    objects = [
        _object("CustomerEmpty", "address_group", "", []),
        _object("VendorEmpty", "address_group", "", [], raw_data={"builtin": True}),
    ]

    findings = _analyze_empty_groups(objects)

    assert len(findings) == 1
    assert findings[0]["finding_type"] == "empty_group"
    assert findings[0]["evidence"]["sample"] == ["CustomerEmpty"]
    assert findings[0]["evidence"]["count"] == 1
    _assert_quality(findings)


def test_checkpoint_group_uid_members_prevent_unused_member_false_positive():
    objects = [
        _object("CP-Group", "address_group", "", [{"uid": "uid-host"}], object_uid="uid-group"),
        _object("CP-Host", "host", "10.10.10.10/32", [], object_uid="uid-host"),
        _object("Orphan", "host", "10.10.10.99/32", [], object_uid="uid-orphan"),
    ]
    obj_map = build_object_map(objects)

    findings = _analyze_unused_objects([_rule(1, sources=["CP-Group"])], objects, obj_map)

    names = _unused_names(findings)
    assert names == {"Orphan"}


def test_checkpoint_raw_group_members_prevent_empty_group_false_positive():
    objects = [
        _object(
            "CP-Group",
            "address_group",
            "",
            [],
            raw_data={"uid": "uid-group", "members": [{"uid": "uid-host", "name": "CP-Host"}]},
        ),
        _object("TrulyEmpty", "address_group", "", []),
    ]

    findings = _analyze_empty_groups(objects)

    names = set(findings[0]["evidence"]["sample"])
    assert names == {"TrulyEmpty"}


def test_db_object_member_entries_prevent_unused_member_false_positive():
    class DbObject:
        id = "obj-db-group"
        vendor = "CheckPoint"
        object_uid = "uid-group"
        object_name = "DB-Group"
        object_type = "address_group"
        value = ""
        protocol = None
        port_start = None
        port_end = None
        members = []
        raw_data = {}

    class DbMember:
        object_name = "DB-Host"
        object_uid = "uid-host"

    class DbEntry:
        member_name = "DB-Host"
        member = DbMember()

    db_group = DbObject()
    db_group.member_entries = [DbEntry()]

    objects = [
        _obj_to_dict(db_group),
        _object("DB-Host", "host", "10.20.30.40/32", [], object_uid="uid-host"),
        _object("Orphan", "host", "10.20.30.99/32", [], object_uid="uid-orphan"),
    ]
    obj_map = build_object_map(objects)

    findings = _analyze_unused_objects([_rule(1, sources=["DB-Group"])], objects, obj_map)

    names = _unused_names(findings)
    assert names == {"Orphan"}


def test_legacy_json_string_rule_refs_still_mark_group_members_used():
    class DbRule:
        id = "rule-db"
        rule_id = "1"
        rule_uid = "uid-rule"
        rule_number = 1
        rule_name = "Legacy synced rule"
        section = ""
        source_interfaces = "[]"
        destination_interfaces = "[]"
        install_on = "[]"
        sources = '["CP-Group"]'
        destinations = '["any"]'
        services = '["Any"]'
        applications = "[]"
        action = "accept"
        schedule = "Any"
        enabled = True
        logging_enabled = True
        nat_enabled = False
        comments = ""
        hit_count = None
        last_hit = None
        first_hit = None

    objects = [
        _object("CP-Group", "address_group", "", ["CP-Host"], object_uid="uid-group"),
        _object("CP-Host", "host", "10.10.10.10/32", [], object_uid="uid-host"),
        _object("Orphan", "host", "10.10.10.99/32", [], object_uid="uid-orphan"),
    ]

    findings = _analyze_unused_objects([_rule_to_dict(DbRule())], objects, build_object_map(objects))

    names = _unused_names(findings)
    assert names == {"Orphan"}


def test_checkpoint_discrete_port_list_is_not_reported_as_wide_range():
    objects = [
        _object(
            "CP-Web-Ports",
            "service",
            "tcp/80-443",
            [],
            protocol="tcp",
            port_start=80,
            port_end=443,
            raw_data={"type": "service-tcp", "port": "80,443"},
        ),
        _object(
            "CP-Wide-Used",
            "service",
            "tcp/2000-4000",
            [],
            protocol="tcp",
            port_start=2000,
            port_end=4000,
            raw_data={"type": "service-tcp", "port": "2000-4000"},
        ),
        _object(
            "CP-Wide-Unused",
            "service",
            "tcp/10000-20000",
            [],
            protocol="tcp",
            port_start=10000,
            port_end=20000,
            raw_data={"type": "service-tcp", "port": "10000-20000"},
        ),
    ]
    rules = [_rule(1, services=["CP-Web-Ports", "CP-Wide-Used"])]

    findings = _analyze_service_ranges(objects, rules, build_object_map(objects))

    names = {f["evidence"]["object_name"] for f in findings}
    assert names == {"CP-Wide-Used"}


def test_consolidation_suppresses_generic_risky_service_when_specific_exposure_exists():
    rule = _rule(1, sources=["any"], destinations=["10.0.0.10/32"], services=["tcp/3389"])
    findings = _analyze_risky_services([rule], {}) + _analyze_exposed_services([rule], {})

    consolidated = _consolidate_findings(findings)
    types = {f["finding_type"] for f in consolidated}

    assert "rdp_exposed" in types
    assert "risky_service" not in types
    rdp = [f for f in consolidated if f["finding_type"] == "rdp_exposed"][0]
    assert rdp["evidence"]["consolidated_related_findings"][0]["finding_type"] == "risky_service"


def test_consolidation_suppresses_usage_when_new_shadow_types_exist():
    zero_hit = {
        "finding_type": "zero_hit_rule",
        "severity": "Medium",
        "confidence": "High",
        "title": "Rule 2 has zero hits",
        "description": "usage",
        "affected_rules": ["rule-2"],
        "evidence": {"rule_id": "2"},
        "recommendation": "review",
    }
    shadow = {
        "finding_type": "redundant_rule",
        "severity": "Medium",
        "confidence": "High",
        "title": "Rule 2 is redundant",
        "description": "shadow",
        "affected_rules": ["rule-2", "rule-1"],
        "evidence": {"rule_id": "2"},
        "recommendation": "review",
    }

    consolidated = _consolidate_findings([zero_hit, shadow])

    assert {f["finding_type"] for f in consolidated} == {"redundant_rule"}
    assert consolidated[0]["evidence"]["consolidated_related_findings"][0]["finding_type"] == "zero_hit_rule"


def test_no_unused_findings_when_no_rules():
    """With objects but no rules, usage is unknown — never flag all objects unused."""
    from app.analysis.engine import _analyze_unused_objects
    objects = [{"object_name": f"host{i}", "object_type": "host", "value": f"10.0.0.{i}", "members": []} for i in range(50)]
    obj_map = {o["object_name"]: o for o in objects}
    assert _analyze_unused_objects([], objects, obj_map) == []


def test_unresolved_rule_object_suppresses_unused_object_detector():
    objects = [
        _object("ImportedHost", "host", "10.0.0.10/32"),
        _object("Orphan", "host", "10.0.0.99/32"),
    ]
    rules = [_rule(1, sources=["MissingGroup"], destinations=["any"], services=["https"])]

    findings = _analyze_unused_objects(rules, objects, build_object_map(objects))

    assert {f["finding_type"] for f in findings} == {"object_usage_unknown"}
    assert "unattached_object" not in {f["finding_type"] for f in findings}


def test_single_unresolved_object_reference_suppresses_cleanup_detector():
    objects = [
        _object("UsedHost", "host", "10.0.0.10/32"),
        _object("Orphan", "host", "10.0.0.99/32"),
    ]
    rules = [
        _rule(1, sources=["UsedHost"], destinations=["any"], services=["https"]),
        _rule(2, sources=["MissingGroup"], destinations=["any"], services=["https"]),
    ]

    findings = _analyze_unused_objects(rules, objects, build_object_map(objects))

    assert {f["finding_type"] for f in findings} == {"object_usage_unknown"}
    assert "unattached_object" not in {f["finding_type"] for f in findings}


def test_unresolved_group_member_reference_suppresses_cleanup_detector():
    objects = [
        _object("UsedGroup", "address_group", "", ["KnownHost", "MissingMember"]),
        _object("KnownHost", "host", "10.0.0.10/32"),
        _object("Orphan", "host", "10.0.0.99/32"),
    ]
    rules = [_rule(1, sources=["UsedGroup"], destinations=["any"], services=["https"])]

    findings = _analyze_unused_objects(rules, objects, build_object_map(objects))

    assert {f["finding_type"] for f in findings} == {"object_usage_unknown"}
    assert findings[0]["evidence"]["unresolved_group_members"] == 1
    assert "unattached_object" not in {f["finding_type"] for f in findings}


def test_service_object_used_through_service_group_is_not_reported_as_service_range():
    objects = [
        _object("SvcGroup", "service-group", "", ["WideSvc"]),
        _object(
            "WideSvc",
            "service",
            "tcp/2000-4000",
            [],
            protocol="tcp",
            port_start=2000,
            port_end=4000,
        ),
        _object(
            "UnusedWideSvc",
            "service",
            "tcp/10000-20000",
            [],
            protocol="tcp",
            port_start=10000,
            port_end=20000,
        ),
    ]

    findings = _analyze_service_ranges(objects, [_rule(1, services=["SvcGroup"])], build_object_map(objects))

    assert {f["evidence"]["object_name"] for f in findings} == {"WideSvc"}


def test_debug_keyword_flags_temp_rule_and_cleanup_removed():
    from app.config import settings
    assert "debug" in settings.temp_keywords
    assert "cleanup" not in settings.temp_keywords


def test_import_quality_notes_flag_missing_data():
    from app.analysis.engine import _import_quality_notes

    class P:
        vendor = "FortiGate"
        nat_rules = None

    rules = [{"id": "r1", "enabled": True, "hit_count": None,
              "source_interfaces": [], "destination_interfaces": []}]
    notes = _import_quality_notes(rules, [], P())
    titles = {n["title"] for n in notes}
    assert "Hit-count data unavailable" in titles
    assert "NAT data unavailable" in titles
    assert "Interface/zone context unavailable" in titles
    assert "Object graph incomplete" not in titles
    assert all(n["severity"] == "Informational" for n in notes)

    # With hit data + interfaces + NAT, the corresponding notes disappear.
    class P2:
        vendor = "FortiGate"
        nat_rules = [{"nat_type": "destination"}]

    rules2 = [{"id": "r1", "enabled": True, "hit_count": 5,
               "source_interfaces": ["wan1"], "destination_interfaces": ["lan"]}]
    assert _import_quality_notes(rules2, [], P2()) == []


def test_evaluation_context_stamped_on_rule_scoped_findings():
    from app.analysis.engine import _enrich_evaluation_context

    rules = [
        {"id": "r1", "source_interfaces": ["wan1"], "destination_interfaces": ["lan"]},
        {"id": "r2", "source_interfaces": ["wan2"], "destination_interfaces": ["dmz"]},
    ]

    # Single-rule finding → context attached.
    single = {"finding_type": "risky_service", "affected_rules": ["r1"], "evidence": {}}
    # Finding spanning two different contexts → left unstamped (ambiguous).
    spanning = {"finding_type": "duplicate_rule", "affected_rules": ["r1", "r2"], "evidence": {}}
    # Finding that already carries context → not overwritten.
    preset = {"finding_type": "redundant_rule", "affected_rules": ["r1"],
              "evidence": {"evaluation_context": "preset"}}
    # Object-only finding (no rules) → untouched.
    object_only = {"finding_type": "unused_object", "affected_rules": [], "evidence": {}}

    _enrich_evaluation_context([single, spanning, preset, object_only], rules, "FortiGate")

    assert single["evidence"]["evaluation_context"] == "interfaces wan1 → lan"
    assert "evaluation_context" not in spanning["evidence"]
    assert preset["evidence"]["evaluation_context"] == "preset"
    assert "evaluation_context" not in object_only["evidence"]
