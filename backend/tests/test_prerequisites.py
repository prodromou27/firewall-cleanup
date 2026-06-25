"""Detector prerequisite matrix tests (read-only)."""
from app.analysis import prerequisites as P


def _rule(**over):
    r = {
        "id": "r1", "rule_id": "1", "rule_number": 1, "rule_name": "r1",
        "action": "accept", "enabled": True,
        "sources": ["10.0.0.0/24"], "destinations": ["10.1.0.0/24"], "services": ["tcp/443"],
        "applications": [], "source_interfaces": [], "destination_interfaces": [],
        "section": "", "install_on": [], "hit_count": None, "last_hit": None,
    }
    r.update(over)
    return r


def _detectors(entries):
    return {e["detector"] for e in entries}


# ── availability assessment ─────────────────────────────────────────────────
def test_assess_flags_missing_usage_and_nat_and_interfaces():
    rules = [_rule()]
    avail = P.assess(rules, [], {}, nat_rules=None, vendor="FortiGate")
    assert avail["rules"] is True
    assert avail["hit_counts"] is False
    assert avail["last_hit"] is False
    assert avail["nat"] is False
    assert avail["interfaces"] is False
    assert avail["objects"] is False


def test_assess_detects_present_data():
    rules = [_rule(hit_count=7, last_hit="2026-01-01T00:00:00Z",
                   source_interfaces=["wan1"], destination_interfaces=["lan"])]
    avail = P.assess(rules, [{"object_name": "H", "object_type": "host"}],
                     {"H": {}}, nat_rules=[{"nat_type": "destination"}], vendor="FortiGate")
    assert avail["hit_counts"] and avail["last_hit"]
    assert avail["nat"] and avail["interfaces"] and avail["objects"]
    assert avail["layer_context"] is True


def test_vip_objects_count_as_nat_capability():
    avail = P.assess([_rule()], [{"object_name": "V", "object_type": "vip"}],
                     {}, nat_rules=None, vendor="FortiGate")
    assert avail["nat"] is True


def test_group_graph_incomplete_when_refs_unresolved():
    rules = [_rule(sources=["Missing-A"], destinations=["Missing-B"]),
             _rule(sources=["Missing-C"], destinations=["Missing-D"])]
    avail = P.assess(rules, [{"object_name": "x"}], {}, nat_rules=None, vendor="FortiGate")
    assert avail["group_graph"] is False


# ── evaluation / vendor gating ──────────────────────────────────────────────
def test_usage_detectors_suppressed_without_hit_data():
    avail = P.assess([_rule()], [], {}, nat_rules=None, vendor="PaloAlto")
    unmet = _detectors(P.evaluate(avail, "PaloAlto"))
    assert "zero_hit_rule" in unmet
    assert "low_usage_rule" in unmet


def test_application_controls_not_reported_for_cisco():
    """Cisco has no L7 app concept — application_controls is N/A, not 'suppressed'."""
    avail = P.assess([_rule()], [], {}, nat_rules=None, vendor="CiscoASA")
    assert "application_controls" not in _detectors(P.evaluate(avail, "CiscoASA"))


def test_application_controls_suppressed_for_fortigate_without_profile_data():
    avail = P.assess([_rule(_cli_parsed=False)], [], {}, nat_rules=None, vendor="FortiGate")
    assert "application_controls" in _detectors(P.evaluate(avail, "FortiGate"))


def test_palo_application_capability_is_present():
    avail = P.assess([_rule()], [], {}, nat_rules=None, vendor="PaloAlto")
    assert avail["applications"] is True
    assert "application_controls" not in _detectors(P.evaluate(avail, "PaloAlto"))


# ── summary finding ─────────────────────────────────────────────────────────
def test_summary_finding_none_when_everything_available():
    rules = [_rule(hit_count=1, last_hit="2026-01-01T00:00:00Z",
                   source_interfaces=["wan1"], destinations=["10.1.0.0/24"])]
    avail = P.assess(rules, [{"object_name": "H"}], {"10.1.0.0/24": {}},
                     nat_rules=[{"nat_type": "destination"}], vendor="PaloAlto")
    # Force every capability true to assert the all-satisfied path.
    avail = {k: True for k in P.CAPABILITIES}
    assert P.summary_finding(avail, "PaloAlto") is None


def test_import_quality_score_full_data_is_high():
    rules = [_rule(hit_count=3, last_hit="2026-01-01T00:00:00Z",
                   source_interfaces=["wan1"], section="L1", applications=["ssl"])]
    objects = [{"object_name": "10.1.0.0/24", "object_type": "network"}]
    iq = P.import_quality(rules, objects, {"10.1.0.0/24": {}},
                          nat_rules=[{"nat_type": "destination"}], vendor="PaloAlto")
    assert iq["score"] >= 85 and iq["grade"] == "A"
    assert iq["missing"] == []
    assert iq["capabilities"]["hit_counts"] is True


def test_import_quality_score_sparse_data_is_low():
    iq = P.import_quality([_rule()], [], {}, nat_rules=None, vendor="CiscoASA")
    # rules present but no objects/nat/hits/interfaces/apps → well below half.
    assert iq["score"] < 50 and iq["grade"] == "D"
    assert "hit_counts" in iq["missing"] and "objects" in iq["missing"]


def test_import_quality_parser_warnings_penalise_but_floor_at_zero():
    base = P.import_quality([_rule(hit_count=1)], [{"object_name": "h"}], {"h": {}},
                            nat_rules=None, vendor="PaloAlto", parser_warnings=0)
    penalised = P.import_quality([_rule(hit_count=1)], [{"object_name": "h"}], {"h": {}},
                                 nat_rules=None, vendor="PaloAlto", parser_warnings=10)
    assert penalised["score"] == max(0, base["score"] - 10)
    assert penalised["parser_warnings"] == 10


def test_summary_finding_lists_suppressed_and_downgraded():
    avail = P.assess([_rule()], [], {}, nat_rules=None, vendor="PaloAlto")
    f = P.summary_finding(avail, "PaloAlto")
    assert f and f["finding_type"] == "detector_prerequisites_unmet"
    assert f["severity"] == "Informational"
    labels = {d["detector"] for d in f["evidence"]["detectors"]}
    assert "zero_hit_rule" in labels
    assert f["evidence"]["data_available"]["hit_counts"] is False
