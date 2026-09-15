"""Unit tests for the consolidation and cleanup-rule detectors."""
from app.analysis.engine import _analyze_mergeable_rules, _analyze_cleanup_rule
from app.analysis.normalizer import build_object_map
import pytest


def _rule(rid, sources, dests, services, action="accept", enabled=True, logging_enabled=False):
    return {
        "id": f"rule-{rid}", "rule_id": str(rid), "rule_number": rid,
        "sources": sources, "destinations": dests, "services": services,
        "action": action, "enabled": enabled, "logging_enabled": logging_enabled,
    }


OBJ_MAP = build_object_map([])  # 'any' resolves without object definitions


# ── Mergeable rules ──────────────────────────────────────────────────────────

def test_mergeable_same_src_dst_diff_service():
    rules = [
        _rule(1, ["WebSrv"], ["DB"], ["MySQL"]),
        _rule(2, ["WebSrv"], ["DB"], ["SSH"]),
    ]
    findings = _analyze_mergeable_rules(rules)
    assert len(findings) == 1
    assert findings[0]["finding_type"] == "mergeable_rules"
    assert set(findings[0]["evidence"]["rule_ids"]) == {"1", "2"}


def test_exact_duplicates_not_flagged_as_mergeable():
    # Identical services -> a duplicate set, owned by the duplicate detector.
    rules = [
        _rule(1, ["WebSrv"], ["DB"], ["MySQL"]),
        _rule(2, ["WebSrv"], ["DB"], ["MySQL"]),
    ]
    assert _analyze_mergeable_rules(rules) == []


def test_different_action_not_mergeable():
    rules = [
        _rule(1, ["WebSrv"], ["DB"], ["MySQL"], action="accept"),
        _rule(2, ["WebSrv"], ["DB"], ["SSH"], action="deny"),
    ]
    assert _analyze_mergeable_rules(rules) == []


def test_different_destination_not_mergeable():
    rules = [
        _rule(1, ["WebSrv"], ["DB-A"], ["MySQL"]),
        _rule(2, ["WebSrv"], ["DB-B"], ["SSH"]),
    ]
    assert _analyze_mergeable_rules(rules) == []


def test_disabled_rules_ignored_in_merge():
    rules = [
        _rule(1, ["WebSrv"], ["DB"], ["MySQL"]),
        _rule(2, ["WebSrv"], ["DB"], ["SSH"], enabled=False),
    ]
    assert _analyze_mergeable_rules(rules) == []


# ── Cleanup rule ─────────────────────────────────────────────────────────────

def test_missing_cleanup_rule_flagged():
    rules = [_rule(1, ["WebSrv"], ["DB"], ["MySQL"])]
    findings = _analyze_cleanup_rule(rules, OBJ_MAP)
    assert len(findings) == 1
    assert findings[0]["severity"] == "Informational"
    assert findings[0]["evidence"]["implicit_default_logging"] == "unknown"
    assert findings[0]["evidence"]["explicit_cleanup_rule"] is False


def test_logged_cleanup_rule_is_clean():
    rules = [
        _rule(1, ["WebSrv"], ["DB"], ["MySQL"]),
        _rule(2, ["any"], ["any"], ["any"], action="deny", logging_enabled=True),
    ]
    assert _analyze_cleanup_rule(rules, OBJ_MAP) == []


def test_unlogged_cleanup_rule_flagged_low():
    rules = [
        _rule(1, ["WebSrv"], ["DB"], ["MySQL"]),
        _rule(2, ["any"], ["any"], ["any"], action="drop", logging_enabled=False),
    ]
    findings = _analyze_cleanup_rule(rules, OBJ_MAP)
    assert len(findings) == 1
    assert findings[0]["severity"] == "Low"
    assert findings[0]["evidence"]["logging_enabled"] is False


@pytest.mark.parametrize("field, value", [
    ("schedule", "weekends"), ("users", ["admins"]), ("applications", ["web"]),
    ("vpn", ["vpn-a"]), ("section", "layer-b"), ("source_interfaces", ["zone-b"]),
    ("logging_enabled", True), ("nat_enabled", True), ("negated", True),
    ("security_profiles", {"ips-sensor": "strict"}),
])
def test_merge_candidates_require_matching_restrictions(field, value):
    rules = [_rule(1, ["Web"], ["DB"], ["HTTPS"]), _rule(2, ["Web"], ["DB"], ["SSH"])]
    rules[1][field] = value
    assert _analyze_mergeable_rules(rules) == []


def test_merge_candidates_cannot_cross_intervening_deny():
    rules = [_rule(1, ["Web"], ["DB"], ["HTTPS"]),
             _rule(2, ["any"], ["DB"], ["SSH"], action="deny"),
             _rule(3, ["Web"], ["DB"], ["SSH"])]
    assert _analyze_mergeable_rules(rules) == []


def test_unknown_cleanup_logging_is_not_reported_as_disabled():
    rule = _rule(1, ["any"], ["any"], ["any"], action="deny", logging_enabled=None)
    assert _analyze_cleanup_rule([rule], OBJ_MAP) == []
