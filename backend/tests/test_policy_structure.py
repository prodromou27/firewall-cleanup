"""Unit tests for the consolidation and cleanup-rule detectors."""
from app.analysis.engine import _analyze_mergeable_rules, _analyze_cleanup_rule
from app.analysis.normalizer import build_object_map


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
    assert findings[0]["severity"] == "Medium"
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
