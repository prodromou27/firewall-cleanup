"""Unit tests for rule-order optimization and oversized-section detectors."""
from app.analysis.engine import _analyze_rule_order, _analyze_section_size


def _rule(num, hit_count=None, section=None, enabled=True):
    return {
        "id": f"rule-{num}", "rule_id": str(num), "rule_number": num,
        "rule_name": f"Rule {num}", "hit_count": hit_count,
        "section": section, "enabled": enabled, "action": "accept",
    }


# ── Rule order ───────────────────────────────────────────────────────────────

def test_busy_rule_below_many_zero_hit_flagged():
    rules = [_rule(i, hit_count=0) for i in range(1, 13)]      # 12 zero-hit rules
    rules.append(_rule(13, hit_count=50000))                   # busy rule at the bottom
    findings = _analyze_rule_order(rules)
    assert len(findings) == 1
    assert findings[0]["finding_type"] == "rule_order_optimization"
    assert findings[0]["evidence"]["zero_hit_rules_above"] == 12


def test_busy_rule_at_top_not_flagged():
    rules = [_rule(1, hit_count=50000)] + [_rule(i, hit_count=0) for i in range(2, 14)]
    assert _analyze_rule_order(rules) == []


def test_few_zero_hit_above_not_flagged():
    # Only 3 zero-hit rules above -> below the threshold of 10.
    rules = [_rule(i, hit_count=0) for i in range(1, 4)] + [_rule(4, hit_count=50000)]
    # Pad with busy rules so there is enough hit data overall.
    rules += [_rule(i, hit_count=500) for i in range(5, 10)]
    assert _analyze_rule_order(rules) == []


def test_skips_when_no_hit_data():
    rules = [_rule(i, hit_count=None) for i in range(1, 20)]
    assert _analyze_rule_order(rules) == []


def test_low_traffic_rule_not_flagged():
    rules = [_rule(i, hit_count=0) for i in range(1, 13)] + [_rule(13, hit_count=5)]
    assert _analyze_rule_order(rules) == []


# ── Section size ─────────────────────────────────────────────────────────────

def test_oversized_section_flagged():
    rules = [_rule(i, section="Legacy") for i in range(1, 26)]   # 25 > 20
    findings = _analyze_section_size(rules)
    assert len(findings) == 1
    assert findings[0]["finding_type"] == "large_rule_section"
    assert findings[0]["evidence"]["rule_count"] == 25


def test_small_section_not_flagged():
    rules = [_rule(i, section="Web") for i in range(1, 11)]
    assert _analyze_section_size(rules) == []


def test_rules_without_section_ignored():
    rules = [_rule(i, section=None) for i in range(1, 30)]
    assert _analyze_section_size(rules) == []
