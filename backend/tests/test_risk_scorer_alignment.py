"""Risk score alignment with explicit finding severity semantics."""
from app.analysis.risk_scorer import score_rule, score_to_severity


def test_any_to_any_any_service_scores_critical():
    rule = {
        "sources": ["any"],
        "destinations": ["any"],
        "services": ["any"],
        "action": "accept",
        "enabled": True,
        "logging_enabled": True,
    }

    score, factors = score_rule(rule, {})
    assert score_to_severity(score) == "Critical"
    assert "any_to_any" in factors


def test_any_to_any_specific_service_scores_critical():
    rule = {
        "sources": ["any"],
        "destinations": ["any"],
        "services": ["HTTPS"],
        "action": "accept",
        "enabled": True,
        "logging_enabled": True,
    }
    objects = {
        "HTTPS": {
            "object_name": "HTTPS",
            "object_type": "service",
            "protocol": "tcp",
            "port_start": 443,
            "port_end": 443,
        }
    }

    score, factors = score_rule(rule, objects)
    assert score_to_severity(score) == "Critical"
    assert "any_to_any" in factors
