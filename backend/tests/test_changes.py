"""Unit tests for the change-feed severity-delta logic."""
from app.api.changes import _severity_delta, _snapshot


class _Run:
    def __init__(self, snap):
        self.severity_snapshot = snap


def test_delta_new_high_risk():
    curr = {"Critical": 3, "High": 10, "Medium": 5}
    prev = {"Critical": 1, "High": 10, "Medium": 8}
    d = _severity_delta(curr, prev)
    assert d == {"Critical": 2, "Medium": -3}   # High unchanged (omitted)


def test_delta_no_change_is_empty():
    snap = {"Critical": 2, "High": 4}
    assert _severity_delta(snap, snap) == {}


def test_delta_against_empty_prev():
    assert _severity_delta({"High": 4}, {}) == {"High": 4}


def test_snapshot_parses_json():
    assert _snapshot(_Run('{"High": 2, "Low": 1}')) == {"High": 2, "Low": 1}


def test_snapshot_handles_missing_and_garbage():
    assert _snapshot(_Run(None)) == {}
    assert _snapshot(_Run("not json")) == {}
    assert _snapshot(None) == {}
