"""Unit tests for the Executive Cleanup Plan wave mapping."""
from app.api.cleanup import WAVES, _TYPE_TO_WAVE, _SEV_WEIGHT


def test_every_wave_type_maps_back():
    for w in WAVES:
        for t in w["types"]:
            assert _TYPE_TO_WAVE[t] == w["id"]


def test_no_type_in_two_waves():
    seen = {}
    for w in WAVES:
        for t in w["types"]:
            assert t not in seen, f"{t} appears in multiple waves"
            seen[t] = w["id"]


def test_safe_removal_types_in_wave1():
    for t in ("disabled_rule", "zero_hit_rule", "duplicate_rule", "unused_object"):
        assert _TYPE_TO_WAVE[t] == 1


def test_security_types_in_wave3():
    for t in ("inbound_from_internet", "rdp_exposed", "overly_permissive", "lateral_movement_risk"):
        assert _TYPE_TO_WAVE[t] == 3


def test_severity_weight_ordering():
    assert _SEV_WEIGHT["Critical"] > _SEV_WEIGHT["High"] > _SEV_WEIGHT["Medium"] > _SEV_WEIGHT["Low"] >= 0


def test_import_quality_is_unscheduled():
    # Informational/data-quality findings are not a cleanup wave.
    assert "import_quality" not in _TYPE_TO_WAVE
