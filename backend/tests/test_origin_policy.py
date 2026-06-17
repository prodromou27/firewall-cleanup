"""Unit tests for the runtime origin-subnet allow-list (CORS/CSRF LAN access)."""
import pytest

from app.security import origin_policy


@pytest.fixture(autouse=True)
def _reset():
    """Each test starts and ends with an empty allow-list (module is global)."""
    origin_policy.set_subnets([])
    yield
    origin_policy.set_subnets([])


# ── parsing ──────────────────────────────────────────────────────────────────

def test_parse_valid_and_invalid():
    nets, invalid = origin_policy.parse_cidrs(["192.168.201.0/24", "bad", "10.0.0.0/8", ""])
    assert len(nets) == 2
    assert invalid == ["bad"]


def test_set_subnets_returns_invalid_and_keeps_valid():
    invalid = origin_policy.set_subnets(["192.168.201.0/24", "nope/99"])
    assert invalid == ["nope/99"]
    assert origin_policy.get_cidrs() == ["192.168.201.0/24"]


def test_set_subnets_replaces_not_appends():
    origin_policy.set_subnets(["10.0.0.0/8"])
    origin_policy.set_subnets(["192.168.201.0/24"])
    assert origin_policy.get_cidrs() == ["192.168.201.0/24"]


# ── matching ─────────────────────────────────────────────────────────────────

def test_in_subnet_matches_any_port():
    origin_policy.set_subnets(["192.168.201.0/24"])
    assert origin_policy.origin_in_allowed_subnet("http://192.168.201.50:3000")
    assert origin_policy.origin_in_allowed_subnet("https://192.168.201.1")
    assert origin_policy.origin_in_allowed_subnet("http://192.168.201.254:8080")


def test_out_of_subnet_rejected():
    origin_policy.set_subnets(["192.168.201.0/24"])
    assert not origin_policy.origin_in_allowed_subnet("http://192.168.202.5:3000")
    assert not origin_policy.origin_in_allowed_subnet("http://10.0.0.5:3000")


def test_empty_allowlist_matches_nothing():
    assert not origin_policy.origin_in_allowed_subnet("http://192.168.201.50:3000")


def test_hostname_origin_not_matched():
    # A DNS name (not an IP literal) can't be a subnet member.
    origin_policy.set_subnets(["192.168.201.0/24"])
    assert not origin_policy.origin_in_allowed_subnet("http://localhost:3000")
    assert not origin_policy.origin_in_allowed_subnet("http://app.internal:3000")


def test_garbage_and_empty_origin_safe():
    origin_policy.set_subnets(["192.168.201.0/24"])
    assert not origin_policy.origin_in_allowed_subnet("")
    assert not origin_policy.origin_in_allowed_subnet("not-a-url")


def test_multiple_subnets():
    origin_policy.set_subnets(["192.168.201.0/24", "10.20.30.0/24"])
    assert origin_policy.origin_in_allowed_subnet("http://10.20.30.5:3000")
    assert origin_policy.origin_in_allowed_subnet("http://192.168.201.5:3000")
    assert not origin_policy.origin_in_allowed_subnet("http://10.20.31.5:3000")
