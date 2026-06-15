"""Unit tests for the password policy, rate limiter, and public-network helper."""
import pytest

from app.security.passwords import validate_password_policy, hash_password, verify_password
from app.security.ratelimit import _RateLimiter
from app.analysis.ip_utils import is_public_network


# ── Password policy ──────────────────────────────────────────────────────────

def test_accepts_strong_password():
    validate_password_policy("Tr0ub4dour&3xtra")  # should not raise


def test_rejects_too_short():
    with pytest.raises(ValueError):
        validate_password_policy("Ab1!xyz")


def test_rejects_too_few_classes():
    with pytest.raises(ValueError):
        validate_password_policy("alllowercaseletters")


def test_rejects_common_base_word():
    for pw in ("Password1234!", "Welcome2026!!", "Sup3rAdmin#99"):
        with pytest.raises(ValueError):
            validate_password_policy(pw)


def test_hash_roundtrip():
    h = hash_password("Tr0ub4dour&3xtra")
    assert verify_password("Tr0ub4dour&3xtra", h)
    assert not verify_password("wrong-password", h)


# ── Rate limiter ─────────────────────────────────────────────────────────────

def test_rate_limiter_allows_then_blocks():
    rl = _RateLimiter(3)
    results = [rl.allow("ip-a")[0] for _ in range(5)]
    assert results == [True, True, True, False, False]


def test_rate_limiter_isolates_keys():
    rl = _RateLimiter(2)
    assert rl.allow("ip-a")[0]
    assert rl.allow("ip-a")[0]
    assert not rl.allow("ip-a")[0]
    # Different key has its own budget.
    assert rl.allow("ip-b")[0]


def test_rate_limiter_disabled_when_zero():
    rl = _RateLimiter(0)
    assert all(rl.allow("ip-a")[0] for _ in range(100))


def test_rate_limiter_returns_retry_after():
    rl = _RateLimiter(1)
    assert rl.allow("ip-a") == (True, 0)
    allowed, retry = rl.allow("ip-a")
    assert allowed is False
    assert retry > 0


# ── Public network helper ────────────────────────────────────────────────────

def test_public_network_detection():
    assert is_public_network("1.2.3.4")
    assert is_public_network("8.8.8.0/24")
    assert is_public_network("any")
    assert is_public_network("0.0.0.0/0")


def test_private_ranges_are_not_public():
    for v in ("10.0.0.0/8", "172.16.0.0/12", "192.168.1.0/24", "127.0.0.1"):
        assert not is_public_network(v)


def test_unparseable_source_is_not_public():
    # Named objects we cannot resolve must not be treated as public exposure.
    assert not is_public_network("Branch-Office-Group")
    assert not is_public_network("")
