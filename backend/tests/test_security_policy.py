"""Unit tests for the password policy, rate limiter, and public-network helper."""
import pytest
from pydantic import ValidationError

from app.security.passwords import validate_password_policy, hash_password, verify_password
from app.security.ratelimit import _RateLimiter
from app.analysis.ip_utils import is_public_network
from app.config import Settings
from app.api.devices import DeviceCreate, _device_dict, _diag
from app.models.device import FirewallDevice
from app.models.user import ROLE_SYSTEM_ADMIN, ROLE_TENANT_ADMIN
from app.security.rbac import CAP_MANAGE_SETTINGS, has_capability
from app.security.redaction import redact_secrets


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


def test_production_requires_secret_secure_cookie_and_real_origin():
    s = Settings(
        environment="production",
        secret_key="",
        cookie_secure=False,
        allowed_origins="http://localhost:3000",
    )
    with pytest.raises(RuntimeError) as exc:
        s.validate_security_posture()
    msg = str(exc.value)
    assert "SECRET_KEY" in msg
    assert "COOKIE_SECURE" in msg
    assert "localhost" in msg


def test_secure_production_settings_pass_validation():
    s = Settings(
        environment="production",
        secret_key="test-secret",
        cookie_secure=True,
        allowed_origins="https://policyinsight.example.com",
    )
    s.validate_security_posture()


def test_device_host_blocks_local_and_metadata_targets():
    base = {
        "customer_id": "c1",
        "name": "FW",
        "vendor": "FortiGate",
        "api_token": "token",
    }
    for host in ("127.0.0.1", "localhost", "169.254.169.254", "0.0.0.0"):
        with pytest.raises(ValidationError):
            DeviceCreate(host=host, **base)


def test_device_host_allows_normal_internal_firewall_ip():
    d = DeviceCreate(
        customer_id="c1",
        name="FW",
        vendor="FortiGate",
        host="10.10.10.1",
        api_token="token",
    )
    assert d.host == "10.10.10.1"


def test_global_settings_are_system_admin_only():
    assert has_capability(ROLE_SYSTEM_ADMIN, CAP_MANAGE_SETTINGS)
    assert not has_capability(ROLE_TENANT_ADMIN, CAP_MANAGE_SETTINGS)


def test_redacts_secrets_from_diagnostics():
    raw = (
        "GET /api/?type=keygen&user=admin&password=SuperSecret!&token=abc123 "
        "api_key=live-key Authorization: Bearer bearer-token Basic abcdef"
    )
    redacted = redact_secrets(raw)

    assert "SuperSecret" not in redacted
    assert "abc123" not in redacted
    assert "live-key" not in redacted
    assert "bearer-token" not in redacted
    assert "abcdef" not in redacted
    assert "[REDACTED]" in redacted


def test_device_response_redacts_persisted_last_error():
    device = FirewallDevice(
        id="dev-1",
        customer_id="cust-1",
        name="FW",
        vendor="PaloAlto",
        host="10.0.0.10",
        last_error="keygen failed: password=SuperSecret token=abc123",
    )

    payload = _device_dict(device)

    assert "SuperSecret" not in payload["last_error"]
    assert "abc123" not in payload["last_error"]
    assert "password=[REDACTED]" in payload["last_error"]


def test_device_diagnostic_helper_limits_and_redacts_secrets():
    err = RuntimeError("failure api_token=very-secret " + "x" * 700)
    message = _diag(err)

    assert len(message) <= 500
    assert "very-secret" not in message
    assert "api_token=[REDACTED]" in message
