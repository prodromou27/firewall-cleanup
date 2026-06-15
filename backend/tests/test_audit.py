"""Unit tests for audit event target derivation."""
from app.security.audit import _derive_target


def test_policy_target():
    assert _derive_target("policy.reanalyze", {"policy_id": "p1", "customer_id": "c1"}) == ("policy", "p1")


def test_device_target():
    assert _derive_target("device.update", {"device_id": "d1"}) == ("device", "d1")


def test_target_user_takes_precedence():
    # An admin acting on another user: target is the affected user, not the actor.
    assert _derive_target("user.password_reset", {"user_id": "actor", "target_user_id": "victim"}) == ("user", "victim")


def test_user_event_falls_back_to_actor():
    assert _derive_target("user.create", {"user_id": "u1"}) == ("user", "u1")


def test_customer_event():
    assert _derive_target("customer.delete", {"customer_id": "c9"}) == ("customer", "c9")


def test_auth_event_has_no_target():
    assert _derive_target("auth.login", {"user_id": "u1", "email": "a@b.com"}) == (None, None)
