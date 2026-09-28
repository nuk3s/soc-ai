"""LoginThrottle keying: an IPv6 client is bucketed by its /64, not its full address."""

from __future__ import annotations

from soc_ai.store import auth as auth_svc


def test_login_throttle_locks_username_across_rotating_ipv6_hosts() -> None:
    """A single IPv6 host owns a whole /64 (SLAAC privacy addresses, a delegated
    prefix), so rotating the interface identifier must not reset the count."""
    throttle = auth_svc.LoginThrottle(max_failures=5)
    for i in range(1, 5):
        assert throttle.record_failure(f"2001:db8::{i}", "admin") is False
    assert throttle.record_failure("2001:db8::5", "admin") is True
    assert throttle.is_locked("2001:db8::ffff", "admin") is True
    # A different /64 is a different source.
    assert throttle.is_locked("2001:db9::1", "admin") is False


def test_login_throttle_ipv6_clear_covers_the_whole_prefix() -> None:
    throttle = auth_svc.LoginThrottle(max_failures=2)
    throttle.record_failure("2001:db8::1", "admin")
    assert throttle.record_failure("2001:db8::2", "admin") is True
    throttle.clear("2001:db8::3", "admin")
    assert throttle.is_locked("2001:db8::1", "admin") is False


def test_login_throttle_ipv4_and_opaque_keys_are_unchanged() -> None:
    """IPv4 addresses, IPv4-mapped IPv6 and unparseable forwarded hops keep their
    raw string as the key, so distinct hosts stay distinct."""
    throttle = auth_svc.LoginThrottle(max_failures=2)
    throttle.record_failure("10.0.0.1", "admin")
    assert throttle.is_locked("10.0.0.2", "admin") is False
    assert throttle.record_failure("10.0.0.1", "admin") is True
    assert throttle.is_locked("10.0.0.1", "admin") is True
    assert throttle.is_locked("::ffff:10.0.0.1", "admin") is False
    throttle.record_failure("::ffff:10.0.0.1", "admin")
    assert throttle.is_locked("::ffff:10.0.0.2", "admin") is False
    # Malformed values (a garbage X-Forwarded-For hop, "testclient", "?") never crash.
    assert throttle.record_failure("not-an-address", "admin") is False
    assert throttle.record_failure("?", "admin") is False
    assert throttle.is_locked("testclient", "admin") is False
