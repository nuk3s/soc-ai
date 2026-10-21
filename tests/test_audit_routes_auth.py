"""LoginThrottle keying: an IPv6 client is bucketed by its /64, not its full address."""

from __future__ import annotations

from typing import Any

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


def test_login_throttle_reports_tries_left_and_the_wait() -> None:
    """The lockout message names how long the lock lasts and which key it
    holds, and the sign-in form warns before the lock (dogfood 2026-10-19,
    H1-D17). The throttle exposes both numbers so the route can say them."""
    throttle = auth_svc.LoginThrottle(max_failures=3, cooldown_s=300)
    assert throttle.failures_left("192.0.2.7", "admin") == 3
    assert throttle.retry_after("192.0.2.7", "admin") == 0.0
    throttle.record_failure("192.0.2.7", "admin")
    assert throttle.failures_left("192.0.2.7", "admin") == 2
    throttle.record_failure("192.0.2.7", "admin")
    throttle.record_failure("192.0.2.7", "admin")
    assert throttle.failures_left("192.0.2.7", "admin") == 0
    wait = throttle.retry_after("192.0.2.7", "admin")
    assert 299.0 < wait <= 300.0
    # Another username from the same address is a different key.
    assert throttle.retry_after("192.0.2.7", "jordan") == 0.0


def test_login_lockout_hint_names_the_wait_and_the_scope(settings_kratos: Any) -> None:
    from pydantic import SecretStr

    from tests.test_webui_api import _client

    auth_svc.login_throttle.reset()
    auth_svc.login_ip_throttle.reset()
    settings = settings_kratos.model_copy(
        update={"api_auth_required": True, "bootstrap_admin_password": SecretStr("pw-12345678")}
    )
    try:
        for client in _client(settings):
            hints = []
            for _ in range(5):
                r = client.post("/api/v1/login", json={"username": "admin", "password": "WRONG"})
                assert r.status_code == 401
                hints.append(r.json()["detail"]["hint"])
            assert hints[0] == "The username or the password is wrong."
            assert "2 more failed sign-ins lock this username for 5 minutes." in hints[2]
            assert "1 more failed sign-in locks this username for 5 minutes." in hints[3]
            assert "soc-ai locked this username for 5 minutes." in hints[4]
            r = client.post("/api/v1/login", json={"username": "admin", "password": "WRONG"})
            assert r.status_code == 429
            assert r.json()["detail"]["hint"] == (
                "Too many failed sign-ins for this username. Try again in 5 minutes."
            )
            assert r.headers["Retry-After"] == "300"
    finally:
        auth_svc.login_throttle.reset()
        auth_svc.login_ip_throttle.reset()


def test_auth_status_is_open_and_names_the_gate(settings_kratos: Any) -> None:
    """The sign-in page offered a full form on a server with authentication
    off (dogfood 2026-10-19, R1-D20). It reads this open flag before the form."""
    from tests.test_webui_api import _client

    for required in (True, False):
        settings = settings_kratos.model_copy(update={"api_auth_required": required})
        for client in _client(settings):
            r = client.get("/api/v1/auth-status")
            assert r.status_code == 200, r.text
            assert r.json() == {"auth_required": required}
