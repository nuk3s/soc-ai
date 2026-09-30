"""The daily TLS expiry loop reasons about the served certificate and fires once per band."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from soc_ai import main as main_mod
from soc_ai.tls_status import inspect_tls

from tests.test_tls_status import NOW, _cert, _key, _write

WEBHOOK = "https://hooks.example.test/x"


def _pair(tmp_path: Path, days: int) -> tuple[Path, Path]:
    key = _key()
    cert = _cert(
        subject="soc-ai.example.test",
        issuer_name="soc-ai.example.test",
        issuer_key=key,
        key=key,
        days=days,
    )
    return _write(tmp_path, [cert], key)


def _settings(
    cert_path: Path | None, key_path: Path | None, data_dir: Path | None = None
) -> SimpleNamespace:
    return SimpleNamespace(
        soc_ai_tls_cert=cert_path,
        soc_ai_tls_key=key_path,
        soc_ai_data_dir=data_dir,
        notify_enabled=True,
        notify_on_tls_expiry=True,
        notify_webhook_url=WEBHOOK,
    )


def _app() -> SimpleNamespace:
    return SimpleNamespace(state=SimpleNamespace())


async def test_a_band_change_fires_once_and_a_repeat_does_not(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cert_path, key_path = _pair(tmp_path, days=20)
    app = _app()
    settings = _settings(cert_path, key_path)
    fired = AsyncMock()
    monkeypatch.setattr(main_mod.notify, "fire_safe", fired)
    monkeypatch.setattr(main_mod, "_utcnow_for_tls", lambda: NOW)
    await main_mod._tls_expiry_check(app, settings)
    await main_mod._tls_expiry_check(app, settings)
    assert fired.await_count == 1
    alarm = app.state._tls_status.alarm
    assert alarm["band"] == 30 and alarm["days_left"] == 20
    assert alarm["disk_differs"] is False
    assert app.state.tls_at_start.fingerprint_sha256 == alarm["fingerprint"]


async def test_days_pass_and_the_band_tightens_on_the_served_certificate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The loop recomputes days left from the served certificate on every check."""
    cert_path, key_path = _pair(tmp_path, days=20)
    app = _app()
    settings = _settings(cert_path, key_path)
    fired = AsyncMock()
    monkeypatch.setattr(main_mod.notify, "fire_safe", fired)
    monkeypatch.setattr(main_mod, "_utcnow_for_tls", lambda: NOW)
    await main_mod._tls_expiry_check(app, settings)
    monkeypatch.setattr(main_mod, "_utcnow_for_tls", lambda: NOW + dt.timedelta(days=10))
    await main_mod._tls_expiry_check(app, settings)
    alarm = app.state._tls_status.alarm
    assert alarm["band"] == 14 and alarm["days_left"] == 10
    assert fired.await_count == 2


async def test_a_swap_on_disk_keeps_the_alarm_and_notes_the_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cert_path, key_path = _pair(tmp_path, days=5)
    app = _app()
    settings = _settings(cert_path, key_path)
    monkeypatch.setattr(main_mod.notify, "fire_safe", AsyncMock())
    monkeypatch.setattr(main_mod, "_utcnow_for_tls", lambda: NOW)
    await main_mod._tls_expiry_check(app, settings)
    assert app.state._tls_status.alarm["band"] == 7
    _pair(tmp_path, days=365)
    await main_mod._tls_expiry_check(app, settings)
    alarm = app.state._tls_status.alarm
    assert alarm is not None and alarm["band"] == 7
    assert alarm["disk_differs"] is True


async def test_a_restart_with_the_renewed_certificate_clears_the_alarm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cert_path, key_path = _pair(tmp_path, days=5)
    app = _app()
    settings = _settings(cert_path, key_path)
    monkeypatch.setattr(main_mod.notify, "fire_safe", AsyncMock())
    monkeypatch.setattr(main_mod, "_utcnow_for_tls", lambda: NOW)
    await main_mod._tls_expiry_check(app, settings)
    assert app.state._tls_status.alarm["band"] == 7
    _pair(tmp_path, days=365)
    app.state.tls_at_start = inspect_tls(cert_path, key_path, now=NOW)
    await main_mod._tls_expiry_check(app, settings)
    assert app.state._tls_status.alarm is None


async def test_a_restart_does_not_repeat_the_webhook(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two fresh app objects with the same files fire once in total."""
    cert_path, key_path = _pair(tmp_path, days=5)
    settings = _settings(cert_path, key_path, data_dir=tmp_path)
    fired = AsyncMock()
    monkeypatch.setattr(main_mod.notify, "fire_safe", fired)
    monkeypatch.setattr(main_mod, "_utcnow_for_tls", lambda: NOW)
    first = _app()
    await main_mod._tls_expiry_check(first, settings)
    second = _app()
    await main_mod._tls_expiry_check(second, settings)
    assert fired.await_count == 1
    assert second.state._tls_status.alarm["band"] == 7
    state = json.loads((tmp_path / "tls-expiry-state.json").read_text())
    assert state == {"fingerprint": first.state.tls_at_start.fingerprint_sha256, "band": 7}


async def test_a_corrupt_state_file_reads_as_nothing_fired(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cert_path, key_path = _pair(tmp_path, days=5)
    settings = _settings(cert_path, key_path, data_dir=tmp_path)
    (tmp_path / "tls-expiry-state.json").write_text("{not json")
    fired = AsyncMock()
    monkeypatch.setattr(main_mod.notify, "fire_safe", fired)
    monkeypatch.setattr(main_mod, "_utcnow_for_tls", lambda: NOW)
    await main_mod._tls_expiry_check(_app(), settings)
    assert fired.await_count == 1


async def test_last_check_is_set_only_after_a_successful_inspect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cert_path, key_path = _pair(tmp_path, days=5)
    app = _app()
    settings = _settings(cert_path, key_path)

    def boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("the inspector fell over")

    monkeypatch.setattr("soc_ai.tls_status.inspect_tls", boom)
    with pytest.raises(RuntimeError):
        await main_mod._tls_expiry_check(app, settings)
    assert app.state._tls_status.last_check is None


async def test_tls_off_never_alarms(monkeypatch: pytest.MonkeyPatch) -> None:
    app = _app()
    settings = _settings(None, None)
    fired = AsyncMock()
    monkeypatch.setattr(main_mod.notify, "fire_safe", fired)
    await main_mod._tls_expiry_check(app, settings)
    assert fired.await_count == 0 and app.state._tls_status.alarm is None
