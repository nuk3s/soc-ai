"""The verdict-quality alarm had no way to reach a human.

Its two channels were an audit record, which nobody reads unprompted, and the
notification webhook, which is off by default and stays off on any install that
has not opted into egress. So on a stock deployment the Quality card on the
dashboard was the only surface where a verdict regression could be learned about
— a card you have to already suspect something to go and look at.

Every other standing condition in this product has a bell entry: a dependency
down, a broken audit chain, a dossier conflict. This is the same class of fact.
These tests hold it to the same contract as those three, and to the one that
took the longest to get right: **the id is the identity of the finding, not the
moment it was noticed.** The audit-chain entry was keyed on the detection stamp
once, which moved on every run, and the result was an undismissable danger
notification that stood for days.
"""

from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from pydantic import SecretStr
from soc_ai.api.webui import routes_meta
from soc_ai.config import Settings
from soc_ai.store import auth as auth_svc
from soc_ai.store import quality as quality_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations

_PREFIX = "quality-alarm:"


def _settings(**over: Any) -> Settings:
    kwargs: dict[str, Any] = {
        "so_host": "https://so.example.com",
        "so_username": "analyst",
        "so_password": SecretStr("password123"),
        "so_verify_ssl": False,
        "es_hosts": ["https://so.example.com:9200"],
        "litellm_base_url": "http://localhost:4000",
        "api_auth_required": False,
    }
    kwargs.update(over)
    return Settings(**kwargs)


async def _db(tmp_path: Any) -> tuple[Any, Settings]:
    settings = _settings(db_path=str(tmp_path / "quality.db"))
    engine = make_engine(settings)
    await run_migrations(engine)
    return make_sessionmaker(engine), settings


def _request(maker: Any, settings: Settings) -> Any:
    """The two attributes ``list_notifications`` reads off the app."""
    return SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(db_sessionmaker=maker, settings=settings))
    )


async def _seed(
    maker: Any,
    *,
    alarmed: bool,
    alarm_key: str | None,
    alarm_since: Any = None,
    ran_at: Any = None,
    reasons: list[str] | None = None,
    n_ok: int = 5,
    n_error: int = 0,
) -> None:
    """One snapshot row.

    ``ran_at`` is stamped over ``created_at`` after the insert, and every test
    that cares about identity sets it to something distinct. SQLite's
    ``func.now()`` has only second precision, so two rows written in the same
    test would otherwise share a ``created_at`` — and an id wrongly keyed on the
    run instead of the condition would look stable, which is the exact mistake
    these tests exist to catch.
    """
    async with maker() as db:
        row = await quality_svc.insert_snapshot(
            db,
            mode="graded",
            n_ok=n_ok,
            n_error=n_error,
            agreement_rate=0.4,
            fallback_rate=0.0,
            error_rate=0.0,
            verdict_counts={},
            latency_p50_ms=1000,
            batch_dir="evals/batch-x",
            alarmed=alarmed,
            alarm_reasons=reasons,
            alarm_key=alarm_key,
            alarm_since=alarm_since,
        )
        if ran_at is not None:
            row.created_at = ran_at
            await db.commit()


def _quality(notifs: list[Any]) -> list[Any]:
    return [n for n in notifs if n.id.startswith(_PREFIX)]


async def test_a_quality_regression_reaches_the_bell(tmp_path: Any) -> None:
    """THE delivery gap: an alarm that only the Quality card could report."""
    maker, settings = await _db(tmp_path)
    since = auth_svc.utcnow() - timedelta(hours=6)
    await _seed(
        maker,
        alarmed=True,
        alarm_key="agreement_drop",
        alarm_since=since,
        reasons=["agreement 0.40 against a median of 1.00"],
    )

    entries = _quality(await routes_meta.list_notifications(_request(maker, settings)))

    assert len(entries) == 1
    entry = entries[0]
    assert entry.tone == "danger"
    assert "agreement_drop" in entry.title
    assert "0.40" in entry.title
    assert entry.href == "/dashboard"


async def test_a_clean_trend_says_nothing(tmp_path: Any) -> None:
    maker, settings = await _db(tmp_path)
    await _seed(maker, alarmed=False, alarm_key=None)

    assert _quality(await routes_meta.list_notifications(_request(maker, settings))) == []


async def test_an_empty_trend_says_nothing(tmp_path: Any) -> None:
    """A fresh install has never run the nightly — that is not a finding."""
    maker, settings = await _db(tmp_path)

    assert _quality(await routes_meta.list_notifications(_request(maker, settings))) == []


async def test_the_id_is_the_condition_and_survives_re_observation(tmp_path: Any) -> None:
    """A dismissal must hold for as long as the operator's judgement does.

    The writer keeps ``alarm_since`` steady while a condition persists, so every
    night that re-observes the same condition mints the SAME id — which is the
    difference between one dismissal and a fresh danger notification every
    morning until somebody stops looking at the bell entirely.
    """
    maker, settings = await _db(tmp_path)
    now = auth_svc.utcnow()
    since = now - timedelta(days=2)
    await _seed(
        maker,
        alarmed=True,
        alarm_key="agreement_drop",
        alarm_since=since,
        ran_at=now - timedelta(days=1),
    )
    first = _quality(await routes_meta.list_notifications(_request(maker, settings)))[0]

    # Tonight re-observes the same condition: a new row on a different clock,
    # same key, same since. The run moved; the finding did not.
    await _seed(
        maker,
        alarmed=True,
        alarm_key="agreement_drop",
        alarm_since=since,
        ran_at=now,
        reasons=["agreement 0.20 against a median of 1.00"],
    )
    second = _quality(await routes_meta.list_notifications(_request(maker, settings)))[0]

    assert first.id == second.id
    # And the id carries BOTH halves of the identity — the condition and the
    # instance of it. Either alone is wrong in one direction: the key alone
    # would suppress every future agreement drop forever, the timestamp alone
    # says nothing about which condition it belongs to.
    assert first.id.startswith(f"{_PREFIX}agreement_drop@")


async def test_a_new_condition_arrives_undismissed(tmp_path: Any) -> None:
    """A different code, or the same code raised again, is a different finding."""
    maker, settings = await _db(tmp_path)
    await _seed(
        maker,
        alarmed=True,
        alarm_key="agreement_drop",
        alarm_since=auth_svc.utcnow() - timedelta(days=2),
    )
    first = _quality(await routes_meta.list_notifications(_request(maker, settings)))[0]

    await _seed(
        maker,
        alarmed=True,
        alarm_key="agreement_drop+fallback_jump",
        alarm_since=auth_svc.utcnow(),
    )
    second = _quality(await routes_meta.list_notifications(_request(maker, settings)))[0]

    assert first.id != second.id


async def test_the_bell_id_matches_the_quality_card_dismiss_id(tmp_path: Any) -> None:
    """One finding, two surfaces, one dismissal.

    The card already mints ``quality-alarm:<alarm_key>@<alarm_since>`` into the
    same client-side dismissed-id set the bell filters on. A different shape here
    would mean clearing the same alarm twice, in two places, every time.
    """
    maker, settings = await _db(tmp_path)
    now = auth_svc.utcnow().replace(microsecond=0)
    # A condition that started before tonight's run, so an id built from the run
    # instead of the finding would not match the card's.
    since = now - timedelta(days=3)
    await _seed(maker, alarmed=True, alarm_key="error_ceiling", alarm_since=since, ran_at=now)

    entry = _quality(await routes_meta.list_notifications(_request(maker, settings)))[0]

    # The card builds `${DISMISS_PREFIX}${alarm_key}@${alarm_since}` from the
    # SAME serialisation /quality/trend hands it.
    from soc_ai.api.webui._shared import _iso_utc

    assert entry.id == f"{_PREFIX}error_ceiling@{_iso_utc(since)}"


async def test_an_eval_that_crashed_is_not_reported_as_a_verdict_regression(
    tmp_path: Any,
) -> None:
    """ "The grader could not run" and "the verdicts got worse" are not the same
    sentence, and an operator who reads the second goes hunting a model problem
    that does not exist. The card already separates them; so does the bell."""
    maker, settings = await _db(tmp_path)
    await _seed(
        maker,
        alarmed=True,
        alarm_key="error_ceiling",
        alarm_since=auth_svc.utcnow(),
        n_ok=0,
        n_error=5,
        reasons=["5 of 5 eval runs errored"],
    )

    entry = _quality(await routes_meta.list_notifications(_request(maker, settings)))[0]

    assert "quality" not in entry.title.lower() or "eval" in entry.title.lower()
    assert "Nightly quality eval failing" in entry.title
    assert "5 of 5" in entry.title
    assert entry.tone == "warn"


async def test_a_mixed_alarm_leads_with_the_quality_half(tmp_path: Any) -> None:
    """Both conditions are true; the one about the verdicts is the headline."""
    maker, settings = await _db(tmp_path)
    await _seed(
        maker,
        alarmed=True,
        alarm_key="agreement_drop+error_ceiling",
        alarm_since=auth_svc.utcnow(),
        n_ok=2,
        n_error=3,
    )

    entry = _quality(await routes_meta.list_notifications(_request(maker, settings)))[0]

    assert entry.tone == "danger"
    assert "agreement_drop+error_ceiling" in entry.title


async def test_a_pre_0027_row_mints_no_entry(tmp_path: Any) -> None:
    """No identity means no dismissal, and an undismissable danger entry is the
    bug the audit-chain entry was fixed for. The card still shows the alarm."""
    maker, settings = await _db(tmp_path)
    await _seed(maker, alarmed=True, alarm_key=None, reasons=["something regressed"])

    assert _quality(await routes_meta.list_notifications(_request(maker, settings))) == []


async def test_the_bell_survives_a_quality_read_failure(tmp_path: Any) -> None:
    """Polled every 15s — one broken table must not take the whole bell down."""
    maker, settings = await _db(tmp_path)
    await _seed(maker, alarmed=True, alarm_key="agreement_drop")

    async def _boom(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError("no such table: quality_snapshots")

    with patch.object(routes_meta.quality_svc, "recent_snapshots", _boom):
        notifs = await routes_meta.list_notifications(_request(maker, settings))

    assert _quality(notifs) == []
