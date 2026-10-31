"""Earlier conclusions: a new hunt reads what the hunts before it concluded.

Prod, 2026-10-24: leads 46, 48, 49 and 50 formed on one host within 21 h, and
each hunt started with no knowledge of the conclusion before it. A closed lead
does not absorb new observations (owner design, kept), so the related-leads
panel never showed a promoted lead. The scheduled runs of 10-27, 10-28 and
10-29 ran the same objective: the 10-27 run named the test workspace behind the
exploit, and the 10-29 run could not name the driver.

soc_ai.hunting.earlier reads the promoted leads on the entities a new lead
names, and the last complete runs of a scheduled objective. It hands the hunt
a block of claims to check. These tests seed TEST-NET data relative to now.
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from soc_ai.agent.hunt import HuntFinding
from soc_ai.agent.hunt_gates import _validate_hunt_findings
from soc_ai.config import Settings
from soc_ai.hunting import earlier
from soc_ai.store import hunts as hunt_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store import leads as leads_store
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import EntityObservation, Hunt, Investigation, Lead
from sqlalchemy import select

_ULID = re.compile(r"\b[0-9A-HJKMNP-TV-Z]{26}\b")
_LEAD_ID = re.compile(r"\blead \d+")
_OBJECTIVE = "Hunt for webshell uploads to the web tier"


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _stamp(at: datetime) -> str:
    return at.strftime("%Y-%m-%d %H:%M")


async def _store(settings: Settings) -> tuple[Any, Any]:
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


# ── leads ───────────────────────────────────────────────────────────────────


async def _lead(maker: Any, subject: str, *, also: tuple[str, ...] = ()) -> int:
    """An open lead whose one observation is about ``subject``.

    ``also`` are hosts the lead only names: its observations mention them.
    """
    async with maker() as db:
        lead = Lead(
            status="open",
            entities_json=[["host", subject], *[["host", a] for a in also]],
            kinds_json=["alert"],
            weight_at_formation=1.5,
            shadow=False,
        )
        db.add(lead)
        await db.commit()
        await db.refresh(lead)
        db.add(
            EntityObservation(
                entity_kind="host",
                entity_key=subject,
                kind="alert",
                spec_id="alert",
                fingerprint=f"fp-{lead.id}",
                summary="ET EXPLOIT web exploit: true positive at 0.70",
                lead_id=lead.id,
            )
        )
        await db.commit()
        return int(lead.id)


async def _investigation(
    maker: Any,
    *,
    title: str = "Host exploits the web app",
    verdict: str | None = "true_positive",
    confidence: float | None = 0.72,
    summary: str | None = "Host 192.0.2.30 sent the exploit.",
    status: str = "complete",
    fallback: bool = False,
) -> str:
    async with maker() as db:
        inv = await inv_svc.create(
            db,
            alert_es_id="docAAAAAAAAAAAAAAAAA",
            started_by="system:hunt",
            rule_name=title,
            kind="hunt",
        )
        if status != "running":
            await inv_svc.finalize(
                db, inv.id, status=status, verdict=verdict, confidence=confidence, summary=summary
            )
        if fallback:
            row = await db.get(Investigation, inv.id)
            assert row is not None
            row.is_fallback = True
            await db.commit()
        return inv.id


async def _promote(maker: Any, lead_id: int, runs: list[str], *, at: datetime) -> None:
    """Close the lead as promoted, the way the settle rule does, with one entry per run."""
    async with maker() as db:
        rows = {
            r.id: r
            for r in (
                await db.scalars(select(Investigation).where(Investigation.id.in_(runs)))
            ).all()
        }
        await leads_store.mark_promoted(
            db,
            lead_id,
            investigation_id=runs[0],
            by=leads_store.SYSTEM_HUNT_ACTOR,
            reason=leads_store.PROMOTED_FINDING_REASON,
            verdicts=[
                {
                    "ordinal": i,
                    "investigation_id": inv_id,
                    "verdict": rows[inv_id].verdict,
                    "confidence": rows[inv_id].confidence,
                }
                for i, inv_id in enumerate(runs)
            ],
            hunt_id="hunt-of-the-old-lead",
            now=at,
        )


async def test_a_lead_hunt_reads_the_promoted_lead_on_the_same_entity(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _store(settings_kratos)
    now = _now()
    old = await _lead(maker, "192.0.2.10")
    i2 = await _investigation(
        maker,
        title="Host probes the web app",
        verdict="needs_more_info",
        confidence=0.5,
        summary="The probe reached the app.",
    )
    i1 = await _investigation(
        maker,
        summary="Host 192.0.2.30 sent the exploit to 192.0.2.10. Second sentence.",
    )
    # Recorded NMI first: the true positive still leads the list.
    await _promote(maker, old, [i2, i1], at=now - timedelta(days=1))
    new = await _lead(maker, "192.0.2.10")

    block = await earlier.earlier_for_lead(maker, new, now=now)

    assert block is not None
    text = block.text
    assert text.startswith(
        "Earlier conclusions about the entities of this lead. They come from leads that "
        "closed as promoted in the last 7 days:\n"
    )
    assert (
        f"- A lead on 192.0.2.10 closed as promoted at {_stamp(now - timedelta(days=1))} UTC."
        in text
    )
    tp = (
        '  - Investigation "Host exploits the web app": true positive at 0.72. '
        'It wrote: "Host 192.0.2.30 sent the exploit to 192.0.2.10."'
    )
    assert tp in text
    assert text.index(tp) < text.index('Investigation "Host probes the web app"')
    assert "needs more info at 0.50" in text
    assert "Second sentence" not in text
    for line in earlier.CLAIMS_RULE:
        assert line in text
    # No record id reaches the model, so the hunt cannot cite one.
    assert not _LEAD_ID.search(text)
    assert not _ULID.search(text)
    assert block.refs == {"leads": [str(old)], "investigations": [i1, i2]}
    await engine.dispose()


async def test_the_other_end_of_an_alert_is_read(settings_kratos: Settings) -> None:
    """Prod lead 47 named the target that lead 46 was about."""
    engine, maker = await _store(settings_kratos)
    now = _now()
    old = await _lead(maker, "192.0.2.10")
    await _promote(maker, old, [await _investigation(maker)], at=now - timedelta(hours=2))
    new = await _lead(maker, "192.0.2.20", also=("192.0.2.10",))

    block = await earlier.earlier_for_lead(maker, new, now=now)

    assert block is not None
    assert "- A lead on 192.0.2.10 closed as promoted" in block.text
    await engine.dispose()


async def test_a_lead_that_only_mentions_the_same_host_is_not_read(
    settings_kratos: Settings,
) -> None:
    """Negative control: two leads that mention the same DNS server are not related."""
    engine, maker = await _store(settings_kratos)
    now = _now()
    old = await _lead(maker, "192.0.2.10", also=("192.0.2.53",))
    await _promote(maker, old, [await _investigation(maker)], at=now - timedelta(hours=2))
    new = await _lead(maker, "192.0.2.20", also=("192.0.2.53",))

    assert await earlier.earlier_for_lead(maker, new, now=now) is None
    await engine.dispose()


async def test_a_promotion_older_than_seven_days_is_not_read(settings_kratos: Settings) -> None:
    engine, maker = await _store(settings_kratos)
    now = _now()
    old = await _lead(maker, "192.0.2.10")
    await _promote(maker, old, [await _investigation(maker)], at=now - timedelta(days=8))
    new = await _lead(maker, "192.0.2.10")

    assert await earlier.earlier_for_lead(maker, new, now=now) is None
    await engine.dispose()


async def test_a_promoted_lead_on_another_entity_is_not_read(settings_kratos: Settings) -> None:
    engine, maker = await _store(settings_kratos)
    now = _now()
    old = await _lead(maker, "192.0.2.22")
    await _promote(maker, old, [await _investigation(maker)], at=now - timedelta(hours=1))
    new = await _lead(maker, "192.0.2.10")

    assert await earlier.earlier_for_lead(maker, new, now=now) is None
    await engine.dispose()


async def test_a_dismissed_or_reopened_lead_is_not_read(settings_kratos: Settings) -> None:
    """The approved scope is promoted leads only."""
    engine, maker = await _store(settings_kratos)
    now = _now()
    dismissed = await _lead(maker, "192.0.2.10")
    async with maker() as db:
        await leads_store.dismiss(
            db,
            dismissed,
            reason="authorized_test",
            note="the operator's test",
            by="alice",
            now=now - timedelta(hours=3),
        )
    reopened = await _lead(maker, "192.0.2.10")
    await _promote(maker, reopened, [await _investigation(maker)], at=now - timedelta(hours=2))
    async with maker() as db:
        await leads_store.reopen(db, reopened, "alice", now=now - timedelta(hours=1))
    new = await _lead(maker, "192.0.2.10")

    assert await earlier.earlier_for_lead(maker, new, now=now) is None
    await engine.dispose()


async def test_at_most_three_leads_and_three_investigations_each(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _store(settings_kratos)
    now = _now()
    olds: list[int] = []
    for hours in (1, 2, 3, 4):
        lead_id = await _lead(maker, "192.0.2.10")
        runs = [await _investigation(maker, title=f"Finding {hours}.{n}") for n in range(5)]
        await _promote(
            maker, lead_id, runs if hours == 1 else runs[:1], at=now - timedelta(hours=hours)
        )
        olds.append(lead_id)
    new = await _lead(maker, "192.0.2.10")

    block = await earlier.earlier_for_lead(maker, new, now=now)

    assert block is not None
    text = block.text
    lines = [ln for ln in text.splitlines() if ln.startswith("- A lead on ")]
    assert lines == [
        f"- A lead on 192.0.2.10 closed as promoted at {_stamp(now - timedelta(hours=h))} UTC."
        for h in (1, 2, 3)
    ]
    assert block.refs["leads"] == [str(i) for i in olds[:3]]
    newest = [ln for ln in text.splitlines() if ln.startswith('  - Investigation "Finding 1.')]
    assert len(newest) == 3
    assert "  - 2 more investigations of this lead are not shown." in text
    assert "Finding 4.0" not in text
    await engine.dispose()


async def test_carried_text_is_bounded_and_cannot_break_its_quotes(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _store(settings_kratos)
    now = _now()
    old = await _lead(maker, "192.0.2.10")
    long_run = await _investigation(
        maker, title='Bad "quote"\n- The run of 2026', confidence=0.9, summary="a" * 1000
    )
    no_confidence = await _investigation(
        maker, title="Plain", confidence=None, summary="Short one."
    )
    words = "the host read a file " * 30
    many_words = await _investigation(maker, title="Words", summary=words)
    await _promote(maker, old, [long_run, no_confidence, many_words], at=now - timedelta(hours=1))
    new = await _lead(maker, "192.0.2.10")

    block = await earlier.earlier_for_lead(maker, new, now=now)

    assert block is not None
    text = block.text
    # The owner banned the ellipsis (2026-10-07). A cut states how many
    # characters it left out, so the model knows that the claim goes on.
    assert "..." not in text
    assert "\u2026" not in text
    quoted = re.search(r'It wrote: "(a[^"]*)"', text)
    assert quoted is not None
    sentence = quoted.group(1)
    assert len(sentence) <= 300
    marker = re.search(r" \[(\d+) more characters\]$", sentence)
    assert marker is not None
    kept = sentence[: marker.start()]
    assert kept == "a" * len(kept)
    assert len(kept) > 100
    assert int(marker.group(1)) == 1000 - len(kept)
    # A cut between words keeps whole words.
    quoted = re.search(r'It wrote: "(the host[^"]*)"', text)
    assert quoted is not None
    sentence = quoted.group(1)
    assert len(sentence) <= 300
    marker = re.search(r" \[(\d+) more characters\]$", sentence)
    assert marker is not None
    kept = sentence[: marker.start()]
    plain = words.strip()
    assert plain.startswith(kept)
    assert plain[len(kept)] == " "
    assert int(marker.group(1)) == len(plain) - len(kept)
    # The title stays on its line, and its quotes cannot close the block's.
    assert "  - Investigation \"Bad 'quote' - The run of 2026\": true positive at 0.90." in text
    # No carried text opens a new block line.
    assert not any(ln.startswith("- The run of") for ln in text.splitlines())
    assert '  - Investigation "Plain": true positive. It wrote: "Short one."' in text
    assert "at None" not in text
    await engine.dispose()


async def test_an_unsettled_investigation_reads_no_verdict(settings_kratos: Settings) -> None:
    engine, maker = await _store(settings_kratos)
    now = _now()
    old = await _lead(maker, "192.0.2.10")
    running = await _investigation(maker, title="Still running", status="running")
    fallback = await _investigation(maker, title="Fell back", fallback=True)
    await _promote(maker, old, [running, fallback], at=now - timedelta(hours=1))
    new = await _lead(maker, "192.0.2.10")

    block = await earlier.earlier_for_lead(maker, new, now=now)

    assert block is not None
    assert '  - Investigation "Still running": no verdict.' in block.text
    assert '  - Investigation "Fell back": no verdict.' in block.text
    assert "It wrote" not in block.text
    await engine.dispose()


async def test_reading_earlier_conclusions_changes_no_lead(settings_kratos: Settings) -> None:
    """A closed lead does not absorb new observations. The read writes nothing."""
    engine, maker = await _store(settings_kratos)
    now = _now()
    old = await _lead(maker, "192.0.2.10")
    await _promote(maker, old, [await _investigation(maker)], at=now - timedelta(hours=1))
    new = await _lead(maker, "192.0.2.10")

    async def snapshot() -> tuple[Any, ...]:
        async with maker() as db:
            lead = await db.get(Lead, old)
            assert lead is not None
            owners = (
                await db.scalars(select(EntityObservation.lead_id).order_by(EntityObservation.id))
            ).all()
            return (
                lead.status,
                lead.decisions_json,
                lead.investigation_id,
                lead.updated_at,
                list(owners),
            )

    before = await snapshot()
    assert await earlier.earlier_for_lead(maker, new, now=now) is not None
    after = await snapshot()

    assert after == before
    assert after[0] == "promoted"
    await engine.dispose()


async def _touch(maker: Any, lead_id: int, at: datetime) -> None:
    """A later write to a closed lead. Lead.updated_at moves on every write."""
    async with maker() as db:
        lead = await db.get(Lead, lead_id)
        assert lead is not None
        lead.updated_at = at
        await db.commit()


async def test_a_lead_touched_after_an_old_promotion_is_not_read(
    settings_kratos: Settings,
) -> None:
    """The window reads the time of the promotion. A later write does not move it."""
    engine, maker = await _store(settings_kratos)
    now = _now()
    old = await _lead(maker, "192.0.2.10")
    await _promote(maker, old, [await _investigation(maker)], at=now - timedelta(days=10))
    await _touch(maker, old, now - timedelta(hours=1))
    new = await _lead(maker, "192.0.2.10")

    assert await earlier.earlier_for_lead(maker, new, now=now) is None
    await engine.dispose()


async def test_the_leads_are_read_newest_promotion_first(settings_kratos: Settings) -> None:
    """A later write to an older promotion does not move it ahead of a newer one."""
    engine, maker = await _store(settings_kratos)
    now = _now()
    touched = await _lead(maker, "192.0.2.10")
    await _promote(maker, touched, [await _investigation(maker)], at=now - timedelta(hours=3))
    await _touch(maker, touched, now - timedelta(minutes=1))
    newer = await _lead(maker, "192.0.2.10")
    await _promote(maker, newer, [await _investigation(maker)], at=now - timedelta(hours=1))
    new = await _lead(maker, "192.0.2.10")

    block = await earlier.earlier_for_lead(maker, new, now=now)

    assert block is not None
    assert block.refs["leads"] == [str(newer), str(touched)]
    lines = [ln for ln in block.text.splitlines() if ln.startswith("- A lead on ")]
    assert lines == [
        f"- A lead on 192.0.2.10 closed as promoted at {_stamp(now - timedelta(hours=h))} UTC."
        for h in (1, 3)
    ]
    await engine.dispose()


async def test_the_lead_line_names_the_shared_entity_first(settings_kratos: Settings) -> None:
    """An earlier lead with 4 subjects names the one that the new lead names."""
    engine, maker = await _store(settings_kratos)
    now = _now()
    old = await _lead(maker, "192.0.2.30")
    async with maker() as db:
        for n, host in enumerate(("192.0.2.31", "192.0.2.32", "192.0.2.40")):
            db.add(
                EntityObservation(
                    entity_kind="host",
                    entity_key=host,
                    kind="alert",
                    spec_id="alert",
                    fingerprint=f"fp-{old}-{n}",
                    summary="ET EXPLOIT web exploit: true positive at 0.70",
                    lead_id=old,
                )
            )
        await db.commit()
    await _promote(maker, old, [await _investigation(maker)], at=now - timedelta(hours=1))
    new = await _lead(maker, "192.0.2.40")

    block = await earlier.earlier_for_lead(maker, new, now=now)

    assert block is not None
    assert (
        f"- A lead on 192.0.2.40, 192.0.2.30, 192.0.2.31 closed as promoted at "
        f"{_stamp(now - timedelta(hours=1))} UTC."
    ) in block.text
    await engine.dispose()


# ── scheduled runs ──────────────────────────────────────────────────────────


def _f(
    title: str,
    *,
    category: str = "threat",
    hosts: list[str] | None = None,
    citations: list[str] | None = None,
    severity: str = "high",
) -> dict[str, Any]:
    return {
        "title": title,
        "detail": f"{title}. The detail.",
        "severity": severity,
        "category": category,
        "hosts": hosts if hosts is not None else ["192.0.2.60"],
        "citations": citations if citations is not None else ["docCCCCCCCCCCCCCCCCC"],
    }


_FAILED = _f("Event search: could not run", category="visibility_gap", citations=[], severity="low")


async def _run(
    maker: Any,
    *,
    at: datetime,
    findings: list[dict[str, Any]],
    status: str = "complete",
    objective: str = _OBJECTIVE,
    narrative: str = "The run looked at the web tier.",
    partial: bool = False,
    synth: bool = False,
    links: dict[str, dict[str, Any]] | None = None,
) -> str:
    async with maker() as db:
        hunt = await hunt_svc.create(
            db,
            objective=objective,
            started_by="scheduler",
            kind="scheduled",
            starter="schedule",
            is_synth_eval=synth,
        )
        await hunt_svc.finalize(
            db,
            hunt.id,
            status=status,
            narrative=narrative,
            report={"findings": findings, "narrative": narrative},
            finding_plan=links,
        )
        await hunt_svc.append_events(
            db,
            hunt.id,
            [
                {
                    "sequence": 9,
                    "kind": "done",
                    "payload": {"finding_count": len(findings), "partial": partial},
                }
            ],
        )
        row = await db.get(Hunt, hunt.id)
        assert row is not None
        row.created_at = at
        await db.commit()
        return hunt.id


async def test_a_scheduled_hunt_reads_the_findings_of_its_last_complete_run(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _store(settings_kratos)
    now = _now()
    at = now - timedelta(days=2)
    await _run(
        maker,
        at=at,
        narrative="The run tied the upload to a lab. More.",
        findings=[
            _f(
                "No host logs on the target",
                category="visibility_gap",
                hosts=["192.0.2.10"],
                citations=["t_host_dossier:192.0.2.10"],
                severity="low",
            ),
            _f(
                "Host logs tie the upload to a lab",
                category="observation",
                hosts=["192.0.2.26"],
                citations=["docAAAAAAAAAAAAAAAAA", "docBBBBBBBBBBBBBBBBB"],
                severity="low",
            ),
            _f("Webshell upload to the web app"),
            _FAILED,
        ],
    )

    block = await earlier.earlier_for_objective(
        maker, "hunt for webshell uploads to the WEB tier", now=now
    )

    assert block is not None
    text = block.text
    assert text.startswith(
        "Earlier conclusions about this objective. They come from the last complete runs "
        "of the same objective:\n"
    )
    assert f"- The run of {_stamp(at)} UTC listed these findings:" in text
    observation = (
        '  - observation: "Host logs tie the upload to a lab". Hosts: 192.0.2.26. '
        "Documents: docAAAAAAAAAAAAAAAAA, docBBBBBBBBBBBBBBBBB."
    )
    assert observation in text
    assert text.index('  - threat: "Webshell upload to the web app"') < text.index(observation)
    assert "t_host_dossier" not in text
    assert "could not run" not in text
    assert "The run tied" not in text
    assert "More." not in text
    assert "  - 1 more finding of this run is not shown." in text
    for line in earlier.CLAIMS_RULE:
        assert line in text
    assert not _ULID.search(text)
    await engine.dispose()


async def test_a_conclusion_two_runs_back_is_still_read(settings_kratos: Settings) -> None:
    """Replay of the scheduled runs of 10-27, 10-28 and 10-29."""
    engine, maker = await _store(settings_kratos)
    now = _now()
    older = await _run(
        maker,
        at=now - timedelta(days=3),
        findings=[
            _f(
                "Host logs tie the exploit to the validation lab",
                category="observation",
                severity="low",
            ),
            _f(
                "Connect-back listener harness on host harness-01",
                category="observation",
                hosts=["192.0.2.70"],
                citations=["docDDDDDDDDDDDDDDDDD"],
                severity="low",
            ),
        ],
    )
    failed = await _run(maker, at=now - timedelta(days=2), findings=[], status="error")
    newer = await _run(
        maker, at=now - timedelta(days=1), findings=[_f("Webshell upload to the web app")]
    )

    block = await earlier.earlier_for_objective(maker, _OBJECTIVE, now=now)

    assert block is not None
    text = block.text
    first = text.index(f"- The run of {_stamp(now - timedelta(days=1))} UTC")
    second = text.index(f"- The run of {_stamp(now - timedelta(days=3))} UTC")
    assert first < second
    assert "Host logs tie the exploit to the validation lab" in text
    assert "192.0.2.70" in text
    assert block.refs["hunts"] == [newer, older]
    assert failed not in block.refs["hunts"]
    await engine.dispose()


async def test_an_old_run_is_read_only_when_it_is_the_newest(settings_kratos: Settings) -> None:
    """A weekly schedule still reads its last run. A newer run pushes it out."""
    engine, maker = await _store(settings_kratos)
    now = _now()
    weekly = await _run(maker, at=now - timedelta(days=8), findings=[_f("Old weekly finding")])

    block = await earlier.earlier_for_objective(maker, _OBJECTIVE, now=now)
    assert block is not None
    assert block.refs["hunts"] == [weekly]

    newer = await _run(maker, at=now - timedelta(days=1), findings=[_f("New daily finding")])
    block = await earlier.earlier_for_objective(maker, _OBJECTIVE, now=now)
    assert block is not None
    assert block.refs["hunts"] == [newer]
    assert "Old weekly finding" not in block.text
    await engine.dispose()


async def test_a_partial_a_blind_and_a_synth_eval_run_are_never_read(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _store(settings_kratos)
    now = _now()
    await _run(maker, at=now - timedelta(hours=1), findings=[_f("Partial")], partial=True)
    await _run(maker, at=now - timedelta(hours=2), findings=[_FAILED])
    await _run(maker, at=now - timedelta(hours=3), findings=[_f("Planted")], synth=True)

    assert await earlier.earlier_for_objective(maker, _OBJECTIVE, now=now) is None

    full = await _run(maker, at=now - timedelta(hours=4), findings=[_f("Full run finding")])
    block = await earlier.earlier_for_objective(maker, _OBJECTIVE, now=now)

    assert block is not None
    assert block.refs["hunts"] == [full]
    assert block.text.count("- The run of ") == 1
    assert f"- The run of {_stamp(now - timedelta(hours=4))} UTC" in block.text
    for title in ("Partial", "Planted"):
        assert title not in block.text
    await engine.dispose()


async def test_the_finding_verdict_is_read_live(settings_kratos: Settings) -> None:
    engine, maker = await _store(settings_kratos)
    now = _now()
    verdict_run = await _investigation(
        maker, title="Webshell upload to the web app", verdict="true_positive", confidence=0.6
    )
    await _run(
        maker,
        at=now - timedelta(days=1),
        findings=[_f("Webshell upload to the web app")],
        links={
            "0": hunt_svc.plan_entry(
                hunt_svc.LINK_ENDED, investigation_id=verdict_run, origin="opened"
            )
        },
    )
    # The analyst overrode the verdict after the run.
    async with maker() as db:
        row = await db.get(Investigation, verdict_run)
        assert row is not None
        row.verdict, row.confidence = "false_positive", 0.8
        await db.commit()

    block = await earlier.earlier_for_objective(maker, _OBJECTIVE, now=now)

    assert block is not None
    assert (
        '  - threat: "Webshell upload to the web app". Hosts: 192.0.2.60. '
        "Documents: docCCCCCCCCCCCCCCCCC. Investigation: false positive at 0.80." in block.text
    )
    assert block.refs["investigations"] == [verdict_run]
    assert not _ULID.search(block.text)

    queued = await _run(
        maker,
        at=now - timedelta(hours=1),
        status=hunt_svc.STATUS_INVESTIGATING,
        findings=[_f("Second webshell upload")],
        links={"0": hunt_svc.plan_entry(hunt_svc.LINK_QUEUED)},
    )
    block = await earlier.earlier_for_objective(maker, _OBJECTIVE, now=now)
    assert block is not None
    assert block.refs["hunts"][0] == queued
    assert 'threat: "Second webshell upload". Hosts: 192.0.2.60. ' in block.text
    assert "Documents: docCCCCCCCCCCCCCCCCC. Investigation: no verdict." in block.text
    await engine.dispose()


async def test_at_most_five_findings_a_run_and_ten_in_total(settings_kratos: Settings) -> None:
    engine, maker = await _store(settings_kratos)
    now = _now()
    for day in (1, 2, 3):
        titles = [f"Run {day} finding {n}" for n in range(7)]
        if day == 2:
            # A title the newer run already carries.
            titles[0] = "Run 1 finding 0"
        await _run(maker, at=now - timedelta(days=day), findings=[_f(t) for t in titles])

    block = await earlier.earlier_for_objective(maker, _OBJECTIVE, now=now)

    assert block is not None
    text = block.text
    finding_lines = [ln for ln in text.splitlines() if ln.startswith("  - threat: ")]
    assert len(finding_lines) == 10
    assert sum(1 for ln in finding_lines if '"Run 1 finding' in ln) == 5
    assert sum(1 for ln in finding_lines if '"Run 2 finding' in ln) == 5
    assert text.count('"Run 1 finding 0"') == 1
    assert "  - 2 more findings of this run are not shown." in text
    assert "  - 7 more findings of this run are not shown." in text
    third = text.index(f"- The run of {_stamp(now - timedelta(days=3))} UTC listed these findings:")
    assert text.index("  - 7 more findings of this run are not shown.") > third
    await engine.dispose()


async def test_a_run_with_no_finding_that_cites_a_document_says_so(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _store(settings_kratos)
    now = _now()
    at = now - timedelta(days=1)
    await _run(maker, at=at, findings=[_f("Uncited threat", citations=[])])

    block = await earlier.earlier_for_objective(maker, _OBJECTIVE, now=now)

    assert block is not None
    assert f"- The run of {_stamp(at)} UTC listed no finding that cites a document." in block.text
    assert "Uncited threat" not in block.text
    await engine.dispose()


class _BrokenSession:
    async def __aenter__(self) -> _BrokenSession:
        return self

    async def __aexit__(self, *_exc: Any) -> bool:
        return False

    async def execute(self, *_a: Any, **_k: Any) -> Any:
        raise RuntimeError("the store is down")

    async def scalars(self, *_a: Any, **_k: Any) -> Any:
        raise RuntimeError("the store is down")

    async def get(self, *_a: Any, **_k: Any) -> Any:
        raise RuntimeError("the store is down")


async def test_a_read_that_fails_starts_the_hunt_without_conclusions(
    caplog: pytest.LogCaptureFixture,
) -> None:
    def maker() -> _BrokenSession:
        return _BrokenSession()

    with caplog.at_level(logging.WARNING, logger="soc_ai.hunting.earlier"):
        assert await earlier.earlier_for_lead(maker, 7) is None
        assert await earlier.earlier_for_objective(maker, _OBJECTIVE) is None

    warnings = [r for r in caplog.records if r.name == "soc_ai.hunting.earlier"]
    assert len(warnings) == 2
    assert all(r.levelno == logging.WARNING for r in warnings)


def test_the_citation_gate_drops_a_citation_of_an_earlier_investigation() -> None:
    """PIN: an id from the block is not a document this hunt read."""
    findings = [
        HuntFinding(
            title="t",
            detail="d",
            severity="high",
            category="threat",
            hosts=["192.0.2.10"],
            citations=["01HZZZZZZZZZZZZZZZZZZZZZZZ", "lead 7"],
        )
    ]
    tool_results = [{"total": 1, "hits": [{"_id": "sREAL_PULLED_ID_42", "dataset": "zeek.conn"}]}]

    validated, _counts = _validate_hunt_findings(findings, tool_results)

    assert validated[0].citations == []
    assert validated[0].severity == "low"


def test_the_refs_sentence_names_the_records_for_the_analyst() -> None:
    sentence = earlier.refs_sentence(
        {"leads": ["46"], "investigations": ["INV-1"], "hunts": ["H-1", "H-2"]}
    )
    assert sentence == (
        "The earlier conclusions come from these records: lead 46; investigation INV-1; "
        "hunt H-1; hunt H-2."
    )
    assert earlier.refs_sentence({}) == ""
