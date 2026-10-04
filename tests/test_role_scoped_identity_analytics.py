"""The three role-scoped identity analytics that replace three role priors.

The priors tested the wrong fact. ``prior-defender-adjudication-on-server``
read new process names and never a Defender event: on the development range it
missed all 10 Defender detections and fired 73 times on versioned updater
names. The audit-policy and group-change priors read new logon accounts and
never event 4719 or 4728, 4732, 4756. Each analytic below reads the event its
title names, and each carries the role gate the prior had.

Every clause has three tests: the positive document, the benign twin, and the
same positive document on a host in the wrong role.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import patch

import pytest
from soc_ai.config import Settings
from soc_ai.hunting import sweep as sweep_mod
from soc_ai.hunting.catalog_tiers import effective_catalog
from soc_ai.hunting.execute import Candidate, SpecRun, _candidates_from, apply_role_gate
from soc_ai.hunting.findings import candidate_findings, spec_report
from soc_ai.hunting.ledger import analytic_ledger
from soc_ai.hunting.match import detection_matches, precondition_matches
from soc_ai.hunting.spec import CATALOG_DIR, HuntSpec, load_catalog
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import EntityObservation, HostDossier, HostDossierField
from sqlalchemy import select

CATALOG = load_catalog(CATALOG_DIR)
DEFENDER = "identity-defender-detection"
AUDIT = "identity-4719-audit-policy-change"
GROUP = "identity-privileged-group-change"
RETIRED = (
    "prior-defender-adjudication-on-server",
    "prior-audit-policy-changed-on-dc",
    "prior-privileged-group-membership-changed",
)

_NOW = datetime(2026, 9, 18, 12, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Documents, in the shape the grid writes them
# ---------------------------------------------------------------------------


def _defender(code: str = "1116", **extra: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "event.code": code,
        "event.provider": "Microsoft-Windows-Windows Defender",
        "host.name": "srv01",
        "winlog.channel": "Microsoft-Windows-Windows Defender/Operational",
        "winlog.event_data.threat_name": "HackTool:Win32/Example.A",
        "winlog.event_data.Severity Name": "Severe",
        "winlog.event_data.Path": "file:_C:\\Users\\Public\\tool.exe",
        "winlog.event_data.Action Name": "Remove",
    }
    doc.update(extra)
    return doc


def _security(code: str, **extra: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "event.code": code,
        "event.provider": "Microsoft-Windows-Security-Auditing",
        "winlog.channel": "Security",
        "host.name": "dc01",
        "winlog.event_data.SubjectUserName": "ops-admin",
    }
    doc.update(extra)
    return doc


def _run(spec: HuntSpec, *candidates: Candidate, matched: int | None = None) -> SpecRun:
    return SpecRun(
        spec_id=spec.id,
        since="now-24h",
        until="now",
        blind=False,
        precondition_docs=100,
        matched_docs=sum(c.doc_count for c in candidates) if matched is None else matched,
        candidates=list(candidates),
    )


def _candidate(spec: HuntSpec, key: str, docs: int = 1, **extra: Any) -> Candidate:
    return Candidate(
        spec_id=spec.id,
        scope_key=key,
        scope_kind=spec.scope_kind,
        doc_count=docs,
        sample_ids=(f"{key}-doc",),
        anchor_id=f"{key}-doc",
        anchor_index="logs-x",
        first_seen=None,
        last_seen=None,
        **extra,
    )


def _roles(table: dict[str, tuple[str | None, float]]):  # type: ignore[no-untyped-def]
    return lambda key: table.get(key, (None, 0.0))


def _gated(spec: HuntSpec, doc: dict[str, Any], role: tuple[str | None, float]) -> SpecRun:
    """One document through the clause tree and the role gate."""
    assert spec.detection is not None
    if not detection_matches(spec.detection, doc):
        return _run(spec)
    return apply_role_gate(
        spec, _run(spec, _candidate(spec, doc["host.name"])), _roles({doc["host.name"]: role})
    )


# ---------------------------------------------------------------------------
# The catalog
# ---------------------------------------------------------------------------


def test_the_three_priors_are_gone_and_the_three_analytics_load() -> None:
    for old in RETIRED:
        assert old not in CATALOG, f"{old} still ships"
    for new in (DEFENDER, AUDIT, GROUP):
        spec = CATALOG[new]
        assert spec.evaluator == "match"
        assert spec.no_benign_baseline
        assert spec.level == "critical"
        assert spec.scope_field == "host.name"
        assert spec.precondition is not None
        assert spec.details, f"{new} quotes no field in its finding"
    assert CATALOG[DEFENDER].roles == ["server", "domain_controller"]
    assert CATALOG[AUDIT].roles == ["domain_controller"]
    assert CATALOG[GROUP].roles == ["domain_controller"]


@pytest.mark.asyncio
async def test_the_effective_catalog_lists_them_live_with_a_ledger(
    settings_kratos: Settings,
) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    async with maker() as db:
        cat = await effective_catalog(db)
        ledgers = {
            sid: await analytic_ledger(db, sid, since=_NOW - timedelta(days=30), now=_NOW)
            for sid in (DEFENDER, AUDIT, GROUP)
        }
    await engine.dispose()
    for sid in (DEFENDER, AUDIT, GROUP):
        assert cat.status_of(sid) == ("shipped", "live")
        assert sid in cat.specs
        assert ledgers[sid].observations == 0 and ledgers[sid].sweeps == 0
    for old in RETIRED:
        assert old not in cat.listed


# ---------------------------------------------------------------------------
# Defender
# ---------------------------------------------------------------------------


def test_defender_fires_on_a_detection_and_its_action_on_a_server() -> None:
    spec = CATALOG[DEFENDER]
    for code in ("1116", "1117"):
        run = _gated(spec, _defender(code), ("server", 0.9))
        assert [c.scope_key for c in run.candidates] == ["srv01"]
    run = _gated(spec, _defender(**{"host.name": "dc01"}), ("domain_controller", 1.0))
    assert [c.scope_key for c in run.candidates] == ["dc01"]


def test_defender_twin_a_definition_update_does_not_match() -> None:
    """Event 2000 is the routine update that made the old prior's noise."""
    spec = CATALOG[DEFENDER]
    assert spec.detection is not None
    update = _defender("2000", **{"process.name": "mpam-d_bd_1.459.428.0.exe"})
    assert not detection_matches(spec.detection, update)
    # It is still on the plane, so the analytic is not blind on a quiet day.
    assert precondition_matches(spec, update)


def test_defender_twin_the_same_event_id_from_another_provider_does_not_match() -> None:
    spec = CATALOG[DEFENDER]
    assert spec.detection is not None
    other = _defender(**{"event.provider": "Example-Application"})
    assert not detection_matches(spec.detection, other)


def test_defender_on_a_workstation_does_not_fire() -> None:
    run = _gated(CATALOG[DEFENDER], _defender(), ("workstation", 0.9))
    assert run.candidates == []
    assert run.matched_docs == 0
    assert run.role_out_of_scope_docs == 1
    assert run.role_unconfirmed_docs == 0


def test_defender_level_follows_the_threat_severity() -> None:
    spec = CATALOG[DEFENDER]

    def bucket(*severities: str | None) -> dict[str, Any]:
        hits = []
        for i, sev in enumerate(severities):
            event_data: dict[str, Any] = {"threat_name": "HackTool:Win32/Example.A"}
            if sev is not None:
                event_data["Severity Name"] = sev
            hits.append(
                {
                    "_id": f"d{i}",
                    "_index": "logs-x",
                    "_source": {"host": {"name": "srv01"}, "winlog": {"event_data": event_data}},
                }
            )
        return {
            "scopes": {
                "buckets": [
                    {"key": "srv01", "doc_count": len(hits), "samples": {"hits": {"hits": hits}}}
                ]
            }
        }

    (low,), _ = _candidates_from(spec, bucket("Low"))
    assert low.level == "low"
    (mixed,), _ = _candidates_from(spec, bucket("Low", "Severe", "Moderate"))
    assert mixed.level == "critical"
    (unmapped,), _ = _candidates_from(spec, bucket(None, "Unknown"))
    assert unmapped.level is None
    finding = candidate_findings(spec, _run(spec, low))[0]
    assert finding["severity"] == "low"
    # No mapped severity: the spec's own level stands.
    assert candidate_findings(spec, _run(spec, unmapped))[0]["severity"] == "critical"


def test_defender_finding_quotes_the_threat_the_path_and_the_action() -> None:
    spec = CATALOG[DEFENDER]
    hits = [
        {
            "_id": "d1",
            "_index": "logs-x",
            "_source": {
                "host": {"name": "srv01"},
                "winlog": {
                    "event_data": {
                        "threat_name": "HackTool:Win32/Example.A",
                        "Path": "file:_C:\\Users\\Public\\tool.exe",
                        "Action Name": "Remove",
                        "Severity Name": "Severe",
                    }
                },
            },
        }
    ]
    aggs = {
        "scopes": {
            "buckets": [{"key": "srv01", "doc_count": 1, "samples": {"hits": {"hits": hits}}}]
        }
    }
    (candidate,), _ = _candidates_from(spec, aggs)
    assert dict(candidate.details) == {
        "threat": ("HackTool:Win32/Example.A",),
        "path": ("file:_C:\\Users\\Public\\tool.exe",),
        "action": ("Remove",),
    }
    detail = candidate_findings(spec, _run(spec, candidate))[0]["detail"]
    assert "threat: HackTool:Win32/Example.A" in detail
    assert "action: Remove" in detail


def test_the_aggregation_carries_the_quoted_fields_back() -> None:
    from soc_ai.hunting.execute import _agg_body

    source = _agg_body(CATALOG[DEFENDER])["scopes"]["aggs"]["samples"]["top_hits"]["_source"]
    for field in (
        "winlog.event_data.threat_name",
        "winlog.event_data.Path",
        "winlog.event_data.Action Name",
        "winlog.event_data.Severity Name",
        "host.name",
    ):
        assert field in source


# ---------------------------------------------------------------------------
# Audit policy, 4719
# ---------------------------------------------------------------------------


def _audit(**extra: Any) -> dict[str, Any]:
    return _security(
        "4719",
        **{
            "winlog.event_data.SubCategory": "Directory Service Access",
            "winlog.event_data.AuditPolicyChangesDescription": ["Success removed"],
            **extra,
        },
    )


def test_audit_policy_change_by_a_named_account_on_a_dc_fires() -> None:
    run = _gated(CATALOG[AUDIT], _audit(), ("domain_controller", 0.9))
    assert [c.scope_key for c in run.candidates] == ["dc01"]


def test_audit_policy_twin_a_group_policy_refresh_under_the_computer_account() -> None:
    spec = CATALOG[AUDIT]
    assert spec.detection is not None
    refresh = _audit(**{"winlog.event_data.SubjectUserName": "DC01$"})
    assert not detection_matches(spec.detection, refresh)


def test_audit_policy_twin_a_new_logon_account_is_not_an_audit_change() -> None:
    """The fact the old prior tested. A 4624 must not match a 4719 analytic."""
    spec = CATALOG[AUDIT]
    assert spec.detection is not None
    assert not detection_matches(spec.detection, _security("4624"))


def test_audit_policy_change_on_a_workstation_does_not_fire() -> None:
    run = _gated(CATALOG[AUDIT], _audit(), ("workstation", 1.0))
    assert run.candidates == [] and run.role_out_of_scope_docs == 1


def test_audit_policy_change_on_a_member_server_does_not_fire() -> None:
    run = _gated(CATALOG[AUDIT], _audit(), ("server", 1.0))
    assert run.candidates == []


# ---------------------------------------------------------------------------
# Privileged group membership, 4728 / 4732 / 4756
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("code", "group"),
    [
        ("4728", "Domain Admins"),
        ("4728", "Group Policy Creator Owners"),
        ("4732", "Administrators"),
        ("4732", "Remote Desktop Users"),
        ("4732", "DnsAdmins"),
        ("4756", "Enterprise Admins"),
        ("4756", "Schema Admins"),
    ],
)
def test_a_privileged_group_add_on_a_dc_fires(code: str, group: str) -> None:
    doc = _security(code, **{"winlog.event_data.TargetUserName": group})
    run = _gated(CATALOG[GROUP], doc, ("domain_controller", 0.9))
    assert [c.scope_key for c in run.candidates] == ["dc01"]


@pytest.mark.parametrize("group", ["Finance-Readers", "Domain Users", "Helpdesk"])
def test_group_twin_an_add_to_an_ordinary_group_does_not_match(group: str) -> None:
    spec = CATALOG[GROUP]
    assert spec.detection is not None
    doc = _security("4728", **{"winlog.event_data.TargetUserName": group})
    assert not detection_matches(spec.detection, doc)


def test_group_twin_a_removal_from_domain_admins_does_not_match() -> None:
    """4729 is a removal. The analytic reads adds only."""
    spec = CATALOG[GROUP]
    assert spec.detection is not None
    doc = _security("4729", **{"winlog.event_data.TargetUserName": "Domain Admins"})
    assert not detection_matches(spec.detection, doc)


def test_a_local_administrators_add_on_a_workstation_does_not_fire() -> None:
    doc = _security("4732", **{"winlog.event_data.TargetUserName": "Administrators"})
    run = _gated(CATALOG[GROUP], doc, ("workstation", 0.95))
    assert run.candidates == [] and run.role_out_of_scope_docs == 1


def test_every_listed_privileged_group_is_in_the_clause() -> None:
    spec = CATALOG[GROUP]
    assert spec.detection is not None
    clause = next(c for c in spec.detection.all if c.field == "winlog.event_data.TargetUserName")
    assert set(clause.value) == {
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators",
        "Account Operators",
        "Backup Operators",
        "Server Operators",
        "Print Operators",
        "DnsAdmins",
        "Group Policy Creator Owners",
        "Remote Desktop Users",
        "Distributed COM Users",
    }


# ---------------------------------------------------------------------------
# The role gate
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("spec_id", [DEFENDER, AUDIT, GROUP])
@pytest.mark.parametrize(
    "belief",
    [(None, 0.0), ("unknown", 0.9), ("workstation", 0.5), ("domain_controller", 0.89)],
)
def test_an_unplaced_host_is_reported_never_dropped(
    spec_id: str, belief: tuple[str | None, float]
) -> None:
    """Below the gate the analytic is blind for that host, and says so.

    Dropping the candidate would make an unclassified server a safe harbour.
    Firing would undo the scope. The run counts the documents and names the
    host, and it is not clean.
    """
    spec = CATALOG[spec_id]
    run = apply_role_gate(
        spec, _run(spec, _candidate(spec, "host-a", docs=3)), _roles({"host-a": belief})
    )
    assert run.candidates == []
    assert run.role_unconfirmed_docs == 3
    assert run.role_unconfirmed_hosts == ("host-a",)
    assert not run.clean
    gaps = [f for f in candidate_findings(spec, run) if f["category"] == "visibility_gap"]
    assert len(gaps) == 1
    assert "host-a" in gaps[0]["detail"]
    assert "Declare the role" in gaps[0]["detail"]


def test_the_gate_keeps_in_scope_hosts_and_splits_the_rest() -> None:
    spec = CATALOG[DEFENDER]
    run = apply_role_gate(
        spec,
        _run(
            spec,
            _candidate(spec, "srv01", docs=2),
            _candidate(spec, "ws01", docs=8),
            _candidate(spec, "new01", docs=1),
        ),
        _roles({"srv01": ("server", 1.0), "ws01": ("workstation", 0.9)}),
    )
    assert [c.scope_key for c in run.candidates] == ["srv01"]
    assert run.matched_docs == 2
    assert run.role_out_of_scope_docs == 8
    assert run.role_unconfirmed_docs == 1
    assert run.role_unconfirmed_hosts == ("new01",)
    narrative = spec_report(spec, run)["narrative"]
    assert "could not place the hosts of 1 document" in narrative


def test_a_spec_with_no_roles_passes_through_the_gate() -> None:
    spec = CATALOG["identity-4662-dcsync-nonmachine"]
    run = _run(spec, _candidate(spec, "someone"))
    assert apply_role_gate(spec, run, _roles({})) is run


def _base(**extra: Any) -> dict[str, Any]:
    spec: dict[str, Any] = {
        "id": "t-role",
        "title": "A test analytic",
        "detection": {"all": [{"field": "event.code", "value": "1"}]},
    }
    spec.update(extra)
    return spec


def test_a_role_gate_needs_a_host_scope() -> None:
    with pytest.raises(ValueError, match="names no host"):
        HuntSpec.model_validate(_base(roles=["server"], scope_field="user.name", scope_kind="user"))


def test_a_role_must_be_in_the_dossier_vocabulary() -> None:
    with pytest.raises(ValueError, match="unknown role"):
        HuntSpec.model_validate(_base(roles=["domain-controller"]))


def test_a_profile_spec_cannot_carry_a_top_level_role_gate() -> None:
    with pytest.raises(ValueError, match="only the match path reads"):
        HuntSpec.model_validate(
            {
                "id": "prior-x",
                "title": "A prior",
                "evaluator": "profile",
                "profile": {"dimension": "process_names", "roles": ["server"]},
                "roles": ["server"],
            }
        )


def test_a_detail_field_must_be_queryable() -> None:
    with pytest.raises(ValueError, match="OQL whitelist"):
        HuntSpec.model_validate(
            _base(details=[{"field": "winlog.event_data.NotAField", "label": "x"}])
        )


# ---------------------------------------------------------------------------
# The sweep, end to end against a dossier
# ---------------------------------------------------------------------------


async def _seed_role(db: Any, ip: str, name: str, role: str, confidence: float) -> None:
    host = HostDossier(host_key=ip, ip=ip)
    db.add(host)
    await db.flush()
    db.add(
        HostDossierField(
            dossier_id=host.id,
            field="role",
            inferred_value=role,
            inferred_confidence=confidence,
        )
    )
    db.add(HostDossierField(dossier_id=host.id, field="hostname", inferred_value=name))
    await db.commit()


@pytest.mark.asyncio
async def test_the_sweep_reads_the_dossier_role_and_writes_only_the_server_hit(
    settings_kratos: Settings,
) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    spec = CATALOG[DEFENDER]
    details = (("threat", ("HackTool:Win32/Example.A",)), ("action", ("Remove",)))
    raw = _run(
        spec,
        _candidate(spec, "SRV01", docs=2, details=details, level="critical"),
        _candidate(spec, "ws01", docs=8),
        _candidate(spec, "ws02", docs=1),
    )

    async def fake_run_spec(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        return raw

    async with maker() as db:
        await _seed_role(db, "192.0.2.10", "srv01.example.test", "server", 0.9)
        await _seed_role(db, "192.0.2.21", "ws01", "workstation", 0.9)
        await _seed_role(db, "192.0.2.22", "ws02", "workstation", 0.5)

    with patch.object(sweep_mod, "run_spec", fake_run_spec):
        async with maker() as session:
            run, hunt_id = await sweep_mod.sweep_spec(
                spec,
                elastic=None,  # type: ignore[arg-type]
                settings=settings_kratos,
                session=session,
                since="now-24h",
                until="now",
                now=_NOW,
            )
            observations = (await session.execute(select(EntityObservation))).scalars().all()
    await engine.dispose()

    assert [c.scope_key for c in run.candidates] == ["SRV01"]
    assert run.role_out_of_scope_docs == 8
    assert run.role_unconfirmed_hosts == ("ws02",)
    assert [o.entity_key for o in observations] == ["SRV01"]
    obs = observations[0]
    assert obs.kind == "prior_no_baseline"
    assert "threat: HackTool:Win32/Example.A" in (obs.summary or "")
    assert obs.evidence_json["details"]["action"] == ["Remove"]
    assert obs.evidence_json["level"] == "critical"
    # The unplaced workstation is reported as a coverage gap on a hunt row.
    assert hunt_id is not None


# ---------------------------------------------------------------------------
# The Sigma bridge
# ---------------------------------------------------------------------------


def test_the_sigma_bridge_grounds_a_draft_on_the_event_fields() -> None:
    """A Sigma rule drafted from one of these findings needs the event code,
    the provider and the discriminating value. The evidence string is what the
    drafter keys the rule on."""
    from soc_ai.api.webui.routes_detection import _build_evidence

    spec = CATALOG[DEFENDER]
    finding = candidate_findings(spec, _run(spec, _candidate(spec, "srv01", level="critical")))[0]
    assert finding["category"] == "threat" and finding["citations"]
    doc = {
        "_id": "srv01-doc",
        "_source": {
            "event": {"code": "1116", "provider": "Microsoft-Windows-Windows Defender"},
            "host": {"name": "srv01"},
            "winlog": {
                "event_data": {"threat_name": "HackTool:Win32/Example.A", "Severity Name": "Severe"}
            },
        },
    }
    evidence = _build_evidence(finding, [doc])
    assert "event.code=1116" in evidence
    assert "event.provider=Microsoft-Windows-Windows Defender" in evidence
    assert "winlog.event_data.threat_name=HackTool:Win32/Example.A" in evidence

    group = CATALOG[GROUP]
    finding = candidate_findings(group, _run(group, _candidate(group, "dc01")))[0]
    doc = {
        "_id": "dc01-doc",
        "_source": {
            "event": {"code": "4728"},
            "winlog": {
                "channel": "Security",
                "event_data": {"TargetUserName": "Domain Admins", "SubjectUserName": "ops-admin"},
            },
        },
    }
    evidence = _build_evidence(finding, [doc])
    assert "event.code=4728" in evidence
    assert "winlog.event_data.TargetUserName=Domain Admins" in evidence
