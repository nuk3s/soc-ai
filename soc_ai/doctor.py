"""Dependency-surface health checks behind ``soc-ai doctor``.

One command an installer/operator runs right after setup — or when something is
wrong — that probes every external dependency the app needs (config, the local
store + migration head, the Security Onion API, Elasticsearch, the LiteLLM
gateway, and the analyst model's actual fitness) and returns structured
pass/fail results. Pure logic lives here; ``soc_ai.cli`` owns argparse and the
table/JSON printing.

Design rules (mirrors ``soc_ai.webui.probes``):

- Every check is ISOLATED — it never raises, and one failing upstream never
  blocks the other checks (the network checks run concurrently).
- Every check is BOUNDED by a short timeout so a hung upstream degrades to a
  clear FAIL line, never a hang.
- Every failing line carries a ``hint`` naming what to do about it.
- No detail string may carry a secret — the reused probe helpers
  (:func:`soc_ai.webui.probes._safe_reason` / ``_scrub``) strip
  credential-shaped substrings.

Exit-code contract (:func:`exit_code`): 0 iff no check FAILed. WARN and INFO
never fail the doctor — they flag things that degrade gracefully.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from alembic.script import ScriptDirectory
from elasticsearch import ApiError, AuthenticationException
from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from soc_ai.config import Settings
from soc_ai.errors import SoAuthError
from soc_ai.so_client.auth import make_auth
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.store.db import _migration_config, make_engine
from soc_ai.webui.probes import _safe_reason, _scrub, list_gateway_models, probe_model_fitness

CheckStatus = Literal["PASS", "WARN", "FAIL", "INFO"]


@dataclass
class CheckResult:
    """One doctor check outcome.

    ``hint`` is the actionable half of a non-PASS line — what the operator
    should DO about it (empty when nothing needs doing).
    """

    name: str
    status: CheckStatus
    detail: str
    hint: str = ""

    def as_dict(self) -> dict[str, str]:
        """JSON-friendly shape for ``soc-ai doctor --json``."""
        return {"name": self.name, "status": self.status, "detail": self.detail, "hint": self.hint}


def exit_code(results: list[CheckResult]) -> int:
    """Process exit code: 0 iff no REQUIRED check failed (WARN/INFO pass)."""
    return 1 if any(r.status == "FAIL" for r in results) else 0


# Per-check wall-clock bounds (seconds). Each check is wrapped in
# ``asyncio.wait_for`` so a hung upstream becomes a FAIL line quickly; a DOWN
# service (connection refused) fails near-instantly regardless. The fitness
# probe self-bounds at 30s (probes._FITNESS_TOTAL_TIMEOUT_S) — its wrapper is
# the belt to that suspender.
_STORE_TIMEOUT_S = 10.0
_SO_TIMEOUT_S = 8.0
_ES_TIMEOUT_S = 8.0
_GATEWAY_TIMEOUT_S = 12.0  # list_gateway_models carries its own 10s HTTP timeout
_FITNESS_TIMEOUT_S = 40.0

# Client-side per-request timeout for the doctor's ES calls — deliberately
# tighter than the app's es_request_timeout_s (30s) so a slow/wedged cluster
# fails fast here, and with retries off (one honest attempt, not 3).
_ES_REQUEST_TIMEOUT_S = 5


# ── Check 1: config ──────────────────────────────────────────────────────────


def check_config() -> tuple[Settings | None, CheckResult]:
    """Settings parse from env/.env — names the offending field(s) on failure."""
    try:
        settings = Settings()  # type: ignore[call-arg]  # required fields come from env/.env
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in err['loc']) or 'settings'}: {err['msg']}"
            for err in exc.errors()[:5]
        )
        return None, CheckResult(
            "config",
            "FAIL",
            _scrub(f"settings failed validation — {problems}")[:300],
            hint="fix the named field(s) in .env (see .env.example for the full surface)",
        )
    except Exception as exc:  # unreadable .env, bad encoding, … — still a graded FAIL
        return None, CheckResult(
            "config",
            "FAIL",
            _safe_reason(exc),
            hint="check that .env exists, is readable, and parses as KEY=value lines",
        )
    return settings, CheckResult("config", "PASS", "settings loaded from env/.env")


# ── Check 2: local store (DB + migration head + FTS5) ────────────────────────


async def check_store(settings: Settings) -> list[CheckResult]:
    """DB reachable/creatable; Alembic head matches code head; FTS5 available.

    Head derivation mirrors ``tests/test_hunts_store.py::
    test_migration_at_head_is_current``: the DB side is ``alembic_version.
    version_num``, the code side is the migration ScriptDirectory's current
    head. FTS5 absence is a WARN, never a FAIL — runbook/chat retrieval falls
    back to the legacy keyword ranker (see ``soc_ai.store.runbooks``).
    """
    db_path = settings.soc_ai_data_dir / "soc-ai.db"
    code_head = ScriptDirectory.from_config(_migration_config()).get_current_head() or "?"
    try:
        engine = make_engine(settings)
    except Exception as exc:
        return [
            CheckResult(
                "store",
                "FAIL",
                f"cannot open the store at {db_path}: {_safe_reason(exc)}",
                hint="check that SOC_AI_DATA_DIR exists and is writable by this user",
            )
        ]
    results: list[CheckResult] = []
    try:
        async with engine.connect() as conn:
            try:
                row = await conn.execute(text("SELECT version_num FROM alembic_version"))
                db_head = row.scalar_one_or_none()
            except OperationalError:
                db_head = None  # fresh store — no alembic_version table yet
            if db_head is None:
                results.append(
                    CheckResult(
                        "store",
                        "PASS",
                        f"store creatable at {db_path} — fresh (no migrations applied yet; "
                        f"code head {code_head})",
                        hint="migrations run automatically on `soc-ai serve` startup",
                    )
                )
            elif str(db_head) == code_head:
                results.append(
                    CheckResult("store", "PASS", f"{db_path} at migration head {db_head}")
                )
            else:
                results.append(
                    CheckResult(
                        "store",
                        "FAIL",
                        f"migration head mismatch — DB at {db_head}, code expects {code_head}",
                        hint="restart the server (`soc-ai serve` migrates to head on startup); "
                        "a DB AHEAD of the code means this checkout is older than the store",
                    )
                )
            # FTS5 availability — informational: the app falls back without it.
            has_fts5: bool | None
            try:
                fts_row = await conn.execute(
                    text("SELECT count(*) FROM pragma_module_list WHERE name = 'fts5'")
                )
                has_fts5 = bool(fts_row.scalar_one())
            except Exception:  # ancient SQLite without pragma_module_list
                has_fts5 = None
            if has_fts5:
                results.append(
                    CheckResult(
                        "store fts5",
                        "INFO",
                        "SQLite FTS5 available — BM25 runbook/chat retrieval active",
                    )
                )
            else:
                detail = (
                    "SQLite lacks FTS5 — runbook/chat retrieval falls back to the "
                    "legacy keyword ranker"
                    if has_fts5 is False
                    else "could not determine FTS5 availability"
                )
                results.append(
                    CheckResult(
                        "store fts5",
                        "WARN",
                        detail,
                        hint="the app still works; use a Python whose SQLite is built with "
                        "FTS5 to get BM25 retrieval",
                    )
                )
    except Exception as exc:
        results.append(
            CheckResult(
                "store",
                "FAIL",
                _safe_reason(exc),
                hint=f"check the store DB file at {db_path} (permissions / corruption)",
            )
        )
    finally:
        await engine.dispose()
    return results


# ── Check 3a: Security Onion API auth ────────────────────────────────────────


async def check_so_api(settings: Settings) -> list[CheckResult]:
    """Authenticate to the SO web API (Kratos session / Connect OAuth) and hit
    the read-only ``/api/info`` — the same first call the app itself makes."""
    name = "security onion"
    mode = "Connect OAuth" if settings.use_connect_api else "Kratos session"
    try:
        auth = make_auth(settings)
    except Exception as exc:
        return [
            CheckResult(name, "FAIL", _safe_reason(exc), hint="check the SO_* settings in .env")
        ]
    try:
        resp = await auth.request("GET", "/api/info")
        if resp.status_code == 200:
            return [CheckResult(name, "PASS", f"authenticated to {settings.so_host} ({mode})")]
        return [
            CheckResult(
                name,
                "FAIL",
                f"authenticated but GET /api/info answered HTTP {resp.status_code}",
                hint="the SO web API is up but unhappy — check the SO user's role grants "
                "(docs/SECURITY-ONION-SETUP.md)",
            )
        ]
    except SoAuthError as exc:
        msg = _scrub(str(exc))[:200]
        if "rejected credentials" in msg:
            return [
                CheckResult(
                    name,
                    "FAIL",
                    f"auth failed: {msg}",
                    hint="check SO_USERNAME / SO_PASSWORD (and that the account isn't locked)",
                )
            ]
        return [
            CheckResult(
                name,
                "FAIL",
                f"unreachable: {msg}",
                hint="check SO_HOST, DNS, TLS (SO_VERIFY_SSL / SO_CA_BUNDLE), and SO's "
                "firewall pinhole for this host (docs/SECURITY-ONION-SETUP.md)",
            )
        ]
    except Exception as exc:
        return [
            CheckResult(
                name,
                "FAIL",
                f"unreachable: {_safe_reason(exc)}",
                hint="check SO_HOST, network reach, and TLS (SO_VERIFY_SSL / SO_CA_BUNDLE)",
            )
        ]
    finally:
        await auth.aclose()


# ── Check 3b: Elasticsearch (auth + trivial search) ──────────────────────────


async def check_elasticsearch(settings: Settings) -> list[CheckResult]:
    """ES auth + a trivial search against the events index pattern.

    Distinguishes UNREACHABLE (transport error) from AUTH FAILED (401) from a
    pattern that matches nothing (WARN — the console would render empty).
    """
    name = "elasticsearch"
    pattern = settings.events_index_pattern
    probe_settings = settings.model_copy(
        update={"es_request_timeout_s": _ES_REQUEST_TIMEOUT_S, "es_max_retries": 0}
    )
    elastic = ElasticClient(probe_settings)
    try:
        info = await elastic.ping()
        cluster = str(info.get("cluster") or "") or "(unknown cluster)"
        version = str(info.get("version") or "") or "?"
        result = await elastic.search(pattern, {"match_all": {}}, size=0, track_total_hits=True)
        if result.total == 0:
            return [
                CheckResult(
                    name,
                    "WARN",
                    f"auth OK ({cluster}, ES {version}) but the events pattern {pattern!r} "
                    "matched no documents",
                    hint="check EVENTS_INDEX_PATTERN — a distributed grid needs the "
                    "cross-cluster prefix (`*:logs-*`); setup.sh auto-detects the right shape",
                )
            ]
        return [
            CheckResult(
                name,
                "PASS",
                f"{cluster} — ES {version}; {result.total_display} docs match {pattern!r}",
            )
        ]
    except AuthenticationException as exc:
        msg = _scrub(str(getattr(exc, "message", "") or ""))[:120]
        return [
            CheckResult(
                name,
                "FAIL",
                f"authentication failed (401){': ' + msg if msg else ''}",
                hint="check ES_USERNAME / ES_PASSWORD (see docs/SECURITY-ONION-SETUP.md "
                "for the SO role grant)",
            )
        ]
    except ApiError as exc:
        status = getattr(getattr(exc, "meta", None), "status", "?")
        msg = _scrub(str(getattr(exc, "message", "") or ""))[:120]
        return [
            CheckResult(
                name,
                "FAIL",
                f"ES refused the request (HTTP {status}): {msg}",
                hint="ES is up but rejected the call — check the ES user's role/privileges",
            )
        ]
    except Exception as exc:
        return [
            CheckResult(
                name,
                "FAIL",
                f"unreachable: {_safe_reason(exc)}",
                hint="check ES_HOSTS, network reach, TLS (ES_VERIFY_SSL), and SO's "
                "firewall pinhole for this host",
            )
        ]
    finally:
        with contextlib.suppress(Exception):  # best-effort cleanup on a probe path
            await elastic.aclose()


# ── Check 4: gateway (/v1/models + configured model ids) ─────────────────────


async def check_gateway(settings: Settings) -> list[CheckResult]:
    """Gateway ``/v1/models`` with the configured key; analyst + RAG model ids.

    A missing analyst/RAG id is a WARN, not a FAIL — it may still resolve via
    a gateway-side alias (and the RAG tiers are fail-soft by design).
    """
    ids, err = await list_gateway_models(settings)
    if err is not None:
        return [
            CheckResult(
                "gateway",
                "FAIL",
                f"cannot list models: {err}",
                hint="check LITELLM_BASE_URL / LITELLM_API_KEY (and LITELLM_VERIFY_SSL "
                "for a self-signed gateway)",
            )
        ]
    results = [
        CheckResult("gateway", "PASS", f"{settings.litellm_base_url} serves {len(ids)} models")
    ]
    analyst = settings.analyst_model
    if analyst in ids:
        results.append(
            CheckResult("analyst model", "PASS", f"{analyst!r} is served by the gateway")
        )
    else:
        results.append(
            CheckResult(
                "analyst model",
                "WARN",
                f"{analyst!r} is not in the gateway's /v1/models list",
                hint="it may still resolve via a gateway alias — if completions 400, set "
                "ANALYST_MODEL to a listed id",
            )
        )
    for label, model_id in (
        ("rag embed model", settings.rag_embed_model),
        ("rag rerank model", settings.rag_rerank_model),
    ):
        configured = model_id.strip()
        if not configured:
            continue  # tier off — nothing to check
        if configured in ids:
            results.append(CheckResult(label, "PASS", f"{configured!r} is served by the gateway"))
        else:
            results.append(
                CheckResult(
                    label,
                    "WARN",
                    f"{configured!r} is not in the gateway's /v1/models list",
                    hint="the RAG tier is fail-soft (retrieval degrades to local FTS5) — "
                    "fix the model id or clear it to silence this",
                )
            )
    return results


# ── Check 5: model fitness (the E1.1 probe) ──────────────────────────────────


async def check_model_fitness(settings: Settings) -> list[CheckResult]:
    """Grade the analyst model via :func:`probe_model_fitness` — UNFIT = FAIL.

    This is the "silent all-fallback verdicts" trap: a model that lists on the
    gateway but can't hold structured output degrades EVERY investigation to a
    fallback needs_more_info verdict, and nothing else surfaces it.
    """
    fitness = await probe_model_fitness(settings)
    grade = str(fitness.get("grade", "fail"))
    detail = str(fitness.get("detail", ""))
    if grade == "pass":
        return [CheckResult("model fitness", "PASS", detail)]
    if grade == "degraded":
        return [
            CheckResult(
                "model fitness",
                "WARN",
                detail,
                hint="usable but degraded — the config console's fitness probe shows "
                "per-leg detail",
            )
        ]
    return [
        CheckResult(
            "model fitness",
            "FAIL",
            detail,
            hint="an unfit analyst model silently lands all-fallback needs_more_info "
            "verdicts — point ANALYST_MODEL at a model that passes structured output",
        )
    ]


# ── Check 6: egress posture (INFO only) ──────────────────────────────────────

# The doctor lines mirror the config console's egress-policy read-model
# (soc_ai.api.webui.routes_config.api_egress_policy) — same row builder, same
# wording — restricted to the always-relevant destinations. INFO only: posture
# is a fact to surface, never a pass/fail judgement.
_EGRESS_DOCTOR_IDS = ("oracle", "analyst_cloud", "notifications", "rag_gateway")


def check_egress_posture(settings: Settings) -> list[CheckResult]:
    """One INFO line per egress destination, worded like the egress-policy page."""
    # Heavy (FastAPI) import, only needed when the doctor runs — and importing
    # the REAL row builder is what keeps the wording consistent by construction.
    from soc_ai.api.webui.routes_config import _egress_destinations  # noqa: PLC0415

    try:
        rows = _egress_destinations(settings)
    except Exception as exc:
        return [CheckResult("egress", "INFO", f"posture unavailable: {_safe_reason(exc)}")]
    zero_egress = not any(row["enabled"] for row in rows)
    results = [
        CheckResult(
            "egress",
            "INFO",
            "zero egress: "
            + ("yes — every egress destination is disabled" if zero_egress else "no"),
        )
    ]
    for row in rows:
        if row["id"] not in _EGRESS_DOCTOR_IDS:
            continue
        state = "ON" if row["enabled"] else "off"
        results.append(
            CheckResult(
                f"egress: {row['id']}",
                "INFO",
                f"{state} — {row['label']}; redaction: {row['redaction']}",
            )
        )
    return results


# ── Check 7: blocklist feed freshness (WARN, never FAIL) ─────────────────────

# Source → on-disk filename, mirroring the loaders in
# soc_ai.enrichment.blocklists (each loader reads exactly this file and records
# its mtime into BlocklistDB.file_mtimes). internal_seed is EXCLUDED on
# purpose: it is operator-curated, not a refreshed feed, so mtime age says
# nothing about its health.
_BLOCKLIST_FEED_FILES: dict[str, str] = {
    "urlhaus": "urlhaus.csv",
    "threatfox": "threatfox.json",
    "feodo": "feodo.csv",
    "tor": "tor_exits.txt",
    "spamhaus_drop": "spamhaus_drop.txt",
}


def check_blocklists(settings: Settings) -> list[CheckResult]:
    """Blocklist feed freshness — file mtime vs ``blocklist_stale_threshold_days``
    (the existing freshness notion the audit warning uses). WARN only: triage is
    fail-open with stale or absent feeds."""
    name = "blocklists"
    configured = [s for s in settings.blocklist_sources if s in _BLOCKLIST_FEED_FILES]
    if not configured:
        return [CheckResult(name, "INFO", "no refreshable blocklist feeds configured")]
    threshold_days = settings.blocklist_stale_threshold_days
    now = datetime.now(UTC)
    missing: list[str] = []
    stale: list[str] = []
    fresh = 0
    for source in configured:
        path = settings.blocklist_data_dir / _BLOCKLIST_FEED_FILES[source]
        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
        except OSError:
            missing.append(source)
            continue
        age_days = (now - mtime).total_seconds() / 86400.0
        if age_days > threshold_days:
            stale.append(f"{source} ({age_days:.0f}d old)")
        else:
            fresh += 1
    if not missing and not stale:
        return [
            CheckResult(
                name,
                "PASS",
                f"{fresh} feed(s) fresh (refreshed within {threshold_days}d) in "
                f"{settings.blocklist_data_dir}",
            )
        ]
    parts = []
    if missing:
        parts.append("never refreshed: " + ", ".join(missing))
    if stale:
        parts.append(f"stale (>{threshold_days}d): " + ", ".join(stale))
    return [
        CheckResult(
            name,
            "WARN",
            "; ".join(parts),
            hint="run `soc-ai blocklists refresh` (abuse.ch feeds need ABUSE_CH_AUTH_KEY; "
            "docs/BLOCKLISTS.md) — triage keeps working with stale/absent feeds (fail-open)",
        )
    ]


# ── Runner ───────────────────────────────────────────────────────────────────


async def _isolated(
    name: str, coro: Awaitable[list[CheckResult]], timeout_s: float
) -> list[CheckResult]:
    """Bound one check: a hung upstream or an unexpected bug becomes a FAIL
    line — one check can never block, hang, or crash the others."""
    try:
        return await asyncio.wait_for(coro, timeout=timeout_s)
    except TimeoutError:
        return [
            CheckResult(
                name,
                "FAIL",
                f"check timed out after {timeout_s:.0f}s",
                hint="the service accepted the connection but hung — check its health "
                "and the network path",
            )
        ]
    except Exception as exc:
        return [
            CheckResult(
                name,
                "FAIL",
                _safe_reason(exc),
                hint="unexpected doctor error — rerun with --json and report it",
            )
        ]


async def run_doctor(settings: Settings | None = None) -> list[CheckResult]:
    """Run every doctor check; return the results in display order.

    ``settings=None`` (the CLI path) loads Settings from env/.env as check 1;
    when that fails the dependent checks are skipped (nothing can run without
    a config) and the single FAIL comes back. Passing a ``Settings`` (tests /
    embedding) skips the env load but still records config as PASS.
    """
    results: list[CheckResult] = []
    if settings is None:
        settings, cfg = check_config()
        results.append(cfg)
        if settings is None:
            results.append(
                CheckResult(
                    "checks",
                    "INFO",
                    "store / security onion / elasticsearch / gateway / model checks "
                    "skipped — settings did not load",
                )
            )
            return results
    else:
        results.append(CheckResult("config", "PASS", "settings loaded"))

    # Independent upstreams — run concurrently so a slow one doesn't serialize
    # the rest; each is individually bounded and never raises.
    batches = await asyncio.gather(
        _isolated("store", check_store(settings), _STORE_TIMEOUT_S),
        _isolated("security onion", check_so_api(settings), _SO_TIMEOUT_S),
        _isolated("elasticsearch", check_elasticsearch(settings), _ES_TIMEOUT_S),
        _isolated("gateway", check_gateway(settings), _GATEWAY_TIMEOUT_S),
        _isolated("model fitness", check_model_fitness(settings), _FITNESS_TIMEOUT_S),
    )
    for batch in batches:
        results.extend(batch)
    results.extend(check_egress_posture(settings))
    results.extend(check_blocklists(settings))
    return results
