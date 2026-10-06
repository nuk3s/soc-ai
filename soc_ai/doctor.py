"""Dependency-surface health checks behind ``soc-ai doctor``.

One command an installer/operator runs right after setup — or when something is
wrong — that probes every external dependency the app needs (config, the local
store + migration head, the Security Onion API, Elasticsearch, the audit write
grant, index-pattern dataset coverage, the LiteLLM gateway, and the analyst
model's actual fitness) and returns structured pass/fail results. Pure logic
lives here; ``soc_ai.cli`` owns argparse and the table/JSON printing.

One check looks inward instead of upstream: ``check_prompt_assets`` grades the
files this deployment's own system prompts are built from. It is here because
a doctor that only ever probes upstreams cannot see a packaging fault, and one
of those shipped an image whose prompts told the model the query language was
unavailable while every other row passed.

Design rules (mirrors ``soc_ai.webui.probes``):

- Every check is ISOLATED — it never raises, and one failing upstream never
  blocks the other checks (the network checks run concurrently).
- Every check is BOUNDED by a short timeout so a hung upstream degrades to a
  clear FAIL line, never a hang.
- Every failing line carries a ``hint`` naming what to do about it.
- No detail string may carry a secret — the reused probe helpers
  (:func:`soc_ai.webui.probes._safe_reason` / ``_scrub``) strip
  credential-shaped substrings.
- A check that reaches past ``ElasticClient`` into the raw ``_client``
  namespace (``check_audit_write_privileges`` does, for ``security``) owns
  the partial-read guard ``ElasticClient.search`` would otherwise have
  applied — go through ``elastic.search(...)`` instead whenever the call has
  a search-shaped equivalent, so a half-read grid can't be misread as a real
  answer (see ``GridPartialResultsError``).

Exit-code contract (:func:`exit_code`): 0 iff no check FAILed. WARN and INFO
never fail the doctor — they flag things that degrade gracefully.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import socket
import ssl
import struct
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

from alembic.script import ScriptDirectory
from elastic_transport import ConnectionTimeout as EsConnectionTimeout
from elasticsearch import ApiError, AuthenticationException
from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError
from sqlalchemy.ext.asyncio import AsyncConnection

from soc_ai.config import DEFAULT_ALERTS_QUERY, Settings
from soc_ai.errors import OqlValidationError, SoAuthError
from soc_ai.so_client.auth import make_auth
from soc_ai.so_client.elastic import ElasticClient, GridPartialResultsError
from soc_ai.store.db import (
    SQLITE_FILENAME,
    _migration_config,
    describe_store,
    is_postgres_url,
    make_engine,
    make_sessionmaker,
    store_url,
)
from soc_ai.webui import alerts_query as aq
from soc_ai.webui.probes import (
    PROBE_BUDGET_S,
    UNMEASURED_CAUSES,
    _safe_reason,
    _scrub,
    list_gateway_models,
    probe_model_fitness,
)

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


def exit_code(results: list[CheckResult], *, strict: bool = False) -> int:
    """Process exit code: 0 iff no REQUIRED check failed (WARN/INFO pass).

    ``strict`` additionally fails on WARN. It is opt-in and stays that way: a
    monitor keyed on this exit status has been reading 0-with-warnings as
    success for the life of the tool, and silently starting to page it would be
    a worse defect than the one it fixes. But the reverse — a deployment warning
    that thirty-three alerts a day never reach the queue, on a doctor that exits
    0 — is exactly how a WARN band becomes decorative. So the strict answer is
    available to anyone who wants their automation to see it, without changing
    what anyone's existing automation sees.
    """
    if any(r.status == "FAIL" for r in results):
        return 1
    return 1 if strict and any(r.status == "WARN" for r in results) else 0


# Per-check wall-clock bounds (seconds). Each check is wrapped in
# ``asyncio.wait_for`` so a hung upstream becomes a FAIL line quickly; a DOWN
# service (connection refused) fails near-instantly regardless. The fitness
# probe self-bounds at probes._FITNESS_TOTAL_TIMEOUT_S — the wrapper here must
# sit ABOVE that bound, or doctor cancels a healthy probe mid-leg and reports
# its own impatience as a model failure (this happened: the wrapper sat at 40s
# while the probe's own budget had grown to 100s, then 130s).
# getaddrinfo has no timeout parameter, so a slow resolver alone can burn ~5s;
# add ~5s for connect plus the TLS handshake, per target. The three targets
# run CONCURRENTLY (see check_upstream_reachability), so 15s bounds the
# slowest SINGLE target with headroom rather than the sum of three — without
# that headroom, one slow probe collapses all three named rows into one
# generic "check timed out" FAIL instead of naming which target is slow.
_REACH_TIMEOUT_S = 15.0
_STORE_TIMEOUT_S = 10.0
_SO_TIMEOUT_S = 8.0
_ES_TIMEOUT_S = 8.0
_AUDIT_TIMEOUT_S = 8.0  # one _has_privileges call — same cost profile as the ES check
_COVERAGE_TIMEOUT_S = 8.0  # 3 CONCURRENT searches — worst case is ~one 5s round trip, not 3x
_ALERT_FILTER_TIMEOUT_S = 8.0  # same shape: 4 CONCURRENT size=0 counts, one round trip
_GATEWAY_TIMEOUT_S = 12.0  # list_gateway_models carries its own 10s HTTP timeout
_ORACLE_ROUTE_TIMEOUT_S = 10.0  # one indexed read of the store, newest first
_FITNESS_TIMEOUT_S = 150.0  # probes._FITNESS_TOTAL_TIMEOUT_S (130s) + headroom
# The audit chain row verifies the last 24 h under its own short bound and
# reports INFO "not checked" when the grid is slow. The _isolated wrapper sits
# above that bound, so a slow grid never reads as a FAIL of the chain.
_AUDIT_CHAIN_TIMEOUT_S = 15.0
_AUDIT_CHAIN_WRAP_S = _AUDIT_CHAIN_TIMEOUT_S + 5.0
# A day of a busy deployment is about 25 000 records; the bound keeps the row
# cheap on a grid that writes far more.
_AUDIT_CHAIN_MAX_RECORDS = 100_000

# Client-side per-request timeout for the doctor's ES calls — deliberately
# tighter than the app's es_request_timeout_s (30s) so a slow/wedged cluster
# fails fast here, and with retries off (one honest attempt, not 3). It is the
# shared probe budget, the same one the header pill and Test ES wait for.
_ES_REQUEST_TIMEOUT_S = int(PROBE_BUDGET_S)


def _probe_client(settings: Settings) -> ElasticClient:
    """A narrowed-timeout, no-retry :class:`ElasticClient` for doctor probes.

    Mirrors ``check_elasticsearch``'s own narrowing below: tight client-side
    timeout and retries off, so a slow/wedged cluster fails fast here (one
    honest attempt) instead of riding the app's normal ``es_request_timeout_s``
    x ``es_max_retries`` retry budget.
    """
    return ElasticClient(
        settings.model_copy(
            update={"es_request_timeout_s": _ES_REQUEST_TIMEOUT_S, "es_max_retries": 0}
        )
    )


# ── Check 1: config ──────────────────────────────────────────────────────────


def check_config() -> tuple[Settings | None, CheckResult]:
    """Settings parse from env/.env — names the offending field(s) on failure."""
    try:
        settings = Settings()  # type: ignore[call-arg]  # required fields come from env/.env
    except ValidationError as exc:
        problems = ". ".join(
            f"{'.'.join(str(p) for p in err['loc']) or 'settings'}: {err['msg']}"
            for err in exc.errors()[:5]
        )
        return None, CheckResult(
            "config",
            "FAIL",
            _scrub(f"the settings failed validation. {problems}")[:300],
            hint="Fix the named fields in .env. See .env.example for the full surface.",
        )
    except Exception as exc:  # unreadable .env, bad encoding, … — still a graded FAIL
        return None, CheckResult(
            "config",
            "FAIL",
            _safe_reason(exc),
            hint="Check that .env exists and is readable. Every line must parse as KEY=value.",
        )
    return settings, CheckResult("config", "PASS", "settings loaded from env/.env.")


async def apply_persisted_overrides(settings: Settings) -> list[str]:
    """Lay the config console's saved overrides onto *settings*. Returns the keys applied.

    The doctor's whole value is grading what the app is actually running, and
    until this ran it graded the environment file alone. The two diverge in
    normal use: on a deployed instance ``ORACLE_MODEL`` was one model in the
    file and another in ``config_overrides``, and the running app used the
    second. Without this the doctor probes the gateway for a model nothing
    asks for, and keeps warning about an alerts filter the operator has already
    fixed in the console, which is the one place its own hint sends them.

    Same order the app uses at startup (``soc_ai.main._init_store``): the
    environment builds the singleton, saved overrides are set over it.

    Fail-soft in every direction. A fresh install has no store yet, and
    ``check_store`` is the row that reports a missing or broken one; a read
    failure here must not take the doctor down or turn a config PASS into a
    FAIL. Secrets are skipped (no ``secret_box``), leaving the environment
    value standing, which is what ``apply_to_settings`` already does.
    """
    # Local imports: the store layer pulls in the whole ORM, and `soc-ai doctor`
    # should not pay for it before check 1 has established there is a config.
    from soc_ai.store.config_overrides import (  # noqa: PLC0415
        apply_to_settings,
        load_overrides,
    )
    from soc_ai.store.db import make_sessionmaker  # noqa: PLC0415

    # A SQLite store that does not exist yet has no overrides. A PostgreSQL
    # store has no file to ask, so the read below answers, and fails soft.
    engine = None
    try:
        if (
            not is_postgres_url(store_url(settings))
            and not (settings.soc_ai_data_dir / SQLITE_FILENAME).exists()
        ):
            return []
        engine = make_engine(settings)
        async with make_sessionmaker(engine)() as db:
            overrides = await load_overrides(db)
        return apply_to_settings(settings, overrides, secret_box=None)
    except Exception:
        return []
    finally:
        if engine is not None:
            with contextlib.suppress(Exception):
                await engine.dispose()


# ── Check 1b: upstream reachability (DNS vs TCP/firewall vs TLS trust) ───────

# check_so_api / check_elasticsearch / check_gateway below each report a dead
# upstream as one undifferentiated "unreachable" — accurate, but it leaves the
# operator guessing which of three unrelated fixes applies. The two documented
# onboarding traps are hostname resolution failing INSIDE the container's
# bridge network (a host that resolves fine from the operator's own shell may
# not resolve from inside Docker) and a private/self-signed CA the container
# doesn't trust — both today only ever surface as a failed first hunt. This
# check classifies the LAYER (DNS / TCP-reach-or-firewall / TLS-trust) so each
# FAIL line names its one fix instead of sending the operator down the wrong
# troubleshooting path.

# "dns" is one shared string (one resolver, inside one container, regardless
# of which upstream). "reach" and "tls" are NOT shared: SO/ES sit behind the
# SO firewall and have a *_CA_BUNDLE knob, but the gateway (LiteLLM) is a
# different service entirely — telling an operator to pinhole the SO firewall
# for a dead LiteLLM box, or to set a LITELLM_CA_BUNDLE that doesn't exist in
# Settings, would send them nowhere. Keyed by (target slug, failure kind) so
# each FAIL line's hint names the fix that actually applies to that target.
_REACH_DNS_HINT = (
    "This container cannot resolve the hostname. Use an IP address in .env. You can "
    "also add an extra_hosts entry for it in docker-compose.yml."
)
_REACH_SO_ES_FIREWALL_HINT = (
    "There is no route, or the upstream refused the connection. Pinhole this host's "
    "IP through the SO firewall. Elasticsearch uses TCP 9200. See "
    "docs/SECURITY-ONION-SETUP.md, section 0."
)
_REACH_TLS_FALLBACK_NOTE = "If the endpoint does not serve TLS on this port, use http://."
_REACH_HINTS: dict[tuple[str, str], str] = {
    ("so", "dns"): _REACH_DNS_HINT,
    ("so", "tls"): (
        "Private CA or self-signed certificate. Point SO_CA_BUNDLE at the CA, "
        "or set SO_VERIFY_SSL=false if you accept unverified TLS. " + _REACH_TLS_FALLBACK_NOTE
    ),
    ("so", "reach"): _REACH_SO_ES_FIREWALL_HINT,
    ("es", "dns"): _REACH_DNS_HINT,
    ("es", "tls"): (
        "Private CA or self-signed certificate. Point ES_CA_BUNDLE at the CA, "
        "or set ES_VERIFY_SSL=false if you accept unverified TLS. " + _REACH_TLS_FALLBACK_NOTE
    ),
    ("es", "reach"): _REACH_SO_ES_FIREWALL_HINT,
    ("gateway", "dns"): _REACH_DNS_HINT,
    ("gateway", "tls"): (
        "Self-signed or private-CA gateway cert. Set LITELLM_VERIFY_SSL=false if you "
        "accept unverified TLS to the gateway. " + _REACH_TLS_FALLBACK_NOTE
    ),
    ("gateway", "reach"): (
        "There is no route, or the gateway refused the connection. Check the gateway "
        "URL and port. Check that the gateway container is up. It must answer from "
        "inside this container on the Docker network."
    ),
}


def _tls_handshake(sock: socket.socket, host: str) -> None:
    """Isolated so tests can stub the handshake without a real TLS peer."""
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(sock, server_hostname=host):
        pass


def _classify_endpoint(url: str, *, verify_tls: bool, timeout_s: float = 5.0) -> tuple[str, str]:
    """Return ("", detail) when reachable, else (failure_kind, detail).

    Synchronous — call through ``asyncio.to_thread``.
    """
    first = url.split(",", maxsplit=1)[0].strip()
    parsed = urlparse(first if "//" in first else f"//{first}")
    host = parsed.hostname or first
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    # This call exists PURELY to classify a DNS failure as its own layer —
    # its result is otherwise discarded (see the hostname-connect comment
    # below). NOTE: getaddrinfo has no timeout parameter (a stdlib gap, no
    # fix available); a blackholed resolver stalls THIS worker thread past
    # timeout_s. _isolated still caps the ROW at _REACH_TIMEOUT_S via
    # asyncio.wait_for, so the doctor's output is never late — but the
    # underlying thread keeps blocking until the resolver eventually answers
    # or errors, which process shutdown may have to wait on.
    try:
        socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError) as exc:
        # UnicodeError: getaddrinfo raises it for a >63-char DNS label, which
        # pydantic's AnyHttpUrl accepts without complaint — without this arm,
        # one such URL falls through to the generic OSError arm below and
        # collapses all three rows into a single undifferentiated FAIL
        # instead of naming it a DNS problem.
        return "dns", f"{host}: DNS resolution failed inside the container: {exc}"
    try:
        # Connect by HOSTNAME, not a resolved address pinned to whichever
        # entry getaddrinfo happened to sort first: create_connection does
        # its own resolution and tries every returned address in turn (AAAA
        # then A), so a dual-stack host on a v4-only network connects the
        # same way the app's own HTTP client would, instead of hard-failing
        # on an address the app itself would have skipped past.
        with socket.create_connection((host, port), timeout=timeout_s) as sock:
            if parsed.scheme == "https" and verify_tls:
                _tls_handshake(sock, host)
    except ssl.SSLCertVerificationError as exc:
        return "tls", f"{host}:{port}: TLS verification failed: {exc}"
    except ssl.SSLError as exc:
        # Broader than a cert-trust failure: the TCP connection succeeded but
        # the peer didn't speak TLS at all (e.g. an http-only service sitting
        # behind an https:// URL). Order matters — SSLCertVerificationError
        # is an SSLError subclass, so this arm MUST come after it, and both
        # MUST come before the OSError arm (SSLError is also an OSError).
        return "tls", f"{host}:{port}: TLS handshake failed: {exc}"
    except TimeoutError:  # socket.timeout is TimeoutError as of Python 3.10
        return "reach", f"{host}:{port}: connection timed out"
    except OSError as exc:
        return "reach", f"{host}:{port}: {exc.strerror or exc}"
    return "", f"{host}:{port} resolves and connects"


async def check_upstream_reachability(settings: Settings) -> list[CheckResult]:
    """Layer-classified reachability for the three upstreams, each failure with its one fix.

    Runs all three probes CONCURRENTLY via ``asyncio.to_thread`` (``socket``
    has no asyncio-native API) — worst case is ~one 5s probe inside the outer
    ``_REACH_TIMEOUT_S`` bound, not three run in series.
    """
    targets: list[tuple[str, str, str, bool]] = [
        ("SO reachability", "so", str(settings.so_host), bool(settings.so_verify_ssl)),
        (
            "ES reachability",
            "es",
            ",".join(str(host) for host in settings.es_hosts),
            bool(settings.es_verify_ssl),
        ),
        (
            "gateway reachability",
            "gateway",
            str(settings.litellm_base_url),
            bool(settings.litellm_verify_ssl),
        ),
    ]
    outcomes = await asyncio.gather(
        *(
            asyncio.to_thread(_classify_endpoint, url, verify_tls=verify)
            for _, _, url, verify in targets
        )
    )
    es_host_count = len(settings.es_hosts)
    results: list[CheckResult] = []
    for (name, slug, url, verify), (kind, detail) in zip(targets, outcomes, strict=True):
        # A multi-node grid's ES row only ever probes the FIRST configured
        # host (see the comma-join above) — say so on both PASS and FAIL, so
        # a green row doesn't read as "the whole cluster is reachable" when
        # it only ever checked one member of it.
        es_note = ""
        if slug == "es" and es_host_count > 1:
            es_note = f". This is the first of {es_host_count} es_hosts"
        if kind:
            results.append(
                CheckResult(name, "FAIL", f"{detail}{es_note}", hint=_REACH_HINTS[(slug, kind)])
            )
            continue
        first = url.split(",", maxsplit=1)[0].strip()
        scheme = urlparse(first if "//" in first else f"//{first}").scheme
        tls_note = ". TLS verifies" if verify and scheme == "https" else ""
        results.append(CheckResult(name, "PASS", f"{detail}{tls_note}{es_note}"))
    return results


# ── Check 2: local store (DB + migration head + FTS5) ────────────────────────

# The FTS5 tables migrations 0017 / 0018 create, and what the app does without
# each one. Both revisions skip the CREATE VIRTUAL TABLE on a SQLite without
# FTS5 and are stamped applied anyway, so a store first migrated on such a
# Python keeps its head but never gets the index, and nothing retries it later.
_FTS_TABLES: dict[str, str] = {
    "runbook_fts": "runbook search uses the legacy keyword ranker",
    "chat_memory_fts": "chat memory retrieval returns nothing",
}


async def _missing_fts_tables(conn: AsyncConnection) -> list[str]:
    rows = await conn.execute(
        text("SELECT name FROM sqlite_master WHERE type = 'table' AND name IN (:a, :b)"),
        {"a": "runbook_fts", "b": "chat_memory_fts"},
    )
    found = {str(row[0]) for row in rows}
    return [name for name in _FTS_TABLES if name not in found]


async def check_store(settings: Settings) -> list[CheckResult]:
    """DB reachable/creatable; Alembic head matches code head; FTS5 available.

    Head derivation mirrors ``tests/test_hunts_store.py::
    test_migration_at_head_is_current``: the DB side is ``alembic_version.
    version_num``, the code side is the migration ScriptDirectory's current
    head. FTS5 absence is a WARN, never a FAIL — runbook/chat retrieval falls
    back to the legacy keyword ranker (see ``soc_ai.store.runbooks``). So is a
    store at head whose FTS tables are missing: SQLite having the module says
    nothing about a store that was migrated before it did.

    A PostgreSQL store (``SOC_AI_DATABASE_URL``) is named by its URL without
    the password, and its search row is INFO: FTS5 is a SQLite module.
    """
    # The SQLite path, or the PostgreSQL URL without its password.
    db_path = describe_store(settings)
    postgres = settings.soc_ai_database_url is not None and bool(
        settings.soc_ai_database_url.get_secret_value().strip()
    )
    code_head = ScriptDirectory.from_config(_migration_config()).get_current_head() or "?"
    try:
        engine = make_engine(settings)
    except Exception as exc:
        return [
            CheckResult(
                "store",
                "FAIL",
                f"soc-ai cannot open the store at {db_path}. {_safe_reason(exc)}",
                hint=(
                    "Check SOC_AI_DATABASE_URL. soc-ai supports postgresql+asyncpg URLs."
                    if postgres
                    else "Check that SOC_AI_DATA_DIR exists. This user must be able to write to it."
                ),
            )
        ]
    results: list[CheckResult] = []
    try:
        async with engine.connect() as conn:
            try:
                row = await conn.execute(text("SELECT version_num FROM alembic_version"))
                db_head = row.scalar_one_or_none()
            except (OperationalError, ProgrammingError):
                # fresh store — no alembic_version table yet. PostgreSQL raises
                # ProgrammingError and aborts the transaction, so roll it back.
                await conn.rollback()
                db_head = None
            if db_head is None:
                results.append(
                    CheckResult(
                        "store",
                        "PASS",
                        f"the store is creatable at {db_path} and is fresh. No migration "
                        f"is applied yet. The code head is {code_head}.",
                        hint="Migrations run at `soc-ai serve` startup.",
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
                        f"migration head mismatch. The DB is at {db_head}. The code "
                        f"expects {code_head}.",
                        hint="Restart the server. `soc-ai serve` migrates to head at startup. "
                        "A DB ahead of the code means this checkout is older than the store.",
                    )
                )
            if conn.dialect.name != "sqlite":
                results.append(
                    CheckResult(
                        "store fts5",
                        "INFO",
                        "The store is PostgreSQL. FTS5 is a SQLite module. Runbook search "
                        "uses the keyword ranker. Chat memory uses PostgreSQL text search.",
                    )
                )
                return results
            # FTS5 availability — informational: the app falls back without it.
            has_fts5: bool | None
            try:
                fts_row = await conn.execute(
                    text("SELECT count(*) FROM pragma_module_list WHERE name = 'fts5'")
                )
                has_fts5 = bool(fts_row.scalar_one())
            except Exception:  # ancient SQLite without pragma_module_list
                has_fts5 = None
            at_head = db_head is not None and str(db_head) == code_head
            missing = await _missing_fts_tables(conn) if has_fts5 and at_head else []
            if missing:
                results.append(
                    CheckResult(
                        "store fts5",
                        "WARN",
                        f"The store has no {' or '.join(missing)}. SQLite has FTS5 now. "
                        "A Python without FTS5 migrated the store. The migration skipped "
                        f"the index. Effect: {'; '.join(_FTS_TABLES[name] for name in missing)}.",
                        hint="The app still works. Migrations 0017 and 0018 create the index "
                        "only when SQLite has FTS5 at migration time. They do not retry later. "
                        "Back up the store. Then re-create the missing tables and their "
                        "triggers with the DDL in those two revisions.",
                    )
                )
            elif has_fts5:
                results.append(
                    CheckResult(
                        "store fts5",
                        "INFO",
                        "SQLite FTS5 is available. BM25 runbook and chat retrieval is on.",
                    )
                )
            else:
                detail = (
                    "SQLite has no FTS5. Runbook and chat retrieval falls back to the "
                    "legacy keyword ranker."
                    if has_fts5 is False
                    else "soc-ai could not read whether SQLite has FTS5."
                )
                results.append(
                    CheckResult(
                        "store fts5",
                        "WARN",
                        detail,
                        hint="The app still works. Use a Python whose SQLite is built with "
                        "FTS5 to get BM25 retrieval.",
                    )
                )
    except Exception as exc:
        results.append(
            CheckResult(
                "store",
                "FAIL",
                _safe_reason(exc),
                hint=(
                    f"Check that the PostgreSQL server at {db_path} is up, and that "
                    "the role in SOC_AI_DATABASE_URL can log in."
                    if postgres
                    else f"Check the permissions on the store DB file at {db_path}. The file "
                    "can also be corrupt."
                ),
            )
        )
    finally:
        await engine.dispose()
    return results


# ── Check 3a: Security Onion API auth ────────────────────────────────────────

# The remedy when the login works and SOC then refuses the session. The old
# hint sent the operator to the user's role grants, which were correct.
_SOC_REFUSED_HINT = (
    "SOC refused the session. Check the SO version and the login flow. "
    "soc-ai logs in with the Kratos browser flow and sends the session cookie. "
    "See docs/SECURITY-ONION-SETUP.md."
)


async def check_so_api(settings: Settings) -> list[CheckResult]:
    """Authenticate to the SO web API (Kratos session / Connect OAuth) and hit
    the read-only ``/api/info`` — the same first call the app itself makes."""
    name = "security onion"
    mode = "Connect OAuth" if settings.use_connect_api else "Kratos session"
    try:
        auth = make_auth(settings)
    except Exception as exc:
        return [
            CheckResult(name, "FAIL", _safe_reason(exc), hint="Check the SO_* settings in .env.")
        ]
    try:
        resp = await auth.request("GET", "/api/info")
        if resp.status_code == 200:
            # Name the flow that worked. An SO upgrade can take one flow away,
            # and the operator needs to read which one is carrying the writes.
            flow = getattr(auth, "login_flow", None)
            how = f"{mode} ({flow} flow)" if flow else mode
            return [
                CheckResult(name, "PASS", f"soc-ai authenticated to {settings.so_host} with {how}.")
            ]
        if resp.status_code == 401:
            # The login worked and SOC then refused the session it issued.
            # That is an auth-mechanism mismatch, not a missing role grant.
            # SO 3.3 stopped accepting the Kratos API-flow session token and
            # takes the browser session cookie or an API key instead.
            return [
                CheckResult(
                    name,
                    "FAIL",
                    f"the login to {settings.so_host} worked. GET /api/info answered HTTP 401.",
                    hint=_SOC_REFUSED_HINT,
                )
            ]
        return [
            CheckResult(
                name,
                "FAIL",
                f"soc-ai authenticated. GET /api/info answered HTTP {resp.status_code}.",
                hint="The SO web API is up and it refused the call. Check the SO user's "
                "role grants. See docs/SECURITY-ONION-SETUP.md.",
            )
        ]
    except SoAuthError as exc:
        msg = _scrub(str(exc))[:200]
        if "rejected credentials" in msg:
            return [
                CheckResult(
                    name,
                    "FAIL",
                    f"authentication failed: {msg}",
                    hint="Check SO_USERNAME and SO_PASSWORD. Check also that the account "
                    "is not locked.",
                )
            ]
        if "SOC refused" in msg or "set no session cookie" in msg:
            return [CheckResult(name, "FAIL", msg, hint=_SOC_REFUSED_HINT)]
        if "throttled the login" in msg:
            return [
                CheckResult(
                    name,
                    "FAIL",
                    msg,
                    hint="SO limits repeated logins from one client. Wait, then run the "
                    "check again. A login loop in soc-ai can cause this.",
                )
            ]
        return [
            CheckResult(
                name,
                "FAIL",
                f"unreachable: {msg}",
                hint="Check SO_HOST and DNS. Check TLS with SO_VERIFY_SSL and "
                "SO_CA_BUNDLE. Check the SO firewall pinhole for this host. See "
                "docs/SECURITY-ONION-SETUP.md.",
            )
        ]
    except Exception as exc:
        return [
            CheckResult(
                name,
                "FAIL",
                f"unreachable: {_safe_reason(exc)}",
                hint="Check SO_HOST and the network route. Check TLS with SO_VERIFY_SSL "
                "and SO_CA_BUNDLE.",
            )
        ]
    finally:
        await auth.aclose()


# ── Check 3b: Elasticsearch (auth + trivial search) ──────────────────────────


async def check_elasticsearch(settings: Settings) -> list[CheckResult]:
    """ES auth + a trivial search against the events index pattern.

    Distinguishes UNREACHABLE (transport error) from AUTH FAILED (401) from a
    HALF-READ grid (FAIL, and not the pattern's fault) from a pattern that
    matches nothing (WARN: the console would render empty).

    The read is ``require_complete=True``. ``es_fail_on_partial_results`` is an
    opt-out for the operator's queries; it used to reach this check too, and a
    half-read grid then arrived here as a zero count and was diagnosed as a
    narrowed ``EVENTS_INDEX_PATTERN``. That is a config remedy for a shard
    fault, which is the wrong building.
    """
    name = "elasticsearch"
    pattern = settings.events_index_pattern
    elastic = _probe_client(settings)
    ping_s: float | None = None
    try:
        started = time.monotonic()
        info = await elastic.ping()
        ping_s = time.monotonic() - started
        cluster = str(info.get("cluster") or "") or "(unknown cluster)"
        version = str(info.get("version") or "") or "?"
        result = await elastic.search(
            pattern, {"match_all": {}}, size=0, track_total_hits=True, require_complete=True
        )
        if result.total == 0:
            return [
                CheckResult(
                    name,
                    "WARN",
                    f"the ES identity authenticated to {cluster} on ES {version}. The "
                    f"events pattern {pattern!r} matched no documents.",
                    hint="Check EVENTS_INDEX_PATTERN. A distributed grid needs the "
                    "cross-cluster prefix `*:logs-*`. setup.sh detects the right shape.",
                )
            ]
        return [
            CheckResult(
                name,
                "PASS",
                f"{cluster} on ES {version}. {result.total_display} docs match {pattern!r}.",
            )
        ]
    except AuthenticationException as exc:
        msg = _scrub(str(getattr(exc, "message", "") or ""))[:120]
        return [
            CheckResult(
                name,
                "FAIL",
                f"authentication failed with HTTP 401{': ' + msg if msg else ''}",
                hint="Check ES_USERNAME and ES_PASSWORD. See docs/SECURITY-ONION-SETUP.md "
                "for the SO role grant.",
            )
        ]
    except GridPartialResultsError as exc:
        # Must precede the ApiError/Exception arms: this grid ANSWERED, so
        # "unreachable" and the connectivity remedy below are both false of it.
        return [
            CheckResult(
                name,
                "FAIL",
                f"the grid answered and read only part of itself: {_safe_reason(exc)}",
                hint="Shards failed, or the search stopped part-way. Check Elasticsearch "
                "shard health. The index pattern is not the problem.",
            )
        ]
    except ApiError as exc:
        status = getattr(getattr(exc, "meta", None), "status", "?")
        msg = _scrub(str(getattr(exc, "message", "") or ""))[:120]
        return [
            CheckResult(
                name,
                "FAIL",
                f"ES refused the request with HTTP {status}: {msg}",
                hint="ES is up and it rejected the call. Check the role and the privileges "
                "of the ES user.",
            )
        ]
    except Exception as exc:
        if ping_s is not None:
            # The base URL answered. A connectivity remedy here sent the
            # operator to ES_HOSTS, TLS and the firewall while `/` answered
            # in 0.02 s (fleet 2026-10-01, RA16).
            timed_out = isinstance(exc, (TimeoutError, EsConnectionTimeout))
            what = (
                f"a search timed out after {_ES_REQUEST_TIMEOUT_S} s"
                if timed_out
                else f"a search failed: {_safe_reason(exc)}"
            )
            return [
                CheckResult(
                    name,
                    "FAIL",
                    f"the ping answered in {ping_s:.2f} s, but {what}",
                    hint=(
                        "The grid is overloaded. Check the Elasticsearch load and the "
                        "shard health. The address and the network route work."
                        if timed_out
                        else "Elasticsearch answers on the base URL. Check the Elasticsearch "
                        "load and the shard health."
                    ),
                )
            ]
        return [
            CheckResult(
                name,
                "FAIL",
                f"unreachable, no answer on the base URL: {_safe_reason(exc)}",
                hint="Check ES_HOSTS and the network route. Check TLS with ES_VERIFY_SSL. "
                "Check the SO firewall pinhole for this host.",
            )
        ]
    finally:
        with contextlib.suppress(Exception):  # best-effort cleanup on a probe path
            await elastic.aclose()


# ── Check 3c: audit write grant (ES _has_privileges, no canary write) ────────

# The exact grant scripts/setup-audit-index.sh applies to the analyst-class
# role, in its order. Split into what breaks WRITES (fail-closed abort — a
# FAIL) vs. what only breaks reading the chain back (verify / chain-head
# recovery — a WARN, since ack/escalate/comment still work).
_AUDIT_PRIVILEGES = (
    "auto_configure",
    "create_index",
    "index",
    "read",
    "view_index_metadata",
    "write",
)
_AUDIT_WRITE_CRITICAL = frozenset({"auto_configure", "create_index", "index", "write"})
_AUDIT_READ_ONLY = frozenset({"read", "view_index_metadata"})


async def check_audit_write_privileges(settings: Settings) -> CheckResult:
    """Preflight the SO-manager-side audit grant (``scripts/setup-audit-index.sh``).

    Requests all six privileges the setup script grants and grades them in two
    tiers: missing ``write``/``index``/``create_index``/``auto_configure`` is a
    FAIL (fail-closed: every ack/escalate/comment aborts with no UI error — or,
    with ``audit_fail_closed=false``, the forensic trail silently drops
    instead). Missing only ``read``/``view_index_metadata`` is a WARN (writes
    still land, but chain verification and the startup chain-head-recovery
    read both fail).

    Checked with ``_has_privileges`` rather than a real write: a canary
    document would enter the tamper-evident audit hash chain
    (``soc_ai.audit.logger``).

    Reaches past the ``ElasticClient`` wrapper into the raw
    ``_client.security`` namespace (which ``ElasticClient`` doesn't expose),
    using the same module-level ``ElasticClient`` import ``check_elasticsearch``
    uses above — so the existing ``patch("soc_ai.doctor.ElasticClient", ...)``
    test idiom covers this check too, with no separate patch target.
    """
    name = "audit write grant"
    fix = (
        "Run this on the SO manager: "
        "ssh <admin>@<so-manager> 'sudo bash -s' < scripts/setup-audit-index.sh . "
        "See docs/SECURITY-ONION-SETUP.md, section 3."
    )
    index_name = f"{settings.audit_index_alias}-{datetime.now(tz=UTC).strftime('%Y.%m.%d')}"
    elastic = _probe_client(settings)
    try:
        resp = await elastic._client.security.has_privileges(
            index=[{"names": [index_name], "privileges": list(_AUDIT_PRIVILEGES)}]
        )
    except Exception as exc:
        return CheckResult(
            name,
            "WARN",
            f"soc-ai could not query _has_privileges: {_safe_reason(exc)}",
            hint=(
                "Fix Elasticsearch connectivity first. Then run the doctor again. "
                "If ack, escalate or comment fail without an error once ES answers, "
                f"the grant can be missing. {fix}"
            ),
        )
    finally:
        with contextlib.suppress(Exception):  # best-effort cleanup on a probe path
            await elastic.aclose()

    # elasticsearch-py answers an ObjectApiResponse, not a dict — unwrap
    # explicitly rather than lean on its __getattr__ proxy (the same trap
    # soc_ai/audit/logger.py's _top_source documents and guards against).
    resp_any: Any = resp  # load-bearing: mypy --strict would flag isinstance below as unreachable
    if isinstance(resp_any, dict):
        body: dict[str, Any] = resp_any
    else:
        maybe_body = getattr(resp_any, "body", None)
        body = maybe_body if isinstance(maybe_body, dict) else {}

    if "has_all_requested" not in body:
        return CheckResult(
            name,
            "WARN",
            "the _has_privileges response has an unexpected shape. soc-ai cannot tell "
            "whether the audit grant is present.",
            hint="This is not a confirmed problem. If ack, escalate or comment ever fail "
            "without an error, check the grant by hand. See docs/SECURITY-ONION-SETUP.md, "
            "section 3.",
        )
    if bool(body["has_all_requested"]):
        return CheckResult(
            name, "PASS", f"the ES identity can write to {settings.audit_index_alias}-*."
        )

    index_block = body.get("index")
    granted: dict[str, Any] = {}
    if isinstance(index_block, dict):
        candidate = index_block.get(index_name)
        if isinstance(candidate, dict):
            granted = candidate
    missing = [priv for priv in _AUDIT_PRIVILEGES if not granted.get(priv)]
    write_missing = [p for p in missing if p in _AUDIT_WRITE_CRITICAL]
    read_missing = [p for p in missing if p in _AUDIT_READ_ONLY]

    if write_missing:
        consequence = (
            "Every ack, escalate and comment aborts. The audit is fail-closed. The UI "
            "shows no error."
            if settings.audit_fail_closed
            else "soc-ai drops the forensic audit trail. audit_fail_closed is false, so "
            "the actions still succeed."
        )
        return CheckResult(
            name,
            "FAIL",
            f"the ES identity is missing {', '.join(write_missing)} on {index_name}. {consequence}",
            hint=fix,
        )
    if read_missing:
        return CheckResult(
            name,
            "WARN",
            f"the ES identity is missing {', '.join(read_missing)} on {index_name}. "
            "Audit chain verification and chain-head recovery fail.",
            hint=fix,
        )
    return CheckResult(
        name,
        "WARN",
        f"_has_privileges reported {index_name} as not fully granted. It named no "
        "missing privilege. The response shape is unexpected.",
        hint=fix,
    )


# ── Check 3d: index-pattern dataset coverage (the .ds-* narrowing trap) ──────

# The three datasets a narrowed EVENTS_INDEX_PATTERN can silently split apart
# (see the warning block in .env.example): SO's own integrations (suricata
# alerts) live under one Elastic Agent namespace, Elastic's stock integrations
# (system.auth, system.syslog — the login + syslog evidence) live under
# another. A pattern narrowed to list `.ds-*` backing indices instead of the
# `logs-*` data-stream name can keep matching the first namespace while
# dropping the second entirely, with zero errors anywhere — a 2026-08-05
# production install did exactly this and got an investigation wrong. Order
# matters here: it drives both the per-dataset ES calls below and the WARN
# detail string.
_COVERAGE_DATASETS = ("suricata.alert", "system.auth", "system.syslog")


async def check_index_pattern_coverage(settings: Settings) -> CheckResult:
    """Count suricata.alert / system.auth / system.syslog under EVENTS_INDEX_PATTERN.

    ``check_elasticsearch`` above only confirms the pattern matches
    *something*; a narrowed pattern can still pass that check while quietly
    dropping an entire Elastic Agent namespace. This check counts each
    dataset independently — concurrently, through ``ElasticClient.search``
    rather than the raw ``_client`` — and WARNs when alerts are present but
    the login/syslog evidence is entirely absent: the specific shape of the
    ``.ds-*`` foot-gun.

    Going through ``search`` (not a raw ``_client.count()``) is deliberate:
    it inherits ``_check_complete``'s partial-read guard, so a half-read grid
    (failed/unassigned shards) raises :class:`GridPartialResultsError`
    instead of quietly answering with an undercount that this check would
    otherwise misdiagnose as a narrowed pattern.

    ``require_complete=True`` is what makes that true unconditionally. Without
    it the guard was subject to ``es_fail_on_partial_results``, so an operator
    who had opted into partial QUERY results also made the arm below dead code
    and got "matches no suricata/auth/syslog events" for a shard fault.
    """
    name = "index pattern coverage"
    pattern = settings.events_index_pattern
    hint_connectivity = "Fix Elasticsearch connectivity first. Then run the doctor again."
    elastic = _probe_client(settings)
    try:
        results = await asyncio.gather(
            *(
                elastic.search(
                    pattern,
                    {"term": {"event.dataset": dataset}},
                    size=0,
                    track_total_hits=True,
                    require_complete=True,
                )
                for dataset in _COVERAGE_DATASETS
            )
        )
    except GridPartialResultsError as exc:
        return CheckResult(
            name,
            "WARN",
            f"the grid returned partial results for the datasets under {pattern!r}. "
            f"Some shards failed. The counts are unreliable: {_safe_reason(exc)}",
            hint="Check Elasticsearch shard health. Then run the doctor again. The counts "
            "above are undercounts. Do not narrow or widen the pattern on them.",
        )
    except EsConnectionTimeout:
        # The reachability rows of the same run answered, so the grid is up.
        # This row fires three counts at once with the probe budget and no
        # retry, and a production grid of 361 backing indices answers in
        # 5 to 6 s on a slow minute. That is latency, and the connectivity
        # remedy sends the operator to the wrong system (2026-10-05).
        from soc_ai.webui.probes import probe_budget_s  # noqa: PLC0415 - lazy

        return CheckResult(
            name,
            "WARN",
            f"the count under {pattern!r} took longer than the probe budget of "
            f"{probe_budget_s(settings):g} s. The grid answered the reachability rows "
            "of this run. This is grid latency, not a connectivity fault.",
            hint="Run the doctor again. If the warning repeats, read the Elasticsearch "
            "node load: CPU, heap and the search thread pool queue.",
        )
    except Exception as exc:
        return CheckResult(
            name,
            "WARN",
            f"soc-ai could not count the datasets under {pattern!r}: {_safe_reason(exc)}",
            hint=hint_connectivity,
        )
    finally:
        with contextlib.suppress(Exception):  # best-effort cleanup on a probe path
            await elastic.aclose()

    counts: dict[str, int] = dict(zip(_COVERAGE_DATASETS, (r.total for r in results), strict=True))
    alerts = counts["suricata.alert"]
    auth = counts["system.auth"]
    syslog = counts["system.syslog"]
    detail_counts = f"suricata.alert={alerts}, system.auth={auth}, system.syslog={syslog}"

    if alerts > 0 and auth == 0 and syslog == 0:
        return CheckResult(
            name,
            "WARN",
            f"{pattern!r} sees alerts and zero auth/syslog events. The counts are "
            f"{detail_counts}. The pattern is probably narrowed to backing indices.",
            hint="Set EVENTS_INDEX_PATTERN=logs-*. A multi-node grid uses *:logs-*. Never "
            "list .ds-* backing indices. See the warning block in .env.example.",
        )
    if alerts == 0 and auth == 0 and syslog == 0:
        return CheckResult(
            name,
            "WARN",
            f"{pattern!r} matches no suricata/auth/syslog events",
            hint="The pattern is wrong, or the grid is idle. A single-node grid uses "
            "logs-*. A multi-node grid uses *:logs-*.",
        )
    if alerts == 0:
        # auth and/or syslog are present, so the pattern itself is fine — just
        # a quiet alert stream (idle grid, or Suricata not yet firing).
        return CheckResult(
            name,
            "PASS",
            f"{pattern!r}: {detail_counts}. There are no suricata.alert events. "
            "The triage queue will be empty.",
        )
    return CheckResult(name, "PASS", f"{pattern!r}: {detail_counts}")


# ── Check 3e: the alerts-feed filter against how the grid labels alerts ──────
#
# ``WEBUI_ALERTS_QUERY`` decides what the triage queue contains, and until this
# check nothing compared it with the grid. On a Security Onion grid measured on
# 2026-09-05 the default ``tags:alert`` matched 2 documents in 24 hours while
# ``event.kind:alert`` matched 25: 22 Elastic Defend endpoint alerts, naming
# hosts and accounts nobody had reviewed, were invisible to the console and to
# every hunt that consults the alert plane. The filter being wrong for one
# deployment is a tuning problem and it is documented as tunable. The defect is
# that an empty queue caused by a filter that does not match how the grid labels
# an alert is indistinguishable from a quiet network: a false all-clear, which
# this project ranks above any 500.

# An alternative label has to beat the configured filter by BOTH of these before
# the check calls it a mismatch rather than ordinary spread between labels. The
# measured mismatch was 2 against 25.
_ALERT_FILTER_RATIO = 5
_ALERT_FILTER_MARGIN = 10


def _alert_filter_hint(recommended: str) -> str:
    """Name one exact filter to paste, say why it is a widening, and where it goes.

    ``recommended`` is always a superset of what the operator has configured
    (see :func:`~soc_ai.webui.alerts_query.widen_alert_filter`), so the
    sentence can promise that following it costs them nothing. It says so out
    loud: the version that just named the better label read as an instruction
    to swap, and on the measured grid swapping would have dropped the two
    DCSync detections that only the configured label found.

    It names both places the value can live, and which one wins, because on the
    deployed instance the value is set in an environment file and the sentence
    sends the operator to the console. That is sound, because the console writes a
    ``config_overrides`` row and ``apply_to_settings`` sets those over the
    environment-loaded singleton at startup and again on save. It is only sound
    because of that precedence, so the precedence is stated rather than relied
    on. An operator who edits the file while an override exists changes nothing,
    and would have no way to know it from a sentence that offered two
    equal-looking options.
    """
    return (
        f"Set WEBUI_ALERTS_QUERY={recommended}. In the config console it is Queries, "
        "then Web-UI alerts feed query. The console saves at once and overrides any "
        "value in the environment file. This filter keeps every alert the current one "
        "finds and adds the ones it misses. A replacement filter can hide alerts that "
        "only the current one matches. One filter feeds the alerts console, auto-triage "
        "and every hunt that reads the alert plane."
    )


def _class_name(dataset: str) -> str:
    """How to say one ``event.dataset`` in a sentence.

    The aggregation's missing-value bucket is a placeholder, not a value, so it
    must not be printed as though the operator could search for it.
    """
    return "alerts carrying no event.dataset" if dataset == aq.UNKNOWN_DATASET else dataset


def _invisible_classes(
    configured: aq.AlertLabelCount, alternatives: dict[str, aq.AlertLabelCount]
) -> dict[str, tuple[str, int]]:
    """Alert classes an alternative label finds and the configured filter finds NONE of.

    Returns ``{event.dataset: (label that finds it, how many it finds)}``, best
    label per class (most documents; ties go to the earliest candidate, which is
    the order :data:`~soc_ai.webui.alerts_query.ALERT_LABEL_CANDIDATES` declares).

    Zero coverage of a class is a different failure from a filter that is merely
    narrower, and no ratio between two totals can express it: on the deployed
    instance the configured filter matched 1,441 documents against an
    alternative's 1,442 and matched none at all of that grid's Sigma engine
    output. A ratio reads that as a rounding difference.

    A truncated class list on the configured side proves nothing, because a class
    missing from a list the grid cut short may simply have fallen off the end, so
    the comparison stands down rather than raising a false alarm.
    """
    if configured.classes_truncated:
        return {}
    found: dict[str, tuple[str, int]] = {}
    for label, count in alternatives.items():
        for dataset, n in count.classes.items():
            if n <= 0 or configured.classes.get(dataset, 0) > 0:
                continue
            best = found.get(dataset)
            if best is None or n > best[1]:
                found[dataset] = (label, n)
    return found


async def check_alerts_feed_filter(settings: Settings) -> CheckResult:
    """Compare ``WEBUI_ALERTS_QUERY`` with the other ways the grid labels alerts.

    Counts what the configured filter matches over the last 24 hours and what
    each of :data:`~soc_ai.webui.alerts_query.ALERT_LABEL_CANDIDATES` would have
    matched over the same window, through the feed's own query builder so the
    numbers are the feed's numbers. WARNs when the configured filter finds
    nothing an alternative finds, or finds far less than one, and hands back
    the configured filter WIDENED with the alternative that would find more,
    never the alternative on its own.

    It also WARNs, whatever the totals say, when an alternative finds a whole
    class of alert (:func:`_invisible_classes`) the configured filter finds none
    of. That is a different failure and the totals cannot express it: the
    deployed instance's filter matched 1,441 documents against 1,442, passing
    every ratio, while matching zero of the grid's Sigma detections.

    When whole classes are invisible, EVERY label needed to cover them is added
    at once rather than the best one — a hint that has to be followed twice is
    a warning that comes back after you did what it said. It never recommends a
    label this grid has no alerts under, so the pasted filter only ever names
    labels that recover something real.

    The totals branch still adds a single alternative: there the complaint is
    about volume rather than a class nobody can see, and one label is the whole
    of the recommendation.

    A grid where no label finds anything is quiet, not misconfigured, and PASSes
    with that said out loud. Reporting a problem on every idle grid is how a
    real mismatch gets scrolled past.
    """
    name = "alerts feed filter"
    hint_connectivity = "Fix Elasticsearch connectivity first, then re-run the doctor."
    elastic = _probe_client(settings)
    try:
        counts = await aq.count_alert_labels(elastic, settings)
    except OqlValidationError as exc:
        return CheckResult(
            name,
            "WARN",
            f"the configured alerts filter is not valid OQL: {_safe_reason(exc)}. The "
            "alerts console rejects every request. The queue stays empty.",
            # Nothing to widen: a filter the builder rejects matches nothing
            # anywhere, and ORing the broken text in would hand back something
            # that still does not parse. Recommend the shipped default.
            hint=_alert_filter_hint(DEFAULT_ALERTS_QUERY),
        )
    except GridPartialResultsError as exc:
        return CheckResult(
            name,
            "WARN",
            "the grid returned partial results for the alert labels. Some shards "
            f"failed. The counts are unreliable: {_safe_reason(exc)}",
            hint=hint_connectivity,
        )
    except Exception as exc:
        return CheckResult(
            name,
            "WARN",
            f"soc-ai could not count the alert labels: {_safe_reason(exc)}",
            hint=hint_connectivity,
        )
    finally:
        with contextlib.suppress(Exception):  # best-effort cleanup on a probe path
            await elastic.aclose()

    detail_counts = ", ".join(f"{label}={count.total}" for label, count in counts.items())
    configured, configured_count_row = next(iter(counts.items()))
    configured_count = configured_count_row.total
    alternatives = {k: v for k, v in counts.items() if k != configured}
    # Ties go to the earliest candidate, which is the order ALERT_LABEL_CANDIDATES
    # declares, SO's own convention before ECS's. ``default`` covers the state
    # where the configured filter IS every candidate: there is then nothing to
    # compare against, and a zero best falls into the quiet branch below rather
    # than taking out the row with a ValueError.
    better, better_count = max(
        ((label, c.total) for label, c in alternatives.items()),
        key=lambda kv: kv[1],
        default=("", 0),
    )

    window = f"in the last {aq.DEFAULT_RANGE}"
    if configured_count == 0 and better_count == 0:
        return CheckResult(
            name,
            "PASS",
            f"{detail_counts}. No label found an alert {window}. The triage queue will be empty.",
        )
    if configured_count == 0:
        return CheckResult(
            name,
            "WARN",
            f"{configured!r} matched nothing {window}. {better!r} matched "
            f"{better_count}. The counts are {detail_counts}. The filter empties the "
            "queue. The grid is not quiet.",
            hint=_alert_filter_hint(aq.widen_alert_filter(configured, better)),
        )
    # Zero coverage of a class, before the ratio: the two can hold at once, and
    # naming the class the queue has never seen is the more useful of the two
    # sentences. This branch is the whole reason the check reads the per-class
    # breakdown: the ratio below passed on the deployed instance at 1,441 against
    # 1,442 while an entire alert class was invisible.
    invisible = _invisible_classes(configured_count_row, alternatives)
    if invisible:
        # Every label needed to cover every blind class, in one recommendation.
        #
        # This used to hand back only the label covering the most documents, on
        # the argument that a second run would catch the rest and the thing
        # converges. It does converge — and from the operator's seat it is a
        # warning that comes back after you did exactly what it said. The home
        # deployment followed this hint on 2026-09-07 and the warning returned
        # naming the next label. The check already holds every label it needs
        # here, so making the reader discover them one per day buys nothing and
        # costs the credibility of the row.
        by_label: dict[str, int] = {}
        for label, n in invisible.values():
            by_label[label] = by_label.get(label, 0) + n
        # Widest first, so the pasted filter reads in order of what it recovers.
        needed = [label for label, _ in sorted(by_label.items(), key=lambda kv: (-kv[1], kv[0]))]
        best_label = " OR ".join(needed)
        named = ", ".join(
            f"{_class_name(ds)} at {n} under {label!r}"
            for ds, (label, n) in sorted(invisible.items(), key=lambda kv: -kv[1][1])
        )
        return CheckResult(
            name,
            "WARN",
            f"{configured!r} matches none of these alert classes {window}: {named}. "
            f"The counts are {detail_counts}. A class with zero coverage never reaches "
            "the queue. The totals can still look close.",
            hint=_alert_filter_hint(aq.widen_alert_filter(configured, best_label)),
        )
    if (
        better_count >= configured_count + _ALERT_FILTER_MARGIN
        and better_count >= configured_count * _ALERT_FILTER_RATIO
    ):
        return CheckResult(
            name,
            "WARN",
            f"{configured!r} matched {configured_count} {window}. {better!r} matched "
            f"{better_count}. The counts are {detail_counts}. Most of what this grid "
            "labels an alert never reaches the queue.",
            hint=_alert_filter_hint(aq.widen_alert_filter(configured, better)),
        )
    return CheckResult(name, "PASS", detail_counts)


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
                f"soc-ai cannot list the models: {err}",
                hint="Check LITELLM_BASE_URL and LITELLM_API_KEY. For a self-signed "
                "gateway, check LITELLM_VERIFY_SSL.",
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
                hint="The id can still resolve through a gateway alias. If completions "
                "answer HTTP 400, set ANALYST_MODEL to a listed id.",
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
                    hint="The RAG tier is fail-soft. Retrieval degrades to local FTS5. "
                    "Fix the model id, or clear it to silence this row.",
                )
            )
    # The Oracle, when it is on. It grades every nightly batch, and its verdict
    # is what the quality alarm is computed from — so an Oracle that stopped
    # resolving would show up as the ANALYST model's agreement collapsing, on a
    # doctor reporting all-PASS. The one model whose failure is attributed to a
    # different component had no row here at all.
    if settings.oracle_enabled:
        oracle = settings.oracle_model.strip()
        if oracle in ids:
            results.append(
                CheckResult("oracle model", "PASS", f"{oracle!r} is served by the gateway")
            )
        else:
            results.append(
                CheckResult(
                    "oracle model",
                    "WARN",
                    f"{oracle!r} is not in the gateway's /v1/models list. This model "
                    "grades the nightly quality batch.",
                    hint="The id can still resolve through a gateway alias. If grading "
                    "answers HTTP 400, the nightly agreement_rate reads as an analyst "
                    "regression. The grader is the missing part. Set ORACLE_MODEL to a "
                    "listed id.",
                )
            )
    return results


# ── Check 4b: the Oracle route ───────────────────────────────────────────────

# How each failure class reads on the doctor row (soc_ai.oracle.failures).
_ORACLE_CLASS_PHRASE = {
    "quota": "a usage limit",
    "5xx": "a server error",
    "4xx": "a client error",
    "timeout": "a timeout",
    "transport": "no answer",
    "paused": "the pause",
}


def _oracle_pause_row(pause_reason: str, until: str | None, message: str) -> CheckResult:
    when = f"{until.replace('T', ' ').replace('Z', '')} UTC" if until else "the reset time"
    if pause_reason == "quota":
        detail = (
            f"the Oracle route answered with a usage limit. soc-ai makes no Oracle call "
            f"until {when}."
        )
        hint = (
            "The pause ends at the reset time. Check the quota of the account behind the "
            "Oracle route, or set ORACLE_MODEL to a route with quota."
        )
    else:
        detail = (
            f"the Oracle route answered with three server errors in a row. soc-ai makes no "
            f"Oracle call until {when}."
        )
        hint = "Check the gateway and the provider behind the Oracle route."
    if message:
        detail += f" The gateway said: {message}"
    return CheckResult("oracle route", "WARN", detail, hint=hint)


async def check_oracle_route(
    settings: Settings, *, now: datetime | None = None
) -> list[CheckResult]:
    """The Oracle route: PASS when the last call answered, WARN while it is paused.

    INFO when the Oracle is off. The pause of THIS process comes from the
    route breaker (:mod:`soc_ai.oracle.breaker`). The CLI doctor runs in
    another process, so the row also reads the newest stored Oracle event: a
    pause recorded there with a reset time still ahead is a WARN too.
    """
    if not settings.oracle_enabled:
        return [
            CheckResult("oracle route", "INFO", "the Oracle is off. soc-ai makes no Oracle call.")
        ]
    from soc_ai.oracle import breaker  # noqa: PLC0415 - lazy, the doctor stays light
    from soc_ai.store import oracle_ledger  # noqa: PLC0415

    now = now or breaker._now()
    route = breaker.route_key(settings)
    until = breaker.BREAKER.open_until(route, now=now)
    if until is not None:
        state = breaker.BREAKER.state(route)
        return [_oracle_pause_row(state.reason, breaker.iso(until), state.message)]

    try:
        engine = make_engine(settings)
        try:
            async with make_sessionmaker(engine)() as db:
                outcome = await oracle_ledger.latest_route_outcome(db)
        finally:
            await engine.dispose()
    except Exception as exc:
        return [
            CheckResult(
                "oracle route",
                "WARN",
                f"soc-ai cannot read the Oracle record in the store. {_safe_reason(exc)}",
                hint="Run the store check above. The Oracle route state is unknown.",
            )
        ]
    if outcome is None:
        return [CheckResult("oracle route", "INFO", "no Oracle call is on record yet.")]
    p = outcome.payload
    paused_until = p.get("paused_until")
    if isinstance(paused_until, str) and paused_until:
        try:
            end = datetime.fromisoformat(paused_until.replace("Z", "+00:00"))
        except ValueError:
            end = None
        if end is not None and end > now:
            pause_reason = str(p.get("pause_reason") or p.get("error_class") or "quota")
            return [_oracle_pause_row(pause_reason, paused_until, str(p.get("message") or ""))]
        if outcome.kind == "oracle_skipped" or p.get("error_class") in ("quota", "5xx"):
            ended = paused_until.replace("T", " ").replace("Z", "")
            return [
                CheckResult(
                    "oracle route",
                    "INFO",
                    f"the last Oracle pause ended at {ended} UTC. The next escalation calls "
                    "the Oracle.",
                )
            ]
    if outcome.kind == "oracle_adjudication":
        return [CheckResult("oracle route", "PASS", "the last Oracle call answered.")]
    error_class = str(p.get("error_class") or "")
    if error_class == "unparseable":
        return [
            CheckResult(
                "oracle route",
                "PASS",
                "the last Oracle call answered. The answer held no verdict.",
            )
        ]
    status = p.get("http_status")
    if error_class:
        phrase = _ORACLE_CLASS_PHRASE.get(error_class, error_class)
        detail = f"the last Oracle call failed with {phrase}"
        if isinstance(status, int):
            detail += f", HTTP {status}"
        detail += "."
        message = str(p.get("message") or "")
        if message:
            detail += f" The gateway said: {message}"
    else:
        detail = (
            f"the last Oracle call failed: {p.get('reason') or 'unknown'}. The event holds no "
            "HTTP status. soc-ai recorded it before the failure class existed."
        )
    return [
        CheckResult(
            "oracle route",
            "WARN",
            detail,
            hint="Check the gateway and the Oracle model. The next escalation tries again.",
        )
    ]


# ── Check 5: model fitness (the E1.1 probe) ──────────────────────────────────


def _unmeasured_legs(fitness: dict[str, Any]) -> list[dict[str, Any]] | None:
    """The failed legs when every one of them failed to measure, else None.

    A leg that timed out or could not reach the model holds no capability
    result. When those are the only failed legs, the probe measured nothing
    that says the model is unfit. A probe result with no leg list (an older
    cache, a test double) gives None, and the grade stands.
    """
    legs = [leg for leg in fitness.get("legs") or [] if isinstance(leg, dict)]
    failed = [leg for leg in legs if leg.get("grade") == "fail"]
    if not failed:
        return None
    if all(leg.get("cause") in UNMEASURED_CAUSES for leg in failed):
        return failed
    return None


async def check_model_fitness(settings: Settings) -> list[CheckResult]:
    """Grade the analyst model via :func:`probe_model_fitness` — UNFIT = FAIL.

    This is the "silent all-fallback verdicts" trap: a model that lists on the
    gateway but can't hold structured output degrades EVERY investigation to a
    fallback needs_more_info verdict, and nothing else surfaces it.

    Only a capability failure reads FAIL. A leg that timed out or could not
    reach the model measured nothing, so it reads WARN "could not measure",
    with the cause and no advice to replace the model. On the range the doctor
    told the operator to replace a model after a 30 s gateway timeout, while
    the same model landed 10 of 10 eval verdicts in the same minute.
    """
    fitness = await probe_model_fitness(settings)
    grade = str(fitness.get("grade", "fail"))
    detail = str(fitness.get("detail", ""))
    if grade == "pass":
        return [CheckResult("model fitness", "PASS", detail)]
    unmeasured = _unmeasured_legs(fitness) if grade == "fail" else None
    if unmeasured:
        model = str(fitness.get("model") or "") or "the analyst model"
        causes = " ".join(str(leg.get("detail") or leg.get("name") or "") for leg in unmeasured)
        return [
            CheckResult(
                "model fitness",
                "WARN",
                f"could not measure {model}. {causes}",
                hint="The call to the model did not finish. This is not a model capability "
                "result. Read the gateway row, then run the doctor again when the load drops.",
            )
        ]
    if grade == "degraded":
        return [
            CheckResult(
                "model fitness",
                "WARN",
                detail,
                hint="The model is usable and degraded. The config console's fitness "
                "probe shows the detail for each leg.",
            )
        ]
    return [
        CheckResult(
            "model fitness",
            "FAIL",
            detail,
            hint="An unfit analyst model lands all-fallback needs_more_info verdicts. "
            "Point ANALYST_MODEL at a model that passes structured output.",
        )
    ]


# ── Check 5c: audit chain (last 24 h) ────────────────────────────────────────


async def check_audit_chain(
    settings: Settings, *, timeout_s: float = _AUDIT_CHAIN_TIMEOUT_S
) -> CheckResult:
    """Verify the audit hash chain over the last 24 h, with a bounded read.

    The doctor and the preflight said green while the verify-chain endpoint
    said the chain was broken: neither looked at the chain. This row closes
    that gap with the same streamed verifier the CLI and the endpoint use.

    PASS intact. WARN duplicate sequence numbers only: two writers appended at
    once, and no record was altered. FAIL any other break: a record was
    altered, deleted or reordered. INFO when the check could not run: a slow
    grid is not a verdict about the chain.
    """
    from soc_ai.audit import verify as audit_verify  # noqa: PLC0415 - lazy

    name = "audit chain"
    hint_run = "Run soc-ai audit verify --days 1 to check the chain."
    elastic = _probe_client(settings)
    try:
        result = await asyncio.wait_for(
            audit_verify.verify_audit_chain(
                elastic,
                settings.audit_index_alias,
                days=1,
                max_records=_AUDIT_CHAIN_MAX_RECORDS,
            ),
            timeout=timeout_s,
        )
    except TimeoutError:
        return CheckResult(
            name,
            "INFO",
            f"not checked: the grid did not answer in {timeout_s:.0f} s.",
            hint=hint_run,
        )
    except GridPartialResultsError:
        return CheckResult(
            name,
            "INFO",
            "not checked: the grid read only part of the audit index.",
            hint=hint_run,
        )
    except Exception as exc:
        return CheckResult(name, "INFO", f"not checked: {_safe_reason(exc)}", hint=hint_run)
    finally:
        with contextlib.suppress(Exception):
            await elastic.aclose()

    if result.ok:
        if result.records_verified == 0:
            return CheckResult(name, "PASS", "intact. The last 24 h hold no audit records.")
        detail = (
            f"intact: {result.records_verified} records in the last 24 h, "
            f"seq {result.first_seq}..{result.last_seq}."
        )
        if result.capped:
            detail += " The check read the newest records only."
        return CheckResult(name, "PASS", detail)
    blast = audit_verify.describe_blast_radius(result)
    if audit_verify.is_duplicates_only(result):
        return CheckResult(
            name,
            "WARN",
            f"duplicate sequence numbers in the last 24 h: {result.duplicate_seqs}. "
            "No record was altered.",
            hint="Two writers appended at once. Run soc-ai audit verify for the detail.",
        )
    what = "a record was altered" if result.altered_records else "the chain does not verify"
    return CheckResult(
        name,
        "FAIL",
        f"{what} in the last 24 h. {blast}".strip(),
        hint="Run soc-ai audit verify --days 1 for the detail. Treat an altered record as "
        "an incident.",
    )


# ── Check 6: egress posture (INFO only) ──────────────────────────────────────

# The doctor lines mirror the config console's egress-policy read-model
# (soc_ai.api.webui.routes_config.api_egress_policy) — same row builder, same
# wording, and the SAME ROWS. It used to list six of the nine, and the three it
# left out (web search, page fetch, online enrichment) were the ones switched
# on. INFO only: posture is a fact to surface, never a pass/fail judgement.


def check_egress_posture(settings: Settings) -> list[CheckResult]:
    """One INFO line per egress destination, worded like the egress-policy page."""
    # Heavy (FastAPI) import, only needed when the doctor runs — and importing
    # the REAL row builder is what keeps the wording consistent by construction.
    from soc_ai.api.webui.routes_config import _egress_destinations  # noqa: PLC0415

    try:
        rows = _egress_destinations(settings)
    except Exception as exc:
        return [
            CheckResult("egress", "INFO", f"the egress posture is unavailable: {_safe_reason(exc)}")
        ]
    zero_egress = not any(row["enabled"] for row in rows)
    results = [
        CheckResult(
            "egress",
            "INFO",
            "zero egress: "
            + (
                "yes. Every egress destination is off."
                if zero_egress
                else "no. At least one egress destination is on."
            ),
        )
    ]
    for row in rows:
        state = "ON" if row["enabled"] else "off"
        label = str(row["label"]).rstrip(".")
        redaction = str(row["redaction"]).rstrip(".")
        results.append(
            CheckResult(
                f"egress: {row['id']}",
                "INFO",
                f"{state}. {label}. Redaction: {redaction}.",
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

# The feeds abuse.ch gates behind a free Auth-Key (2024 policy). Without the key
# `blocklists refresh` skips them, so these three can never become fresh and the
# warning about them can never clear — see _blocklist_hint.
_ABUSE_CH_FEEDS = frozenset({"urlhaus", "threatfox", "feodo"})


_RESTART_AFTER_SWAP = "soc-ai loads the files at start. After a swap, restart soc-ai."


def _open_proxy_blocks(proxies: list[str]) -> list[str]:
    """The entries in ``proxy_trusted_ips`` that trust every address: a /0 block."""
    found: list[str] = []
    for entry in proxies:
        text = str(entry).strip()
        if "/" not in text:
            continue
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError:
            continue
        if network.prefixlen == 0:
            found.append(text)
    return found


# ── Authentication and the listening sockets ────────────────────────────────

# The kernel's TCP socket tables. Column 2 is the local address, column 4 the
# state, and 0A is LISTEN. Each address word is the hex of a native-order u32.
_PROC_NET_TCP: tuple[str, ...] = ("/proc/net/tcp", "/proc/net/tcp6")
_TCP_LISTEN = "0A"


def _read_proc_net(path: str) -> str:
    """One socket table. A seam for the tests: they hand the doctor a fake table."""
    with open(path, encoding="ascii") as fh:
        return fh.read()


def _decode_proc_address(hex_addr: str) -> str:
    """``0100007F`` to ``127.0.0.1``, and the 32-digit IPv6 form to its text."""
    words = [int(hex_addr[i : i + 8], 16) for i in range(0, len(hex_addr), 8)]
    packed = struct.pack("=" + "I" * len(words), *words)
    family = socket.AF_INET if len(words) == 1 else socket.AF_INET6
    return socket.inet_ntop(family, packed)


def listening_addresses(
    port: int, *, read: Callable[[str], str] | None = None
) -> tuple[list[str], list[str]]:
    """The local addresses with a LISTEN socket on *port*, and the read errors.

    Reads ``/proc/net/tcp`` and ``/proc/net/tcp6``. A host with IPv6 off has no
    tcp6 table, so one missing table is not an error. Both unreadable gives no
    address and two errors, and the caller says it could not read them.
    """
    reader = read or _read_proc_net
    found: list[str] = []
    errors: list[str] = []
    for path in _PROC_NET_TCP:
        try:
            text = reader(path)
        except OSError as exc:
            errors.append(f"{path}: {exc.strerror or type(exc).__name__}")
            continue
        for line in text.splitlines()[1:]:
            cols = line.split()
            if len(cols) < 4 or cols[3] != _TCP_LISTEN or ":" not in cols[1]:
                continue
            addr_hex, port_hex = cols[1].rsplit(":", 1)
            try:
                if int(port_hex, 16) != port:
                    continue
                addr = _decode_proc_address(addr_hex)
            except (ValueError, OSError, struct.error):
                continue
            shown = f"[{addr}]:{port}" if ":" in addr else f"{addr}:{port}"
            if shown not in found:
                found.append(shown)
    if len(errors) < len(_PROC_NET_TCP):
        errors = []
    return found, errors


def _is_loopback_listener(shown: str) -> bool:
    host = shown.rsplit(":", 1)[0].strip("[]")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    return bool(ip.is_loopback or (mapped is not None and mapped.is_loopback))


def check_authentication(
    settings: Settings,
    *,
    read: Callable[[str], str] | None = None,
    in_container: bool | None = None,
) -> list[CheckResult]:
    """Authentication on or off, and when off, the addresses that carry the port.

    The app cannot see uvicorn's bind. The start warning read ``SOC_AI_HOST``
    and said "loopback bind 127.0.0.1" on a range where the systemd unit bound
    0.0.0.0 and a remote browser used the API with no login. The doctor reads
    the kernel's socket tables, which hold the real bind, and fails soft when
    it cannot read them.
    """
    name = "authentication"
    if settings.api_auth_required:
        return [CheckResult(name, "PASS", "on. Each API call needs a session or a token.")]
    port = int(settings.soc_ai_port)
    addresses, errors = listening_addresses(port, read=read)
    container = Path("/.dockerenv").exists() if in_container is None else in_container
    note = (
        " soc-ai runs in a container. The port that the host publishes sets the reach. "
        "See SOC_AI_BIND."
        if container
        else ""
    )
    fix = "Set API_AUTH_REQUIRED=true for a shared deployment."
    if errors:
        return [
            CheckResult(
                name,
                "WARN",
                f"off. soc-ai could not read the listening sockets: {'; '.join(errors)}.{note}",
                hint=f"Run `ss -ltn` to list them. {fix}",
            )
        ]
    if not addresses:
        return [
            CheckResult(
                name,
                "WARN",
                f"off. No socket on this host listens on port {port}. soc-ai cannot tell "
                f"which addresses the server binds.{note}",
                hint=f"Start the server, or check SOC_AI_PORT. {fix}",
            )
        ]
    listed = ", ".join(addresses)
    if all(_is_loopback_listener(a) for a in addresses):
        return [
            CheckResult(
                name,
                "INFO",
                f"off. Port {port} listens on {listed} only. Only this host can call the API."
                f"{note}",
            )
        ]
    return [
        CheckResult(
            name,
            "WARN",
            f"off. Port {port} listens on {listed}. Another host that reaches this host can "
            f"call the API with no login.{note}",
            hint=f"{fix} Or bind the server to 127.0.0.1.",
        )
    ]


def check_tls(settings: Settings, *, now: datetime | None = None) -> list[CheckResult]:
    """The certificate soc-ai serves with, or the reason it serves plain HTTP."""
    proxies = [str(p) for p in (getattr(settings, "proxy_trusted_ips", None) or [])]
    rows = [_tls_mode_row(settings, proxies, now=now)]
    if _open_proxy_blocks(proxies):
        rows.append(
            CheckResult(
                "tls",
                "WARN",
                "PROXY_TRUSTED_IPS trusts every address. "
                "Any client can forge the forwarded headers.",
                hint=(
                    "List the proxy address or the Docker address pool, for example "
                    "172.16.0.0/12. Do not list 0.0.0.0/0 or ::/0."
                ),
            )
        )
    return rows


def _tls_mode_row(settings: Settings, proxies: list[str], *, now: datetime | None) -> CheckResult:
    """The one row that states the TLS mode and the state of the served certificate."""
    from soc_ai.tls_status import describe, inspect_tls  # noqa: PLC0415 - lazy

    status = inspect_tls(settings.soc_ai_tls_cert, settings.soc_ai_tls_key, now=now)
    if status.mode == "off":
        if proxies:
            return CheckResult(
                "tls",
                "INFO",
                "TLS terminates at the proxy. soc-ai serves plain HTTP and trusts "
                f"forwarded headers from {', '.join(proxies)}. "
                "Confirm SOC_AI_BIND=127.0.0.1 so port 8443 stays on the host loopback.",
            )
        # The real listeners, not the configured host: the systemd unit and
        # the container pass their own bind to the server, and the setting
        # keeps its loopback default there.
        addresses, _errors = listening_addresses(int(settings.soc_ai_port))
        # With no listener on the port, for example from the CLI while the
        # service is down, the configured host is the only fact there is.
        if addresses:
            on_loopback = all(_is_loopback_listener(a) for a in addresses)
            host = ", ".join(sorted(addresses))
        else:
            host = str(settings.soc_ai_host)
            on_loopback = host in {"127.0.0.1", "::1", "localhost"}
        if on_loopback:
            return CheckResult("tls", "INFO", "TLS is off. soc-ai serves plain HTTP on loopback.")
        return CheckResult(
            "tls",
            "WARN",
            f"TLS is off. soc-ai serves plain HTTP on {host}, and no proxy is trusted.",
            hint=(
                "Set SOC_AI_TLS_CERT and SOC_AI_TLS_KEY for the direct path. Behind a proxy, "
                "set PROXY_TRUSTED_IPS to the proxy address. See docs/DOCKER.md, TLS."
            ),
        )
    detail = describe(status)
    if status.errors:
        return CheckResult(
            "tls",
            "FAIL",
            detail,
            hint=(
                "Install a valid certificate and key at the configured paths. "
                f"{_RESTART_AFTER_SWAP}"
            ),
        )
    proxy_hint = (
        "For a browser-trusted certificate with automatic renewal, use the proxy path: "
        "scripts/tls-proxy.sh enable <domain>. See docs/DOCKER.md, TLS."
    )
    # describe() already states the expiry. Repeat only the other warnings.
    extra = [w for w in status.warnings if not w.startswith("The certificate expires in")]
    only_self_signed = status.self_signed and status.expiry_band is None and status.chain_ok
    if only_self_signed:
        return CheckResult(
            "tls",
            "INFO",
            f"{detail} {' '.join(extra)} The proxy path gives a trusted certificate.",
            hint=proxy_hint,
        )
    if status.warnings:
        return CheckResult(
            "tls",
            "WARN",
            " ".join([detail, *extra]),
            hint=f"{proxy_hint} {_RESTART_AFTER_SWAP}",
        )
    sans = ", ".join(status.sans) if status.sans else "no SAN"
    return CheckResult("tls", "PASS", f"{detail} Names: {sans}. Chain of {status.chain_length}.")


def _blocklist_hint(settings: Settings, missing: list[str], stale: list[str]) -> str:
    """What would actually clear this warning, in THIS configuration.

    The hint used to say "run `soc-ai blocklists refresh`" unconditionally. On a
    deployment with no Auth-Key that command cannot fix the three abuse.ch feeds
    — it skips them by design — so the warning returned every day with the same
    unusable advice, and the only two things that would clear it (get a key, or
    stop asking for those feeds) went unmentioned. A warning nobody can act on
    teaches its reader to stop reading the doctor, which costs more than the
    feeds do.
    """
    unrefreshable = sorted(
        _ABUSE_CH_FEEDS.intersection(
            # `stale` entries carry an age suffix; the source is the first token.
            set(missing) | {s.split(" ", 1)[0] for s in stale}
        )
    )
    if unrefreshable and settings.abuse_ch_auth_key is None:
        joined = ", ".join(unrefreshable)
        return (
            f"{joined} need a free abuse.ch Auth-Key. ABUSE_CH_AUTH_KEY is not set, so "
            f"`soc-ai blocklists refresh` skips them. The warning stays until you do one "
            f"of two things. Register at https://auth.abuse.ch/ and set the key. Or remove "
            f"{joined} from blocklist_sources. Triage continues in both cases. See "
            f"docs/BLOCKLISTS.md."
        )
    return (
        "run `soc-ai blocklists refresh`. The abuse.ch feeds need ABUSE_CH_AUTH_KEY. "
        "See docs/BLOCKLISTS.md. Triage keeps working with stale feeds and with "
        "absent feeds."
    )


def check_blocklists(settings: Settings) -> list[CheckResult]:
    """Blocklist feed freshness — file mtime vs ``blocklist_stale_threshold_days``
    (the existing freshness notion the audit warning uses). WARN only: triage is
    fail-open with stale or absent feeds."""
    name = "blocklists"
    configured = [s for s in settings.blocklist_sources if s in _BLOCKLIST_FEED_FILES]
    if not configured:
        return [CheckResult(name, "INFO", "no refreshable blocklist feed is configured.")]
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
            stale.append(f"{source} at {age_days:.0f} days old")
        else:
            fresh += 1
    if not missing and not stale:
        return [
            CheckResult(
                name,
                "PASS",
                f"{fresh} feed(s) are fresh in {settings.blocklist_data_dir}. soc-ai "
                f"refreshed each one within {threshold_days} days.",
            )
        ]
    parts = []
    if missing:
        parts.append("never refreshed: " + ", ".join(missing))
    if stale:
        parts.append(f"stale after {threshold_days} days: " + ", ".join(stale))
    return [
        CheckResult(
            name,
            "WARN",
            ". ".join(parts),
            hint=_blocklist_hint(settings, missing, stale),
        )
    ]


# ── Check 8: prompt assets (FAIL: absence is invisible in the output) ────────


def check_prompt_assets() -> list[CheckResult]:
    """Prompt assets present on disk, per ``soc_ai.agent.prompts.PROMPT_ASSETS``.

    The one doctor row about this deployment's own files rather than an
    upstream. It exists because the doctor reported fifteen passed and zero
    failures on an image whose agent prompts had carried a stub saying the
    query language was unavailable since the day it was built: nothing here
    looked at what the prompts are assembled from, so nothing could say so.

    FAIL, not WARN. The WARN band is for things that degrade gracefully, and a
    missing prompt asset does the opposite: the verdicts keep coming and keep
    looking like verdicts. The app also refuses to start on this condition
    (``soc_ai.main._require_prompt_assets``), so on a normally started instance
    the row is a PASS by construction; it earns its place on the installs that
    reach the doctor another way, which is the CLI inside a container that is
    crash-looping for exactly this reason.
    """
    name = "prompt assets"
    # Deferred: importing the prompts module builds every system prompt (and
    # reads these files) as a side effect of import, and the doctor should pay
    # that only when this check runs. Same pattern as check_egress_posture.
    try:
        from soc_ai.agent.prompts import PROMPT_ASSETS, missing_prompt_assets  # noqa: PLC0415
    except Exception as exc:
        return [
            CheckResult(
                name,
                "FAIL",
                f"the prompt module did not import: {_safe_reason(exc)}",
                hint="The install is broken beyond a missing asset. Run the doctor again "
                "with --json and report it.",
            )
        ]

    missing = missing_prompt_assets()
    present = [asset.name for asset in PROMPT_ASSETS if asset not in missing]
    if not missing:
        root = PROMPT_ASSETS[0].path.parent if PROMPT_ASSETS else "(none declared)"
        return [
            CheckResult(
                name,
                "PASS",
                f"{len(present)} assets are present in {root}: " + ", ".join(present),
            )
        ]
    parts = ["missing: " + ". ".join(f"{a.name} at {a.path} costs: {a.cost}" for a in missing)]
    if present:
        parts.append("present: " + ", ".join(present))
    return [
        CheckResult(
            name,
            "FAIL",
            ". ".join(parts),
            hint="The deployment is incomplete. Redeploy from a build that ships the "
            "docs/ directory. The image copies that directory whole. Until then the "
            "prompts carry a stub. The model writes queries that return nothing.",
        )
    ]


# ── Check 9: the estate model (tier 3, in shadow) ────────────────────────────

# A fit older than this, with the model on, reads as stale. The loop fits once
# a day, so two missed fits in a row.
_ESTATE_STALE_AFTER = timedelta(hours=48)


def _fit_day(at: datetime) -> str:
    return at.strftime("%Y-%m-%d %H:%M UTC")


async def _latest_estate_fit(settings: Settings) -> Any:
    """The newest estate model fit in the store, or None. Raises on a read error."""
    from soc_ai.store import estate_model as estate_store  # noqa: PLC0415

    engine = make_engine(settings)
    try:
        async with make_sessionmaker(engine)() as db:
            return await estate_store.latest_fit(db)
    finally:
        await engine.dispose()


async def _last_fit_when_off(settings: Settings) -> Any:
    """The newest fit for the "off" row, or None. Never raises and never creates a store.

    A setting turned off does not erase the fit it made. The row used to drop
    it: on the range a learning fit ran at 01:50, the setting went back off,
    and the row read "off" with no trace of the fit.
    """
    try:
        if (
            not is_postgres_url(store_url(settings))
            and not (settings.soc_ai_data_dir / SQLITE_FILENAME).exists()
        ):
            return None
        return await _latest_estate_fit(settings)
    except Exception:
        return None


async def check_estate_model(
    settings: Settings, *, now: datetime | None = None
) -> list[CheckResult]:
    """The estate model: unavailable, off, learning, measured, drifted or held.

    The row never imports the extra. An import of scikit-learn costs memory
    for the life of the process, and the in-app preflight runs the doctor.
    ``ml_installed`` asks the import system whether the packages exist.
    """
    from soc_ai.hunting.estate_model import ml_installed  # noqa: PLC0415 - lazy, no numpy
    from soc_ai.store import estate_model as estate_store  # noqa: PLC0415

    name = "estate model"
    enabled = bool(getattr(settings, "estate_model_enabled", False))
    if not ml_installed():
        if not enabled:
            return [
                CheckResult(
                    name,
                    "INFO",
                    "unavailable. The ml extra is not installed. The estate model is off.",
                )
            ]
        return [
            CheckResult(
                name,
                "WARN",
                "unavailable. The estate model is on, and the ml extra is not installed. "
                "soc-ai fits no estate model.",
                hint="Install the extra with `uv sync --extra ml`, or run the container "
                "image. The image includes it.",
            )
        ]
    if not enabled:
        last = await _last_fit_when_off(settings)
        if last is None:
            return [CheckResult(name, "INFO", "off. The ml extra is installed.")]
        return [
            CheckResult(
                name,
                "INFO",
                f"off. The ml extra is installed. The last fit ran on "
                f"{_fit_day(last.fitted_at)}, in state {last.state}.",
            )
        ]
    try:
        fit = await _latest_estate_fit(settings)
    except Exception as exc:
        return [
            CheckResult(
                name,
                "WARN",
                f"soc-ai cannot read the estate model record in the store. {_safe_reason(exc)}",
                hint="Run the store check above. The estate model state is unknown.",
            )
        ]
    if fit is None:
        return [
            CheckResult(
                name, "INFO", "learning. No fit is on record yet. The first fit runs within a day."
            )
        ]
    at = (now or datetime.now(UTC)).astimezone(UTC).replace(tzinfo=None)
    day = _fit_day(fit.fitted_at)
    if at - fit.fitted_at > _ESTATE_STALE_AFTER:
        return [
            CheckResult(
                name,
                "WARN",
                f"stale. The last fit ran on {day}, in state {fit.state}.",
                hint="Read the app log for lines that start with `estate model:`.",
            )
        ]
    if fit.state == estate_store.STATE_MEASURED:
        return [
            CheckResult(
                name,
                "PASS",
                f"measured. The last fit ran on {day}. It read {fit.hosts} hosts in "
                f"{fit.groups} groups and wrote {fit.observations} shadow observations.",
            )
        ]
    reason = f" {fit.reason}" if fit.reason else ""
    return [CheckResult(name, "INFO", f"{fit.state}. The last fit ran on {day}.{reason}")]


# ── Runner ───────────────────────────────────────────────────────────────────


def check_grid_tls(settings: Settings) -> list[CheckResult]:
    """One line when TLS verification to the grid is off, else no row.

    The CLI hides the elasticsearch SecurityWarning about ``verify_certs=False``,
    because the operator chose the setting and the warning headed every
    command. This row keeps the fact in view, once, under the grid row.
    """
    off = [
        name
        for name, verify in (
            ("ES_VERIFY_SSL", settings.es_verify_ssl),
            ("SO_VERIFY_SSL", settings.so_verify_ssl),
        )
        if not verify
    ]
    if not off:
        return []
    names = " and ".join(off)
    verb = "is" if len(off) == 1 else "are"
    return [
        CheckResult(
            "grid tls",
            "INFO",
            f"TLS verification to the grid is off. {names} {verb} false. soc-ai accepts "
            "any certificate from the grid.",
        )
    ]


def _insert_after(results: list[CheckResult], name: str, rows: list[CheckResult]) -> None:
    """Put *rows* after the last row named *name*, or at the end when there is none."""
    if not rows:
        return
    at = max((i for i, r in enumerate(results) if r.name == name), default=len(results) - 1)
    results[at + 1 : at + 1] = rows


async def _solo(coro: Awaitable[CheckResult]) -> list[CheckResult]:
    """Adapt a single-``CheckResult`` check coroutine into ``_isolated``'s list contract."""
    return [await coro]


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
                f"the check timed out after {timeout_s:.0f} s",
                hint="The service accepted the connection and then stopped answering. "
                "Check its health and the network path.",
            )
        ]
    except Exception as exc:
        return [
            CheckResult(
                name,
                "FAIL",
                _safe_reason(exc),
                hint="The doctor met an unexpected error. Run it again with --json and report it.",
            )
        ]


async def run_doctor(
    settings: Settings | None = None, *, include_fitness: bool = True
) -> list[CheckResult]:
    """Run every doctor check; return the results in display order.

    ``settings=None`` (the CLI path) loads Settings from env/.env as check 1;
    when that fails the dependent checks are skipped (nothing can run without
    a config) and the single FAIL comes back. Passing a ``Settings`` (tests /
    embedding) skips the env load but still records config as PASS.

    ``include_fitness`` (default True, unchanged CLI behavior) gates the model
    fitness check — the one expensive probe (worst-case ~130s,
    ``_FITNESS_TIMEOUT_S``). The cached preflight API (routes_meta.py) passes
    ``include_fitness=False`` so a dashboard poll never pays that cost; the
    fitness card in the config console still runs it directly.
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
                    "the settings did not load. soc-ai skipped the store, security "
                    "onion, elasticsearch, gateway and model checks.",
                )
            )
            return results
        # Grade what the app runs, not just what the file says. A caller that
        # passed its own Settings (the in-app preflight) already holds the live
        # singleton with these applied.
        applied = await apply_persisted_overrides(settings)
        if applied:
            cfg.detail += (
                f" The config console holds {len(applied)} saved non-secret "
                f"setting{'' if len(applied) == 1 else 's'}: "
                f"{', '.join(sorted(applied))}. Saved secrets also apply. This list does not "
                "show them."
            )
    else:
        results.append(CheckResult("config", "PASS", "settings loaded"))

    # Independent upstreams — run concurrently so a slow one doesn't serialize
    # the rest; each is individually bounded and never raises.
    checks: list[Awaitable[list[CheckResult]]] = [
        _isolated(
            "upstream reachability",
            check_upstream_reachability(settings),
            _REACH_TIMEOUT_S,
        ),
        _isolated("store", check_store(settings), _STORE_TIMEOUT_S),
        _isolated("security onion", check_so_api(settings), _SO_TIMEOUT_S),
        _isolated("elasticsearch", check_elasticsearch(settings), _ES_TIMEOUT_S),
        _isolated(
            "audit write grant",
            _solo(check_audit_write_privileges(settings)),
            _AUDIT_TIMEOUT_S,
        ),
        _isolated(
            "index pattern coverage",
            _solo(check_index_pattern_coverage(settings)),
            _COVERAGE_TIMEOUT_S,
        ),
        _isolated(
            "alerts feed filter",
            _solo(check_alerts_feed_filter(settings)),
            _ALERT_FILTER_TIMEOUT_S,
        ),
        _isolated("audit chain", _solo(check_audit_chain(settings)), _AUDIT_CHAIN_WRAP_S),
        _isolated("gateway", check_gateway(settings), _GATEWAY_TIMEOUT_S),
        _isolated("oracle route", check_oracle_route(settings), _ORACLE_ROUTE_TIMEOUT_S),
        _isolated("estate model", check_estate_model(settings), _STORE_TIMEOUT_S),
    ]
    if include_fitness:
        checks.append(_isolated("model fitness", check_model_fitness(settings), _FITNESS_TIMEOUT_S))
    batches = await asyncio.gather(*checks)
    for batch in batches:
        results.extend(batch)
    _insert_after(results, "elasticsearch", check_grid_tls(settings))
    results.extend(check_egress_posture(settings))
    results.extend(check_authentication(settings))
    results.extend(check_tls(settings))
    results.extend(check_blocklists(settings))
    results.extend(check_prompt_assets())
    return results
