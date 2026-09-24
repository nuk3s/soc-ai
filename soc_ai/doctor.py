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
import socket
import ssl
from collections.abc import Awaitable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import urlparse

from alembic.script import ScriptDirectory
from elasticsearch import ApiError, AuthenticationException
from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from soc_ai.config import DEFAULT_ALERTS_QUERY, Settings
from soc_ai.errors import OqlValidationError, SoAuthError
from soc_ai.so_client.auth import make_auth
from soc_ai.so_client.elastic import ElasticClient, GridPartialResultsError
from soc_ai.store.db import _migration_config, make_engine
from soc_ai.webui import alerts_query as aq
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
_FITNESS_TIMEOUT_S = 150.0  # probes._FITNESS_TOTAL_TIMEOUT_S (130s) + headroom

# Client-side per-request timeout for the doctor's ES calls — deliberately
# tighter than the app's es_request_timeout_s (30s) so a slow/wedged cluster
# fails fast here, and with retries off (one honest attempt, not 3).
_ES_REQUEST_TIMEOUT_S = 5


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
    return settings, CheckResult("config", "PASS", "settings loaded from env/.env")


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

    if not (settings.soc_ai_data_dir / "soc-ai.db").exists():
        return []
    engine = None
    try:
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
                f"soc-ai cannot open the store at {db_path}. {_safe_reason(exc)}",
                hint="Check that SOC_AI_DATA_DIR exists. This user must be able to write to it.",
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
                hint=f"Check the permissions on the store DB file at {db_path}. The file "
                "can also be corrupt.",
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
    try:
        info = await elastic.ping()
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
        return [
            CheckResult(
                name,
                "FAIL",
                f"unreachable: {_safe_reason(exc)}",
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
                "If ack, escalate or comment fail silently once ES answers, the "
                f"grant can be missing. {fix}"
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
            "silently, check the grant by hand. See docs/SECURITY-ONION-SETUP.md, "
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
        return [
            CheckResult("egress", "INFO", f"the egress posture is unavailable: {_safe_reason(exc)}")
        ]
    zero_egress = not any(row["enabled"] for row in rows)
    results = [
        CheckResult(
            "egress",
            "INFO",
            "zero egress: " + ("yes. Every egress destination is off." if zero_egress else "no."),
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
                f"{state}. {row['label']}. Redaction: {row['redaction']}.",
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
            f"`soc-ai blocklists refresh` skips them. This warning cannot clear. Register "
            f"at https://auth.abuse.ch/ and set the key. You can instead drop {joined} "
            f"from blocklist_sources. Triage is fail-open either way. See "
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


# ── Runner ───────────────────────────────────────────────────────────────────


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
                f" The config console holds {len(applied)} saved setting(s): "
                f"{', '.join(sorted(applied))}."
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
        _isolated("gateway", check_gateway(settings), _GATEWAY_TIMEOUT_S),
    ]
    if include_fitness:
        checks.append(_isolated("model fitness", check_model_fitness(settings), _FITNESS_TIMEOUT_S))
    batches = await asyncio.gather(*checks)
    for batch in batches:
        results.extend(batch)
    results.extend(check_egress_posture(settings))
    results.extend(check_blocklists(settings))
    results.extend(check_prompt_assets())
    return results
