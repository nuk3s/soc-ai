"""Dependency-surface health checks behind ``soc-ai doctor``.

One command an installer/operator runs right after setup — or when something is
wrong — that probes every external dependency the app needs (config, the local
store + migration head, the Security Onion API, Elasticsearch, the audit write
grant, index-pattern dataset coverage, the LiteLLM gateway, and the analyst
model's actual fitness) and returns structured pass/fail results. Pure logic
lives here; ``soc_ai.cli`` owns argparse and the table/JSON printing.

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

from soc_ai.config import Settings
from soc_ai.errors import SoAuthError
from soc_ai.so_client.auth import make_auth
from soc_ai.so_client.elastic import ElasticClient, GridPartialResultsError
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
    "This container can't resolve the hostname. Use an IP address in .env, or add "
    "an extra_hosts entry for it in docker-compose.yml."
)
_REACH_SO_ES_FIREWALL_HINT = (
    "No route or refused. Pinhole this host's IP through the SO firewall "
    "(Elasticsearch is TCP 9200) — docs/SECURITY-ONION-SETUP.md, section 0."
)
_REACH_TLS_FALLBACK_NOTE = "If the endpoint isn't serving TLS on this port, use http:// instead."
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
        "No route or refused. Check the gateway URL and port, and that the gateway "
        "process/container is up and reachable from inside this container (Docker network)."
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
        return "dns", f"{host}: DNS resolution failed inside the container ({exc})"
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
        return "tls", f"{host}:{port}: TLS verification failed ({exc})"
    except ssl.SSLError as exc:
        # Broader than a cert-trust failure: the TCP connection succeeded but
        # the peer didn't speak TLS at all (e.g. an http-only service sitting
        # behind an https:// URL). Order matters — SSLCertVerificationError
        # is an SSLError subclass, so this arm MUST come after it, and both
        # MUST come before the OSError arm (SSLError is also an OSError).
        return "tls", f"{host}:{port}: TLS handshake failed ({exc})"
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
            es_note = f" (first of {es_host_count} es_hosts)"
        if kind:
            results.append(
                CheckResult(name, "FAIL", f"{detail}{es_note}", hint=_REACH_HINTS[(slug, kind)])
            )
            continue
        first = url.split(",", maxsplit=1)[0].strip()
        scheme = urlparse(first if "//" in first else f"//{first}").scheme
        tls_note = ", TLS verifies" if verify and scheme == "https" else ""
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
    elastic = _probe_client(settings)
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
        "Run on the SO manager: "
        "ssh <admin>@<so-manager> 'sudo bash -s' < scripts/setup-audit-index.sh "
        "(docs/SECURITY-ONION-SETUP.md, section 3)"
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
            f"couldn't query _has_privileges: {_safe_reason(exc)}",
            hint=(
                "Fix Elasticsearch connectivity first, then re-run the doctor. "
                f"If ack/escalate/comment fail silently once ES is reachable, the "
                f"grant may be missing. {fix}"
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
            "unexpected _has_privileges response shape — couldn't determine whether "
            "the audit grant is present",
            hint="Not a confirmed problem — verify the grant manually "
            "(docs/SECURITY-ONION-SETUP.md, section 3) if ack/escalate/comment ever "
            "fail silently.",
        )
    if bool(body["has_all_requested"]):
        return CheckResult(
            name, "PASS", f"{settings.audit_index_alias}-* is writable by the ES identity"
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
            "every ack/escalate/comment will abort (fail-closed audit), with no UI error"
            if settings.audit_fail_closed
            else "the forensic audit trail is being dropped "
            "(audit_fail_closed=false: actions still succeed)"
        )
        return CheckResult(
            name,
            "FAIL",
            f"the ES identity is missing {', '.join(write_missing)} on {index_name} — "
            f"{consequence}",
            hint=fix,
        )
    if read_missing:
        return CheckResult(
            name,
            "WARN",
            f"the ES identity is missing {', '.join(read_missing)} on {index_name} — "
            "audit chain verification and chain-head recovery will fail",
            hint=fix,
        )
    return CheckResult(
        name,
        "WARN",
        f"_has_privileges reported {index_name} as not fully granted but named no "
        "specific missing privilege — unexpected response shape",
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
    """
    name = "index pattern coverage"
    pattern = settings.events_index_pattern
    hint_connectivity = "Fix Elasticsearch connectivity first, then re-run the doctor."
    elastic = _probe_client(settings)
    try:
        results = await asyncio.gather(
            *(
                elastic.search(
                    pattern,
                    {"term": {"event.dataset": dataset}},
                    size=0,
                    track_total_hits=True,
                )
                for dataset in _COVERAGE_DATASETS
            )
        )
    except GridPartialResultsError as exc:
        return CheckResult(
            name,
            "WARN",
            f"the grid returned partial results counting datasets under {pattern!r} — "
            f"some shards failed; counts are unreliable ({_safe_reason(exc)})",
            hint=hint_connectivity,
        )
    except Exception as exc:
        return CheckResult(
            name,
            "WARN",
            f"couldn't count datasets under {pattern!r}: {_safe_reason(exc)}",
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
            f"{pattern!r} sees alerts but zero auth/syslog events ({detail_counts}) — "
            "the pattern is likely narrowed to backing indices",
            hint="Set EVENTS_INDEX_PATTERN=logs-* (multi-node: *:logs-*). Never list "
            ".ds-* backing indices — see the warning block in .env.example.",
        )
    if alerts == 0 and auth == 0 and syslog == 0:
        return CheckResult(
            name,
            "WARN",
            f"{pattern!r} matches no suricata/auth/syslog events",
            hint="Wrong pattern or an idle grid. Single-node grids use logs-*, "
            "multi-node *:logs-*.",
        )
    if alerts == 0:
        # auth and/or syslog are present, so the pattern itself is fine — just
        # a quiet alert stream (idle grid, or Suricata not yet firing).
        return CheckResult(
            name,
            "PASS",
            f"{pattern!r}: {detail_counts} — no suricata.alert events; "
            "the triage queue will be empty",
        )
    return CheckResult(name, "PASS", f"{pattern!r}: {detail_counts}")


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
                    "store / security onion / elasticsearch / gateway / model checks "
                    "skipped — settings did not load",
                )
            )
            return results
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
        _isolated("gateway", check_gateway(settings), _GATEWAY_TIMEOUT_S),
    ]
    if include_fitness:
        checks.append(_isolated("model fitness", check_model_fitness(settings), _FITNESS_TIMEOUT_S))
    batches = await asyncio.gather(*checks)
    for batch in batches:
        results.extend(batch)
    results.extend(check_egress_posture(settings))
    results.extend(check_blocklists(settings))
    return results
