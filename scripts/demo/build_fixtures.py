"""Build ``soc_ai/demo/fixtures.json`` from recorded runs.

Inputs:

* eval bundle dirs (``evals/<batch>/<run>/`` — ``meta.json`` + ``events.jsonl``
  + ``mapping.json``), recorded on a live grid and sanitized at capture time.
  Each bundle's own ``mapping.json`` is used to REHYDRATE its capture-time
  labels first, so re-sanitizing everything through ONE shared
  :class:`~soc_ai.oracle.sanitize.Mapping` yields pseudonyms that are stable
  across the whole fixture set — the same host keeps the same label in every
  record. The rehydrated originals never touch disk.
* optionally (``--db``) a store sqlite file with hunts/backtests recorded on
  a live grid; opened read-only, ``complete`` rows only.
* optionally (``--replay``, repeatable) bundle dirs to emit as
  click-to-investigate recordings: the alert doc lands in ``alerts[]`` (the
  queue shows it un-investigated) and the run in ``replays[]``
  (``{alert_es_id, investigation{...}, events[]}`` — the shape
  ``soc_ai.demo.replay.find_replay`` consumes), NOT in ``investigations[]``.
* optionally (``--hunts-file``) a JSON list of authored, pre-sanitized hunt
  rows appended to ``hunts[]`` (``scripts/demo/demo_hunts.json``), and
  (``--chats-file``) a JSON list of canned chat threads emitted as the
  ``chats[]`` section (``scripts/demo/demo_chats.json``). Both ride the shared
  mapping + leak gates; hunts are timestamp-rebased with the rest, chats are
  request-time content (like ``replays``) so they are only sanitized + gated.

Timestamps are rebased (newest ``finished_at`` lands at build time, relative
ordering preserved) BEFORE sanitization, so the demo always looks recent.

Every output value then passes three independent gates:
:func:`~soc_ai.oracle.sanitize.sanitize` with the shared mapping,
:func:`~soc_ai.oracle.sanitize.unsafe_residue` over the raw string values
(fed every real value learned from the bundle mappings; see
:func:`residue_scan`), and the public-mirror leak patterns parsed at run
time from the mirror build script — the publish gate's single source of
truth, so the two scans cannot drift and no pattern is ever spelled out here
(this file ships in the public tree; the mirror script does not). Any hit
fails the build with a non-zero exit.

The emitted file still requires manual owner review before commit
(spec: docs/dev/superpowers/specs/2026-07-12-demo-site-design.md).
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import re
import sqlite3
import sys
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
_MIRROR = REPO / "scripts" / "build-public-mirror.sh"

# Crockford base32 (the ULID alphabet) — deterministic demo row ids.
_ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

# Dict keys that carry ISO-8601 timestamps to rebase: the store row columns
# plus the alert timestamps inside event payloads / mock-ES documents.
_TIME_KEYS = frozenset({"created_at", "finished_at", "timestamp", "@timestamp"})


# ---------------------------------------------------------------------------
# Leak gate (patterns parsed from the mirror build script — source of truth)
# ---------------------------------------------------------------------------


def leak_patterns() -> list[str]:
    """Parse the ``grep -e '…'`` pattern block out of the mirror build script."""
    # Assumes the mirror script's only `-e '...'` occurrences ARE the leak-grep
    # block; anything else (say a future `sed -e`) would over-capture — which
    # fails in the safe direction (extra patterns make the gate stricter).
    return re.findall(r"-e '([^']+)'", _MIRROR.read_text())


def scan_for_leaks(text: str) -> list[str]:
    """Return every mirror leak pattern that matches *text* (empty == clean)."""
    return [p for p in leak_patterns() if re.search(p, text)]


def _raw_strings(node: Any, out: list[str]) -> None:
    """Collect every raw string in *node* (dict keys and values included)."""
    if isinstance(node, str):
        out.append(node)
    elif isinstance(node, dict):
        for key, value in node.items():
            _raw_strings(key, out)
            _raw_strings(value, out)
    elif isinstance(node, list | tuple):
        for item in node:
            _raw_strings(item, out)


def locate_pattern_hits(fixtures: dict[str, Any]) -> list[str]:
    """Name each top-level record whose serialized form trips a mirror pattern.

    Gate-failure attribution for the curation operator: the build writes no
    output file on a hit, so this is the only way to learn WHICH record to
    drop or scrub without re-running bundles one by one.
    """
    locations: list[str] = []
    for section in ("investigations", "hunts", "backtests", "alerts", "replays", "chats"):
        for index, record in enumerate(fixtures.get(section) or []):
            hits = scan_for_leaks(json.dumps(record, ensure_ascii=False))
            if hits:
                rid = record.get("id") or record.get("_id") or record.get("alert_es_id") or "?"
                locations.append(f"{section}[{index}] (id={rid}): {hits}")
    return locations


def _gate_or_exit(fixtures: dict[str, Any], blob: str, known_values: tuple[str, ...]) -> None:
    """Run both leak arms; exit non-zero (naming the offending record) on any hit.

    The residue arm scans the RAW string values (``residue_scan`` — JSON escaping
    is an artifact, not content); the mirror-pattern arm scans the serialized
    ``blob``, exactly what CI greps. Covers every fixtures section (investigations,
    hunts, backtests, alerts, replays, chats)."""
    residue = residue_scan(fixtures, known_values=known_values)
    hits = scan_for_leaks(blob)
    if residue or hits:
        where = locate_pattern_hits(fixtures) if hits else []
        detail = f" — pattern hits in: {'; '.join(where)}" if where else ""
        sys.exit(f"LEAK GATE FAILED — residue={residue} patterns={hits}{detail}")


def residue_scan(fixtures: Any, known_values: tuple[str, ...] = ()) -> list[str]:
    """``unsafe_residue`` over the ACTUAL string values, not the JSON blob.

    json.dumps escaping necessarily writes two-char backslash sequences inside
    strings (a newline becomes backslash + ``n``), which the credential-context
    residue net reads as a ``DOMAIN\\logon`` shape — 55 of 64 recent bundles
    failed solely on that artifact. Scanning the raw values (real newlines, no
    escaping) removes the artifact without weakening the net: every string the
    file carries still passes through ``unsafe_residue``, and a genuine
    ``DOMAIN\\user`` inside a value is exactly the single-backslash form the
    net is built for. The mirror-pattern arm stays on the serialized blob —
    that mirrors what CI greps.
    """
    from soc_ai.oracle.sanitize import unsafe_residue

    parts: list[str] = []
    _raw_strings(fixtures, parts)
    return unsafe_residue("\n".join(parts), known_values=known_values)


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _first_payload(events: list[dict[str, Any]], kind: str) -> dict[str, Any]:
    """The payload of the first event of *kind* (empty dict if absent)."""
    for row in events:
        if row.get("kind") == kind:
            return dict(row.get("payload") or {})
    return {}


def _demo_id(seed: str) -> str:
    """Deterministic 26-char ULID-shaped row id ("01DEMO" + 20 hash chars).

    Stable across rebuilds (same alert → same id) so owner-review diffs of a
    regenerated fixture file only show real content changes.
    """
    digest = hashlib.sha256(f"demo-fixture:{seed}".encode()).digest()
    return "01DEMO" + "".join(_ULID_ALPHABET[b % 32] for b in digest[:20])


def _parse_dt(value: str) -> datetime:
    """ISO-8601 → aware UTC datetime (naive values are treated as UTC)."""
    dt = datetime.fromisoformat(value)
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt


def _load_json(value: Any) -> Any:
    """A sqlite JSON column value → Python (SQLAlchemy stores JSON as TEXT)."""
    if value is None or isinstance(value, dict | list):
        return value
    return json.loads(value)


# ---------------------------------------------------------------------------
# Record mappers (bundle → fixture schema rows)
# ---------------------------------------------------------------------------


def _investigation_from(meta: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, Any]:
    """Map one eval bundle onto the Task-4 investigation fixture row.

    ``status`` is always ``"complete"`` (the real lifecycle value — the API
    rejects anything else), ``started_by`` is always ``"demo"`` (never the
    recorded operator). Fields the bundle genuinely lacks stay ``None`` — the
    API/UI already fall back (e.g. rationale → summary); nothing is invented.
    """
    triage = _first_payload(events, "triage_report")
    if not triage:
        raise ValueError("bundle has no triage_report event — not a completed run")
    alert = _first_payload(events, "enriched_alert_context").get("alert") or {}
    alert_label = str(meta.get("alert_id_label") or meta.get("alert_id") or "")
    created = _parse_dt(meta["timestamp_utc"])
    finished = created + timedelta(milliseconds=int(meta.get("investigation_elapsed_ms") or 60000))
    confidence = meta.get("confidence")
    if confidence is None:
        confidence = triage.get("confidence")
    return {
        "id": _demo_id(alert_label),
        "alert_es_id": alert_label,
        "rule_name": alert.get("rule_name"),
        "verdict": meta.get("verdict") or triage.get("verdict"),
        "confidence": confidence,
        "rationale": triage.get("rationale"),
        "summary": triage.get("summary"),
        "report": triage,
        "src_ip": alert.get("source_ip"),
        "dest_ip": alert.get("destination_ip"),
        "status": "complete",
        "started_by": "demo",
        "created_at": created.isoformat(),
        "finished_at": finished.isoformat(),
        "events": [
            {"kind": row["kind"], "sequence": row["sequence"], "payload": row.get("payload") or {}}
            for row in events
        ],
    }


def _alert_doc_from(meta: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The mock-ES document for the alerts queue (scripts/demo/mock_es.py shape).

    Built from the bundle's enriched alert context; ``None`` when the bundle
    carries no context (nothing to honestly show in the queue).
    """
    alert = _first_payload(events, "enriched_alert_context").get("alert") or {}
    if not alert:
        return None
    dataset = alert.get("event_dataset") or "suricata.alert"
    source: dict[str, Any] = {
        "@timestamp": alert.get("timestamp") or meta.get("timestamp_utc"),
        "event": {
            "dataset": dataset,
            "severity_label": alert.get("severity_label") or "low",
            "acknowledged": False,
            "escalated": False,
        },
        "source": {"ip": alert.get("source_ip"), "port": alert.get("source_port")},
        "destination": {"ip": alert.get("destination_ip"), "port": alert.get("destination_port")},
    }
    if alert.get("host_name"):
        source["host"] = {"name": alert["host_name"]}
    if alert.get("rule_name"):
        if dataset.endswith(".notice"):
            source["notice"] = {"note": alert["rule_name"]}
        else:
            source["rule"] = {"name": alert["rule_name"]}
    return {
        "_index": "logs-demo",
        "_id": str(meta.get("alert_id_label") or alert.get("id") or ""),
        "_source": source,
    }


def _hunts_and_backtests(db: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Copy complete hunts (+ their events) and backtests out of a store sqlite file."""
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        hunts: list[dict[str, Any]] = []
        for row in conn.execute(
            "SELECT id, objective, objective_hash, kind, status, narrative, report,"
            " created_at, finished_at FROM hunts WHERE status = 'complete' ORDER BY created_at"
        ):
            events = [
                {
                    "kind": ev["kind"],
                    "sequence": ev["sequence"],
                    "payload": _load_json(ev["payload"]) or {},
                }
                for ev in conn.execute(
                    "SELECT sequence, kind, payload FROM hunt_events"
                    " WHERE hunt_id = ? ORDER BY sequence",
                    (row["id"],),
                )
            ]
            hunts.append(
                {
                    "id": row["id"],
                    "objective": row["objective"],
                    "objective_hash": row["objective_hash"],
                    "kind": row["kind"],
                    "status": "complete",
                    "narrative": row["narrative"],
                    "report": _load_json(row["report"]),
                    "started_by": "demo",  # never the recorded operator
                    "created_at": row["created_at"],
                    "finished_at": row["finished_at"],
                    "events": events,
                }
            )
        backtests: list[dict[str, Any]] = []
        for row in conn.execute(
            "SELECT id, params, status, sampled, results, created_at, finished_at"
            " FROM backtests WHERE status = 'complete' ORDER BY created_at"
        ):
            backtests.append(
                {
                    "id": row["id"],
                    "params": _load_json(row["params"]) or {},
                    "status": "complete",
                    "sampled": row["sampled"],
                    "results": _load_json(row["results"]),
                    "started_by": "demo",
                    "created_at": row["created_at"],
                    "finished_at": row["finished_at"],
                }
            )
    finally:
        conn.close()
    return hunts, backtests


# ---------------------------------------------------------------------------
# Timestamp rebasing (BEFORE sanitization/gating; preserves relative order)
# ---------------------------------------------------------------------------


def _rebase_delta(rows: list[dict[str, Any]], now: datetime) -> timedelta | None:
    """``now - max(finished_at)`` over the parent rows (None if nothing parses)."""
    finished: list[datetime] = []
    for row in rows:
        value = row.get("finished_at")
        if isinstance(value, str):
            with contextlib.suppress(ValueError):
                finished.append(_parse_dt(value))
    return (now - max(finished)) if finished else None


def _shift_iso(value: str, delta: timedelta) -> str:
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return value
    shifted = (dt + delta).isoformat()
    return shifted.replace("+00:00", "Z") if value.endswith("Z") else shifted


def _shift_times(node: Any, delta: timedelta) -> Any:
    """Recursively shift every ISO string under a `_TIME_KEYS` dict key by *delta*."""
    if isinstance(node, dict):
        return {
            k: (
                _shift_iso(v, delta)
                if k in _TIME_KEYS and isinstance(v, str)
                else _shift_times(v, delta)
            )
            for k, v in node.items()
        }
    if isinstance(node, list):
        return [_shift_times(item, delta) for item in node]
    return node


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------


def _load_authored_hunts(
    hunts_file: Path, claim: Callable[[dict[str, Any]], None]
) -> list[dict[str, Any]]:
    """Parse the authored-hunts JSON list, claiming each row's id (dedup)."""
    authored = json.loads(hunts_file.read_text())
    if not isinstance(authored, list):
        sys.exit(f"{hunts_file}: expected a JSON list of hunt rows")
    for hunt in authored:
        if "id" not in hunt:
            sys.exit(f"{hunts_file}: a hunt row is missing its 'id'")
        claim(hunt)
    return authored


def _load_chats(chats_file: Path) -> list[dict[str, Any]]:
    """Parse the canned-chats JSON list (request-time content — not seeded)."""
    loaded = json.loads(chats_file.read_text())
    if not isinstance(loaded, list):
        sys.exit(f"{chats_file}: expected a JSON list of chat threads")
    return loaded


def _load_bundle(bundle: Path, known: set[str]) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Read + rehydrate one bundle → (investigation record, alert doc or None).

    Exits naming the bundle path on any malformed/incomplete input — an
    operator feeding 20 bundles must learn WHICH one failed. Bad JSON is
    covered too: JSONDecodeError is a ValueError subclass. Real values from
    the bundle's capture-time mapping are added to *known* for the residue net.
    """
    from soc_ai.oracle.sanitize import Mapping, desanitize

    try:
        meta = json.loads((bundle / "meta.json").read_text())
        events = [
            json.loads(line)
            for line in (bundle / "events.jsonl").read_text().splitlines()
            if line.strip()
        ]
        mapping_file = bundle / "mapping.json"
        if mapping_file.exists():
            recorded = json.loads(mapping_file.read_text())
            bundle_map = Mapping(
                forward=dict(recorded.get("forward") or {}),
                reverse=dict(recorded.get("reverse") or {}),
            )
            known.update(bundle_map.forward)
            # Rehydrate the capture-time labels (each bundle allocated its own
            # IP_01…) so the shared-mapping re-sanitize in build() assigns
            # pseudonyms that are consistent across the whole fixture set.
            meta = desanitize(meta, bundle_map)
            events = desanitize(events, bundle_map)
        return _investigation_from(meta, events), _alert_doc_from(meta, events)
    except (ValueError, KeyError, OSError) as exc:
        sys.exit(f"{bundle}: {type(exc).__name__}: {exc}")


def build(
    bundle_dirs: list[Path],
    db: Path | None,
    out: Path,
    replay_dirs: list[Path] | None = None,
    hunts_file: Path | None = None,
    chats_file: Path | None = None,
) -> None:
    from soc_ai.oracle.sanitize import Mapping, sanitize

    patterns = leak_patterns()
    if not patterns:
        sys.exit(f"cannot parse leak patterns from {_MIRROR} — refusing to build without a gate")

    mapping = Mapping()  # ONE instance — a host stays the same host across the demo
    known: set[str] = set()  # every real value seen at capture time, for the residue net

    investigations: list[dict[str, Any]] = []
    alerts: list[dict[str, Any]] = []
    replays: list[dict[str, Any]] = []
    seen_ids: dict[str, Path] = {}

    def _claim_id(
        record: dict[str, Any],
        bundle: Path,
        *,
        kind: str = "investigation",
        detail: str = "record the same alert; pick distinct alerts",
    ) -> None:
        # The id is derived from the alert, so two bundles recording the same
        # alert collide — and the idempotent seeder would silently drop the
        # second row (or a replay alert would arrive pre-investigated). Fail
        # loudly: that is a curation error to fix upstream. Spans --bundles,
        # --replay AND authored --hunts-file rows (shared id namespace so an
        # authored hunt id can never shadow another seeded row either).
        earlier = seen_ids.get(record["id"])
        if earlier is not None:
            sys.exit(
                f"duplicate {kind} id {record['id']} — {earlier} and {bundle} {detail}"
            )
        seen_ids[record["id"]] = bundle

    for bundle in bundle_dirs:
        record, doc = _load_bundle(bundle, known)
        _claim_id(record, bundle)
        investigations.append(record)
        if doc is not None:
            alerts.append(doc)

    # --replay bundles become click-to-investigate recordings: the alert doc
    # lands in the queue (alerts[]) looking un-investigated, the run itself
    # ships in replays[] for soc_ai/demo/replay.py to stream through the live
    # recorder when the visitor clicks Investigate — NOT in investigations[],
    # which would pre-seed the verdict and spoil the click.
    for bundle in replay_dirs or []:
        record, doc = _load_bundle(bundle, known)
        _claim_id(record, bundle)
        if doc is None:
            sys.exit(
                f"{bundle}: replay bundle carries no enriched alert context — no alert "
                "doc means nothing appears in the demo queue for the visitor to click"
            )
        events = record.pop("events")
        replays.append(
            {"alert_es_id": record["alert_es_id"], "investigation": record, "events": events}
        )
        alerts.append(doc)

    hunts: list[dict[str, Any]] = []
    backtests: list[dict[str, Any]] = []
    if db is not None:
        hunts, backtests = _hunts_and_backtests(db)

    # Authored, pre-sanitized hunt rows (scripts/demo/demo_hunts.json): a small,
    # reviewed set of demo hunts so the Hunt Console has content to browse even
    # when no live store was captured. They ride the SAME shared mapping + leak
    # gates + timestamp rebase as everything else. Their ids share the dedup
    # namespace so an authored hunt can never shadow another seeded row.
    if hunts_file is not None:
        hunts.extend(
            _load_authored_hunts(
                hunts_file,
                lambda h: _claim_id(
                    h,
                    hunts_file,
                    kind="hunt",
                    detail="both define this authored hunt; hunt ids must be unique",
                ),
            )
        )

    # Canned chat threads (scripts/demo/demo_chats.json): scripted replies the
    # demo serves for a seeded investigation/hunt instead of calling an LLM
    # (soc_ai/demo/chat.py). Consumed at request time — like replays[], the
    # seeder ignores them — so they are NOT time-rebased (they carry no
    # created_at/finished_at), only sanitized + gated.
    chats: list[dict[str, Any]] = _load_chats(chats_file) if chats_file is not None else []

    replay_parents = [r["investigation"] for r in replays]
    delta = _rebase_delta([*investigations, *hunts, *backtests, *replay_parents], datetime.now(UTC))
    if delta is not None:
        investigations = _shift_times(investigations, delta)
        hunts = _shift_times(hunts, delta)
        backtests = _shift_times(backtests, delta)
        alerts = _shift_times(alerts, delta)
        replays = _shift_times(replays, delta)

    fixtures: dict[str, Any] = {
        "version": 1,
        "investigations": [sanitize(r, mapping) for r in investigations],
        "hunts": [sanitize(r, mapping) for r in hunts],
        "backtests": [sanitize(r, mapping) for r in backtests],
        "alerts": [sanitize(r, mapping) for r in alerts],
        "replays": [sanitize(r, mapping) for r in replays],
        "chats": [sanitize(r, mapping) for r in chats],
    }

    # ensure_ascii=False keeps the file human-reviewable and identical to what
    # the store holds after seeding. The residue arm scans the RAW string
    # values (residue_scan — JSON escaping is an artifact, not content); the
    # mirror-pattern arm scans the serialized blob, exactly what CI greps.
    blob = json.dumps(fixtures, indent=1, ensure_ascii=False)
    known.update(mapping.forward)  # values the re-sanitize pass learned, too
    _gate_or_exit(fixtures, blob, tuple(known))
    out.write_text(blob + "\n", encoding="utf-8")
    print(
        f"wrote {out} ({len(fixtures['investigations'])} investigations, "
        f"{len(fixtures['hunts'])} hunts, {len(fixtures['backtests'])} backtests, "
        f"{len(fixtures['alerts'])} alerts, {len(fixtures['replays'])} replays, "
        f"{len(fixtures['chats'])} chats) "
        "— owner review required before commit"
    )


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Build the sanitized demo fixture set from recorded runs."
    )
    parser.add_argument(
        "--bundles",
        nargs="+",
        type=Path,
        default=[],
        metavar="DIR",
        help="eval bundle dirs (evals/<batch>/<run>/ with meta.json + events.jsonl)",
    )
    parser.add_argument(
        "--replay",
        action="append",
        type=Path,
        default=[],
        dest="replays",
        metavar="DIR",
        help="eval bundle dir to emit as a click-to-investigate replay (repeatable): "
        "its alert doc lands in alerts[] and its run in replays[], NOT investigations[]",
    )
    parser.add_argument(
        "--db", type=Path, default=None, help="store sqlite file for hunts/backtests (read-only)"
    )
    parser.add_argument(
        "--hunts-file",
        type=Path,
        default=None,
        metavar="FILE",
        help="authored, pre-sanitized hunt rows (JSON list) to add to hunts[] "
        "(scripts/demo/demo_hunts.json)",
    )
    parser.add_argument(
        "--chats-file",
        type=Path,
        default=None,
        metavar="FILE",
        help="canned chat threads (JSON list) for the chats[] section "
        "(scripts/demo/demo_chats.json)",
    )
    parser.add_argument("--out", type=Path, default=REPO / "soc_ai" / "demo" / "fixtures.json")
    args = parser.parse_args(argv)
    if (
        not args.bundles
        and not args.replays
        and args.db is None
        and args.hunts_file is None
        and args.chats_file is None
    ):
        parser.error(
            "nothing to build — pass --bundles, --replay, --db, --hunts-file and/or --chats-file"
        )
    build(
        list(args.bundles),
        args.db,
        args.out,
        replay_dirs=list(args.replays),
        hunts_file=args.hunts_file,
        chats_file=args.chats_file,
    )


if __name__ == "__main__":
    main()
