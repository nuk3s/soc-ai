"""Shipped starter-pack runbooks: lenient front-matter parsing + directory loading.

The repo ships a small pack of generic, vendor-neutral SOC runbooks under
``runbooks/starter-pack/*.md`` (top level, next to ``soc_ai/`` — copied into the
Docker image alongside the source, same layout as the frontend bundle).
``POST /runbooks/starter-pack`` loads them server-side and creates any runbook
whose title isn't already in the store, so a fresh install gets a useful corpus
for the agent's ``lookup_runbook`` tool in one click — and re-running the
endpoint is a no-op (idempotent by title).

The browser "Import files…" flow (frontend Runbooks page) parses the SAME
front-matter dialect client-side — keep the two parsers' semantics aligned:

* an optional ``---``-fenced YAML block at the very top of the file;
* ``title`` (string), ``tags`` / ``rules`` (or ``linked_rules``) — lists,
  comma-separated strings, or single scalars all accepted;
* malformed YAML is silently ignored — the file still imports, metadata is a
  bonus, never a gate (operators paste runbooks from wikis with all kinds of
  header cruft; a hard parse failure would punish exactly the users this
  feature is for);
* title precedence: front-matter ``title`` → first ``#`` heading → filename.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

# Resolves to the repo root in a dev checkout and /opt/soc-ai in the image —
# the same parent-of-package resolution main.py uses for FRONTEND_DIST, so the
# Dockerfile's `COPY runbooks/ /opt/soc-ai/runbooks/` lands exactly here.
STARTER_PACK_DIR = Path(__file__).resolve().parent.parent.parent / "runbooks" / "starter-pack"

# The fence must open at byte 0 (a mid-file `---` is a thematic break, not
# front-matter) and the closing fence consumes its trailing newline so the body
# starts clean. DOTALL because the block spans lines.
_FRONT_MATTER_RE = re.compile(r"\A---[ \t]*\r?\n(.*?)\r?\n---[ \t]*\r?\n?", re.DOTALL)
_H1_RE = re.compile(r"^#\s+(.+?)\s*$", re.MULTILINE)


@dataclass
class ParsedRunbook:
    """One markdown file, resolved to the runbook-create payload shape."""

    title: str
    content: str
    tags: list[str] = field(default_factory=list)
    linked_rules: list[str] = field(default_factory=list)


def _coerce_list(value: object) -> list[str]:
    """Lenient list coercion: YAML list, comma-separated string, or scalar.

    Anything unusable (mappings, None, empties) collapses to ``[]`` — metadata
    is best-effort by design, mirroring the store's own ``_norm_list``.
    """
    if value is None or isinstance(value, dict):
        return []
    if isinstance(value, str):
        parts = value.split(",")
    elif isinstance(value, (list, tuple)):
        parts = [str(v) for v in value]
    else:
        parts = [str(value)]
    return [p.strip() for p in parts if p and p.strip()]


def parse_runbook_markdown(text: str, *, fallback_title: str) -> ParsedRunbook:
    """Parse one markdown document into a runbook payload (never raises).

    Front-matter is optional and forgiven: a missing fence, malformed YAML, or
    a non-mapping document all degrade to "no metadata" — the body still
    imports. ``fallback_title`` (the filename stem) is the last-resort title
    when neither front-matter nor a ``#`` heading provides one.
    """
    meta: dict[str, object] = {}
    body = text
    match = _FRONT_MATTER_RE.match(text)
    if match:
        body = text[match.end() :]
        try:
            loaded = yaml.safe_load(match.group(1))
        except yaml.YAMLError:
            loaded = None  # malformed front-matter → treated as absent, not fatal
        if isinstance(loaded, dict):
            meta = {str(k): v for k, v in loaded.items()}

    raw_title = meta.get("title")
    title = str(raw_title).strip() if raw_title is not None else ""
    if not title:
        heading = _H1_RE.search(body)
        title = heading.group(1).strip() if heading else ""
    if not title:
        title = fallback_title.strip() or "Untitled runbook"

    # `rules` is the documented front-matter key; `linked_rules` (the API field
    # name) is accepted as an alias so a round-tripped export re-imports clean.
    rules = meta.get("rules")
    if rules is None:
        rules = meta.get("linked_rules")

    return ParsedRunbook(
        # Same title cap as the store/API (Runbook.title is String(512)).
        title=title[:512],
        content=body.strip(),
        tags=_coerce_list(meta.get("tags")),
        linked_rules=_coerce_list(rules),
    )


def load_starter_pack(directory: Path | None = None) -> list[ParsedRunbook]:
    """Parse every ``*.md`` in the pack dir, sorted by filename (stable order).

    Returns ``[]`` when the directory is missing (an image built without the
    ``runbooks/`` COPY, or a trimmed checkout) — the endpoint turns that into
    an honest 404 rather than a silent zero-count success. An unreadable
    individual file is skipped, never fatal.
    """
    pack_dir = STARTER_PACK_DIR if directory is None else directory
    if not pack_dir.is_dir():
        return []
    parsed: list[ParsedRunbook] = []
    for path in sorted(pack_dir.glob("*.md")):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:  # pragma: no cover — racing FS trouble; skip, don't fail the pack
            continue
        parsed.append(parse_runbook_markdown(text, fallback_title=path.stem))
    return parsed
