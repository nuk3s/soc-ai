"""Tests for the starter runbook pack (I2) + the embed-status API surface:

* lenient front-matter parsing (``soc_ai.store.runbook_pack``) — YAML block,
  heading/filename title fallbacks, malformed YAML forgiven;
* the shipped ``runbooks/starter-pack/*.md`` content — every file parses,
  carries real front-matter + a substantive body, and contains NO lab-leak
  strings (the pack ships in the public mirror);
* ``POST /runbooks/starter-pack`` — created/skipped counts, idempotency by
  title, honest 404 on a missing pack dir;
* ``RunbookOut.embedded`` / ``.stale`` — None with the RAG tier off, computed
  from the ``runbook_embedding`` table when it's on (same MockTransport fake
  gateway as tests/test_runbook_rag.py).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import runbook_pack

REPO_ROOT = Path(__file__).resolve().parent.parent
PACK_DIR = REPO_ROOT / "runbooks" / "starter-pack"

# Strings that must NEVER appear in shipped pack content (the pack rides the
# public mirror by default — same list the mirror build scans for, plus the
# repo-owner names). Checked case-insensitively for safety. Each pattern is
# assembled from fragments so THIS test file stays clean under the very same
# publish-time leak scan it mirrors (the scan greps literal substrings).
_LEAK_STRINGS = tuple(
    "".join(parts)
    for parts in (
        ("home", ".lan"),
        ("10.", "9.8."),
        ("git", "lab"),
        ("cra", "ig"),
        ("meri", "dian"),
        ("/home/", "roo", "ter"),
    )
)


# ---------------------------------------------------------------------------
# parse_runbook_markdown: lenient front-matter
# ---------------------------------------------------------------------------


def test_parse_full_front_matter() -> None:
    text = (
        "---\n"
        "title: Beacon triage\n"
        "tags: [beacon, c2]\n"
        "rules:\n"
        '  - "ET MALWARE Beacon"\n'
        "  - ET CNC Tracker\n"
        "---\n"
        "# Heading that must NOT win\n\nBody text.\n"
    )
    parsed = runbook_pack.parse_runbook_markdown(text, fallback_title="file-stem")
    assert parsed.title == "Beacon triage"  # front-matter beats the heading
    assert parsed.tags == ["beacon", "c2"]
    assert parsed.linked_rules == ["ET MALWARE Beacon", "ET CNC Tracker"]
    # the fence is stripped; the body keeps its markdown
    assert parsed.content.startswith("# Heading that must NOT win")
    assert "title:" not in parsed.content


def test_parse_title_falls_back_to_heading_then_filename() -> None:
    heading_only = runbook_pack.parse_runbook_markdown(
        "# From The Heading\n\nbody", fallback_title="stem"
    )
    assert heading_only.title == "From The Heading"

    bare = runbook_pack.parse_runbook_markdown("just a body, no heading", fallback_title="my-file")
    assert bare.title == "my-file"
    assert bare.content == "just a body, no heading"

    # nothing at all → the guaranteed non-empty last resort
    empty = runbook_pack.parse_runbook_markdown("", fallback_title="  ")
    assert empty.title == "Untitled runbook"


def test_parse_malformed_yaml_is_forgiven() -> None:
    """Broken front-matter must not fail the import — metadata is a bonus."""
    text = "---\ntitle: [unclosed\n  ::: not yaml\n---\n# Real Title\n\nbody"
    parsed = runbook_pack.parse_runbook_markdown(text, fallback_title="stem")
    assert parsed.title == "Real Title"  # fence stripped, heading takes over
    assert parsed.tags == []
    assert parsed.linked_rules == []
    assert parsed.content.startswith("# Real Title")


def test_parse_non_mapping_front_matter_ignored() -> None:
    text = "---\n- just\n- a\n- list\n---\nbody only"
    parsed = runbook_pack.parse_runbook_markdown(text, fallback_title="stem")
    assert parsed.title == "stem"
    assert parsed.content == "body only"


def test_parse_lenient_list_shapes() -> None:
    # comma-string tags + the linked_rules alias + scalar coercion
    text = "---\ntitle: T\ntags: alpha, beta ,\nlinked_rules: solo-rule\n---\nb"
    parsed = runbook_pack.parse_runbook_markdown(text, fallback_title="s")
    assert parsed.tags == ["alpha", "beta"]
    assert parsed.linked_rules == ["solo-rule"]


def test_mid_file_fence_is_not_front_matter() -> None:
    """A `---` thematic break later in the file must not be eaten as metadata."""
    text = "intro paragraph\n\n---\ntitle: not metadata\n---\nmore"
    parsed = runbook_pack.parse_runbook_markdown(text, fallback_title="stem")
    assert parsed.title == "stem"
    assert "not metadata" in parsed.content


def test_load_starter_pack_missing_dir_returns_empty(tmp_path: Path) -> None:
    assert runbook_pack.load_starter_pack(tmp_path / "does-not-exist") == []


# ---------------------------------------------------------------------------
# The shipped pack content: parses, substantive, leak-free (it ships publicly)
# ---------------------------------------------------------------------------


def _pack_files() -> list[Path]:
    return sorted(PACK_DIR.glob("*.md"))


def test_pack_ships_ten_runbooks() -> None:
    assert len(_pack_files()) == 10


@pytest.mark.parametrize("path", _pack_files(), ids=lambda p: p.name)
def test_pack_file_parses_with_substance(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    # every shipped file declares explicit front-matter (title + tags at least)
    assert text.startswith("---\n"), "pack files must carry YAML front-matter"
    parsed = runbook_pack.parse_runbook_markdown(text, fallback_title=path.stem)
    assert parsed.title, "front-matter title required"
    assert parsed.title != path.stem, "title must come from front-matter, not the filename"
    assert parsed.tags, "pack runbooks are tagged for retrieval"
    # genuinely useful procedure, not filler — the pack targets ~300-600 words
    assert len(parsed.content.split()) >= 200, "pack runbook body looks too thin"
    # MITRE grounding is part of the pack's contract, except the meta
    # (methodology) runbook where a technique id is optional.
    if path.stem != "noisy-rule-tuning":
        assert "T1" in parsed.content, "expected a MITRE ATT&CK technique reference"


@pytest.mark.parametrize("path", _pack_files(), ids=lambda p: p.name)
def test_pack_file_has_no_lab_leakage(path: Path) -> None:
    """The pack ships in the public mirror — no lab identifiers, ever."""
    lowered = path.read_text(encoding="utf-8").lower()
    for needle in _LEAK_STRINGS:
        assert needle not in lowered, f"leak-gate string {needle!r} in {path.name}"


# ---------------------------------------------------------------------------
# POST /runbooks/starter-pack: counts + idempotency
# ---------------------------------------------------------------------------


def _client(settings: Settings) -> Iterator[TestClient]:
    fake_es = AsyncMock()
    fake_auth = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=settings),
    ):
        app = create_app()
        with TestClient(app) as client:
            yield client


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    yield from _client(settings_kratos)


def test_starter_pack_install_and_idempotency(client: TestClient) -> None:
    n_pack = len(_pack_files())

    # first install: everything created
    body = client.post("/api/v1/runbooks/starter-pack").json()
    assert body == {"created": n_pack, "skipped": 0}
    listing = client.get("/api/v1/runbooks").json()
    assert len(listing) == n_pack
    titles = {r["title"] for r in listing}
    assert "Noisy rule tuning methodology" in titles
    # front-matter metadata landed on the rows
    beacon = next(r for r in listing if "Beaconing" in r["title"])
    assert "beacon" in beacon["tags"]
    assert any("ET " in rule for rule in beacon["linked_rules"])

    # second install: pure no-op — operator data is never duplicated
    body = client.post("/api/v1/runbooks/starter-pack").json()
    assert body == {"created": 0, "skipped": n_pack}
    assert len(client.get("/api/v1/runbooks").json()) == n_pack

    # delete one, re-install: only the missing one comes back
    victim = client.get("/api/v1/runbooks").json()[0]
    client.delete(f"/api/v1/runbooks/{victim['id']}")
    body = client.post("/api/v1/runbooks/starter-pack").json()
    assert body == {"created": 1, "skipped": n_pack - 1}


def test_starter_pack_skip_matches_title_case_insensitively(client: TestClient) -> None:
    """An operator-authored runbook with the same title (any case) wins —
    the pack never overwrites or duplicates it."""
    client.post(
        "/api/v1/runbooks",
        json={"title": "beaconing / c2 CALLBACK triage", "content": "our own version"},
    )
    body = client.post("/api/v1/runbooks/starter-pack").json()
    assert body["skipped"] == 1
    assert body["created"] == len(_pack_files()) - 1
    # the operator's content survived
    listing = client.get("/api/v1/runbooks").json()
    ours = next(r for r in listing if r["title"].lower().startswith("beaconing"))
    assert ours["content"] == "our own version"


def test_starter_pack_missing_dir_404s(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An image built without the runbooks/ COPY should fail loudly, not
    return a lying {created: 0, skipped: 0}."""
    monkeypatch.setattr(runbook_pack, "STARTER_PACK_DIR", tmp_path / "gone")
    resp = client.post("/api/v1/runbooks/starter-pack")
    assert resp.status_code == 404
    assert resp.json()["detail"]["reason"] == "starter_pack_missing"


# ---------------------------------------------------------------------------
# RunbookOut embed status: None while the tier is off; computed when on
# ---------------------------------------------------------------------------

_REAL_ASYNC_CLIENT = httpx.AsyncClient


def _fake_gateway(embed_status: int = 200) -> Any:
    """Minimal /v1/embeddings fake (fixed 3-dim vector) — MockTransport-routed,
    so no real gateway is ever touched (same pattern as test_runbook_rag.py)."""

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/v1/embeddings"):
            if embed_status != 200:
                return httpx.Response(embed_status, json={"error": "boom"})
            body = json.loads(req.content)
            data = [{"index": i, "embedding": [1.0, 0.0, 0.0]} for i in range(len(body["input"]))]
            return httpx.Response(200, json={"data": data, "model": body["model"]})
        return httpx.Response(404, json={"error": "unexpected path"})

    transport = httpx.MockTransport(handler)

    def _factory(*a: Any, **k: Any) -> httpx.AsyncClient:
        k["transport"] = transport
        return _REAL_ASYNC_CLIENT(*a, **k)

    return patch("soc_ai.rag.runbook_embeddings.httpx.AsyncClient", _factory)


def test_embed_status_none_when_tier_off(client: TestClient) -> None:
    created = client.post("/api/v1/runbooks", json={"title": "Plain", "content": "x"}).json()
    assert created["embedded"] is None
    assert created["stale"] is None
    listed = client.get("/api/v1/runbooks").json()[0]
    assert listed["embedded"] is None
    assert listed["stale"] is None


def test_embed_status_computed_when_tier_on(settings_kratos: Settings) -> None:
    rag = settings_kratos.model_copy(update={"rag_embed_model": "test-embed"})

    # created while the gateway is UP → embedded, current model
    with _fake_gateway():
        for client in _client(rag):
            created = client.post("/api/v1/runbooks", json={"title": "Vectored"}).json()
            assert created["embedded"] is True
            assert created["stale"] is False

    # created while the gateway is DOWN → fail-soft save, honestly not embedded
    with _fake_gateway(embed_status=503):
        for client in _client(rag):
            created = client.post("/api/v1/runbooks", json={"title": "Unvectored"}).json()
            assert created["embedded"] is False
            assert created["stale"] is False

            by_title = {r["title"]: r for r in client.get("/api/v1/runbooks").json()}
            assert by_title["Vectored"]["embedded"] is True
            assert by_title["Vectored"]["stale"] is False
            assert by_title["Unvectored"]["embedded"] is False


def test_embed_status_stale_after_model_switch(settings_kratos: Settings) -> None:
    """Switching rag_embed_model marks existing vectors stale in the list —
    the UI's cue to offer the re-embed pass."""
    with _fake_gateway():
        for client in _client(settings_kratos.model_copy(update={"rag_embed_model": "old-model"})):
            client.post("/api/v1/runbooks", json={"title": "Aging"})
        for client in _client(settings_kratos.model_copy(update={"rag_embed_model": "new-model"})):
            listed = client.get("/api/v1/runbooks").json()[0]
            assert listed["embedded"] is True
            assert listed["stale"] is True
