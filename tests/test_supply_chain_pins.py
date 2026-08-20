"""Supply-chain pinning gates (2026-07-21 review, "supply-chain" batch).

release.yml SHA-pins every third-party GitHub Action "(supply-chain
hardening; the tj-actions compromise class)". These tests hold the rest of
the build/deploy surface to the same standard: a compromised or maliciously
republished upstream artifact (a base image, a floating registry tag, or an
unpinned PyPI installer) must not be able to land silently.

Hermetic by design: regex over the repo's own infra files, no network, no
Docker/GitLab daemon required.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_dockerfile_base_images_pinned_by_digest() -> None:
    """F49: every ``FROM`` in the multi-stage build must pin a content
    digest, not float on a mutable tag — a registry republish of
    ``python:3.12-slim``/``node:22-bookworm-slim``/the uv base image would
    otherwise be baked into the next build with no diff or CI signal."""
    text = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    from_lines = [line for line in text.splitlines() if re.match(r"^\s*FROM\s+\S", line)]
    assert len(from_lines) >= 3, (
        f"expected >=3 FROM lines in Dockerfile, found {len(from_lines)}: {from_lines} "
        "— did a build stage move or get renamed? Update this test."
    )
    unpinned = [line for line in from_lines if "@sha256:" not in line]
    assert not unpinned, (
        "Dockerfile FROM line(s) missing a content-digest pin (@sha256:...): " + "; ".join(unpinned)
    )


def test_compose_quickstart_pull_command_pins_a_tag() -> None:
    """F50: docker-compose.yml's own documented quick-start
    (``docker compose pull soc-ai && docker compose up -d``) must not be
    copy-pasteable into an unpinned ``:latest`` deploy — every example of
    that command in the file's comments must set SOC_AI_IMAGE_TAG inline."""
    text = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    pull_examples = [line for line in text.splitlines() if "docker compose pull soc-ai" in line]
    assert len(pull_examples) >= 2, (
        f"expected >=2 documented 'docker compose pull soc-ai' examples in "
        f"docker-compose.yml, found {len(pull_examples)} — did the quick-start "
        "comment move or get reworded? Update this test."
    )
    unpinned = [line for line in pull_examples if "SOC_AI_IMAGE_TAG=" not in line]
    assert not unpinned, (
        "docker-compose.yml documents a 'docker compose pull soc-ai' quick-start "
        "that does not set SOC_AI_IMAGE_TAG inline, so copy-pasting it rides the "
        "mutable :latest tag: " + "; ".join(unpinned)
    )


def test_llm_compose_images_pinned_by_tag() -> None:
    """The optional local-LLM profile (docker-compose.llm.yml) declares both
    images pinned — its own header comment says "Tags are PINNED (verified
    against the registries ...). Never run :latest — it's an unaudited moving
    target." Hold that promise to the same standard as the Dockerfile/
    docker-compose.yml gates above: a bare or ``:latest`` image tag must not
    silently creep back in."""
    text = (REPO_ROOT / "docker-compose.llm.yml").read_text(encoding="utf-8")
    image_lines = [line.strip() for line in text.splitlines() if re.match(r"^\s*image:\s*\S", line)]
    assert len(image_lines) == 2, (
        f"expected exactly 2 'image:' lines in docker-compose.llm.yml (ollama, litellm), "
        f"found {len(image_lines)}: {image_lines} — did a service get added, removed, or "
        "renamed? Update this test."
    )
    for line in image_lines:
        image = line.split(":", 1)[1].strip()
        assert ":latest" not in image, f"docker-compose.llm.yml rides :latest: {line!r}"
        # rpartition, not a bare count(":") == 1 — a lab-registry re-pin
        # (registry.lan:5000/ollama/ollama:0.32.14) puts a second colon in the
        # host:port before the tag separator, which count() can't tell apart
        # from a missing tag (same trap tests/test_setup_script.py's
        # test_llm_compose_profile_is_wellformed already guards against).
        _, sep, tag = image.rpartition(":")
        assert sep and tag and "/" not in tag, f"docker-compose.llm.yml image not pinned: {line!r}"
