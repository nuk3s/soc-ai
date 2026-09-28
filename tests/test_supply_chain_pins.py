"""Supply-chain pinning gates (2026-07-21 review, "supply-chain" batch).

release.yml SHA-pins every third-party GitHub Action "(supply-chain
hardening; the tj-actions compromise class)". These tests hold the rest of
the build/deploy surface to the same standard: a compromised or maliciously
republished upstream artifact (a base image, a floating registry tag, or an
unpinned PyPI installer) must not be able to land silently.

Hermetic by design: regex and a plain YAML/TOML parse over the repo's own
infra files, no network, no Docker/GitLab daemon required.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]


def _run_lines(workflow: dict[str, Any]) -> list[str]:
    """Every ``run:`` command across a parsed workflow's jobs, in file order."""
    return [
        str(step.get("run", ""))
        for job in workflow["jobs"].values()
        for step in job.get("steps", [])
    ]


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


def test_precommit_ruff_rev_matches_locked_ruff() -> None:
    """The ruff-pre-commit hook and CI's ``uv run ruff`` must be the same
    ruff. The hook runs ``ruff check --fix``: a hook older than the locked
    ruff does not know a rule the lock enforces, treats that rule's
    ``# noqa`` as unused (RUF100) and deletes it on commit, and CI then fails
    on the very rule the comment silenced. The rev is pinned to the ``ruff``
    entry in uv.lock so the two cannot drift apart."""
    config = yaml.safe_load((REPO_ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8"))
    revs = [
        repo["rev"]
        for repo in config["repos"]
        if repo["repo"].rstrip("/").endswith("/ruff-pre-commit")
    ]
    assert len(revs) == 1, (
        f"expected exactly one ruff-pre-commit repo in .pre-commit-config.yaml, found {revs}"
    )
    lock = tomllib.loads((REPO_ROOT / "uv.lock").read_text(encoding="utf-8"))
    locked = [pkg["version"] for pkg in lock["package"] if pkg["name"] == "ruff"]
    assert len(locked) == 1, f"expected exactly one ruff entry in uv.lock, found {locked}"
    assert revs[0].lstrip("v") == locked[0], (
        f".pre-commit-config.yaml pins ruff-pre-commit {revs[0]} but uv.lock pins ruff "
        f"{locked[0]}: the hook's --fix rewrites noqa comments the locked ruff still needs"
    )


def test_check_yaml_hook_skips_mkdocs_python_tags() -> None:
    """mkdocs.yml carries ``!!python/name:`` tags (pymdownx superfences,
    the Material emoji index) that a safe YAML load rejects, and the
    check-yaml hook is a safe load. Without an exclude, every commit that
    stages mkdocs.yml fails the hook and gets pushed with ``--no-verify``,
    which also skips ruff and the private-key check for that commit. mkdocs
    validates its own config through ``mkdocs build --strict`` in CI."""
    try:
        yaml.safe_load((REPO_ROOT / "mkdocs.yml").read_text(encoding="utf-8"))
    except yaml.YAMLError:
        needs_exclude = True
    else:
        needs_exclude = False
    if not needs_exclude:
        return  # no python tags any more, so the hook may cover mkdocs.yml again
    config = yaml.safe_load((REPO_ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8"))
    hooks = [
        hook for repo in config["repos"] for hook in repo["hooks"] if hook["id"] == "check-yaml"
    ]
    assert len(hooks) == 1, f"expected exactly one check-yaml hook, found {hooks}"
    exclude = hooks[0].get("exclude", "")
    assert exclude and re.search(exclude, "mkdocs.yml"), (
        "mkdocs.yml needs python/name tags that check-yaml's safe load rejects, but the hook "
        f"does not exclude it (exclude={exclude!r}); commits touching mkdocs.yml fail the hook"
    )


def test_frontend_scripts_call_binaries_the_lockfile_provides() -> None:
    """Every ``npm run`` script in frontend/package.json is a documented entry
    point, so the tool it starts must come from a package in
    package-lock.json. A script whose tool is not a dependency runs nothing on
    a clean checkout, and on a machine with a global copy it runs whatever
    version and config happen to be there instead of the repo's."""
    frontend = REPO_ROOT / "frontend"
    package = json.loads((frontend / "package.json").read_text(encoding="utf-8"))
    lock = json.loads((frontend / "package-lock.json").read_text(encoding="utf-8"))
    provided = {
        name
        for path, entry in lock["packages"].items()
        if path.startswith("node_modules/")
        for name in entry.get("bin") or {}
    }
    # npm's own commands need no package of their own.
    provided |= {"node", "npm", "npx"}
    dangling = {}
    for script, command in package["scripts"].items():
        for segment in re.split(r"&&|\|\||;", command):
            tool = segment.split()[0]
            if tool not in provided:
                dangling[script] = tool
    assert not dangling, (
        "frontend/package.json script(s) start a tool no package in package-lock.json "
        f"provides, so they cannot run from a clean checkout: {dangling}"
    )


def test_dependabot_covers_every_pinned_surface() -> None:
    """A pin only holds its value while something refreshes it. Dependabot
    must watch every surface this file pins: uv.lock (Python), the SPA's
    package-lock.json, the SHA-pinned actions in .github/workflows, and the
    digest-pinned base images in the Dockerfile. Without it a lock keeps
    shipping an advisory and a SHA/digest pin decays with no diff to review."""
    config = yaml.safe_load((REPO_ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8"))
    assert config["version"] == 2
    watched = {entry["package-ecosystem"]: entry["directory"] for entry in config["updates"]}
    assert watched == {"uv": "/", "npm": "/frontend", "github-actions": "/", "docker": "/"}, (
        f"dependabot.yml watches {watched}; expected uv (uv.lock), npm (frontend/), "
        "github-actions and docker, each at the directory that holds its manifest"
    )


def test_ci_audits_the_dependencies_that_ship() -> None:
    """CI must run the advisory audits on what the image ships — the locked
    runtime Python set (pip-audit) and the SPA's production npm dependencies
    (npm audit) — or a lockfile keeps passing green while carrying a known
    vulnerability, which is how advisories accumulated before the gate."""
    ci_yml = REPO_ROOT / ".github" / "workflows" / "ci.yml"
    runs = _run_lines(yaml.safe_load(ci_yml.read_text(encoding="utf-8")))
    assert any("pip-audit" in run and "--no-dev" in run for run in runs), (
        "ci.yml has no pip-audit step over a --no-dev export of uv.lock"
    )
    assert any("npm audit" in run and "--omit=dev" in run for run in runs), (
        "ci.yml has no `npm audit --omit=dev` step over frontend/package-lock.json"
    )


def test_docs_build_strictly_in_ci_from_the_locked_docs_group() -> None:
    """A PR that renames a page still listed in mkdocs.yml's nav must fail in
    CI, not in the post-merge Pages deploy, so ci.yml runs ``mkdocs build
    --strict`` on every PR (never with ``-q``: quiet mode hides the strict
    abort). The docs tooling is pinned once, in uv.lock's docs group: docs.yml
    installs from that lock rather than a second ``pip install`` pin that
    drifts from it."""
    workflows = REPO_ROOT / ".github" / "workflows"
    ci_runs = _run_lines(yaml.safe_load((workflows / "ci.yml").read_text(encoding="utf-8")))
    docs_runs = _run_lines(yaml.safe_load((workflows / "docs.yml").read_text(encoding="utf-8")))
    strict = [run for run in ci_runs if "mkdocs build --strict" in run]
    assert strict, "ci.yml never runs `mkdocs build --strict`, so a broken nav merges green"
    assert not any(re.search(r"\s-q\b", run) for run in strict), (
        f"`mkdocs build --strict -q` exits 0 on a strict abort; drop -q: {strict}"
    )
    assert any("mkdocs build --strict" in run for run in docs_runs)
    assert not any("pip install" in run for run in docs_runs), (
        "docs.yml pins the docs tooling a second time with pip, outside uv.lock: "
        + "; ".join(run for run in docs_runs if "pip install" in run)
    )


def test_every_workflow_job_sets_a_timeout() -> None:
    """A job without ``timeout-minutes`` inherits GitHub's 360-minute default,
    so one stalled package install or ``gh release`` call burns six hours of
    runner time, and docs.yml's ``pages`` concurrency group (cancel-in-
    progress: false) queues every later docs deploy behind it. Jobs that only
    ``uses:`` another workflow carry no steps of their own and take the
    called workflow's timeouts."""
    missing = []
    for path in sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml")):
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        for name, job in workflow["jobs"].items():
            if "uses" in job:
                continue
            if not isinstance(job.get("timeout-minutes"), int):
                missing.append(f"{path.name}:{name}")
    assert not missing, (
        "workflow job(s) without timeout-minutes (GitHub's default is 360): " + ", ".join(missing)
    )
