# Contributing to soc-ai

Thanks for your interest. soc-ai is an open, self-hosted LLM triage assistant for
Security Onion. It is a **companion service, not a fork** of SO.

## Ground rules

- Be excellent to each other. Assume good faith.
- By contributing you agree your work is licensed under the project's
  [Apache-2.0](../LICENSE) license.
- **Never commit secrets** (`.env`, API keys, passwords, TLS keys, SSH keys) or
  real grid data (host IPs/hostnames, alert dumps). They are gitignored for a
  reason; double-check `git diff` before pushing.

## Dev setup

Requires Python 3.12 and [uv](https://docs.astral.sh/uv/), plus Node 20 for the
frontend.

```bash
# Backend
uv sync --all-extras --dev

# Frontend (the React SPA in frontend/)
cd frontend && npm ci
```

Copy `.env.example` → `.env` and fill it in (the field reference is
`soc_ai/config.py`). For local-only work you can point `SO_HOST`/`ES_HOSTS`/
`LITELLM_BASE_URL` at a lab grid + gateway.

## The checks (what CI enforces)

CI gates every push (GitHub Actions). Run
them locally before opening a PR:

```bash
# Backend — must all pass
uv run ruff check soc_ai/ tests/
uv run ruff format --check soc_ai/ tests/
uv run mypy --strict soc_ai/
uv run pytest                      # coverage gate is 80%

# Frontend
cd frontend && npm run typecheck && npm run build
```

`pre-commit` hooks are available: `uv run pre-commit install`.

## Conventions

- **Commits:** imperative, scoped subject lines (e.g. `fix(api): …`,
  `feat(ui): …`). Explain the *why* in the body.
- **Tests:** new behavior needs a test. The suite is fast and offline (no live
  grid/LLM) — mock the upstreams (`AsyncMock`, `respx`).
- **Types:** `mypy --strict` is the gate; no new `# type: ignore` without a
  reason.
- **Security boundary:** OQL goes through the field-whitelist validator before
  ES; write tools always go through the human approval gate; anything sent to
  the Oracle is sanitized first. Don't route around these.

## Pull requests

1. Branch off `main`.
2. Make the change + tests; keep PRs focused.
3. Ensure the checks above pass.
4. Open the PR with a clear description of the change and its motivation.

## Architecture pointers

- `docs/ARCHITECTURE.md` — the system shape.
- `docs/AGENT_TOOLS.md` — the read/write tool surface.
- `docs/SAFETY_MODEL.md` — the trust boundaries.
