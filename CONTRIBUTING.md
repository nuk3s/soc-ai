# Contributing to soc-ai

Thanks for your interest. soc-ai is an open, self-hosted LLM triage assistant for
Security Onion. It is a **companion service, not a fork** of SO.

## Ground rules

- Be excellent to each other. Assume good faith.
- By contributing you agree your work is licensed under the project's
  [Apache-2.0](LICENSE) license.
- **Never commit secrets** (`.env`, API keys, passwords, TLS keys, SSH keys) or
  real grid data (host IPs/hostnames, alert dumps). They are gitignored for a
  reason; double-check `git diff` before pushing.

## Scope: privacy first

soc-ai's core promise is that **nothing leaves the box by default**. Features
must not add default-on egress: any new network destination (a feed, an API, a
telemetry endpoint, a model call) has to be **opt-in, off by default, and
visible on the egress-policy page**. The trust boundaries — what the agent may
read, what requires human approval, what the sanitizer strips before anything
cloud-facing — are documented in [docs/SAFETY_MODEL.md](docs/SAFETY_MODEL.md);
read it before proposing anything that touches the agent's tools, the approval
gate, or an outbound connection. PRs that route around these boundaries will be
declined regardless of code quality.

## Dev setup

Requires Python 3.12 and [uv](https://docs.astral.sh/uv/), plus Node 22 for the
frontend (Node 20+ works; CI runs 22).

```bash
# Backend
uv sync --all-extras --dev

# Frontend (the React SPA in frontend/)
cd frontend && npm ci
```

Copy `.env.example` → `.env` and fill it in (the field reference is
`soc_ai/config.py`). For local-only work you can point `SO_HOST`/`ES_HOSTS`/
`LITELLM_BASE_URL` at a lab grid + gateway. `uv run soc-ai doctor` checks the
whole dependency surface once configured.

## The checks (what CI enforces)

CI (`.github/workflows/ci.yml`) gates every push and PR. Run the same commands
locally before opening a PR:

```bash
# Backend — must all pass
uv run ruff check soc_ai/ tests/
uv run ruff format --check soc_ai/ tests/
uv run mypy soc_ai/                  # strict mode (configured in pyproject.toml)
uv run pytest                        # coverage gate: 80% (browser E2E excluded)

# Frontend
cd frontend && npm run typecheck && npm test && npm run build
```

Frontend unit tests are vitest + Testing Library (`frontend/src/**/*.test.{ts,tsx}`,
happy-dom environment); `npm run test:watch` gives the watch mode.

`pre-commit` hooks are available: `uv run pre-commit install`.

### Browser smoke (E2E)

The Playwright smoke drives the seeded demo stack (login → alerts →
investigation → hunt → config) against the real app serving `frontend/dist`.
It is excluded from the default pytest run (the coverage-gated `addopts`
carries `--ignore=tests/browser`) and runs in its own CI job. To run it
locally:

```bash
cd frontend && npm ci && npm run build && cd ..   # the app serves frontend/dist
uv run playwright install chromium                 # one-time (CI adds --with-deps)
uv run pytest --override-ini "addopts=" --no-header -v -m browser tests/browser/
```

## Pull requests

1. Branch off `main`; keep PRs focused.
2. **Behavior changes need tests.** The suite is fast and offline (no live
   grid/LLM) — mock the upstreams (`AsyncMock`, `respx`).
3. **Behavior changes need a changelog entry** under `[Unreleased]` in
   [CHANGELOG.md](CHANGELOG.md) (the file follows
   [Keep a Changelog](https://keepachangelog.com/)).
4. All the checks above must be green.
5. Open the PR with a clear description of the change and its motivation.

## Conventions

- **Commits:** imperative, scoped subject lines (e.g. `fix(api): …`,
  `feat(ui): …`). Explain the *why* in the body.
- **Types:** `mypy --strict` is the gate; no new `# type: ignore` without a
  reason.
- **Security boundary:** OQL goes through the field-whitelist validator before
  ES; write tools always go through the human approval gate; anything sent to
  the Oracle is sanitized first. Don't route around these.

## Architecture pointers

- `docs/ARCHITECTURE.md` — the system shape.
- `docs/AGENT_TOOLS.md` — the read/write tool surface.
- `docs/SAFETY_MODEL.md` — the trust boundaries.
