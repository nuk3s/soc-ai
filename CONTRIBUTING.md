# Contributing to soc-ai

Thanks for your interest. soc-ai is an open, self-hosted LLM triage assistant for
Security Onion. It is a companion service. It does not fork Security Onion.

## Ground rules

- Be excellent to each other. Assume good faith.
- By contributing you agree your work is licensed under the project's
  [Apache-2.0](LICENSE) license.
- **Never commit secrets** or real grid data. That covers `.env`, API keys,
  passwords, TLS keys, SSH keys, host addresses, hostnames and alert dumps. They
  are gitignored. Check `git diff` before you push.

## Scope: privacy first

The core promise of soc-ai is that **nothing leaves the box by default**. A
feature must not add default-on egress. Any new network destination has to be
opt-in, off by default, and visible on the egress-policy page. A feed, an API, a
telemetry endpoint and a model call all count as destinations.

[docs/SAFETY_MODEL.md](docs/SAFETY_MODEL.md) documents the trust boundaries: what
the agent may read, what needs human approval, and what the sanitizer strips
before anything cloud-facing. Read it before you propose anything that touches
the agent's tools, the approval gate, or an outbound connection. A PR that routes
around these boundaries is declined, whatever its code quality.

## Dev setup

soc-ai needs Python 3.12 and [uv](https://docs.astral.sh/uv/). The frontend
needs Node 22. Node 20 and above works, and CI runs Node 22.

```bash
# Backend
uv sync --all-extras --dev

# Frontend (the React SPA in frontend/)
cd frontend && npm ci
```

Copy `.env.example` to `.env` and fill it in. `soc_ai/config.py` is the field
reference. For local-only work you can point `SO_HOST`, `ES_HOSTS` and
`LITELLM_BASE_URL` at a lab grid and gateway. Once the file is filled in,
`uv run soc-ai doctor` checks the whole dependency surface.

## The checks that CI enforces

`.github/workflows/ci.yml` gates every push and every pull request. Run the same
commands locally before you open one:

```bash
# Backend — must all pass
uv run ruff check soc_ai/ tests/
uv run ruff format --check soc_ai/ tests/
uv run mypy soc_ai/                  # strict mode (configured in pyproject.toml)
uv run pytest                        # coverage gate: 80% (browser E2E excluded)

# Frontend
cd frontend && npm run typecheck && npm test && npm run build
```

Frontend unit tests use vitest and Testing Library. They live in
`frontend/src/**/*.test.{ts,tsx}` and run in the happy-dom environment.
`npm run test:watch` gives the watch mode.

`pre-commit` hooks are available: `uv run pre-commit install`.

### Browser smoke (E2E)

The Playwright smoke drives the seeded demo stack against the app serving
`frontend/dist`. It walks login, alerts, investigation, hunt and config. The
default pytest run excludes it, because the coverage-gated `addopts` carries
`--ignore=tests/browser`. It runs in its own CI job. To run it locally:

```bash
cd frontend && npm ci && npm run build && cd ..   # the app serves frontend/dist
uv run playwright install chromium                 # one-time (CI adds --with-deps)
uv run pytest --override-ini "addopts=" --no-header -v -m browser tests/browser/
```

## Pull requests

1. Branch off `main`. Keep each PR focused.
2. Behavior changes need tests. The suite is fast and offline. It reaches no live
   grid and no live model, so mock the upstreams with `AsyncMock` and `respx`.
3. Behavior changes need a changelog entry under `[Unreleased]` in
   [CHANGELOG.md](CHANGELOG.md). That file follows
   [Keep a Changelog](https://keepachangelog.com/).
4. All the checks above must be green.
5. Open the PR with a clear description of the change and its motivation.

## Conventions

- **Commits:** imperative, scoped subject lines, such as `fix(api): …` and
  `feat(ui): …`. Explain the *why* in the body.
- **Types:** `mypy --strict` is the gate. Add no new `# type: ignore` without a
  reason.
- **Security boundary:** OQL goes through the field-whitelist validator before
  Elasticsearch. Write tools always go through the human approval gate. Anything
  sent to the Oracle is sanitized first. Don't route around these.

## Architecture pointers

- `docs/ARCHITECTURE.md`: the system shape.
- `docs/AGENT_TOOLS.md`: the read and write tool surface.
- `docs/SAFETY_MODEL.md`: the trust boundaries.
