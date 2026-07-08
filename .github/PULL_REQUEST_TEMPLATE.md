## What this changes

<!-- One or two sentences. Link the issue it closes (e.g. "Closes #12"). -->

## Checklist

<!-- The same gates CI runs — see CONTRIBUTING.md for the details. -->

- [ ] `uv run ruff check soc_ai/ tests/` and `uv run ruff format --check soc_ai/ tests/` pass
- [ ] `uv run mypy soc_ai/` passes
- [ ] `uv run pytest` passes (80% coverage gate included)
- [ ] Frontend (if touched): `cd frontend && npm run typecheck && npm run build` succeeds
- [ ] Behavior changes have tests, and a `CHANGELOG.md` entry under `[Unreleased]`
- [ ] No new default-on egress (see `docs/SAFETY_MODEL.md`); safety boundaries untouched
- [ ] No secrets, real host IPs/hostnames, or grid data in the diff
