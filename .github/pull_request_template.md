## What this changes

<!-- One or two sentences. Link the issue it closes (e.g. "Closes #12"). -->

## Checklist

- [ ] `uv run ruff format soc_ai tests` leaves no diff, and `uv run ruff check soc_ai tests` passes
- [ ] `uv run mypy soc_ai` passes
- [ ] `uv run pytest --ignore=tests/browser` passes
- [ ] Frontend (if touched): `cd frontend && npm run build` succeeds
- [ ] No secrets, real host IPs/hostnames, or grid data in the diff
- [ ] Docs updated if behavior changed
