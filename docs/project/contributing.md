# Contributing

soc-ai welcomes contributions. The full contributor guide — how to set up the dev
environment, the coding standards, and how to open a pull request — lives in the
repository:

[:octicons-arrow-right-24: **CONTRIBUTING.md on GitHub**](https://github.com/nuk3s/soc-ai/blob/main/.github/CONTRIBUTING.md)

## Building on it

```bash
uv sync                                 # Python deps + dev tools
uv run pytest --ignore=tests/browser    # the test suite
uv run mypy soc_ai                      # strict type check

cd frontend && npm ci && npm run build  # the React console
```

## Building these docs locally

```bash
uv run --group docs mkdocs serve
```

Then open <http://127.0.0.1:8000/>. The site is defined by `mkdocs.yml` and the Markdown
files under `docs/` (excluding `docs/dev/`, which is internal-only and never published).
