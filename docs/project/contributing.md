# Contributing

soc-ai welcomes contributions. The full contributor guide lives in the repository.
It covers the dev setup, the coding standards and the pull request steps:

[:octicons-arrow-right-24: **CONTRIBUTING.md on GitHub**](https://github.com/nuk3s/soc-ai/blob/main/CONTRIBUTING.md)

## Build commands

```bash
uv sync                                 # Python deps + dev tools
uv run pytest --ignore=tests/browser    # the test suite
uv run mypy soc_ai                      # strict type check

cd frontend && npm ci && npm run build  # the React console
```

## Docs site

```bash
uv run --group docs mkdocs serve
```

Then open <http://127.0.0.1:8000/>. `mkdocs.yml` and the Markdown files under `docs/`
define the site. `docs/dev/` is internal, and the site never publishes it.
