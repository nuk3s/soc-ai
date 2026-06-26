"""Module entrypoint so ``python -m soc_ai ...`` runs the CLI.

The Docker image installs dependencies with ``uv sync --no-install-project``
(the project itself is made importable via ``PYTHONPATH`` rather than installed),
so the ``soc-ai`` console script is not created in the image. ``python -m soc_ai``
is the portable invocation — used by the Docker docs for ``blocklists refresh``.
"""

from soc_ai.cli import main

if __name__ == "__main__":
    main()
