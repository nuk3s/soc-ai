"""Options for the scale harness tests.

The default run of the suite skips this directory (``--ignore=tests/scale`` in
the pyproject addopts). The ``scale`` CI job runs it on its own::

    uv run pytest --override-ini "addopts=" -m scale tests/scale/

``--scale-hosts`` sets the estate size. CI runs 2,000. Run 10,000 and 20,000
by hand::

    uv run pytest --override-ini "addopts=" -m scale tests/scale/ --scale-hosts 20000

``SCALE_HOSTS`` in the environment does the same.
"""

from __future__ import annotations

import os

import pytest

_DEFAULT_HOSTS = 2000


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--scale-hosts",
        type=int,
        default=None,
        help="Hosts in the synthetic estate for the scale tests (default 2000).",
    )


@pytest.fixture(scope="session")
def scale_hosts(request: pytest.FixtureRequest) -> int:
    given = request.config.getoption("--scale-hosts")
    if given is not None:
        return int(given)
    return int(os.environ.get("SCALE_HOSTS", _DEFAULT_HOSTS))
