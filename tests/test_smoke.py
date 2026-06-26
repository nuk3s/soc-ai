"""Smoke tests verifying the package skeleton is wired correctly."""

import importlib

import pytest
import soc_ai


def test_package_imports() -> None:
    """The top-level package imports and exposes a version."""
    assert soc_ai.__version__
    assert isinstance(soc_ai.__version__, str)


@pytest.mark.parametrize(
    "module",
    [
        "soc_ai.so_client",
        "soc_ai.tools",
        "soc_ai.agent",
        "soc_ai.mcp_server",
        "soc_ai.audit",
        "soc_ai.rag",
        "soc_ai.api",
        "soc_ai.config",
        "soc_ai.main",
    ],
)
def test_subpackage_imports(module: str) -> None:
    """Every declared subpackage imports cleanly."""
    importlib.import_module(module)
