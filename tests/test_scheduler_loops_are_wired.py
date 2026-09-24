"""Every scheduler loop defined in main.py must actually be started and stopped.

A background loop is invisible when it is not wired. It has no route to 404, no
button to stay grey; the app boots, every test of the loop's own body passes, and
the work silently never happens. That is how the health probe shipped: the
function existed, its unit tests passed, and nothing in the process ever called
it — an open browser tab was the scheduler.

So the guard is static rather than behavioural. Parse `soc_ai/main.py`, collect
every `async def _*_loop` it defines, and require each one to be handed to
`asyncio.create_task` and to have its task cancelled in the shutdown block. A new
loop added without wiring fails here rather than at 3am on somebody's grid.
"""

from __future__ import annotations

import ast
from pathlib import Path

_MAIN = Path(__file__).resolve().parent.parent / "soc_ai" / "main.py"


def _tree() -> ast.Module:
    return ast.parse(_MAIN.read_text(encoding="utf-8"))


def _loop_names(tree: ast.Module) -> set[str]:
    return {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef) and node.name.endswith("_loop")
    }


def _started(tree: ast.Module) -> set[str]:
    """Names passed to ``asyncio.create_task(<name>(...))``."""
    out: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr == "create_task"):
            continue
        for arg in node.args:
            if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name):
                out.add(arg.func.id)
    return out


def _task_var_by_loop(tree: ast.Module) -> dict[str, str]:
    """``{loop name: the variable its task was assigned to}``.

    Read from the assignments themselves rather than guessed from a naming
    convention — the lifespan does not follow one consistently
    (``_discovery_scheduler_loop`` is held as ``discovery_task``), and a guard
    that invents the mapping reports failures that are its own.
    """
    out: dict[str, str] = {}
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)):
            continue
        call = node.value
        if not (isinstance(call.func, ast.Attribute) and call.func.attr == "create_task"):
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name):
            continue
        for arg in call.args:
            if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name):
                out[arg.func.id] = target.id
    return out


def _cancelled(tree: ast.Module) -> set[str]:
    """Variables on which ``.cancel()`` is called."""
    return {
        node.func.value.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "cancel"
        and isinstance(node.func.value, ast.Name)
    }


def test_every_loop_is_started_at_startup() -> None:
    tree = _tree()
    loops = _loop_names(tree)
    assert loops, "no scheduler loops found in main.py — did they move?"
    unstarted = sorted(loops - _started(tree))
    assert not unstarted, (
        "these loops are defined but never handed to asyncio.create_task, so the "
        f"work they do never happens: {unstarted}"
    )


def test_every_loop_is_cancelled_at_shutdown() -> None:
    """An uncancelled task keeps its client alive past shutdown and logs on the
    way out; the lifespan's teardown block exists to stop exactly that."""
    tree = _tree()
    cancelled = _cancelled(tree)
    task_var = _task_var_by_loop(tree)
    missing = sorted(
        loop for loop in _loop_names(tree) if loop in task_var and task_var[loop] not in cancelled
    )
    assert not missing, (
        f"these loops are started but their task is never cancelled at shutdown: {missing}"
    )
