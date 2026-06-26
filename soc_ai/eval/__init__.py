"""Offline evaluation harness for soc-ai.

`soc-ai validate <alert_id>` runs the full investigation pipeline
in-process, sanitizes every event + the final report against the
recipe in :mod:`soc_ai.eval.sanitize`, ships the result through the
LiteLLM gateway (which forwards to the cloud model) for a 1M-ctx
critique, and saves a bundle under
``evals/<ts>-<alert_id>/`` for later review.

Public surface kept intentionally small — the CLI is the only
recommended entry point.
"""

from soc_ai.eval.harness import EvalResult, run

__all__ = ["EvalResult", "run"]
