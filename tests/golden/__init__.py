"""Golden-pipeline backtest gate (E1.4).

A DETERMINISTIC regression suite that pins the *deterministic* layers of the
triage funnel — decision templates, the evidence/citation gates, the targeted
downgrades, and the funnel routing — AROUND the model, not the model's quality.

Each :class:`~tests.golden.scenarios.GoldenScenario` replays a realistic ES
``_source`` dict (Suricata / Zeek shape) through
:func:`soc_ai.agent.orchestrator.investigate` with:

* a mocked Elasticsearch (:mod:`tests.golden.harness`) that returns the
  scenario's alert + canned pivots keyed by the query shape, and
* a SCRIPTED model double (:mod:`tests.golden.model_double`) whose per-call
  outputs are fixed — so the synth/investigator never touch the network.

The test then asserts the final verdict + which deterministic gates fired
(read off the yielded :class:`StepEvent` stream). A prompt or gate edit that
silently flips a golden verdict fails the gate with a clear diff.

See ``docs/dev/superpowers/plans/2026-07-07-epochs-1-3-execution.md`` (E1.4).
"""
