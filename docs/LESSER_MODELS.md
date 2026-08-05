# Running soc-ai on a lesser model

soc-ai's triage contract was tuned against a strong analyst model. Smaller or
slower backends — a llama.cpp CPU tier, a mid-size local model, an emergency
fallback route — can drive the same pipeline, but they fail in specific,
recognizable ways. This page lists the failure shapes we have actually recorded,
the knobs that address each one, and the probe workflow for qualifying a
candidate backend before prod points at it.

## Qualify the backend first: `model-probe`

Before changing any setting, measure the candidate against the real contract:

```bash
soc-ai model-probe --model my-new-backend
soc-ai model-probe --model my-new-backend --output-mode native
soc-ai model-probe --model my-new-backend --tool-choice required
soc-ai model-probe --model my-new-backend -n 12 --min-ok 10   # CI gate
```

The probe runs the same synthesizer agent prod uses (same builders, same system
prompt) against a canned benign-DNS scenario and tallies the outcomes into the
failure classes below. Attempts run sequentially so queue wait on a single-slot
backend never masquerades as model latency. The report includes
`served_backend` from the gateway's own response headers — trust that over the
model name, because a LiteLLM alias or fallback route reports the requested
name, not the serving engine. That mislabeling derailed a real incident
investigation on 2026-08-03.

Probe once per candidate setting. The results tell you which of the knobs below
to flip; most backends need none.

## Failure taxonomy

Every entry here comes from a recorded incident, not speculation.

| Probe label / symptom | What is happening | Knob |
| --- | --- | --- |
| `schema_retry_exhausted` | Output-shape wobble: the model produces near-valid JSON that fails validation until the retry budget runs out | `--output-mode native`; retries are already 3-10 per agent |
| Prose instead of a tool call | Under `tool_choice='auto'` the model answers in text; the report never arrives | `--tool-choice required`, or `--output-mode native` (removes the tool path entirely) |
| Tool-call markup leaking as content | The serving engine's tool-call parser does not match the model's template (seen as DSML markup in prose from an aliased route) | `--output-mode native` or `prompted` — both bypass the parser |
| "Model token limit ... before any response was generated" | A reasoning model burned the whole response budget thinking | Raise `synthesizer_max_response_tokens`; already 32000 by default |
| `timeout` / `http_408` | Generation is slower than the HTTP or wall-clock budget | Raise `litellm_request_timeout_s` (default 300s — a CPU tier writing a 600-token report at 3 tok/s exceeds it), then check the wall-clock ladder below |
| `http_5xx` | The serving stack, not the model | Fix the backend; the hint system distinguishes gateway from Elasticsearch failures since the 2026-08-03 fix |
| Stringified JSON, `"None"` strings, bare scalars for lists, `"False Positive"` | Formatting wobble in an otherwise-correct report | Nothing — schema coercion folds these before validation |

## The knobs

### Structured output mode — the biggest lever

`synthesizer_output_mode` (`tool` | `native` | `prompted`, default `tool`)
controls how the no-tools synthesizer agents obtain the TriageReport:

- `tool` — pydantic-ai's synthetic `final_result` tool call. Works everywhere
  the backend's tool-call parser works, and that parser is the component that
  has failed most interestingly in this lab.
- `native` — OpenAI `response_format` json_schema, i.e. server-side guided
  decoding. The server constrains generation to the schema, so schema wobble
  is impossible and the tool-call parser is out of the path. Both vLLM and
  llama.cpp support it, verified through LiteLLM on 2026-08-04:
  deepseek-v4-flash (vLLM) 4/4 usable in 13.7s versus 4/4 in 95.1s for `tool`
  mode, and qwen3.6-35b-cpu (llama.cpp) 2/2 in every mode. Guided decoding
  also skips a lot of ceremony.
- `prompted` — schema in the prompt, JSON parsed from text. The escape hatch
  for a backend where both the tool parser and `response_format` are broken.

The investigator keeps `tool` mode regardless: it interleaves real tool calls,
which is the thing `native` mode removes.

### Tool choice

`analyst_tool_choice_required` (default `False`) allows
`tool_choice='required'` instead of the historical forced-`auto` (a workaround
for a vLLM qwen3_coder parser bug, previously hardcoded for every backend).
Whether `required` helps is a per-backend fact: the llama.cpp CPU tier is fine
under `auto`, while the short-lived laguna-s21 backend appeared to need
`required` (small-N evidence; that backend is gone). Probe before flipping.

### Time budgets

A lesser model shifts the whole latency distribution right. The budget ladder,
inner to outer — each must stay under the next:

| Setting | Default | Bounds |
| --- | --- | --- |
| `litellm_request_timeout_s` | 300 | One HTTP read from the gateway |
| `investigation_turn_timeout_s` | 600 | One agent turn (model call + retries) |
| `investigation_run_timeout_s` | 900 | One whole investigation |
| `auto_triage_per_target_timeout_s` | 1200 | Outer cap per auto-triage target; floored at 1.25× the run timeout at use |

For a very slow backend, scale the ladder together — raising only the outer
caps leaves the inner HTTP timeout doing the failing. Completed-run p99 on the
strong model is ~8.6 min; measure your candidate's probe `elapsed_s` and size
accordingly.

### Retry budgets

Schema-validation retries are per-agent: 3 on every synthesizer, 10 on the
investigator (`investigator_retries`). These were the bottleneck before the
coercion layer landed; with it, raising them further mostly spends tokens on a
backend that native mode would fix outright.

### Quality compensation

Two existing features pair well with a weaker analyst:

- **Oracle escalation** (`oracle_enabled`): the weak model does the legwork,
  and uncertain or high-stakes verdicts escalate to the Oracle model for
  adjudication. This is the highest-leverage quality knob when the analyst is
  small — the expensive model reviews only the cases that need it.
- **Self-consistency vote**: the flag-gated N-sample vote turns verdict
  variance (a weak-model trait) into an explicit `inconclusive` instead of a
  confidently wrong answer. Costs N× synthesis tokens per alert.

The deterministic guardrails need no configuration: the evidence gate blocks
zero-tool TP/FP verdicts, decision templates constrain routine dispositions,
and the confidence policy caps what an under-evidenced report can claim.

## Attribution: knowing which model actually ran

Every error event and usage event records `served_backend` — the `api_base`,
deployment id, and attempted-fallback count from LiteLLM's response headers.
When triage quality looks off after a fallback window, filter investigations by
backend rather than by route name; route names lie whenever an alias or
fallback is involved. The schema-coercion layer logs nothing when it rescues a
report, so the definitive record of what a backend emitted is `retry_causes`
on the error events.
