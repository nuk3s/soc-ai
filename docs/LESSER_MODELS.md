# Running soc-ai on a lesser model

soc-ai's triage contract was tuned against a strong analyst model. A smaller or slower
backend can drive the same pipeline. Such a backend is a llama.cpp CPU tier, a mid-size
local model or an emergency fallback route. These backends fail in specific, recognizable
ways. This page lists the recorded failures, the knobs that address each one, and the
probe workflow. Qualify a candidate backend with that workflow before production points
at it.

## Standing one up

You have 2 paths from nothing to an endpoint. Both paths land on the same
OpenAI-compatible `LITELLM_BASE_URL` contract.

- **Local, bundled profile:** it runs Ollama and a LiteLLM proxy on the app's own Docker
  network. It publishes nothing to the host. The order of the steps matters, because the
  main stack owns the `soc-ai_default` network that this profile joins.

  1. Run `./setup.sh` first. At the gateway-URL prompt enter `http://litellm:4000`.
     Accept the model-list warning, because the host cannot resolve that name yet. The
     doctor validates the name after everything is up.
  2. Run `docker compose -f docker-compose.llm.yml up -d`. Then run
     `docker compose -f docker-compose.llm.yml exec ollama ollama pull qwen3:14b`.
  3. A later `.env` edit needs `docker compose up -d` to apply. A model swap and a new
     key are both such edits. `restart` does not re-read `.env`.

  On a CPU a verdict takes minutes. Read the time-budget ladder below before you call the
  backend broken.

  The pull is several GB. Until it finishes, the gateway lists the model and every call
  fails. A model-fitness FAIL from the doctor in that window means that the model is
  still downloading. Ollama also runs on system RAM if you have no GPU. It is slower
  there.

- **Cloud key:** pick route 2 in `./setup.sh`. Supply an OpenRouter key or any other
  OpenAI-compatible key. The route sets `ANALYST_CLOUD_REDACTION=true` for you and prints
  the egress disclosure. There is no local model process.

Qualify the backend with `model-probe` on either path. The next section covers the probe.
Do this before you point real triage at the backend.

## Qualify the backend first: `model-probe`

Measure the candidate against the real contract before you change any setting:

```bash
soc-ai model-probe --model my-new-backend
soc-ai model-probe --model my-new-backend --output-mode native
soc-ai model-probe --model my-new-backend --tool-choice required
soc-ai model-probe --model my-new-backend -n 12 --min-ok 10   # CI gate
```

The probe runs the same synthesizer agent as production. It uses the same builders and
the same system prompt against a canned benign-DNS scenario. It counts the outcomes into
the failure classes below. The attempts run one after the other, so queue wait on a
single-slot backend never reads as model latency.

The report includes `served_backend` from the gateway's own response headers. Trust
`served_backend` over the model name, because a LiteLLM alias or fallback route reports
the requested name. That mislabelling derailed a real incident investigation on
2026-08-03.

Probe once for each candidate setting. The results tell you which knob below to change.
Most backends need no knob.

## Failure taxonomy

Every entry here comes from a recorded incident.

| Probe label / symptom | What is happening | Knob |
| --- | --- | --- |
| `schema_retry_exhausted` | The output shape wobbles. The model produces near-valid JSON. Validation fails until the retry budget runs out. | `--output-mode native`. Retries are already 3-10 per agent. |
| Prose instead of a tool call | Under `tool_choice='auto'` the model answers in text. The report never arrives. | `--tool-choice required`. `--output-mode native` also works, and it removes the tool path. |
| Tool-call markup arrives as content | The serving engine's tool-call parser does not match the model's template. An aliased route showed DSML markup in prose. | `--output-mode native` or `prompted`. Both bypass the parser. |
| "Model token limit ... before any response was generated" | A reasoning model spent the whole response budget on reasoning. | Raise `synthesizer_max_response_tokens`. The default is already 32000. |
| `timeout` / `http_408` | Generation is slower than the HTTP budget or the wall-clock budget. | Raise `litellm_request_timeout_s`. The default is 300 s. A CPU tier that writes a 600-token report at 3 tok/s exceeds it. Then check the wall-clock ladder below. |
| `http_5xx` | The serving stack failed. The model did not. | Fix the backend. The hint system separates a gateway failure from an Elasticsearch failure since the 2026-08-03 fix. |
| Stringified JSON, `"None"` strings, bare scalars for lists, `"False Positive"` | The report is correct, and its formatting wobbles. | Nothing. Schema coercion folds these values before validation. |

## The knobs

### Structured output mode

This is the biggest lever.

`synthesizer_output_mode` controls how the no-tools synthesizer agents obtain the
TriageReport. The values are `tool`, `native` and `prompted`. The default is `tool`.

- `tool` uses the synthetic `final_result` tool call of pydantic-ai. It works wherever
  the backend's tool-call parser works. That parser is the most troublesome component in
  this lab.
- `native` uses the OpenAI `response_format` json_schema. That is server-side guided
  decoding. The server constrains generation to the schema, so schema wobble is
  impossible, and the tool-call parser is out of the path. vLLM and llama.cpp both
  support it. A test through LiteLLM verified this on 2026-08-04: deepseek-v4-flash on
  vLLM returned 4/4 usable in 13.7 s, against 4/4 in 95.1 s for `tool` mode, and
  qwen3.6-35b-cpu on llama.cpp returned 2/2 in every mode. Guided decoding also skips a
  lot of ceremony.
- `prompted` puts the schema in the prompt and parses the JSON out of the text. Use it
  for a backend where both the tool parser and `response_format` are broken.

The investigator keeps `tool` mode in every case. The investigator interleaves real tool
calls, and `native` mode removes that ability.

### Tool choice

`analyst_tool_choice_required` allows `tool_choice='required'`. Its default is `False`.
The historical behaviour forced `auto` for every backend. That was a workaround for a
parser bug in the vLLM qwen3_coder path, and it was hardcoded.

The value of `required` is a per-backend fact. The llama.cpp CPU tier works under `auto`.
The short-lived laguna-s21 backend appeared to need `required`. The evidence for that was
small-N, and the backend is gone. Probe before you change the setting.

### Time budgets

A lesser model shifts the whole latency distribution right. The budget ladder runs from
inner to outer. Each budget must stay under the next one.

| Setting | Default | Bounds |
| --- | --- | --- |
| `litellm_request_timeout_s` | 300 | One HTTP read from the gateway |
| `investigation_turn_timeout_s` | 600 | One agent turn: the model call and the retries |
| `investigation_run_timeout_s` | 900 | One whole investigation |
| `auto_triage_per_target_timeout_s` | 1200 | Outer cap for each auto-triage target. The floor is 1.25× the run timeout at use. |

For a slow backend, scale the whole ladder together. If you raise only the outer caps,
the inner HTTP timeout still fails the run. The p99 of a completed run on the strong
model is ~8.6 min. Measure the probe `elapsed_s` of your candidate and size the ladder
from it.

### Retry budgets

Schema-validation retries are per agent. Every synthesizer has 3. The investigator has 10
in `investigator_retries`. These retries were the bottleneck before the coercion layer
arrived. With the coercion layer, a higher retry count mostly spends tokens on a backend
that native mode would fix outright.

### Quality compensation

Two existing features suit a weaker analyst model:

- **Oracle escalation** in `oracle_enabled`. The weak model does the routine work. An
  uncertain verdict and a high-stakes verdict escalate to the Oracle model for
  adjudication. This is the strongest quality knob for a small analyst model, because the
  expensive model reviews only the cases that need it.
- **Self-consistency vote:** the flag-gated N-sample vote turns verdict variance into an
  explicit `inconclusive`. Verdict variance is a weak-model trait. The vote costs N×
  synthesis tokens for each alert.

The deterministic guardrails need no configuration. The evidence gate blocks a zero-tool
true-positive or false-positive verdict. Decision templates constrain the routine
dispositions. The confidence policy caps what an under-evidenced report can claim.

One exemption from the evidence gate exists: a dispositive decision template. The
STUN, QUIC, DNSSEC and NTP templates read what the rule detected. The exemption still
requires the report to cite the grounds of the template. Automatic acknowledgement needs
the same retrieval. soc-ai never writes a verdict with no retrieval back to Security
Onion unattended.

## Attribution: which model ran

Every error event and every usage event records `served_backend`. That field holds the
`api_base`, the deployment id and the attempted-fallback count from LiteLLM's response
headers. If triage quality drops after a fallback window, filter the investigations by
backend. A route name is unreliable for an alias or a fallback. The schema-coercion layer
logs nothing if it rescues a report. `retry_causes` on the error events is the definitive
record of what a backend emitted.
