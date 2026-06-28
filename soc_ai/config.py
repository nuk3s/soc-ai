"""Application configuration via pydantic-settings.

Settings are loaded from environment variables (case-insensitive) and from
a ``.env`` file in the working directory. See ``.env.example`` for the full
surface and inline documentation of each knob.
"""

from __future__ import annotations

from functools import lru_cache
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address
from pathlib import Path
from typing import Annotated, Any

from pydantic import (
    AliasChoices,
    AnyHttpUrl,
    Field,
    IPvAnyNetwork,
    SecretStr,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    """Top-level configuration for soc-ai."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
        # The admin Danger Zone persists connection/secret overrides that are
        # re-applied onto this singleton at startup via setattr. validate_assignment
        # makes those assignments coerce + validate exactly like construction (a
        # str → AnyHttpUrl/SecretStr, a list → typed list), so a DB-stored override
        # lands as the right type. The ONLY setattr site is
        # config_overrides.apply_to_settings.
        validate_assignment=True,
    )

    # --- Security Onion grid -------------------------------------------
    so_host: AnyHttpUrl
    so_username: str
    so_password: SecretStr
    so_verify_ssl: bool = True
    so_ca_bundle: Path | None = None
    # SO 3.0.0 mounts Kratos under /auth/... (the older path is /self-service/...).
    # Default matches SO 3.0.0; older grids can override to "" to skip the prefix.
    so_kratos_path_prefix: str = "/auth"
    # Default timezone for ack/escalate calls (matches the SO web UI default).
    so_timezone: str = "America/New_York"

    # --- Connect API (Pro feature, optional fallback) ------------------
    so_client_id: str | None = None
    so_client_secret: SecretStr | None = None

    # --- Elasticsearch (typically the same cluster as SO ES) -----------
    es_hosts: Annotated[list[AnyHttpUrl], NoDecode]
    es_username: str | None = None
    es_password: SecretStr | None = None
    es_verify_ssl: bool = True
    # Per-request timeout in seconds. Bumped from the original 30s after
    # batch runs saw prefetches time out with `ConnectionTimeout` under
    # concurrency (several runs * ~6 pivot queries each = dozens of
    # simultaneous ES queries on a contended cluster). 60s gives a typical
    # grid headroom; lower for fast production clusters, raise for
    # shared/contended ones.
    es_request_timeout_s: int = 30
    # Transport-layer retries for transient ConnectionTimeout / 5xx from
    # ES under heavy concurrency. The elasticsearch-py client retries
    # internally, so we don't need to wrap call sites by hand. Bounded so a
    # fully-unreachable grid can't stall a call for request_timeout x (1+retries):
    # 30s x 3 = 90s worst case (was 60 x 4 = 240s).
    es_max_retries: int = 2
    # Hard wall-clock bound for INTERACTIVE console grid queries (alerts list +
    # group events). Below the worst-case ES retry budget so the UI fails fast
    # with a clean "grid unavailable" error instead of hanging while the client
    # retries a down/slow Elasticsearch. Background hunts are not bounded by this.
    webui_grid_timeout_s: int = 12

    # --- LiteLLM gateway -----------------------------------------------
    litellm_base_url: AnyHttpUrl
    litellm_api_key: SecretStr | None = None
    # Disable for self-signed certs in homelab deployments. Defaults true.
    litellm_verify_ssl: bool = True
    # Per-request HTTP read timeout in seconds. The synthesizer (heavy 120B)
    # can take 60-150s for a single TriageReport call on a busy GPU; under
    # batch concurrency=2+ that crosses the old 120s default. 300s gives
    # headroom for slow-but-progressing calls without masking genuine hangs
    # (the harness layer enforces a separate per-run wall-clock cap).
    litellm_request_timeout_s: float = 300.0

    chat_turn_timeout_s: int = 300
    """Wall-clock timeout for a single chat turn (seconds).  A chat turn may
    issue several tool calls, so this should be larger than
    litellm_request_timeout_s.  When the turn exceeds the limit it is bounded by
    an ``asyncio.timeout`` block inside the turn (raising ``TimeoutError``, a
    normal Exception), so the turn's error handler writes a terminal error row
    and the pending status never gets stuck.  Bumped 180→300 after
    a legitimately-deep follow-up needed >180s; raise further for slower GPUs."""

    litellm_max_retries: int = 5
    """How many times the OpenAI client retries a gateway request on a transient
    error (connection drop, 429, 5xx). The openai default is 2, which can't ride
    out a brief LiteLLM-gateway blip (observed ~15s) — the investigator then
    fails and the run collapses to a misleading needs_more_info. 5 with the
    client's exponential backoff covers a short outage."""

    # --- Model aliases (defined in the LiteLLM config) -----------------
    # The single model the analyst agent uses for every triage. (There is no
    # separate "fast" tier; the optional cloud second opinion is the Oracle,
    # configured under `oracle_*` below and OFF by default.) ``HEAVY_MODEL`` is
    # still accepted as a deprecated alias so older .env files keep working.
    analyst_model: str = Field(
        default="soc-ai-analyst",
        validation_alias=AliasChoices("ANALYST_MODEL", "HEAVY_MODEL"),
    )

    # --- Audit logging -------------------------------------------------
    audit_index_alias: str = "soc-ai-audit"
    audit_redact: bool = True
    """Redact secret-shaped strings from audit records before the ES write.

    Default True: soc-ai's audit log lands in a *shared* ES cluster, so any
    credential that leaks into audit content would be readable by everyone with
    cluster access. Redaction fires only on secret *shapes* — ``scai_`` tokens,
    ``Bearer`` headers, ``X-Session-Token``, ``password=``, AWS/GitHub keys, and
    similar patterns — so normal audit content (verdicts, tool calls, alert ids,
    reasoning) is untouched. Set False only if you need verbatim audit bodies and
    accept the leak risk."""
    audit_fail_closed: bool = True
    """Abort SO-mutating actions (ack/escalate/comment/auto-ack) when their audit
    record cannot be written. Default True: no state change without an audit
    trail — a write tool returns an error instead of silently succeeding without
    a record. This trades *availability* for *accountability*: if the audit ES
    index is unreachable, mutating actions fail until it recovers. Read/triage/
    enrichment audit writes stay fail-open regardless (audit loss never crashes a
    read). Set False to revert mutating writes to fail-open (the pre-1.x
    behaviour) if availability matters more than a guaranteed audit record."""

    # --- Local enrichment ----------------------------------------------
    misp_url: AnyHttpUrl | None = None
    misp_api_key: SecretStr | None = None
    # Verify the MISP TLS cert. Default True (secure). Homelab MISP often uses a
    # self-signed cert — set MISP_CA_BUNDLE to its CA, or MISP_VERIFY_SSL=false to
    # disable verification entirely (insecure; the API key transits this channel).
    misp_verify_ssl: bool = True
    misp_ca_bundle: Path | None = None
    internal_cidrs: Annotated[list[IPvAnyNetwork], NoDecode] = [
        IPv4Network("10.0.0.0/8"),
        IPv4Network("172.16.0.0/12"),
        IPv4Network("192.168.0.0/16"),
    ]

    # --- Index patterns ------------------------------------------------
    # Patterns that match the SO indices. On Security Onion 3.0 the Suricata/Zeek
    # event + alert data lives in Elasticsearch DATA STREAMS named `logs-*` (e.g.
    # `.ds-logs-suricata.alerts-so-*`), while cases/detections/playbooks use the
    # older `so-*` indices. The defaults below target a SINGLE-NODE grid.
    #
    # MULTI-NODE / distributed grids reach the data through cross-cluster search,
    # so prefix every pattern with the remote-cluster wildcard, e.g.
    # `*:logs-*`, `*:so-case*`. `setup.sh` AUTO-DETECTS the right prefix (it
    # probes the grid during the ES check) and writes the concrete values to
    # `.env`, so the guided install gets this right on either shape.
    #
    # NOTE: the legacy `*:so-*` default matched the old `so-*` indices, NOT the
    # `logs-*` data streams where alerts live — it left the console empty on a
    # healthy grid. Do not reintroduce it.
    events_index_pattern: str = "logs-*"
    cases_index_pattern: str = "so-case*"
    detections_index_pattern: str = "so-detection*"
    playbooks_index_pattern: str = "so-playbook*"

    # --- Internal-identifier discovery ---------------------------------
    # Auto-discovery of internal domain suffixes + bare internal hostnames from
    # Security Onion data, for the Oracle egress sanitizer (so it redacts a
    # deployment's own internal hosts before cloud egress without hand-config).
    # See soc_ai/enrichment/discovery.py and the managed list in
    # soc_ai/store/internal_identifiers.py.
    discovery_enabled: bool = True
    """Master switch for the internal-identifier discovery job (the daily timer
    and the `discover-internal-identifiers` CLI / scan-now endpoint). Off skips
    the scan entirely — operator-set identifiers still apply."""

    discovery_lookback_days: int = 7
    """ES query window (days) the discovery scan aggregates over to learn
    internal domain suffixes + hostnames."""

    discovery_min_hosts: int = 3
    """Distinct-internal-host count at/above which a clearly-internal candidate
    auto-activates as a redaction rule. Below it, the candidate lands `muted`
    (a suggestion). A public registrable domain NEVER auto-activates regardless
    of this count — it is always muted."""

    discovery_schedule_enabled: bool = False
    """Run the internal-identifier discovery scan automatically on a schedule
    (an in-process background loop in the API server). Off by default — the
    scan still runs on demand via the 'Scan now' button / the
    `discover-internal-identifiers` CLI. When on, the loop honors
    `discovery_enabled` (the master switch) and the interval below. Toggling
    this in the config console takes effect live (no restart)."""

    discovery_schedule_interval_hours: int = 24
    """Hours between automatic discovery scans when `discovery_schedule_enabled`
    is on. Bounded 1..168 (hourly to weekly). The scheduler checks elapsed time
    against the last completed scan, so a freshly-toggled-on schedule that has
    never run scans on the next wake."""

    # --- Server --------------------------------------------------------
    soc_ai_host: str = "127.0.0.1"
    soc_ai_port: int = 8443
    soc_ai_tls_cert: Path | None = None
    soc_ai_tls_key: Path | None = None
    log_level: str = "INFO"

    # --- Web UI / local store -------------------------------------------
    soc_ai_data_dir: Path = Path("data")
    # Secure default: require a login/token for the API. The admin console and
    # the userscript both authenticate; only flip this off for an isolated,
    # trusted-network demo where you understand the exposure.
    api_auth_required: bool = True
    # Cross-origin origins allowed to call the API (the Tampermonkey userscript
    # runs in the SO web UI's origin). CSV; empty = scope to so_host; "*" = allow
    # all (NOT recommended for a public deployment). The React /app is
    # same-origin and needs none of this.
    cors_allow_origins: str = ""
    # Extra origins (CSV) that cookie-authenticated mutating requests may carry in
    # their Origin/Referer header, folded into the CSRF allowlist alongside the
    # app's own origin and ``cors_allow_origins``. Default empty. Same-origin
    # requests from the React SPA need nothing here; this is an escape hatch for
    # a reverse-proxy hostname or an extra UI host. (Distinct from CORS: CORS
    # governs cross-origin *browser fetches*; this governs CSRF Origin checks.)
    csrf_trusted_origins: str = ""
    # Expose the interactive API docs (/docs, /redoc) and the raw schema
    # (/openapi.json). Off by default — a security product shouldn't publish its
    # full admin API surface unauthenticated. Turn on for local development.
    expose_api_docs: bool = False
    # Content-Security-Policy sent on every response. The default is safe for the
    # bundled Vite SPA (self-hosted scripts; Tailwind needs inline styles). Set to
    # an empty string to disable, or override for a custom deployment.
    content_security_policy: str = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; font-src 'self' data:; connect-src 'self'; "
        "object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
    )
    # Coarse per-client-IP request ceiling (fixed 60s window) as flood/DoS
    # backpressure. Generous by default so normal UI polling never trips it; set
    # 0 to disable (e.g. when a reverse proxy already rate-limits). /healthz is
    # always exempt so container health checks keep working under load.
    api_rate_limit_per_min: int = 1200
    session_ttl_hours: int = 12
    bootstrap_admin_password: SecretStr | None = None
    config_secret_key: SecretStr | None = None
    """Fernet key (44-char url-safe base64) for encrypting secret config
    overrides at rest in the config DB. Generate with
    ``python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"``
    and set ``CONFIG_SECRET_KEY`` in ``.env``. When unset, the Danger Zone can
    still edit connection identity but secret VALUES (passwords/keys/tokens) are
    not editable via the UI — they stay env-managed."""
    webui_alerts_query: str = "tags:alert"
    webui_inherit_window_days: int = 7
    webui_extra_detections: bool = True
    """Broaden the alerts feed beyond Suricata to SO's other detection outputs:
    union ``sigma.alert`` (Sigma hits) and ``zeek.notice`` ATTACK::*
    (behavioral threat notices) with the configured Suricata primary, each tagged
    by ``kind``. SO catches more than Suricata (e.g. Zerologon fires Zeek dce_rpc,
    not a Suricata sig); this surfaces what SO flags by non-Suricata means. Off
    restores the Suricata-only feed."""

    auto_triage_max_targets: int = 25
    """Safety cap on how many investigation targets a single ⚡ auto-triage run
    will queue. On a busy grid the planner can cluster many distinct (rule,
    src, dst) flows; without a cap one click could spawn dozens of sequential
    hunts. Overflow targets are simply not queued this run (they have no verdict
    yet, so the next run picks them up). Set 0 to disable the cap."""

    # --- Agent execution limits ----------------------------------------
    # Caps the number of tool calls + LLM requests per investigation so a
    # runaway loop can't burn the budget (or the operator's patience). Tuned
    # down from 100/50 after a thorough investigation was observed to run
    # ~12 tool calls (web_search + host pivots + oracle); 25/18 leaves
    # generous headroom while bounding worst-case latency. Raise if a
    # deployment legitimately needs deeper loops.
    agent_tool_calls_limit: int = 25
    agent_request_limit: int = 18

    synthesizer_temperature: float = 0.2
    """Sampling temperature for the SYNTHESIZER (the verdict decision). Low for
    determinism — the same evidence should yield the same verdict, run to run.
    Reduces the FP/TP verdict swing observed on repeated hunts."""

    investigator_temperature: float = 0.4
    """Sampling temperature for the INVESTIGATOR (tool selection / pivots).
    Moderate — keep some exploration so it doesn't tunnel on one path, but low
    enough that the investigation is broadly reproducible."""

    # --- Two-stage investigation routing -------------------------------
    # The investigator (fast model) gathers evidence with the read tools;
    # the synthesizer (heavy model) reads the transcript and emits a
    # TriageReport. If the synthesizer's confidence comes back below
    # synthesis_confidence_floor, the investigator is retasked once with
    # the prior transcript + the synthesizer's open_questions, and the
    # synthesizer runs again on the combined evidence. The retask is
    # capped at 1 — a still-low confidence after retask surfaces as-is.
    synthesis_confidence_floor: float = 0.6

    # The retask round 2 is meant for FOCUSED gap-closing, not breadth
    # gathering. Cap its tool calls tightly so a runaway second round
    # can't accumulate enough tool-result history to blow either model's
    # 64K context window on this grid (both Nemotron 3 Nano-30B and
    # Super-120B are deployed with 64K serving windows).
    agent_retask_tool_calls_limit: int = 15
    agent_retask_request_limit: int = 12

    # --- Investigator response-token cap -------------------------------
    # Single investigator turns were observed producing ~13.6K
    # reasoning-trace tokens for 2 tool calls — pure waste, and a dominant
    # contributor to p95 investigation latency. The cap bounds the response
    # (reasoning + content) per turn, so a chatty turn can't dominate the
    # wall-clock.
    #
    # Calibration: measured reasoning_trace sizes — p50 5.6K chars (≈1.4K
    # tokens), p95 23.7K chars (≈5.9K tokens), max 23.7K chars. With
    # tool-call args on top, the actual response total p95 is closer to
    # 6-7K tokens. Iterative calibration:
    # - 2500 → rejected immediately ("token limit exceeded before any
    #   response was generated")
    # - 8000 → rejected on first outlier turn
    # - 16000 → hit the cap on ~10% of turns, each retry was another
    #   16K-token attempt, and in-flight alerts stuck waiting for
    #   retry-exhaust → per-run timeout → effective error budget exceeded
    # - 32000 → covers the worst-observed reasoning trace (~6K tokens)
    #   with 5x headroom, while still preventing the truly pathological
    #   "model writes a 50K-token essay before calling final_result"
    #   degenerate case. Per-turn, not per-investigation.
    investigator_max_response_tokens: int = 32000

    # --- Rule-class fast-path ------------------------------------------
    # Meta-analysis showed the large majority of verdicts (e.g. 33/38) were
    # false_positive with mean investigation time ~12 min. Most of that work
    # confirms noise. The fast-path routes informational_visibility +
    # severity=low alerts through a stripped-down "confirm-or-deny benign
    # hypothesis" prompt with a relaxed retask floor and a tighter tool budget.
    enable_rule_class_fast_path: bool = True
    # Lower confidence floor on the fast-path. The full-pipeline floor
    # (synthesis_confidence_floor=0.6) errs on the side of retasking;
    # informational-visibility alerts almost never benefit from a second
    # round, so we let confidence ≥0.4 pass through.
    fast_path_synthesis_floor: float = 0.4
    # Tool-call cap on the fast-path investigator. Phase 1 smoke showed
    # a healthy ET INFO triage uses 3 tool calls + 1-3 final_result schema
    # retries → ~6 requests. The original 8-request cap was right on the
    # edge (one bad retry overshoots). 15 / 12 give the model real headroom
    # while staying tighter than the standard 100 / 50.
    fast_path_tool_calls_limit: int = 15
    fast_path_request_limit: int = 12
    # Fraction of fast-path-eligible alerts to route through the FULL
    # pipeline anyway, for drift monitoring. Setting to 0.0 disables
    # sampling (fast-path always taken when eligible). Tests should
    # also set 0.0 so they're deterministic.
    fast_path_sampling_rate: float = 0.05
    # Mandatory enrichment call on the fast-path. When an alert has
    # an external destination IP, the orchestrator runs ONE t_enrich_ip
    # call before the synth so the verdict rests on positive enrichment
    # signal. If the result has a MISP hit / flagged ASN, the orchestrator
    # escalates to the FULL investigator pipeline. Timeout bounds the
    # extra wall-clock cost — 30s is generous for a local MISP call.
    fast_path_enrichment_timeout_s: float = 30.0

    # --- Synth-first pipeline ------------------------------------------
    fast_triage_enabled: bool = True
    """Allow the fast path: finalize a confident first-pass verdict without the
    full tool-driven investigation loop. Saves time but can yield shallower
    results (a verdict may land with few or no tool calls). Turn OFF to always
    investigate with tools. Exposed in the admin config console."""

    synth_first_pipeline: bool = True
    """Route alerts through the synth-first A→B→C→D pipeline (default).

    Set to ``False`` only to A/B against the legacy two-stage investigator
    pipeline (still wired through ``soc_ai.agent.orchestrator.investigate``
    when this flag is False)."""

    investigate_when_unsure: bool = True
    """Run a real bounded investigation loop when the synth-first round-1
    verdict is not evidence-backed (Theme-1 Task 1).

    The synth-first round-1 call is a NO-tools structured-output guess that
    rationalizes the prefetch. When its verdict's citations resolve only to
    self-referential ``alert.*`` fields (not to actual tool/enrichment/pivot
    evidence), and the alert is non-trivial (not a clean-internal benign),
    the pipeline runs the tool-bound investigator on the HEAVY model so the
    model itself chooses which read tools to call, then re-synthesizes over
    the gathered transcript. Trivially-benign alerts keep the fast path.

    Flag so we can A/B it on the synth-9 and revert instantly. Set ``False``
    to restore the pure zero-tool synth-first behavior."""

    host_risk_window_hours: int = 24
    """Look-back/forward window (hours, each side) for the host-risk profile.

    The 5 tight pivots key on fields (``network.community_id`` / ``host.name`` /
    ``user.name``) that are absent on network-sensor / so-import-pcap alerts, and
    they only span ±``window_seconds`` (5 min) — far too narrow to notice that the
    alert's HOST is compromised. For example, an internal SMB leg from a
    NetSupport-RAT victim was cleared zero-tool because the C2 check-ins were
    ~12h away and keyed on fields the pivot never queried. The host-risk profile
    is a wide ±N-hour aggregation over the alert's source/destination IPs that
    surfaces the endpoint's recent alert histogram so the agent can see "this host
    is also firing RAT/C2/malware signatures." Set to 0 to disable."""

    investigation_reaper_minutes: int = 30
    """Age (minutes) past which a still-``running`` investigation is considered
    stale and marked ``error`` by the periodic reaper. Generous so a legitimately
    in-flight hunt is never killed; on startup ALL ``running`` rows are reaped
    regardless of age (their background tasks died with the previous process)."""

    investigation_reaper_interval_minutes: int = 10
    """How often the background reaper sweeps for stale ``running`` rows. Set the
    interval or the age above to 0 to effectively disable the periodic sweep
    (startup reap still runs)."""

    # --- Local enrichment data directories (no runtime egress) ---------
    blocklist_data_dir: Path = Path("/var/lib/soc-ai/blocklists")
    """Directory holding refreshed blocklist files (URLhaus CSV, Feodo Tracker
    JSON, Tor exit list, internal_seed.yaml, etc.). Refreshed by the
    `soc-ai blocklists refresh` CLI subcommand."""

    maxmind_data_dir: Path = Path("/var/lib/soc-ai/maxmind")
    """Directory holding MaxMind GeoLite2 .mmdb files (ASN + City). Refreshed
    by the same CLI subcommand. Requires `maxmind_license_key` to be set."""

    cloud_prefix_data_dir: Path = Path("/var/lib/soc-ai/cloud_prefixes")
    """Directory holding vendored cloud-provider prefix JSON files (AWS, GCP,
    Azure, Cloudflare). Refreshed weekly by the CLI subcommand."""

    blocklist_sources: Annotated[list[str], NoDecode] = [
        "urlhaus",
        "threatfox",
        "feodo",
        "tor",
        "internal_seed",
    ]
    """Which BlocklistDB sources to load at startup. Spamhaus DROP/EDROP is
    OFF by default — it requires a commercial license for paid deployments
    and the operator must explicitly opt in via this list AND set
    `spamhaus_license_acknowledged=True`."""

    spamhaus_license_acknowledged: bool = False
    """Operator acknowledges Spamhaus license terms (free for non-commercial
    use; commercial use requires a paid license). Required to enable the
    `spamhaus_drop` blocklist source."""

    maxmind_license_key: SecretStr | None = None
    """Free MaxMind GeoLite2 license key. Register at maxmind.com/en/geolite2/signup
    and put the key in `.env` as `MAXMIND_LICENSE_KEY=...`. Without it,
    GeoIP/ASN enrichment is disabled (everything else still works)."""

    blocklist_stale_threshold_days: int = 7
    """How many days a blocklist file can be without refresh before the
    DB emits a warning event in the audit log. Triage continues to work
    with stale data — fail-open."""

    abuse_ch_auth_key: SecretStr | None = None
    """abuse.ch Auth-Key for the URLhaus / ThreatFox / Feodo Tracker downloads.

    As of the 2024 abuse.ch policy, the CSV/JSON data exports are gated behind
    a free Auth-Key sent as the ``Auth-Key`` HTTP header. Register at
    https://auth.abuse.ch/ and put the key in ``.env`` as
    ``ABUSE_CH_AUTH_KEY=...``. When unset, ``soc-ai blocklists refresh`` SKIPS
    the abuse.ch feeds with a clear message (the Tor exit list needs no key and
    still refreshes). The key is sent only by the refresh job — never during
    triage — and is never logged. See ``docs/BLOCKLISTS.md``."""

    azure_service_tags_url: AnyHttpUrl = AnyHttpUrl(
        "https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/"
        "ServiceTags_Public_20241125.json"
    )
    """Download URL for the Azure Service Tags prefix JSON. Override to point
    at a newer dated snapshot without redeploying (the filename encodes the
    publish date). Default matches the file that was current when this
    setting was introduced (2026-06-10)."""

    cloud_prefix_stale_threshold_days: int = 45
    """How many days the cloud-prefix data can be without a successful refresh
    before enrichment appends a staleness warning to ``errors``. 45 days
    is generous for a weekly-refresh schedule with a few missed runs."""

    # --- PCAP retrieval (SSH + suripcap, behind explicit opt-in) ------
    pcap_enabled: bool = False
    """Opt-in to live PCAP retrieval via SSH + Suricata ring-buffer pcap logs.

    Requires ``so_ssh_key`` to point at a private key that has been
    provisioned on the sensor.  Off by default so the package deploys
    safely without an SSH key.  Set ``PCAP_ENABLED=true`` + the SSH
    variables below to enable."""

    so_ssh_host: str = ""
    """Hostname or IP of the Security Onion sensor running Suricata pcap-log.

    Empty by default — the package ships no environment-specific host. REQUIRED
    when ``pcap_enabled`` is True (enforced at startup). Set via ``SO_SSH_HOST``
    or in the config console (Danger Zone)."""

    so_ssh_user: str = "soc-ai"
    """Remote user to SSH in as.  Must have passwordless sudo tcpdump or be
    in the ``socore`` group with read access to ``so_suripcap_dir``."""

    so_ssh_key: Path | None = None
    """Path to the SSH private key file.  Passed as ``ssh -i <key>``.  If
    ``None`` (the default), ssh falls back to its own key discovery — but
    the service unit's ``ProtectHome=read-only`` means it won't find
    ``~/.ssh``, so you almost always need to set this explicitly."""

    so_ssh_known_hosts: Path | None = None
    """Path to a persistent SSH ``known_hosts`` file for the sensor.

    ``None`` (the default) derives ``<soc_ai_data_dir>/known_hosts``. Used as
    ``UserKnownHostsFile`` so the sensor's host key is accepted on first contact
    (``accept-new``) and *remembered* — a later key swap is then rejected rather
    than silently trusted. Set via ``SO_SSH_KNOWN_HOSTS`` to override the path."""

    so_ssh_sudo: str = "sudo"
    """``sudo`` prefix for the remote tcpdump command.  Set to ``""`` if the
    SSH user is already in ``socore`` and has direct read access."""

    so_suripcap_dir: str = "/nsm/suripcap"
    """Directory on the sensor where Suricata's pcap-log files live."""

    so_ssh_timeout_s: int = 120
    """Per-SSH-invocation timeout in seconds (connect + data transfer)."""

    pcap_max_packets: int = 50000
    """Maximum packets to decode from a merged PCAP (``decode_pcap`` cap).
    Prevents OOM on very large flows; truncation is noted in ``PcapFacts``."""

    # --- Web search (SearXNG) -----------------------------------------
    web_search_enabled: bool = False
    """Enable the ``web_search`` investigator tool (SearXNG). When False the
    tool returns a disabled error without any network I/O. Editable in the
    config console."""

    searxng_url: str = ""
    """Base URL of the self-hosted SearXNG instance (e.g. ``https://search.example.com``).
    Empty disables web search. Requires SearXNG's JSON API
    (``search.formats: [json]``). Editable in the config console."""

    searxng_verify_ssl: bool = True
    """Verify the SearXNG TLS cert. Set False for a self-signed homelab cert."""

    searxng_timeout_s: int = 10
    """Per-request timeout for a web search."""

    web_search_max_results: int = 5
    """How many SearXNG results to return to the agent per query."""

    # --- Online enrichment (opt-in, runtime egress) -------------------
    # Everything else in this app is zero-egress (local-mirror feeds). These
    # tools reach OUT to third-party reputation/asset APIs, so they are OFF by
    # default and gated by this master flag. Per-provider keys live below (set in
    # .env; never stored in the DB). The master flag is hot-editable in the
    # config console; keys are display-only there.
    allow_online_enrichment: bool = False
    """Master switch for the opt-in online-enrichment tools (GreyNoise, Shodan
    InternetDB, …). OFF by default to preserve the zero-egress posture. When off,
    each online tool returns a clean 'disabled' result with no network I/O."""

    online_enrichment_timeout_s: int = 8
    """Per-request timeout (seconds) for an online-enrichment lookup."""

    online_enrichment_verify_ssl: bool = True
    """Verify TLS for online-enrichment HTTP calls (these reach the public
    internet, so leave True; only a transparent-proxy setup would need False)."""

    greynoise_api_key: SecretStr | None = None
    """GreyNoise API key (free Community tier available). Set in .env. Without it,
    t_greynoise reports 'not configured' and performs no network I/O."""

    shodan_api_key: SecretStr | None = None
    """Shodan API key (paid). Set in .env. Powers t_shodan_host (the full,
    authenticated /shodan/host lookup — banners, services, vulns). Without it
    that tool reports 'not configured' and makes no request; the free,
    keyless t_shodan_internetdb and t_cve_lookup still work (master flag on)."""

    # --- crawl4ai (deep page read) ------------------------------------
    crawl4ai_enabled: bool = False
    """Enable the ``crawl_page`` investigator tool (crawl4ai). When False the
    tool returns a disabled error without any network I/O. Editable in the
    config console. Complements web_search: search finds pages, crawl_page reads
    them."""

    crawl4ai_url: str = ""
    """Base URL of the self-hosted crawl4ai service (e.g. ``https://crawl.example.com``).
    Empty disables page reads. Editable in the config console."""

    crawl4ai_token: SecretStr | None = None
    """Optional Bearer token for the crawl4ai service (.env only — never the
    config console, never rendered)."""

    crawl4ai_verify_ssl: bool = True
    """Verify the crawl4ai TLS cert. Set False for a self-signed homelab cert."""

    crawl4ai_timeout_s: int = 30
    """Per-request timeout for a page crawl (crawling can be slower than search)."""

    crawl_max_chars: int = 6000
    """Cap on extracted page content (chars) returned to the agent per crawl."""

    # --- Oracle frontier adjudication ---------------------------------
    oracle_enabled: bool = False
    """Explicit cloud opt-in.  When False, _should_escalate_to_oracle() is
    always False and no case ever reaches a frontier model."""

    oracle_model: str = "claude-opus-4-8"
    """LiteLLM model alias for the frontier adjudicator.  Must be reachable
    via litellm_base_url (typically an oracle alias on the gateway)."""

    oracle_timeout_s: float = 120.0
    """Per-call HTTP timeout for the Oracle adjudication request (seconds)."""

    oracle_escalate_needs_more_info: bool = True
    """Escalate to Oracle when local verdict is needs_more_info."""

    oracle_escalate_malware_non_tp: bool = True
    """Escalate to Oracle when the rule signals malware/exploit AND the local
    verdict is not a high-confidence true_positive (confidence ≥ 0.7)."""

    oracle_skip_after_confident_loop: float = 0.8
    """Cost gate: skip the malware/attack-non-TP escalation (condition 2) when
    the investigation loop RAN and reached at least this confidence. A confident
    verdict after a real tool-driven investigation is trustworthy — the Oracle
    double-check is redundant. The zero-tool fast path (loop did NOT run) still
    escalates regardless (the QVOD/BPFDoor safety net), and low-confidence or
    needs_more_info verdicts still escalate via conditions 1 and 3. Set to 1.0
    to always escalate (restore the prior always-double-check behavior)."""

    oracle_escalate_below_confidence: float = 0.6
    """Escalate to Oracle when local confidence falls below this threshold,
    regardless of verdict or rule class."""

    # --- Oracle privacy gate -------------------------------------------
    oracle_internal_suffixes: tuple[str, ...] = (".lan", ".local", ".internal", ".corp")
    """DNS suffixes that identify internal hostnames.

    Any FQDN ending in one of these suffixes is redacted to an opaque
    ``HOST_NN`` label before the payload is sent to the frontier model.
    Public domains pass through untouched.  Extend via a comma-separated
    env var: ``ORACLE_INTERNAL_SUFFIXES=.lan,.local,.myco.internal``
    (pydantic-settings' :class:`NoDecode` + ``_split_csv`` validator handle
    the parsing).
    """

    oracle_extra_hosts: list[str] = []
    """Bare internal hostnames (without a suffix) to redact before the Oracle.

    The redacter already catches a lot automatically: private IPs/MACs, FQDNs on
    an internal suffix, NetBIOS-shaped computer names (``DESKTOP-AB12``,
    ``FINANCE-PC``), every identifier learned from a structured host/user field
    (propagated into free text), and usernames in an explicit credential context
    (``user=jdoe``, ``DOMAIN\\jdoe``).

    What it CANNOT know without being told: an internal FQDN on a public-looking
    suffix (``dc01.ad.acme.com``) or an arbitrary bare codename (``WIN11-01``,
    ``APPSERVER01``) — these are shape-indistinguishable from public threat infra
    the Oracle must see, so they egress verbatim unless enumerated here (bare
    names) or via ``oracle_internal_suffixes`` (internal domains).  Comma-separated:
    ``ORACLE_EXTRA_HOSTS=WIN11-01,APPSERVER01,dbserver``.

    When ``oracle_enabled`` is true and neither this nor a custom
    ``oracle_internal_suffixes`` is set, the Oracle client logs a one-time warning
    (see ``soc_ai.oracle.client._warn_if_privacy_gate_unconfigured``).  Negligible
    on the synthetic lab grid (all addresses are IPs); relevant on real home/work
    grids where hostnames appear in alert fields and Zeek pivot records.
    """

    @field_validator("oracle_internal_suffixes", mode="before")
    @classmethod
    def _parse_suffixes(cls, v: Any) -> Any:
        if isinstance(v, str):
            v = v.strip()
            if not v:
                return ()
            return tuple(s.strip() for s in v.split(",") if s.strip())
        return v

    @field_validator("oracle_extra_hosts", mode="before")
    @classmethod
    def _parse_extra_hosts(cls, v: Any) -> Any:
        if isinstance(v, str):
            v = v.strip()
            if not v:
                return []
            return [h.strip() for h in v.split(",") if h.strip()]
        return v

    # --- Auto-acknowledge high-confidence false positives ---------------
    auto_ack_fp_enabled: bool = False
    """When True, an investigation that finalises with verdict=false_positive
    at confidence >= auto_ack_fp_threshold will automatically acknowledge
    that alert in Security Onion.

    Off by default — this is a write action taken without analyst review.
    Enable only after validating the model's FP precision on your alert set.
    """

    auto_ack_fp_threshold: float = 0.7
    """Minimum confidence required for automatic FP acknowledgement.

    Must be in [0.0, 1.0]. Recommended: 0.7 or higher. At 0.7, the model
    is confident in the FP verdict; at 0.9+ it is very confident.
    """

    @field_validator("auto_ack_fp_threshold", mode="before")
    @classmethod
    def _clamp_auto_ack_threshold(cls, v: Any) -> Any:
        """Clamp auto_ack_fp_threshold to [0.0, 1.0]."""
        try:
            f = float(v)
        except (TypeError, ValueError) as exc:
            raise ValueError("auto_ack_fp_threshold must be a number in [0.0, 1.0]") from exc
        if f < 0.0 or f > 1.0:
            raise ValueError(f"auto_ack_fp_threshold must be in [0.0, 1.0], got {f}")
        return f

    auto_triage_min_severity: str = "high"
    """Minimum severity included in a ⚡ auto-triage sweep — this level and
    above. One of: critical, high, medium, low.

    Example: "high" triages critical + high; "medium" adds medium too.
    """

    _VALID_SEVERITIES: frozenset[str] = frozenset({"critical", "high", "medium", "low"})

    @field_validator("auto_triage_min_severity", mode="before")
    @classmethod
    def _validate_auto_triage_min_severity(cls, v: Any) -> Any:
        """Lowercase and validate auto_triage_min_severity."""
        if not isinstance(v, str):
            raise ValueError(f"auto_triage_min_severity must be a string, got {type(v).__name__}")
        lowered = v.strip().lower()
        if lowered not in {"critical", "high", "medium", "low"}:
            raise ValueError(
                f"auto_triage_min_severity must be one of: critical, high, medium, low; got {v!r}"
            )
        return lowered

    # --- Eval harness (cloud oracle via LiteLLM) -----------------------
    # The oracle path runs through LiteLLM (which forwards to an OAuth
    # proxy that holds the cloud credential). This reuses
    # `litellm_base_url` / `litellm_api_key` / `litellm_verify_ssl` —
    # only the model alias and max_tokens are eval-specific.
    claude_oracle_model: str = "claude-opus-4-7"
    claude_oracle_max_tokens: int = 8192

    # ---- validators ---------------------------------------------------

    @field_validator("es_hosts", "internal_cidrs", "blocklist_sources", mode="before")
    @classmethod
    def _split_csv(cls, v: Any) -> Any:
        """Accept both JSON-style and comma-separated env values for list fields."""
        if isinstance(v, str):
            v = v.strip()
            if not v:
                return []
            if v.startswith("["):
                return v  # let pydantic parse as JSON
            return [item.strip() for item in v.split(",") if item.strip()]
        return v

    @field_validator(
        "so_ca_bundle",
        "so_client_id",
        "so_client_secret",
        "es_username",
        "es_password",
        "litellm_api_key",
        "misp_url",
        "misp_api_key",
        "misp_ca_bundle",
        "bootstrap_admin_password",
        "config_secret_key",
        "so_ssh_key",
        mode="before",
    )
    @classmethod
    def _blank_optional_to_none(cls, v: Any) -> Any:
        """Treat an empty/whitespace env value as unset.

        ``.env.example`` ships optional integrations as bare keys (e.g.
        ``MISP_URL=``), and a verbatim copy would otherwise fail URL/path
        validation or wrongly trip an ``is not None`` feature gate (Connect API
        OAuth). For these optional fields an empty string always means "unset".
        """
        if isinstance(v, str) and not v.strip():
            return None
        return v

    @model_validator(mode="after")
    def _require_ssh_host_when_pcap(self) -> Settings:
        """Fail fast if PCAP retrieval is enabled without a sensor SSH host.

        ``so_ssh_host`` defaults to empty (we ship no environment-specific IP);
        enabling PCAP without pointing it at a sensor would otherwise surface as
        confusing per-tool SSH errors at investigation time.
        """
        if self.pcap_enabled and not self.so_ssh_host.strip():
            raise ValueError(
                "PCAP_ENABLED is true but SO_SSH_HOST is empty — set SO_SSH_HOST to "
                "the Security Onion sensor host (or set PCAP_ENABLED=false)."
            )
        return self

    # ---- derived ------------------------------------------------------

    @property
    def use_connect_api(self) -> bool:
        """True iff Connect API OAuth client credentials are configured."""
        return self.so_client_id is not None and self.so_client_secret is not None

    def network_is_internal(self, ip: str) -> bool:
        """True iff ``ip`` belongs to one of the configured internal CIDRs."""
        try:
            addr = ip_address(ip)
        except ValueError:
            return False
        for net in self.internal_cidrs:
            if isinstance(addr, IPv4Address) and isinstance(net, IPv4Network) and addr in net:
                return True
            if isinstance(addr, IPv6Address) and isinstance(net, IPv6Network) and addr in net:
                return True
        return False


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached singleton accessor for FastAPI dependency injection."""
    return Settings()  # type: ignore[call-arg]
