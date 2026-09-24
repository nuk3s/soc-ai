# What the soc-ai agent can do

This page states the complete capability of the triage agent. It names the tools the
agent can call, the enrichments that run on every alert before the agent runs, and the
guardrails. SO means Security Onion.

> **Trust boundary:** every read tool is read-only. A write tool changes Security Onion
> state. A write tool runs only if a person executes it from the report's recommended
> actions in the UI. The actions API is the single write path. The agent recommends a
> write. The agent never executes a write on its own.
>
> The third class is the proposal tool. A proposal tool changes nothing. It puts a control
> on the screen for you to press. See `docs/SAFETY_MODEL.md`.

## Read tools

A read tool runs without human approval.

| Tool | What it does | Backing system |
|------|--------------|----------------|
| `query_events` | Run a validated OQL query against the SO events index. The fields are whitelisted. Pipes and aggregations are supported. This is the general-purpose pivot. | Elasticsearch events index |
| `query_zeek_logs` | Pivot into the Zeek connection logs by `network.community_id`. The result shows the flow duration, the bytes and the conn state. | Elasticsearch (Zeek datasets) |
| `run_analytic` | Run one catalog analytic over a window. The result lists the entities that matched and the document ids the agent can cite. Hunt role only. | Elasticsearch events index |
| `query_cases` | Search the existing SOC cases with a free-text query. Use it to find out if someone saw or escalated this before. | SO cases index |
| `query_detections` | Search the SOC detection rules with a free-text query. The result shows what a rule looks for. | SO detections index |
| `get_rule_content` / `t_get_rule_content` | Fetch the full text of a detection rule by SID, by `publicId` or by exact title. The text states what the signature matches: content strings, ports, dsize and PCRE. A verdict then rests on the rule body. | SO detections index |
| `decode_payload` / `t_decode_payload` | Decode the payload bytes that are already in the evidence. The input is a Suricata base64 `payload`, hex, or `payload_printable` text. The output is printable strings, embedded domains, URLs and IPs, Shannon entropy, and DNS, HTTP and TLS protocol hints. The decode runs locally, and there is no egress. The tool works after the PCAP ring rotates. | In-process (dpkt decode helpers) |
| `get_playbooks` | Pull the response playbooks. You can scope the result to one alert. | SO playbooks index |
| `lookup_runbook` | Search the runbooks that the operator wrote. A runbook records a procedure and the normal behaviour of this network, so a verdict can cite the guidance of your own organization. The default ranking is local BM25 with a rule-link boost, a tag boost and a keyword boost, in that order of weight. `RAG_EMBED_MODEL` adds an optional semantic tier through your gateway. There is no external index, and nothing leaves your network. | Local store (`soc_ai/store/runbooks`) |
| `enrich_ip` | Enrich an IP address locally. The result gives the vendored blocklist hits, the MaxMind GeoIP and ASN data, a cloud-prefix tag, and an internal or external classification from `INTERNAL_CIDRS`. MISP is optional. An internal IP address skips the external-only lookups. | Vendored blocklists / MaxMind / MISP |
| `enrich_domain` | Enrich a domain with a local blocklist lookup. MISP is optional. | Vendored blocklists / MISP |
| `enrich_hash` | Enrich a file hash with a local blocklist lookup. MISP is optional. | Vendored blocklists / MISP |
| `get_event_raw` / `t_get_event_raw` | Fetch the full raw JSON of one event by id. Use it if the summarized context is not enough. | Elasticsearch events index |
| `t_describe_dataset` / `t_field_values` | Discover the telemetry on demand. One tool describes the shape of a dataset. The other lists the observed values of a field. The agent learns what *this* grid holds, and it does not assume a fixed schema. | Elasticsearch (terms aggregations) |
| `t_host_summary` | Summarize the recent activity of a host on the internal side of a flow. The summary names the datasets seen, the top peers and the notable events. | Elasticsearch |
| `t_origin_chain` | Who controlled this host? The tool lists the inbound remote-access sessions over SSH, RDP, WinRM and SMB to an internal host in the window before the activity. The list is time-ordered, and it flags the closest preceding session as the likely driver. Call this tool before you attribute hostile behaviour to an internal host. A host with an inbound session is a waypoint, so attribute the behaviour upstream. An empty result is also decisive, because the host acted on its own. | Elasticsearch |
| `t_host_dossier` | What is this host, and is this normal for it? The dossier is the durable asset record that the network sweep keeps for an internal IP address. It holds the hostname, the OS, the inferred role, the services the host offers, the behavioural baseline, the operator-set criticality and the site policy. The inferred role is hypervisor, domain controller, security appliance, server, workstation, network device or IoT. Every field carries its provenance, its evidence and the date of its last confirmation, and an operator value outranks an inferred value. `t_host_summary` returns a fresh 24 h snapshot, and the dossier is the stored record that the sweep builds over a much wider window. A field with no value states why: `no_signal`, `low_confidence` or `stale`. A missing dossier means the sweep has no record of the address, and it is not evidence that the address is benign. | Local store (built from Elasticsearch by the dossier sweep) |
| `t_prevalence` / `t_rule_prevalence` | Measure how common one indicator or one rule is across the grid and the window. A rare indicator and a noisy indicator lead to different false-positive calls. Both tools separate a spread-out baseline from a single burst, and neither averages one into the other. | Elasticsearch (aggregations) |
| `t_suggest_rule_tuning` | Suggest a tuning for a noisy detection. The analyst applies the tuning in Detection Tuning. The agent never changes a rule. | Local store + Elasticsearch |
| `t_shodan_internetdb` / `t_shodan_host` / `t_greynoise` / `t_cve_lookup` | Look up the external reputation of one indicator. The sources are Shodan InternetDB, the Shodan host API, GreyNoise and the CIRCL CVE DB. Shodan InternetDB is free, and the Shodan host API needs a paid key. These tools send traffic out of the network, and the hunt and chat agents use them. Only the indicator leaves the network, and an alert payload never does. See `docs/SAFETY_MODEL.md` → external-intel egress. | Public Shodan / GreyNoise / CIRCL APIs |
| `get_pcap` / `t_get_pcap` | Fetch and decode the raw packets of a bidirectional flow. The result gives the five-tuples, the SNI, the DNS qnames, the HTTP hosts and the inter-arrival beacon statistics. The tool connects over SSH to the Suricata pcap-log ring on the SO sensor and runs a BPF-filtered tcpdump. This costs more than an Elasticsearch query. Use it only if packet or protocol confirmation is the deciding evidence, such as a C2 beacon, exfiltration, kerberoasting, or an ET MALWARE or ET EXPLOIT rule. The tool is disabled by default with `PCAP_ENABLED=false`, and it needs the sensor SSH key. | SSH + Suricata `/nsm/suripcap` |
| `web_search` / `t_web_search` | Search a self-hosted SearXNG instance to research an external indicator: domain reputation, the identity of a host or a service, and known-abuse reports. A verdict then rests on outside evidence. The tool is privacy-guarded. The query reaches public engines through SearXNG, so it must hold external indicators only, and the tool refuses a query that names an internal IP address. The tool is disabled by default with `WEB_SEARCH_ENABLED=false`, and it needs `SEARXNG_URL` and the SearXNG JSON API. Configure it in the admin config console. | SearXNG |
| `crawl_page` / `t_crawl_page` | Read the full content of an external web page through a self-hosted crawl4ai instance. Use it after `web_search` to read a promising reputation, abuse or threat-intelligence page in full. The tool returns the readable markdown of the page and its title. The tool has a server-side request forgery guard. It fetches server-side, so it refuses an internal IP address, an internal host and localhost. The tool is disabled by default with `CRAWL4AI_ENABLED=false`, and it needs `CRAWL4AI_URL`. Configure it in the admin config console. | crawl4ai |
| `beacon_profile` / `t_beacon_profile` | Sweep `zeek.conn` for beacon cadence. The tool measures the inter-arrival coefficient of variation for each source-to-destination pair, so a hunt reports a *measured* cadence. The tool is hunt-only from 1.3 slice 2, and triage has no alert-anchored equivalent. | Elasticsearch (aggregations) |
| `dns_entropy_scan` / `t_dns_entropy_scan` | Sweep `zeek.dns` for DNS entropy. The tool groups the qnames by parent domain. It flags DGA and tunnel candidates by the mean Shannon entropy of the subdomain labels and by the query volume. The tool is hunt-only from 1.3 slice 2. | Elasticsearch (aggregations) |
| `dcerpc_histogram` / `t_dcerpc_histogram` | Build an operation histogram over `zeek.dce_rpc`. The tool flags the dangerous operations: the Zerologon-style `NetrServerAuthenticate*`, the DCSync `DRSGetNCChanges` and `DsGetNCChanges`, and remote service creation. It also flags an operation that is rare against a busy baseline. The tool is hunt-only from 1.3 slice 2. | Elasticsearch (aggregations) |
| `first_seen` / `t_first_seen` | Sweep for novelty. The tool compares the external destinations of a recent window against a trailing baseline window. The baseline window ends where the recent window begins. The tool reports every destination with no earlier sighting in the baseline. The tool is hunt-only from 1.3 slice 2. | Elasticsearch (aggregations) |

> **Not a callable tool:** `get_alert_context` is not registered for the agent to call. It
> fans out across the 5 typed pivots: the community_id flow, the host, the user, the
> process and the file. It runs in the prefetch stage, and it runs the same way every
> time. The prefetch embeds its result in the agent's prompt. The agent never pulls
> the alert picture itself, and the agent cannot skip it. See the prefetch enrichments
> below.

## Proposal tools

A proposal tool is available in chat only. It is neither a read tool nor a write tool. It
changes nothing anywhere. It puts a control in front of you. The agent has already read
the evidence, so the proposal arrives filled in. You still press the button.

Each tool appears only on the screen it belongs to, so the model cannot select the wrong
one. The investigation chat can propose a verdict, and it cannot propose a hunt. The
Dashboard assistant can propose a hunt, and it cannot propose a verdict.

| Tool | Where | What happens |
|------|-------|--------------|
| `propose_verdict` | Investigation chat | The agent proposes `true_positive` or `false_positive` with a confidence, a rationale and citations. The stored verdict does not change. An Apply control appears, and it appears only if evidence backs the proposal. |
| `propose_hunt` | Dashboard assistant | Some questions need a sweep across many hosts or a long window. The agent writes the hunt objective from the evidence it has read, and it states what the sweep settles. Nothing starts. A Start hunt control appears, and you confirm it. |

## Write tools

The analyst executes a write tool from the report in the UI.

| Tool | What it does |
|------|--------------|
| `ack_alert` | Acknowledge a SOC alert. The comment is optional. |
| `escalate_to_case` | Create a SOC case from an alert. The title and the description are required. |
| `add_case_comment` | Add a comment to an existing SOC case. |

## Enrichments on every alert

These enrichments run before the agent runs. They run locally in the prefetch stage, with
no LLM and no runtime egress. The prefetch gives the results to the agent as part of
the alert context.

- **Blocklist match:** the vendored threat feeds are URLhaus, ThreatFox, Feodo Tracker
  and the Tor exit nodes. The internal seed list is optional. The match flags the source
  and destination IP addresses, the domains and the hashes.
- **GeoIP and ASN:** MaxMind returns the country, the ASN and the organization of an
  external IP address.
- **Cloud-prefix tag:** the tag marks an IP address that belongs to a known cloud
  provider.
- **Internal-CIDR classification:** `INTERNAL_CIDRS` labels each endpoint as internal or
  external.
- **MISP IOC match:** if you configure a MISP instance with `MISP_URL`, soc-ai checks the
  indicators against it.

The UI shows these enrichments on the alert context and on the investigation timeline, so
an analyst can see which enrichments fired.

## Known gaps

The agent cannot do these things today. The list follows the roadmap order.

- **PCAP retrieval is disabled by default.** The `get_pcap` and `t_get_pcap` tool is
  wired. It needs `PCAP_ENABLED=true` and a provisioned SSH key in `SO_SSH_KEY`. If the
  tool is disabled, it returns an error dict that says so, and it performs no network
  I/O. If the tool is enabled, the agent fetches and decodes the Suricata pcap-log ring
  buffer for a bidirectional flow. The result gives the SNI, the DNS names, the HTTP
  hosts, the inter-arrival timing and the five-tuple statistics.
- **No active host or network actions.** The three SO write tools are the limit. The
  agent cannot isolate a host, block traffic or change a firewall.
- A read tool runs against the indices that the deployment's index-pattern settings name.
  The agent cannot see data outside that pattern.
