# Security Policy

soc-ai is security tooling that runs with privileged access to a Security Onion
grid (Elasticsearch, the SOC API, and — when PCAP is enabled — SSH to a sensor).
A vulnerability here is a vulnerability in the SOC that runs it; I treat
reports accordingly.

## Supported versions

soc-ai 1.0 is the current release; the latest `main` is supported. The latest
minor release receives security fixes.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately via [GitHub Security Advisories](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository (Security → Advisories → Report a vulnerability).

Please include: affected version/commit, a description, reproduction steps, and
the impact. I aim to acknowledge within a few days and to ship a fix or
mitigation as fast as the severity warrants.

## Security model (what to keep in mind)

soc-ai is built around a few hard boundaries — regressions in these are treated
as vulnerabilities:

- **OQL trust boundary** — all analyst/LLM query input is parsed and validated
  against a field whitelist before it touches Elasticsearch.
- **Human approval gate** — every *write* tool (ack/escalate/comment) requires
  explicit human approval; nothing mutates the grid autonomously.
- **Oracle egress sanitization** — anything sent to the cloud second-opinion
  model is field-aware redacted first, behind an independent refuse-gate. The
  Oracle is **opt-in** (`ORACLE_ENABLED=false` by default); nothing leaves your
  network unless you turn it on.

  The redactor automatically tokenises private IPs/MACs, FQDNs on an internal
  suffix, NetBIOS-shaped computer names, every identifier learned from a
  structured host/user field (propagated into free text), and usernames in an
  explicit credential context (`user=jdoe`, `DOMAIN\jdoe`). It then runs an
  **independent** residue sweep over the actual outbound bytes and **refuses to
  send** if anything internal-looking survived.

  What it *cannot* infer without you: an internal FQDN on a public-looking
  suffix (`dc01.ad.acme.com`) or a bare codename (`WIN11-01`, `APPSERVER01`) is
  shape-indistinguishable from the public threat infrastructure the Oracle
  exists to reason about, so it is **not** blanket-redacted. If you enable the
  Oracle, enumerate your internal namespace so these are caught:

  - `ORACLE_INTERNAL_SUFFIXES` — your internal DNS suffixes/domains, each with a
    **leading dot** (e.g. `.lan,.corp,.ad.acme.com`). Any FQDN ending in one is
    redacted. The leading dot is the boundary — `.acme.com` matches
    `dc01.acme.com` but not a public `notacme.com`.
  - `ORACLE_EXTRA_HOSTS` — bare internal hostnames/codenames with no suffix
    (e.g. `WIN11-01,APPSERVER01`).

  With the Oracle enabled and neither configured, the client logs a one-time
  warning at startup of the first adjudication. (Operators who would rather fail
  closed than risk a miss can keep the Oracle disabled — the local analyst model
  never leaves the network.)
- **Secret handling** — secrets are never logged, never rendered in API/UI
  responses, and (config-console secrets) are Fernet-encrypted at rest.

## Deploying safely

See `docs/DEPLOYMENT.md` and `docs/SAFETY_MODEL.md`. In short: keep
`API_AUTH_REQUIRED=true`, scope `CORS_ALLOW_ORIGINS` to your SO host, terminate
TLS (or sit behind a trusted reverse proxy), and bind to loopback/your trusted
LAN — not a public interface.
