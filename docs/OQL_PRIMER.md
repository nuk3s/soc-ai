# OQL primer (LLM-facing)

> This file is loaded **verbatim** into the soc-ai agent's system prompt at
> initialization. Keep it precise, self-contained, and example-heavy.

OQL is Security Onion's query DSL. A query is a Lucene-style boolean filter
expression, optionally followed by one or more pipe stages.

```
<filter-expression>  [ | <pipe-stage> ]*
```

soc-ai parses OQL with a strict grammar, validates every field name against a
whitelist sourced from the ECS / SO / Zeek / Suricata field references, and
translates the result to Elasticsearch DSL before execution. **Raw OQL never
reaches Elasticsearch.** A query with an unknown field, an unsafe operator, or
a result-size that exceeds the caller's `max_results` is rejected with an
explanatory error so you can self-correct in the next turn.

## Filter grammar

```
filter   ::= or
or       ::= and ("OR" and)*
and      ::= not ("AND" not)*
not      ::= "NOT" atom | atom
atom     ::= "*" | "(" or ")" | term
term     ::= field ":" value
value    ::= bare | quoted | wildcard | range
range    ::= "[" bound "TO" bound "]"
bound    ::= bare | quoted | "*"
```

- **bare** values: `tcp`, `203.0.113.50`, `2026-05-07`, `0`, `8080` — no spaces.
- **quoted** values: `"ET MALWARE Suspicious User-Agent"` — required when the
  value contains spaces or special characters.
- **wildcard** values: `et?probe`, `PSEXESVC*` — `*` matches any sequence, `?` a
  single char. **A LEADING wildcard (`*foo`, `*foo*`) is REJECTED as too expensive
  — anchor the prefix (`foo*`).** There is no substring/"contains" match; if you
  need one, pick a more specific field or an anchored prefix.
- **ranges**: `[1 TO 100]`, `[now-7d TO now]`, `[* TO 1000]` (open-low),
  `[1024 TO *]` (open-high).

### Two rejections that waste a turn — avoid them

- **Parentheses group whole `field:value` expressions, NOT values.**
  `source.ip:(203.0.113.10 OR 203.0.113.20)` is INVALID (LPAR parse error). Write it
  as `(source.ip:203.0.113.10 OR source.ip:203.0.113.20)`, or use a range / two queries.
- **Never assume a dataset is empty from a different dataset.** To check a
  protocol, query ITS dataset: `event.dataset:zeek.ssh`, `event.dataset:zeek.kerberos`,
  `event.dataset:zeek.smb_files`, etc. An empty `zeek.conn` slice says nothing
  about SSH.

## Pipe stages

| Stage              | Purpose                              | Example                                        |
| ------------------ | ------------------------------------ | ---------------------------------------------- |
| `groupby F[, F2…]` | Bucket aggregation by one or more fields. Returns aggregations, not docs. | `* \| groupby host.name`           |
| `sortby F [asc\|desc]` | Sort hits by `F` (default `asc`). Use `sortby count desc` after a `groupby` to sort buckets by document count. | `… \| sortby @timestamp desc`         |
| `head N` / `limit N`   | Return at most `N` hits (or top-`N` buckets after `groupby`). Capped at the caller's `max_results`. | `… \| head 10`                  |
| `count`                | Return only the total hit count (no documents).                                       | `event.module:zeek \| count`        |

A pipe stage may not be repeated. Stage order is expressive: `groupby` always
applies before `sortby` and `head`.

## Field naming

soc-ai accepts ECS-style dotted field names. Common namespaces:

- **Time**: `@timestamp`
- **Event metadata**: `event.module`, `event.kind`, `event.severity`, `event.severity_label`, `event.dataset`
- **Rules / detections**: `rule.name`, `rule.uuid`, `rule.severity`
- **Network 5-tuple**: `source.ip`, `source.port`, `destination.ip`, `destination.port`, `network.transport`
- **Network correlation**: `network.community_id` — **the most useful pivot in SO**
- **Host**: `host.name`, `host.ip`
- **Identity**: `user.name`
- **Process**: `process.entity_id`, `process.name`, `process.command_line`
- **File**: `file.name`, `file.hash.sha256`, `file.hash.md5`
- **Zeek logs**: `zeek.conn.*`, `zeek.dns.query`, `zeek.http.uri`, `zeek.ssl.server_name`, `zeek.files.*`
- **Suricata**: `suricata.eve.alert.*`

If you reference a field outside the whitelist, the validator rejects the query
and tells you which field was bad. Try a more conventional name from the list
above before guessing.

## Worked examples

These cover the patterns you'll need most often during alert triage.

### 1. Find a specific alert by rule name

```oql
rule.name:"ET MALWARE Suspicious User-Agent"
```

### 2. Pivot from an alert to the matching Zeek connection

The `network.community_id` is a hash of the 5-tuple — same value across the
alert, the conn log, and any associated http/dns/ssl records. **This is the
canonical pivot.**

```oql
network.community_id:"1:abc123def456==" AND event.module:zeek
```

### 3. All events on a host in the last hour

Combine with `time_range_minutes=60` from the caller. Use a host name OR an IP:

```oql
host.name:workstation-01
```

```oql
source.ip:203.0.113.50 OR destination.ip:203.0.113.50
```

### 4. Top-10 destination IPs that triggered any alert

```oql
event.kind:alert | groupby destination.ip | sortby count desc | head 10
```

### 5. Suspicious outbound traffic on non-standard ports

```oql
network.direction:outbound AND NOT destination.port:[80 TO 443]
| sortby @timestamp desc
| head 50
```

### 6. Failed DNS lookups for a host

```oql
host.name:workstation-01 AND event.module:zeek AND zeek.dns.rcode_name:NXDOMAIN
| sortby @timestamp desc
```

### 7. Count of alerts grouped by severity in the last day

```oql
event.kind:alert | groupby event.severity_label | sortby count desc
```

### 8. Find all events touching a specific file hash

```oql
file.hash.sha256:deadbeefcafe0000000000000000000000000000000000000000000000000000
```

### 9. Multi-host beaconing pattern (top destinations contacted by many hosts)

```oql
event.module:zeek AND zeek.conn.duration:[60 TO *]
| groupby destination.ip, host.name
| sortby count desc
| head 20
```

### 10. Total alert volume in the window (count only, no docs)

```oql
event.kind:alert | count
```

## Lateral-movement & behavioral examples

These target the datasets that reveal east-west movement and RITA-style rollups.
**Use them ONLY IF the dataset appears in the auto-discovered inventory** — an
absent dataset means the grid does not collect that log, which is itself a finding.

### 11. Kerberoasting (TGS requests with RC4 — weak-cipher ticket harvesting)

```oql
event.dataset:zeek.kerberos AND zeek.kerberos.request_type:TGS AND zeek.kerberos.cipher:RC4-HMAC
```

### 12. PsExec service creation (classic remote-exec lateral movement)

```oql
event.dataset:zeek.smb_files AND zeek.smb_files.name:PSEXESVC*
```

### 13. Completed (successful) SSH logins — the ones that actually landed

```oql
event.dataset:zeek.ssh AND zeek.ssh.auth_success:true
```

### 14. RITA-style behavioral rollups (beacon / DNS-tunnel summaries)

When the grid ships summary datasets, they pre-compute beaconing and DNS-tunnel
scores — a single decisive lens instead of reconstructing from raw conn/dns:

```oql
event.dataset:zeek.conn_summary OR event.dataset:zeek.dns_summary
```

### 15. Every host that contacted one attacker indicator (cross-host fan-out)

Given an external attacker IP, find the SET of internal hosts that touched it —
the fan-out itself is a finding. Use TEST-NET `203.0.113.7` as the indicator:

```oql
destination.ip:203.0.113.7 | groupby host.name | sortby count desc
```

## Common pitfalls (avoid these)

- **Don't quote bare numbers or IPs.** `source.port:"443"` and `source.ip:"203.0.113.1"` work, but the unquoted forms are clearer and behave identically.
- **Don't use OR/AND/NOT/TO as field names.** Those are reserved.
- **Don't mix `head` and `count`.** `count` returns just the total; `head` returns documents. Pick one.
- **Don't request more than `max_results` documents** in a `head N`. The validator will reject it. If you need to scan more, structure as a `groupby` aggregation instead.
- **Don't try to access `_source` directly** — it's forbidden. Use named ECS fields.
- **Don't omit time bounds for unbounded queries** — the caller always supplies a `time_range_minutes` window, but you should still scope by an indicator (host, rule, IP) rather than relying on time alone.

## When the validator rejects a query

The error message names the offending fragment. Re-read the field reference
above, pick a known field from the same conceptual area, and re-emit. Example:
if you tried `agent.hostname` and it was rejected, the right field is
`host.name`.
