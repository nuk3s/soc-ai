# OQL primer for the model

> soc-ai loads this file **verbatim** into the agent's system prompt at initialization.
> Keep the file precise. Keep it self-contained. Give many examples.

OQL is the query language of Security Onion. A query is a Lucene-style boolean filter
expression. One or more pipe stages can follow the expression.

```
<filter-expression>  [ | <pipe-stage> ]*
```

soc-ai parses OQL with a strict grammar. It validates every field name against a
whitelist. The whitelist comes from the ECS, SO, Zeek and Suricata field references.
soc-ai then translates the query to Elasticsearch DSL before execution. **Raw OQL never
reaches Elasticsearch.**

soc-ai rejects a query with an unknown field, with an unsafe operator, or with a result
size above the caller's `max_results`. The error explains the cause, so you can correct
the query in the next turn.

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

- **bare** values are `tcp`, `203.0.113.50`, `2026-05-07`, `0` and `8080`. A bare value
  holds no spaces.
- **quoted** values look like `"ET MALWARE Suspicious User-Agent"`. Quote a value if it
  holds spaces or special characters.
- **wildcard** values look like `et?probe` and `PSEXESVC*`. `*` matches any sequence.
  `?` matches a single character. **A LEADING wildcard is REJECTED as too expensive.
  `*foo` and `*foo*` are leading wildcards. Anchor the prefix and write `foo*`.** There
  is no substring match. If you need one, pick a more specific field or an anchored
  prefix.
- **ranges** look like `[1 TO 100]` and `[now-7d TO now]`. `[* TO 1000]` is open-low.
  `[1024 TO *]` is open-high.

### Two rejections to avoid

- **Parentheses group whole `field:value` expressions, NOT values.**
  `source.ip:(203.0.113.10 OR 203.0.113.20)` is INVALID and returns an LPAR parse error.
  Write `(source.ip:203.0.113.10 OR source.ip:203.0.113.20)`. A range or two separate
  queries also work.
- **Never assume a dataset is empty from a different dataset.** To check a protocol,
  query ITS dataset: `event.dataset:zeek.ssh`, `event.dataset:zeek.kerberos` or
  `event.dataset:zeek.smb_files`. An empty `zeek.conn` slice says nothing about SSH.

## Pipe stages

| Stage              | Purpose                              | Example                                        |
| ------------------ | ------------------------------------ | ---------------------------------------------- |
| `groupby F[, F2…]` | Bucket aggregation by one or more fields. It returns aggregations, and it returns no documents. | `* \| groupby host.name`           |
| `sortby F [asc\|desc]` | Sort the hits by `F`. The default is `asc`. Use `sortby count desc` after a `groupby` to sort the buckets by document count. | `… \| sortby @timestamp desc`         |
| `head N` / `limit N`   | Return at most `N` hits. After a `groupby` it returns the top `N` buckets. The caller's `max_results` caps the number. | `… \| head 10`                  |
| `count`                | Return only the total hit count. It returns no documents.                                       | `event.module:zeek \| count`        |

A pipe stage may not be repeated. The written order of the stages does not change the
evaluation. `groupby` always applies before `sortby` and `head`.

## Field naming

soc-ai accepts ECS-style dotted field names. The common namespaces are:

- **Time**: `@timestamp`
- **Event metadata**: `event.module`, `event.kind`, `event.severity`, `event.severity_label`, `event.dataset`
- **Rules / detections**: `rule.name`, `rule.uuid`, `rule.severity`
- **Network 5-tuple**: `source.ip`, `source.port`, `destination.ip`, `destination.port`, `network.transport`
- **Network correlation**: `network.community_id`. **This is the most useful pivot in SO.**
- **Host**: `host.name`, `host.ip`
- **Identity**: `user.name`
- **Process**: `process.entity_id`, `process.name`, `process.command_line`
- **File**: `file.name`, `file.hash.sha256`, `file.hash.md5`
- **Zeek logs**: `zeek.conn.*`, `zeek.dns.query`, `zeek.http.uri`, `zeek.ssl.server_name`, `zeek.files.*`
- **Suricata**: `suricata.eve.alert.*`

If you name a field outside the whitelist, the validator rejects the query. The error
names the bad field. Try a more conventional name from the list above before you guess.

<!-- triage-examples:start -->
## Worked examples

These examples cover the most common patterns in alert triage.

### 1. Find a specific alert by rule name

```oql
rule.name:"ET MALWARE Suspicious User-Agent"
```

### 2. Pivot from an alert to the matching Zeek connection

The `network.community_id` is a hash of the 5-tuple. The value is the same on the alert,
on the conn log and on any associated http, dns or ssl record. **This is the canonical
pivot.**

```oql
network.community_id:"1:abc123def456==" AND event.module:zeek
```

### 3. All events on a host in the last hour

Combine the query with `time_range_minutes=60` from the caller. Use a host name or an IP
address:

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

### 8. Find every event with a specific file hash

```oql
file.hash.sha256:deadbeefcafe0000000000000000000000000000000000000000000000000000
```

### 9. Multi-host beacon pattern

This query returns the top destinations that many hosts contact.

```oql
event.module:zeek AND zeek.conn.duration:[60 TO *]
| groupby destination.ip, host.name
| sortby count desc
| head 20
```

### 10. Total alert volume in the window

This query returns the count only. It returns no documents.

```oql
event.kind:alert | count
```

<!-- triage-examples:end -->
## Lateral-movement & behavioral examples

These examples target the datasets that reveal east-west movement and RITA-style
rollups. **Use them ONLY IF the dataset appears in the auto-discovered inventory.** An
absent dataset means that the grid does not collect that log. That absence is itself a
finding.

### 11. Kerberoasting

These are TGS requests with RC4. The attacker harvests tickets under a weak cipher.

```oql
event.dataset:zeek.kerberos AND zeek.kerberos.request_type:TGS AND zeek.kerberos.cipher:RC4-HMAC
```

### 12. PsExec service creation

This is classic remote-execution lateral movement.

```oql
event.dataset:zeek.smb_files AND zeek.smb_files.name:PSEXESVC*
```

### 13. Successful SSH logins

These logins completed.

```oql
event.dataset:zeek.ssh AND zeek.ssh.auth_success:true
```

### 14. RITA-style behavioral rollups

If the grid ships summary datasets, they pre-compute the beacon scores and the
DNS-tunnel scores. One query then decides the question, with no reconstruction from the
raw conn and dns logs:

```oql
event.dataset:zeek.conn_summary OR event.dataset:zeek.dns_summary
```

### 15. Every host that contacted one attacker indicator

This query measures the cross-host fan-out. Start from an external attacker IP address.
Find the SET of internal hosts that contacted it. The fan-out itself is a finding. The
indicator below is the TEST-NET address `203.0.113.7`:

```oql
destination.ip:203.0.113.7 | groupby host.name | sortby count desc
```

## Common pitfalls (avoid these)

- **Do not quote a bare number or an IP address.** `source.port:"443"` and `source.ip:"203.0.113.1"` work. The unquoted forms behave the same way, and they are clearer.
- **Do not use OR, AND, NOT or TO as a field name.** These words are reserved.
- **Do not mix `head` and `count`.** `count` returns the total. `head` returns documents. Pick one.
- **Do not request more than `max_results` documents** in a `head N`. The validator rejects the query. To scan more, write a `groupby` aggregation.
- **Do not access `_source` directly.** It is forbidden. Use named ECS fields.
- **Do not omit the time bounds of an unbounded query.** The caller always supplies a `time_range_minutes` window. Scope the query by an indicator as well: a host, a rule or an IP address.

## When the validator rejects a query

The error message names the bad fragment. Read the field reference above again. Pick a
known field from the same area. Emit the query again. For example, the validator rejects
`agent.hostname`, and the correct field is `host.name`.
