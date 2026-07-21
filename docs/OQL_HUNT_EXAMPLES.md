## Hunting worked examples

These are hunt patterns: telemetry first, alerts as corroboration only. The
default move is DATASET SCOPING — name the `event.dataset` you are testing a
hypothesis against instead of taking an unscoped slice (unscoped slices come
back dominated by alert docs, which triage already owns). Query
`event.dataset:suricata.alert` only to corroborate a telemetry finding you
have already measured.

### H1. Top talkers by destination (volume baseline for the window)

```oql
event.dataset:zeek.conn AND network.direction:outbound
| groupby destination.ip
| sortby count desc
| head 20
```

### H2. Rare destinations — novelty candidates (invert the sort)

Destinations contacted only once or twice in the window are the novelty tail
worth enriching; pair with `t_prevalence` before calling anything a finding:

```oql
event.dataset:zeek.conn AND network.direction:outbound
| groupby destination.ip
| sortby count asc
| head 20
```

### H3. Long-lived connections (tunnels, C2 channels, forgotten sessions)

```oql
event.dataset:zeek.conn AND zeek.conn.duration:[3600 TO *]
| sortby @timestamp desc
| head 25
```

### H4. Host-first pivot — what telemetry does one host have?

Before theorizing about a host, see which datasets it appears in, then narrow:

```oql
host.name:workstation-01 AND event.module:zeek
| groupby event.dataset
| sortby count desc
```

### H5. Busiest DNS names (tunnel / DGA candidates surface at both extremes)

```oql
event.dataset:zeek.dns
| groupby zeek.dns.query
| sortby count desc
| head 20
```

### H6. NXDOMAIN churn per host (DGA beacon tell)

```oql
event.dataset:zeek.dns AND zeek.dns.rcode_name:NXDOMAIN
| groupby host.name
| sortby count desc
| head 10
```

### H7. Cadence check for one suspect pair (eyeball the interval)

Pull the raw conn records time-ordered and measure the spacing yourself — the
MEASURED periodicity is the finding, not any alert title:

```oql
event.dataset:zeek.conn AND source.ip:10.0.0.5 AND destination.ip:203.0.113.7
| sortby @timestamp asc
| head 50
```

### H8. Corroborate a measured finding against the alert stream (LAST, not first)

Once H1-H7 produced a concrete suspect, check whether any detector also saw it:

```oql
event.dataset:suricata.alert AND destination.ip:203.0.113.7
| groupby rule.name
| sortby count desc
```
