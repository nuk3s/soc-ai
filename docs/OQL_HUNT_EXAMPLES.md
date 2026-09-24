## Hunting worked examples

These are hunt patterns. Telemetry comes first, and an alert only corroborates it. The
default step is DATASET SCOPING. Name the `event.dataset` that you test a hypothesis
against. An unscoped slice comes back dominated by alert documents, and triage already
owns those. Query `event.dataset:suricata.alert` only to corroborate a telemetry finding
that you have already measured.

### H1. Top talkers by destination

This query is the volume baseline for the window.

```oql
event.dataset:zeek.conn AND network.direction:outbound
| groupby destination.ip
| sortby count desc
| head 20
```

### H2. Rare destinations as novelty candidates

Invert the sort. A destination contacted only once or twice in the window is a novelty
candidate worth enriching. Run `t_prevalence` before you call anything a finding:

```oql
event.dataset:zeek.conn AND network.direction:outbound
| groupby destination.ip
| sortby count asc
| head 20
```

### H3. Long-lived connections

These connections are tunnels, C2 channels and forgotten sessions.

```oql
event.dataset:zeek.conn AND zeek.conn.duration:[3600 TO *]
| sortby @timestamp desc
| head 25
```

### H4. Host-first pivot

See which datasets hold one host before you theorize about that host. Then narrow the
query:

```oql
host.name:workstation-01 AND event.module:zeek
| groupby event.dataset
| sortby count desc
```

### H5. Busiest DNS names

Tunnel and DGA candidates appear at both extremes of this list.

```oql
event.dataset:zeek.dns
| groupby zeek.dns.query
| sortby count desc
| head 20
```

### H6. NXDOMAIN churn per host

This churn is an indicator of a DGA beacon.

```oql
event.dataset:zeek.dns AND zeek.dns.rcode_name:NXDOMAIN
| groupby host.name
| sortby count desc
| head 10
```

### H7. Cadence check for one suspect pair

`t_beacon_profile` runs this cadence measurement across every source-to-destination pair
in the window at once. It measures the inter-arrival coefficient of variation. Call the
tool first. Use the manual query below only if the tool returns an error.

Pull the raw conn records in time order and measure the spacing yourself. The MEASURED
periodicity is the finding:

```oql
event.dataset:zeek.conn AND source.ip:10.0.0.5 AND destination.ip:203.0.113.7
| sortby @timestamp asc
| head 50
```

### H8. Corroborate a measured finding against the alert stream

Run this query last.

After H1 to H7 produce a concrete suspect, check whether a detector also saw it:

```oql
event.dataset:suricata.alert AND destination.ip:203.0.113.7
| groupby rule.name
| sortby count desc
```
