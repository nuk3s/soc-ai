# Hunting

soc-ai triages the alerts your grid raises. It also looks for the attacks that raise no alert.
This guide covers that second half. The analytics run over the grid and write hits. Leads form
from the hits. Hunts answer the leads, and investigations end in a verdict.

![How hunting flows: analytic, hit, lead, hunt, investigation](img/hunting-flow.svg)

## The five nouns

soc-ai uses one word for one thing. These five carry the whole pipeline.

- **Analytic:** one detection logic. A shipped analytic is a YAML file in the repository. A local
  analytic is one that you write in the console. Both use one schema.
- **Hit:** one thing one analytic found about one entity, with the documents behind it. A hit is
  stored as an observation. The lead page and the host page call it an observation.
- **Lead:** the observations on one entity that are worth one decision.
- **Hunt:** one agent run with an objective. An analyst, a schedule or a lead starts it. A hunt
  ends in findings and a narrative. It states no verdict.
- **Investigation:** one agent run that ends in a verdict. Its subject is one alert, or one hunt
  with all of its findings.

Two more words appear on screen. An **entity** is a host, a user or an address. A **type** is the
class of an observation or a hunt. The database column is still named `kind`.

## Lead formation

Every source writes into one observations table. Each observation carries a weight, and the weight
decays with a 48 h half-life. The decay starts at the event time. A profile departure and a catalog
hit record the time of the newest document they cite. An alert and a hunt finding record no
document time, so they decay from the time soc-ai wrote them. The lead page shows the event time
and keeps the record time in the hover text.

| Source | Type | Birth weight |
|---|---|---|
| A profile departure | `novel_destination`, `off_hours` and the other profile types | 0.30 to 0.50 |
| A profile novelty that fewer than 3 hosts know | the novelty type | 0.6 |
| One new member on 3 or more hosts in one sweep | `scope_count` | 0.4 |
| A new member that the peers in the role do not know | `rare_for_peers` | 0.45 |
| A host far from its learned peer group, from the estate model, always in shadow | `estate_outlier` | 0.3 |
| A catalog hit | `catalog_match` | 0.7 |
| A catalog hit from an analytic with no benign baseline | `prior_no_baseline` | 1.0 |
| A triaged alert, true positive | `alert` | 1.0 |
| A triaged alert, needs more info | `alert` | 0.5 |
| A promoted hunt finding | `hunt_finding` | 0.7 |
| A learned detector hit: one plane of a machine fell silent | `telemetry_silence` | 0.45 |
| A learned detector hit: a logon chain | `logon_chain` | 0.7 |

A false-positive verdict records nothing. A verdict changed to false positive removes the
observation it wrote.

A repeat sighting adds one occurrence to an observation only if the sweep cites a document the
observation has not cited before. A sweep that reads the same documents again moves nothing. The
observation row states two counts apart. The first is the documents in the window, as in "6
documents in the last 24 h". The second is the sweeps that saw a new document, as in "seen on 3
sweeps, first seen 3d ago".

A lead forms in one of three ways.

1. The live weight on one entity reaches 0.85 across two or more types. Two different things saw the
   same machine. Each type counts at most 1.7, twice the lead threshold, so one type that repeats
   cannot carry the total alone. The lead page shows the weight of each type against that cap, as
   in "new served port 1.70 of 1.70, saturated".
2. One observation is **finding grade**: a catalog hit from an analytic that declares no benign
   baseline, or a true-positive alert. One such observation forms a lead alone.
3. One type repeats until its uncapped weight reaches 1.5. A 0.7 type reaches that on the fourth
   sighting. The lead is flagged `single_signal`.

A lead spans the entities that one hit names, and it merges through them. An entity that sits on
more than 8 open leads is a hub, such as a domain controller or a resolver. A hub is listed on a
lead. It never pulls two leads together.

A lead that holds one or more shadow observations is a shadow lead. A shadow lead starts nothing by
itself.

## The baseline behind a profile departure

A profile departure compares a host with its own baseline. The baseline holds one vector for each
of these dimensions:

- the served ports and the consumed ports
- the peers and the DNS names
- the processes and the process pairs
- the logon users
- the active hours and the connection rate

The build reads up to 30 days of history for each dimension. The baseline stops 24 hours before
the present, where the recent window of the sweep starts.

### Set dimensions

Seven dimensions are sets of members: ports, addresses, names and accounts. A member counts as
**known** if the baseline saw it on two days or more. The days run from its first sighting to its
last. A member that the baseline saw on one day is new again if it comes back. Before this rule,
one sighting a month ago made a member known permanently. The logon set of the range DC then held
the three accounts that an attack created. An analytic can move the bar with `min_known_days`.

A member first seen inside a confirmed attack is not known either. soc-ai reads every investigation
with a true-positive verdict. The window runs from 24 hours before the investigation to 24 hours
after it finished. It applies to every address and host name the investigation names. A false
positive, a synthetic evaluation run and a pipeline fallback confirm nothing.

A set keeps the 200 members with the most documents. A set at that cap cannot tell a new member
from a member past the cut. A novelty analytic is blind on that host, and its note starts with "set
full".

A **served port** is a port the host receives connections on. A DNS lookup does not count. An
outbound flow does not count. On an endpoint network event, only an accepted connection counts. A
served port also needs two different peers or two different days before it counts, in the baseline
and at novelty alike. A port at 32768 or above needs both. One client that tries one high port once
is not a service.

### Estate prevalence

After each build, soc-ai counts the hosts whose set knows each member. The count reads the stored
profiles, so it costs no search. The prior sweep refreshes it if a build is newer than the count.
A new member on a host is then one of three things:

| Hosts that know the member | Name | Effect |
|---|---|---|
| Fewer than 3 | estate-rare | The observation is born at 0.6, where a plain novelty is born at 0.5 |
| More than 20 % of the profiled hosts, and at least 3 | estate-common | A trait of the estate. No observation. The note counts it |
| Any other count | novelty | The observation is born at 0.5 |

The observation states the count as its statistic, as in "1 of 40 profiled hosts holds this
member". If one new member appears on 3 or more hosts in one sweep, each of those hosts also gets
a `scope_count` observation at 0.4. It states the spread and how many hosts knew the member before.
A spread past the span cap of 8 hosts forms a fleet condition.

### Peer groups

The peer group of a host is the other hosts in its role. The role must be declared, or inferred at
0.9 or more. The refresh after each build writes the role and its confidence on every profile row.
With 5 peers or more, a new member that most peers know is a trait of the role. It forms no
observation, and the note counts it. A host whose role is a guess has no peer group, unless the
estate model is on. With `estate_model_enabled` on, a host with no confident role reads its
learned group as its peer group. The note then names the group, as in "learned group 3". The
learned group serves only from a measured fit that is under 48 hours old. See "The estate model"
below.

The test `rare_for_peers` finds a member that is new to the host and new to its peers. At most
`max_peer_share` of the peers may know it, 0 by default. The test writes a `rare_for_peers`
observation at 0.45. Below `min_peers` peers, 5 by default, it is blind and says so. No shipped
analytic uses the test. A local analytic can use it, and a local analytic starts in shadow:

```yaml
id: local-server-rare-outbound-port
title: A server uses an outbound port no other server uses
evaluator: profile
scope_field: host.name
scope_kind: host
profile:
  dimension: consumed_ports
  test: rare_for_peers
  roles:
    - server
false_positives:
  - A server with a unique duty uses a port its peers never need.
```

### The connection rate

The build keeps the hourly series of flows each host starts. An hour with no document between the
first hour and the last is a zero. The old baseline dropped those hours, so it measured the rate
in active hours only.

The prior sweep reads the expected count for each hour of the week from the series, in local time.
The expected count is the median of the samples of that hour. The dispersion of an hour is the
larger of two numbers. One is the pooled MAD of every sample against its own hour. The other is the
square root of the expected count. A host whose hours never vary still has a dispersion, so a burst of one hour
moves the test. The hours inside a confirmed attack stay out of the series.

The recent read returns every whole hour of the last 24 hours. An hour that held no document is a
zero. An hour crosses the bar if both of these hold:

- The count sits 3 dispersions or more from the expected count of its hour.
- The count is 3 times the expected count or more, or a third of it or less for a drop.

A departure is a run of `min_hours` hours in a row that cross the bar, 2 by default. One hour that
sits twice as far out departs alone. An hour with an expected count of zero and a pooled MAD of zero
is unmeasurable. It is never a departure. A rate baseline built before the hourly series existed is
blind until the next build. The sweep states that reason beside the blind count. A build of a
release that changes the stored shape runs at once. See "The profile shape" below.

The observation names the hour of the week, the count, the expected count and how many hours the
departure lasted. Its statistic is the residual z of the furthest hour.

### The evidence on an observation

Every observation records the event time, the statistic, its value and the baseline value it
departed from. It also records up to 10 document ids and an OQL query that shows the departure
again. The lead page shows the statistic and the query under each observation. **Run this query** opens a new hunt with
the query in the objective. The host page shows the statistic on each row. The hunt a lead starts
reads each statistic and each query first, so it reads the departure and does not search for it
again.

### Coverage

Each dimension of each host carries a coverage state, and the host page shows it as a chip.
**measured** is a real baseline, and an empty one means the host does none of this. **learning**
has under 7 days of history, and nothing is scored against it yet. **blind** means no plane on this
grid can answer the dimension for this host. A dimension whose telemetry plane the grid does not
carry reads blind on every host. **behind proxy** means the external destinations
of the host all resolve to a proxy, and the proxy carries the dimension. **unmeasurable** means a
plane carries the field, but the grid refused the query that measures it. soc-ai scores a departure
against a measured dimension only.

The builder reads the active hours and the connection rate with one query over the whole estate,
split into partitions. If Elasticsearch refuses the query for too many buckets, the builder doubles
the partitions and tries again, up to 32 partitions. If the grid still refuses, the builder records
both dimensions as unmeasurable, with the reason that the grid gave. The host page shows the reason on the row,
as "not measured: <reason>", and the Analytics coverage line reads "baseline unmeasurable:
<reason>".

The profile sweep owns the age of the baseline. At each wake it reads when the baseline was last
built. The sweep rebuilds a baseline older than the dossier refresh interval before it scores
anything. The dossier schedule setting does not change this. The age has a floor of twice the
sweep interval, so the defaults rebuild after 24 h. A dossier refresh also rebuilds the baseline on
every run. The Analytics coverage line reads "baseline N h old". It adds "stale" if a rebuild was
due and did not happen. The sweep then scores against the baseline it has.

### The blind reason

The profile sweep states why an analytic is blind. The evaluator writes a reason on each blind
entity. The sweep carries the reason of the most blind entities. The reason opens with two counts:
the entities that share it and all the blind entities. An example is "35 of 56 blind hosts: the
role of this host is not known well enough. The confidence is 0.50 and the gate is 0.90." The
counts appear even if every blind entity shares the reason. The reason names the dimension in
words, for example "no connection rate baseline exists for this host yet." These surfaces show
it:

- `soc-ai priors` prints the reason under the row of the analytic.
- The sweep notes hold one note for each analytic that measured no entity.
- The journal gets one line if the reason of an analytic appears or changes.
- The analytic ledger in the Analytics API holds `blind_reason`.
- The coverage of a profile analytic in `GET /api/v1/hunt-catalog` holds `blind_reason`.

The trail column `prior_spec_runs.blind_reason` holds the reason of each run. Migration 0060 adds
it.

### The profile shape

Each profile row records the version of its stored shape, in `entity_profiles.shape_version`.
Migration 0060 adds the column. The code holds the current version as `PROFILE_SHAPE` in
`soc_ai/dossier/profile.py`. A row with no version holds shape 1. Shape 2 adds the hourly series
of the connection rate.

A release that changes the stored shape bumps `PROFILE_SHAPE`. If no host row holds the shape of
the running release, a profile build is due at once. The age of the rows does not matter.
`soc_ai.dossier.profile_job.shape_due` gives the reason, and the prior sweep loop reads it beside
the age rule. The build reads each host whose rows hold an older shape, whatever their age. The
build notes and the journal state how many hosts it read for that reason.

## Learned detectors

An analytic has one of three evaluators. A `match` analytic is a grid query, and the catalog sweep
runs it. A `profile` analytic compares a host with its stored baseline. A `model` analytic runs a
learned detector. The profile sweep runs the `profile` and the `model` analytics every hour, with
the same time anchor.

A learned detector learns what is normal from the estate's own history. It calls no model and it
needs no label. It is pure Python. A `model` analytic names its detector and the parameters of the
detector:

```yaml
evaluator: model
model:
  detector: logon_chain
  params:
    chain_minutes: 15
```

A hit of a detector is an observation with source `model`. It carries the event time, the
statistic, its value, the baseline value, the document ids, an OQL query and a reason. The reason
is one sentence that names the features of the hit and their values. The Analytics tab shows a
`model` analytic as it shows a `profile` analytic. Its hits appear in the hits block with their
receipts.

### The false-all-clear rule

A detector never states an all-clear. It records one state for each entity it reads:

| State | Meaning |
|---|---|
| measured | The detector scored the entity against what it learned. |
| learning | The entity has too little history to score. |
| blind | The detector could not read the plane it needs. |
| unmeasurable | The detector cannot score this entity at all. |
| stale | What the detector learned is too old. |
| drifted | The features of the entity moved past what the detector learned. |
| held | The detector found a hit and held it, because the condition is on most of the grid. |

The sweep notes count each state for each `model` analytic, and `soc-ai priors` prints them. The
coverage line has four columns. A `held` entity counts as measured there. An `unmeasurable`,
`stale` or `drifted` entity counts as blind. The row of each analytic in `soc-ai priors` uses the
same four columns. The journal, the trail and the analytic ledger count the same way. Only the
per-state note names the `unmeasurable`, `stale`, `drifted` and `held` counts.

Every hit cites at least one document. soc-ai drops a hit with no document, counts it, and states
the count in the sweep notes. The lead hunt skips a lead with no cited document.

A learned detector ships in shadow. Its spec declares `ships_as: shadow`, a fire budget and a
precision floor. Its observations are shadow observations until an analyst approves the analytic to
live. The self-healing hold moves a live detector back to shadow if it passes its fire budget or
falls under its precision floor. See "Automatic status changes".

### Cross-plane silence

`model-cross-plane-silence` finds a machine where one telemetry plane stopped while another plane
of the same machine kept going. An intruder who stops an endpoint agent leaves the network sensor
running.

The detector reads each plane of each machine, hour by hour. The planes are host logs, process
events, endpoint network events, Windows security events, osquery, agent self-logs and the network
flows of the sensor. The host planes are keyed by `host.name`. The flows join the machine through the
`host.ip` values its agent reports, inside the estate. An address that two machines report joins
neither.

Each plane is compared with its own expected count for the same hour of the week. The expected
count comes from the same hours in the 4 earlier weeks, through the same arithmetic as the
connection rate. A hit needs all of these:

- One plane holds a tenth of its expected count or less, for 2 hours in a row.
- The expected count of each of those hours is 5 or more.
- Each of those hours sits 3 dispersions or more under its expected count.
- Another plane of the same machine holds half of its expected count or more in each hour.

A machine whose every plane fell is off, and the detector reports nothing for it. A plane that
always dips at that hour expects nothing then. A machine with one plane is unmeasurable. A plane
with under 7 days of history is learning. One plane silent on more than half of the machines that
ship it, and on 3 machines or more, is a grid condition. The detector holds those hits and states
the condition in a note.

A hit cites the newest document of the silent plane before the silence ends, and the newest
document of the live plane inside the silence. Its statistic is `plane_documents`: the documents
of the silent plane in the silent hours, against the expected count of those hours. Its query
groups the documents of the machine by dataset, over the silence and the hour before it.

This detector is meant to replace `profile-connection-rate-collapsed` on machines that ship two or
more planes. Both run until a shadow week measures them.

### Logon chain

`model-logon-chain` finds a session that lands on host B, followed by the first attempt from B to a
third host C. This is how an intruder moves from one host to the next.

The detector learns the edge set of the estate over 30 days: which address opened an accepted
session on which host. A session is a Windows 4624 of logon type 3 or 10 with a source address, or
an sshd Accepted line in `system.auth`. The outbound edges of a host are the edges whose source is
one of its own addresses.

A hit needs a session on B from another host, then within 15 minutes an attempt from an address of
B to a host C. The attempt is an accepted or a failed logon on C. C is not in the edge set of B.
B did not try C earlier in the read. C is not the host that the session came from. The edge set of
the estate and the history of B must each hold 14 days or more. Until then B is learning. A host
whose address soc-ai does not know is unmeasurable.

A hit cites the session document on B and the attempt document on C. Its statistic is
`chain_minutes`: the minutes between the two documents, against the number of outbound edges B
had. Its query shows the documents of B and the attempts from the addresses of B over that time.

## The estate model

The estate model is tier 3 of the detection design. It fits a model of the whole estate once a
day. The model groups the hosts that act alike, and it scores each host against the estate. It
writes observations in shadow only. It is off by default. Turn on `estate_model_enabled` to run it.

### Dependencies

The model needs scikit-learn and numpy. They come in the optional extra `ml`. The container image
installs the extra. On the systemd path, run `uv sync --extra ml`. With the setting on and the
extra absent, the daily run logs one line, "estate model: unavailable", and does nothing. soc-ai
imports the extra only when the run starts.

| Package | Version on 2026-10-04 |
|---|---|
| scikit-learn | 1.9.1 |
| numpy | 2.5.3 |
| scipy | 1.18.1 |
| joblib | 1.6.0 |
| threadpoolctl | 3.7.0 |
| cloudpickle | 3.1.2 |
| narwhals | 2.26.0 |

The seven packages add about 220 MB of site-packages to the image. The dependency audit in CI and
in the publish script reads them.

### The behaviour vector

The run reads the stored profiles and builds one vector per host. The vector holds these numbers,
in a fixed order:

| Feature | What it counts |
|---|---|
| `<set dimension>.members` | The members in the set, for each of the 7 set dimensions |
| `<set dimension>.per_day` | The documents behind the set, per support day |
| `active_hours.hours` | The hours of the day the host was ever active in |
| `active_hours.night_share` | The share of activity from 00:00 to 06:00 local time |
| `connection_rate.work`, `.off`, `.weekend` | The median connections an hour in each cell |
| `plane.flow`, `plane.dns`, `plane.process`, `plane.logon` | 1 when a dimension of the plane is measured or learning |
| `role.<role>` | 1 when an operator declared the role |

A count or a rate enters the model as `log1p`. An inferred role does not enter the vector. A host
with no measured or learning dimension gets no vector, and the run counts it as blind.

The profile store keys the flow and DNS planes on the address of a host and the process and logon
planes on its `host.name`. The run fits the two key spaces apart. A key space with fewer than 20
hosts forms one group and gets no score.

### Peer groups

The run standardizes each column and groups the vectors with k-means. k runs from 2 to 10. The
silhouette score picks k. A cluster under 5 hosts folds into the nearest larger cluster, because a
group of one host has no peers. The run matches the new groups to the groups of the previous fit,
so a group keeps its id from day to day.

The run writes the group of each host to the store. The record holds the group id, the distance to
the group centroid, the score, the model hash and the fit time. The fit row holds the centroid and the
median of each group.

### The outlier score and its reason

An isolation forest scores each host from 0 to 1. Near 0.5 is ordinary. A host at 0.55 or more is
an outlier. The score does not name a feature, so the score alone never becomes an observation.

The reason comes from the learned group. For each feature, the run divides the distance from the
group median by the spread of the group. This value is the deviation. The spread is 1.4826 times
the median absolute deviation, with a floor of 0.5 standard deviations. The three largest
deviations name the top features. A declared role is never a reason.

An outlier becomes an observation only if all of these hold:

1. Its largest deviation is 3 or more. A host under that has no stated reason.
2. Fewer than 5 other hosts sit within 1 standard deviation of it. A host with that many twins
   shares its behaviour with a subgroup.
3. The grid returns at least one current document of the host from the last 24 hours.

The fit row counts each case: outliers, unexplained, shared, no document and observations.

The observation has the type `estate_outlier` at 0.3, the source `model` and the analytic id
`model-estate-outlier`. It is always shadow. Its statistic is `estate_outlier`. The value is the
score of the host, and the baseline is the median score of its group. It cites the documents and
carries an OQL query that groups the documents of the host by dataset. The summary names the top
three features with the value of the host and the median of its peers:

```
198.51.100.2 departs from learned group 2 of 102 hosts. Its estate outlier score is 0.62. The
group median is 0.48. Logon users: 30. The peer median is 1. Logons a day: 400.0. The peer
median is 9.7. Outbound ports: 6. The peer median is 5.
```

### States

Each fit records one state. The doctor row and the fit row use the same words.

| State | Condition | Effect |
|---|---|---|
| learning | Fewer than 20 hosts have a profile | No fit. The fit row holds the state, the reason and the host count. No model file, no group and no audit record. No observation. No peer source |
| learning | 20 hosts or more have a profile, and the median host has under 7 days of profiles | Groups recorded. No observation. No peer source |
| drifted | Two or more features have a population stability index above 0.25 against the previous fit | Groups recorded. No observation. No peer source |
| held | More hosts qualify than the fire budget: 1 in 100 hosts, with a floor of 10 | Groups recorded. No observation. No peer source |
| measured | None of the above | Observations written. The groups serve as peers |

The run fits again every day. A new fit is a challenger for its first 24 hours. The next fit
promotes it to champion. The run scores once, with the newest fit. The challenger state is a
record only. The run does not score the champion beside it.

### The model file

The fit writes a JSON file to `<data dir>/models/estate/`, with mode 0600. The file holds the
feature names, the scale, the centroids, the drift bins and the forest settings. It holds no
serialized Python object, so a file cannot run code when it loads. The store records the file
name and the sha256 of its bytes. The run also writes the hash to the audit chain, as the event
type `estate_model_fit`.

The run reads the previous file to keep the group ids and to compute the drift index. It reads the
file only if the hash of its bytes is the hash that the store recorded for that name. The run refuses
a file that no fit wrote, a file whose bytes changed, and a file that resolves outside the
directory. It then fits without the previous file and records the refusal on the fit row. The
last 5 files stay on disk. The store keeps every fit row.

### Schedule and the doctor

A loop wakes every 5 minutes. It fits if the newest fit is 24 hours old. The fit takes the
single-flight slot of the dossier sweep, so it never runs beside a dossier sweep or a profile
rebuild. The fit runs in a worker thread.

The doctor row "estate model" reads "unavailable", "off", "learning", "measured", "drifted" or
"held", with the date of the last fit. A fit older than 48 hours reads "stale". With the setting
off, the row still states the date and the state of the last fit.

`soc-ai estate-model show` prints the newest fit. `soc-ai estate-model run` fits once, now. See
"The command line".

## Lead hunts

With `lead_auto_hunt` on, a loop wakes every 60 s. It starts the hunt for each open lead that has
no hunt, oldest lead first, up to `lead_auto_hunt_concurrency` hunts at a time. The lead then reads
"New · hunt queued".

The loop leaves five leads alone:

- A **dismissed** lead, because you answered it.
- A **reopened** lead, because you reopened it to decide again.
- A **shadow** lead, because nothing in shadow starts a hunt.
- A lead whose observations **cite no documents**, because its hunt would have no evidence to read
  first.
- A lead whose loop hunt **could not run twice**, because a third attempt would end the same way.

The first four carry the chip "left to you" and keep their Hunt button. The fifth reads
"Hunted · Could not run" and offers Hunt again. soc-ai logs the skip once an hour for each lead.

A lead hunt reads the lead's own documents before it queries the grid. Its objective names the
lead's observations and the related leads. It asks the hunt to state, with the evidence, whether
the leads are one campaign. soc-ai writes the objective once, at the start of the hunt. The
objective therefore reads "Related leads at the start of this hunt".

## Hunt outcomes

A lead settles when its hunt finishes. What the hunt found decides where the lead goes.

- The hunt found **no threat**. soc-ai closes the lead with the reason `hunt_clean`. The lead moves
  to the Closed tab and reads "Closed. The hunt found no threat.", with the chip "closed by soc-ai".
  No analyst chose a reason, so the lead quality report counts it apart from your dismissals.
  soc-ai closes the lead only if the hunt read its evidence. A visibility gap finding, a failed
  tool call, a degraded run or a report from the budget synthesizer keeps the lead open. An earlier
  hunt on the same lead with a threat finding keeps it open too. The lead then waits under Needs
  decision. The lead page states the reason: "The hunt could not read all evidence." or "An
  earlier hunt found a threat."
- The hunt found a **threat**, or it reported a **visibility gap**. The lead waits on you under
  Needs decision as "Hunted · Threat findings" or "Hunted · No threat observed · visibility gap".
  Read the hunt, then promote or dismiss.
- The hunt **could not run**: an error, a cancel, an interrupted process, or a query that raised.
  The lead returns to open and keeps the hunt. The loop starts one more hunt. If that one cannot
  run either, the lead waits on you as "Hunted · Could not run" and offers Hunt again.

**Hunt again** starts a second hunt, and the lead then points at it. While the attached hunt
still runs, the button opens that hunt. A lead the hunt closed offers Reopen only. Reopen
it first, then hunt again.

soc-ai signs a hunt closure as soc-ai even if you started the hunt by hand. A lead you dismissed
yourself and then reopened is never closed by a hunt. A clean hunt on it waits on you.

The lead page lists every decision on the lead in order. The decisions are each dismissal, each
reopen, the promotion, the close by a clean hunt and a hold. A reopen clears the current dismissal. The old
dismissal stays in the list.

A closed lead keeps its history. A type that the hunt already cleared can show up again while the
lead's observations are still live. The new observation then joins the closed lead as history. Nothing
forms and nothing re-hunts. A new type reopens the lead in place, and the loop hunts it again.

A lead that an earlier release left in hunting settles at the next start. With `lead_auto_hunt` on,
the loop also settles finished hunts at each wake, before it picks the next leads.

## Hunt promotion

Press **Promote** on a hunted lead, or promote one finding from the hunt page. soc-ai then runs an
investigation whose subject is the hunt.

The run reads the hunt's objective, its narrative, every finding, and every document those findings
cite, up to 40. The promoted finding's documents come first and the rest follow newest first. A lead
hunt also carries the lead's observations and its related leads. soc-ai loads the cited documents as
evidence before the investigation starts. A verdict that cites one of them then resolves against a
document the run holds.

The verdict is `true_positive`, `false_positive` or `needs_more_info`, with a confidence, a
rationale, citations and recommended actions. For a hunt subject the three words mean this:

- **true positive**: the hunt's hypothesis holds as an attack or a compromise.
- **false positive**: the findings have a benign explanation that the evidence supports.
- **needs more info**: the report names the gap that a tool call can close.

Every gate runs: the evidence gate, the citation validation and cap, the confidence floor, the
egress guard, the Oracle escalation and the session gate. Two things do not run. The decision
templates do not. Each template matches an alert rule class, and a hunt has none. The unattended
acknowledge does not either. Security Onion holds no hunt to acknowledge.

The server refuses Promote on a lead with no finished hunt, with HTTP 409 `lead_not_hunted`. Hunt
the lead first. The investigation reads the hunt's findings.

## Related leads

One entity is one lead. A coordinated attack across several machines is several leads, and no
single one of them reads as a campaign. The lead page carries a **Related leads** panel for that
case.

A related lead is open, and it formed in the last 7 days. It also shares one of four things with
the lead you are reading:

- the same analytic on an observation within 24 h
- the same alert rule within 24 h
- the same external address or /24 network named in an observation
- the same ATT&CK technique

IPv4 compares on the /24. Two hosts that talk to neighbouring addresses usually talk to one place.
Each row states the share in one phrase, names the state of the related lead, and links to it. The
lead row on the strip carries a "+N related" chip.

soc-ai computes the list on read and stores nothing. A stored relation goes stale as soon as you
answer either lead. A deployment whose API returns no related leads shows no panel. An empty panel
there would read as an answer nobody gave.

## The Hunts page

The page is the pipeline in order. Each item appears once. Every section header carries one dim
line that says what the section holds. That line ends in a link, **How this flows**. The link opens
the chart above in a drawer. The address `?flow=1` opens the same drawer.

### 1. Needs you

One line at the top. It gives the count, then one link per thing that waits on you: "2 shadow hits
are unread", "2 leads wait on a decision". Each link jumps to the block below with its filter set.
If nothing waits, the strip reads "Nothing needs you" and takes one line. The sidebar badge on
the Hunts item shows the same count, and the bell lists the items.

### 2. Analytic hits

Every hit from the last 7 days, live and shadow, in one list. Under All, the unread shadow hits
come first, newest first. Needs-you counts these hits, so they open the list. The live hits follow,
newest first, and the read shadow hits come last. The filter chips are All, Unread, Live and
Shadow, and the counts behind them are read over the whole window.

The list reads 50 hits at a time. The line under the list states the share, for example "50 of
148 hits". "Show more" reads the next 50 hits.

A live hit carries a solid accent border and a bold title. A shadow hit carries a dashed amber
border and the `shadow` chip. A read shadow hit is dimmer still. A live hit is never lighter than a
shadow hit.

Each card names the analytic, the entity, the document count, when the hit was first seen and how
many times it was seen. Evidence sits under that, and each document opens the document drawer. If
a lead holds the hit, the action is **Open lead**, because you decide on the lead.
A hit that formed no lead offers **Hunt this entity**. A shadow hit adds **Approve analytic**,
**Reject analytic** and **Mark read**.

A shadow hit stays unread until you open its evidence or act on it. A live hit has no read flag.

### 3. Leads

Four tabs, named by what you must do: **Needs decision**, **In progress**, **Closed**, **All**. The
block opens on Needs decision. Closed holds the leads you dismissed or promoted and the leads a
hunt closed.

Every row carries a state pill: `New`, `In progress`, `Hunted · <outcome>`, `Dismissed`,
`Closed. The hunt found no threat.`, `Promoted`. A new lead whose hunt the loop has taken reads
`New · hunt queued`. A lead whose loop hunt could not run twice reads `Hunted · Could not run`. The
pill is the state. The tab is a filter.

| State | Actions |
|---|---|
| New | Hunt now, Dismiss |
| In progress | View hunt |
| Hunted | Read hunt, Promote, Dismiss, Hunt again |
| Dismissed, Closed by the hunt, Promoted | Reopen. A promoted lead also offers Open investigation. |

A dismissal needs a reason: `expected_for_role`, `known_change`, `benign_repeat`, `bad_baseline` or
`other`. Free text is optional. The lead quality report counts the reasons, so pick the reason
that is true.

### 4. Hunts

The list of agent runs, with a Started-by column that reads Manual, Schedule or Lead. The objective
of a lead hunt links to the lead. Scheduled hunts sit under the list. The catalog sweep adds no
entry here, so this list holds agent runs only.

### 5. New hunt

One button at the top right of the Hunts section. It opens the composer in a drawer: the objective
box, the starters, the template control and the Start button. A starter can name the analytics to
run first.

### 6. Analytics tab

The analytic catalog. Each row carries the title, the tier, the status and the analyst actions.
The tier is shipped or local. The status is live, shadow, candidate or retired. An analytic opens a drawer with its
description, its evaluator, its version history, its outcome ledger and its recent observations by
entity.

soc-ai computes the outcome ledger on read, over one window. The ledger holds these numbers:

- the observations that the analytic wrote
- the leads it contributed to
- how many of those leads were hunted, promoted or dismissed under each reason
- the documents it scanned, with the runtime
- the entities it scored, against the entities it could not see

Retirement decisions read the ledger.

#### Drafts from a finding

"Draft an analytic" on a threat finding writes one local analytic. The console shows the draft
and its 30-day dry run. The analyst confirms, and soc-ai stores the analytic as a candidate.

**Generalization.** An analytic describes a behaviour that any host, user or address can show.
The model keeps an exact value only for a stable discriminator, such as an event code, a dataset,
a port or a response code. soc-ai checks each draft for clauses that name the entity of the
finding. A pin is a value test on a host, user, address, domain, URL, path or command line field.
A literal IP address in a clause is a pin. A host of the finding in the title or the id is a pin.
A value from the finding's indicator list is no pin. On a pin, the model rewrites the draft once.
A draft that still pins shows a warning with one line per clause, and the save button reads
"Save anyway". The drawer lists the pins under "Specific to one case". The Analytics tab marks
the row "specific". The dry run also states how many distinct scope entities matched. One host
in 30 days tells the analyst that the analytic still describes one case. The clause language
matches each event and cannot count. A finding about a repeat becomes an analytic for one event.

### 7. Lead quality

A block under the analytics table. It states the lead rule in one sentence. The noise floor rule
stands beside it: "A threshold moves only on a week of data." Then two tables follow.

- **Per ISO week**: leads formed, hunted, with a threat finding, promoted, closed by hunt, and
  dismissed under each reason. A week with no leads is still a row, because a quiet week is a
  measurement.
- **Per set of observation types**: formed, dismissed, closed by hunt, and with a threat finding.

Closed by hunt counts the leads soc-ai closed because the hunt found no threat. The dismissal
columns count your reasons only.

The reason columns come from the data, so a reason nobody used costs no column. A failed read
states the failure. Over a dead endpoint, "no leads" is a false all-clear.

## Role-scoped analytics

A match analytic can name roles. It then applies only to scope hosts that the dossier places in
one of those roles. The gate uses the role and the confidence that the role priors use. An
operator declaration has full confidence.

| Dossier belief about the scope host | Result |
|---|---|
| A named role at confidence 0.9 or above | The analytic fires. |
| Another role at confidence 0.9 or above | No hit. The documents leave the match count. |
| No role, `unknown`, or a confidence below 0.9 | No hit. The sweep reports a coverage gap that names the host. |

The third row is not a clean result. A server with no confident role must not hide a hit. Declare
the role on the host page. The next sweep then decides the host.

Three shipped analytics carry a role gate. Each one replaces a role prior that tested a different
fact from the one its title stated. soc-ai removed the three prior files. The old observations keep
the old id.

| Old prior id | New analytic id | Event read | Roles | The finding quotes |
|---|---|---|---|---|
| `prior-defender-adjudication-on-server` | `identity-defender-detection` | Defender 1116 and 1117 | server, domain_controller | threat, path, action |
| `prior-audit-policy-changed-on-dc` | `identity-4719-audit-policy-change` | 4719 | domain_controller | account, subcategory, change |
| `prior-privileged-group-membership-changed` | `identity-privileged-group-change` | 4728, 4732, 4756 | domain_controller | account, group, member, member SID |

The reasons for the change:

- The Defender prior read new process names. It never read a Defender event. On the development
  range it missed all 10 Defender detections. It fired 73 times on Defender updater files, because
  each definition update has a new file name.
- The audit-policy prior and the group-change prior read new logon accounts on the domain
  controller. Neither read event 4719 or a group change.

The level of a Defender hit follows the Defender severity. Severe is critical. High is high.
Moderate is medium. Low is low. A document with no severity keeps the level critical.

The audit-policy analytic excludes subject accounts that end in `$`. Group policy refresh writes
4719 under the computer account. An intruder who runs as SYSTEM on the domain controller also
writes under the computer account. The analytic does not see that change.

The group-change analytic matches the group by name. The names are Domain Admins, Enterprise
Admins, Schema Admins, Administrators, Account Operators, Backup Operators, Server Operators, Print
Operators, DnsAdmins, Group Policy Creator Owners, Remote Desktop Users and Distributed COM Users.
A renamed group or a translated builtin name needs a tuning filter.

All three declare no benign baseline. One hit forms a lead.

## The shadow week

A new analytic runs in shadow before it counts. Run it in shadow for a week and read what it
produced.

1. **Put the analytic into shadow.** On the Analytics tab, open the analytic and choose **Run in
   shadow**. A shadow analytic runs on the normal sweep. It writes shadow observations. It cannot
   go live by itself.
2. **Dry run the catalog by hand.** `soc-ai spec-sweep --shadow` reports what every analytic would
   have found. It records no hunt, and it does not spend the fire-once budget. An analytic
   therefore still fires on the day you switch it on. Add `--backfill` once, at the time you add an
   analytic. It seeds the state from history and writes no finding for each past occurrence.
3. **Read the hits with their receipts.** Every shadow hit carries the matched documents and the
   fields that matched. A hit from a profile analytic also carries the baseline. Every shadow hit
   carries a 30-day dry run with its fire count and entities. The last receipt is the overlap with
   any live analytic that saw the same documents. A hit with
   incomplete receipts reads "could not run" and names the missing part. It is never shown as a
   hit, and it is never hidden.
4. **Approve or reject.** **Approve analytic** moves it to live and records the receipts as the
   reason. **Reject analytic** leaves it in shadow for you to edit, or you retire it with a reason.
   Every transition records the spec text before and after, who acted, when and why.
5. **Keep the hit you read.** An approval leaves the hit in place. The shadow hit stays with its
   read state. The next sweep records the entity as a live observation, and the card then reads as a
   live hit. A hit recorded in shadow whose analytic is now live carries a dim "recorded in shadow"
   chip.
6. **Turn the loop on last.** Set `hunt_spec_sweeps_enabled` on after the shadow week. The catalog
   then sweeps on a schedule.

Retirement is the one status that hides a hit. A retired analytic keeps its ledger and its reason.

## Automatic status changes

soc-ai changes the status of an analytic in the cases below. A version row records each change.
The actor on the row starts with `system:`. soc-ai never approves an analytic to live and never
retires one. Those two actions stay with the analyst.

### Shadow on first deploy

A shipped analytic can declare `ships_as: shadow` in its file. The default is `ships_as: live`.
Every analytic without the field keeps that behaviour.

On the first catalog load, soc-ai writes a `shadow` status row for each shipped analytic that
declares `ships_as: shadow` and has no status row. The version row names the actor
`system:catalog` and says that the analytic shipped in shadow. The startup, each sweep and the
status route load the catalog this way. Before the row exists, the catalog already reads the
analytic as shadow. A new analytic therefore never runs live on its first deploy.

Approve the analytic to live on the Analytics tab after its shadow week. Once a status row exists,
the row decides. A later release that changes the field to `live` does not move a retired analytic
or an analytic in shadow. A local analytic refuses the field, because it always starts as a
candidate.

### Demotion to shadow

soc-ai has one transition of its own: live to shadow. Only a system actor can make it. The
version row holds the actor, the reason and the evidence. The observations that the analytic wrote
while live stay as they are. The next sweep writes its new observations in shadow.

The Analytics tab marks the row "held by soc-ai", and the chip carries the reason. The Analytics
card on Operate shows the same chip. `GET /hunt-catalog` holds the reason in `held_by_system`. The
drawer states the hold under the description. The version row carries a `soc-ai` chip, the reason
and one evidence line for each breach. Read the evidence. Then select Approve or Reject. Approve
puts the analytic back to live. Reject retires it. The store refuses a system actor that tries to
approve an analytic to live or to retire one.

### Fire budget and precision floor

A spec can declare two limits. Both are off by default.

| Field | What it limits |
|---|---|
| `fire_budget_per_day` | The hits the analytic can write in 24 hours. A hit is an observation that the analytic wrote or refreshed live in the window. |
| `precision_floor` | The lowest share of hunted leads over 30 days that reach a promoted finding or an investigation. The other leads in the share are the leads that a hunt closed clean. |

After each analytic sweep and each profile sweep, soc-ai checks each live analytic that declares a
limit. The check reads the store only. It makes no grid query and no model call. A breach moves the
analytic to shadow through the demotion above. The version row holds the numbers. The bell shows
one entry until an analyst approves or retires the analytic.

The rules of the check:

- An analytic that declares neither field never moves.
- An analytic in shadow never moves.
- A lead that an analyst dismissed counts on neither side of the precision.
- The precision counts only if 5 or more leads are decided.
- The window starts 24 hours or 30 days back. If the latest approval to live is later, the window
  starts at the approval. The hits and the leads that caused a demotion therefore cannot cause a
  second one after an analyst approves the analytic again.
- One window holds one demotion at most.

The setting `analytic_self_heal_enabled` turns the check on and off. It is on by default.

## Settings

| Setting | Default | What it does | Applies |
|---|---|---|---|
| `lead_auto_hunt` | on | A lead that has never had a hunt starts one when it forms. | live |
| `lead_auto_hunt_concurrency` | 2 | How many lead hunts the loop runs at once. The floor is 1. | live |
| `entity_profiles_enabled` | off | Build a behavioural baseline for each host. The profile sweep rebuilds it when it is older than the dossier refresh interval, and a dossier refresh rebuilds it too. The profile sweep reads every host as blind until this is on. Turn it on for the shadow week. | live |
| `profile_estate_rare_hosts` | 3 | Below this many hosts that know a member, a new member is estate-rare. Its observation is born at 0.6. A member must also reach this many hosts to be estate-common. | live |
| `profile_estate_common_share` | 0.2 | Above this share of the profiled hosts, a new member is estate-common. It forms no observation. | live |
| `estate_model_enabled` | off | Fit the estate model once a day. Its observations stay in shadow. A host with no confident role reads its learned group as its peer group. Needs the `ml` extra. | live |
| `hunt_spec_sweeps_enabled` | off | Run every live analytic as a grid query on a schedule. A matching document becomes an observation on the host it names. Observations can form a lead. No model call. Turn this on last, after the shadow week. | live |
| `hunt_spec_sweep_interval_minutes` | 60 | Minutes between analytic sweeps. The floor is 5. | live |
| `hunt_spec_sweep_window_minutes` | 1440 | How far back each analytic sweep reads. Keep it wider than the interval. | live |
| `analytic_self_heal_enabled` | on | Move a live analytic to shadow when it breaches the fire budget or the precision floor in its spec. An analytic with neither field never moves. | live |
| `catalog_hunt_rows` | off | Add an entry to the Hunts list for each analytic hit, as the sweep did before 1.5.0. | live |
| `investigator_emits_report` | on | The investigation loop writes the verdict report itself. | next run |
| `synth_round1_always` | off | Run the first-pass synthesis even when it cannot close the alert. | next run |

Turn `lead_auto_hunt` off to restore the older behaviour, where a lead waits for you to press Hunt.
The count in `lead_auto_hunt_concurrency` covers the hunts the loop started, so a hunt you start by
hand never blocks the loop.

## The command line

Each command reads the local store or the grid. None of them calls a model.

| Command | What it does |
|---|---|
| `soc-ai leads --report` | Print the lead quality table. `--weeks N` sets the window. The default is 4. |
| `soc-ai priors` | Run the role priors against every entity that has a behavioural profile, and print what departed. It also runs the learned detectors and prints their states. Each row states the status of its analytic: shadow, live or retired. The status comes from the effective catalog that the sweep runs. A line names each profile or model analytic that the sweep did not run. `--recent-hours N` sets the window of the priors. The default is 24. |
| `soc-ai priors --record` | Write each departure as an observation, and form leads from what accumulates. Off by default, because a read of the coverage must have no side effect. |
| `soc-ai spec-run [<id>] --since <start>` | Run one analytic, or the whole catalog, and print the candidates as JSON. `--since` is required. It takes ES date math or ISO-8601. Example: `now-7d`. `--until` and `--include-synth` shape the run. |
| `soc-ai spec-sweep` | Sweep the catalog and record what is not already handled. `--since`, `--until`, `--shadow` and `--backfill` shape the run. |
| `soc-ai estate-model show` | Print the newest estate model fit: the time, the state, the hosts, the groups, the outliers, the model file, the hash and the drift index. `--json` prints the fit as JSON. |
| `soc-ai estate-model run` | Fit the estate model once, now. It runs when `estate_model_enabled` is off, and it says so. It refuses in a demo. It cannot take the dossier slot of the server, so run it when no dossier sweep runs. |

`soc-ai leads --report` and the Lead quality block print the same numbers from the same function,
so a terminal and a browser cannot disagree.

## The API

Every route sits under `/api/v1`. The console uses these, and an integrator can too.

| Route | What it answers |
|---|---|
| `GET /hunts/hits` | Every analytic hit from the last `days` days. Under `all`: unread shadow hits, then live hits, then read shadow hits. `filter` takes `all`, `unread`, `live` or `shadow`. `limit` and `offset` page through the order. |
| `GET /hunts/needs-you` | The one number the sidebar badge and the Needs-you strip show: unread shadow hits plus leads that wait on a decision. |
| `GET /leads` | The lead list. `status` takes a stored value, `all`, or one of the tab aliases `new`, `closed`, `needs_decision` and `in_progress`. |
| `GET /leads/quality` | The lead rule, the noise floor rule, and what the rule produced per ISO week and per observation-type pair, with `closed_by_hunt` counted apart from `dismissed`. `weeks` sets the window. |
| `GET /hunts/leads/{id}` | One lead: its observations, its entities, its related leads and whether its investigation still exists. |
| `POST /hunts/leads/{id}/hunt` | Start the lead hunt by hand. While the attached hunt runs, it returns that hunt. After a hunt has finished, it starts a new one. |
| `POST /hunts/leads/{id}/promote` | Promote the lead to an investigation of its hunt. Answers 409 `lead_not_hunted` when no hunt has finished. |
| `POST /hunts/leads/{id}/dismiss` | Dismiss the lead with a reason from the fixed list. |
| `POST /hunts/leads/{id}/reopen` | Reopen a closed lead. The loop does not hunt it again. |
| `POST /hunts/{hunt_id}/findings/{ordinal}/investigate` | Promote one finding of a hunt to an investigation of that hunt. |
| `GET /hunts/observations` | The observations on one entity, from every source, for the host page. |
| `GET /hunts/shadow-hits` | The shadow half on its own, for the bell and the Dashboard card. |
| `POST /hunts/shadow-hits/{obs_id}/read` | Mark one shadow hit read. |
| `GET /analytics` | The catalog, both tiers, with status and tier on each row. `held_by_system` holds the reason of a system demotion while it holds the analytic in shadow. |
| `GET /analytics/{id}` | One analytic with its version history, its outcome ledger and its recent observations. A version row carries `system` for a change soc-ai made, and `evidence` for a system demotion. |
| `POST /analytics/{id}/status` | Move an analytic between candidate, shadow, live and retired, with a reason. |
| `GET /hunt-catalog` | The health of the catalog: the last sweep, the last firing and the 24-hour counts for each analytic. |

`GET /investigations/{id}` carries a `subject` block for a hunt run. The block holds the hunt id,
the objective, the finding ordinals and titles, the lead id, the document ids and the observation
ids. A list row
carries `subjectType`, which reads `alert` or `hunt`.

## Known limits

- There is no campaign object. Related leads name the leads that may share a story. Nothing joins
  them into one record.
- Related leads are computed on read. A hunt objective holds the list as it stood when the hunt
  started, and it says so.
- The lead thresholds are not yet validated against a miss. The lead threshold (0.85) and the
  single-type threshold (1.5) come from arithmetic. The hub limit (8) was set on an attack range
  with no derivation on record. Read the lead quality report for a week before you move any of
  them.
- A profile dimension has no exclusion list. The `process_names` dimension records each Defender
  updater file name, such as `mpam-d_bd_<version>.exe`, as a new process. A prior names the members
  it reads with `member_patterns`, a list of case-insensitive globs on the base name.
  `prior-workstation-remote-execution-tooling` reads only the PsExec, WMIC, WinRM and PowerShell
  remoting names, so an updater name does not fire it. It does not see a renamed copy of a tool.
- Estate prevalence reads the stored sets, and a set keeps 200 members. A member past the cap of
  a host does not count toward its prevalence on that host.
- The active hours set holds counts per hour of the day, with no dates. A confirmed attack window
  stays out of the sets and the rate. It does not stay out of the active hours.
- A role change between two builds reaches the peer groups at the next build.
- No shipped analytic uses `rare_for_peers` yet. Each tier 2 change starts in shadow for a week,
  and a shipped analytic starts live.
- Every `model` observation is a shadow observation, whatever the status of its analytic. The
  analytic lifecycle work lifts this.
- A learned detector stores no parameter set. It reads what it learns from the grid on every sweep.
  The `stale` and `drifted` states have no writer yet.
- The logon chain detector reads an attempt from the logon plane of the target host. An attempt to
  a host that ships no logon plane is not read. The edge set learns accepted sessions only. A
  failed attempt from B to C before the recent read does not count as an earlier attempt.
- The estate model fits the address key space and the name key space apart. The address and the
  name of one machine are two vectors. The join to the machine row is not done yet.
- The estate model does not call a change on 5 or more hosts at once an outlier. Each such host
  counts as shared. The scope count of tier 2 records a spread across hosts.
- The thresholds of the estate model come from the design and the synthetic estates. They are the
  score bar 0.55, the reason bar 3, the twin radius 1 and the fire budget. None has a shadow week
  yet.
- The estate model has no live mode. Its observations stay in shadow, and a lead that holds one is
  a shadow lead.
- A hunt-subject investigation still stores its anchor document as `alert_es_id`, and
  `GET /investigations/{id}` returns that id as `groupId`. soc-ai keeps the run out of the alert's
  group on every surface, so a hunt verdict does not read as the alert's verdict.

The [1.5.0 release notes](releases/1.5.0.md) hold the measured numbers and the upgrade steps.
