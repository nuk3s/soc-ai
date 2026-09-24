# Hunting with soc-ai

soc-ai triages the alerts your grid raises. It also looks for the attacks that raise no alert.
This guide covers that second half: the analytics that run over the grid, the hits they write, the
leads that form from the hits, the hunts that answer the leads, and the investigations that end in
a verdict.

![How hunting flows: analytic, hit, lead, hunt, investigation](img/hunting-flow.svg)

## The five nouns

soc-ai uses one word for one thing. These five carry the whole pipeline.

- **Analytic:** one detection logic. A shipped analytic is a YAML file in the repository. A local
  analytic is one that you write in the app. Both use one schema.
- **Hit:** one thing one analytic found about one entity, with the documents behind it. A hit is
  stored as an observation. The lead page and the host page call it an observation.
- **Lead:** the observations on one entity that are worth one decision.
- **Hunt:** one agent run with an objective. An analyst, a schedule or a lead starts it. A hunt
  ends in findings and a narrative. It states no verdict.
- **Investigation:** one agent run that ends in a verdict. Its subject is one alert, or one hunt
  with all of its findings.

Two more words appear on screen. An **entity** is a host, a user or an address. A **type** is the
class of an observation or a hunt. The database column is still named `kind`.

## How a hit becomes a lead

Every source writes into one observations table. Each observation carries a weight, and the weight
decays with a 48 h half-life.

| Source | Type | Birth weight |
|---|---|---|
| A profile departure | `novel_destination`, `off_hours` and the other profile types | 0.30 to 0.50 |
| A catalog hit | `catalog_match` | 0.7 |
| A catalog hit from an analytic with no benign baseline | `prior_no_baseline` | 1.0 |
| A triaged alert, true positive | `alert` | 1.0 |
| A triaged alert, needs more info | `alert` | 0.5 |
| A promoted hunt finding | `hunt_finding` | 0.7 |

A false-positive verdict records nothing. A verdict changed to false positive removes the
observation it wrote.

A lead forms in one of three ways.

1. The live weight on one entity reaches 0.85 across two or more types. Two different things saw the
   same machine.
2. One observation is **finding grade**: a catalog hit from an analytic that declares no benign
   baseline, or a true-positive alert. One such observation forms a lead alone.
3. One type repeats until its uncapped weight reaches 1.5. A 0.7 type reaches that on the fourth
   sighting. The lead is flagged `single_signal`.

A lead spans the entities that one hit names, and it merges through them. An entity that sits on
more than 8 open leads is a hub, such as a domain controller or a resolver. A hub is listed on a
lead. It never pulls two leads together.

A lead that holds one or more shadow observations is a shadow lead. A shadow lead starts nothing by
itself.

## How a lead becomes a hunt

With `lead_auto_hunt` on, a loop wakes every 60 s. It starts the hunt for each open lead that has
no hunt, oldest lead first, up to `lead_auto_hunt_concurrency` hunts at a time. The lead then reads
"New · hunt queued".

The loop leaves four leads alone:

- a **dismissed** lead, because you answered it;
- a **reopened** lead, because you reopened it to decide again;
- a **shadow** lead, because nothing in shadow starts a hunt;
- a lead whose observations **cite no documents**, because its hunt would have no evidence to read
  first.

Each of those carries the chip "left to you" and keeps its Hunt button. The skip is logged once an
hour for each lead.

A lead hunt reads the lead's own documents before it queries the grid. Its objective names the
lead's observations and the related leads, and it asks the hunt to state whether the leads are one
campaign, with the evidence. The objective is written once, at the start of the hunt, so it reads
"Related leads at the start of this hunt".

## How a hunt becomes an investigation

Press **Promote** on a hunted lead, or promote one finding from the hunt page. soc-ai then runs an
investigation whose subject is the hunt.

The run reads the hunt's objective, its narrative, every finding, and every document those findings
cite, up to 40. The promoted finding's documents come first and the rest follow newest first. A lead
hunt also carries the lead's observations and its related leads. soc-ai loads the cited documents as
evidence before the investigation starts. A verdict that cites one of them then resolves against a
document the run holds.

The verdict is `true_positive`, `false_positive` or `needs_more_info`, with a confidence, a
rationale, citations and recommended actions. For a hunt subject the three words mean this:

- **true positive**: the hunt's hypothesis holds as an attack or a compromise;
- **false positive**: the findings have a benign explanation that the evidence supports;
- **needs more info**: the report names the gap that a tool call can close.

Every gate runs: the evidence gate, the citation validation and cap, the confidence floor, the
egress guard, the Oracle escalation and the session gate. Two things do not run. The decision
templates do not. Each template matches an alert rule class, and a hunt has none. The unattended
acknowledge does not either. Security Onion holds no hunt to acknowledge.

Promote on a lead with no finished hunt is refused with HTTP 409 `lead_not_hunted`. Hunt the lead
first. The investigation reads the hunt's findings.

## Related leads

One entity is one lead. A coordinated attack across several machines is several leads, and no
single one of them reads as a campaign. The lead page carries a **Related leads** panel for that
case.

A lead is related when it is open, when it formed in the last 7 days, and when it shares one of
four things with the lead you are reading:

- the same analytic on an observation within 24 h;
- the same alert rule within 24 h;
- the same external address or /24 network named in an observation;
- the same ATT&CK technique.

IPv4 compares on the /24. Two hosts that talk to neighbouring addresses usually talk to one place.
Each row states the share in one phrase, names the state of the related lead, and links to it. The
lead row on the strip carries a "+N related" chip.

soc-ai computes the list on read and stores nothing. A stored relation goes stale as soon as you
answer either lead. A deployment whose API returns no related leads shows no panel. An empty panel
there would read as an answer nobody gave.

## The Hunts page, top to bottom

The page is the pipeline in order. Each item appears once. Every section header carries one dim
line that says what the section holds. That line ends in a link, **How this flows**. The link opens
the chart above in a drawer. The address `?flow=1` opens the same drawer.

### 1. Needs you

One line at the top. It gives the count, then one link per thing that waits on you: "2 shadow hits
are unread", "2 leads wait on a decision". Each link jumps to the block below with its filter set.
When nothing waits, the strip reads "Nothing needs you" and takes one line. The sidebar badge on
the Hunts item shows the same count, and the bell lists the items.

### 2. Analytic hits

Every hit from the last 7 days, live and shadow, in one list. Live hits come first, newest first.
Shadow hits follow, unread first. The filter chips are All, Unread, Live and Shadow, and the counts
behind them are read over the whole window.

A live hit carries a solid accent border and a bold title. A shadow hit carries a dashed amber
border and the `shadow` chip. A read shadow hit is dimmer still. The real hit is never lighter than
the provisional one.

Each card names the analytic, the entity, the document count, when the hit was first seen and how
many times it was seen. Evidence sits under that, and each document opens the document drawer. When
a lead holds the hit, the action is **Open lead**, because the lead is where the decision is made.
A hit that formed no lead offers **Hunt this entity**. A shadow hit adds **Approve analytic**,
**Reject analytic** and **Mark read**.

A shadow hit stays unread until you open its evidence or act on it. A live hit has no read flag.

### 3. Leads

Four tabs, named by what you must do: **Needs decision**, **In progress**, **Closed**, **All**. The
block opens on Needs decision.

Every row carries a state pill: `New`, `In progress`, `Hunted · <outcome>`, `Dismissed`,
`Promoted`. A new lead whose hunt the loop has taken reads `New · hunt queued`. The pill is the
state. The tab is a filter.

| State | Actions |
|---|---|
| New | Hunt now, Dismiss |
| In progress | View hunt |
| Hunted | Read hunt, Promote, Dismiss, Hunt again |
| Dismissed, Promoted | Reopen. A promoted lead also offers Open investigation. |

A dismissal needs a reason: `expected_for_role`, `known_change`, `benign_repeat`, `bad_baseline` or
`other`. Free text is optional. The lead quality report counts the reasons, so pick the honest one.

### 4. Hunts

The list of agent runs, with a Started-by column that reads Manual, Schedule or Lead. The objective
of a lead hunt links to the lead. Scheduled hunts sit under the list. The catalog sweep adds no
entry here, so this list holds agent runs only.

### 5. New hunt

One button at the top right of the Hunts section. It opens the composer in a drawer: the objective
box, the starters, the template control and the Start button. A starter can name the analytics to
run first.

### 6. Analytics tab

The analytic catalog. Each row carries the title, the tier (shipped or local), the status (live,
shadow, candidate or retired) and the analyst actions. An analytic opens a drawer with its
description, its evaluator, its version history, its outcome ledger and its recent observations by
entity.

The outcome ledger is computed on read over one window. It holds the observations the analytic
wrote, the leads it contributed to, how many of those leads were hunted, promoted or dismissed
under each reason, the documents it scanned with the runtime, and the entities it scored against
the entities it could not see. Retirement decisions read the ledger.

### 7. Lead quality

A block under the analytics table. It states the lead rule in one sentence, and the noise floor
rule beside it: a threshold moves on a week of data, never on a day. Then two tables.

- **Per ISO week**: leads formed, hunted, with a threat finding, promoted, and dismissed under each
  reason. A week with no leads is still a row, because a quiet week is a measurement.
- **Per set of observation types**: formed, dismissed, and with a threat finding.

The reason columns come from the data, so a reason nobody used costs no column. A failed read
states the failure. Over a dead endpoint, "no leads" is a false all-clear.

## The shadow week

A new analytic earns its place before it counts. Run it in shadow for a week and read what it
produced.

1. **Put the analytic into shadow.** On the Analytics tab, open the analytic and choose **Run in
   shadow**. A shadow analytic runs on the normal sweep. It writes shadow observations. It cannot
   go live by itself.
2. **Dry run the catalog by hand.** `soc-ai spec-sweep --shadow` reports what every analytic would
   have found. It records no hunt and it does not spend the fire-once budget, so an analytic is
   not silent on the day you switch it on. Add `--backfill` once when you add an analytic, to seed
   the state from history without one finding per historical occurrence.
3. **Read the hits with their receipts.** Every shadow hit carries the matched documents and the
   fields that matched, the baseline for a profile analytic, a 30-day dry run with its fire count
   and entities, and the overlap with any live analytic that saw the same documents. A hit with
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

## Settings

| Setting | Default | What it does | Applies |
|---|---|---|---|
| `lead_auto_hunt` | on | A lead that has never had a hunt starts one when it forms. | live |
| `lead_auto_hunt_concurrency` | 2 | How many lead hunts the loop runs at once. The floor is 1. | live |
| `entity_profiles_enabled` | off | The dossier refresh builds a behavioural baseline for each host. The profile sweep reads every host as blind until this is on. Turn it on for the shadow week. | live |
| `hunt_spec_sweeps_enabled` | off | Run the analytic catalog on a loop. Turn this on last. | live |
| `hunt_spec_sweep_interval_minutes` | 60 | Minutes between catalog sweeps. The floor is 5. | live |
| `hunt_spec_sweep_window_minutes` | 1440 | How far back each sweep looks. | live |
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
| `soc-ai priors` | Run the role priors against every entity that has a behavioural profile, and print what departed. `--recent-hours N` sets the window. The default is 24. |
| `soc-ai priors --record` | Write each departure as an observation, and form leads from what accumulates. Off by default, because a read of the coverage must have no side effect. |
| `soc-ai spec-run [<id>]` | Run one analytic, or the whole catalog, and print the candidates as JSON. |
| `soc-ai spec-sweep` | Sweep the catalog and record what is not already handled. `--since`, `--until`, `--shadow` and `--backfill` shape the run. |

`soc-ai leads --report` and the Lead quality block print the same numbers from the same function,
so a terminal and a browser cannot disagree.

## The API

Every route sits under `/api/v1`. The console uses these, and an integrator can too.

| Route | What it answers |
|---|---|
| `GET /hunts/hits` | Every analytic hit from the last `days` days, live first, then shadow with unread first. `filter` takes `all`, `unread`, `live` or `shadow`. |
| `GET /hunts/needs-you` | The one number the sidebar badge and the Needs-you strip show: unread shadow hits plus leads that wait on a decision. |
| `GET /leads` | The lead list. `status` takes a stored value, `all`, or one of the tab aliases `new`, `closed`, `needs_decision` and `in_progress`. |
| `GET /leads/quality` | The lead rule, the noise floor rule, and what the rule produced per ISO week and per observation-type pair. `weeks` sets the window. |
| `GET /hunts/leads/{id}` | One lead: its observations, its entities, its related leads and whether its investigation still exists. |
| `POST /hunts/leads/{id}/hunt` | Start the lead hunt by hand. |
| `POST /hunts/leads/{id}/promote` | Promote the lead to an investigation of its hunt. Answers 409 `lead_not_hunted` when no hunt has finished. |
| `POST /hunts/leads/{id}/dismiss` | Dismiss the lead with a reason from the fixed list. |
| `POST /hunts/leads/{id}/reopen` | Reopen a closed lead. The loop does not hunt it again. |
| `POST /hunts/{hunt_id}/findings/{ordinal}/investigate` | Promote one finding of a hunt to an investigation of that hunt. |
| `GET /hunts/observations` | The observations on one entity, from every source, for the host page. |
| `GET /hunts/shadow-hits` | The shadow half on its own, for the bell and the Dashboard card. |
| `POST /hunts/shadow-hits/{obs_id}/read` | Mark one shadow hit read. |
| `GET /analytics` | The catalog, both tiers, with status and tier on each row. |
| `GET /analytics/{id}` | One analytic with its version history, its outcome ledger and its recent observations. |
| `POST /analytics/{id}/status` | Move an analytic between candidate, shadow, live and retired, with a reason. |
| `GET /hunt-catalog` | The health of the catalog: the last sweep, the last firing and the 24-hour counts for each analytic. |

`GET /investigations/{id}` carries a `subject` block for a hunt run: the hunt id, the objective, the
finding ordinals and titles, the lead id, the document ids and the observation ids. A list row
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
- A hunt-subject investigation still stores its anchor document as `alert_es_id`, and
  `GET /investigations/{id}` returns that id as `groupId`. soc-ai keeps the run out of the alert's
  group on every surface, so a hunt verdict does not read as the alert's verdict.

The [1.5.0 release notes](releases/1.5.0.md) hold the measured numbers and the upgrade steps.
