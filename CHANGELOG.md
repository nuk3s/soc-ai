# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and the project aims to follow
[Semantic Versioning](https://semver.org/) from 1.0 onward.

## [Unreleased]

## [1.5.0] - 2026-09-23

1.5.0 is the hunting release. soc-ai now looks for the attacks that raise no alert. An analytic
finds a hit, hits on one entity form a lead, a lead starts its own hunt, and a hunt reaches a
verdict. The Hunts page holds that whole pipeline, and the Needs-you strip names the few things
that wait on you. The release also makes an investigation more accurate and restores every write
to a Security Onion 3.3 grid.

### The profile sweep runs in the app (2026-09-22)

- **The profile sweep needs no host timer.** The sweep compares each host with its own baseline,
  records what departs, and forms a lead from what accumulates. It ran from a systemd timer on the
  range. A container has no timer, so a Docker deployment recorded no profile observation and formed
  no profile lead. Nothing failed and nothing said so. An in-process loop now runs the same code
  path `soc-ai priors --record` runs, every 60 minutes, with a floor of 15 minutes. Two settings
  control it in Config → Hunting: "Run the profile sweep", on by default, and "Minutes between
  profile sweeps". Both apply live. The loop skips a demo, and it skips a sweep while Elasticsearch
  is down, because a sweep that cannot measure records that nothing departed. It does not wait for
  the dossier loop: a sweep with no baseline behind it reports what it could not measure as blind,
  as the command does.

### What the sixth dogfood round found (2026-09-22)

The four decisions in this release were read on the range through the browser, the API, the
database and the service log.

- **A reopened lead with a finished hunt waits on the analyst.** A reopen keeps the hunt, so the
  lead is open again with a hunt attached. That lead matched no tab: not new, because it names a
  hunt, and not hunting, because the analyst reopened it. The loop leaves a reopened lead alone,
  so nothing held it at all. The Needs-you count, the Needs decision tab and the sidebar badge now
  hold it under both settings, and an open lead whose hunt runs reads In progress.
- **A hunt-subject investigation is not the anchor alert's investigation.** A promotion anchors
  the pipeline's time windows on one cited document, so the row names that document. Every reader
  that grouped by the column read the run as the alert's: the alert's own investigation arrived as
  a superseded earlier run, and a false positive about the hunt's hypothesis would have read as
  the alert's verdict on the Alerts page. One rule now answers whose run it is for a row, for a
  grouping key and for a stored query, so no reader can answer it a different way. The two
  prefetch events also say that the subject is the hunt.
- **The related rows carry the state of their own hunt.** The Related leads panel read the stored
  status, which stays `hunting` after a hunt lands, so one lead read "In progress" in the panel and
  "Hunted" on every other surface. Each row now carries `hunt_status` and `hunt_outcome_label`, in
  one query for the page.
- **A lead that shares an entity is not a related lead.** Related leads answer one question: did
  this move to another entity? A dismissed lead and the lead that forms next on the same host
  share the analytic that formed them both, and the panel offered that successor as a relation.
- **The investigation timeline reads a hunt subject as one.** The context step said "Loaded alert
  context + enrichments" over the hunt's findings, and the template step said no pattern matched
  when the templates had not run at all. The steps now read "Loaded the hunt subject: N findings,
  M documents" and "Templates do not run on a hunt subject".
- **The hunt objective says that its related list is a snapshot.** The objective is written once,
  at the start of the hunt. The related list is computed on read. The line now reads "Related leads
  at the start of this hunt:", so a reader hours later knows which list it is.
- **The lead auto-hunt help names all four leads the loop leaves alone.** It named the dismissed
  lead only. The loop also leaves a reopened lead, a shadow lead and a lead that cites no document.
  Four replaces the three that entries below this one name.

### Leads are hunted, hunts are investigated, leads relate (2026-09-22)

The screens for the four decisions in the design for the hunting layer.

- **A new lead says that its hunt is coming.** soc-ai starts the hunt on a new lead by itself. The
  lead then waits on that loop and not on the analyst, and the strip still read "New", which is
  the word for a lead nobody has touched. The pill on such a lead now reads "New · hunt queued".
  The lead offers Dismiss and Promote. Hunt drops to a second act under the name "Hunt now",
  because the hunt is already coming and the button only makes it come sooner. The lead page reads
  the same words. The legend gains one sentence while the loop runs: "A new lead starts its own
  hunt." The note that said soc-ai starts no hunt from a lead is replaced while the loop runs,
  because it states the opposite of the truth. The strip reads the setting from the leads
  themselves. A lead that carries a queued hunt is a lead the loop has taken.
- **An investigation of a hunt names the hunt.** The right panel of the investigation page named
  the rule and the event. A hunt investigation has neither. The panel now reads "Subject: hunt"
  for such a run. It carries the objective, the findings the run read, a link to the hunt, a link
  to the lead when the hunt started from one, and the count of the documents the findings cite. A
  backend that sends the finding ordinals without their titles gets the ordinals on screen. The
  verdict block, the evidence and the citations are unchanged. The Investigations list carries a
  type chip "hunt" beside the detection type for such a run.
- **Promote waits on a hunt.** An investigation of a lead reads the hunt's findings. Promote on a
  lead with no finished hunt is now refused on the lead page, under the sentence "Hunt this lead
  first. The investigation reads the hunt's findings." A refusal from the server carries its own
  sentence, and the leads strip prints that sentence in place of its own "Try again."
- **A lead names the leads that relate to it.** One entity is one lead. A coordinated attack
  across entities is several leads, and no single one of them reads as a campaign. The lead page
  carries a Related leads panel. Each row names the entity, the lead, the reason the two are
  related, and the state of the related lead. An empty panel states "No related lead in the last
  7 days." The strip row carries a chip "+N related" that opens the lead page. A deployment whose
  API computes no related leads shows no panel, because an empty panel there would read as an
  answer nobody gave.
- **The Analytics tab counts what the lead rule produced.** The lead rule is a set of thresholds,
  and a threshold nobody measures is a guess. A Lead quality block sits under the analytics table.
  It states the rule and the noise floor rule in the server's own words, then counts per week the
  leads formed, hunted, with a threat finding, promoted, and dismissed under each reason. A second
  table counts the same per set of observation types. The reason columns come from the data, so a
  reason nobody used costs no column. A failed read states the failure, because "no leads" over a
  dead endpoint is a false all-clear.

### The screens after dogfood round 6 (2026-09-22)

The screen half of the sixth dogfood round.

- **A related lead wears the pill of its own hunt.** The Related leads panel built the pill from
  the stored status alone. A lead whose hunt had finished read "In progress" there and "Hunted" on
  the strip, on its own page and on the host page. The panel reads the whole row now, and the row
  carries the hunt status and the outcome label.
- **The leads note names the leads the loop leaves.** The note claimed a hunt on every new lead.
  The loop leaves a shadow lead, a reopened lead and a lead with no documents, so a shadow lead
  read "New" under a note that promised a hunt that never came. The note states the three
  exclusions, and such a lead carries the chip "left to you" beside its pill on the strip and on
  the lead page.
- **An investigation of a hunt reads in hunt words.** The breadcrumb read "Alerts / Investigation"
  over a run with no alert behind it, and it goes to Hunts now. The header carried the severity,
  the host and the peer of the first cited document, which is one of many the run read. It reads
  the first sentence of the objective and a link to the lead.
- **The related sentences name the alert rule.** The server joins two leads on four things. The
  chip and the reason column named three, and the reason an analyst read on the range was the
  fourth.
- **The lead page legend reads the setting.** The legend is a taxonomy of the deployment. The page
  appended "A new lead starts its own hunt." only when this one lead was queued, so every hunted,
  promoted and reopened lead read the legend without it.
- **Promote waits on a hunt on both surfaces.** The lead page disabled Promote on a lead with no
  finished hunt and said why. The strip row kept the button live, and the click returned 409.
- **The New pill stops offering Promote.** The server refuses a promotion until a hunt has
  finished. The pill names the hunt that starts on its own, the hunt by hand, and the dismissal.
- **The type chip states what a lead run is.** The chip on a lead run read "The detector that
  raised this alert, as the grid names it." No detector raised it.
- **The Subject panel counts findings from one.** The list read "Finding 0" over the first finding
  of the hunt. The stored ordinal is unchanged.
- **A promotion from the lead page says so.** The click left no mark, while the record already
  held the promotion and the running investigation. The page states "Promoted. The investigation
  is running.", links the investigation, and reads the lead again.
- **A lead title spaces the names of two entities.** The two names ran together under one dot.
- **The hunt page names a reopen.** The lead page ended a reopened dismissal with "Reopened." and
  the hunt page ended it without, though both render one timeline component.

### A hunt is investigated as a whole (2026-09-22)

- **An investigation of a hunt has the hunt as its subject.** Promotion used to start the
  ordinary alert triage on one cited document, so the scope collapsed from the hunt to one
  event. The investigation now reads the hunt: its objective, its narrative, all of its findings
  and every document those findings cite, up to forty, with the promoted finding's documents
  first and the rest newest first. A lead hunt also carries the lead's observations and the
  leads that relate to it. The verdict schema does not change. The prompt states what the three
  verdicts mean for a hunt: a true positive means the hunt's hypothesis holds as an attack or a
  compromise, a false positive means the findings have a benign explanation the evidence
  supports, and needs more info names the gap a tool call can close. The summary answers the
  hunt's objective in one paragraph.
- **The cited documents are the prefetched evidence.** They join the run's bundle before the
  first model call, so a verdict that cites one of them resolves against a document the run
  really holds. The evidence gate, the citation cap, the egress guard, the Oracle escalation and
  the session gate all run. Three do not. The decision templates each match an alert rule class,
  and a hunt has none. The unattended acknowledge has nothing to write to, because nothing in
  Security Onion holds a hunt. A hunt has no session, so the same-session prior has nothing to
  read.
- **Promoting a lead reads its hunt.** A lead with no finished hunt answers 409
  `lead_not_hunted` and names the way forward. Promotion is idempotent as before.
- **The investigation page can say what the run was about.** `GET /investigations/{id}` carries
  `subject` with the hunt id, the objective, the finding ordinals and titles, the lead id, the
  document ids and the observation ids. The list rows carry `subjectType`, which reads `alert`
  or `hunt`. The `kind` field is unchanged. Migration 0050 adds `investigations.subject_json`,
  which is empty on every alert run.

### A lead starts its own hunt (2026-09-22)

- **A lead that has never had a hunt starts one when it forms.** A lead is already several
  observations that crossed a threshold together, so the question "is this worth a look?" is
  answered by the time the lead exists. Before this the lead waited for a click, and a lead that
  formed overnight was still waiting in the morning. A loop wakes every 60 seconds and starts the
  hunt for each open lead that has no hunt, oldest lead first. The hunt is the lead hunt the Hunt
  button starts: the same objective, the same evidence block, the same type. The route and the
  loop now call one function, so the two cannot start different hunts. The loop starts the hunt,
  and not the sweep that forms the lead, because leads also form in the timer process that runs
  the priors, and that process cannot run an agent.
- **The loop leaves three leads alone.** A dismissed lead is never hunted. A reopened lead is not
  hunted again, because the analyst reopened it to decide again and Hunt again is their button. A
  lead whose observations cite no documents is skipped. Its hunt would have no evidence to read
  first and would search the grid from scratch. The skip is logged once an hour for each lead. The
  lead keeps its Hunt button in every one of these cases.
- **Two settings, both live.** "A lead starts its own hunt" (`lead_auto_hunt`) is on by default.
  Off restores the older behaviour, where a lead waits for an analyst to start the hunt. "Lead
  hunts at once" (`lead_auto_hunt_concurrency`) is 2 by default. It counts the hunts the loop
  started, so a hunt an analyst started by hand never blocks the loop.
- **The Needs-you strip counts what an analyst must act on.** With the loop on, a new lead waits
  on soc-ai and not on the analyst, so it leaves the count and the Needs decision tab. A lead
  whose hunt finished still waits, and so does a reopened lead. With the loop off the older rule
  holds. Each lead carries `hunt_queued`, which the New pill reads as "New · hunt queued".

### Related leads, and the lead rule instrumented (2026-09-22)

- **A lead names the open leads it may share a story with.** A lead spans the entities that one
  hit names. A coordinated attack does not, so an analyst who read one lead could not see the
  rest of the attack. The lead page now carries a Related leads list, and the lead row carries
  the count. A lead is related when it is open, when it formed in the last 7 days, and when it
  shares one of three things: the same analytic on an observation within 24 hours, the same
  external address or network in an observation, or the same ATT&CK technique. Each entry states
  the share in one phrase, for example "same analytic within 24 h", "same external address
  203.0.113.0/24" or "same technique T1558.003". soc-ai computes the list on read and stores
  nothing. A stored relation goes stale as soon as an analyst answers either lead. IPv4 compares
  on the /24, because two hosts that talk to neighbouring addresses usually talk to one place.
- **The objective of a lead hunt names the related leads.** The hunt reads them with the lead's
  own observations, and the objective asks it to state whether the leads are one campaign, with
  the evidence.
- **Every threshold in the lead rule states its derivation.** The lead threshold (0.85) and the
  single-type threshold (1.5) were derived from arithmetic, and each docstring gives the
  derivation. The hub limit (8) was set on the range on 2026-09-17 with no derivation on record,
  and the docstring says that. None of the three is yet validated against a miss.
- **`GET /api/v1/leads/quality` reports what the rule produced.** Per ISO week: leads formed,
  hunted, with a threat finding, promoted, and dismissed by reason. Per observation-type pair:
  formed, dismissed, and with a threat finding. A threat finding is the outcome the Hunts page
  paints as "Threat findings", read from the same function, so the two surfaces cannot disagree.
  A week with no leads is still a row, because a quiet week is a measurement. The report states
  the rule and the noise floor: a threshold moves on a week of data, never on a day.
- **`soc-ai leads --report` prints the same table.** It takes `--weeks N` (the default is 4). It
  reads the local store. It calls no model and queries no grid.

### The Security Onion login (2026-09-21)

- **The login uses the Kratos browser flow, which SO 3.3 requires.** Security Onion 3.3 stopped
  accepting a Kratos API-flow session token in an `X-Session-Token` header. The login still
  succeeded and SOC then refused the session on every call, with HTTP 401 and the server-side
  reason "Missing or invalid authorization header for bearer token". Every write to Security Onion
  failed that way: acknowledge, escalate, case creation and case comments. Reads were unaffected,
  because they read Elasticsearch with a different credential. soc-ai now logs in the way the
  Security Onion web interface does. It reads the login flow document, submits the credentials
  with the flow's CSRF token, and lets the cookie jar carry the `ory_kratos_session` cookie on
  every later request. The srv-token handling that writes depend on is unchanged, and the Kratos
  path prefix setting is unchanged.
- **One build works on every Security Onion release.** The setting "Security Onion login flow"
  (`so_login_flow`) takes `auto`, `browser` or `api`. `auto` is the default. It runs the browser
  flow, and falls back to the older API flow when the browser flow cannot complete: the browser
  endpoint is absent, the flow document holds no CSRF token, the login answers a 4xx that is not
  a credential rejection, or SOC refuses the cookie session on `/api/info` while it accepts the
  same account's API-flow session. A wrong password never causes the fallback, because the same
  password fails on both flows. soc-ai keeps the flow that worked for the life of the process, so
  a fallback costs one extra login and not one for every request. `browser` and `api` force one
  flow with no fallback. The setting applies at the next restart. One log line names the flow at
  the first login that Security Onion accepts.
- **A refused session backs off instead of logging in again.** A 401 made soc-ai drop the session
  and log in once more, on every request, with no ceiling. Over three days that made 32,420
  throttled logins, 75,800 warnings in Security Onion, and an audit index sixteen times its normal
  size. When SOC refuses a session that soc-ai has just established, soc-ai now holds the login.
  The hold starts at 30 seconds and doubles to a ceiling of ten minutes. One log line names the
  cause, and the next accepted call clears the hold.
- **A throttled login reads as a throttled login.** Security Onion sheds repeated logins by
  redirecting them to its own login page. soc-ai read that page as JSON and reported "Kratos login
  flow init failed: Expecting value: line 1 column 1 (char 0)". That message filled the log and
  described a login that never started, which hid the session refusal behind it. The message now
  says that SO throttled the login, and gives the status code.
- **The setup check names the cause.** On a 401 the check said the Security Onion API was unhappy
  and sent the operator to the user's role grants. The grants were correct. The check now says
  that SOC refused the session, and to check the SO version and the login flow. Its PASS line names
  the login flow in use. The header status indicator says the same.

### The Hunts page spine (2026-09-19)

- **One list holds every analytic hit.** The band on the Hunts page showed shadow hits only, so
  nobody could see what a real hit looks like. `GET /api/v1/hunts/hits` lists both halves from
  the last seven days: the live hits first, newest first, then the shadow hits, unread first.
  Each hit carries the analytic, its tier, the entity, the document count, the lead that holds
  it and the lead's status. A live hit has no read flag and carries `read` null, so nothing
  draws an unread dot on a hit nobody can read. The counts behind the filter chips are read over
  the whole window, not over the returned page. `GET /api/v1/hunts/needs-you` answers the one
  number the sidebar badge and the Needs-you strip show: the unread shadow hits plus the leads
  that wait on a decision. `GET /api/v1/leads` takes two filters named by what the analyst must
  do, `needs_decision` and `in_progress`. The existing shadow-hit routes are unchanged.
- **The catalog sweep writes the observation only.** A catalog hit made three records: a hunt
  row of kind `triggered` with a report, a finding inside that report, and the observation. The
  hunt list showed those rows beside the runs an agent made and the Hunt Console subtitle
  counted them as hunts. The sweep now writes the observation, and the setting
  "Record a hunt row for each analytic hit" restores the old write for one release. It is off by
  default and applies live. The catalog hunt rows described in the older entries here are the rows
  that setting restores. Rows written before this release stay in the database: the hunt list
  leaves them out by default and `?kind=triggered` still lists them. A visibility-gap row is not
  a hit and is unaffected, because a gap says the analytic could not see and silence there is a
  false all-clear.
- **An approval keeps the hit that earned it.** Two rules met and cancelled a hit. A hit was
  written shadow at birth and kept the flag for the life of the row. The hits surface then hid a
  shadow hit whose analytic had left shadow. Approving an analytic from its own hit card took the
  card off every hits surface, and no sweep could bring it back as a live hit. The flag on the
  observation now records the status the analytic had at the latest sighting. An approval changes
  no row, so the analyst keeps the shadow hit with its read state. The next sweep refreshes the
  row as a live observation and the card reads as a live hit. Retirement is the one status that
  hides a hit. A lead reads its shadow mark back from its observations, so a lead stops reading
  shadow once its analytics are live.
- **The status chip reads the analytic's current status.** The hits payload took `analytic_status`
  from the shadow flag on the observation row. That flag records the status the analytic had at
  the latest sighting, and it holds until the analytic fires again. A hit recorded in shadow
  therefore still read as a shadow hit after an analyst approved its analytic: the card wore the
  shadow chip and offered Approve analytic on an analytic that was already live. `analytic_status`
  is now the status the catalog holds, and a new `recorded_in_shadow` field carries the flag on
  the row. The card takes the status chip and the two analytic decisions from `analytic_status`,
  and the half, the border, the weight and the read state from `recorded_in_shadow`. A hit
  recorded in shadow whose analytic is live carries a dim "recorded in shadow" chip. The halves,
  the filters and the counts split on `recorded_in_shadow` as before, so the hit stays under Shadow
  until the next sweep refreshes it. The one flag the entry above describes now answers only where
  the hit sits, and no longer answers what the analytic is.
- **The bell counts what the page counts.** The bell wrote its own query for unread shadow hits.
  It counted a hit from a retired analytic that the hits list and the Needs-you count both hide,
  and it sent the analyst to a block that did not hold the card. One clause now answers "what is
  an unread shadow hit" for the hits surface, the Needs-you count and the bell. The bell row and
  the Notifications row link to `/hunts?hits=unread`, which sets the filter that holds the hit.
- **A lead says whether its investigation is still there.** `Lead.investigation_id` carries no
  foreign key, so a deleted investigation leaves the id on the lead. A promoted lead then offered
  Open investigation on a link that answered 404. `GET /api/v1/leads` and
  `GET /api/v1/hunts/leads/{id}` carry `investigation_exists`. The list answers it in one query
  for the page. The lead keeps its status, because an analyst promoted it and that decision holds.
- **An observation says whether its spec id names an analytic.** An alert verdict and a promoted
  hunt finding are recorded under a spec id that names the adapter. The lead timeline linked every
  observation to the Analytics tab, and those two opened a drawer that could not be read. The hits
  payload, the observations payload and the lead timeline row carry `analytic_exists`. It is true
  only when the id is in the catalog, so a renamed or removed analytic reads the same way.

- **The page says what each thing is, draws the flow, and folds.** The rebuilt page named a hit,
  a lead, a hunt, a schedule and an analytic, and it said what none of them was. One dim line
  under each section header now states it, and the lead page, the hunt page and the analytic
  drawer carry the same sentence under their own titles. Each line ends in a link, "How this
  flows", which opens the chart of the pipeline in a drawer: what an analytic finds, what forms a
  lead, what starts a hunt, what ends in a verdict, and what waits on the analyst. The address
  `?flow=1` opens the same drawer, and a tab change closes it. The four sections of the Hunts tab
  fold from a chevron in their header. A folded section keeps its title, its count and its
  definition, so it still says what it holds and how much. The fold is kept on that browser, and
  a Needs-you link opens the block it jumps to before it scrolls there.

### Investigation turns (2026-09-19)

- **A setting lets the investigator write the report itself.** The investigation loop gathers the
  evidence, then a second model call re-reads the transcript and writes the verdict. A turn audit
  of 41 runs found the second call added no new evidence in 40 of them, cited nothing in 78% of
  recent production runs, and reversed two correct verdicts on the range. With
  `investigator_emits_report` on, the loop writes the report and the second call does not run. It
  is on by default: on eleven range alerts with ground truth this path landed 31 of 31 correct
  verdicts against 30 of 31, 42 s faster. Every gate still runs on the report either way: the
  citation validation and cap, the confidence floor, the deterministic downgrades, the evidence
  gate, the Oracle escalation and the session gate. The stored `triage_report` event names the
  call that wrote it, `investigator` or `synth_round2`, so the two can be compared on real alerts.

- **The first-pass synthesis runs only when it can close the alert.** soc-ai ran a first-pass
  verdict on most alerts, then ran the investigation loop and replaced that verdict. On the
  production deployment the first pass ran 2,009 times and its answer was discarded 1,661 times.
  It now runs only when a dispositive decision template has already cleared the alert. Every
  other alert goes straight to the loop, which is the only path to a verdict on those alerts.
  This removes about 18 seconds and 8,000 tokens from each affected run. The verdict is
  unchanged: the loop never read the first-pass report. Turn on "Always run the first-pass
  synthesis" to get the old behaviour back.
- **A run that stops early reads the evidence it gathered.** With the first pass skipped there is
  no first-pass verdict to fall back on. A tool-call budget cut, and a concluding synthesis that
  fails, now write the verdict from the tool results that did land. A run that gathered nothing
  lands the honest failure report and stays retryable.

### Analytics, observations, leads and hunts (2026-09-18)

The Hunts page and the hunt catalog read as two products. One word did three jobs. This part
gives each noun one home.

- **Analytic.** One detection logic. The catalog reads two tiers: shipped analytics are YAML
  files, local analytics are rows. A local analytic starts as a candidate. An analyst moves it
  to shadow, approves it to live, or retires it. Every transition writes a version row with the
  spec text before and after. A shipped analytic can only be retired.
- **Observation.** One thing one analytic observed about one entity, with a weight that decays.
  Every source writes to one table: profile departures, catalog hits, triaged alerts (true
  positive 1.0, needs more info 0.5, false positive not recorded), promoted hunt findings.
- **Lead.** Observations on one entity that are worth examination together. A lead forms at a
  live weight of 0.85 across two or more types, or on a finding with no benign baseline, or on
  one type that repeats. A lead spans the entities a hit names and merges through them, never
  through a hub. A lead has a status: open, hunting, dismissed with a reason, promoted.
- **Hunt.** An analyst, a schedule or a lead starts a hunt. A lead hunt reads the documents
  that formed the lead before it queries. The catalog sweep no longer writes hunt rows.
- **Shadow hits.** A shadow analytic's hit brings receipts: the matched documents, a 30-day dry
  run, the overlap with live analytics, and the baseline for a profile analytic. A hit with
  incomplete receipts reads "could not run" and names the missing part. Shadow hits are visible
  in five places: a band on Hunts, the bell, the sidebar, a Dashboard card, and the hit list.
- **Screens.** Hunts has two tabs, Hunts and Analytics. A lead has a page with its timeline.
  An analytic opens to its outcome ledger and its versions. The host page lists its
  observations from every source. Operate's panel reads Analytics.
- **Agent.** The hunt agent runs a catalog analytic as a step with `t_run_analytic`. A starter
  can name analytics to run first. A threat finding offers "draft an analytic", which writes a
  candidate after a 30-day dry run.
- **Writing.** Every string a person reads follows Simplified Technical English. The model prompts
  ask for the same style.
- **Vocabulary.** The word type replaces kind in every label, legend and hint.
- **Fixed on the way.** The production Oracle refused every escalation because the credential
  redacter learned "n" and a shellcode dump as usernames. A hunt that timed out read
  "Complete · 1 finding". A hunt row for a lead ignored the lead's own documents.

### The release, as first written

Proactive hunting. Everything up to now waited for a person: an alert arrived, or you typed an
objective. This release is soc-ai deciding what to go looking for.

### The case for it, measured rather than argued

On the Security Onion grid soc-ai is developed against, measured on 2026-09-04, the grid's own
sensors had produced about 3.4 million documents. **3,940 of them are tagged as an alert**: about
a tenth of one percent. Exactly **two** datasets out of roughly seventy ever produce one. In the
48 hours before the measurement, live telemetry produced 17.

That is not everything on the grid, and this entry as first published counted everything: 56,158
alert-tagged documents out of 23,055,409, a quarter of one percent. That denominator was wrong for
the argument. About 19.6 million of those documents carry an import marker, and 18.8 million of
them are a single Windows event-log import: something somebody loaded, not something a sensor saw.
The numerator was mostly imports too. The gap between 56,158 and 3,940 is alert documents that
carry the same marker, because a replayed packet capture raises Suricata alerts like any other
traffic. A census of what the sensors saw has to leave imports out, and the figures above do. Live
counts grow every day, so the share is the stable number and the totals are not.

So an analyst working the alert queue is working a tenth of one percent of what the grid saw, and
hunting that starts from that queue inherits the loss. A full credential-abuse chain of DCSync,
Kerberoasting and AS-REP roasting was run against a real domain controller. It produced no alert
anyone would have seen at the time. The Sigma rule for it had been enabled for months; it did not
fire because the rule engine tails the stream and its cursor had already passed those documents. A
query has no cursor.

### Added

- **A hunt can now be a document rather than a conversation.** A hunt spec is YAML that compiles to
  one Elasticsearch query and runs with no model call at all. That is the whole point: hunting you
  can afford to leave running, instead of hunting you pay for each time you ask. Four ship in the
  box, covering DCSync, Kerberoasting, AS-REP roasting and decoy interaction.
- **Findings from a spec cannot be invented.** Nothing generative runs on that path. The title and
  the explanation come from the spec's own text, written by a person and reviewed before it shipped.
- **The catalog can run on a schedule** (`hunt_spec_sweeps_enabled`, off by default), and a
  condition it has already shown you does not come back. A finding fires once, not once per sweep,
  which on a one-analyst SOC is the difference between a useful signal and another thing to ignore.
- **Run it in shadow first.** `soc-ai spec-sweep --shadow` reports what every spec *would* have
  surfaced without recording anything and without spending the fire-once budget, so a week of
  watching does not leave a spec silent on the day you switch it on.
- **soc-ai can tell "nothing happened" from "I could not see."** Every spec declares what telemetry
  it needs. When that telemetry is absent the result is a coverage gap in your findings, never an
  all-clear, and a spec whose grid read came back partial reports that it could not see rather than
  reporting nothing found.
- **The Windows Security fields these detections turn on are now readable**, and classified for
  redaction in the same change, so adding a field is one reviewed decision rather than two that can
  disagree.

### Fixed

- **soc-ai could not see the busiest sensor on the network.** 632,523 documents carried their
  identity in a field it did not read, so an entire family of network telemetry went missing from
  the list of data soc-ai believes exists: the flow, DNS, TLS and HTTP records from the sensor
  watching the live segments. Any evidence found there was discarded as unidentifiable. It now reads
  the data-stream name as well.
- **A network sensor's hostname is no longer attributed to the machines it watches.** Two hosts with
  no agent of their own were each reported as the router observing them, because a network document
  names the box that shipped it rather than either end of the connection. Hosts with no agent were
  the worst case and the reason it went unnoticed: for them the sensor's name was the only candidate.
- **The investigator is no longer told its answers change something they do not.** The prompt
  promised that confidence would be capped if it reported its coverage honestly. Nothing had applied
  that cap for some time. Both the promise and the field it asked for are gone.
- **A field the query language refuses is no longer readable another way.** One tool would return
  the top values of a field the query language would not let you filter on.
- **The evaluation can now describe an attack that never became an alert.** Every scenario was
  required to open with one, so the case this release exists for could not be written down. Four
  scenarios now carry no alert at all, and the two types of scenario are scored separately, because
  a scenario the triage harness cannot run should never have counted against it.
- **Model-fitness battery runs are audited again.** Every one of them had been failing to write its
  audit record. The event kind was used at the call site and never declared, so construction raised
  and a `try` that exists to stop an audit failure killing a completed battery swallowed it. The
  battery ran; its trail did not.
- **An investigation kept working after it had the answer.** The loop stated its verdict on the
  first turn and then spent two or three more turns confirming it. Those turns were 79% of the
  time an alert took, and not one of them changed a verdict. The loop now stops as soon as every
  evidence item carries a citation and one fact supports the verdict beside one fact that tried to
  contradict it. A signature that claims malware still needs a tool result behind its verdict.
  Tools that cannot answer are no longer offered: the playbook lookup is registered only on a
  deployment that keeps playbooks, and the rule-text lookup only when the alert does not already
  carry the rule.

### Known gaps, stated plainly

- **There is no health surface for the hunt catalog.** A CI gate proves each spec still matches its
  own fixture; nothing yet says whether a spec still fires against a real grid, because no sweep
  result is persisted. Tracked as issue #56, along with a related and worse one: on a grid
  with no alerts to sample, the nightly quality evaluation writes nothing at all, so its trend
  quietly stops growing and no surface says why.
- **Nothing yet knows what normal looks like.** The analytics measure cadence, entropy and rarity.
  There is no peer-group or seasonal baseline anywhere, which is the next release's subject.

### Then: the catalog's own health

1.5.0 shipped hunting that runs without you and said, under its known gaps, that nothing could
tell you whether it was still running. This release closes that gap.

### Added

- **Every sweep leaves a trail.** Each spec writes one row per sweep, clean sweeps included, so
  "ran and saw nothing" is a fact on disk rather than an absence in the log. Shadow and backfill
  sweeps are marked as such and never count as a firing. Rows are kept per spec, so a catalog that
  grows does not shorten the history of the specs already in it.
- **The Operate hub shows the catalog.** A panel lists every installed spec with its level, when it
  last swept, when it last fired, and its 24-hour counts of fired, fresh and already-handled
  conditions. A spec that is blind is marked amber; one that errored is marked red with the reason
  on hover. The status line says whether sweeps are on, how often they run, how far back they look
  and when the last one landed. Sweeps that are switched on but have not landed a row in two
  intervals show amber, not green: the toggle being on is not the loop running. Backed by
  `GET /api/v1/hunt-catalog`.
- **Catalog hunts are marked on the Hunts list.** A type badge (manual, scheduled, catalog) sits
  beside each objective, and the list's presets filter by kind on the server
  (`GET /api/v1/hunts?kind=`), so a catalog hunt that fell off the first page is still found.
- **The demo carries a week of catalog sweeps.** Four specs, one blind by construction, one that
  fired two days ago into a catalog hunt, one transient error in the history, so the panel and the
  Hunts list's Catalog preset show the feature working rather than four empty rows.

### Fixed

- **The quality trend could not say that it had stopped.** On a grid with no alerts to sample the
  nightly evaluation wrote nothing, which was right, and then said nothing, which was not: the only
  record of the attempt lived in process memory, the card showed the last point as if it were
  current, and a month-old point looked like last night's. The trend now carries a freshness block:
  when the newest point landed, whether the nightly is scheduled at all, whether the trend is stale
  by two runs, and what the last attempt did and why. The card dates its newest point, names the
  last attempt, and marks a stale trend amber. A run that wrote nothing is also logged as a warning.
  The other half of issue #56, and it closes.
- **The CI leak gate had never run.** 1.5.0 said the check that keeps private identifiers out of
  the publishable tree was in CI. It was, and the job image had no `git`, so it raised before it
  scanned anything and every pipeline since had been red for that reason alone. The image now has
  git, and the gate fails with a message that says what is missing rather than a traceback.
- **A failed Refresh from the dashboard's stale line changed nothing on screen.** The stale notice
  was checked before the failed-refresh notice, so a Refresh that failed re-rendered the same line.

### Known gaps, stated plainly

- **The catalog trail is a table and a panel, not an alarm.** Nothing yet notices that a spec which
  used to fire has stopped, the way the nightly triage evaluation notices a regression. That needs
  weeks of rows to be meaningful and follows once they exist.
- **Nothing yet knows what normal looks like.** Unchanged from 1.5.0, and still the next release's
  subject.

### Then: what a day against the range found

1.5.1 was tested by its own unit suite and a seeded loopback stack. This is what happened when it
met a live Security Onion grid and a browser.

The catalog itself held up. It fired on a genuine honeypot interaction the grid had not alerted
on, reported the same condition once rather than on every sweep, and every number its read-model
publishes recomputes exactly from the rows underneath. What follows is everything that did not
hold up.

### Fixed

- **The 1.5.0 notes measured the alert queue over the wrong denominator.** They said 56,158 of
  23,055,409 documents on the grid were alerts, a quarter of one percent. About 19.6 million of
  those documents were imports, 18.8 million of them a single Windows event-log import, and most of
  the 56,158 alerts carried an import marker too. Over what the sensors actually produced, the share
  is about a tenth of one percent. The 1.5.0 entry, the README and both roadmaps now say so.
- **The DCSync spec could not see Get-Changes-All.** `identity-4662-dcsync-nonmachine` matched one
  replication right, DS-Replication-Get-Changes. A domain controller writes one 4662 per right it
  checks, and a later reading of the range found an attacking-account document carrying only
  DS-Replication-Get-Changes-All, the right that releases secrets, which that clause could not match.
  The spec now matches any of the three replication rights (Get-Changes, Get-Changes-All,
  Get-Changes-In-Filtered-Set); the machine-account exclusion, which carries all of the precision,
  is unchanged. The fixture plants each right alone, and a new CI gate requires every document from
  the expected actor to match on its own, because the journey score cannot see one missed document
  while a sibling carries the candidate. The range counts quoted in the spec were measured with the
  narrower clause and are now dated as such.
- **The panel said "Sweeps off" while the catalog was sweeping and firing.** The cadence, the
  look-back and the time of the last sweep were built only in the branch that renders when the
  scheduler is on, so an operator running sweeps by hand, which is what the panel's own hint tells
  them to do, saw a line that read as nothing running while the counts moved beside it.
- **A row could not say when its spec was last swept.** The time was on the wire and the row used
  it as a yes or no. The critical DCSync row read the same whether it was checked ninety seconds
  ago or last week, which is the one question this release exists to answer.
- **A shadow sweep made a spec look broken.** Shadow runs count toward fresh and never toward
  fired, by design, and the panel tells a new operator to run shadow first. So an ordinary new
  install read "fresh 2, fired 0" with nothing to explain it. Rows now say how many of their
  sweeps were shadow, and the counts name the window they cover on screen, not in a tooltip.
- **A catalog hunt showed 0.00 confidence in large type.** These hunts make no model call, so the
  absent value was being coerced to zero on the way out and rendered as a verdict. The detail
  endpoint now preserves the absence the way the list endpoint always did, and the page shows no
  dial at all. A model that genuinely scores 0.00 still shows it.
- **A finding mixed what matched now with prose written months ago.** Counts measured when a spec
  was authored sat in the same paragraph as this run's result, so they read as fresh measurement
  and would quietly go false as a grid grows. They are now labelled as the spec's own rationale.
- **The type filter on the hunt list was invisible to the address bar.** It reset on reload, could
  not be linked to, and the Operate panel's own link therefore landed on the unfiltered list.
- **`soc-ai spec-sweep --shadow` did not run.** The panel and the config console both print that
  exact command and it exited with an argument error, because the window was required and neither
  hint mentioned it. It now defaults to the configured look-back.
- **The scheduler and the command line disagreed about what one sweep covers.** Both widen a
  window narrower than the interval, but only the scheduler applied a floor to the interval and
  said so in the log. One function now computes it for the scheduler, the command line and the
  API, and the API reports the window a sweep will actually use rather than the raw setting.
- **No shipped command could see a planted evaluation scenario.** The four no-alert fixtures exist
  to prove the catalog finds attacks that raise no alert, and until now only a test could use
  them: `spec-run` and `spec-sweep` never passed the flag that reads the synthetic index. Both
  take `--include-synth` now, off by default, and a hunt recorded under it is marked as one.
- **Planting a scenario with nothing to triage wrote every document and then refused.** The check
  ran after the loop. It now runs first, and says nothing was planted.
- **Two empty states named the wrong thing**, one of them pointing at a control that would not
  have helped, and a catalog hunt's row showed its spec id where its title belonged.

### Known gaps, stated plainly

- **Two of the four shipped specs are no longer detecting what nothing else sees.** Security
  Onion's own rules for DCSync and Kerberoasting now fire on the same grid. The catalog's unique
  contribution today rests on AS-REP roasting and the decoy. Endpoint antivirus verdicts look like
  the strongest addition: on the range they are the only telemetry that caught a credential-dumping
  tool running on the domain controller, and like the decoy they need no threshold.
- **A grid census that counts documents does not ask what a document is.** On the range, one
  imported file split into millions of lines dominated every count, and soc-ai's inventory reads
  those indices the same way the census did. Not fixed in this release.

### Then: a fortnight of living with it

Nothing above had been run against a real deployment for longer than an afternoon. Between
2026-09-05 and 2026-09-14 it was: the home deployment against its own Security Onion, and the
attack range against its exploit chain, with every read and write exercised the way an analyst
would. That found more than the three iterations before it. The largest were a denominator and a
gate. Every prevalence, novelty and baseline figure had been computed over everything on disk, and
on the development grid 85% of that was imported packet captures, a baseline of somebody else's
network. Every population statistic now counts live telemetry only and says so. And the catalog,
which is where a detection's doctrine lives, could not be read by a triage: the same real DCSync
alert closed false positive one day and escalated true positive the next, both runs grounded,
because triage never learned that directory replication by a non-machine account has no benign
population to compare against. A spec can now declare that, and a triage that closes such a
detection benign on a volume argument is refused.

The rest is below, as it was written at the time. A recurring theme: a number that said one
thing and counted another, a surface that rendered the same whether the thing behind it was
healthy or dead, and a warning that could not be cleared. The home deployment's "pipeline errors
that never heal" and its recurring quality alarm turned out to be four distinct defects, each
fixed.

#### Fixed

- **A count nobody could take was reported as a count of zero.** The alert queue's "N
  acknowledged" chip comes from a filter aggregation on `event.acknowledged`. Elastic Defend
  writes its alerts to an index Elastic's own package maps `dynamic: false`, without that
  field or `event.escalated` beside it, so Security Onion's flags land in `_source` where no
  query reaches them and the aggregation answers 0 whatever the truth is. Measured on a live
  SO 3.2.0 grid on 2026-09-06 against a 16-event endpoint group: all 16 acknowledged, SO
  answered 200 each time, and a query for the flag still matched none of them. The row said
  "untouched" about a group an analyst had cleared, every single time.

  The write path already refuses to trust that query and reads the flag off each hit. A
  per-group count has no such option: a group can hold thousands of events and the console
  will not page them to draw one chip. It does the other honest thing instead. The aggregation
  now resolves each group's datasets alongside its counts, and a group holding documents on
  an index that cannot store the flag reports the count as unknown rather than as zero. So
  does a group whose dataset list came back truncated, because past the cap a blind dataset
  cannot be ruled out. A mixed group counts as unknown too: the number the aggregation
  returns there is a real undercount of unknown size, and an undercount reads exactly like a
  complete count.

  The row renders that as a faint chip carrying a question mark and the reason, next to where
  the green check would have been, and points at the expanded group. Each event carries the
  flag in its own document, which is the one place the answer still exists. A grid that
  answers is unaffected, including the ordinary case of a group with nothing acknowledged:
  zero is a real answer on an index that maps the field.

- **`/healthz` said `ok` about things it had never looked at.** The container healthcheck
  polls it and Docker prints the result beside the container as the word *healthy*. That word
  was read as a verdict on the product by people whose grid was unreachable, whose model
  gateway was down, or who had no analyst model configured at all. The endpoint had probed
  none of that. It never should: a liveness probe that failed on a dependency outage would
  have the orchestrator restart a container whose dependencies are merely down, turning
  somebody else's outage into a restart loop and taking away the surface that could have
  explained it.

  So the logic is unchanged and the wording is not. The response is a `LivenessResponse`, its
  status reads `alive` rather than `ok`, and it carries a `checks` field saying in plain words
  that nothing was probed and naming where the verdict does live (`GET /api/v1/health`, or
  `soc-ai doctor`). That sentence is on the wire and not only in a docstring because the two
  places this body is read are a paste of `curl` and `docker inspect`'s health log. The
  Dockerfile and compose healthchecks, `setup.sh`, `soc-ai healthz --help` and the deployment
  and Docker guides all say liveness where they used to say health, and each points at the
  doctor for the rest.

- **The verdict-quality alarm had no way to reach a human.** Its two channels were an audit
  record, which nobody reads unprompted, and the notification webhook, which is off by
  default and stays off on any install that has not opted into egress. So on a stock
  deployment the Quality card on the dashboard was the only surface where a regression in the
  verdicts this product exists to produce could be learned about. It is a card you have to
  already suspect something to go and look at.

  It is now a standing bell entry, on the same terms as every other standing condition here
  (a dependency down, a broken audit chain, a dossier conflict): read from the newest
  snapshot only, one indexed row, fail-soft, and never a probe on an endpoint polled every
  fifteen seconds. An eval that crashed is not reported as a verdict regression. "The grader
  could not run" and "the verdicts got worse" need different responses, and the bell separates
  them the way the card already did.

  The entry's id is the identity of the finding: the alarm's rule codes and the moment the
  condition started. It is not the id of the run that noticed it. The writer holds that start
  steady for as long as the condition persists, so one dismissal covers every night that
  re-observes the same condition, while a different code, or the same code raised again after a
  clean night, arrives undismissed. It is the id the Quality card was already minting for its own
  dismiss control, so clearing the alarm in either place clears it in both.

- **Ten nullable JSON columns stored an absence as the text `null`.** SQLAlchemy's `JSON`
  type serialises a Python `None` through `json.dumps`, so it lands as the two-byte string
  `null`. The column holds a JSON value where SQL NULL belongs. It reads back as `None`, which
  is why it survived: every assertion in the suite is spelled `row.col is None` and every one of
  them passed. SQL says the opposite of the truth. `WHERE col IS NOT NULL` matched every row in
  ten tables; `WHERE col IS NULL` matched none.

  Nothing was visibly broken, because every reader coalesces with `or []`. That is what made
  it worth fixing: the columns were a loaded trap for the first query that asked whether a
  lane held anything, and one subsystem had already stepped in it. A cleared dossier override
  stored that way would have read as still held forever, which is why the dossier store grew a
  per-statement workaround for three columns and never covered the two beside them. The fix
  now lives on the column type, where it cannot be skipped by a statement someone forgot to
  route through a helper.

  Existing rows are normalised by the migration rather than left alone, because a half-normalised
  table is a worse trap than a uniformly wrong one: the query that motivated the fix would work on
  this month's rows and silently skip everything older. The repair cannot take a legitimate value
  with it. A stored string `"null"` serialises with its quotes, so only the defect matches. The
  downgrade does not put the old representation back: a rewritten NULL and an original NULL are
  the same value, and restoring one would fabricate the other.

- **A quality snapshot could not say what was running when it was measured.** The nightly
  trend recorded agreement, fallback, errors and latency, and nothing at all about the
  instrument, so a bend in the line had nowhere to point. The published image is tagged
  `latest` and every build of one release carries the same version string, which means the
  version alone cannot tell two builds apart either.

  Each snapshot now carries three things. `app_version` and `code_commit` say which build ran;
  the commit is baked into the image at build time, because `.dockerignore` excludes `.git`
  and a container has no other way to know. `analyst_model` says which route the verdicts came
  out of. The failure this whole subsystem exists to catch is an inference-engine swap or a
  model bump, and neither of those changes a line of code. All three are visible on the
  Quality card and on `GET /api/v1/quality/trend`, and `/healthz` reports the commit too, so a
  bug report from a container install can name its build.

  Unknown stays unknown: an image nobody stamped records no commit rather than a guess, and
  rows written before this change are left as they are. A wrong commit is worse than a missing
  one when the entire point is attributing a regression to a change.

- **An empty threat-intel feed read as a clean answer.** The blocklist feeds have never been
  refreshed on either deployment and the data directory does not exist, so `BlocklistDB`
  loads nothing and every lookup misses. The only signal was a warning in the process log:
  the enrichment result carried no field saying so, which made "we checked and found
  nothing" and "we could not check" the same object. The timeline rendered that object as
  "no blocklist/MISP match" and three triages leaned on the phrasing to support a false
  positive.

  `IndicatorEnrichment` now carries `blocklist_sources`, the feeds that actually answered,
  and reads it back as `blocklist_checked` with three states rather than two, because there
  are three: unrecorded, recorded-and-nothing-loaded, and recorded-with-feeds. Collapsing the
  first two would have relabelled every archived enrichment as unchecked, which is its own
  false statement, so only an explicit "nothing loaded" changes any behaviour. The lookup
  also appends a line to `errors`, the same way the cloud tagger already reports that IPv6 is
  uncovered, so the model reads the distinction in prose as well as in a field.

  Every renderer of the empty case reads it. The timeline outcome says the blocklist was not
  loaded instead of reporting a miss, on an internal address too, because the curated
  internal-seed feed is the one that names known-bad internal hosts. The entity graph note
  says its unflagged nodes were never checked. The prefetch line stops implying that
  "enriched N indicators" means N reputation checks. The synthesizer gets a citable coverage
  bullet in the same shape as the endpoint-coverage gap, worded as neither exoneration nor
  guilt. The `clean_internal_traffic` template keeps its two locality grounds but no longer
  writes down a reputation check that did not happen, and `informational_external_unknown_asn`
  stands down entirely: its only ground beyond informational-and-allowed IS the reputation of
  an external address, so with no feed it has none. The synthesizer rubric no longer names an
  empty blocklist as positive evidence without qualifying it.

- **The field that answers the first question in Windows triage was not queryable.** A hunt
  asking whether an authentication was Kerberos or NTLM failed four queries with
  unknown-or-forbidden-field errors. `winlog.event_data.AuthenticationPackageName` is the
  field the range's own operating documentation names for separating management traffic from
  real users, and it is populated: counted over fourteen days on the range, Negotiate 20614,
  Kerberos 19984, NTLM 526, all on `system.security`. It is now queryable, along with
  `LogonProcessName`, `LmPackageName` and `winlog.logon.type`, the readable alias for the
  numeric logon type that was already admitted. Each is enumerated individually, never as a
  `winlog` prefix, for the same reason the existing entries are: a prefix admits several
  hundred leaves in one line, many of them carrying identifiers no redaction route
  classifies. Their values are public Windows constants but word-shaped, so unlike the GUIDs
  and hex masks already admitted they do not pass the egress value check on their own; each
  is allowlisted by path in the Oracle backstop so a Kerberos-versus-NTLM finding is not
  adjudicated with the package itself redacted.

- **A contains query on a keyword field matched nothing and said so quietly.** `field:~value`
  compiled to an Elasticsearch `match`, which is right on analyzed text and useless on a
  `keyword` field: the keyword analyzer emits the whole value as one token, so the query
  degenerates into an exact full-value comparison. `process.command_line` is keyword-mapped.
  Measured on the range on 2026-09-07 over seven days, all four counts in one aggregation:
  a `match` for a known command matched 0 documents, the analyzed `.text` sibling matched
  405, and the leading wildcard the validator refuses as too expensive also matched 405.
  A bare zero on the process command line is an absence a model reads as innocence.

  The substring search is not expensive here, so refusing it would have been the wrong kind
  of honesty: Elastic's Windows and endpoint integrations map an analyzed `.text` sibling
  alongside the keyword field, and the answer was one field name away. `:~` now asks both
  names in a single `multi_match`, phrase-typed when the value was quoted. The named field
  is never dropped, so a grid that maps the field as analyzed text with no sibling behaves
  exactly as before, and an unmapped sibling scores nothing rather than erroring. The set of
  names that can reach Elasticsearch stays the whitelist plus one fixed suffix per entry,
  because validation still runs on the field the caller wrote. The leading-wildcard refusal
  stands and now names the form that works.

- **Every "in the last N hours" question was answered over N divided by two.** The event
  query tool centres its window on the alert, so a 1440-minute request became twelve hours
  before the anchor and twelve after, and for a live alert the forward half holds nothing.
  Measured on the range on 2026-09-07, anchored on a real alert: a grid-wide 24-hour count
  came back 504 where the grid held 1061, and a one-host 48-hour count came back 81 where
  the grid held 113. Counting the grid over the effective half-windows reproduces 504 and
  81 exactly, so the window was the cause rather than a coincidence. The tool's description
  did say the window was centred, but for a live alert that is never what the caller means,
  and nothing checked the arithmetic afterwards: the citation validator resolves document
  identifiers, not numbers.

  These are two questions, so they now take two forms rather than one parameter that has to
  mean both. `window_mode="around"` is the default and is unchanged: the window stays
  centred, which is the right shape for "what happened around this alert", where the minutes
  before it are the setup and the minutes after are what followed. `window_mode="before"`
  puts the whole requested span behind the anchor, which is what a how-often question means.
  With no anchor at all there is nothing to centre on and both modes look back from now, as
  they already did. The result also carries a `window` block naming the mode, the two bounds
  and how far the window reached either side of the anchor, on the same reasoning as
  `counted`: a number handed over without its span gets the span the reader assumed. The
  Zeek pivot keeps the centred window with no mode at all, because it follows one flow and
  answers no prevalence question.

- **Every agent in a container ran without the query-language reference, and nothing said
  so.** The system prompts for triage, hunting and chat are assembled from
  `docs/OQL_PRIMER.md`, resolved as parent-of-package. The Dockerfile copied `soc_ai/`,
  `pyproject.toml`, `runbooks/`, two demo scripts and the built SPA, and never copied
  `docs/`. Measured inside the running container on 2026-09-07: the primer path did not
  exist and the prompt block was 971 bytes, all of it the fallback stub, whose text is
  "Primer file missing on disk; OQL is unavailable." So every investigator, hunt and chat
  prompt shipped a sentence telling the model the query language was unavailable in place
  of the field reference and the worked examples. The hunt flavor lost its examples twice
  over: the splice keys on markers the stub does not contain, so it never even read the
  hunt file, which was equally absent.

  Nothing surfaced it in any direction. The `FileNotFoundError` branch was annotated as a
  development-only safeguard and logged nothing. The test that checks the primer's splice
  markers reads the repository, which always has the file. No doctor check looked at a
  prompt asset, which is how the doctor reported fifteen passed and zero failures while it
  was true. The development range runs from source under systemd and has the file, so a
  week of dogfooding against the range could not have caught it and did not.

  `docs/` is now copied into the image WHOLESALE, the same way `soc_ai/` and `runbooks/`
  are, because naming the two files individually is the mistake that produced the defect:
  the next prompt asset added under `docs/` would silently not ship. `docs/img` and one
  internal subtree are excluded in `.dockerignore` instead, about 10 MB of screenshots and
  vendored guides that nothing reads at runtime.
  An audit of every path the application resolves outside its own package found exactly
  these two files missing; `runbooks/`, `frontend/dist` and `pyproject.toml` were already
  copied, and everything else a prompt or a tool reads lives inside `soc_ai/`.

  The absence is now loud in three places, because it was silent in all three. The app
  refuses to start when a declared prompt asset is missing, before the store, any client
  or any request: the standing rule that a false all-clear outranks a crash is about
  upstreams, where an honest degraded answer exists and can be handed to the analyst, and
  here there is none. The verdicts keep arriving and keep looking like verdicts. A missing
  file is knowable with two stat calls at boot, where an operator is already watching,
  rather than at the moment an analyst is trusting the answer. `soc-ai doctor` grows a
  `prompt assets` row that names which assets are present, which are missing, and what the
  absence costs; it FAILs rather than WARNs, since the WARN band is for things that
  degrade gracefully. And the fallback stub, which stays so the CLI and the doctor can
  still run inside a broken deployment to report it, now logs at ERROR every time it is
  produced.

  The regression gate replays the Dockerfile's own COPY directives into a scratch tree and
  imports the package from there in a subprocess, so it grades the deployed layout rather
  than the checkout. Real copies, never symlinks, since `Path.resolve()` follows a symlink
  back to the repository and would hand the checkout's answer back under a container's
  name. Its negative control drops the one COPY that carries `docs/` and asserts the
  defect reappears.

  Not a claim about accuracy, but the reason to look: on the deployed instance
  `t_query_events_oql` has run 3,870 times and 2,132 of those calls (55%) returned zero
  hits, with 173 more rejected outright. Every one of those calls was made by a prompt
  built from the stub, so the recorded history contains no primer-present period to
  compare against and cannot, on its own, attribute the rate to the missing file.
- **`rule_prevalence` printed a rate over the observed span under the words "while active".**
  Measured against a live grid: a rule with 438 fires on 17 of the 30 days it spanned reported
  `fires_per_day=14.612, rate_basis='observed_span'` and a summary reading "about 14.612/day
  while active". 14.612 is 438 divided by the span. While active it is 25.765. A second rule
  reported 8.555/day "while active" where the figure on its active days was 13.9. The number had
  been moved off the lookback window and onto the observed span, which was the right denominator,
  but the sentence kept its old adverb and so named a denominator that had not been used.

  Both quantities are real and they answer different questions, so both are now reported, each
  under its own name. `fires_per_day` is unchanged: fires over the span, with `rate_basis` still
  saying so. `fires_per_active_day` is the new field, fires over the days the rule actually fired
  on, and the summary prints the span figure as "across that span" followed by the active-day
  figure as "on the N days it fired". A rule that fired on every day it spans has one rate, not
  two, so the second clause is dropped when the numbers agree rather than printing the same
  figure twice.

- **`burst_fires_per_minute` divided the burst by the window that held it.** 335 fires clumped
  onto 4 days of a 25.4-day span came out as 0.01 fires per minute, and went into the JSON the
  model reads under a name that says burst. It is the same window-over-burst error that had just
  been taken out of the daily rate, alive one field along: when the fires sit on a handful of
  days inside a long span, most of that span is silence, and dividing by it describes the gaps
  rather than the episodes.

  The shared burstiness test now reports `fires_fill_span`, and the per-minute figure is emitted
  only when the observed span is the episode. A day histogram has no sub-day timing in it, so
  there is nothing honest to put in its place and nothing is offered; `fires_per_active_day`
  carries the magnitude instead, and the summary says both that the span is mostly silence and
  what the rule did on the days it fired. The one-episode burst is unchanged: 1531 fires in 59
  seconds still reports 1560.2 a minute.

- **`rule_prevalence` called a rule it had never queried "first-seen".** The query was pinned to
  `suricata.alert`, so every Sigma rule, Zeek notice and endpoint rule came back
  `observed: false, total_fires: 0, noisiness: "first-seen"` regardless of how often it had
  fired. On a live grid the Sigma rule "Security Onion - Grid Node Login Failure (SSH)" had
  fired 48 times over seven days and reported as never seen; a Zeek capture-loss notice with 841
  firings reported the same. The narrow scope was deliberate and the module docstring said so.
  The output did not: "first-seen" is a claim about the network, and the reading a model takes
  from it is the exact opposite of the truth.

  The query now covers every dataset that carries a detection (Suricata alerts, Sigma alerts,
  Zeek notices, endpoint alerts) and resolves a rule name across `notice.note` as well as the
  ECS and legacy fields. It stays an allowlist rather than dropping the dataset filter, because
  `windows.sysmon_operational` populates `rule.name` with Sysmon's operator-supplied config tag,
  which is not a detection. Comparability is handled by naming the source instead of narrowing
  the search: a rule name belongs to one engine in practice, `fires_by_dataset` breaks the total
  down whenever it does not, and the summary then says outright that the total pools sources
  whose firing rates are not comparable. The noisiness thresholds were set against IDS volume, so
  the summary names the source the count came from. When nothing matches, `searched_datasets` and
  the summary both say where the tool looked and that it did not look anywhere else.

  Widening surfaced the same defect shape one field over. Sigma and Zeek docs keep their
  addresses outside `source.ip` and `destination.ip`, so the cardinality aggregations returned 0
  and the summary read "0 source hosts / 0 dest hosts" for 841 real detections. Zero distinct
  hosts over a non-empty match is a missing field, not a measurement, so those counts are now
  `None` and the sentence says the docs carry no address. The `noisy` bucket needs host spread to
  be measured; where it cannot be, the bucket is withheld rather than awarded on an untested
  condition, and the summary says which test could not be applied. Where spread is measured
  nothing changes.
- **The host address on an alert row was the shipper's, not the host's.** On a host-shaped
  detection Security Onion nests the originating document under `event_data`, and the endpoint's
  own address sits at `event_data.host.ip` while the address of whatever forwarded the log to the
  grid sits under the beats input metadata. The resolver read only the beats path. On the range's
  DCSync detections that meant the row named `sr-dc01` and showed the log-forwarding host's
  address, and an investigation pulled a host dossier for the forwarder believing it had the
  domain controller. The neighbouring host *name* resolver already preferred the nested field,
  which is how the name and the address on one row came to describe two different machines.

  The nested endpoint address is now tried first and the beats path kept as a fallback, since on
  an agent that ships its own logs the two are the same machine. That field is an array of every
  address the host claims, in interface-enumeration order, and it lands on the row as a live pivot
  to `/entity/<ip>`, so the first entry is no longer taken blindly: loopback and link-local are
  skipped when anything else is on offer. One endpoint on the measured grid reports a routable v4,
  a link-local v6 and two container-bridge addresses. Nothing beyond those two is ranked, because a
  bridge address is still an address that host answers on.

- **A planted evaluation fixture reached the live alert queue as a critical detection, and the
  guard that let it in then hid the evidence needed to recognise it.** The synthetic kill switch
  excluded documents carrying a scenario marker at the top level of the document. Security Onion's
  Sigma pipeline re-nests the whole originating document under an `event_data` envelope, so the
  marker lands one level down and the exclusion missed it. Measured on the range on 2026-09-06:
  56,162 alert-tagged documents survived the exclusion and 2 of them carried the marker in the
  nested position. Those two were a planted DCSync fixture, and they presented as a critical Sigma
  alert in the queue.

  The chain compounds from there, and the second half is the worse one. The underlying event does
  carry the marker at the top level, so it is excluded from every query the agent can run. A triage
  of that alert made fifteen tool calls, got zero results from every corroborating query, exhausted
  its budget, stated that the account's purpose could not be independently verified, and issued
  false positive at 0.60 anyway. The absence was the guard's, not the network's, and nothing in the
  run could tell the two apart. Because the group verdict applies to the whole group, three genuine
  DCSync events on the real domain controller then read "inherited, same detection" under a
  false-positive badge.

  Two changes. The exclusion now names every position the marker is known to occupy, top level and
  under a detection pipeline's envelope, and is built in one module that every read path calls; the
  alerts queue, the dataset inventory and the two host-dossier passes each carried their own copy
  naming the top level only, and now do not. Adding a pipeline is one line. A wildcard field
  expansion would need no list at all and finds the same two documents, but it costs 219ms against
  9ms on the same query and returns no clauses and no error when it matches no mapped field, which
  is the same silent nothing this guard exists to prevent.

  And an investigation whose own subject the guard hides now refuses instead of investigating. The
  anchor is fetched by document id, so it is the one read in a run that does not pass the exclusion
  clauses, while every pivot after it does; that combination cannot produce evidence, only zeros.
  The refusal happens before the first pivot, names the scenario, and yields no verdict at all
  rather than a low-confidence one, because a disposition on a fixture is still a disposition and
  still counts. The same check catches a batch-eval run handed a sibling scenario's alert id.

  Negative control, measured on the same grid: the three genuine DCSync detections on the real
  domain controller carry no marker in either position, survive the widened exclusion, and are
  investigated unchanged. The `suricata.alert` class did not move (56,107 before and after); the
  `sigma.alert` class went from 55 to 53.
- **A shellcode rule was being acknowledged unattended, and the classification table already
  knew why.** Measured on the deployed instance: 156 unattended acknowledgements across two
  `GPL SHELLCODE` rules, three of them after the classtype description fix went live and the
  most recent today. All four arms of the high-stakes guard missed the alert. Its Suricata
  category, "A system call was detected", normalizes correctly to `system-call-detect`, and
  neither the routing map in the classifier nor the attack-classtype set the escalation guard
  uses had an entry for it; "shellcode" is not one of the malware signal tokens; and the
  severity, medium at score 2, is under the severity arm.

  The hole was not a missing token, it was a table with a silent default. The classification
  table enumerates all 43 of Suricata's classifications and the routing map had an opinion about
  20 of them; the other 23 fell through to "unknown", which reads as no opinion and spends as
  safe. The map now covers the same ground as the table: every classification is either routed
  to a class or named in an explicit unrouted set, and a test fails if a new one arrives with
  nobody having decided what it means. What makes a rule high-stakes is therefore the
  classification its author declared, read through the one table the codebase has, rather than a
  substring found in the rule's name. The token list stays where it earns its keep, on alerts
  that carry no classification at all, and is deliberately not where new signals get added: it
  also drives benign-template routing across the whole decision layer, so a token added to close
  an auto-ack hole would change verdicts for every rule whose name contains it and would still
  leave the next unrouted classification open.

  Negative control: the six classtype values actually measured on the production grid, in the
  description form the sensor writes, are still eligible for unattended acknowledgement. A
  widening that switched the feature off would be a different defect, not a fix.

- **One call site kept comparing a raw classtype, so an exemption could never fire.** The gate
  that downgrades a true positive resting on nothing but the host's alert history has an
  exemption for the case where the focus alert is itself attack-class. It lower-cased the raw
  classtype and tested it against a set of shortnames, and the field carries Suricata's
  classification description, so on live data the comparison never matched. The consequence is
  the inverse of the auto-ack hole above and comes from the same root cause: the exemption never
  fired, and genuine attack-class true positives were downgraded to needs-more-info. The
  comparison now runs through the same normalizer every other classtype comparison uses, and a
  sweep found no other site reading the raw field for anything but display. Two assertions in
  the quality-spine suite that compared the raw value on synthetic fixtures now normalize too:
  the scenarios render shortnames, so those assertions passed while standing for code that
  could not match a sensor.

- **The daily audit-chain alarm reported one break out of many, and could not be cleared.** The
  scheduled verification ran and correctly found a break. It named a single sequence number. The
  window it scanned held 41 distinct duplicated sequence numbers across 51 extra records, some
  positions claimed by four writers. An operator could not tell a single collision from a
  widespread one, and could not see the fact that mattered most: all 41 fall before the fix that
  stopped the forking, so the honest reading is that the damage is historical and bounded.

  Every channel now carries the blast radius as well as the first break: how many positions are
  claimed more than once, how many records that is beyond the first at each, the most writers at
  any one position, how many records no longer match their own hash, and the oldest and newest
  timestamps among the records involved. That last one is what says whether anything has broken
  since. Counted per epoch, because sequence numbers restart at zero on every process incarnation,
  and only over the epochs that actually failed, since an intact one censuses to zero by
  construction. The same sentence goes to the bell, the notification webhook and
  `soc-ai audit verify`, so the three cannot disagree.

  The alarm also could not be dismissed. It lived only in application state and the bell entry's id
  embedded the detection timestamp, so every run minted a new identity: an undismissable danger
  notification every day until the forked stretch aged out of the seven-day window, which was
  several days away. The id is now the identity of the FINDING, in the same shape every other
  standing alarm here uses. What goes into it is the safety argument: the break types present, so
  dismissing a known historical fork can never suppress a record being edited; the newest record
  involved in any break, so anything that breaks afterwards re-raises; and the count of records
  that no longer match their own hash, so a further alteration re-raises even when the type is
  already showing. The duplicate counts are deliberately excluded, because a rolling window sheds
  old records every day and keying on them would re-raise the same scar every morning.

  A finding that includes an altered record is not dismissible at all: it carries no dismiss
  control and "Clear all" steps over it. A duplicated position is what a second writer leaves
  behind and an operator can reasonably acknowledge a bounded historical scar; a record whose
  content no longer matches its own hash is someone changing the record of a decision, and one
  click should not be able to sweep that away. None of this touches the reporting: the audit record
  and the webhook still fire on every run for as long as the chain does not verify.

- **Sigma and host detections reached the agent with every pivot field empty, and one benign
  verdict then silenced the rule everywhere.** Security Onion's Sigma pipeline does not merge
  the document a rule matched into the alert it writes: the detection's identity goes at the top
  level and the whole originating document is nested under `event_data`. `SoAlert.from_es_hit`
  read only the top level. Measured on 55 `sigma.alert` documents from a live grid, not one
  carried a top-level source address, destination address, host name, host address, user name,
  process id, file hash, community id, event action, event category or message, while 48 carried
  a nested source address and 53 a nested host name. The alert queue already knew about the
  nesting and worked around it for the host column alone.

  The model and the queue now read through one shared envelope reader. Precedence is
  top-level-wins, decided on the three fields that are present at both levels: `event.module`,
  `event.dataset` and `tags` disagree on every one of those documents, because the top level
  names the Sigma detection and the envelope names the log it fired on. Letting the envelope win
  would relabel every Sigma alert as the dataset it matched, so the fields that name the
  detection are not unwrapped at all and only the fields that describe what happened are.

  The worse half was the clustering. Auto-triage keyed each cluster on rule plus both addresses,
  a missing address degraded to the empty string, and the result was that every address-free
  detection of a rule shared one key, for all time, on every machine. On the same grid 100 of 208
  investigations carried that key, and one Sigma rule held a false positive and a true positive
  under it at once, so whichever landed last answered for the other everywhere. The key now
  carries the host, but only when both addresses are empty: a flow seen by two sensors carries
  two host names and must not split, while a detection with no flow has no other subject. When
  even the host is unknown the key names nothing at all, and a verdict is no longer handed along
  it. Every legacy row keys there, so none of them inherits onto anything any more; the
  in-flight duplicate guard is untouched, because a coarse stop is safe where a coarse verdict
  is not.

- **One tile, three denominators.** "True positives · 24h" was labelled for a 24-hour window,
  counted detection groups, and carried a subtext counting investigation runs over thirty days.
  Read in two tabs at the same minute on 2026-09-07 the tile said one and the investigations
  list said three, and nothing on the tile said the two were counting different things: one
  detection group with a standing true-positive verdict against three true-positive runs.

  Every number in the tile now names what it counts. The headline figure reads "1" over "of 3
  detection groups", which is the denominator the neighbouring Events tile already uses, so a
  reader can see immediately that it is not a count of runs. The needs-info clause sits beside
  it because it counts the same groups over the same window. The pipeline-error clause moves to
  its own line carrying its own unit and window, "runs, last 30d", because it is neither.

- **A deployment with authentication off gave the same caller three different identities.**
  `GET /api/v1/me` invented "analyst" so the sidebar had a name. Every write recorded
  "anonymous". Saved views refused outright. So assigning an alert group to yourself stored an
  owner the identity endpoint did not recognise: the row grew an avatar and an owned chip, and
  the Mine filter stayed at zero and always would. Both names render "AN" as initials, so
  nothing on screen gave it away. The feature did nothing while appearing to succeed.

  The two halves get different answers, because they are different problems. Ownership works
  once the caller has one identity: `/me` now reports the same name every write on that
  deployment is recorded under, so claiming a group and filtering for it agree. Saved views
  genuinely need a user row, which an unauthenticated deployment has none of, so they still
  refuse. What changed there is that the refusal is now visible. `/me` carries `signed_in`,
  false for a token caller and for an open deployment alike, and the four list screens render a
  disabled "Save view" control with the reason beside it rather than nothing at all. Rendering
  nothing is what taught an analyst the feature did not exist.

  A deployment WITH authentication behaves exactly as before: the signed-in user is reported as
  themselves, ownership records their username, and saved views work.

- **The pipeline-error tile promised a count the list it opens could not reproduce.** The tile
  counted runs after excluding the ones an operator had dismissed and the ones a later run had
  already superseded. The list behind its link applied neither exclusion and offered no filter
  or marker for them. Watched live on 2026-09-07 the tile read nine, then eight, then seven
  while the list sat at twenty, and a run dismissed seconds earlier rendered exactly like a
  counted one. Twelve of those twenty were superseded and three were dismissed, so the gap was
  most of the list.

  `GET /api/v1/investigations` takes an `error_state` of `live` or `handled`, and the deep link
  carries `errors=live`, so both surfaces read the same number off the same query. One query
  cannot make the split, because "superseded" is a fact about an alert's whole run group and not a
  column on the row, so the server decides it per row over one capped read and counts the
  partition it returns rather than the wider filter set. When that read is not the whole set the
  response says `partial`, and the tile renders its count as a floor instead of reading as exact.
  The list grows a three-way control naming which half is on screen, defaulting to the half the
  tile counted and one click from all of them, and every dismissed or superseded row is marked
  as such wherever it appears. An unknown `error_state`, like an unknown verdict, is dropped
  rather than refused, so a mangled link widens the query instead of wedging the screen.

- **The header connection pill stayed green through a hung Security Onion.** The pill covered
  Elasticsearch and the model gateway only. It never covered the Security Onion web API, which
  is the path every acknowledge, escalate and case write travels, so on 2026-09-07 it read
  "connected" in the same frame as a page reporting the grid could not be read, and again beside
  a setup-health card saying the Security Onion check had timed out. This is the product's one
  always-on trust indicator, which makes it the worst place in the app for an optimistic answer.

  `/api/v1/health` now carries a third component, `so`, probed on the same short TTL and the
  same single-flight lock as the other two, so the pill's colour cannot disagree with its own
  dropdown. The probe issues `GET /api/info` through the shared auth client the write endpoints
  already hold, which means it exercises the live session rather than logging in afresh every
  fifteen seconds, and it classifies what went wrong the way the Elasticsearch probe does:
  refused, timed out, shedding load, or credentials rejected. An API that answers with a 401,
  403 or 5xx counts as down, because that is exactly what the next acknowledge will get. The
  dropdown lists Security Onion as its own row, the dashboard's connection banner names it, and
  a down API becomes a standing bell entry like any other dependency. A payload with no `so`
  field, which is what an older server sends, still reads as "not reported" rather than "down".

- **The alerts-filter check compared totals, so it passed while a whole alert class was
  invisible.** Measured on the deployed instance on 2026-09-06: the configured
  `event.dataset:suricata.alert` matched 1,892 documents in 24 hours and the broadest
  alternative, `tags:alert`, matched 1,896. Every ratio and margin the check applies reads that
  as a rounding difference, and it PASSed. The four documents between them were Security Onion's
  Sigma engine, whose host-behavioural detections the configured filter matches none of and
  never has: 397 of them over thirty days, none of which reached the triage queue, the alerts
  console, or any hunt that reads the alert plane. Zero coverage of a class is a different
  failure from a filter that is merely narrower, and no ratio between two totals can express it.

  Each label probe now also breaks its matches down by `event.dataset`, a terms aggregation on
  the size=0 count the check already ran, so no extra round trip. The check now WARNs whatever
  the totals say when an alternative finds a class the configured filter finds none of. The
  message names the class rather than the shortfall, because "your filter is narrower" is not
  something an operator can act on and "the queue has never seen a sigma.alert" is. The remedy
  stays a widening: the recommended value is the configured filter ORed with the label that
  covers the most invisible documents, never that label on its own. A class list the grid cut
  short (`sum_other_doc_count` above zero) proves nothing, so the comparison stands down rather
  than raising a false alarm on a healthy grid.

- **`soc-ai doctor` graded the environment file, not the configuration the app runs.** Saved
  console settings live in `config_overrides` and are applied over the environment-loaded
  settings at startup, so the two diverge in ordinary use. On the deployed instance
  `ORACLE_MODEL` is one model in the file and another in the database; the running app uses the
  second, while the doctor probed the gateway for the first. It also meant the alerts-filter
  row would go on reporting a filter the operator had already fixed in the console, which is the
  one place its own hint sends them. The CLI path now applies those overrides before running the
  checks, in the same order the app uses, and says on the config row how many it applied. Reading
  them is fail-soft in every direction: a fresh install has no store yet, and `check_store` is
  the row that reports a missing or broken one. A caller that passes its own settings (the in-app
  preflight) already holds the live singleton and is untouched.

  The filter hint now also says which of the two places wins, because it sends the operator to the
  console while the value on that instance lives in a file. A console save applies immediately
  and outranks the file; an edit to the file while an override exists changes nothing, and a
  sentence offering two equal-looking options gave no way to know that.

- **A triage that died was announced nowhere, and could not be cleared.** On the deployed
  instance 188 investigations of real alerts ended in an error status with no verdict, no
  rationale, no summary and no report, over ten weeks. Not one had been acknowledged, and no
  surface in the product had ever mentioned any of them: the Dashboard's pipeline-error count
  matched only the E1.2 fallback marker, which is stamped from a report these runs never wrote;
  the notification bell listed in-flight runs and completions and nothing else; and the dismiss
  endpoint refused anything that was not fallback-marked, so even a count that had included them
  could never have been worked down. A monitoring product that fails loudly is fine. This one
  failed silently, and the alerts behind those runs sat unacknowledged and unqueued with nobody
  able to see it.

  One rule now stands behind all three surfaces: the run displays as an error and carries no
  verdict. The `pipeline_error` verdict filter matches those runs as well as fallbacks, so the
  Dashboard tile and the list its deep link opens both reach them; the bell announces each one as
  "Triage failed, no verdict", capped at three so a gateway outage cannot become the whole panel;
  and the terminal-failure panel in the drawer now carries the same Dismiss control the fallback
  panel has always had. A dismissed run stays dismissed: the bell reads the acknowledgement stamp
  in its own query, and the tile applies the exclusion it already applied to fallbacks.

  Cancelled and interrupted runs are deliberately outside all of it. An operator asked for the
  cancel, and a restart orphan stays re-huntable so auto-triage picks it up again; counting
  either would be a nag about work that needs none. An errored run that did reach a verdict is
  outside it too, being reachable under that verdict. The bell's status filter now grades a row
  by its DISPLAY status, so a complete run with a blank verdict is reported as the failure it is
  rather than as "Verdict untriaged".
- **The investigator gathered the evidence and the handoff threw it away.** The investigator queries
  the grid and writes what it found into a transcript, one fact per line with the tool, path or
  document id that supports it. The synthesizer reads that transcript and writes the verdict, and
  its citation list comes out empty. On the deployed instance 1,187 of the 3,379 runs that produced
  both a transcript and a report lost between six and thirteen evidence strings that way, a median
  of eight, and 713 of those reports were then acknowledged in Security Onion as verdicts resting on
  nothing. The evidence was never missing. It failed to reach the report, and every surface
  downstream read the absence as an absence of grounds: the citation gate, the drawer, the analyst.

  The transcript's evidence is now carried into a report that cited nothing, next to the
  template-grounds adoption and ahead of it: where a dispositive template and a real investigation
  are both available, the run's own retrieval is the better answer to what the verdict rests on.
  Three properties keep this a carry rather than a manufacture. It only fires when the report cited
  nothing, so the model's own citations are never overwritten or padded. Every bullet goes to the
  resolver unfiltered, so one that does not resolve lowers coverage exactly as a fabricated citation
  would, and nothing is dropped to flatter the number. It also requires the loop's real message
  history, because without it the tool-citation resolver falls back to a substring match against the
  transcript's own text, and a bullet carried out of that transcript would resolve itself. That last
  one is the way this change could have been worse than the bug, so it has a test of its own.

  Measured on 400 of the affected production runs, the carried bullets resolve at a mean coverage of
  0.996: 3,075 strict resolutions against 15 that fail. The grounds were real and structurally
  checkable the whole time. Practically, that means the citation gate added alongside this stops
  refusing the acknowledgements it should not have been refusing, and the timeline says which
  findings the verdict was recorded against.

- **Automatic acknowledgement wrote back verdicts that cited nothing.** The gate on the unattended
  write asked four questions: is the toggle on, is confidence above the threshold, did the run
  retrieve anything, is the alert high-stakes? None of them asked whether the report supported
  itself. Nothing downstream asked either: the confidence cap deliberately stands down when there
  are no citations to measure, because a ratio over an empty set is undefined rather than bad, so an
  uncited verdict keeps its full confidence and clears the threshold. On the deployed instance 1,315
  of 3,696 completed runs shipped a report that cited nothing and 834 of them were acknowledged in
  Security Onion, at a mean confidence of 0.77.

  The citation state is now a refusal in its own right, alongside the others. An uncited report is
  not acknowledged, and neither is one whose citations were all measured and none of them resolved.
  That second case is the worse of the two, because the report named its grounds and not one of them
  could be tied to anything the run retrieved. Partial coverage still acknowledges: the question is
  whether the verdict rests on something, not on everything, and the confidence cap already prices
  the shortfall. Measured against the recorded history, 834 of the 2,768 acknowledgements would have
  been refused on this bar alone, and 714 of those had retrieved something, so the retrieval bar
  above would have let almost all of them through. The control that matters holds: 1,776 of the
  2,768 both retrieved and cited, and every one of them still fires. The verdict itself is
  unaffected, and the drawer now says why the ack is waiting for a person instead of leaving two
  identical-looking cards to behave differently.

- **The second acknowledge path was forty times larger than the one that was repaired, and nothing
  could see it.** Auto-triage inheritance hands one investigation's false positive to every sibling
  alert on the same rule and address pair and acknowledges them in Security Onion. On the deployed
  instance's own audit index that path had written 110,693 acknowledgements since 2026-07-07, every
  one recorded `ok`, against 2,768 from the direct auto-acknowledge that the evidence bar was added
  to. It creates no investigation row and emitted no acknowledge event of its own, so it appeared on
  no surface in the product and the bar did not reach it.

  It now applies the same bar, closing the inheritance gap an older entry here records as open.
  The bar reads the recorded run rather than a live message history: a verdict is only lent
  to a sibling alert when the investigation behind it made a successful tool call, dispatched a
  Phase-D tool that returned discriminating data, or the Oracle called a tool in its own loop. The
  content test is one function now, shared with the live reading, because two implementations of
  "did this run retrieve anything" is how the two paths came to disagree. It fails closed: if the
  store cannot answer, nothing is written. Measured against the recorded history, a 24,000-write
  sample across July, August and September says 16.4 percent of the acknowledgements inherited a
  verdict from an investigation that had retrieved nothing, so roughly 18,100 of the 110,693 would
  have been refused. The verdicts are untouched and still read as confident false positives. They
  stop authorizing unattended writes.

  On the amplification: the inheritance key is `(rule, source ip, destination ip)`, and the sample
  says the key is not the problem. 24,000 writes fall into 393 clusters and none of them is a
  both-endpoints-empty catch-all, so no cluster is collecting unrelated traffic. The fan-out is a
  time integral rather than a batch: one verdict covers every future alert on that exact pair for
  the whole inherit window, which is a median of 11 acknowledgements per investigation, 146 at the
  90th percentile and 945 at the largest. The 27 sources that had retrieved nothing were among the
  loudest, averaging 145 writes each and reaching 790. The key is not being changed.

  Two records come out of every write now. An `auto_ack_inherited` audit record carries
  `inherited_from`, so an acknowledgement can be walked back to the reasoning that authorized it.
  The `ack_alert` records already written name the alert and the user string and nothing else. An
  `inherited_ack` row lands on the SOURCE investigation, which puts the running total somewhere
  durable and answers the question in the direction an analyst asks it: what has this false positive
  I closed three weeks ago been acknowledging on my grid since? One row per source, updated in
  place. The sweep runs every few minutes and the largest fan-out on record is 945, so a row per
  sweep would bury the investigation's own timeline under its aftermath. The auto-triage status
  reports the all-time total alongside the per-sweep count, and says why acknowledgements were held
  back.
- **A tool divided a 59-second burst by 30 days and handed the model the answer as a background
  rate.** A lateral-movement alert asked `rule_prevalence` for its signature's base rate. The tool
  returned 1531 fires, 51.033 per day, "occasional", with a `first_seen` and a `last_seen` 59
  seconds apart in the same dictionary. Checked against the grid, all 1531 documents fall in one day
  bucket, from one source host to one destination host, on a single source port, inside one TCP
  session. It is one burst, and the tool's docstring told the agent the per-day rate was the number
  to weigh. The run closed the only real intrusion in that window as a false positive at 0.85 and
  recommended acknowledging it.

  The error scales with how bursty the detection is: the reported rate is wrong by the ratio of the
  lookback to the burst, here about 43000 to 1. On the deployed instance, of 3798 recorded
  `t_rule_prevalence` results that claimed a rate, 270 divided by a window the data occupied less
  than 5% of, and 227 of those by a window it occupied less than 1% of. The worst was four fires at
  one instant divided by 90 days. Most of the tail understated rather than overstated, which pushes
  a bursty rule toward "rare" and toward escalation, so the fabricated number has been distorting
  triage in both directions rather than only closing cases.

  The rate is now computed over the span the fires actually occupy, and no per-day rate is emitted
  at all when that span covers under 5% of the window or the fires are clumped onto under a quarter
  of the days they span. `fires_per_day` is null there and `rate_basis` names the denominator when
  there is one. Both conditions are needed: 700 fires on day 1 and 800 on day 29 span 93% of a
  30-day window and are still two episodes. Offering a substitute number would invite the same
  mistake, so none is offered.

  Burstiness becomes the signal instead of the thing that gets erased. A new `burst` noisiness
  bucket, plus `is_burst`, `observed_span_seconds`, `active_days`, `span_fraction_of_window` and
  `burst_fires_per_minute`; source-port cardinality is now queried too, because one port is one
  session. Against the same alert the tool now returns: "fired 1531x in 59s on 2026-09-01 - one
  burst, 1 active day of the 30d window, from 1 source host / 1 dest host / 1 source port, and
  nothing before or after it. That is a single episode, not a background rate, so no per-day rate is
  reported."

  Guarding the inverse error mattered as much. A span-based rate alone would call 12 fires in six
  hours 48 a day and label a small clump background noise, so `noisy` and `occasional` now require
  the window average to agree with the span rate before either is claimed. The lookback-normalised
  figure survives only as that floor and is never reported. A rule that genuinely fires steadily
  across the window reports the same steady rate it always did, which is the control the change is
  pinned against.

- **A burst also cleared the bar for recommending the signature be muted.** `suggest_rule_tuning`
  reads the same alert count and its volume floors carry the same assumption, that the alerts
  recurred. The 1531 fires clear the mute bar by 15x, so with three of them acknowledged the tool
  would have recommended muting the signature that fired on the intrusion. It now asks for the span
  and the day histogram as well, and a burst can be surfaced but never muted. A separate defect in
  the same function: the heuristic counted `fp + tp + nmi` as its data points, and on the
  Elasticsearch path `nmi` is every alert nobody has touched, which made the floor satisfiable by
  volume alone and produced the line "investigated 1531x" about a rule no analyst had opened. The
  count is now the dispositioned alerts only.

- **A packet flood was reported as the most perfectly periodic beacon on the wire.** When every
  packet in a flow shares a timestamp the mean inter-arrival gap is zero. `_compute_inter_arrival`
  guarded that division by returning a coefficient of variation of 0.0, which its own docstring
  tells the reader means a perfectly periodic beacon. `cv` is `None` there now: unmeasurable rather
  than perfect. `beacon_profile` already carried a local guard for this case; `decode_pcap` did not.

- **`origin_chain` looked after the activity it said it looked before.** Every sentence the tool
  emits reads "in the N minutes before the activity", and its empty branch is the load-bearing claim
  "nothing was observed driving this host, so its behavior appears self-originated". It borrowed
  `query_events`' anchored time filter, which centers the window on the anchor, so at the default 30
  it read 15 minutes before and 15 after. A driving session 20 minutes earlier fell outside the
  window while sessions that happened after the alert were counted, named as peers, and offered as
  the closest preceding one. Re-running the lateral-movement alert, a verdict cited the tool for
  "inbound SSH sessions from admin before/after ... consistent with an admin-managed update push";
  the only session was six minutes after the alert. The tool now builds its own
  `[anchor - lookback, anchor]` window and drops any post-anchor hit alongside the existing
  direction guard. Centering stays in `query_events`, where the caller did ask for context around an
  alert.

- **`host_summary`'s DNS counts were a sample presented as a window.** `top_peers` and `top_ports`
  are aggregations over every matching document; `top_dns` is a tally over the 200-document sample,
  and all three sat side by side in the identical `{value, count}` shape next to a full-window
  `event_count`. On a busy host that reads short by three orders of magnitude. The key is now
  `count_in_sample` and `top_dns_sample_size` travels with it.
- **Every Elastic Defend document failed validation, so no hunt finding anchored on endpoint
  telemetry could be promoted.** `SoAlert.event_action` was typed `str | None`. ECS says
  `event.action` may be an array and Elastic Defend writes one: on the measured range every
  `endpoint.events.*` document carries `["start"]`, `["end"]` or `["start", "end"]`, which is
  175,812 of 919,839 documents in a 24h window, 19%. On the deployed grid the same planes are
  3,074,734 of 5,952,745 documents, 52%. Promoting such a finding produced an investigation that
  errored at its second timeline entry with zero tool calls and zero pivots: `1 validation error
  for SoAlert / event_action / Input should be a valid string / input_value=['end']`.

  Pydantic enforces the annotation by refusing the whole document, so one array field cost the
  reader every other field on it. `event_action` now reads through the same `_first` helper the
  neighbouring `event.category` has always used, and so does every other scalar attribute on
  `SoAlert`, `SoCase`, `SoDetection` and `SoPlaybook`. Elasticsearch has no array type and
  guarantees nothing about arity on any field, so enumerating the fields that "can" be arrays only
  postpones the next outage; the guard is a test that wraps every leaf of a realistic document in
  a list and asserts the model still parses it, which fails the moment a new scalar attribute is
  read without narrowing. Narrowing does drop the tail of a genuinely multi-valued field, and that
  is the smaller cost: the untouched document is still on `alert.raw`, whereas a refused one is
  unreadable in full.

  Three things fell out of the sweep. `zeek_ssh_auth_success` was computed as `bool(value)` on the
  raw read, so a list-wrapped `False` reported a FAILED SSH authentication as a successful one, and
  the same held for `zeek_ssl_established` and `zeek_dns_rejected`. `tags` had the asymmetry
  inverted: annotated `list[str]` and built with `list(...)`, so a grid writing the scalar
  `"alert"` produced the five tags `a`, `l`, `e`, `r`, `t`, silently and with no error. And the
  regression test guarding the behavioural-summary pivot used a list-where-a-scalar-is-expected
  document as its needle, which this fix makes valid, so the needle moved to a shape that still
  fails.

  The failure looks different to each caller, and the difference matters. On the promotion path it
  is LOUD: the prefetch retry wrapper deliberately does not retry a validation error, the
  orchestrator has no fallback for a failed prefetch, and the investigation lands `status=error`
  with the pydantic message in its timeline. On the best-effort pivots it is an ABSENCE: the
  behavioural-summary pivot catches every exception and returns `[]`, and auto-triage's
  inherited-acknowledgement pass logs a warning and skips the alert. Those read as "no such
  evidence" and "nothing to acknowledge" rather than as a parse failure.

- **The ambient inventory listed datasets and told the model to query them a way that matches none
  of their documents.** The "data available on this grid" block is rendered into the model's prompt
  as ground truth, and it said to ask for any listed plane with `event.dataset:<name>`. On the
  measured grid 374,688 of 919,845 documents in a 24h window, 41%, carry no `event.dataset` at all.
  Five `network_traffic.*` planes there are named only by `data_stream.dataset`, and one of them,
  the flow records, is the largest plane on the grid. The census was taught to find those planes
  earlier, so they appeared in the list. The filter the block implied still matched none of their
  documents. The model was handed a plane and a way of asking about it that returns nothing.
  This is the asymmetry that hid an entire network-metadata plane before, resurfacing one layer up:
  fixed at the census, still wrong at the prompt.

  The census is the only part of the program that knows which of its two aggregations produced a
  row, and it was discarding that when it merged them into one ranked list. `DatasetInfo` now
  carries the `identity_field` it was found under and exposes a `predicate`, and the block renders
  that predicate at the head of every line: `event.dataset:zeek.conn` for a plane that has one,
  `data_stream.dataset:network_traffic.flow` for a plane that does not. Nothing is inferred at
  render time, so a mixed grid gets the right filter on every row instead of one guess applied to
  all of them.

  A model that learns the right field from the block still meets tools that assume the other one.
  `t_describe_dataset`, `t_field_values` and `t_first_seen` now match a dataset name under either
  field, through one shared filter builder. Before this,
  `t_describe_dataset("network_traffic.flow")` answered "no documents", which reads exactly like
  the plane not existing.
- **Two alerts from one TCP session reached opposite verdicts, and nothing in the product could see
  they were the same session.** Twenty-eight minutes apart on the range: one true positive
  recommending escalation, one false positive recommending acknowledgement. Same source, same
  destination, same port, same community id, same fifty-nine second window. The second run's own
  prefetch matched a benign template and closed it with no tools. An analyst working the queue top
  down meets the false positive first, acknowledges on the product's recommendation, and never
  reaches the row saying the same session was lateral movement.

  The finest key an investigation row carried was `(rule_name, src_ip, dest_ip)`: no ports, no
  protocol, and a match only when the rule name matched too. So two sessions between one pair looked
  identical, and two alerts on ONE session looked unrelated. Migration 0038 adds the community id,
  which is the hashed five-tuple, stamped off the enriched alert exactly as the endpoints already
  are.

  Before synthesis the pipeline now asks whether a completed investigation already covered this
  session, and puts the answer into the prompt as a constraint rather than as context. It is
  resolved ahead of the decision-template fast path, because a template can close a case with no
  tools and a constraint arriving after that has arrived too late. A true positive on the session
  also forces the investigation loop, and deliberately not behind `memory_enabled`: that flag
  governs whether the model is shown resemblances it may weigh, and this is a contradiction inside
  one conversation.

  A deterministic gate has the last word, downstream of the Oracle and of the auto-acknowledge. It
  does not adopt the earlier verdict, because a gate that can promote a verdict is a gate that can
  invent one. It refuses the close: `false_positive` becomes `needs_more_info`, the acknowledge
  recommendation goes, and the note names the prior investigation. Both timelines carry the relation
  whether or not the verdicts end up disagreeing, so the analyst is told the two alerts are the same
  session either way. A true positive on a different session between the same two hosts changes
  nothing, and neither does an alert with no session behind it.

- **The Alerts footer and the preset chips counted rows the analyst had already filtered away.** A
  list showing one row was captioned "59 detections", and every preset chip carried the same 59.
  All of it was measured against the array the grid returned, before the severity facet, the verdict
  facet and the hide-acknowledged toggle were applied, so the caption described a list nobody was
  looking at. A count under a list is a claim about that list.

  The header and footer now count the rows on screen, presets included. The chips are counted after
  the facets and before the preset, which is what a chip badge means: how many rows clicking it
  would produce. Each chip runs the same match the list itself uses rather than a second copy that
  can drift, so the All chip and the footer can no longer disagree about the same list.

- **A configuration override that failed validation was written onto the live settings anyway, and
  bricked every later change.** `validate_assignment` runs the model validators after the field has
  been set, and pydantic does not put the old value back when one of them raises. So the assignment
  "failed", the key was correctly reported as not applied, and the rejected value was sitting on the
  settings object all the same. From then on every `setattr` re-ran the same validator and failed
  too, which meant every subsequent hot apply on that instance was refused with a message naming the
  setting that was stuck rather than the one the operator was changing. One bad value took
  configuration down and misdirected whoever tried to work out why.

  `POST /config/setting` and the Danger Zone save already prove an assignment on a copy before
  committing it. The shared apply path does the same now: each override is assigned to a throwaway
  copy first, and only a copy that validates gets the assignment for real, so a rejected value
  leaves the previous one in place. This covers the startup replay of stored overrides too, which
  is where a single bad row used to poison every override after it.

- **An escalate reported success for an alert it put on no case, and wrote that claim into the
  ledger.** Pressing escalate on a range investigation answered `{"status": "executed", "detail":
  "Case created: ..."}`. What Security Onion actually did was create the case, accept the attach,
  and attach nothing: the alert was not on that grid at all. The attach is query-shaped, so
  Security Onion rebuilds a search from the fields it is given and answers 200 with `{"count": 0}`
  when the search matches nothing, and soc-ai read the status code instead of the count.

  Two things went wrong at once and the second is the worse one. An empty case is now sitting in
  the queue wearing a title that reads like a real incident. And the escalation ledger, which
  exists so a second press cannot open a duplicate case, recorded the alert as escalated to that
  case, so the machinery would have refused to open the case actually needed. A duplicate-prevention
  record is only worth having if it is true.

  `escalate_to_case` now keys `alert_linked` on the count Security Onion reported rather than on its
  status code, and a 2xx whose body carries no count at all is treated the same way: an attach
  nobody observed is not a link. Nothing is stamped escalated over an attach that did not happen.
  The execute-action route reports the three outcomes as three different sentences (attached and
  stamped, attached but not stamped so the alert still reads untriaged in Security Onion's own list,
  or not attached at all) and only counts an escalate when the alert was genuinely linked. An
  unattached escalate takes a bare ledger claim instead of a resolved row, which reads as "soc-ai
  tried, outcome unknown" and is reconciled against the grid's case links on the next group press.
  Both the single-alert response and the group escalate name the empty case id, because closing or
  reusing that case is something only the operator can do.

  Reachable from the shipped product, not just from a test: the demo investigation ships with a
  pressable escalate card, and the same path runs on any live alert whose document rolled over or
  was deleted between a group scan and the write.
- **A pipeline error raised while the LLM gateway was unreachable told the operator to go and check
  Elasticsearch.** The fallback that records a failed run worked out which dependency had failed by
  reading the exception string. A refused gateway connection arrives as `ModelAPIError:
  "Connection error."` with nothing in it naming LiteLLM, so the ambiguous connect arm fell through
  to the grid branch and both the error event and the stored `pipeline_fallback` report carried
  "elasticsearch / Security Onion unreachable. Verify the SO grid is online and ES_HOSTS in
  soc-ai's .env points at the right node." Reproduced with a healthy grid and the gateway pointed
  at a closed port: the run landed a `needs_more_info` fallback whose only piece of guidance sent
  the analyst to the one dependency that was working.

  The phase already answers the question without guessing. The synthesizer runs, round 1, round 2,
  the loop synth and its partial-report variant, have no tools registered on them, and the
  investigation loop's tools each catch their own grid failure and hand the model a structured
  result, so no Elasticsearch exception can leave any of those phases. Phase-A prefetch is the
  mirror image and only ever reads the grid. Both surfaces now attribute by call site, and only a
  phase that could genuinely be either falls back to the string matching. The same outage now reads
  "the LLM gateway did not answer: soc-ai could not open a connection to it. This phase makes no
  Elasticsearch call, so the grid is not the problem."

  A gateway that never accepted the connection is a different fault from one that answered and
  could not reach its own backend, so the two now have separate remedies; the LiteLLM markers in
  the error string still separate them.

  The same misattribution ran in the other direction and is fixed with it: an Elasticsearch connect
  timeout inside prefetch renders as "Connection timed out", matched the generic timeout arm, and
  was reported as "LiteLLM gateway slow or unreachable", which prefetch never calls. A genuine grid
  outage still reads exactly as it did, verified byte for byte against the unfixed build.

- **The opt-out for partial Elasticsearch results was also switching off the report that the read
  was partial.** `es_fail_on_partial_results=false` is a reasonable answer to a chronically red
  shard: keep working off the shards that still answer rather than failing every query on the ones
  that do not. It reached the health probe through the same `ElasticClient.search` path, so an
  operator who set it had also, without being asked and without being told, turned off the one
  surface whose job is to say the grid is half-read. Reproduced against a grid answering HTTP 200
  in 7ms off 2 of 4 shards: `/api/v1/health` returned `es.ok: true` with the detail "readable", the
  topbar stayed connected, and the bell, which derives its dependency-down entry from that same
  probe result, had nothing to say. The operator who accepted short answers had bought silence
  about the cause along with them.

  The probe now reads with `require_complete=True`, the existing per-call opt-out from the opt-out,
  so it reports a partial read whichever way the setting is left. What a query does about a partial
  read stays the operator's call; whether anyone is told is not. The same grid now answers
  `es.ok: false`, `kind: "partial"`, naming the two failed shards and the shard reason, and the
  bell carries "reading only part of the grid".

  Two more consumers had the same conflation, and both are health surfaces rather than queries.
  `soc-ai doctor`'s `elasticsearch` check took the half-read grid's zero count at face value and
  reported "the events pattern matched no documents", with the remedy "check
  EVENTS_INDEX_PATTERN": a config diagnosis for a shard fault. `check_index_pattern_coverage` did
  the same, reporting "matches no suricata/auth/syslog events" with "wrong pattern or an idle
  grid", and it already had a `GridPartialResultsError` arm written for exactly this case, plus a
  docstring claiming it inherited the guard. The opt-out had made both the arm and the claim dead.
  Both checks now require a complete read, the coverage arm is reachable again, and the
  `elasticsearch` check gained a partial-read result of its own so a grid that answered in
  milliseconds is not filed as "unreachable" with a connectivity remedy. The coverage arm's hint
  moved from "fix Elasticsearch connectivity first" to shard health, for the same reason.

  The config console's help text for the setting now states the scope, so an operator can see what
  they are and are not turning off before they turn it off.

  A census of the remaining `ElasticClient.search` call sites that omit `require_complete=True`
  found the same exposure across a long tail of surfaces whose answer is a claim about absence or
  coverage rather than ordinary query data: grid inventory and dataset discovery, the alerts
  console's "quiet network" reason, the dossier's identity-retraction pass, auto-triage's degraded
  mark, and several agent tools whose own docstrings promise to distinguish "could not look" from
  "nothing there". None of those are changed here. Each needs its own answer to what the caller
  should do with a short read, and a blanket `require_complete=True` would hand an error page to
  the operator who deliberately asked for the opposite.

- **Triage was closing exploitation attempts as false positives without looking anything up, and
  acknowledging them in Security Onion.** On the deployed instance, 13 of the last 60 recorded runs
  reached a verdict with zero tool calls. All 13 matched `clean_internal_traffic`, all 13 settled
  false positive at 0.85 to 0.90, and all 13 were auto-acknowledged. Nine were the same alert: "ET
  HUNTING Potential Forced OGNL Evaluation - HTTP Body", an exploitation-attempt signature against
  an internal HTTP service, recurring daily since 2026-08-22 and closed unread every time. Three
  independent things had to be wrong for that to happen and all three were.

  **A decision template was seeding the verdict on network locality alone.** The template's grounds
  were that both endpoints were private and no blocklist named either of them. Blocklists never
  name an RFC1918 address, so the second ground is vacuous, and the first is true of every
  east-west flow on a flat network including an exploit landing on an internal service. Templates
  exist to make routine traffic cheap and turning them off would be a real cost, so the fix is a
  distinction rather than a deletion: a candidate is now `dispositive` or `provisional`. A
  dispositive template reads what the rule DETECTED, which is why STUN/QUIC keepalives, DNSSEC
  record queries and NTP keep the zero-tool fast path: the protocol's ordinary operation is the
  entire content of the alert and no retrieval would change the reading. A provisional template
  reads a property of the endpoints, or the absence of a reputation hit. It still reaches the
  synthesizer as a prior and still steers routing, but it cannot close a case.
  `clean_internal_traffic` and both external-reputation templates are provisional, and so is
  `policy_violation_internal`, whose second leg is the same locality test. The default is
  provisional, so a template added later does not inherit the fast path by forgetting to think
  about it. Registration order also moves `clean_internal_traffic` last: it matches any internal
  pair, so from fifth position it shadowed all three housekeeping templates on east-west traffic,
  which is why two production RRSIG alerts matched it instead of `dns_dnssec_housekeeping`.

  **The citation gate reported full coverage of an empty set.** `total: 0, valid: 0,
  coverage_ratio: 1.0` was the audit line beside a verdict that had cited nothing, on a
  vacuous-truth reading: no citation failed to resolve, so nothing is missing. That reads as full
  coverage and satisfies any coverage threshold a consumer might write, which is the empty-list
  bypass the 2026-07-30 review found in the evidence gate, in a second place. A ratio over an empty
  set is undefined rather than one, so it is reported as 0.0 with an explicit `vacuous` flag, and
  the timeline says the report offered no citations instead of quoting a number for citations that
  do not exist. The confidence cap skips the vacuous case on purpose: 41 of the 47 runs that DID
  call tools also emitted no citations, so shaving there would have coerced most of the grid to
  `needs_more_info` while telling nobody anything. Whether an uncited verdict may stand is the
  evidence gate's question, and it asks about retrieval.

  **The hard evidence gate treated a confident template as a substitute for retrieval.** Any benign
  candidate at 0.8 or above counted as "strong, rule-grounded" and settled the alert, which is why
  no `evidence_gate_downgrade` appears anywhere in 180 recorded runs. The exemption is keyed on the
  template's authority now, not on how sure it sounds, and it also requires the grounds to be on
  the record: a dispositive template lends its own `cited_evidence` to a report that cited nothing,
  so the analyst sees the reason the alert was closed rather than an empty list, and a report with
  no citations and no retrieval settles nothing whatever matched.

  **And automatic acknowledgement fired on all of it.** Confidence was the only quantitative
  condition on an unattended write to Security Onion, and a template supplies confidence without
  supplying evidence. Auto-acknowledge now needs a retrieval behind the verdict as well: a
  successful tool call, a Phase-D dispatch, or a tool call in the Oracle's own loop when the
  Oracle's verdict is the one being written. The verdict is untouched, so a template-settled false
  positive still reads as a confident false positive on the console and waits for a person; the
  run records `auto_ack_skipped` with reason `no_investigation` so the pending ack explains
  itself. This is deliberately independent of the two fixes above, so a future exemption added to
  the evidence gate is one step away from a write rather than zero.

  What to expect on the deployed instance: internal east-west alerts get an investigation instead
  of a locality anchor, which on the measured window is 13 more runs out of 60 entering the loop
  and the other 47 unchanged, because they already called tools. The daily OGNL alert stops being
  acknowledged unread. Alerts that a housekeeping template genuinely disposes of still settle with
  no tool calls, and now cite what they settled on.

- **No classtype guard in the product had ever matched a live Security Onion alert.** `classtype`
  is parsed from Suricata EVE's `alert.category`, and EVE writes the classification's DESCRIPTION,
  not its shortname. Every table keyed on it used shortnames: the alert classifier's map, the
  attack-classtype set that withholds a benign template from lateral movement, the auto-acknowledge
  high-stakes guard, and three decision templates. Across 180 recorded runs the field held nine
  distinct values and all nine were descriptions, among them "Attempted Denial of Service",
  "Attempted Administrator Privilege Gain" and "Malware Command and Control Activity Detected". A
  "GPL MISC Teardrop attack" carrying the denial-of-service description was auto-acknowledged
  twice, because the only arm of the high-stakes guard still working was Security Onion's own
  severity and that alert reads low. It stayed invisible for the same reason the Kerberoasting gap
  did in August: the synthetic eval scenarios render the shortname, so every test agreed with the
  code and nothing compared either against the grid. Classtype comparisons now go through one
  normalizer built from Suricata's own `etc/classification.config`. The mapping is exact, so an
  unrecognized value passes through rather than being guessed at, which leaves a local ruleset's
  own classifications alone and keeps shortnames idempotent. Reviving these guards also revives
  `policy_violation_internal`, which had never fired either.

  Not closed by this: the auto-triage sweep's inheritance path can still acknowledge a cluster from
  a prior false positive without applying the retrieval test, because the stored investigation row
  does not record whether that run retrieved anything. Closing it needs a schema change.

- **Elastic Defend endpoint alerts wore a Suricata badge.** `_kind_for` returns the generic `alert`
  for an alert-labelled document from a dataset it does not map, and the frontend coercion then
  turned that into `suricata`, the first detector the SPA's union happened to hold. On the measured
  grid that was 37 of the 40 alerts in the 24 hour queue: endpoint detections from an Elastic Agent,
  carrying no network flow at all, presented as network-sensor hits. The badge named the wrong tool
  and implied the wrong kind of evidence behind it. `alert` is now a kind the SPA understands, with
  a colour that belongs to no detector, and an unrecognized kind falls back to it rather than to
  Suricata. The investigation drawer's own kind chip is the shared badge now instead of a hand-rolled
  one that painted every kind in Suricata's blue.

  The kind is also what the console posts back when a group is expanded or acknowledged, so it can
  in principle steer a write. It did not steer this one: the group query branches on exactly two
  kinds, `notice` and `unnamed`, and everything else takes the same rule.name-scoped default, so the
  mislabelled groups resolved to a byte-identical query and no acknowledge or escalate ever landed
  on a document set the analyst had not seen. That equality is now asserted, alongside the two kinds
  that genuinely differ, because it stops holding the moment a third kind gets its own branch and at
  that point an upstream coercion would silently redirect a write.

- **The severity on an alert row was invented, and the row's own filter disagreed with it.** A
  shared coercion turned any severity outside the four-value ladder into `low` before the SPA saw
  it, so the 37 Elastic Defend endpoint alerts and 3 OpenCanary honeypot hits that were the entire
  24 hour queue on the measured grid arrived badged Low. Filtering that queue to Severity=Low then
  returned nothing, because the filter is a term query on `event.severity_label` and none of those
  documents carry the field. The screen showed a value its own control could not select, and it
  presented the three highest-signal alerts on the range at the lowest severity the product has. An
  absent severity is now reported and rendered as `unknown`: a badge with its own label, its own
  off-ramp colour and a hollow dot, because a filled dot on the same ramp as the four rungs reads as
  a position among them. The Severity filter offers it as an option, `?sev=unknown` survives the
  deep-link allow-list, and Acknowledge and Escalate accept it, so a queue narrowed to those alerts
  is one an analyst can act on rather than one they can only look at. The severity sort groups them
  at the end in either direction, the convention the confidence sort already used for a null;
  ranking them below Low would have put them back where they were hiding. The Dashboard's severity
  breakdown draws a bar for them, which it previously could not: they were counted in the group
  total and omitted from the four bars, so the bars under-read and the numbers beside them did not
  add up to the count above. `SeverityTag` no longer indexes its colour map unguarded either, which
  is what turned one unrecognized severity into a blank screen instead of one odd badge.

- **Auto-triage could not reach a single alert in the queue it was pointed at.** The alert-queue
  repair put 40 rows back on the console and the sweep half of it went on reading nothing, because
  the sweep asks for one severity at a time and every one of those asks is a term query on
  `event.severity_label`. None of these documents carry that field. Measured in-process on the
  deployed host over 24 hours: critical 0 groups, high 0, medium 0, low 0, no label 3 groups over 40
  events, which was the entire queue. An operator who ran the doctor, watched the filter check pass,
  counted 40 rows and turned the scheduler on got zero targets and nothing that said why. An alert
  with no `event.severity_label` now has a severity of `unknown`, which is a selector of its own and
  not a fifth rung: the query is `must_not exists` on the same field the console reads, so the row
  and the sweep are talking about the same documents. Every severity band carries it, at every
  floor including `critical`. A floor is a comparison and there is nothing to compare an absent
  label against, so the only two choices are to sweep those alerts or to drop them without saying
  so, and dropping them is the whole defect. Nor is there a number to fall back on: ECS defines
  `event.severity` as the source's own, and the three sources measured on one grid do not share a
  scale. Security Onion's Suricata pipeline writes 1, 2 and 3 next to the labels low, medium and
  high (3,907 documents over 30 days, one number per label, no exceptions); Elastic Defend writes 99
  out of 100 and no label; OpenCanary writes nothing at all. Reading 99 as a rung would be picking a
  scale on the shipper's behalf and would still leave the honeypot hits with nothing. The ladder part
  of a band is unchanged in content and in order, held by a negative control that pins the
  critical-then-high prefix and a second that pins the query a labelled severity is selected by,
  because most of the grid's history does carry a label. The degraded-run label for a failed
  unlabelled read says "alerts with no severity" rather than "severity unknown", which would read as
  not knowing which query failed.
- **Pressing escalate on a group twice opened two Security Onion cases for the same alert.** The
  guard added for this read `event.acknowledged` and `event.escalated` off the alert document and
  skipped anything carrying either. Attaching an alert to a case does not write either flag:
  `POST /api/case/events` creates a related document on the case and touches the alert not at all.
  So the guard held for alerts something else had already acknowledged, which is the case where a
  duplicate was never in question, and did nothing at all for an alert that had just been escalated.
  Measured on the range on 2026-09-06 against an 18-event Elastic Defend endpoint group holding
  exactly one unwritten alert, two presses six seconds apart: both answered
  `{"escalated": 1, "already_escalated": 17}`, and the grid ended with two cases whose related
  documents both point at the same alert. Cases are not something an operator can quietly undo.
  Whether an alert is on a case is now a fact soc-ai records rather than infers. A new
  `alert_escalations` table (migration 0037) holds one row per escalated alert with a unique index
  on the alert id, and the row is claimed BEFORE the case is opened, so a second press and a second
  operator both collide on the insert rather than on the case. A read-then-write check could not do
  that and neither could the grid, whose case index is a refreshed read: the second of the two
  measured presses was six seconds behind the first and the case it would have had to see was not
  visible yet. Behind the ledger, Security Onion's own case links are queried for the alerts of a
  press, which is the only source that sees a case opened from Security Onion's console or by
  another soc-ai instance; that query is best-effort, because letting it fail the escalate would
  trade a recoverable gap for an outage, and a degraded read raises rather than answering "no case"
  since the caller uses absence to decide it may open one. The single-alert escalate an analyst runs
  from an investigation writes the ledger too, so a group press covering the same alert can skip it
  without having to reach the grid at all. Re-verified live after the change: three presses on a
  20-event group produced one case, and a press on an alert carrying two cases opened before the
  ledger existed opened no third one. Known and not addressed: a single-alert escalate and a group
  escalate racing on the same alert in the same instant can still both open a case, because only the
  group path takes a claim.
- **The message after a group escalate was false in both directions at once.** It reported
  "17 events already escalated, not opening a second case" on a press where not one of the seventeen
  had a case, and reported the one alert that really did collect a second case as a clean escalate.
  The count behind it was every alert the press skipped, and the press skipped on acknowledged OR
  escalated, so a dismissal and a case were the same number. They are now separate facts with
  separate sources: `already_escalated` counts only alerts a case was withheld from, `already_acked`
  counts alerts Security Onion had already acknowledged, and `unresolved` counts alerts an earlier
  escalate claimed and never came back from, which are neither escalated nor safe to escalate and
  are left alone rather than folded into a count that would be wrong either way. The strip now reads
  "Opened no cases for X · 1 alert already on a case, no second case opened · 17 alerts already
  acknowledged in Security Onion, skipped". The API field `already_escalated` has narrowed. It no
  longer counts acknowledged alerts.
- **An alert soc-ai escalated still read as untouched in Security Onion's own alert list.** Security
  Onion's console makes three writes when an analyst escalates; soc-ai made the first two and left
  the alert unflagged, so the analyst working that list had nothing to tell them the alert was
  already case work and escalated it again. The escalate tool now makes the third write,
  `POST /api/events/ack` with `escalate: true`, which closes the gap an older entry here records as
  open. That also acknowledges the alert, and it is not a separable choice: measured on a live
  SO 3.2.0 grid on 2026-09-06 with one variable changed per probe,
  `escalate:true, acknowledge:true` set both flags and `escalate:true, acknowledge:false` set
  neither, so Security Onion applies the acknowledge value to both and there is no request shape
  that stamps escalated alone. The console behaves the same way and taking an alert that is now case
  work out of the triage queue is the right outcome. The write is best-effort and is only attempted
  once the alert is actually attached: the case exists the moment Security Onion answers the create,
  so raising on a flag would make the caller retry and open the duplicate, and stamping over a
  failed attach would hide a live alert behind a link that is not there. A flag that would not stamp
  is reported in `mark_error` with `marked_escalated: false`.
- **A decoy interaction was auto-closed on a volume baseline, which is the reasoning a decoy exists
  to defeat.** An OpenCanary honeypot recorded an inbound SSH interaction from an internal router
  and triage returned false_positive at 0.9: "This is routine east-west management traffic: over
  the prior 72h the router made 358 SSH connections to internal hosts (111 to one host)." The
  honeypot's own log, the authoritative record of what touched it, held 17 documents over its whole
  retention, of which exactly two came from that source, ever, both of them this interaction; in
  the hour that supplied 101 of the 111 claimed connections it logged no SSH events at all. The
  count is fixed separately. This is about the route. The catalog spec for this detection says in
  its own text that nothing has a legitimate reason to talk to a decoy, because it advertises
  services that exist only to be touched, sits in no DNS zone and serves no workload, so unlike
  every other detection there is no benign population to separate from and therefore no threshold,
  no baseline and no tuning. Triage built a baseline and concluded routine, and that route
  generalises to a miss: "the router talks to this host a lot, so a decoy hit from the router is
  routine" auto-closes an intruder pivoting through the router. Correcting the number would not
  have been enough. A second run on the same alert closed it at 0.85 by a different argument,
  naming the decoy, noting the absence of a credential attempt and still calling it routine
  internal east-west traffic. So the refusal is on the verdict class rather than on the prose,
  which pattern-matching would have missed. A false_positive on an alert from a deception sensor is
  now coerced to needs_more_info with confidence capped at 0.4; a true_positive and an already
  unsettled verdict pass untouched, since the concern is closure, not escalation. The spec's own
  false-positive list, an authorised scanner and the operator's own validation, says both are still
  worth seeing, so needs_more_info is where they belong rather than an automatic close. The
  decision template got there first and is fixed at the same choke point: `clean_internal_traffic`
  seeded false_positive at 0.85 before a single tool ran, on the sole ground that both endpoints
  were internal, which a decoy interaction always is because the decoy sits inside the network it
  protects. Benign templates are now withheld for the whole class in `match_decision_template`, so
  a template added later cannot reintroduce the anchor by forgetting a guard. The refusal also runs
  on the Oracle path, because it is what sends the case there: capping a refused decoy at 0.4 puts
  it under `oracle_escalate_below_confidence`, so the Oracle gets asked exactly the question the
  local path just declined to answer benign, and the parity block previously re-ran only two of the
  deterministic downgrades. The same reasoning shape threatens the non-machine DCSync spec, whose
  precision also comes from an exclusion that leaves no benign population; that one is not gated
  here and is noted as open.

- **A count that did not say what it counted was read as the wrong unit, and closed an alert.**
  `t_query_events_oql` ran `source.ip:<router> AND destination.port:22 | groupby destination.ip`
  over the events index and returned `total: 358` with bucket `doc_count` values, an empty `hits`
  list and nothing saying what had been counted. The triage run wrote that up as "the router made
  358 SSH connections to internal hosts (111 to one host)" and closed a honeypot alert on it. The
  arithmetic was right and the sentence was wrong: measured on the development range on 2026-09-06,
  348 of the 358 documents were periodic packetbeat flow records, 3 were endpoint network events
  and 2 were the honeypot's own log. A flow record is re-emitted per interval, so one session
  yields many documents, and the 106 documents naming the honeypot carried 19 distinct source ports
  in two hourly buckets across the whole three-day window. Two bursts, described as a routine. The
  events index is a superset of every sensor on the grid, so this is not one query's problem: any
  count drawn from it can span datasets the reader never considered, and a bare integer under a key
  called `total` takes the unit of whatever question was asked. Every OQL result now carries a
  `counted` block naming the unit, the index pattern and the dataset composition of the documents
  behind the number. The composition is read from `data_stream.dataset`, falling back to
  `event.dataset` on grids without data streams. On this grid `event.dataset` was absent from 348
  of the 353 documents, which is why the field that names the most of them is the one reported. The
  reserved aggregation is stripped before the result is handed over, so a model that asked for one
  `groupby` still sees exactly one. Two test doubles had encoded "a request carrying aggregations
  wants no hits" and returned empty reads once every query carried one; both now answer the way
  Elasticsearch does, which the hunt-journey test caught and the demo mock did not.

- **A hunt spec could report a clean grid while deleting every document it was written to find.**
  The earlier fix in this release made a `none` clause also require the field it reads, because a
  `must_not` over a field a document does not carry excludes nothing and a spec whose precision
  came from excluding machine accounts lost that exclusion on an Elastic Defend copy of the same
  event: 78 candidates, 74 of them the population the exclusion existed to remove. The
  precondition inherited the same requirement, and the stated safety net was that a grid where
  every copy lacks the field returns zero on the precondition and reads blind rather than clean.
  That net only fires on total absence. Windows writes no `winlog.event_data.SubjectUserName` on a
  network logon at all, because the subject is the null SID, so a field can be sparse inside the
  dataset the spec is written against. Measured on the development range over 2026-09-05, with
  soc-ai's own compiler and one query per row, on a reconstructed 4624 spec excluding machine
  accounts: 10,844 documents in the precondition and 5,240 in the detection before the presence
  rule; 182 and 0 after. 182 is greater than zero, so the run was not blind, and it reported an
  all-clear over 5,240 documents that matched its positive clauses. Nothing in a document
  distinguishes a field absent because this is a different-schema copy from a field absent because
  Windows does not populate it for this type of event, so the compiler no longer guesses either
  way. The exclusion still requires its field, and the documents that requirement removes are now
  counted by their own query and reported as a coverage gap: neither matched nor silently dropped,
  and a run holding one of them is not clean. A spec author who knows what absence means on their
  data declares it on the clause with `absent: match`, and one who wants a single copy of a
  double-shipped event pins `event.dataset` in `all`; there is deliberately no declaration for
  "treat it as excluded", since that is the silent drop. The precondition stops inheriting the
  exclusion's field, because a document missing it is inside the population and undecidable rather
  than outside it, and subtracting it from the denominator is what let the run call itself clean.
  It still inherits the fields the `all` block reads by value, which is what keeps the duplicate
  copy out. Both failure modes are held by negative controls: the 4648 case is asserted unchanged
  in both engines, and a property test says no document the tree returned before the presence rule
  may now be neither matched nor counted. The four shipped specs do not change meaning, and their
  fixture counts are identical for matched documents, candidates and scope keys, with no undecided
  documents in any of them; on the live grid the two specs with exclusions read the same either
  way (4662: precondition 86, detection 3; 4769: precondition 5393, detection 1), because every
  document their positive clauses match carries the field their exclusions read. Known and not
  addressed here: a positive clause on a field the second copy lacks is still a decided non-match,
  so a spec whose whole discriminator sits in an `any` block is blind to that copy without saying
  so.
- **A sweep that found nothing to surface recorded nothing, whatever else the run was holding.** A
  seeing run can be un-clean with no candidates in three ways: documents it could not decide,
  documents it matched and could not group by scope, and documents the bucket ceiling left out.
  `candidate_findings` writes a visibility-gap finding for each, and the sweep's early return asked
  only whether a candidate had survived the gate, so none of them ever reached a hunt, a
  notification or the trail. The un-clean run now gates on the same visibility-gap scope a blind
  run uses, so it reports once and re-reports on transition, and the gap is stripped before the run
  is rebuilt so it cannot render as a finding about an entity called "visibility-gap". Two things
  that turned up on the way: the gate's already-handled count was including the gap, and the sweep
  suite's own fixture returned a detection total of 2 against an empty bucket list, so every case
  in that file called clean was really a run holding two unattributable documents. Nothing noticed,
  because a run with no candidates recorded nothing.
- **The empty-queue explanation recommended an undocumented label and no value.**
  `GET /api/v1/alerts/empty-reason` ranks the alert labels by how many documents each matched and
  names the winner. Ties went to whichever label `ALERT_LABEL_CANDIDATES` listed first, an order
  written for the doctor's output rather than for a recommendation, and that put `tags:alerts` ahead
  of `event.kind:alert`. The plural is measured but its mechanism is unconfirmed, this module's own
  docstring says so, no Security Onion pipeline is known to write it, and it is a strict subset of
  what the product ships as its default. A tie now goes to a label the shipped default already
  unions. The sentence also ended at "Change WEBUI_ALERTS_QUERY in Config → Queries", which leaves
  the analyst where they started, so it now names one exact filter: the configured filter widened
  with the label that beats it, the same superset rule `soc-ai doctor` follows, through the same
  helper. The unparseable-filter branch had the same gap with nothing to widen, and now names the
  shipped default. A label that genuinely wins on count is still named with its number, tie-break or
  not: a route that refused to say `tags:alerts` at all would hide the larger figure on the grid
  this was measured on, which is the same defect one preference deeper.
- **An alert with no rule name had no row in the queue and no place in the count.** The alerts
  console buckets alerts on a terms aggregation over `rule.name`, and a terms aggregation has
  nowhere to put a document that does not carry the field, so those documents produced no bucket,
  no row and no count while still matching the filter. Measured on 2026-09-06: the shipped filter
  matched 38 documents over 24 hours and the console could show at most 35. The three it dropped
  were OpenCanary honeypot alerts, which on the range this was measured on are the one surface
  nothing benign touches, so the alerts that disappeared were the highest-signal ones present. The
  numbers to catch it were already on screen and in `soc-ai doctor`, in different places and never
  compared. A sibling aggregation in the same request now picks up exactly the documents the terms
  aggregation cannot see and groups them by `event.dataset`, the most specific thing still true of
  an alert with no rule name, with a bucket of last resort for one carrying no dataset either. Those
  rows come back under a new group kind, `unnamed`, because expanding or acknowledging a group posts
  its kind back and every other kind resolves the group's name against a name field these documents
  do not have; coercing it to a detector kind would have produced a row that counts three and
  expands to nothing. Re-verified against the live grid after the change: 39 matched, 36 in named
  buckets, 3 unnamed, so the rows now add up to what the filter matched. No row is invented when
  every alert has a name, which is pinned by a test: a permanent empty "(no rule name)" group is
  the kind of row an analyst opens once and never opens again.
- **The Dashboard's setup-health card said "All checks passing" while two checks were warning.**
  `GET /health/preflight` reports `status` as FAIL-driven, matching the exit code `soc-ai doctor`
  returns on the CLI, so a grid whose only problems are WARNs answers green with a non-zero
  `warned`. The card read `status` and nothing else. Measured on a live deployment on 2026-09-06:
  `{"status":"green","failing":0,"warned":2}`, while one of those two checks was warning that 34
  alerts on the grid never reach the triage queue. The count was already on the wire, in the same
  response, and nothing read it. The card now goes green only when both counts are zero, names
  warnings in their own words and their own colour rather than in the failing count's, and fetches
  the admin-only detail rows for a warning as it already did for a failure, so an admin sees which
  check and what to do rather than a bare number. The analyst view keeps its counts-only boundary.
  The route is unchanged: its `status` still means what the CLI means by it, and reusing that as
  "is anything wrong" was the client-side mistake. Two checks were warning, not one, so this was
  never specific to the new alerts-feed-filter row.
- **The doctor's remedy for a filter that hides alerts could hide different alerts.** The new
  `alerts feed filter` row warns correctly and then said "Set
  `WEBUI_ALERTS_QUERY=event.kind:alert`", naming the label that found more instead of a filter that
  keeps what the operator already has. On the grid measured on 2026-09-05 the two labels had zero
  overlap: `tags:alert` matched 2 documents, `event.kind:alert` matched 34, and the 2 carried no
  `event.kind` field at all. Those 2 were that grid's DCSync detections, the highest-value alerts
  on it, so pasting the hint verbatim would have dropped them and left a queue that looked healthier
  than before. The product already ships the right answer, a union of both labels, and the check now
  recommends the operator's own filter ORed with the label that beats it, which is a superset by
  construction. `soc-ai doctor` on that grid now says
  `Set WEBUI_ALERTS_QUERY=tags:alert OR event.kind:alert`. No parentheses are added because `OR` is
  OQL's lowest-precedence operator, so a compound filter such as `tags:alert AND host.name:x` widens
  correctly as written and the value stays pasteable; a test pins that on the compiled query rather
  than on the string, since a grammar where `OR` bound tighter would turn this widening into a
  narrowing. Only the best alternative is added, so a grid spreading alerts over three disjoint
  labels converges over two doctor runs instead of being handed a filter with labels it has no
  alerts under. A filter the query builder cannot parse has no coverage to preserve and would not
  survive an `OR`, so that branch recommends the shipped default instead of the last candidate in
  the list. The default is now one named constant that the field default, the doctor and the alerts
  console all read, with a test that fails if they drift apart.
- **Bulk acknowledge re-acknowledged the same alerts on every press and reported success every
  time.** Acknowledging a detection group fetched one page of events the hide-acknowledged filter
  had not excluded, acknowledged up to 199 of them, and left the rest for another press. That works
  only where an acknowledged event drops out of the next query. On Elastic Defend's endpoint alert
  index it does not: `.ds-logs-endpoint.alerts-default-*` is mapped `dynamic: false` and carries no
  `event.acknowledged` field, so Security Onion writes the flag into `_source` where no query can
  reach it. Measured on 2026-09-06 against a 16-event endpoint group: all 16 acknowledged, Security
  Onion answered 200 to each, and the very next fetch with the same filter returned the same 16 ids.
  A group larger than the cap could therefore never empty, and the answer said only "capped", which
  the console rendered as an invitation to press again and finish. It never finished. Suricata
  alerts in the same measurement behaved correctly, which is why the gap survived: the index the
  console was mostly pointed at hid its acknowledged events, and the one that did not was the newer
  source. The fix reads the flag off the document instead of asking the query for it. Events
  Security Onion already records as acknowledged or escalated are skipped rather than rewritten, the
  scan pages past them up to a bound of 2000 documents, and the answer now carries two numbers
  instead of one flag: how many are left, and how many the grid will keep listing no matter how many
  times the button is pressed. The same skip is applied to group escalate, where a repeat press was
  worse than wasteful: it opened a second Security Onion case for every alert the grid still
  listed. What an operator sees now, on the endpoint index: the first press acknowledges the group
  and the rows stay, because the grid cannot hide them; the second press says the alerts are already
  acknowledged in Security Onion and writes nothing. On every other index the behaviour is
  unchanged, and a group over the cap now reports the real number outstanding (measured: 1,332 left
  of 1,531) rather than a bare flag. Not fixed here, because it is not ours to fix: the endpoint
  alert index still cannot hide an acknowledged alert, so the group keeps its count. That is an
  index mapping on the grid.
- **Escalating an alert to a case, and commenting on a case, both posted to a route Security Onion
  does not serve.** `escalate_to_case` posted to `/connect/case` and `add_case_comment` to
  `/connect/case/{id}/comment`. `/connect/` is not a Security Onion route at all: it is an nginx
  alias that rewrites to `/api/`, and Security Onion only renders that alias when the grid carries
  the licensed `api` feature. On a grid without it, every case write soc-ai made was answered by
  nginx's own 404 page, so cases were readable and not writable, and the tools reported an error
  that named a path the operator could not find in any Security Onion document. Acknowledge had
  already been moved to the web API in an earlier release; these two were left behind. Settled
  against the live grid rather than by pattern-matching the old paths: Security Onion serves its own
  console's Vue sources unminified, so the routes its Escalate button calls can be read directly,
  and each candidate was then exercised end to end. `POST /api/case/` returns the new case document,
  `POST /api/case/comments` takes `caseId` and `description` in the body and returns the stored
  comment, and `POST /api/case/events` attaches an alert to a case by its `soc_id`, answering 202
  once the attach is queued. The per-case path shape the old code assumed, `/api/case/{id}/comment`,
  404s. Escalation is now the two writes the console itself makes, create then attach, and the
  result says which of the two happened: a failed attach reports the case id with `alert_linked`
  false rather than raising, because the case already exists by then and a retry would open a second
  one. Not fixed here: soc-ai does not stamp `event.escalated` on the alert, which the console does
  as a third write, so an escalated alert still shows as unescalated in Security Onion's own alert
  list even though a case now references it.
- **Acknowledging an Elastic Defend endpoint alert failed, because the ack carried a scope filter
  the alert could not match.** Security Onion's `/api/events/ack` ANDs the body's `searchFilter`
  with the `eventFilter` that pins the document by id, so a scope naming one alert label silently
  excludes every alert written without it. soc-ai sent the literal `tags:alert`, which held only
  while the feed showed nothing else. Widening the feed's default to include `event.kind:alert`
  made the gap reachable: Elastic's package pipeline writes Defend endpoint alerts, they never
  reach the pipeline that derives Security Onion's tag, and they carry the ECS field instead.
  Measured on a live grid on 2026-09-05, one variable changed per probe in the same session:
  `tags:alert` acknowledged a tagged Sigma alert (200, one document updated) and refused a Defend
  endpoint alert (400, still unacknowledged), and a permissive scope acknowledged that same
  endpoint alert (200, one document updated). Security Onion returns the same bodyless 400 for an
  expired token, a zero-match filter and an already-acknowledged alert, so nothing in the response
  said which of the four it was, which is why this was settled by experiment rather than by
  reading. The scope is now permissive. The id pin is what narrows the write, and it is not
  advisory: the same probe run over a window holding roughly fifteen documents updated exactly one,
  and a wide-window acknowledgement across a 23-million-document grid also updated exactly one.
  The scope is deliberately not derived from `webui_alerts_query` either, since the feed unions
  that setting with other sources and an operator who narrows it would narrow their ack scope with
  it, rebuilding the same defect one config edit later. `_EVENT_ID_RE` already rejects an empty or
  malformed id before any HTTP call, so an acknowledgement cannot go out unpinned. Known and not
  fixed here: on that grid `event.acknowledged` is written into the endpoint alert's `_source` but
  is not an indexed field on `logs-endpoint.alerts-*`, so an acknowledged Defend alert still reads
  as unacknowledged to any query, including the console's hide-acknowledged filter and its
  per-group acknowledged counts. That is an index mapping on the grid, not something soc-ai writes.
- **A visibility gap could only ever be reported once, whatever happened afterwards.** The sweep
  records a blind or errored spec run on a `visibility-gap` scope so the gap reports once instead of
  on every sweep, and its own comment says the gap re-reports on transition: blind, then seeing,
  then blind again. It did not. Nothing in the gate retired a terminal row, so the first coverage
  gap a spec ever recorded was the last one it could record. Probed rather than reasoned about:
  blind reports, seeing clears the run flag, blind again reports `blind_reported=0` and records no
  second hunt. This bites hardest on a deployment that already logged a gap for the decoy spec
  before it was fixed to read a quiet honeypot as clean rather than blind, because the report it
  will need the day that honeypot really dies has already been spent on the bug. A live sweep that
  carries no gap candidate now retires the spec's gap, since that call is the spec saying it can see
  its plane again, and a later gap is news. Migration 0035 adds `hunt_spec_state.retired_at`.
- **A visibility gap on a grid returning partial results re-fired every sweep.** The same path, the
  opposite symptom, and live before this change. The gap fingerprint carried the reason string, and
  an errored run's reason is the exception text: a partial-results error names how many shards
  failed, and an Elasticsearch API error frequently names a concrete backing index whose generation
  changes at each rollover. A grid failing two shards and then three produced two fingerprints for
  one outage, so the gate treated the second as a new thing to say. The gap is now keyed on its
  scope rather than its fingerprint, so while a spec's gap is open a change of reason is a change of
  detail on the same gap. Stabilising the reason strings was the alternative and is the weaker fix:
  it holds only until somebody adds an error message with a request id in it, and no test could
  notice.

- **An exclusion stopped excluding when the same event code arrived from a second dataset.** A host
  running both the winlog integration and Elastic Defend ships every Windows security event twice.
  The `system.security` copy carries the full `winlog.event_data` tree; the `endpoint.events.security`
  copy carries the same `event.code` and none of it. An Elasticsearch `must_not` over a field a
  document does not have excludes nothing, so a spec whose precision comes from excluding machine
  accounts lost that exclusion entirely on the duplicate. Measured on the development range on
  2026-09-05: event code 4648 arrived 154 times, 77 from each dataset, and not one endpoint copy
  carried `SubjectUserName`. Compiled as the clause form then was, that spec returned 78 candidates
  of which 74 were the machine accounts the exclusions exist to remove. That is 98.7% false
  positives from a clause written correctly. A `none` clause that reads a value now compiles to
  "has the field and does not match it", and the in-memory evaluator says the same. Positive
  clauses never had the problem, because a term query cannot match a field that is not there. None
  of the four shipped specs was exposed, by luck of which event codes Elastic Defend subscribes to,
  and each reads at least one `winlog.event_data` field in a positive clause; their detections are
  unchanged in meaning. The two engines used to agree here and agree on the wrong answer, which is
  why the CI coverage gate could not have caught it: a missing field makes the in-memory clause
  False, so `not any(...)` admitted the document exactly as `must_not` did.
- **A spec on a dual-sourced event code reported double the documents it examined.** The same
  duplication inflated `precondition_docs`, which a catalog finding states in prose: "the spec could
  see. Its precondition matched N documents". A precondition of `event.code 4662` alone counted both
  copies. Schema presence is now a scope in the same sense as the provenance and synth scopes, so it
  is applied to both queries: the precondition requires every field the detection reads by value.
  That also keeps the exclusion fix above from becoming a silent miss. Narrowing the detection with
  nothing reporting the narrowing is how an all-clear gets invented, and now a grid where every copy
  of an event lacks the field returns zero on the precondition and the run reads BLIND, a stated
  coverage gap, rather than clean. Fields read by an `op: exists` clause are left out, because there
  the presence is the detection: inheriting it would collapse the decoy spec's precondition into its
  detection and make a honeypot that only ever booted read blind instead of clean. `any` fields are
  left out too, since alternatives cannot all be required at once. The three Windows identity specs
  now count the copy that carries their fields, which on a grid shipping both copies is half what
  they counted before; the decoy is unchanged. Running all four fixtures, no detection moved: same
  matched documents, same candidates, same scope keys. The only number that moved is s1's
  precondition, 6 documents to 5, and the one it dropped is the duplicate the fixture now plants.
- **The dataset census counted an imported file as live telemetry.** It applied the synthetic-data
  kill switch and nothing else, so `so-import-pcap` and `so-import-evtx` loads and replayed corpora
  were counted as sensor output. On the measured grid the default 24 hour window was clean only
  because the last bulk import had landed thirty hours earlier; at 48 hours 91.3 percent of every
  document was backfill, and the host dossier deliberately widens the window and walked into it.
  The visible damage was recency: the census reported the newest Suricata alert as five hours old
  when the sensor had been dead for three days, because the document it read had an import marker
  and a file path under an import directory. Volume and recency are now measured over live
  telemetry alone, using the same provenance filter every hunt spec query already applies.
  Imported documents are not hidden. A grid that holds imported evidence is a real situation and
  suppressing it is its own kind of lie, so imports are counted beside the live figures and a plane
  with backfill and no sensor behind it reads "no live events, 18.8M imported" rather than
  vanishing or masquerading as a working sensor. `last_seen` can no longer be satisfied by an
  import, the ranking is by live volume so one imported file cannot outrank every sensor, and the
  host dossier now gates its identity searches on live planes only: resolving a host out of an
  imported event log names it after whatever the import contains.
- **A hunt template required a dataset that cannot exist.** "Suspicious PowerShell / LOLBins"
  declared `endpoint`. Elastic Defend has no such data stream: process execution is
  `endpoint.events.process`, loaded modules are `endpoint.events.library`, and so on. Availability
  is an exact string match against the grid census, so the template reported missing telemetry on
  every Elastic Defend deployment there has ever been, including the measured grid, which carries
  20,760 process documents and 13,719 PowerShell documents in a day. It now requires
  `endpoint.events.process`, and a startup re-seed refreshes the value on grids that already have
  the row. The other six builtins were audited against Security Onion's own ingest pipeline names
  and Elastic Defend's data streams and were all correct: `zeek.conn`, `zeek.dns`, `zeek.kerberos`,
  `zeek.smb_files`, `zeek.rdp` and `zeek.dce_rpc` are all names Security Onion writes. A test now
  checks every declared name against that vocabulary, so the next one is caught before it ships.
- **The biggest plane on the grid was listed thirty-second.** The dataset census runs two
  aggregations, one over `event.dataset` and a fallback over `data_stream.dataset` for the
  documents that carry no `event.dataset`, and it appended the second list to the first instead of
  ranking them together. Each list arrives sorted by count, so the result was two orderings glued
  end to end. On the measured grid that put `network_traffic.flow`, 39 percent of every document
  there and the only surviving network-metadata sensor, below a dataset holding two documents. The
  inventory says most-populated-first and the model reads it as a ranked list, so it is now one
  ranking over both censuses, with ties broken on the dataset name so an unchanged grid reads the
  same way twice.
- **The count of documents a spec could not decide never reached the screen built to catch a spec
  gone dark.** The repair that landed with this release counts documents an exclusion could not be
  evaluated against, marks the run not clean and reports it on the command line, in a hunt, in a
  notification on the transition sweep and in a database column. The Hunt Catalog panel on the
  Operate hub, whose own source says a spec gone dark "would otherwise read as clean", could not
  read any of it: `GET /api/v1/hunt-catalog` carried no such field, so a spec discarding thousands
  of documents an hour rendered "fired 0, fresh 0, handled 0, last swept 2m ago", which is exactly
  what a healthy quiet spec renders, from the second sweep onward forever. That is not a gap the
  existing counters could close, because a run that discards everything matches nothing, buckets
  nothing and fires nothing, so every counter on the row is honestly zero. The newest sweep's
  undecided count now travels from the trail row through the read model and the route to a marker
  on the spec's row, in the amber the blind and shadow markers already use, with the count on the
  chip and the remedy in its tooltip. It is the newest sweep's fact rather than a 24h rate, like
  `blind` and the last error beside it, so a spec whose grid started carrying the field again loses
  the marker on its next sweep instead of wearing it for a day. Measured against a live deployment
  before the change: the route returned no undecided field at all, and the word appeared nowhere in
  the API, the web layer or the frontend. A healthy spec growing a marker would be the worse
  failure of the two, so that is what the negative controls pin, on the store, the route and the
  panel.
- **The finding about undecided documents named a field that every one of them carried.** The
  sentence joined all of a detection's exclusion fields and said the documents "carry no value for"
  them. The compiled query requires only that at least one is missing, so the claim is false as
  soon as a spec has two exclusions on two fields. Measured on the range on 2026-09-06 with a
  reconstructed two-exclusion 4624 spec over 24 hours: 6,138 undecided documents, every one of them
  carrying `user.name` and none carrying `winlog.event_data.SubjectUserName`, so the first field
  the sentence named was present on all 6,138 documents the sentence was about. The cost is not
  only accuracy. The remedy the product offers is a per-clause declaration, so an analyst told
  those documents lack a field can add `absent: match` to the wrong clause, watch the number stay
  where it was, and conclude the gap is handled. The undecided query now carries a named `filters`
  aggregation, one bucket per exclusion field, so it comes back with how many of those documents
  were missing each field at no extra round trip, and the finding names only the fields something
  was actually missing. With one field, which is both shipped specs with exclusions, the sentence
  is unchanged. With several it names each with its own count and says "at least one", because a
  document can lack two fields and be counted in both. If the grid returns no breakdown the finding
  falls back to the weakest claim the query itself guarantees rather than naming a field as absent
  on no evidence. The gated rebuild the sweep composes its findings from carries the breakdown too,
  which is where a fix like this usually goes missing.
- **The split that keeps a spec's old measurements from reading as fresh ones never fired on a
  visibility-gap finding.** A catalog finding's detail is the spec's prose, written and reviewed
  when the detection was authored, followed by what this run found. An earlier fix in this release
  set the two apart on the hunt page. It found the seam by matching the sentence a candidate
  finding ends with, "Matched N documents for ...". No gap finding contains that sentence, so a
  blind spec, a spec that could not evaluate its exclusions, a spec whose matches grouped nowhere
  and a spec the bucket ceiling truncated all kept rendering as one paragraph. On the range every
  catalog finding is currently a visibility gap, so in practice the split fired on nothing. It is
  also the case where the authored prose misleads most: the run saw nothing, so every number on
  the card was measured by the author, once, on a grid that has moved since. The seam is now data
  rather than a pattern. The composer appended the second half, so it knows where the first one
  ends, and it sends that half as its own field with the candidate's document count beside it; the
  page reads both instead of parsing prose, and the count under the citation chips stops being
  scraped out of a sentence. The prefix is checked rather than trusted, because two fields of one
  stored record can disagree and cutting on a prefix the detail does not start with would drop
  text: a mismatch renders whole. `detail` still carries both halves for every other reader of a
  report, and the old tail match survives for hunts recorded before the field existed and for
  nothing else. A model's finding has no authored half, sends no such field, and is still never
  carved up.

#### The alert queue was empty for the wrong reason and nothing said so

`WEBUI_ALERTS_QUERY` decides what the triage queue contains. It defaulted to `tags:alert`. On a
grid that had just started producing real endpoint alerts, measured on 2026-09-05 over 24 hours,
that filter matched 2 documents. `event.kind:alert` matched 25. The 22 in the gap were Elastic
Defend behavioural alerts naming hosts and accounts nobody had reviewed, and they were invisible:
`GET /api/v1/alerts` returned one group, and a hunt run against the same grid concluded that no
malicious indication was found, partly because the alert plane it consulted was empty.

The filter being wrong for one deployment is a tuning problem, and it was already documented as
tunable. The defect is that nothing checked the configured filter against the grid, so an empty
queue caused by asking the wrong question was indistinguishable from a quiet night. This project's
own rule is that a false all-clear outranks any 500.

**The default is now `tags:alert OR event.kind:alert`**, and the two halves are there for different
reasons. Security Onion's ingest pipelines derive `tags:alert` from `event.dataset` for Suricata,
Sigma/ElastAlert, Wazuh and Strelka, and set `event.kind` on none of them; it is the base filter of
SO's own Alerts page, and moving to ECS alone would have emptied the queue on a stock grid rather
than filling it. Elastic Defend endpoint alerts never pass through that pipeline. They are written
by Elastic's own package pipeline and carry ECS `event.kind:alert` and no SO tag. The union is a
superset of the old default, so no grid sees less than it did.

**`soc-ai doctor` gained an "alerts feed filter" row.** It counts what your filter matches over the
last 24 hours against what each known alert label would have matched over the same window, through
the alerts console's own query builder so the numbers are the feed's numbers rather than an
approximation. It warns when your filter finds nothing an alternative finds, or far less than one,
and names the alternative. A grid where no label finds anything is quiet rather than misconfigured
and passes with that said out loud, because a row that fires on every idle grid is a row nobody
reads. It also appears in the Dashboard's setup-health card and, row by row, in the admin preflight
detail.

**An empty alerts feed now explains itself.** When the console has nothing to show it can say which
of the two it is: the grid is quiet, or your filter matched nothing while other alert labels did.
The second query only runs when the result is empty.

If you set `WEBUI_ALERTS_QUERY` explicitly in `.env`, your value is untouched. Run `soc-ai doctor`
to see how it scores against your own grid.
- **The decoy spec called a quiet honeypot a coverage gap.** `decoy-opencanary-interaction`
  required an OpenCanary document inside the sweep window before it would trust its own empty
  result. OpenCanary writes a record when its service starts and then nothing at all until
  something touches the honeypot. There is no heartbeat, so the precondition measured "was the
  decoy touched recently" rather than "is the decoy reporting": on a live grid, a run over a window
  with no interactions returned `blind: true, precondition_docs: 0` and recorded a finding reading
  "no telemetry. The spec's precondition matched nothing, so this is a coverage gap rather than a
  clean result." The decoy was healthy and its silence was the good outcome, so that sentence was
  false. It is the invariant the catalog is built on pointed the wrong way: blind-is-never-clean
  exists to stop an absence of visibility being read as an all-clear, and here an all-clear was
  read as an absence of visibility, which teaches an analyst to ignore the one marker that exists
  to be believed.
- **A spec can now say how far back its precondition looks.** `precondition_lookback_minutes`, and
  the decoy sets ninety days: long enough to outlast the reboot cadence of a machine that is
  deliberately left alone, short enough that a decoy whose shipper dies goes blind a quarter later
  rather than never. The detection still covers only the sweep window, so nothing reports ninety
  days of findings. This is per spec rather than a wider window for everything, because the
  opposite case is shipped and the catalog's own acceptance test depends on it: a domain controller
  with Directory Service Access auditing on writes 4662s continuously, so silence there means the
  auditing was switched off and blind is the correct reading. The three identity specs declare no
  look-back and compile byte for byte as they did, all four detections are unchanged, and the four
  spec-journey fixtures produce the same candidates on the same scope keys. Nothing was switched
  off either: a grid where the honeypot was never deployed holds no document in any window and
  still reads blind, which is covered by a test. The window start is shifted rather than the end,
  so a precondition can only be asked about more ground than its detection and never less, and a
  blind report now names the window it was blind over ("no telemetry in the 90 days to now")
  instead of a window it never asked about.

#### The tamper-evident audit trail was forking, and nothing was checking it

`soc-ai audit verify --days 3` on the deployed instance: TAMPER DETECTED, break at sequence 109667,
in the epoch that is still being written to. Not a window artefact. A composite aggregation over
seven days of the audit index found 41 duplicated sequence values across 51 extra documents, with
one sequence claimed by four records. The duplicates share a `prev_hash`, which names the shape
exactly: two writers continued the chain from the same point.

```
109667  19:07:01Z  enriched_alert_context  prev=88b058b2a2ee
109667  19:07:04Z  host_dossier            prev=88b058b2a2ee
```

The chain head was held in memory and guarded by an `asyncio.Lock`. That lock is real and it
works. In a reproduction against a real Elasticsearch, twelve concurrent tasks in one process
wrote 180 records with no duplicate at all. But it covers one logger object in one process, and
there was never only one. The nightly quality alarm built a second `AuditLogger` while the
server's was alive a few objects away. The nightly evaluation is documented as a host cron entry,
which writes from a separate process entirely. And a write whose acknowledgement never arrived
left the head unknown, after which the recovery read fell into Elasticsearch's near-real-time
window and returned a head older than the record it was trying to find. Three routes to the same
fork. The same reproduction with three OS processes instead of one: 60 duplicated sequences, 120
extra documents, chain broken.

The sequence is no longer claimed in memory. Each record is created at a deterministic `_id` derived
from its sequence with `op_type=create`, so the grid arbitrates: the first writer to reach a
position gets it, and every other writer is refused with a version conflict, reads back the run of
ids around the refusal with a realtime multi-get, and claims the next free position. Allocation and
persistence become one atomic operation, which is what closes the window. It also settles the
unacknowledged write without guessing, since the next claim on that sequence either conflicts (it
landed) or succeeds (it did not). A refused claim backs off briefly before retrying, because the
writer that lost a race is a round trip behind the one that won it and would otherwise be lapped on
every attempt. Same three-process reproduction after the fix: no duplicates, chain verifies.

Two smaller repairs came out of the same path. A head re-read now only ever moves the head forward,
since a near-real-time search can legitimately answer with a sequence older than the one already
held. And the index-template install moved inside the chain lock: outside it, the first writer paid
for the install while the writers behind it went ahead, so the earliest-timestamped record carried a
higher sequence than records written after it. The verifier fetches timestamp-ascending and starts
a new epoch at every sequence zero, so it split one healthy chain in two and reported both halves
broken. Measured on a test grid: 180 records, zero duplicates, TAMPER.

**Nobody was ever going to notice.** The verification existed from v1 as a CLI command and an admin
diagnostic, and the only way to learn that the current epoch was broken was to press a button nobody
presses. A scheduled verification now runs the check on its own: daily, over a seven-day window, on
by default. Every other background job here defaults off because it spends money or changes state.
This one is a bounded read of one index. A break goes to three places: an audit record, in the
chain it is reporting on; the notification webhook, at critical severity; and a standing entry on
the in-app bell, which is the only one of the three that works on a stock install, because
notifications are off by default. It is deliberately not transition-gated the way the quality alarm
is. A standing break is a standing claim that the decision record cannot be trusted, and going
quiet about it would read as resolved. A verification that could not run is logged and never
alarmed: "we could not check" is not "we found tampering", and conflating them is how an operator
learns to ignore the alarm.

**"TAMPER DETECTED" was also one sentence for several different facts.** A position claimed twice by
two concurrent writers and a record whose content was edited after the fact both printed "a record
was edited, reordered, inserted, or deleted" and nothing else. Verification now classifies the
break as a duplicated position, a missing position, a missing head, a relink or altered content,
and carries one plain sentence with it. For a duplicated position it reports whether every copy
still matches its own hash, which is exactly the test that separates a concurrency fork from an
alteration: two writers each write a record that is internally sound, and an edit does not. The
type and its sentence appear under the CLI verdict, in the admin verify-chain response, and in the
alarm.

The break already on the deployed instance is not repaired by any of this and is not repaired
silently by anything else. See `docs/AUDIT-CHAIN.md` for what it is, how to tell it from a
real alteration, and the three options for what to do about it.

#### Known gaps, stated plainly

- **The nightly quality evaluation has never contained a true positive.** It samples the live
  alert queue and plants no ground truth, so it measures the grader's opinion of benign traffic.
  If the analyst model began calling real intrusions benign, agreement would go up. The alarm now
  says this outright when a batch holds no positive verdict; planting one per batch is the fix.
- **The backtest still reads soc-ai's own acknowledgements as the analyst's false-positive
  labels.** The escalate half is fixed by ledger; the acknowledge half has no ledger yet.
- **About twenty Elasticsearch reads still inherit the partial-read opt-out** and make an
  absence or coverage claim on a short read. The health surfaces are fixed; each of the rest needs
  its own answer to what a partial read should mean there.

## [1.4.0] - 2026-09-04

The trust release. Four arcs, one subject: whether soc-ai's judgement can be checked rather than
taken on faith. After the 1.3.2 security audit closed the ways soc-ai could be abused, this makes its
judgement measurable, and closes the deterministic half of that audit's most serious finding.

### The hunt journey became measurable

- **soc-ai can now measure whether it actually finds the attacks it should.** The evaluation harness
  has always been able to plant synthetic attacks and check the verdict on a single alert. It could
  never check the thing soc-ai is really for: taking a plain-English hunt across the network,
  surfacing a finding, promoting it to a full investigation, and reaching a verdict. That whole
  journey can now be scored, and when it falls short it says **which step broke** — the hunt found
  nothing, the finding cited no usable evidence, or the investigation reached the wrong verdict —
  rather than just failing.
- **Synthetic runs are unmistakable.** Anything produced from planted evaluation data is marked as
  such in the database and carries a "Synthetic — evaluation data" badge everywhere it appears: hunt
  and investigation lists and detail pages, notifications, the command palette, the dashboard. A
  planted attack can never be read as something that really happened on your network. Evaluation runs
  are also kept out of a host's real history entirely, so they cannot alter what soc-ai says a machine
  has been up to.
- **The evaluation refuses to run if a planted document ever reached a real index**, rather than
  quietly measuring against contaminated data — and it now refuses just as firmly when it cannot read
  the grid completely enough to be sure, instead of reporting a clean result it did not earn.
- **The actions soc-ai recommends are now scored.** Every scenario has always declared which action a
  correct triage should suggest; that expectation had never actually been checked.

### Verdicts must rest on evidence the run retrieved

- **A verdict must now rest on evidence soc-ai actually retrieved.** Previously the checks confirmed
  that evidence had been *gathered*, never that it *supported* the conclusion — so a single successful
  lookup was enough to let a confidently-wrong true positive stand, including one steered by text
  planted in the network traffic being analysed. A true positive whose decisive indicator appears in
  nothing the run actually retrieved is now held back for review instead of escalated, and its
  recommended actions are withdrawn. Where the evidence is partly there, confidence is reduced rather
  than the verdict discarded — a sound judgement is never thrown away over formatting.

  This closes the fabricated-indicator case. It does not settle every case: an attacker who plants a
  real value in their own traffic still passes it, and the broader question of whether a conclusion
  genuinely follows from its evidence remains open work.

### The detection quality pass

Work on the backlog the trust release produced, before the version was cut. Most of what follows is
repair to soc-ai's ability to *judge itself*: the pass found seven separate places where a scenario
rendered perfectly and measured nothing, and four of those were introduced by earlier fixes to the
evaluation itself.

- **An attack can no longer be dismissed as benign without looking.** Two scenarios — a thousand-file
  share sweep followed by a 3.2 GB archive, and a remote WMI execution followed two seconds later by
  a PowerShell download — were both closed as routine internal traffic with **zero tool calls**. The
  guards covered attack signatures and malware rule names, but not the deliberately-informational
  analytics rules that behavioural detections actually use. soc-ai already refused to *escalate*
  without looking; it now refuses to *dismiss* without looking, which matters more, because a missed
  intrusion is quieter than a false alarm.
- **The cloud second opinion was reasoning with no evidence in front of it.** Its transcript was
  assembled from text message parts only — and every tool returns structured data, so **every tool
  result was silently dropped**. It once overrode a fully-cited local verdict while complaining that
  "no file hash, signature, or service name is actually present in the evidence." That was literally
  true of the payload it had been handed. Its scepticism was rational; it was being starved. This
  affected every escalation in production.
- **soc-ai can tell "nothing happened" from "nothing was watching."** On a host outside an endpoint
  rollout it would probe for process telemetry, get nothing back, retry across field shapes and wider
  windows, and burn its entire budget — then report a hedged verdict that read as uncertainty about
  the attack rather than a gap in coverage. It now states the gap plainly and spends the budget
  elsewhere. Runs that exhausted their budget fell from six in twenty-six to one.
- **Correct verdicts were being recorded as misses.** Citations naming genuinely retrieved evidence
  could not be resolved when the evidence sat under an IP address key, because the resolver split
  paths on dots and an address contains dots. Coverage collapsed, a confidence penalty fired, and
  sound detections were scored as false negatives.
- **The physical index name is no longer queryable.** It served no purpose in any query soc-ai makes,
  and it let a search select documents by storage location rather than content. Operators pasting an
  index filter copied from Security Onion will now get a clear error pointing at `event.dataset`.

  Alongside these, the scenario catalogue nearly doubled (13 → 25), so no single case swings the
  measurement by more than six percent.

### The Oracle checks its own claims, behind a boundary that is complete by construction

Until now the cloud second opinion adjudicated from a sanitized case payload and nothing else — a
review formed entirely from what the local run had happened to write down. It can now run the same
read-only tools the investigator has, with its arguments desanitized before execution and its results
re-sanitized on the way back. Off by default (`oracle_tools_enabled`).

- **A class-changing Oracle verdict now requires the Oracle to have looked.** At least one successful
  tool call in its own loop, or the disagreement is recorded on the adjudication event and the local
  verdict stands. A zero-tool *agreement* still lands, because it adds confidence rather than flipping
  anything.
- **Egress flipped from block-known-bad to allow-known-safe, and this is the load-bearing change.**
  Building the tool loop proved the wire gate was a blocklist. A bare internal name like `filesrv` or
  `PDC01` has no regex shape, so the residue sweep could only catch it through values the sanitizer's
  harvest recognised, and the harvest is keyed on field paths — an open set. Five commits each closed
  one missed category (generic-key envelopes, single-label names on domain fields, non-ECS Windows
  event leaves), which is the argument that a sixth was always possible. Now any scalar from a field
  the harvest does not classify is masked before the model can see it, on the initial payload and on
  every tool result. The cost is utility, not privacy: an unclassified value arrives opaque rather
  than as a stable token, so the Oracle cannot correlate it across fields.

### A measurement that knows its own noise floor

- **Each scenario can run N times** (`--repeats`), reporting per-scenario stability, macro-averaged
  recall, and a scenario-bootstrap confidence interval. This exists because a test-retest on code that
  provably could not affect the outcome moved strict recall by 0.235 and flipped 6 of 25 scenarios
  between pass and fail. A single batch cannot distinguish a fix from a coin flip, and it no longer
  claims to.
- Adjudication and the eval judge moved to `claude-opus-5`.

### Fixed in this release

- **A network sensor's hostname is no longer attributed to the hosts it watches.** Found on a live
  attack range: two agentless targets were each reported as the router that observed them, because a
  Zeek or Suricata document's top-level `host.name` names the box that *shipped* it. Any host with no
  agent of its own was liable to inherit its sensor's identity — including in the stored host dossier,
  where the wrong name would persist. Host identity from a document is now accepted only when the
  document is about that host.


## [1.3.2] - 2026-08-26

An adversarial security audit of the whole product, and the fixes it earned. Four attacker positions
were tested — someone who controls the telemetry soc-ai ingests, a logged-in analyst gone rogue, a
stranger on the network, and anything that could carry your data out of the building. Every finding
below came with a working reproduction before it was fixed.

### Fixed

- **A hunt that runs out of budget no longer sends your objective to the model unredacted.** When a
  hunt exhausted its request budget, tool budget, or timeout, the partial-report step wrote its summary
  from the raw objective — internal IPs and hostnames included — even with redaction on. Every other
  step on that path was redacting correctly, which is what made it hard to see.
- **A detection drafted from an attacker's own traffic can no longer quietly exclude them.** Field
  values from telemetry were spliced into the drafting prompt as trusted ground truth, so text planted
  in a payload could steer the rule into skipping the attacker's address — and the checks still passed
  it, because the "would have fired" count measured a different query than the rule you exported. The
  telemetry is now fenced off and treated as data, the two are cross-checked, and the console shows you
  the query the count came from.
- **A citation now has to name evidence that was actually retrieved.** Citations were confirmed by
  looking for the reference anywhere in the gathered text, so a string planted in a DNS lookup could
  pass as a document that was never fetched. Verdicts and hunt findings now resolve citations against
  the evidence itself — document IDs, sensor-computed hashes and fingerprints, and detector-assigned
  labels — while anything an attacker composes freely cannot stand in as a source.
- **Redaction now covers every place that talks to a model.** Three paths sanitized without running the
  fail-closed check, which mattered because that check catches bare Windows hostnames and
  credential-style usernames that sanitizing alone does not. The optional runbook-embeddings tier sent
  queries and runbook text to the gateway with no redaction at all.
- **A bad password from one person no longer locks out everyone else.** Failed logins accumulated
  against the whole site and were never cleared by a successful one, so on a shared network connection
  a handful of typos could refuse valid credentials for fifteen minutes. `PROXY_TRUSTED_IPS`, which
  tells soc-ai how to identify individual clients behind a proxy, is now documented.
- **Group acknowledge and escalate now refuse what they cannot honour.** An unrecognized severity was
  silently dropped rather than rejected, which quietly widened an acknowledgement to every severity in
  the group. Unrecognized filter values are now refused outright.
- **A promoted hunt finding cannot be acknowledged or escalated in Security Onion by a side door**, and
  re-investigating one no longer produces a record that could.
- **Metrics are no longer readable by anonymous visitors on the public demo**, and resetting a user's
  password now requires being signed in.


## [1.3.1] - 2026-08-25

A critical dogfood of the 1.3 journey before it went public — a live walk of hunt → promote →
investigate → draft, plus correctness and performance passes. The fixes below all land before the
first public 1.3 release.

### Fixed

- **The Draft-detection button no longer times out before the rule arrives.** The request carried the
  20-second budget meant for database reads, but drafting a rule takes 16–44 seconds on the analyst
  model — so the button reliably failed while the server finished a good draft and threw it away. The
  client now waits long enough, and the server has its own 150-second budget that returns an honest
  "took too long" before the client gives up.
- **A detection can only be drafted from a confirmed true positive.** The two draft buttons had drifted
  apart: the hunt-console button would draft a rule from any finding — including one whose investigation
  concluded *false positive* — while the investigation screen required a confirmed true positive. Both
  surfaces and both API routes now enforce the same rule: investigate and confirm the finding first.
- **Drafted rules are grounded in the events that were actually seen.** The drafter used to receive only
  the finding's prose and a list of document IDs, never the events themselves, so it could invent field
  values the UI then called "grounded." It now reads the cited events and keys the rule on their observed
  values, and refuses to draft when nothing resolves on the grid.
- **"Rule structure valid" and the would-have-fired count now match what you export.** Editing the rule
  in the review box no longer leaves a green validity badge and a firing count describing the *original*
  draft — once you edit, the pane says the checks reflect the pre-edit rule until re-checked. The badge
  was also renamed so it no longer implies the rule is guaranteed to load in Security Onion, and Sigma
  field names are now checked against the same allow-list the query engine uses.
- **The would-have-fired dry run is anchored to when the activity happened**, not the last 30 days from
  now, so a rule drafted from older evidence no longer reports a misleading zero. Over-broad rules that
  match everything now surface as "not specific enough to dry-run" instead of a reassuring huge count.
- **Exported rules carry their origin.** The copied/downloaded `.yml` now names the hunt and finding it
  came from and marks soc-ai as the author, so a rule pasted into Security Onion can be traced back.
- **A drafting failure returns an honest error, not a raw 500** — a slow or unavailable analyst model
  now maps to a clear "model unavailable / timed out, retry" instead of an opaque server error.
- **`first_seen` no longer floods a hunt with false "novel" destinations** when the baseline window has
  no data (a young grid, short retention, or a coverage gap): it says novelty could not be determined
  instead of calling every established destination brand-new.
- **Beaconing analysis stops ranking a burst of identical timestamps as the strongest beacon** (a
  zero-interval burst is not a cadence), and internal destinations are now excluded in the query rather
  than after hauling them back and discarding them — so the external candidates the tool exists for are
  no longer crowded out.
- **Plainer, more discoverable copy across the journey**: the "citation gate stripped this finding"
  tooltip is gone; the investigation toolbar's "Export" is now "Export decision record" so it doesn't
  compete with the Sigma "Download .yml"; a completed hunt points the way to promote → investigate →
  draft; and when detection authoring is off, a confirmed finding shows a quiet "enable it in Config"
  link instead of nothing.

### Performance

- The polled hunt-detail endpoint and the triage prior-outcomes memory no longer deserialize whole
  investigation report blobs to read a handful of scalar fields; the detection dry run makes one grid
  round trip instead of two.

## [1.3.0] - 2026-08-25

The hunting release: three capabilities that compound. A confirmed hunt finding
becomes a first-class investigation; behavioral-analytics tools surface the
findings worth confirming; and a confirmed finding becomes a drafted detection
you review and export.

### Added

- **Promote a hunt finding into its own investigation.** A finding you want to
  pursue becomes a full investigation with the hunt as its provenance. It
  anchors on the finding's own cited telemetry — the exact event the hunt
  surfaced — so the verdict is grounded in what you were looking at rather than
  re-derived from scratch. Hunt-kind investigations never write back to Security
  Onion (no ack, escalate, or auto-close), and re-promoting the same finding
  returns the existing investigation instead of a duplicate.
- **Behavioral-analytics hunt tools.** Four tools the hunt agent can call, each
  bounded to a candidate set before the model sees it: beaconing by inter-arrival
  regularity, high-entropy DNS query names, a DCE-RPC operation histogram with
  dangerous/rare flags, and first-seen external destinations measured against a
  trailing baseline. Each cites the underlying events by ID, so a finding can be
  confirmed against real telemetry and carried into a promotion. A "DCE-RPC abuse
  / DC attacks" hunt template ships alongside them.
- **Draft a detection from a confirmed finding (export-only).** A confirmed hunt
  finding can be turned into a Sigma rule: soc-ai drafts it grounded in the
  finding's evidence, checks it against the Sigma schema, and runs a
  would-have-fired dry run over your grid so you see how many events it matches —
  with a few sample IDs — before you trust it. You review and edit the rule, then
  copy it or download a `.yml` to paste into Security Onion yourself; soc-ai never
  writes a detection to the grid. Off by default — enable `sigma_authoring_enabled`
  in the config console.

### Changed

- **A usability pass across the deployed app.** Notification badge counts, the
  Ask panel's chip-submit, middle-ellipsis truncation for long names, host results
  in the command palette, window-derived hunt stats, hosts defaulting to the
  active filter, GUID-hostname rejection, OS-family labels, and alert-event
  bucketing.

### Fixed

- **A chat turn can no longer hang after its answer exists.** The post-answer
  tail (grounding check, redaction, save) ran with no deadline of its own; a
  stalled save left the turn pending with the reply already written. The tail
  now has a 20-second bound and a timeout message that says what actually
  happened instead of blaming the question.
- **The grounding check stops reading security prose as hostnames.** Terms like
  "C2-style" and "Cloudflare-fronted" qualified as artifacts and burned both
  regrounding attempts on every reply that used them; a hyphenated token now
  counts only when backticked or shaped like a real machine name
  (all capitals and digits).
- **The audit chain stops crying tamper over its own restarts.** A chain-head
  recovery bug (fixed 2026-08-17) reset the hash chain to genesis on every
  process restart for eight weeks; prod's trail carries 134 of those
  legitimate boundaries, and verification used to report the whole thing
  broken at the second one. Verification is now epoch-aware — each restart
  checks as its own chain — and an all-clear spanning more than one epoch
  renders amber, never the green full-success line, because cross-epoch
  linkage is not provable. `soc-ai audit verify`, the verify-chain endpoint,
  and the Diagnostics control all now name which epoch a real break falls in,
  tally the blast radius ("1 of 134 epochs broken"), and say the thing an
  operator actually needs: whether every epoch after the newest break verified
  intact — suppressed under a capped scan, which cannot make claims about the
  chain's newest end in either direction.

## [1.2.9] - 2026-08-19

The front-door release: the path from `git clone` to a first verdict on your
own alert is now engineered with the same care as the verdicts themselves. The
installer asks how you'll reach a model and redacts the cloud route by
default, the doctor names each silent trap with its fix attached, Config opens
on eight decisions instead of 109, and an Operate hub gives the trust
instruments one page that says what each proves.

### Added

- **The installer asks how you'll reach a model — and the cloud route
  redacts by default.** `setup.sh` forks local (primary) vs. cloud API key;
  route 2 sets `ANALYST_CLOUD_REDACTION=true` and prints exactly what
  egresses before the first hunt runs; a junk route answer fails loudly
  instead of silently defaulting.
- **The quickstart leads with a working demo, not a wall of config.**
  `docs/quickstart.md` opens with a five-minute, no-SO, no-LLM local replay
  (`docker compose -f docker-compose.demo.yml up`, plus a hosted twin) before
  asking for a single Security Onion or LLM credential.
- **Day one turns the lights on instead of leaving them for an admin to
  find.** `setup.sh` now prompts for auto-triage (a 5-minute schedule, ≤25
  targets/sweep, high-severity+) and the 10-runbook starter pack — both
  default to yes — plus an optional MaxMind GeoLite2 key for GeoIP/ASN
  enrichment.
- **Setup doesn't stop at "the container is up."** A doctor preflight
  (`python -m soc_ai doctor`) runs automatically once the stack reports
  healthy, and the runbook starter pack installs itself through the admin API
  (`POST /api/v1/runbooks/starter-pack`) — a fresh box is triage-ready, not
  just running.
- **Doctor gained three checks, each with a fix attached to its failure.**
  The SO audit write grant (`_has_privileges`, no canary writes, graded per
  privilege), index-pattern coverage (catches the `.ds-*` narrowing trap and
  reports a partial match honestly rather than pass/fail), and layered
  DNS/TCP/TLS upstream reachability, with a hint scoped to whichever layer
  actually failed.
- **A local LLM stack is one file away.** Optional `docker-compose.llm.yml`
  runs a pinned Ollama + LiteLLM profile on the app network for the local
  route; `docs/LESSER_MODELS.md` gained a "Standing one up" walkthrough.
- **CI now catches doc drift that used to ship silently.** The README's
  version badge and the quickstart's internal links are checked against
  `pyproject.toml` and the doc tree on every run — a stale badge or a dead
  link fails the build instead of waiting for a reader to find it.
- **The 30-minute clone-to-verdict bar is now a release gate, not a claim.**
  `scripts/first-verdict-timer.sh` times `setup.sh --auto` plus the wait for
  a real completed verdict and reports pass/fail against the 1800-second bar;
  `setup.sh --env-only` plus a pytest harness cover the installer's config
  generation (both LLM routes, the day-1 prompts, junk-input handling), so
  the installer itself is under test.
- **The sidebar now reads like an analyst tool.** Navigation splits into
  Investigate (the analyst loop) and a collapsed-by-default Operate group;
  nothing moved routes, only shelves. Detection tuning stays one click from
  alert-group context, where noise nominations originate: a Tune rule link
  on each group row jumps straight to Config → Detection tuning.
- **Config opens on eight decisions, not 109.** Day-1 settings render up
  front; the rest folds behind per-section Advanced reveals. Settings search
  still finds everything and expands whatever it lands on. The day-1 set is
  snapshot-tested at ten or fewer.
- **An Operate hub presents the trust instruments.** One page names what
  each proves: model fitness, verdict quality, the audit chain, backtest
  replay, diagnostics, runbooks. No more scattered peer screens.
- **The Dashboard carries a persistent setup-health card.** Wave 1's doctor
  checks (minus the expensive fitness probe) feed a cached preflight API:
  green when clean, named failures with fixes for admins, honest counts for
  analysts. A Re-check button forces a fresh read past the cache; if the
  attempt itself fails, the card says so plainly instead of going quiet.
- **The audit chain is now verifiable from the console.** Config →
  Diagnostics (what the Operate hub's audit-chain card points to) runs a
  real chain walk on demand and reports one of four honest outcomes: intact,
  partially verified (capped short of the full chain), tampered at a named
  sequence number, or couldn't verify. A capped scan never gets the green
  check; only a full, clean one does.

## [1.2.8] - 2026-08-17

The degraded-grid release: what soc-ai says when Security Onion is down,
saturated, stalled, or answering with half its shards is now as engineered as
what it says when everything works. The rule the whole release enforces: a
false all-clear outranks any loud error — a blind sensor must never be
reported as a calm network. No breaking changes; seven migrations (0024–0030),
applied automatically on upgrade.

### Degraded-grid honesty

- **A partial read is no longer a complete read, anywhere.** Elasticsearch
  answers 200 having read only some shards; the client used to discard
  `_shards`/`timed_out`, so every surface reasoned from a partial view as if it
  were whole. Partial reads now raise, every route answers 503 with the shard
  story, and the diagnostics probe and topbar health pill detect the state
  instead of reporting green. Opt-out for exploratory reads:
  `es_fail_on_partial_results`.
- **An outage can no longer dismiss identifier suggestions.** The discovery
  scan's public-suffix retirement — the one irreversible write in the product —
  now requires that the sub-queries feeding that signal succeeded AND observed
  events; and it is gated per signal, so one persistently failing unrelated
  sub-query no longer suppresses retirement forever.
- **A sweep that could not read the backlog is not an empty backlog.**
  Auto-triage cycles that land zero because the grid refused are marked
  degraded, durably; a refused (429) sweep no longer records as
  "Last batch · 0 investigated"; a malformed query is answered as a bad query
  (400) instead of accusing the grid of an outage.
- **A backtest cannot mistake an outage for a bad model.** An unreadable
  window is reported as unreadable rather than "no dispositioned alerts";
  a run that loses the grid mid-flight no longer scores unread rows as model
  disagreement; and the failure note now survives onto consoles that have run
  a backtest before.
- **A hunt with no successful grid read cannot land as a clean sweep.**
  Includes closing the retry hole where a deduplicated retry of a failed query
  counted as a success, and the all-rejected case, which is labelled a query
  problem — not grid health.
- **The buttons an analyst clicks while the grid is sick answer instead of
  crashing.** Investigate, group ack/escalate, find-alert and bulk re-hunt
  return honest 503/400s (nothing acknowledged before a failure is reported),
  and bulk re-hunt stops burning one grid timeout per row against a dead grid.
- **The server produces the outage verdict, not the browser.** The routes that
  used to hang until the SPA gave up at 20 s (Test ES, auto-triage, backtest,
  model-fitness) answer within the console grid budget with a definitive
  diagnosis; an ES 429 reads as "overloaded — retryable", never as "check your
  query".
- **The audit chain cannot report intact from a half-read index.** Verification
  of a partial read is answered as *unverifiable* — never a pass, and never a
  tamper claim — and chain-head recovery at write time is guarded against the
  same state, so a stalled grid can no longer manufacture a future false
  tamper verdict.
- **The screens stop asserting numbers they never obtained.** Alerts renders
  em-dashes, not zeros, when its query failed; the Dashboard no longer prints
  "queue clear" under an unknown count; failed actions say so on screen; a
  scan that is running, or that came back blind, says which — for every role.

### Added

- **`GET /api/v1/dossiers/sweep-health`** — a non-privileged projection of
  sweep health (`running`, `degraded`, `last_run`, `error_count`; never the
  raw failure strings), so non-admin analysts see "the sweep came back blind"
  instead of "the sweep hasn't run yet" over a sweep that ran and died.
- **A degraded-grid dogfood harness.** The demo mock grid gains five
  runtime-switchable states (healthy, down, half-read, saturated, stalled) —
  strictly opt-in, off in the packaged demo — and a capture script walks every
  screen and action in each state.

### Fixed

- **The hosted demo's Config screen renders its read lock as policy, not as an
  outage.** The demo refuses admin-gated reads (a security fix: the public
  demo used to answer the user table and which secrets were set); that refusal
  now reads "Read-only demo" instead of an alarm-red failure card.
- **A Send button that did nothing.** The chat draft was restored twice on
  mount, so text typed before the second restore was silently replaced and the
  send dropped. Type, press Send, nothing — no request, no error. Fixed at the
  source.
- **Opening an investigation whose Oracle run redacted something answered
  500.** The redaction record is per-category counts; the detail page expected
  a sentence. Every investigation the egress guard had actually protected was
  unopenable; the counts are now phrased ("1 IP address and 2 hostnames
  redacted before the second opinion").

### Added

- **A Dashboard assistant that answers you instead of handing you off.** The
  "Ask soc-ai" box on the landing screen used to prefill the Hunt Console and
  navigate away, so "what datasets do I have?" became a multi-minute background
  job. It is now a chat: it answers in one turn using the investigation chat's
  read tools, at roughly the same latency. Each analyst gets one rolling thread
  that survives navigation and restarts; **Clear** discards it. When a question
  needs a sweep, the agent does not start one. It writes the hunt objective from
  what it just looked at, says what the sweep would settle, and puts a **Start
  hunt** control in front of you. It has no write tools and cannot change a
  verdict. New setting `general_chat_enabled` (Config → Models & Reasoning →
  Agent, hot, on by default) switches it off without a restart. That matters if
  a shared analyst model is already busy with the triage backlog: this is the
  one agent that sits on the screen everyone lands on. New endpoints
  `GET`/`POST`/`DELETE /api/v1/chat`, migration 0025,
  and the flag rides on `GET /api/v1/about` so a disabled deployment hides the
  box rather than failing the first question someone asks.
- **soc-ai knows what a host is.** Every internal address was only an address:
  "10.0.0.5 is probing SSH" read as unremarkable internal noise, where "the
  hypervisor running your SIEM and your backups is probing SSH" would have been
  escalated on sight. Same events, opposite urgency, and the whole difference is
  asset knowledge the product did not hold. A sweep now builds a durable record
  for each internal host out of telemetry already in Elasticsearch — hostname,
  OS, the services it answers on, a behavioral baseline, and an inferred role
  (hypervisor / domain controller / security appliance / server / workstation /
  network device / IoT) — and the agent reads it through `t_host_dossier` and a
  prompt block on every investigation, chat and hunt. Classification is
  rule-based and deterministic, never model-written: an ordered port-set table
  with peer-count and hour-spread preconditions, so one inbound SSH connection
  can no longer promote a laptop to "server". A dossier is context and never
  evidence — it is marked system-inferred in the prompt and cannot satisfy the
  evidence gate, because "this is probably a hypervisor" is a conclusion, and a
  conclusion must not unlock a confident verdict the way an observation does.
  What you declare and what the system infers are stored in separate columns
  and resolved at read time, so an override survives every later sweep
  structurally rather than by convention; the builder keeps observing an
  overridden host anyway, so three consecutive builds that disagree with your
  value earn one prompt, then at most one per 14 days, with "keep mine"
  snoozing on a backoff capped at 90 days. Thirteen hot settings under
  Config → Host dossier. **The schedule (`dossier_schedule_enabled`) is off by
  default** — a sweep is hundreds of hosts times several Elasticsearch round
  trips, so you choose when it runs; `POST /api/v1/dossiers/refresh` (admin,
  single-flight) runs one now, and `dossier_context_enabled` takes the dossier
  back out of prompts while leaving the data building. Reads are
  `GET /api/v1/dossiers`, `/dossiers/{ip}`, `/dossiers/conflicts` and
  `/dossiers/summary`; overrides are admin-gated and audited. Migration 0024.
  The record reaches you through the agent, the API, and the Hosts screen
  below.
- **The agent asks who was driving an internal host before it blames the
  host.** On 2026-08-05 soc-ai attributed SSH username-probing to an internal
  host and stopped there, while the events it had already pulled included a
  `zeek.ssh` record showing a different machine opening an SSH session to that
  host seconds earlier. The real actor was one pivot away and never got named.
  `t_host_summary` cannot answer this by construction: its peer list is
  a volume-ranked aggregation over 24 hours, so a two-second session is
  invisible beside thousands of routine events, and an aggregation carries no
  ordering — "immediately before" is not expressible in it. The new
  `t_origin_chain` lists remote-access sessions inbound to a host in the window
  before the activity, time-ordered, and names the closest preceding one as the
  likely driver. It matches SSH, RDP, WinRM and SMB by dataset or by well-known
  port, because a short session often lands as a bare `zeek.conn` with no
  protocol log at all. Both answers are load-bearing: a session found means the
  host is a waypoint and attribution belongs upstream, and no session found
  means it acted on its own, which is usually the more serious finding — so an
  empty result is reported as a result rather than a shrug. The tool alone would
  not have changed the outcome above (`t_host_summary` was available, and was
  called twice), so investigator doctrine now makes the pivot a precondition for
  attributing hostile behavior to an internal host.
- **A Hosts screen that says what a machine is and what it is doing right now.**
  The dossier had no screen: what the sweep concluded reached you only through
  the agent or the API, and `/entity/10.0.0.5` showed traffic with no idea whose
  traffic it was. `/app/hosts` lists every host the sweep knows, with a search
  box, role and lane filters, and a queue of the fields where the sweep
  disagrees with something you declared. `/app/hosts/<ip>` is the host itself:
  a banner naming the machine and its role, four counters (services, accounts
  seen authenticating, connection volume, alerts over seven days), a peer graph
  and a volume chart, then the twelve two-lane field cards. An internal address
  opened from anywhere in the console — an alert, the peer graph, a saved
  `/entity/` link — lands here. Identity and activity have different freshness
  rules and the page keeps them apart: identity comes from the last sweep and
  still renders with Security Onion down, activity is read off the grid on the
  request that draws it, over 24h or 7d. When the grid is unreachable the
  activity half says so and the rest of the page carries on, rather than
  reporting a quiet host. New endpoint `GET /api/v1/dossiers/{ip}/activity`
  (analyst; three aggregations, nothing cached). Declaring a value, accepting
  the sweep's, "keep mine" and Rebuild now stay admin-only.
- **The host list opens with four numbers about the whole network.** That list
  is one SQL page of a table capped at 5,000 hosts, so nothing on the screen
  said how large the network was, how much of it had a name, or whether the
  host-log agents were reaching it. Counting the fifty rows on screen would
  have described a page while reading as the network, which this project has
  shipped twice. `/app/hosts` now leads with four counts and one new endpoint
  behind them, `GET /api/v1/dossiers/summary` (analyst; three aggregate
  queries, nothing per-host): hosts held and how many have no clean build,
  hosts whose name the resolver will assert, hosts where an agent on the
  machine reports about itself, and disagreements waiting on a decision. Two of
  those are defined carefully. **Named** applies the resolver's own confidence
  floor and staleness window in SQL, so a stored name the resolver withholds is
  not counted and the number agrees with the Hostname column under it.
  **Reporting** counts the observation rather than the resolved value, so
  declaring a hostname yourself does not hide that the machine is shipping
  logs. The strip dates itself from the newest host build and says when
  automatic sweeps are off, because they are off by default and the counts are
  otherwise only as fresh as your last Rebuild. A summary that cannot be read
  shows dashes rather than zeroes; a refresh that fails over good numbers keeps
  them and marks them stale.
- **The sweep names the hosts only DNS can name.** Hostname was blank on most
  rows — 122 of 147 on the network this was built against — because the lanes
  that name a machine need it to announce itself: a DHCP request, an NTLM
  exchange, a log agent. A printer, an appliance or a VM that answers nothing
  does none of that. Those are the addresses an analyst has least context for. One aggregation per sweep now reads what the network's own DNS answers
  call each internal address and takes the name a majority of answers agree on.
  Contention is left unresolved on purpose: two names tied means no name, and a
  name spread across several addresses of one family is a service record rather
  than a machine, so a round-robin VIP claims none of its members. It sits at
  the `telemetry` rung, below anything the machine says about itself, so an
  agent's or a DHCP client's answer still wins the field — and the name shows
  its weight ("214 A/AAAA answers over the window") so you can judge it. A host
  DNS names also becomes a row in its own right, which is how the quiet machine
  finally gets a dossier. Mined names are proposed to the internal-identifier
  list as muted suggestions, so a name that would otherwise leave the box in the
  clear can be accepted into the redaction vocabulary.
- **The agent is told which machine an address is, on every surface that names
  one.** The dossier block reached the investigation pipeline and stopped there,
  and only for the alert's own source and destination — so a hunt objective
  about `10.0.0.5`, a chat question about it, and any other address in the same
  alert group all went to the model as bare numbers. The investigation block now
  covers every internal address in the group (bounded at eight), and the hunt
  planner, the hunt console's seed, the investigation chat and the Dashboard
  chat each carry the same identity lines for the addresses their own text
  names. Free-text surfaces only describe hosts the sweep already has a record
  of: a "no dossier for this address" line about an address the analyst or the
  model just typed would put that address into the corpus the grounding check
  reads, letting it vouch for itself. `dossier_context_enabled` still takes the
  whole thing back out of every prompt.

### Changed

- **"Estate" is now "network".** The word appeared on screens and in the
  dossier's own prose; the product says network. Nothing on the wire moved: no
  setting, route, JSON field or database column ever carried it. This is labels
  and documentation, and no configuration needs changing. If you alert on
  soc-ai's own logs, one thing did move: a failed census records `census pass: …`
  on the run row and logs `dossier: census aggregation failed`, where both used
  to say `estate`. An alert keyed on the old text stops matching and needs
  re-keying.

### Fixed

- **The Investigations list is a query now, not a page pretending to be one.**
  `GET /api/v1/investigations` fetched the newest 100 rows and the screen
  filtered them in the browser, so once one outcome saturated those 100 —
  on the live deployment, 98 completed false positives — every older failed
  run was unreachable under any filter: selecting Status=error searched the
  same 100 completed rows and found nothing, while 107 errored and 2
  interrupted runs sat in the table. Filtering, counting and paging now run
  in SQL (`rows` + `total` + `limit` + `offset`, the host-list shape): the
  time range, the Status multi-select and the Verdict multi-select (including
  the synthetic "Pipeline error") are WHERE clauses, the header figures come
  from server-side counts over the same filter set instead of a tally of the
  visible page, and the table pages at 50 rows with an exact "X–Y of N".
  Status filtering matches the status a row *renders* with, so a run that
  finished without a verdict is found under Error, where the table shows it.
  A retry's `isPrimary` is decided over its alert's whole run group — never
  over whatever matched the filter — and the screen shows a retry top-level
  whenever its primary is not on the page, which retires the pipeline-error
  and needs-more-info promotion special cases by generalizing them.
  The Dashboard's "N pipeline errors" KPI moves onto the same footing: it
  used to count fallbacks in the newest-100 sample, which read "0 pipeline
  errors" over a store holding 19 the moment the list started telling the
  truth. It now runs the exact query its deep link opens (the 30-day
  pipeline-error filter) and applies its documented exclusions — dismissed
  and superseded runs — over that full match set, so the tile counts the same
  query the list runs, minus the dismissed and superseded runs it deliberately
  excludes. Past the 500-row page the tile reads "500+" rather than quietly
  undercounting.
- **Auto-triage no longer ignores every detection that has no IP.** The
  scheduled sweep clustered alerts by `(rule, source.ip, destination.ip)` and
  dropped anything missing an endpoint, tallying it as a `no_ip` skip. Sigma
  process, file and endpoint rules carry no `source.*` or `destination.*` at
  all, so that whole detection class was seen and discarded on every five-minute
  sweep — forever. On the live deployment every investigation of such an alert
  had been started by a human; the scheduler had never once picked one up. A
  missing endpoint now degrades the cluster key to empty instead of dropping the
  event, which keeps the dedupe that clustering exists for (one investigation
  per rule per sweep, not one per event). The alert table also names the machine
  on these detections, falling back to the endpoint document's own
  `event_data.host.name` where Security Onion nests it, and shows the agent's
  address on a second line; the address is deliberately kept out of
  `source.ip`/`destination.ip`, which mean flow endpoints. And a blank endpoint
  in an alert row is no longer a live link to an entity page for an em-dash.
- **The dashboard's untriaged count leads somewhere that can hold it.**
  Clicking the Untriaged tile opened `/investigations?verdict=untriaged`, which
  was empty by construction: an alert group nobody has investigated has no
  investigation row, and cannot get one while it stays untriaged. The tile read
  "1" and the destination read "no investigations". It now opens the Alerts list
  — the same endpoint counting the same unit — carrying the dashboard's time
  range and un-hiding acked groups, so the destination holds exactly what the
  tile counted. The Investigations screen's "Untriaged" verdict filter is gone
  for the same reason; a run that ended without a verdict is still reachable
  through the Status filter's Error and Interrupted options.
- **The nightly quality alarm tests for a regression instead of firing inside
  its own noise.** `agreement_rate` is a handful of oracle grades, five by
  default, so as a rate it moves in 0.2 steps. Comparing it against a median of
  other such rates alarmed roughly one night in eleven at the deployment's own
  healthy agreement — near-certain to page spuriously within a month, which is
  what it did. The detector now pools the trailing month's grade counts into a
  single baseline and runs an exact binomial test against it. A night has to be
  both statistically unlikely (2% or less under that baseline) and worse by the
  operator's `quality_alarm_drop` before it fires, a budget of about one false
  alarm per fifty graded nights. Add-one smoothing keeps a flawless month from
  making the next single disagreement look impossible, so one flipped verdict
  still cannot page anyone on its own. That was the job of the sample-size floor
  this replaces, which bought the guarantee by pinning `quality_alarm_drop` to
  0.20 and silently ignoring any lower value an operator set. Migration 0026
  records the grades behind each rate (`n_yes`, `n_partial`, `n_no`,
  `n_classified`); rows written before it fall back to the old median rule
  rather than going quiet. The Quality card now shows the composition ("3 agree
  · 2 partial", since a partial critique costs the same as a flat disagreement)
  and, on an alarm, the path to the eval bundle holding the oracle critiques
  that settle it.
- **Nightly eval bundles survive a container recreate.** They were written to a
  path relative to the container's working directory, which is not a volume, so
  every `docker compose up -d` deleted every bundle — and with them the oracle
  critiques that are the only evidence for or against an alarm on the quality
  trend. On 2026-08-07 a recreate destroyed the artifacts for both of that day's
  alarms while they were being diagnosed. Bundles now land beside the data dir
  (`/var/lib/soc-ai/evals` in the packaged layout, `./evals` on a host install),
  and the run logs a warning and keeps going if that directory is not writable
  instead of failing the nightly. **Upgrading a Docker install adds a fifth
  named volume, `soc_ai_evals`**: `git pull && docker compose up -d --build`
  picks it up from the repo's compose file, but a hand-maintained compose file
  needs the mount added by hand. Bundles written before the upgrade are lost in
  that recreate. The upgrade note is in `docs/DOCKER.md` under "Updating".
- **The web UI no longer freezes when Elasticsearch goes down.** Backend routes
  that talk to the grid can hang for about ninety seconds against an
  unreachable Elasticsearch (client timeout times retries), and no frontend
  request had a timeout at all. Polls stacked until they exhausted the
  browser's six connections per origin, so widgets reading only the local
  database froze too, and screens you had not visited yet could not fetch their
  code. The degraded-mode banner that exists to explain exactly this was itself
  stuck behind the queue. Every request now carries a 20-second timeout, a poll
  will not start while its predecessor is still in flight, each health-probe
  leg is hard-bounded at five seconds (a timeout is the down verdict), and the
  health cache is single-flight, so N cold polls no longer launch N parallel
  hanging probes. The banner arrives in seconds instead of a minute and a half.
  The notification bell also carries a standing entry for each dependency that
  is currently down (Security Onion / Elasticsearch, the LLM gateway), read
  from the warm health cache — the notifications path never probes
  Elasticsearch itself, so it keeps working precisely when Elasticsearch is
  what is broken. A dismissal holds for the duration of that outage.
- **The agent is made to fix an ungrounded claim instead of publishing it with
  a caveat.** The narrative-grounding validator has always detected per-event
  facts an answer asserted that appear in no tool result, and has only ever
  appended a warning. On 2026-08-05 a chat answer asserted a successful
  authentication to overturn a correct true-positive verdict; the validator
  flagged that exact claim as ungrounded, and the answer shipped anyway —
  caveat attached, verdict flipped. Detecting a fabrication and then publishing
  it is not a guardrail. The finding now goes back to the agent as a correction
  naming the offending claims, with two permitted resolutions: call a tool that
  establishes the claim and cite it, or remove the claim. Hedging the claim is
  not a third option, because a softened fabrication is still a fabrication.
  `chat_regrounding_attempts` (Config → Agent, hot, default 1) bounds it; each
  attempt costs a full turn against `chat_turn_timeout_s`, and 0 restores the
  warn-only behavior. The caveat is still the terminal fallback for an agent
  that will not comply, so nothing got weaker.
- **A hunt query written as `field:(a OR b)` no longer matches nothing and
  then reports that as a finding.** The OQL grammar rejected the Lucene-style
  value group at the parenthesis, and the analyst model writes that shape
  constantly — 23 of 47 parse failures in one 4,000-event window on the live
  deployment. Each rejected query became zero coverage, and the hunt reported
  the absence with confidence: one live hunt concluded a term appeared nowhere
  on the grid on the strength of queries that could not have matched. Value
  groups now parse and expand to one term per value under a single `OR`. Bare
  terms (`... AND somename`) stay unsupported, since implicit full-text would be
  guessing at what was meant, but the parse error now states the contract it
  will accept — `field:value`, `AND`/`OR`/`NOT`, both parenthesis forms,
  `message:term*` for full text — because that error string is the agent's only
  channel for correcting itself.
- **A long chat turn no longer looks the same as a hung one.** A turn that
  called several tools showed a bare typing indicator until it finished, so a
  thorough answer and a wedged one were indistinguishable, and analysts stopped
  waiting on the good ones. The dock now names the current step under the dots
  in analyst language ("Querying events · 3 steps"), updated as each tool
  starts. It rides the poll that was already there: no new endpoint, no
  streaming connection, nothing extra to get through a reverse proxy.
- **A hunt objective longer than a paragraph is accepted.** The cap was 2,000
  characters, and a brief that names scope, exclusions and the behaviors to
  look for runs past that easily. It came back as a bare 422 with nothing the
  analyst could act on. The limit is now 12,000 characters across the console,
  schedules and templates, which all take the same analyst-written text. It is
  still bounded, because the objective is prepended to the agent's prompt and
  an unbounded paste would eat the context budget. The objective box is a
  textarea rather than a single-line input: four rows, scrolls and resizes,
  Shift+Enter for a newline (Enter still launches), a counter past 80% of the
  limit, and a client-side maximum mirroring the server's so the UI cannot
  compose a request the API will reject.
- **The dashboard's verdict tiles and severity bars are links.** Both were dead
  numbers. A verdict tile opens the Investigations list filtered to that
  verdict over 30 days — deliberately wider than the dashboard's own window,
  which closes the gap where a standing needs-more-info count had no age bound
  while the list it should have pointed at defaulted to 24 hours. A severity
  bar opens the Alerts list filtered to that severity (`/alerts?sev=`, a new
  URL parameter), since severity belongs to the alert group rather than to an
  investigation.
- **A superseded needs-more-info run is reachable under the needs-more-info
  filter.** The Investigations list groups runs by alert group and shows the
  newest as the visible row, so a run left at needs-more-info that a later run
  superseded disappeared from its own filter: the newer row did not match, and
  the older one was folded underneath it. That filter now promotes the matching
  run to the visible row, which the pipeline-error filter already did.
- **A chat reply that lands while you are on another screen is not lost.** The
  investigation chat took a one-shot snapshot of its thread when the screen
  mounted and only began polling once you sent a message, so a reply that
  completed while you were elsewhere existed only in the database — navigate
  away and back and it was gone, along with any sign that a turn was still
  running. The screen now syncs the thread on mount, restoring both a finished
  reply and the typing indicator for a turn still in flight.

## [1.2.7] - 2026-08-05

The lesser-model release: soc-ai now adapts to whatever analyst backend is
behind the gateway by configuration and measurement instead of code changes,
and failed pipeline runs explain themselves. No breaking changes; two
migrations (0022, 0023).

### Added

- **A model fitness battery.** The Config console's fitness check gains an
  on-demand second tier: "Run full battery" probes the selected analyst model
  under every structured-output configuration (tool, native, prompted,
  tool+required) through the real synthesizer contract, shows per-config
  usable rates and timings, and — when a configuration strictly beats the
  baseline — offers a deterministic, explained recommendation ("native: 4/4,
  7.0x faster than tool mode") that one click stages into the normal config
  Apply flow. Runs as a background task with live progress (minutes on a CPU
  tier); the last result persists per model with its age (migration 0022);
  every run lands a `model_battery` audit event. Never auto-applies.

- **`soc-ai model-probe`.** A contract probe for candidate analyst backends: it
  runs the real synthesizer agent N times against a canned scenario and tallies
  outcomes into failure classes (`schema_retry_exhausted`, `http_5xx`,
  `timeout`), reporting which backend actually served via the gateway's own
  attribution headers. `--min-ok` makes it CI-gateable. The first command to
  run before pointing prod at a new or lesser model.
- **Per-backend adaptation knobs.** `synthesizer_output_mode`
  (`tool`/`native`/`prompted`) selects how the no-tools synthesizers obtain the
  TriageReport — `native` uses server-side guided decoding (`response_format`
  json_schema), which removes both schema wobble and the tool-call parser from
  the path. `analyst_tool_choice_required` lifts the historical forced-`auto`
  workaround per backend. Both default to today's exact behavior.
- **Backend attribution on success.** Usage events now carry `served_backend`
  (api_base, deployment, attempted fallbacks) like error events already did, so
  verdict quality can be sliced by backend after a fallback window.
- **A lesser-model runbook.** `docs/LESSER_MODELS.md`: the recorded failure
  taxonomy, the knob for each failure shape, the timeout ladder, and the probe
  workflow.
- **Select-type settings in the Config console.** Fixed-choice settings render
  as dropdowns with server-supplied options and save-time membership
  validation; the two new knobs are registered in the Agent section, both
  hot-apply.
- **A daily fitness cache.** The quick fitness check is cached per model with
  a 24h TTL, so opening the Config page renders the stored grade instantly
  with its age; "Check fitness" forces a fresh measurement, and "Run all
  checks" runs fitness plus the full battery in one click.

### Fixed

- **Failed pipeline runs are diagnosable instead of silently terminal.** Every
  terminal failure path (timeout, cancel, crash) now persists an error event
  with a hint; the auto-triage per-target cap can no longer pre-empt the more
  informative whole-run backstop (and is floored against misconfiguration);
  gateway/backend failures are no longer misattributed to Elasticsearch in
  operator hints, and bare gateway 5xx responses now carry a hint at all; the
  round-2 loop synthesizer gets a real schema-retry budget; error and usage
  events record which backend actually served the call (`served_backend`), so
  an aliased or fallback-routed model can no longer misattribute a failure.
- **Citations the model actually writes now resolve.** The citation validator
  recognizes the reference shapes the analyst model emits, ending a class of
  spurious needs-more-info coercions.
- **The model-fitness check no longer cries wolf.** Its per-leg and total
  budgets were internally inconsistent and sized below a reasoning model's
  real latency, producing intermittent false "unfit" grades on a healthy
  model; budgets are now consistent (pinned by test) and a probe timeout
  reports the legs that completed plus where it stopped, instead of nothing.
- **The battery recommendation is honest about applied settings.** When the
  current knob values already match the recommendation, the panel says so
  instead of offering a no-op Apply.
- **Weak-model output-shape wobble no longer burns schema retries.** Verdict
  formatting variants ("False Positive", "false-positive") fold to canonical;
  a bare string citation wraps into a list; a bare recommended-action object
  wraps into a one-element list; null sentinels on those fields become empty.
  Packaging only — synonyms, prose, and unknown action tools still fail.

## [1.2.6] - 2026-08-01

An About page and a ground-up restructure of the Config page. No schema changes.

### Added

- **An About section.** Config → System → About shows the running version, the
  license, and links to the GitHub repo and releases; a quiet version line in
  the sidebar footer deep-links to it, and the command palette gains an "About
  soc-ai" entry. The running version was never visible in the UI before.
- **An opt-in update check.** `GET /api/v1/about` serves the build metadata, and
  `POST /api/v1/updates/check` (admin) compares the running version against the
  latest GitHub release. Off by default and faithful to the zero-egress posture:
  no outbound call of any kind until an admin enables `update_check_enabled`
  (under Privacy & Egress), manual-only with no polling, the version compared
  locally so nothing about the deployment is sent, and a clean inconclusive
  result — never a crash, never a leaked host — when GitHub is unreachable or
  returns something unparseable.
- **Settings search.** A filter box over every setting's label, key, and help
  text plus the section names and Danger Zone entries; a hit jumps to the owning
  section with the exact row flashed. The command palette gets the same corpus:
  typing a settings concept ("inherit", "egress") now lands on the setting
  instead of "No matches".

### Changed

- **The Config page is master-detail.** It was one ~36-screen scroll of all 31
  sections; the section nav now drives a pane that renders only the selected
  section (~2 screens). Every existing deep link still works, the last-visited
  section and collapse state persist per operator, and every section is
  reachable from the nav at laptop viewport heights.
- **The Apply bar names its changes.** Each staged edit is a chip (tooltip shows
  old → new); clicking a chip returns to the owning section with the row
  flashed, and each chip can be discarded individually — no more committing
  "Apply changes (3)" blind.
- **Internal identifiers are a real table.** The auto-detected identifier lists
  gained a per-kind filter, first-25 paging with "Show all", and bulk
  select-and-act (enable / disable / dismiss, confirm-gated) — replacing an
  unpaginated wall of hundreds of rows.

## [1.2.5] - 2026-08-01

A visual refresh of the alert workspace, a code-review remediation across the
1.2.x line, and a batch of dogfood fixes from the live deployment. No schema
changes.

### Added

- **Toast notifications.** Transient events (a triage finishing, a bulk action
  landing, a background poll failing) surface as dismissable toasts instead of
  inline banners that pushed the page around as they appeared. The Notifications
  page gained a "Clear all" that dismisses every entry at once.
- **Freshness indicators on live surfaces.** The Alerts, Notifications, and
  Entity screens show when their data last refreshed and raise a stale notice
  when a background poll stops landing, so a wedged poll is visible instead of
  passing for quiet.

### Changed

- **Alert workspace redesign.** Colors, spacing, and radii come from CSS
  custom-property design tokens rather than scattered literals. The filter bar
  and the bulk-action bar now share one row that morphs on selection instead of
  stacking a second bar and shifting the table below it. Activity indicators are
  consolidated and per-row feedback moved to toasts.
- **Consistent error and retry states.** A failed load shows an explicit retry
  control instead of an empty panel, and open modals hold focus and block
  background scroll while they are up.
- **Review remediation across the 1.2.x line.** A full code review produced 58
  findings; the fixes tightened request-auth scoping, the scheduler's
  storm-protection window, and reverse-proxy header parsing, among others,
  without changing a public contract.

### Fixed

- **DNS-SD / SRV service records no longer pollute the internal-domain
  inventory.** The internal-domain-suffix auto-detector ingested mDNS service
  types (`_dns-sd._udp.local`, `_printer._tcp.local`) and a doubled suffix as if
  each were a host's own domain. Underscore-prefixed service labels (RFC 6763 /
  RFC 2782) are now filtered before any suffix or bare host is recorded.
- **The alerts table stops shifting when a row is selected.** The morphing
  filter/bulk row is pinned to a fixed height, so selecting an alert no longer
  nudges the table below it.
- **The notification bell opens immediately.** Opening the bell used to hang for
  seconds while it fetched; it now renders from cached state and refreshes in the
  background. Further dogfood fixes landed for the config console, chart
  accessibility, and the command palette.

## [1.2.4] - 2026-07-24

A dogfood patch: four rough edges found during an analyst shift on the live
deployment. No schema changes.

### Fixed

- **Scheduled hunts no longer look active while they are paused.** A per-schedule
  "on" pill in the Hunt Console read as running even when the global
  scheduled-hunts switch was off, so nothing actually fired. The console now shows
  a banner that links to the setting and marks each row "on (paused)" while the
  global switch is off. `GET /api/v1/hunt-schedules` returns the master-switch
  state alongside the schedules.
- **The triage pipeline recovers from a transient grid blip.** A momentary
  Elasticsearch or Security Onion transport error during the prefetch step used to
  end the investigation in a manual-recovery error state. That step now retries
  with backoff on transient transport errors only; a genuine "alert not found" or
  a validation error still fails fast, without a fabricated verdict. Tunable via
  `prefetch_max_retries` and `prefetch_retry_base_delay_s`.
- **The nightly quality-regression alarm stops crying wolf on small samples.** At
  the default sample size of five, a single flipped verdict moved the agreement
  rate by exactly the alarm threshold, so one disagreement always paged. The alarm
  now scales its floor to the sample size and needs at least two flips to fire.

### Changed

- **The config console groups each external service with its own settings.**
  Turning an integration on now sits next to where you enter its key. The MISP URL
  is editable in the console beside the MISP key, the crawl4ai token moved from the
  Danger Zone to the ordinary API-keys panel, and help text that pointed at `.env`
  for settings the console already owns was corrected.

## [1.2.3] - 2026-07-23

A targeted fix: per-alert verdict inheritance now honors the configured inherit
window.

### Fixed

- **Per-alert verdict inheritance respects `webui_inherit_window_days`.** The
  alerts feed's rule-level inheritance fallback had no age bound, so an alert
  could display a verdict inherited from an investigation far older than the
  configured window — and never be re-triaged. The per-alert fallback is now
  bounded by the same window as the pair tier; the rule-group standing badge
  still reflects the rule's last disposition regardless of age.

## [1.2.2] - 2026-07-23

A security and correctness patch from a full code review of 1.2.1. Sixty-nine
findings were fixed across the agent, tools, API, oracle redaction, store, and
frontend, plus a decision-template fix that spares a high-volume class of benign
informational alerts from a redundant investigation loop. No new features and no
schema changes.

### Security

- **The evidence gate requires real evidence.** A data-free tool call (a
  zero-hit query, a clean-internal enrichment) no longer satisfies the hard
  evidence gate, and a verdict grounded only in a prefetched IOC hit must agree
  with that hit. This closes several ways a verdict could settle without a
  genuine investigation.
- **Auto-acknowledge is opt-in and bound to the investigation.** The unattended
  false-positive acknowledge path defaults off, honors the same attack-classtype
  guard as oracle escalation, and executes only against the alert the analyst
  approved — never a target chosen by model output.
- **Oracle redaction gaps closed.** The cloud-egress sanitizer now redacts
  Windows profile and UNC paths, single-label hostnames written with a trailing
  root dot, and defanged indicators in web-search queries, and it masks the full
  length of a multi-word secret. The eval path threads the operator's configured
  internal hosts and suffixes through its own sanitizer and residue gate, and
  never re-sends a rehydrated (desanitized) critique to the cloud.
- **SSRF hardening in the page-fetch tool.** The internal-range guard rejects
  carrier-grade-NAT (100.64.0.0/10) and every non-global range, and DNS
  resolution runs off the event loop so a slow or hostile resolver cannot stall
  the server.
- **Audit trail.** Windowed chain verification no longer false-positives "tamper
  detected" on a normal deployment, and the redactor masks the whole multi-word
  secret value.
- **Auth and session hygiene.** The CSRF origin allowlist no longer trusts the
  Security Onion grid origin; an admin password reset revokes previously minted
  API tokens; unauthenticated login bodies are size-capped; the CLI warns when a
  bearer token would ride over unverified TLS; and the bootstrap admin password
  is written to a `0600` file instead of the log.
- **Denial-of-service caps.** Hunt and investigation chat, alert-action batches,
  auto-triage batches, OQL group-by and count stages, and the always-on triage
  time windows are now bounded so a single caller — or the model — cannot
  overload the app or the Elasticsearch cluster.
- **Supply chain.** Container base images and the compose quick-start pin by
  digest or explicit tag, and the GitLab CI `uv` install is version-pinned.
- **Frontend.** The markdown renderer rejects protocol-relative link and image
  URLs.

### Fixed

- **Benign informational alerts skip the redundant investigation loop.** The
  benign decision templates now judge the external endpoint regardless of flow
  direction, so a server-side observation (a TLS certificate, JA3S, or banner)
  whose external counterparty is the connection *source* is recognized without a
  full tool-driven investigation.
- A batch of correctness fixes across advisory-action idempotency, group-ack
  semantics, chat-turn isolation, redaction case-folding and word boundaries,
  runbook full-text search, tool-result clamping, and frontend polling and error
  handling. The per-commit history has the full list.

## [1.2.1] - 2026-07-21

A quality patch: the two failure modes behind the dashboard's "pipeline
errors" KPI are now self-healing or fully diagnosable, hunts regained their
telemetry-first latitude, and the docs caught up with the code.

### Added

- **Public roadmap.** `docs/ROADMAP.md` tells the release story with a
  you-are-here graphic and an honest list of what ships dark behind
  default-off switches. Linked from the README and the docs site nav.
- **Hunting-flavored OQL examples.** Hunts (and hunt follow-up chat) get
  telemetry-first worked examples (dataset scoping, first-seen destinations,
  cadence measurement) in place of the alert-triage primer examples;
  investigator and alert-chat prompts are unchanged. The examples are also a
  docs page (`docs/OQL_HUNT_EXAMPLES.md`).

### Fixed

- **Schema-retry pipeline errors self-heal.** The most common pipeline error
  (the analyst model emitting a nested report field as a JSON-encoded string,
  burning every retry identically) is now tolerated at the schema layer:
  stringified containers are decoded in place, and strings that aren't valid
  JSON still fail loudly. Retry exhaustion, when it does happen, records each
  attempt's validation cause on the error event and the report, so the KPI
  drilldown says exactly what went wrong.
- **Budget-cut investigations land real verdicts.** When the tool budget or
  wall clock cuts an investigation short with no settled round-1 verdict, the
  gathered evidence is replayed through a partial synthesizer (the same
  pattern hunts use) instead of discarding it for a generic fallback.
- **Hunt corroboration gate credits telemetry found via OQL.** The gate now
  partitions OQL results per document: a Zeek record found through the broad
  lens corroborates a high-severity finding, while alert documents still
  cannot corroborate the claim they raised. Generic hunt sweeps no longer
  re-disposition alerts; triage owns the alert stream.

### Docs

- Accuracy pass across the whole set: retired every shipped-feature-described-
  as-future claim (runbook retrieval, API auth, external TI, tuning
  suggestions, the web console itself), caught the docs changelog up from
  1.0.6 to current, fixed stale version strings, and rewrote the dev roadmap
  as a reality ledger.

## [1.2.0] - 2026-07-16

A dogfood-driven release: a full analyst shift on the live deployment produced
fourteen findings, and this release fixes all of them plus the follow-ups.

### Added

- **Pipeline errors are now clickable and dismissible.** The Dashboard's
  "N pipeline errors" note deep-links to the pre-filtered Investigations list;
  each fallback run's detail page has a **Dismiss** button beside Re-run
  (`POST /investigations/{id}/dismiss-error`, new `error_dismissed_at` column,
  migration 0021). A fallback run superseded by a successful re-run no longer
  counts — re-running *is* the fix. The pipeline-error filter also surfaces
  superseded (non-primary) runs instead of hiding them under their primary.
- **Deep re-run.** Re-running a "heuristic · no tools" verdict used to repeat
  the fast path. `POST /hunt` gained a per-run `deep` flag that forces the
  full tool-driven loop, and the drawer offers **Deep re-run** whenever the
  completed run made zero tool calls.
- **⌘K entity search.** The palette now searches investigations (rule name,
  src/dst IP, id → permalink) and alert groups in addition to screens and
  actions — typing a rule fragment or an IP finds the thing you're looking at.
- **Completion notifications.** The bell lists last-24h completed
  investigations (verdict + tone) and finished hunts (finding count) as
  durable, dismissible items with permalinks — the badge can no longer
  advertise something the panel can't show, and a 17-minute hunt now tells
  you when it lands.
- **Detection-tuning suggestions are surfaced.** A Dashboard panel shows the
  count of pending mute recommendations (`GET /detection-tuning/summary`) and
  links to Config → Detection tuning; a verdict that cites the rule-tuning
  tool gets a direct "review the suggestion" link. Previously the
  recommendations sat unseen while auto-investigate kept spending runs on
  rules already known to be benign noise.
- **Pending acks explain themselves.** When auto-ack was armed but held back
  (high/critical severity or exploit-class guard, or below the confidence
  threshold) the pending action says why (`auto_ack_skipped` event).
- **Scheduled-maintenance panel.** `GET /maintenance` + Config → System →
  Scheduled maintenance show the observed facts of the host cron jobs: backup
  archives in the data volume (name / size / time) and blocklist-feed
  freshness — with an honest "cron has not run" cold state.
- **Verdict quality is schedulable from the UI.** The nightly micro-eval core
  was extracted from the CLI (`soc_ai/eval/nightly.py`) and is now runnable
  three ways sharing one single-flight slot: the existing `soc-ai
  eval-nightly` CLI (unchanged flags/exit codes), a **Run now** button on the
  Dashboard's Verdict-quality card (`POST /quality/eval/run` + status
  polling), and an in-app scheduler (`eval_nightly_enabled` +
  `eval_nightly_hour_utc`, Config → Quality) that runs once per UTC day and
  defers to a snapshot that already landed.

### Fixed

- **The recommended-action ACK is group-scoped.** Executing "Acknowledge
  alert" acked one event while the settled bar acked the whole group — the
  queue never shrank after "Executed ✓". It now acknowledges every unacked
  event of the detection (same contract as `/alerts/ack-group`), reports the
  count, and the Alerts list hides the group optimistically while the ES
  aggregation catches up (re-surfacing on newer events).
- **The Oracle is never consulted on a pipeline-fallback run.** A mechanical
  failure placeholder carries `needs_more_info`, which tripped the escalation
  gate and burned heavy-model tokens on "Oracle did not return a verdict".
- **Chat's unverified caveat is scoped when tools ran.** The blanket "not
  backed by a tool result" no longer contradicts a visible tool-call footer;
  it names the specific ungrounded artifacts instead. Zero-tool turns keep
  the blanket wording.
- **The settled-action bar is suppressed on fallback runs** — no more
  "VERDICT SETTLED — TAKE ACTION" directly under "this run failed before
  reaching a verdict".
- **Markdown renders where markdown is shown.** Model-reasoning traces render
  through the Markdown component; runbooks open in rendered preview (Write
  one click away); runbook list excerpts strip markdown syntax.
- **Filtered-empty investigation lists say so** instead of rendering a blank
  table when every match was tucked under a filtered-out primary.
- Executed-action attribution shows the real username (was hardcoded
  "analyst"); backtest results show when they ran; console-started hunts read
  "kind: manual"; auto-triage skip counts explain themselves ("74 verdict
  inherited · 9 already triaged"); Notifications/Backtest/Runbooks got their
  missing breadcrumbs; icon-only chrome buttons got aria-labels.

## [1.1.1] - 2026-07-11

### Added

- **Re-hunt and multi-select on the Hunts page.** A hunt can now be re-run
  directly: a "Re-hunt" button on the hunt detail (prominent on failed /
  interrupted hunts, a quiet secondary action on completed ones) and a per-row
  re-hunt icon on the hunts list. Re-hunt is a **clean re-run of the objective as
  a fresh hunt** — it does NOT seed the prior hunt's narrative (that would poison
  a re-run of a broken hunt); because the objective hash matches, the fresh run
  automatically gets the "vs last run" diff. The hunts list also gained
  Investigations-style **multi-select** (a checkbox column + header select-all)
  with bulk **Re-hunt selected** and **Delete selected** actions and an
  expandable "Started N · M skipped" result panel. Bulk re-hunt is **throttled**
  — it starts only the first few hunts and returns the rest as `queued` — so a
  large selection can't launch many concurrent hunts at the single model route.
  New endpoints `POST /hunts/rehunt` and `POST /hunts/bulk-delete`.
- **Host summaries now infer OS from telemetry-domain evidence** (Apple / Windows
  / Linux / Android) when no User-Agent is available, so an OS-specific compromise
  claim can be checked against what the host actually is. `t_host_summary` gained
  an additive, evidence-bearing `os_hint` (`{os, confidence, signals, basis}`)
  derived from the vendor telemetry the host queried / SNI'd — the DNS/TLS traffic
  a modern TLS-only device leaves even with an empty User-Agent. A User-Agent guess
  stays primary and the hint corroborates it (or notes a conflict); the hint only
  becomes `device_os_guess` when there is no UA. "Linux" is only ever inferred from
  positive distro telemetry, never from the absence of other families — so a "Linux
  backdoor" alert on a MacBook is now contradicted by the host's own Apple traffic.

### Fixed

- **Hunts no longer assert compromise from alert titles alone.** A high/critical
  threat finding now requires corroborating evidence beyond the detector alert
  that raised it (a decoded payload, a measured beacon cadence, a blocklist/MISP
  or enrichment hit, host prevalence, or a host artifact) or its severity is
  capped — citing the Suricata alert that IS the claim no longer satisfies the
  gate. The hunt prompts now require reading the signature and confirming the
  host's OS before claiming an OS-specific implant (Apple/icloud telemetry means
  macOS/iOS, not a "Linux backdoor"), and treat a solicited ICMP echo reply that
  merely matches a heartbeat signature as an uncorroborated false positive.
  Budget/timeout-truncated hunts are now marked low-confidence (their overall
  confidence is clamped and their threat findings capped), and the exploration
  model's own reasoning — where it had already debunked the false positive — is
  fed into the partial-report write-up so a loud alert title no longer overrides
  it.
- **Hunts that hit their exploration budget now produce the partial report
  instead of erroring.** Exhausting the tool-call budget always left the
  transcript ending in unexecuted tool calls, which the partial-report
  synthesizer refused to replay — every budget-capped hunt errored and its
  gathered evidence was discarded. The transcript tail is now repaired (each
  unexecuted call closed out as "not executed — hunt budget exhausted") before
  synthesis. The default hunt budget was also raised from 60 to 90 tool calls
  to match current model behavior — the 2026-07-08 inference-engine change
  roughly doubled per-hunt tool appetite, making the old cap a wall every
  hunt hit.
- **Bulk investigation re-hunt is now throttled like the hunts side.** Selecting
  many investigations to re-hunt started every one at once against the single
  model route; it now starts only the first few and returns the rest as `queued`,
  the same concurrency cap the hunts page already had (a real incident showed
  simultaneous runs all hitting the wall-clock and producing garbage). The cap is
  checked before the per-row alert-name lookup, so it also bounds those queries.
- **Interactive investigations now honour the whole-run wall-clock timeout.** The
  `investigation_run_timeout_s` backstop was only enforced on background hunts; a
  slow-but-progressing interactive "Investigate" run could exceed it because only
  the per-turn timeout applied. The whole-run cap now lives in the shared recorded
  runner, covering the interactive SSE path and the background path in one place.
- **`soc-ai <command>` works inside the Docker container.** The image builds with
  `uv sync --no-install-project`, which never generated the `soc-ai` console entry
  point, so documented commands like `docker exec soc-ai soc-ai backup` and
  `soc-ai blocklists refresh` failed with "executable not found". A small wrapper
  now ships on the image PATH so the CLI (backup/restore/blocklists/audit/doctor)
  works in-container, matching the from-source install.

### Changed

- **Container logs are now size-capped** (`json-file`, 5 × 50 MB) so an always-on
  triage loop plus the healthcheck can't grow the log unbounded and fill the disk.
- **Prebuilt (`--prebuilt`) installs pin the image tag.** `setup.sh` resolves the
  release version and writes `SOC_AI_IMAGE_TAG` into `.env` instead of tracking the
  mutable `:latest`, so an upgrade is a deliberate re-pin, not a surprise pull.
- **Guided install collects the abuse.ch key and offers blocklist scheduling.**
  `setup.sh` now prompts for `ABUSE_CH_AUTH_KEY` (blank to skip) so URLhaus / Feodo
  / ThreatFox actually seed, and a cron example (`scripts/cron.d/`) refreshes
  blocklists on the Docker deployment (previously only the host-venv systemd timer
  did). `docs/DOCKER.md` gained a backup-scheduling recipe and a "back up before
  upgrading" step.
- **`.env.example` no longer weakens the secure audit default** (`AUDIT_REDACT`
  ships commented so installs inherit the code's redact-on default) and documents
  the timeout/retry knobs for discoverability.
- Frontend build stage moved to Node 22 (Node 20 is end-of-life); `vitest` bumped
  to 3.2.7 for a dev-only advisory (GHSA-5xrq-8626-4rwp).

### Security

- **The audit hash chain can now be verified.** The tamper-evident chain already
  existed, but nothing let an operator check it — the whole point of the property.
  Added `soc-ai audit verify` (CLI) and an admin-gated
  `GET /api/v1/config/audit/verify-chain`; both page the audit index and report
  whether the chain is intact or where it broke.
- **Agent-rendered markdown pins a link allow-list in code.** The shared renderer
  for all agent output now applies an explicit URL transform (http/https/mailto +
  relative only) rather than relying on react-markdown's library default, closing
  a latent stored-XSS vector should that default ever change. Agent output is
  derived from attacker-influenced data.
- **OQL pipe-splitting tracks single- and double-quoted strings**, so a `|` inside
  a single-quoted value can no longer smuggle a spurious pipe-stage break through
  the read-only query boundary.
- **Startup warns loudly when `API_AUTH_REQUIRED=false`** — with auth off the admin
  gate is a no-op (secret edit, user/token creation are open); the warning is
  escalated when the bind is non-loopback.
- **Supply-chain hardening for CI.** Third-party GitHub Actions are pinned to commit
  SHAs (the tj-actions compromise class), workflows run with least-privilege
  `permissions`, and the public-mirror leak scan now hard-fails instead of warning.

## [1.1.0] - 2026-07-10

The measurement release. 1.0.8 built the honesty machinery; 1.1.0 makes it
continuously measured (nightly quality trend with a regression alarm),
inspectable down to the span (highlighted redaction previews), and fed by your
own institution's knowledge (a real runbooks workspace, history-distilled
drafts, chat-transcript memory). Plus the ops floor a self-hosted tool owes
you: one-command diagnosis, WAL-safe backups, published container images, and
an install hardened by literally role-playing an impatient analyst on a bare
box.

### Added

- **Runbook drafts distilled from your own history.** The Runbooks page lists
  rules with three or more completed investigations and no covering runbook;
  one click turns the observed verdicts, rationales, and analyst chat into an
  org-specific DRAFT runbook. Drafts are excluded from every agent retrieval
  tier until you approve them, the distillation call honors the analyst
  egress redaction end to end, and every promotion is audited.
- **`soc-ai backup` / `soc-ai restore`.** WAL-safe snapshots via SQLite's
  backup API — safe while the app runs — with a manifest, the signing key and
  sensor trust anchors included, and re-downloadable caches excluded unless
  `--full`. Restore refuses to clobber an existing store or a running app
  without an explicit `--yes`, and refuses archives from a newer soc-ai
  outright. Copy-paste docker command blocks in docs/DOCKER.md.
- **Continuous quality measurement (`soc-ai eval-nightly` + the Verdict
  quality card).** A nightly micro-eval investigates a few real alerts through
  the normal pipeline and trends the results locally (new `quality_snapshots`
  table, pruned to 90 rows), so a silent verdict regression — e.g. after an
  inference-engine swap — bends a sparkline on the dashboard instead of going
  unnoticed. Two honest modes, never blended: **oracle-graded** (agreement
  rate; one cloud call per alert, the default only when `oracle_enabled`) and
  **zero-egress local** (fallback/error rates, verdict distribution, latency
  p50 — no oracle at all; the card labels which mode measured each point). A
  regression against the trend's own trailing same-mode median (agreement drop
  > `quality_alarm_drop`, error rate > 30%, or a fallback-rate jump) fires a
  `quality_regression` audit event plus the opt-in notification webhook, and
  red-flags the card. Scheduling stays on the host (cron → `docker exec`, see
  docs/DOCKER.md); new admin-editable settings `quality_nightly_n` and
  `quality_alarm_drop` live in the config console's Quality section, with
  `GET /api/v1/quality/trend` as the admin read-model.
- **A first-class Runbooks page** (`/app/runbooks`, in the sidebar): search,
  markdown editor with preview, tags and linked rules, multi-file `.md` import
  with lenient front-matter parsing, and embed-status chips when the semantic
  tier is on. Ships with a **starter pack of ten vendor-neutral SOC runbooks**
  (`runbooks/starter-pack/`) loadable in one click — idempotent, never
  overwrites your own. The old Config section is now a compact signpost.
- **Chat-transcript memory (context, never evidence).** When investigation
  memory is on, synthesis also recalls relevant excerpts from past analyst↔AI
  chats (investigation and hunt threads) via a new local full-text index.
  Excerpts are hard-framed as context only — user statements are labeled as
  unverified operator opinion on every line, transcript-grounded citations are
  rejected by the evidence gate, and excerpts ride the full egress-redaction
  path. New hot setting `memory_include_chat` (effective only with
  `memory_enabled`).
- **`soc-ai doctor`** — one command that checks the whole dependency surface
  in ~15 seconds: config, database + migration head, FTS5 availability,
  Security Onion and Elasticsearch auth vs reachability, gateway + configured
  models, the model-fitness probe, egress posture, and blocklist freshness —
  each with a concrete fix hint. `--json` for automation; the bug-report
  template asks for its output.
- **Published container image on GHCR.** Every `v*` tag now builds the
  Dockerfile (linux/amd64 + linux/arm64) and pushes
  `ghcr.io/nuk3s/soc-ai:{version}` + `:latest`, gated on the full CI suite
  passing first (`.github/workflows/release.yml`). `./setup.sh --prebuilt`
  (or `docker compose pull soc-ai && docker compose up -d`) runs the published
  image with no local build; `SOC_AI_IMAGE_TAG` pins a version. Plain
  `docker compose up`/`up --build` still builds from source, unchanged — note
  the compose image name is now `ghcr.io/nuk3s/soc-ai` (was `soc-ai:latest`),
  so the next `up` on an existing install rebuilds once under the new name.
- **Contributor surface.** A root `CONTRIBUTING.md` (dev setup, the exact CI
  gates, the browser-smoke how-to, and privacy-first scope guidance citing
  the safety model), structured GitHub issue forms (the bug form asks for
  `soc-ai doctor --json` output), and a PR checklist mirroring the CI gates.
- **Runbook retrieval upgraded to full-text search, with an optional semantic
  tier.** Runbook lookup (both the agent tool and the console) now uses SQLite
  FTS5/BM25 ranking — built into the SQLite already shipped, zero new
  dependencies, zero egress; installs whose SQLite lacks FTS5 fall back to the
  previous scorer transparently. For large corpora, a new "Retrieval (RAG)"
  config section can point `rag_embed_model` / `rag_rerank_model` at your
  OpenAI-compatible gateway (both off by default): embeddings are stored
  locally, retrieval blends keyword and semantic hits, and a "Re-embed
  runbooks" button (plus `POST /api/v1/config/rag/reembed`) refreshes the
  index. The egress-policy page lists the retrieval gateway as a destination
  when enabled.
- **Investigation memory (opt-in, off by default).** With `memory_enabled` on,
  verdict synthesis sees up to `memory_max_items` prior verdicts for similar
  alerts — matched deterministically (same rule + source/destination overlap,
  most-specific match first, `memory_window_days` window), no embeddings, no
  new services. Prior outcomes are explicitly framed as context, never
  evidence: they cannot be cited, fallback-produced verdicts are excluded, the
  block passes through the analyst egress guard, and a `prior_outcomes`
  timeline event records exactly what was recalled. Leave it off until you've
  evaluated anchoring effects on your own alert mix.
- **Analyst-path redaction preview.** The redaction preview panel gains an
  "Analyst path" tab: pick any past completed investigation and see exactly
  what a cloud analyst model would receive — the rebuilt synthesis prompt,
  original vs redacted under your current identifier config, with per-category
  redaction counts and an explicit banner when analyst redaction is currently
  off. Read-only, nothing is sent anywhere
  (`GET /api/v1/analyst/redaction-preview/{id}`).

- **Redaction previews highlight exactly what was redacted.** Both the Oracle
  sample and the Analyst path preview now mark every internal value (amber, in
  the original pane) and every opaque label (green, in the sanitized pane),
  with hover tooltips naming the counterpart and a per-category span count.
  The replacement pairs come from the sanitizer's own mapping, filtered to
  what the preview actually redacted — never the whole identifier config.

### Security

- **DNS-SD / mDNS hostnames now redact correctly.** Service-record names with
  underscore-led labels (`_service._proto.<your-suffix>`) escaped the
  redaction pattern at every layer; the fail-closed egress gate caught one in
  real eval traffic and refused the send — investigating it showed the
  detection was partly luck, and a sibling form would have leaked silently.
  The pattern now accepts underscore-led labels at all three declaration
  sites, and a 640-case property test pins the invariant: anything the
  residue detector flags, the redactor must have caught first.

### Changed

- **The Config page is organized into six sections** (Models & Reasoning,
  Triage & Workflow, Retrieval & Memory, Privacy & Egress, Data & Enrichment,
  System) with a two-level nav, and the section highlight now tracks clicks
  correctly — the old scroll-spy could light the wrong row after a jump.
- **The Runbooks page uses the full screen**: searchable list on the left,
  editor filling the rest of the viewport, stacking on narrow windows.
- **RAG model settings are dropdowns** fed by your gateway's model list, with
  an explicit "(off)" and an "Other…" escape hatch for unlisted ids.
- **Config page section navigation snaps instantly** instead of a slow smooth
  scroll.
- **Hunt template affordance reads positively**: templates your grid can run
  are highlighted; ones needing missing telemetry keep their flag (wording
  inverted from "dimmed").
- **Machine-generated hunt titles stay short**: the agent is instructed to
  keep finding/chart titles to ~8 words, a deterministic 90-character clamp
  backstops it, and the hunt page wraps to two lines before ellipsizing.
- **The app loads faster**: route-level code splitting cut the initial
  JavaScript bundle from ~1 MB to ~214 kB; screens load on first visit.
- **Banner wording corrected** to match the safety model: "can run on
  self-hosted models" and "nothing leaves your network without your consent".
- **The demo dataset exercises every headline feature** (failed retries,
  pipeline-fallback chips, hunt diffs, redaction preview with highlighting,
  runbooks, assignment states, memory recalls) and the README screenshots are
  regenerated from it.

### Fixed

- **`./setup.sh --prebuilt` no longer strands you when no published image
  exists.** A failed registry pull now explains itself and offers to build
  from source in the same run, the README leads with the always-working
  command, and the health-check timeout points at `soc-ai doctor` before raw
  logs. Found by re-running the whole install on a bare Rocky Linux 10 box
  with an analyst's patience: clone to healthy container in 43 seconds.
- **An open tab now survives a redeploy.** Previously a deploy replaced the
  app's content-hashed chunks and an already-open tab could go blank on its
  next navigation (stale chunk → 404 → the whole page unmounted) until a hard
  refresh. Now: a failed chunk load auto-reloads the page exactly once (never
  loops), an error card inside the still-mounted shell backstops anything
  else, `index.html` is served `no-cache`, and the app checks for a newer
  build every minute (and on focus) — showing a "soc-ai was updated — reload
  for the latest" banner instead of silently running old code.
- **The browser E2E now actually runs in CI.** The `browser-smoke` GitHub
  Actions job referenced tests that were excluded from the public repository,
  so it failed on every run. The Playwright smoke and the demo-stack harness
  it drives now ship publicly (all demo data is RFC 5737 TEST-NET fiction).
- **Alerts-queue layout fixes** from a full visual audit: action buttons no
  longer overlap the "last seen" column on assigned rows, the assignment
  state chip no longer clips ("OWN…"), the severity tag no longer touches the
  source IP, and the destination port is no longer printed twice — which also
  fixes the source/destination entity pivots, which previously navigated to a
  port-suffixed value the entity page could not match.
- **The analyst redaction preview's "events missing" state no longer logs a
  browser console error** — it is a normal 200 response with a status field
  instead of an HTTP 409, and the panel shows the server's explanation for
  both non-previewable states.

## [1.0.8] - 2026-07-07

Trust, workflow, and threat-hunting release. This one is about honesty (the UI
now tells you when a verdict came from the fallback, not the model, and when a
hunt finding isn't backed by evidence), analyst throughput (assignment states,
keyboard triage, bulk transparency), a much deeper Hunt Console (scheduling,
templates, charts, run-to-run diffing, per-entity pages), and a hardened,
inspectable egress boundary (fail-closed redaction + a policy page).

### Added

- **Model-fitness check on the config page.** A probe reports whether the
  configured analyst model and context window are actually large enough for
  reliable triage, surfaced as a config chip — so an under-provisioned model is
  caught up front instead of showing up as silently poor verdicts.
- **Assignment / triage states for alerts.** An analyst can take ownership of an
  alert and move it through owned → in-review → done. Every state change is
  audited, so a shift handoff shows who has what and where it stands.
- **Keyboard-driven triage on the Alerts screen.** `j`/`k` to move, `o` to open,
  `a` to ack, `e` to escalate, `i` to investigate, `x` to select, and `?` for
  the shortcut cheatsheet — full-speed keyboard triage without leaving the list.
- **Opt-in notification webhooks** (`webui_notifications`, off by default). When
  enabled, soc-ai can POST a notification to a secret webhook URL on the events
  you choose; with the feature off there is zero outbound traffic. Useful for
  wiring triage events into chat/on-call without adding a cloud dependency.
- **Scheduled hunts.** A hunt objective can run on a recurring schedule
  (`hunt_schedules_enabled`) instead of only on demand, so recurring threat
  hunts run themselves and land in the console for review.
- **Hunt template library.** A curated set of starter hunt objectives you can
  launch with one click, so common hunts don't have to be re-typed from scratch.
- **Run-to-run hunt diffing.** A completed hunt is automatically diffed against
  the previous completed run of the same objective — new, resolved, and
  persisting findings are called out, so you see what *changed* since last time.
- **Charts in hunt reports.** The hunt agent can render charts from its
  findings, and each chart must cite the evidence behind it (uncited, empty, or
  runaway charts are dropped) — visual summaries you can still trace to data.
- **Per-entity pages.** `/app/entity/<host-or-ip-or-user>` gives every entity a
  single page aggregating the hunt findings that name it, so you can pivot from
  a name to everything the system has seen about it.
- **Feedback distillation for detection tuning.** Analyst overrides roll up
  per-rule into suggestions for which detections are noisy or miscalibrated.
  Nothing is auto-applied — a rule that has ever produced a true positive is
  never suggested for suppression — it's decision support, not an auto-action.
- **Egress-policy page.** A config page that shows exactly what categories of
  data can leave the box under the current settings, plus best-effort 7-day
  egress counts, so the trust boundary is inspectable instead of implied.
- **Cloud egress sanitizer for the analyst model** (`analyst_cloud_redaction`,
  opt-in, off by default). For deployments that point `analyst_model` at a
  cloud provider: every payload sent to the analyst model — enriched alert
  context, prompts (investigation, hunt, chat), and all tool results — has
  internal IPs/hostnames/usernames replaced with stable opaque labels
  (`IP_01`, `HOST_02`, …) using the same reversible redaction tunnel as the
  Oracle path; model outputs (verdicts, rationales, reasoning traces, hunt
  reports, chat replies) are label-restored before storage/display, and tool
  arguments coming from the model are restored before hitting Elasticsearch so
  the agent loop keeps working. Costs some verdict quality (the model reasons
  over opaque labels). See `docs/SAFETY_MODEL.md` → "Cloud analyst models".

### Changed

- **Fallback verdicts are now labelled as fallbacks.** When the deterministic
  pipeline (not the LLM) produces a verdict — because the model was unavailable
  or failed a gate — that verdict carries an explicit `pipeline_fallback`
  marker, gets its own chip and filter in the UI, and is excluded from the
  model-accuracy KPI. You can always tell whether a call was the model's or the
  fallback's, and the accuracy number reflects only the model.
- **Alerts show their last triage attempt.** Each alert badge now surfaces the
  most recent attempt (including reruns), so a rerun is visible rather than
  silently overwriting the prior result.
- **Bulk actions explain what they skipped.** Bulk rehunt and the auto-triage
  sweep now report per-item skip reasons instead of silently passing over
  alerts, so a bulk run is auditable at a glance.
- **Hunt findings must cite evidence.** A finding (or chart) that doesn't cite
  real supporting evidence is dropped by a citation gate rather than rendered —
  the console shows substantiated findings only.
- **Auto-acknowledge of high-confidence false positives is now ON by default**
  (`auto_ack_fp_enabled`). Both gates are unchanged — the confidence threshold
  (default 0.7) and the high-stakes guard (critical/high-severity or
  malware/exploit-class alerts are never auto-acked) — and every unattended ack
  is audited. Set `auto_ack_fp_enabled` to false (env or config console) to
  require a human click for every acknowledgement. Existing installs with a
  saved config-console override keep their setting.
- **Inherited verdicts now acknowledge their alerts.** An auto-triage sweep
  that skips a cluster because it inherits a qualifying false-positive verdict
  (same rule + source + destination within the inherit window) now acks those
  events in Security Onion. Previously the inherited verdict was display-only
  and the alerts lingered unacked forever.

### Security

- **Analyst-model redaction now fails closed.** Before any payload is sent to a
  cloud analyst model, the composed string is re-scanned for un-redacted
  internal identifiers; if residue is found, the request is blocked
  (`egress_blocked` audit event) and the deterministic fallback verdict is used
  instead of leaking. Redaction is no longer best-effort — a redaction miss
  stops the egress rather than letting it through.

### Fixed

- **The same flow is no longer investigated twice minutes apart.** The sweep
  planner now sees pairs with an in-flight investigation — the pair-verdict
  check is complete-only by design, so a newer event id in the same cluster
  used to launch a duplicate investigation while the first run was still
  executing (most visible with a short `webui_inherit_window_days`).

### Removed

- **The dead approval-gate machinery.** `POST /approve` (both the legacy
  prefix-less route and `/api/v1/approve`), the in-memory `ApprovalGate`
  (plus `GET /sessions/{id}`, which only listed its pending tokens), the
  `pending_approvals` field on `/healthz`, and the `socai_pending_approvals`
  metric are gone. Nothing could create a pending approval since the
  synth-first pipeline landed — the agent recommends write actions in the
  report and the analyst executes them through the actions API
  (`POST /api/v1/investigations/{id}/actions/{index}/execute`), which remains
  the single audited write path (`execute_write_tool`). Historical
  `approval_request`/`approval_required` events still render in old
  investigation timelines, permanently non-actionable.

## [1.0.7] - 2026-07-04

### Fixed

- **Acknowledge / escalate writes to Security Onion no longer fail after ~10
  minutes.** SO 3.0 expires its CSRF (srv) token 600 seconds after login and
  signals an expired token with a `400`, which the previous 401-only refresh
  never caught, so any write more than ten minutes after login (and every
  unattended auto-ack) failed. The token is now refreshed proactively and on a
  `400`, so ack, escalate-to-case, and auto-ack work for the life of the session.
- **Investigation timeline reads cleanly.** Tool-call rows show a short, plain
  title (`Host summary: 10.0.0.5 — 699 events`) instead of raw JSON; a disabled
  online lookup shows a neutral `skipped` line rather than a configuration notice;
  write actions group under Decision, not Tool calls; the full result stays in the
  row's expander.
- **The "Model reasoning" panel now appears on every investigation**, not only the
  ones that ran the deep investigation loop.
- **Source → destination no longer truncates** on the investigation view or the
  investigations list.
- **The acknowledge action reflects an alert that was already acknowledged**
  (elsewhere, or by an earlier run), and advisory-action executions are persisted
  so a reload never re-offers an escalate that already opened a case.
- **The hunt agent writes valid OQL** — the primer and parser errors now state the
  exact supported pipe stages (`groupby`, `sortby`, `head`, `count`) and that there
  is no `fields`/projection stage, ending a class of parse failures.
- Comma-separated environment values for the Oracle privacy gate and
  `PROXY_TRUSTED_IPS` load correctly instead of failing settings validation at
  startup.
- Phase-D targeted evidence tools (the Elasticsearch-query family) no longer fail
  to dispatch; several evidence-gate and audit events that were being dropped are
  now recorded.
- `X-Forwarded-Proto` is trusted only from a proxy listed in `PROXY_TRUSTED_IPS`,
  matching the existing `X-Forwarded-For` rule, so a client cannot forge the
  `Secure` cookie flag.
- A batch of web-console correctness fixes: idle polling no longer freezes the live
  views, terminal statuses render correctly, and a duplicate-key warning in the
  API-token list is gone.

### Added

- **Self-consistency vote on the final verdict**, off by default
  (`VERDICT_CONSISTENCY_SAMPLES=1`). Set it to 2–5 to run the final synthesis
  several times and majority-vote; a split lands the new `inconclusive` verdict.
- **CLI authentication:** `soc-ai triage` / `healthz` accept `--token` (or
  `SOC_AI_API_TOKEN`) and a `--verify` / `--cafile` TLS option, so the CLI works
  against the shipped secure default.
- A documentation-accuracy check in CI that keeps the agent-tools reference and the
  audit-event list in sync with the code.
- The online-enrichment tools (Shodan, GreyNoise, CVE lookup) register only when
  `ALLOW_ONLINE_ENRICHMENT` is on, so the agent never spends a tool call on a
  disabled lookup.

### Security

- Dependency updates clearing known CVEs: starlette, python-multipart, pyjwt,
  aiohttp, cryptography, idna, joserfc, and pydantic-ai.

### Changed

- The web API implementation was reorganised into a package of route modules
  (internal refactor; every endpoint path and response is unchanged).
- Documentation pass across the README and guides for clarity, and the console
  screenshots were regenerated against the current UI.

## [1.0.6] - 2026-07-03

### Removed

- **Retired the Tampermonkey userscript** ("Hunt with AI" in the Security Onion
  alerts view). soc-ai is now driven entirely from its own web console at `/app`
  (open a detection and **Investigate**, or sweep the queue with auto-triage) and
  the Hunt Console — no browser extension to install or keep updated. The API's
  cross-origin (CORS) support remains, config-gated and off by default, for
  programmatic clients and integrations. Existing userscript installs keep calling
  the API until you remove them; nothing server-side changed.

## [1.0.5] - 2026-07-03

Patch: a scheduler fresh-boot fix and green public CI.

### Fixed

- **Auto-triage scheduler fires its first sweep on a freshly-booted host.** The
  "last swept" marker used a `0.0` sentinel compared against `time.monotonic()`,
  whose epoch is arbitrary and near-zero right after boot — so on a fresh host the
  first enabled wake read as "just swept" and skipped the sweep for up to one
  interval. It now uses a `None` sentinel, so the first enabled wake always fires.
  (Also fixes a CI test that was green only on long-uptime machines.)

### CI

- Workflows updated to Node 24-native action versions (`actions/checkout@v6`,
  `actions/setup-python@v6`, `actions/setup-node@v6`,
  `actions/upload-pages-artifact@v4`), clearing the Node 20 deprecation warnings.

## [1.0.4] - 2026-07-03

Slow-stack resilience + detection release: bounded timeouts everywhere, a
malware-label payload gate, stronger hunts, and a settled-verdict action bar.

### Added

- **Wall-clock timeouts for a slow stack.** Dedicated, tunable knobs bound every
  long-running path so a slow gateway degrades gracefully instead of hanging:
  `hunt_run_timeout_s` (a hung hunt concludes with a grounded PARTIAL report, not
  an error), `hunt_chat_turn_timeout_s`, `investigation_run_timeout_s`, and a
  per-turn `investigation_turn_timeout_s` on every primary investigator/synthesizer
  model call (a hung turn concludes with the round-1 verdict from evidence already
  gathered).
- **Stronger hunts.** The hunt agent now plans inventory-first (uses only datasets
  that actually exist), reasons about correlation patterns (kill-chain sequencing,
  cross-host attacker-indicator fan-out, beacon/DNS-tunnel decisiveness), and ships
  prominent lateral-movement + behavioral OQL recipes (Kerberoasting, PsExec,
  completed-SSH, RITA beacon / DNS-tunnel summaries).
- **First-run "not connected" banner.** The Dashboard shows a clear banner when
  Security Onion / the model gateway is unreachable, instead of silently-empty lists.
- **Settled-verdict action bar.** A completed investigation always offers
  Acknowledge / Escalate even when the agent recommended no actions, backed by a
  new `POST /alerts/escalate-group` endpoint (same auth/CSRF as ack-group).
- **Reliability metrics.** `investigation_fallback_verdicts_total` and
  `investigation_zero_tool_verdicts_total` in `/metrics` — early warning for
  fallback-verdict rate and QVOD-style zero-tool escalations.

### Changed / Fixed

- **Malware-label payload gate.** A `true_positive` on a malware-signalling rule
  name is coerced to `needs_more_info` (→ investigated) unless corroborated by a
  concrete IOC hit or a cited decisive typed pivot value (JA3/hash/SPN/RPC) — the
  rule label alone is not corroboration (the BPFDoor false-escalation pattern). The
  solicited-ICMP defense and real tool-evidence still stand.
- **Fast-path reputation for domains.** The cheap fast-path now reputation-gates an
  external destination *domain* (SNI/Host/DNS, port-stripped), not just external
  IPs — an unknown or blocklisted domain forces the full investigation.
- **Sharper citations.** A citation resolves semantically only on a distinctive
  token (stop-word filtered, length/word-boundary checked), so a verdict can't
  "cite" the bundle by echoing a generic word — while short domains/IPs still
  resolve.

## [1.0.3] - 2026-07-03

Dogfood + detection + resilience release: 11 dogfood fixes from live use, a docs
site, operator runbooks, and one-click "request more info", plus dataset-agnostic
grid discovery, behavioral-summary detections (beaconing + DNS tunneling), and a
sweep of resilience / effectiveness / performance / flow hardening (from
autonomous sessions).

### Added

- **The agent discovers what's in your Elastic.** Dataset-agnostic grid
  inventory (ambient, TTL-cached) plus on-demand `describe_dataset` /
  `field_values` tools, so hunts and chat reason over whatever datasets a
  deployment actually ships — not a hardcoded Zeek list. Network-only today,
  host-log ready.
- **Behavioral-summary detections.** When the deployment surfaces a derived
  connection/DNS summary (e.g. RITA-style beacon scoring or a DNS-tunnel
  aggregate), the agent reads it as decisive evidence: a periodic beacon profile
  (regular timing + constant payloads) or a high-entropy, TXT/NULL-dominant DNS
  channel is now a `true_positive` on its own, even behind an ET HUNTING /
  Informational alert. These per-host rollups carry only `source.ip` (not a
  `community_id` or `host.name`), so a dedicated IP-keyed prefetch pivot fetches
  them alongside the five typed pivots — otherwise the decisive signal never
  reaches the agent. Verified on the synth eval: a Cobalt Strike beacon that read
  as a false positive on the alert alone now escalates once the beacon profile is
  in context.

- **Operator runbooks.** A local runbook store (Config → Runbooks) the triage
  agent can cite: the `lookup_runbook` tool searches your own guidance
  (rule-link > tag > keyword) and grounds verdicts in it. Purely local — never
  written to Security Onion.
- **One-click "request more info."** A `needs_more_info` investigation can be
  re-launched with its open questions threaded in as a focus hint, so the fresh
  run targets the gaps instead of re-deriving from scratch.
- **Chat about a hunt.** Hunts now have the same follow-up chat thread as
  investigations (read-only — a hunt chat never acks or escalates).
- **Canned hunts.** Six one-to-three-click preset hunts for routine, high-payoff
  sweeps (beaconing, new-external-service, rare-process, etc.).
- **Documentation site.** A Material for MkDocs site (quickstart, config, hunts,
  backtest, security posture) published via GitHub Pages.
- **Delete hunts** from the Hunt Console.

### Changed / Fixed

- **Internal-identifier discovery no longer over-claims.** A single-label suffix
  is treated as internal only if it is not a public TLD (fixes "the entire `.com`
  is internal"), and per-device Windows mDNS `<guid>.local` names are dropped
  instead of flooding the identifier list.
- **Auto-ack of false positives now leaves an audit trail** and its coupling to
  investigation completion is documented (a benign FP is acked when the
  investigation that judged it completes, not on a separate schedule).
- **Timezone-correct "when."** Investigation/hunt/runbook timestamps serialize
  with an explicit UTC offset, fixing the "a 1-hour-old run shows 8h ago" skew
  (the browser was parsing naive UTC as local time).
- **Inheritance is legible.** An inherited verdict shows which investigation it
  came from and when; re-running an investigation now correctly clears the
  "inherited" pill on that alert.
- **Alerts grid** uses the space between IPs and verdict for timestamps, a
  copyable short alert-id, and a "fired N×" count.
- **Config apply is explicit.** A sticky "Apply changes (N)" bar with dirty-state
  tracking replaces the ambiguous auto-apply.
- **Hunt UI** brought to parity with investigations (collapsible sections,
  confidence ring, consistent panels).
- **Hardening (self-review):** runbook content + list fields are size-bounded and
  the runbook search working-set is capped; a second hunt-chat turn is rejected
  while one is still pending (no orphaned pending rows).
- **Auto-triage can't be stalled by a hung run.** Each investigation in a sweep
  is bounded by a wall-clock backstop (`auto_triage_per_target_timeout_s`); a
  hung LLM stream is now counted as a failure and the sweep moves on instead of
  wedging behind it.
- **Oracle retries use full jitter.** The second-opinion path's backoff is now a
  randomized draw (matching the primary transport), so many concurrent
  investigations don't retry in lockstep and re-hammer the gateway as it recovers.
- **Confidence floor is stricter.** The "grounded catch" confidence floor now
  fires only on a cited decisive pivot *value* (a JA3/hash/SPN/…), not the mere
  presence of a correlated pivot id — a raise has to be earned by real signal.
- **Recall: decisive Zeek evidence surfaces.** SSH logins, low-and-slow exfil
  duration, Kerberos/SMB/DCE-RPC lateral chains, and the beacon/DNS aggregates
  above are extracted and cited rather than silently dropped before the agent
  sees them.
- **Follow-ups on any verdict.** Residual open questions (and the focused
  "request more info" action) now show on `true_positive` / `false_positive`
  investigations too, not only `needs_more_info`.
- **Faster bulk re-investigate.** The re-hunt endpoint fetches all target
  investigations in one query instead of one round-trip per id (was an N+1).
- **Quieter UI.** The Investigations re-investigate/delete status line
  auto-dismisses; idle screens stop polling at terminal state.

## [1.0.2] - 2026-07-02

Trust + reliability release: make the pipeline resilient and the trust story
provable (from an autonomous review + direction-brainstorm session).

### Added

- **Model reasoning visible on every investigation.** A collapsible "Model
  reasoning" panel surfaces the agent's per-turn `<think>` traces (previously
  captured but dropped by the timeline) — the "show your work" explainability an
  analyst needs to defend a verdict.
- **Signed decision-record exports.** The audit export now carries a real Ed25519
  detached signature + public key (verifiable by an external auditor with the
  public key alone), alongside the existing sha256 checksum. New
  `GET /decision-record/public-key`.
- **Benign synthetic eval scenarios + escalation precision.** The synth catalogue
  gained a benign (false-positive) class, so the eval now reports precision and a
  true-negative rate — answering the "does it call obvious FPs malicious?" test,
  not just recall.

### Changed / Fixed

- **Resilient LLM gateway transport.** The primary model path (investigator /
  synthesizer / hunt / chat) now retries transient gateway failures (429/502/503/
  504 + connection/read/timeout) with jittered exponential backoff, honoring
  Retry-After — parity with the Oracle path. Bursty gateway 502s previously
  errored investigations, hunts, and eval batches outright.

## [1.0.1] - 2026-07-01

Highlights: the **Hunt Console** and a **backtest harness** land, and a full
correctness / security / performance review hardened the engine.

### Security

- **`web_search` refuses all internal identifiers, not just RFC1918 IPv4.** A
  shared internal-identifier guard (also used by `crawl_page` and online
  enrichment) now blocks internal FQDNs, known internal hostnames, IPv6, and every
  non-globally-routable IP class (CGNAT, benchmark, loopback, link-local) from
  reaching public search engines.
- **API tokens are bound to their creator's account** — disabling the operator who
  minted a token now rejects that token, matching session auth.
- HSTS is emitted behind a TLS-terminating reverse proxy (honors
  `X-Forwarded-Proto`); the login throttle and rate limiter are proxy-aware via an
  opt-in `PROXY_TRUSTED_IPS`; chat input is length-capped; the Oracle
  redaction-preview endpoint is admin-gated; the decision-record export is
  described honestly as an integrity checksum (not a signature).

### Fixed

- **Hard evidence gate restored.** The zero-tool-verdict gate was silently
  defeated by a part-type miscount (the model's own text/reasoning counted as
  "tool evidence"); it now counts only real tool results, so an ungrounded
  true/false-positive correctly falls back to `needs_more_info`.
- **Investigations and hunts conclude gracefully at their budget** instead of
  erroring with no result — a hunt that reaches its exploration budget now
  synthesizes a grounded partial report.
- Background worker tasks are cancelled on shutdown (no use-after-close on the ES
  or DB clients); several unbounded per-rule queries are now bounded; MaxMind
  lookups no longer block the event loop; the web console stops polling once a
  hunt/backtest is idle and no longer races stale responses.

### Added

- **Hunt Console — network-wide, objective-driven hunting.** Give it a hunting
  objective in plain English and it turns the same read-only agent loose across
  many hosts and a time window, then reports **findings + a narrative** mapped to
  MITRE ATT&CK — rather than a single-alert verdict. Read-only (no acks, no case
  edits), runs on a bounded budget, and lands a grounded partial report if cut
  short.
- **Backtest harness — "prove it on my last N days."** Samples your already-
  dispositioned Security Onion alerts, replays soc-ai's triage against them, and
  scores agreement, false-positive-toil cleared, and a prominent **missed true
  positives** count — so you can measure the assistant before you trust it.
- **In-UI admin config console** — Oracle toggle, data sources, agent tools, API
  tokens, detection tuning, and the Oracle **redaction preview**, applied without
  a restart where possible.
- **Internal-identifier discovery + management.** soc-ai now learns a
  deployment's internal identifiers from its own Security Onion data instead of
  assuming them. A new admin **Internal identifiers** config section manages
  internal domain **suffixes**, bare internal **hostnames**, and internal
  **subnets (CIDRs)** as a single list of detected / manual / muted / always-on
  entries with provenance (host + event counts, last-seen). A background
  discovery job (a config-console **schedule toggle** (in-process scheduler)
  plus the `discover-internal-identifiers` CLI and a **"Scan now"** button)
  infers candidates from
  Elasticsearch: domain suffixes and hostnames tied to internal hosts, and
  RFC1918 subnets seen in traffic but not yet in `internal_cidrs`.
  - High-confidence internal domain/host identifiers are activated automatically
    (the fail-safe direction for egress redaction is to over-redact); a **public
    registrable domain is never auto-activated** (suggestion only). **CIDRs are
    suggest-first** — discovered subnets are always muted suggestions, because a
    CIDR is two-directional and changes triage classification; the operator
    un-mutes to activate.
  - The merged effective set (env/reserved config ∪ active − muted) feeds the
    Oracle egress sanitizer (suffixes/hosts) and the internal-vs-external IP
    classification (CIDRs, applied consistently across triage downgrades and
    Phase-A enrichment). Reserved special-use suffixes (`.lan/.local/.internal/
    .corp`) are always redacted and cannot be muted away (defense-in-depth);
    behavior is unchanged for deployments with no managed entries.
- **Config console surfacing.** Non-secret operational settings that were
  previously env-only (model/index/alerts-query patterns, agent tuning, the new
  discovery knobs) are now visible and editable in the admin config console with
  a source badge and hot-apply/restart indicator. Secrets remain set/unset-only.

### Fixed

- Removed a hardcoded lab-specific internal domain from the eval sanitizer's
  default suffix list — it was redundant (`.lan` already covers it) and a
  developer-environment leak. Internal domains are now discovered/configured per
  deployment rather than assumed.

## [1.0.0] - 2026-06-23

The first public release. Highlights:

### Added

- **React web UI (`/app`)** — a single-page console for the full triage loop:
  alerts grouped by detection, an investigation drawer + permalink with a live
  timeline, entity graph, host context, recommended actions, and a scoped chat.
  Served directly by the backend.
- **Agentic investigation loop** — the agent investigates with read tools
  (event/Zeek search, IP/domain/hash enrichment, PCAP fetch + decode, playbooks,
  cases, web search) and synthesizes an evidence-cited verdict; a human approval
  gate guards every write action.
- **Oracle second opinion** — optional escalation to a stronger cloud model with
  field-aware egress sanitization.
- **Config console** — admin settings (hot-applied), user + API-token
  management, and a Fernet-encrypted secrets Danger Zone.
- **Upstream health indicator** — live ES / LLM / PCAP status, including a
  detector that flags a broken sensor-PCAP user and points to the fix.
- **Tampermonkey userscript** — "Hunt with AI" from inside the SO web UI.
- **Docker** — multi-stage image (builds the SPA) + compose for `docker compose up`.

### Security

- API auth (session cookie or bearer token), CORS scoped to the SO host, OQL
  field-whitelist validation, and secret-safe logging/rendering throughout.
- **Oracle egress redaction — free-text credential usernames.** Usernames that
  appear only in a free-text field in an explicit credential context
  (`user=jdoe`, `username: svc-bak`, `DOMAIN\jdoe`) are now tokenised before the
  payload is sent to the cloud second-opinion model; previously such a name
  could egress verbatim. Universal built-in accounts and public emails are left
  intact. The independent residue gate gained a matching check and fails closed
  on any miss. The client now warns once when the Oracle is enabled but no
  organization-specific internal names are configured, and
  `oracle_internal_suffixes` is threaded from the active settings so a runtime
  override is honored. Credential usernames are redacted in place only (not
  globally propagated) so a free-text match cannot corrupt a public IOC.
- **Oracle redaction — ReDoS hardening.** The suffix-FQDN and email redaction
  patterns had unbounded quantifiers that could backtrack catastrophically on a
  long hyphenated run in attacker-controlled free text (e.g. `payload_printable`).
  Quantifiers are now bounded to DNS/RFC length limits — multi-second worst case
  reduced to milliseconds, with no change to matching for valid hostnames/emails.
- **Security-audit hardening pass.** A full audit (no critical findings — the
  human-approval gate is unbypassable by the agent, OQL→Elasticsearch is
  injection-proof, and the SSH/PCAP path is argument-injection-safe) drove a
  round of edge hardening:
  - **SSRF**: the `crawl_page` host guard now resolves DNS and checks every
    resolved address against private/loopback/link-local/reserved ranges, not
    just the hostname string (closing the resolve-to-internal and octal/hex-IP
    bypasses).
  - **ReDoS**: bounded the quantifiers in the eval-path sanitizer (the prod
    Oracle path was already bounded).
  - **MISP over TLS** is now verified by default (`MISP_VERIFY_SSL`, optional CA
    bundle) instead of hardcoded-insecure.
  - **Tamper-evident audit log**: records are hash-chained (`seq`/`prev_hash`/
    `hash`) with a verify path; SO-mutating writes fail **closed** when the audit
    write fails (`AUDIT_FAIL_CLOSED`, default on); the approver identity is
    resolved and recorded; redaction defaults on and covers soc-ai's own secret
    shapes (`scai_`, bearer, session token, `password=`).
  - **CSRF**: cookie-authenticated state-changing requests now require a
    same-origin (or allowlisted) `Origin`/`Referer`; bearer-token (userscript)
    requests are exempt.
  - **Login throttle** (per-IP/username lockout), **security response headers**
    (nosniff / DENY / no-referrer / HSTS), **CORS fails closed** when
    unconfigured, **leading-wildcard OQL** is rejected (grid-DoS guard),
    **SSH known-hosts** persist (key-swap detection), and auto-ack of false
    positives is **capped** to low-stakes alerts (a prompt-injected verdict can
    no longer auto-acknowledge a malware/exploit/high-severity alert).

[Unreleased]: https://github.com/nuk3s/soc-ai/compare/v1.4.0...HEAD
[1.0.0]: https://github.com/nuk3s/soc-ai/releases/tag/v1.0.0
