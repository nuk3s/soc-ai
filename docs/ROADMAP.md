# Roadmap

soc-ai moves fast, and it moves in public. This page gives the honest picture. It
says what shipped, what you can turn on today, and what comes next.

![soc-ai roadmap: 1.0 through 1.5 shipped, 1.5 current, 1.6 joins leads into campaigns and validates the lead thresholds](img/roadmap.svg)

## The story so far

**Release 1.0 arrived in June 2026 with the core promise.** An agent reads an
alert on your Security Onion grid. It investigates the alert with real tool
calls. It lands a verdict with the evidence attached.

No verdict stands without evidence. No write runs without your click. No data
leaves your network. The always-on web console shipped on day one.

**The 1.0.x line made soc-ai a place to work all day.** The Hunt Console took a
plain-English objective across the whole network. Backtests replayed the agent
against alerts that you had already dispositioned, so you could measure trust
instead of assuming it. Runbooks gave the agent your team's own procedures to
cite. Grid discovery taught the agent to learn what data your deployment holds.

**Release 1.1 was the measurement release.** It added a nightly quality eval with
a trend line and a regression alarm. It added redaction previews that you can
inspect span by span. It added a real runbooks workspace. If the agent gets
worse, a chart tells you, and not a bad morning.

**Release 1.2 came from a full analyst shift on a live deployment.** 14 findings
went in. 14 fixes came out. The release added notifications, entity search, a
maintenance panel, pipeline-error visibility with a one-click dismiss, group
acknowledge, and a deep re-run. The dashboard can also schedule the quality eval.

**Release 1.2.6 rebuilt the Config page as a master-detail screen.** A section
nav now drives a single-section pane, in place of a scroll about 36 screens long.
Settings search works on the page and in the command palette. An Apply bar names
each staged change. The identifier lists page, filter and bulk-edit. An About
page shows the running version, with an opt-in GitHub update check that sends
nothing by default.

**Release 1.2.7 adapted the pipeline to whatever analyst model sits behind the
gateway.** It added a fitness battery and a standalone probe, so you can judge a
candidate backend before production depends on it. The pipeline also records
exactly why a model stumbled, and it recovers from the most common failure on its
own. Hunts got their latitude back. A generic sweep now hunts the telemetry for
beacons, first-seen destinations and odd cadences, because triage already owns
the alert queue.

The next patch tightened the edges that an operator meets. A scheduled hunt now
says plainly that it is paused, in place of a switched-on pill that never fires.
Triage retries a transient grid error in place of dropping it. The nightly
regression alarm no longer pages on one flipped verdict at a small sample size.
The config console groups the switch for each integration with the key that it
needs.

A later patch refreshed the alert workspace. It added design-token theming, a
filter bar that becomes bulk actions without shifting the table below it, toast
notifications with a one-click clear, and freshness markers for a stalled poll.
It shipped with a code-review remediation and a run of dogfood fixes.

**Release 1.2.8 was the degraded-grid release.** It gives the same care to what
soc-ai says if Security Onion is down, saturated, stalled, or reading only some
of its shards. A partial read now raises an error in place of passing for a whole
read. A sweep that could not read the backlog is marked degraded in place of
empty. Every screen an analyst depends on answers honestly, from the health pill
in the topbar to the audit chain, and it asserts no number that it never
obtained. One rule holds end to end: a false all-clear is worse than any loud
error.

**Release 1.2.9 was the front-door release.** It gave the same care to the first
30 minutes. The installer asks how you reach a model. A local endpoint stays the
primary route. A cloud key gets redacted egress by default and a printed
disclosure.

The doctor preflights the traps that used to cost an afternoon: the audit write
grant, a narrowed index pattern, and DNS and TLS inside the container. It names
the fix on every failing line. The console opens as an analyst tool, with 8 day-1
config decisions and the rest behind a per-section reveal. An Operate hub holds
the trust instruments. A setup-health card says what is broken.

**Release 1.3 made soc-ai a hunting tool.** A finding from a hunt can become a
full investigation on its own anchor evidence, so "this looks odd" reaches a
verdict with no retyping. Four behavioral analytics sweep the network instead of
the alert queue: beaconing cadence, DNS entropy, DCE-RPC operation histograms,
and first-seen external destinations. soc-ai can also draft a confirmed true
positive into a Sigma rule and export it for you to review and deploy yourself.
soc-ai writes nothing to your detection store.

**Release 1.3.2 was an adversarial security audit of our own work.** It planted
18 attacks against the redaction boundary, the citation grounding and the route
guards. Every finding is fixed or refuted on the record. 2 of the defects it
found were in earlier fixes.

**Release 1.4 was the trust release.** Its subject is whether you can check the
judgement of soc-ai for yourself.

The evaluation could always plant an attack and score the verdict on one alert.
It could never score the work the product exists for: a plain-English hunt across
your network that produces a finding, promotes it, and reaches a verdict. The
evaluation now scores that journey end to end. If the journey falls short, the
evaluation names the step that broke. The hunt found nothing, or the finding
cited no usable evidence, or the investigation reached the wrong verdict.

A verdict must now rest on evidence that soc-ai retrieved. The old checks
confirmed that the run had gathered evidence. They never confirmed that the
evidence supported the conclusion. One successful lookup was therefore enough to
let a confidently wrong true positive stand. One such verdict came from text
planted in the network traffic under analysis.

The cloud second opinion can now check its own claims with read-only tools. It
used to reason from whatever the local run wrote down. Building that proved the
outbound privacy gate was a blocklist. The gate blocked the field names we had
thought of, and a bare internal hostname has no shape that a filter can catch.
The gate now works the other way round. soc-ai masks any value from a field that
the sanitizer does not recognise before the model can see it, so the boundary is
complete by construction.

Release 1.4 holds one more change, less visible and more important than it
sounds. The evaluation can run each scenario several times and report a
confidence interval. A test-retest on code that provably could not affect the
outcome moved a headline recall number by 0.235. It also flipped 6 of 25
scenarios between pass and fail. A single batch cannot tell a real improvement
from chance, and it no longer pretends to.

**Release 1.5 is the current release. It is hunting that starts without you.**

Every earlier release waited for a person. One number makes the case for the
change. A measurement on 2026-09-04, on the grid that soc-ai is developed
against, found about 3.4 million documents from the sensors. Of those, 3,940
carried an alert tag. That is about a tenth of one percent, from 2 datasets out
of about 70.

The grid holds about 19 million more documents that arrived as imports. Most of
them came from one Windows event-log import. That count leaves the imports out,
because no sensor saw them.

An analyst who works the alert queue works the visible part. A hunt that begins
there inherits the same loss. A full credential-abuse chain against a real domain
controller produced nothing that anyone could have seen at the time. The rule for
it had been enabled for months. A rule engine reads the stream as it arrives, and
its cursor had already passed those events. A query has no cursor.

A hunt can now be a document instead of a conversation. The document is YAML that
compiles to a single query and runs with no model call. That is what makes a hunt
cheap enough to leave running. soc-ai ships 4 hunt documents. They cover the
credential-abuse techniques that generate real evidence and no alert.

Three properties matter more than the feature itself. A finding from that path
cannot be invented, because nothing generative is involved. The words come from
the spec, and a person writes the spec and reviews it. A condition that soc-ai
has already shown you does not come back, so the tenth sweep is as quiet as the
first. soc-ai can also tell "nothing happened" from "I could not see". Every spec
declares the telemetry that it depends on, so an absent data source becomes a
coverage gap in your findings instead of a quiet all-clear.

You can watch a spec before you trust it. A shadow mode reports what every spec
would have reported, and it records nothing. It also spends none of the
once-only budget. A week of observation therefore leaves no detection silent on
the day that you switch it on.

soc-ai also reports on itself. Every sweep leaves a record, and a clean sweep
leaves one too. The Operate hub shows the last sweep and the last firing of each
spec. It also shows whether the spec is blind, errored or overdue. "Switched on"
and "running" are different facts, and the panel keeps them apart.

A fortnight of use followed. One deployment ran against its own grid, and the
attack range ran against its exploit chain. Both exercised every read and
write the way an analyst does. Two of the findings changed the numbers that you
see.

Every prevalence, novelty and baseline figure used to count everything on disk.
On the development grid most of that was imported packet captures. Those figures
now count your own sensors only, and they say so. The catalog doctrine also
reaches triage now. A detection that the catalog says has no benign population
cannot be closed benign on how often it fires. Two such detections are directory
replication by a non-machine account, and an account without Kerberos
pre-authentication.

A hunt template can also name alternative telemetry that satisfies one
requirement. It can report that a data source is present only as imported
history.

**Release 1.5 then grew a spine.** The word hunt had done three jobs. It now
names one thing, and four other nouns name the rest. An analytic is one
detection logic. A hit is one thing one analytic found about one entity. A lead
is the observations on one entity that are worth one decision. A hunt is one
agent run with an objective. An investigation is one agent run that ends in a
verdict.

Every source writes into one observations table: a profile departure, a catalog
hit, a triaged alert and a promoted hunt finding. Each observation carries a
weight, and the weight decays with a 48 h half-life. A lead forms at a live
weight of 0.85 across two or more types, on a finding with no benign baseline,
or on one type that repeats. The lead is the one join in the system.

A new analytic runs in shadow before it counts. Its hits are visible with their
receipts: the matched documents, the baseline, a 30-day dry run and the overlap
with a live analytic. You approve the analytic from its own hit card. Nothing in
shadow starts a hunt.

A lead starts its own hunt. A loop picks up each open lead within 60 s and runs
the hunt that the Hunt button runs. The hunt reads the lead's own documents
before it queries the grid. You decide after the hunt lands, and Promote then
runs an investigation whose subject is the hunt: the objective, every finding,
and every document those findings cite, up to 40.

A lead also names the open leads that relate to it, by analytic, by alert rule,
by external network or by ATT&CK technique, over the last 7 days. A coordinated
attack across several machines is then visible from any one of them.

The Hunts page holds that pipeline in order. One strip at the top, Needs you,
counts the two things that wait on an analyst: the unread shadow hits, and the
leads that need a decision. Everything else runs without you.

**Release 1.5 also measured its own verdicts.** A turn audit read 41 stored
investigations. The correct verdict was reachable at 2 s and stated at 17 s. The
58 s after that first statement were 79% of the wall time, and no turn in them
changed a verdict. An accuracy mission then ran eleven attack-range alerts with
known truth, three times each. The investigation loop now writes the verdict
report itself, and that path went from 29 of 31 correct to 31 of 31. The
first-pass synthesis call runs only when it can close the alert. That removes
about 18 s and 8,000 tokens from each affected run.

**Security Onion 3.3 needed a new login.** Security Onion 3.3 stopped accepting
a Kratos API-flow session token, so every write failed with HTTP 401 while reads
kept working. soc-ai now logs in the way the Security Onion web interface does,
with the browser flow and a session cookie. The `so_login_flow` setting takes
`auto`, `browser` or `api`, and `auto` picks the flow that the grid accepts.

## Already in the box, waiting on a switch

A lot of soc-ai ships dark. Each feature is built and tested, and it is off by
default, because you decide what runs on your network. The list today holds
semantic runbook search and reranking, chat memory, the cloud Oracle second
opinion and its tool loop, scheduled auto-triage, recurring hunts, catalog
sweeps, scheduled identifier discovery, outbound notifications, PCAP fetch and
decode, Sigma rule drafting, web search, and online enrichment. Semantic runbook
search and reranking need an embeddings model on your gateway. Each feature is a
config toggle, and the admin page hot-applies most of them.

## What's next: release 1.6

1.6 closes what 1.5 left open. Five items, each one named by a limit that the
1.5 work recorded.

- **A campaign object over related leads:** today a lead names the open leads
  that may share a story, and the hunt is asked whether they are one campaign.
  Nothing joins them into one record with one owner and one verdict. The dogfood
  week showed related leads that read as one attack, so the join is the next
  step.
- **An API key login for Security Onion:** Security Onion 3.3 takes a browser
  session cookie or an API key. soc-ai uses the cookie. An API key needs no
  password on disk and survives a login throttle, so it is the better credential
  for an unattended service.
- **A group key of its own for a hunt-subject investigation:** the record still
  stores the first cited document as `alert_es_id`, and soc-ai keeps the run out
  of that alert's group on every surface. A key of its own removes that special
  case.
- **Threshold validation from the quality report:** the lead threshold (0.85),
  the single-type threshold (1.5) and the hub limit (8) are not yet validated
  against a miss. The lead quality report exists to measure them. A threshold
  moves on a week of data, never on a day.
- **A production dogfood of the hunting layer:** the layer was built and read
  against an attack range over six rounds. It has not run on a production
  deployment for a week.

**After that: a measure of normal.** The analytics soc-ai has today measure
cadence, entropy and rarity. None of them knows what is ordinary for one machine,
next to machines that do the same job, at a given hour of the week. "Unusual for
this host, for its peers, at this time" is the question we want to ask. A
signature cannot express that question. Then come hunts that trigger themselves.
A cluster of activity that moves from reconnaissance towards command-and-control
is the moment to start looking. The next visit to the console is too late.

**Further out:** multi-tenant deployments with role-based access for MSSPs and
multi-team SOCs. Deployment of a drafted detection into Security Onion, if a
supported path arrives. Specialty copilots on the same audited core, for
detection engineering and for incident-response playbooks.

Plans change if evidence says they should. This page tracks what is real. The
[1.5.0 release notes](releases/1.5.0.md) hold the measured numbers and the
upgrade steps. The [hunting guide](HUNTING.md) covers the pipeline. The
[changelog](project/changelog.md) holds the full version-by-version record.
