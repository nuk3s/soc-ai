// ---------------------------------------------------------------------------
// The sentence each chip, pill, badge, count and status carries.
//
// The navigation rule of the Hunts spine says every one of them states what it
// means in one sentence, in the analyst's words. Three merges put those
// sentences on screen: the Hunts tab, the lead page and the other surfaces.
// Three copies of a sentence drift, and a chip that means one thing here and
// another thing there is worse than a chip with no tooltip at all.
//
// The copy is Frame 7 of the approved mockup, `public/guide/mockup-hunts/`.
// A new chip ships with its sentence, and the sentence lands here first.
// ---------------------------------------------------------------------------

// ── What each thing is ──────────────────────────────────────────────────────
//
// One sentence per noun, in plain words. The owner read the rebuilt page and
// could not tell a lead from a hit from a hunt, because every section named its
// thing and none of them said what the thing was.
//
// Each sentence is a line under its section header on the Hunts page, and the
// same line under the title of the page or the drawer that holds one of them.
// The sentences match the chart the "How this flows" link opens, so the words
// on the page and the words on the chart are the same words.

import { CLOSE_RULE_CLAUSE } from './leadDecisions';

export const DEFINE_HIT =
  'A hit is one match of one analytic on one entity: an observation with the records behind ' +
  'it. A live hit adds weight to a lead. A shadow hit adds no weight, and you review it to ' +
  'approve or reject the analytic that wrote it.';

export const DEFINE_LEAD =
  'A lead is a set of observations on one entity that are worth one look. soc-ai hunts each ' +
  'new lead that is not a shadow lead. A clean hunt or a verdict on each threat it found ' +
  'closes the lead. A lead of a campaign holds only alerts of the investigations of one ' +
  'campaign. It waits on that campaign, and a close or an authorization of the campaign ' +
  'dismisses it. Any other lead waits on you.';

export const DEFINE_HUNT =
  'A hunt is one search of the grid for one objective, and a lead, a campaign, a schedule or ' +
  'you start it. It reads the open campaigns and reports only new activity on their machines. ' +
  'It returns findings and takes no action. When the hunt ends, soc-ai investigates each ' +
  'threat finding that names an entity, up to 20 for each hunt, unless a campaign holds the ' +
  'finding.';

export const DEFINE_SCHEDULE =
  'A schedule starts a hunt on an interval and writes a hunt row on every run.';

export const DEFINE_ANALYTIC =
  'An analytic is one written detection. The sweep reads the grid with each live and shadow ' +
  'analytic every hour, when the operator turns it on. A live analytic records hits that can ' +
  'form a lead, and a shadow analytic records hits for you to review.';

// The rest of the flow: the alert path, the investigation and the campaign.
// The "How this flows" drawer prints these lines under the chart, in the order
// the chart reads. The chart of 2026-10-07 left out the campaign, and a review
// of 2026-11-14 found nine places where it differed from the code.

export const DEFINE_ALERT =
  'An alert is a detection that the grid raised. One investigation serves the alerts of one ' +
  'rule between two addresses, and the other alerts take its verdict for 7 days.';

export const DEFINE_INVESTIGATION =
  'An investigation is the work of soc-ai on one alert or one hunt finding, dated by the time ' +
  'of its event. It cites its evidence, ends in a verdict and writes an audit record.';

export const DEFINE_VERDICT =
  'A verdict is true positive, false positive or needs more info, and you can override it. ' +
  'When the operator turns on auto-acknowledge, soc-ai acknowledges a confident false ' +
  'positive, except on a critical, high, exploit or malware alert.';

export const DEFINE_CAMPAIGN =
  'A campaign is one activity: a confirmed attack from one machine on another, and the ' +
  'investigations that proven links join to it. soc-ai builds the campaigns again after each ' +
  'verdict. soc-ai starts at most one hunt for a campaign in 24 hours. A higher stage, a new ' +
  'machine, new activity after a close or activity beyond an authorization starts one.';

export const DEFINE_CAMPAIGN_DECISION =
  'You open one Security Onion case for the whole campaign, close the campaign with a reason, ' +
  'or record its activity as authorized until an expiry. An administrator records the ' +
  'authorization. New activity opens a closed campaign again, and activity outside the ' +
  'authorization gets normal handling.';

export const DEFINE_NEEDS_YOU =
  'Needs you lists the work that waits on you, the oldest first. The work is the campaigns ' +
  'with no decision, the investigations that wait, the leads that need a decision and the ' +
  'alert groups with no verdict. The top bar, the Dashboard and the Needs you page state the ' +
  'same number.';

export const DEFINE_TWO_VERBS =
  '"Hunt this lead" starts the hunt of a lead now. "Open an investigation" is the control on ' +
  'a finding with no investigation, and the press also writes an observation.';

// ── The fold of a section ───────────────────────────────────────────────────
//
// A fold is kept on the browser that made it, not on the account, so the
// sentence says where it lives. An analyst who folds the hits on one machine
// and opens the page on another must not read the fold as lost work.

export const COLLAPSE_SECTION = 'Collapse this section. It stays collapsed on this browser.';

export const EXPAND_SECTION = 'Expand this section.';

// ── The lead state pills ────────────────────────────────────────────────────

/** The pill named an act the analyst cannot take before a hunt has finished,
 *  so the sentence names the acts a new lead offers. */
export const PILL_NEW =
  'New: nobody has acted on this lead. Its hunt starts on its own, or hunt it by hand. ' +
  'Dismiss it if it is noise.';

export const PILL_IN_PROGRESS =
  'In progress: a hunt is running on this lead. View the hunt to follow it.';

export const PILL_HUNTED =
  'Hunted: the hunt on this lead finished. Read the verdicts it brought back, or dismiss the lead.';

export const PILL_DISMISSED =
  'Dismissed: an analyst closed this lead with a reason. Reopen puts it back in the queue.';
/** The rule soc-ai closes a lead by when its hunt investigated its findings,
 *  as a sentence. The clause lives in lib/leadDecisions.ts. */
export const CLOSE_RULE = `${CLOSE_RULE_CLAUSE.charAt(0).toUpperCase()}${CLOSE_RULE_CLAUSE.slice(1)}.`;

export const PILL_CLOSED_BY_HUNT =
  'Closed: soc-ai closed this lead. Its hunt found no threat. Reopen puts it back in the queue.';

/** The pill of a lead soc-ai closed because every finding of its hunt has a
 *  verdict. The pill read "Promoted", the word of an analyst's act. */
export const PILL_CLOSED_ON_VERDICTS = `Closed: soc-ai closed this lead. ${CLOSE_RULE} Open the hunt to read each verdict.`;

export const PILL_PROMOTED =
  'Promoted: an analyst opened an investigation from this lead. The lead is closed.';

/** The line of a closed lead that observations joined after the close. The
 *  horizon is the decay horizon of soc_ai.hunting.leads. */
export const REPEATS_AFTER_CLOSE =
  'A true positive alert of a rule this lead held joins the closed lead for 207 hours. ' +
  'It starts no hunt.';

/** What a fleet condition is, in one line. The Fleet condition tab prints it,
 *  and the pill and the legend read the same words. The span cap is
 *  DEFAULT_SPAN_CAP in soc_ai/hunting/leads.py. Only a profile departure
 *  counts toward it. */
export const FLEET_CONDITION_LINE =
  'A fleet condition is one departure that more than 8 hosts hold at one time. A change to ' +
  'the network causes it more often than an attack does. A fleet condition lead waits on no ' +
  'decision, and soc-ai starts no hunt on it.';

/** The pill of a lead in the stored status `fleet_condition`. The pill read
 *  "New", and 47 of 70 leads on production then read as work nobody had
 *  started (review 2026-11-12, F1). */
export const PILL_FLEET_CONDITION =
  'Fleet condition: more than 8 hosts hold one departure of this lead at one time. A change ' +
  'to the network causes that more often than an attack does. The lead waits on no decision, ' +
  'and soc-ai starts no hunt on it. You can hunt it or dismiss it.';

/** The one sentence on the Reopen button. The strip said "back in the queue"
 *  and the lead page said "back in the new list", which is two names for one
 *  place. The pill sentence above names the queue, so the queue it is. */
export const ACTION_REOPEN =
  'Put this lead back in the queue. The dismissal stays on the timeline.';

/** The sentence beside the words a promoted lead shows in place of the link
 *  when the investigation it names has gone. The label itself lives beside the
 *  other lead action words, in `components/LeadsStrip.tsx`. */
export const INVESTIGATION_GONE =
  'The lead names an investigation this deployment no longer holds. Reopen the lead to work it again.';

// ── The lead tabs ───────────────────────────────────────────────────────────
//
// The tab is a filter and the pill is the state. Each tab says which leads it
// keeps, in the words of the design: what waits on a decision, what is being
// worked, what is finished, everything.

export const TAB_NEEDS_DECISION =
  'Leads with no hunt yet, and leads whose hunt has finished. These wait on you.';

export const TAB_IN_PROGRESS = 'Leads with a hunt running. Nothing waits on you here.';

export const TAB_CLOSED =
  'Leads an analyst dismissed or opened an investigation on, and leads a hunt closed when it found no threat. ' +
  `soc-ai also closes a lead when ${CLOSE_RULE_CLAUSE}. Reopen puts one back.`;

export const TAB_FLEET_CONDITION =
  'Leads that are a fleet condition. Nothing waits on you here. ' + FLEET_CONDITION_LINE;

export const TAB_ALL = 'Every lead, in every state.';

/** The line beside the tab counts while auto-hunt holds new leads. Such a
 *  lead is in no tab but All, so the four tab counts and this count sum to
 *  the All count. */
export function leadsQueuedNote(n: number): string {
  return n === 1
    ? '1 new lead waits on auto-hunt. The All tab lists it.'
    : `${n.toLocaleString()} new leads wait on auto-hunt. The All tab lists them.`;
}

/** The leads that an active campaign holds. They wait on no hunt and on no
 *  decision of their own: the analyst decides on the campaign. */
export function leadsOfCampaignNote(n: number): string {
  return n === 1
    ? '1 lead waits on its campaign. The All tab lists it.'
    : `${n.toLocaleString()} leads wait on their campaign. The All tab lists them.`;
}

// ── The analytic chips ──────────────────────────────────────────────────────

// ── Authorized activity ─────────────────────────────────────────────────────

export const DEFINE_AUTHORIZED_ACTIVITY =
  'Authorized activity is activity that an analyst recorded as authorized: a label, a scope ' +
  'and an expiry. An investigation inside the scope keeps its true positive verdict. It requests ' +
  'no case and raises no notification of its own. An investigation outside the scope gets normal handling.';

export const CHIP_AUTHORIZED_ACTIVITY =
  'Authorized activity: this investigation is inside a scope that an analyst recorded as authorized. ' +
  'It keeps its verdict and requests no case.';

export const CHIP_LIVE = 'Live: the analytic runs on every sweep. Its hits count and can form leads.';

/** The chip on a hit whose analytic the catalog no longer lists. */
export const CHIP_ANALYTIC_REMOVED =
  'The catalog no longer lists this analytic. The hit stays on record. ' +
  'No drawer can open the analytic, and no decision can change it.';

export const CHIP_SHADOW =
  'Shadow: the analytic runs on every sweep, and its hits are recorded and shown. ' +
  'It raises nothing. Approve it to make it live.';

/** The dim chip on a hit the sweep recorded while its analytic was in shadow,
 *  and whose analytic is live now. The flag on the row holds the status of the
 *  last sighting, so such a hit lists under Shadow with a live chip above it.
 *  The sentence states that, so the two words do not read as a contradiction. */
export const CHIP_RECORDED_IN_SHADOW =
  'This hit was recorded while the analytic was in shadow. The analytic is live now.';

export const CHIP_RECORDED_LIVE =
  'This hit was recorded while the analytic was live. It counts toward a lead. The analytic ' +
  'is in shadow now.';

export const CHIP_LOCAL = 'Local: a row in this deployment, written or drafted here.';

export const CHIP_SHIPPED = 'Shipped: a file in the soc-ai release.';

// ── The lead and hit chips ──────────────────────────────────────────────────

export const CHIP_ANALYTIC_MATCH = 'An analytic matched documents on this entity.';

export const CHIP_ONE_SIGNAL_REPEATED =
  'One type of observation repeated until its weight reached the single-signal threshold.';

export const CHIP_NO_BENIGN_BASELINE =
  'No benign population produces this. One observation is a finding on its own.';

export const CHIP_NO_LEAD = 'This hit formed no lead and joined none.';

export const CHIP_CATALOG_RUN = 'A row the analytic sweep wrote for an analytic hit. No agent ran.';

export const CHIP_DISMISS_REASON = 'The dismissal reason the analyst chose.';
export const CHIP_CLOSED_BY_HUNT = 'soc-ai closed this lead after its hunt. No analyst chose a reason.';

export const CHIP_CLOSED_ON_VERDICTS = `soc-ai closed this lead after its hunt. ${CLOSE_RULE}`;

export const CHIP_WINDOW = 'The window the hunt searched.';

/** The read chip of a shadow hit. The time is the API's, so a payload without
 *  one states the read alone rather than a made-up hour. */
export function chipRead(when?: string | null): string {
  const tail = when ? ` ${when}` : '';
  return `An analyst opened this hit's evidence or acted on it${tail}.`;
}

/** The not-applicable cluster in the New hunt drawer. */
export function chipNotApplicable(n: number): string {
  const noun = n === 1 ? '1 starter does' : `${n} starters do`;
  return `${noun} not match the telemetry this grid sees.`;
}

// ── The hit filters ─────────────────────────────────────────────────────────

export const HIT_FILTER_ALL =
  'Every hit from the last 7 days, and every unread shadow hit of any age.';

export const HIT_FILTER_UNREAD =
  'Every shadow hit that nobody has opened or acted on, at any age.';

export const HIT_FILTER_LIVE = 'Hits from live analytics. They count and can form leads.';

export const HIT_FILTER_SHADOW =
  'Hits from analytics in shadow. Recorded and shown. They raise nothing.';

/** The three filters in one sentence, for a surface that names the row rather
 *  than each chip. */
export const HIT_FILTERS =
  'Hit filters. Unread: shadow hits nobody has opened or acted on. ' +
  'Live: hits from live analytics. Shadow: hits from analytics in shadow.';

// ── The header of one analytic in the hits block ────────────────────────────
//
// 233 unread hits came from 3 analytics, and each card repeated the two
// decisions on its analytic (review 2026-11-12, F2). The decisions sit once on
// the header of the analytic, and each button states its effect: one line in
// plain view, and the same sentence on the hover. Each line starts with the
// name of its button, as the lines on the lead page do.

export const HIT_GROUP_APPROVE =
  'Approve analytic. The analytic goes live, and its hits then count toward a lead.';

export const HIT_GROUP_REJECT =
  'Reject analytic. The analytic is retired and stops. Its hits leave this list.';

/** The effect of "Mark N read". `n` is the number on the button. */
export function hitGroupMarkRead(n: number): string {
  const hits = n === 1 ? 'The 1 unread hit of this analytic is' : `The ${n.toLocaleString()} unread hits of this analytic are`;
  return `Mark ${n.toLocaleString()} read. ${hits} marked read. The analytic keeps its status.`;
}

export const HIT_GROUP_FOLD =
  'The header counts every hit of the analytic. The rows under it are the hits the list has read.';

// ── The hunt type chips ─────────────────────────────────────────────────────

export const TYPE_ALL = 'Every hunt in the window. The catalog runs are included.';

export const TYPE_MANUAL = 'Hunts an analyst started from an objective.';

export const TYPE_SCHEDULE = 'Hunts a schedule started.';

export const TYPE_LEAD = 'Hunts started from a lead.';
export const TYPE_CAMPAIGN = 'Hunts that soc-ai started on a change of a campaign.';

export const TYPE_CATALOG =
  'Runs the analytic sweep recorded. The sweep records a run when an analytic cannot read its data.';

// ── The hunt statuses and the unread dot ────────────────────────────────────

export const STATUS_RUNNING = 'The hunt is running now.';

export const STATUS_INVESTIGATING =
  'The hunt wrote its report. The investigations of its findings run now.';

export const STATUS_COMPLETE = 'The hunt finished. The findings column counts its threat findings.';

/** The same status on a surface with no findings column. The lead page listed a
 *  hunt as Complete under a sentence naming a column that is not on the page. */
export const STATUS_COMPLETE_ROW =
  'The hunt finished. The count beside it is its threat findings.';

export const STATUS_COULD_NOT_RUN = 'The hunt could not run. The row names the reason.';

export const UNREAD_DOT = 'Unread. Open the evidence or act on the hit to mark it read.';

// ---------------------------------------------------------------------------
// Sentences for the other surfaces: the lead page, the host page, the
// Dashboard, Notifications, the hunt page, the drawers and Operate.
// ---------------------------------------------------------------------------

/** The line under the lead tabs and the lead actions. The tab is a filter and
 *  the pill is the state, so the four words are said once, in one place. */
export const LEAD_LEGEND =
  'Needs decision: the lead is New or Hunted, and it waits on you. ' +
  'In progress: a hunt is running. ' +
  'Closed: an analyst dismissed the lead or opened an investigation on it. soc-ai also closes ' +
  `a lead when its hunt finds no threat, or when ${CLOSE_RULE_CLAUSE}. ` +
  'Fleet condition: one departure is on more than 8 hosts at one time. It waits on no decision.';

/** The chip on an analytic in the stored status `candidate`. The screen word
 *  is "draft": the analytic is written and has never run. */
export const CHIP_CANDIDATE =
  'Draft: the analytic is written and has never run. Put it in shadow to see what it would find.';

export const CHIP_RETIRED =
  'Retired: the analytic no longer runs. It keeps its ledger and its reason.';

export const CHIP_LEVEL = 'The level the analytic gives a hit of its own.';

// ── The entity page header ──────────────────────────────────────────────────
//
// The chip read "host" over a user account, because the server calls anything
// that is not an address a host. The chip states what the page knows.

export const ENTITY_ADDRESS = 'An IP address. This page holds what the grid records about it.';

export const ENTITY_NAME =
  'A name. It may be a host or an account. This grid does not say which.';

export const CHIP_NOT_SWEPT =
  'The analytic sweep has never reached this analytic. A count of zero would read as a clean grid.';

export const CHIP_ONE_SIGNAL =
  'One type of observation repeated until its weight reached the single-signal threshold.';

export const CHIP_IN_LEAD = 'This observation is part of a lead. Open the lead to decide.';

/** The id of an observation no analytic wrote. An alert verdict writes one, and
 *  an alert has no analytic, so there is nothing to open. */
export const OBSERVATION_NO_ANALYTIC =
  'The source of this observation. No analytic in this deployment carries the id, so there is nothing to open.';

/** The statistic line under an observation. A departure is the gap between
 *  what soc-ai measured and what is usual for the entity. The sentence said
 *  "the statistic that departed", which explains the word with itself. */
export const OBSERVATION_STATISTIC =
  'What soc-ai measured, and the usual value for this entity. The gap between the two is the departure.';

/** The link that opens the console with the query of one observation. */
export const OBSERVATION_RERUN =
  'Open a new hunt with this query in the objective. The hunt measures the value again.';

export const CHIP_DISMISSED_EVENT =
  'An analyst closed this lead here. The dismissal stays on the record.';

export const CHIP_SHADOW_LEAD =
  'Recorded in shadow. No hunt starts from this lead by itself.';

/** How a sighting ages. One sentence for every surface that shows a weight.
 *  The words "48 h half-life" named the scoring machinery in analyst text. */
export const SIGHTING_HALF_WEIGHT = 'An observation counts half as much after 48 hours.';

/** The lead rule of soc_ai/hunting/leads.py: two or more types reach 0.85
 *  together, or one type repeats to 1.50 alone (SINGLE_SIGNAL_THRESHOLD). */
export const LEAD_RULE =
  'Two or more types on one entity form a lead at a weight of 0.85. One type forms a lead alone when its repeats reach a weight of 1.50.';

export const CHIP_TYPE = `The type of observation. ${LEAD_RULE}`;

export const CHIP_SEEN = 'The analytic matched this entity again. The repeat adds weight.';

/** The sweep count. A sweep counts when it cites a document the row had not
 *  cited. A re-read of the same documents is not a sighting. */
export const CHIP_SWEEPS =
  'The number of sweeps that saw a new document for this observation. Each one adds weight. A signal seen on many sweeps repeats. It is not more severe.';

export const WEIGHT_NOW = `${SIGHTING_HALF_WEIGHT} A sweep that sees it again adds weight.`;

/** The weight the lead reached at formation. It is a record of one moment and
 *  it never moves, so it cannot wear the sentence of the decaying weight. */
export const WEIGHT_AT_FORMATION =
  'The live weight the lead reached when it formed. This number does not change.';

/** The weight per type. Stated against the cap, so one type repeated reads
 *  as saturated and not as a large number. */
export const WEIGHT_BY_TYPE =
  'The live weight of this type. One type saturates at its cap. A second type adds a chain.';

export const FILTER_HITS =
  'Hit filters. Unread: shadow hits nobody has opened or acted on. Live: hits from live ' +
  'analytics. Shadow: hits from analytics in shadow.';

export const FILTER_MANUAL = 'Hunts an analyst started from an objective.';

export const FILTER_SCHEDULE = 'Hunts a schedule started.';

export const FILTER_LEAD = 'Hunts started from a lead.';

export const FILTER_ALL = TYPE_ALL;

export const FILTER_CATALOG = TYPE_CATALOG;

export const STATUS_INVESTIGATION =
  'Where the investigation is. An investigation that is still going has no verdict yet.';

/** One sentence per hunt status. A hunt that was cancelled, interrupted or
 *  errored did not run to the end, and the row names the reason.
 *
 *  `where` names the surface: `list` has a findings column and `row` does not.
 *  A sentence that names a column the page does not have sends the reader
 *  looking for it. */
export function huntStatusTitle(status: string, where: 'list' | 'row' = 'list'): string {
  if (status === 'running') return STATUS_RUNNING;
  if (status === 'investigating') return STATUS_INVESTIGATING;
  if (status === 'complete') return where === 'row' ? STATUS_COMPLETE_ROW : STATUS_COMPLETE;
  return STATUS_COULD_NOT_RUN;
}

export const COUNT_THREAT_FINDINGS =
  'The threat findings the hunt reported. A visibility gap is not a threat finding.';

export const COUNT_FINDINGS = 'Everything the hunt reported: threats, gaps and observations.';

export const COUNT_STEPS = 'The steps the agent took, and the time the hunt spent.';

export const COUNT_OBSERVATIONS =
  'The observations on this entity in the window, from every source.';

export const COUNT_UNREAD_SHADOW_HITS =
  'Hits from analytics in shadow that nobody has opened or acted on.';

export const COUNT_AFFECTED_HOSTS = 'The hosts the findings of this hunt name.';

export const COUNT_MITRE = 'The MITRE ATT&CK techniques the findings of this hunt name.';

export const COUNT_AGE = 'The time of the event that the investigation judges.';

export const CHIP_INTERVAL = 'The interval a schedule runs at.';

export const DISPOSITION =
  'What the hunt concluded, from the worst threat finding it reported.';

export const CHIP_LEAD = 'The lead that asked for this hunt. Open it to decide.';

export const CHIP_SEVERITY = 'The severity of this finding, as the hunt reported it.';

/** The tooltip of a severity chip. Two things carry a severity: the rule that
 *  raised an alert, and a hunt finding. The console drew three chip styles
 *  for them and named neither, so a reader could not tell whose level it was.
 *  `label` is the screen word, "High". */
export function severityTitle(label: string, source: 'rule' | 'finding' = 'rule'): string {
  if (source === 'finding') return `Finding severity: ${label}. The hunt reported it.`;
  if (label.toLowerCase() === 'unknown') {
    return 'Rule severity: none. The alert document carries no severity label.';
  }
  return `Rule severity: ${label}. The detection rule that raised the alert sets it.`;
}

/** The count beside the host and finding map of a hunt. It read "1F · 0H",
 *  a code the reader had to decode. */
export function mapCountLabel(findings: number, hosts: number): string {
  const f = `${findings} finding${findings === 1 ? '' : 's'}`;
  const h = `${hosts} host${hosts === 1 ? '' : 's'}`;
  return `${f} · ${h}`;
}

export const CHIP_MITRE = 'A MITRE ATT&CK technique a finding of this hunt names.';

export const DIFF_STRIP = 'This run against the last complete run of the same objective.';

export const DIFF_NEW = 'Findings this run reported and the last run did not.';

export const DIFF_PERSISTING = 'Findings both runs reported.';

export const DIFF_NOT_REPORTED =
  'Findings the last run reported and this run did not. The activity can still run.';

export const STEP_DETAIL = 'Open the step to read what the agent did.';

export const LEDGER_OBSERVATIONS =
  'The observations this analytic wrote over the window, and the entities they name.';

export const LEDGER_LEADS = 'The leads this analytic fed over the window.';

export const LEDGER_HUNTED_PROMOTED =
  'The leads it fed that an analyst hunted, and the leads it fed that became an investigation.';

export const LEDGER_DISMISSED = 'The leads it fed that an analyst dismissed, by reason.';

export const LEDGER_VERSION = 'The status changes on record for this analytic.';

export const CHIP_VERSION = 'The version this analytic reached at this status change.';

/** The chip on a status change soc-ai made. soc-ai moves an analytic to
 *  shadow, and it never approves one to live or retires one. */
export const CHIP_SYSTEM_CHANGE =
  'soc-ai made this status change. soc-ai can move an analytic to shadow. ' +
  'Only an analyst approves an analytic to live or retires it.';

/** The chip on the version row that soc-ai writes when a shipped analytic
 *  ships in shadow. It is no demotion, so it wears no amber. */
export const CHIP_SHIPPED_IN_SHADOW =
  'soc-ai wrote this row when the analytic shipped. A new shipped analytic starts in shadow. ' +
  'An analyst approves it to live after the shadow week.';

/** The chip on an analytic that a system demotion holds in shadow. The chip
 *  reads "paused by soc-ai". The sentence named the "fire budget" and the
 *  "precision floor", two spec field names no analyst reads. */
export const CHIP_HELD_BY_SYSTEM =
  'Paused by soc-ai. soc-ai moved this analytic from live to shadow. It went over its daily ' +
  'hit limit, or its precision fell under the minimum. Read the evidence. Then select Approve or Reject.';

// ── The detection type chips ────────────────────────────────────────────────
//
// One chip per thing that raised the alert an investigation started from. The
// chips carried the word alone, so a row read SURICATA and said nothing about
// what Suricata is or what it reads.
//
// Two of the words name no detector. A lead run and a hunt run start from
// what soc-ai found, not from what the grid raised, and the standing sentence
// called a lead a detector.

export const DETECTION_KIND_TITLE: Record<string, string> = {
  suricata: 'Suricata raised this alert. It reads network traffic.',
  sigma: 'A Sigma rule raised this alert. It reads host and application logs.',
  notice: 'Zeek raised this notice. It reads network traffic.',
  hunt:
    'An investigation that started from a hunt. Its subject is one finding of the hunt or the ' +
    'whole hunt.',
  lead: "An investigation that started from a lead. Its subject is the lead's hunt.",
  unnamed: 'The alert carries no rule name. The list groups these by dataset.',
  alert: 'The alert comes from a dataset this deployment maps to no detector.',
};

/** The sentence for one detection type. A type this build does not know states
 *  what the app can say about it and nothing more. */
export function detectionKindTitle(kind: string): string {
  return DETECTION_KIND_TITLE[kind] ?? 'The detector that raised this alert, as the grid names it.';
}

// ── The Dashboard counts ────────────────────────────────────────────────────

export const COUNT_ALERT_EVENTS =
  'The alert documents the grid holds in this window, and the detection groups they fall into.';

/** The flow in the analyst's words, under the Needs you tile (owner,
 *  2026-10-07: "What is the user flow?"). The "How this flows" link follows
 *  it. */
export const OVERVIEW_FLOW =
  'soc-ai investigates alerts, hunts leads and joins confirmed attacks into campaigns. You ' +
  'decide in Needs you, and soc-ai writes your actions to Security Onion.';

export const COUNT_NEEDS_YOU =
  'The decisions that wait on you: campaigns with no decision, leads to decide, alert groups with no verdict, verdicts that need more info and recommended actions. The bell states the same count. Unread shadow hits are review work, and the tile states them on their own line.';

export const COUNT_TRUE_POSITIVES =
  'True positives in this window. The Confirmed threats panel states the same count and lists each target host.';

// ── Confirmed threats ───────────────────────────────────────────────────────
//
// The first panel of the Dashboard and of the Hunt Console, and the strip on
// a host page. The review of 2026-11-12 found the one result that needed a
// response 10,900 px down the Hunt Console, and a Dashboard with two true
// positive counts and no host name.

/** The line under the panel title. */
export const DEFINE_CONFIRMED_THREATS =
  'A confirmed threat is a true positive verdict. The panel lists the campaigns first, the worst ' +
  'stage first. It merges the other investigations by target host and lists the worst host first.';

/** The word and the sentence of each impact chip. Only Succeeded and
 *  Attempted wear a color. */
export const CHIP_IMPACT: Record<'succeeded' | 'attempted' | 'unknown' | 'none', { label: string; title: string }> = {
  succeeded: {
    label: 'Succeeded',
    title: 'Succeeded: the evidence shows that the attack worked on the target.',
  },
  attempted: {
    label: 'Attempted',
    title: 'Attempted: the evidence shows an attack on the target. It shows no success.',
  },
  unknown: {
    label: 'Impact unknown',
    title: 'Impact unknown: the evidence does not show if the attack worked.',
  },
  none: {
    label: 'No impact',
    title: 'No impact: the evidence shows no effect on the target.',
  },
};

/** The primary link of a row with recommended actions that wait. */
export const THREAT_ACTIONS_WAIT =
  'Recommended actions wait for your decision. The link opens the newest investigation of this host.';

/** The primary link of a row with no action that waits. */
export const THREAT_OPEN =
  'The link opens the true positive investigations of this host in this window.';

/** The quiet line of a group inside an authorized activity record. */
export const THREAT_AUTHORIZED =
  'Each investigation of this group is inside an authorized activity record. The investigations ' +
  'keep the true positive verdict. The link opens the investigations.';

/** The count of the investigations of a campaign inside an authorized activity record. */
export const THREAT_CAMPAIGN_AUTHORIZED =
  'True positive investigations of this campaign inside an authorized activity record. They request no case.';

export const COUNT_RUNNING = 'Investigations soc-ai is working now.';

export const TONE_URGENT = 'Urgent: this item needs an analyst now.';

export const TONE_ATTENTION = 'Attention: this item waits on an analyst.';

export const TONE_INFORMATIONAL = 'Informational: this item states what happened.';

export const GROUP_HUNTING = 'Shadow hits, leads and hunts. The Hunts page holds them all.';

// ---------------------------------------------------------------------------
// A lead starts its own hunt, a hunt is investigated as a whole, leads relate.
//
// The sentences follow the design for the hunting layer (leads hunt themselves,
// a hunt is investigated as a whole, leads relate, the lead rule is measured).
// Four decisions reach the screen, and each one puts a new word on it: a
// queued hunt, a hunt as the subject of an investigation, a related lead, and
// the table that says whether the lead rule earns its place.
// ---------------------------------------------------------------------------

// ── The queued hunt ─────────────────────────────────────────────────────────

/** The pill on a New lead whose hunt the loop has not started yet. The lead
 *  waits on the loop, not on the analyst, and a New pill alone said the
 *  opposite. */
export const PILL_HUNT_QUEUED =
  "The lead's hunt starts within a minute. Nothing waits on you yet.";

/** The sentence the leads legend gains while auto-hunt is on. Without it the
 *  four state words read as four things an analyst must do. */
export const LEGEND_AUTO_HUNT = 'A new lead starts its own hunt.';

/** The note on the leads strip while auto-hunt is on. The standing note says
 *  soc-ai starts no hunt from a lead, which is the opposite of the truth once
 *  the loop runs.
 *
 *  The note names the three leads the loop leaves. It claimed every new lead,
 *  and an analyst who read it over a shadow lead waited for a hunt that never
 *  came. */
export const LEADS_NOTE_AUTO_HUNT =
  'soc-ai starts a hunt on every new lead, except a shadow lead, a reopened lead and a ' +
  'lead with no documents. A shadow lead comes from a shadow analytic. ' +
  'You decide what the hunt found.';

/** The chip beside the pill on a New lead the loop leaves to the analyst. The
 *  note above states the exclusions, and this states which lead carries one.
 *  The screen word for the loop is "auto-hunt", the name of its setting. */
export const CHIP_LEFT_TO_YOU =
  'Auto-hunt starts no hunt here: a shadow lead, a reopened lead, or a lead with no ' +
  'documents. A shadow lead comes from a shadow analytic. Hunt it by hand.';

/** The secondary act on a lead whose hunt is queued. The loop starts it within
 *  a minute, and this button does not wait for the loop. */
export const ACTION_HUNT_NOW = 'Start the hunt now. The lead does not wait for auto-hunt.';

// ── The hunt as a subject ───────────────────────────────────────────────────

/** The hover of "Hunt this lead": what a hunt returns, and what it does not
 *  do. The owner could not tell a hunt from an investigation (2026-10-07). */
export const ACTION_HUNT =
  'Start a hunt on this lead. The hunt returns findings and a narrative. soc-ai investigates ' +
  'each threat finding and shows the verdicts. The hunt takes no action in Security Onion.';

/** The line under the actions of a lead. The two verbs of the flow, once. */
export const LEAD_ACTIONS_LINE =
  'Hunt this lead. soc-ai investigates each threat finding of the hunt and shows the verdicts.';

// ── The lead page: one effect line for each button ──────────────────────────
//
// The lead page printed the hunt line above over every open lead. A lead with
// the pill "Hunted · No threat found" then read "Hunt this lead. ..." and
// offered no such button. The other buttons stated no effect (review
// 2026-11-12, F5). Each button the page shows now has one line, and the page
// prints the lines of the buttons it shows. Each line starts with the name of
// its button. The keys are the keys of LEAD_ACTION in LeadsStrip.tsx.

export const LEAD_ACTION_EFFECT = {
  hunt: LEAD_ACTIONS_LINE,
  huntNow: 'Hunt now. The hunt starts now. The lead does not wait for auto-hunt.',
  dismiss:
    'Dismiss. The lead closes with the reason that you choose. The observations on the lead ' +
    'and their repeats then form no new lead.',
  viewHunt: 'View hunt. The page of the hunt opens. The hunt still runs.',
  readHunt:
    'Read hunt. The page of the hunt opens with the findings, the narrative and the verdicts.',
  huntAgain:
    'Hunt again. One more hunt starts after a confirm. The lead then points at the new hunt.',
  reopen:
    'Reopen. The lead goes back in the queue and waits on you. Auto-hunt starts no hunt on a ' +
    'reopened lead.',
  viewInvestigation: 'View investigation. The page of the investigation on this lead opens.',
} as const;

/** The two buttons of the verdict strip on the lead page. */
export const LEAD_VERDICT_EFFECT = {
  close: 'Close the lead. The lead closes and names this investigation.',
  keep: 'Keep open. The lead stays open. The page does not ask again about this investigation.',
} as const;

// ── The dismissal reasons ───────────────────────────────────────────────────
//
// The form listed nine reasons and stated the effect of none. The store keeps
// the reason on the lead and in its history (soc_ai/store/leads.py, dismiss).
// The lead quality report and the ledger of each analytic count it
// (routes_hunts.py lead_quality, soc_ai/hunting/ledger.py). No code reads a
// reason to change a baseline, an analytic, a role or a host. So every effect
// line says what the reason records and what it leaves as it is.

export const DISMISS_REASON_COMMON =
  'Each reason closes the lead in the same way. The history of the lead keeps the reason, and ' +
  'the lead quality report counts it. No reason changes a baseline, an analytic or a host.';

export const DISMISS_REASON_EFFECT: Record<string, string> = {
  expected_for_role:
    'Records that the role of the host explains the observations. The role of the host does not change.',
  known_change:
    'Records that a known change caused the observations. soc-ai stores no exception for the change.',
  benign_repeat:
    'Records that the observations repeat a benign pattern. soc-ai stores no rule for the pattern.',
  bad_baseline: 'Records that the baseline is wrong. The baseline does not change.',
  authorized_test:
    'Records that an authorized test or scan caused the observations. The reason authorizes no later activity.',
  duplicate:
    'Records that another lead or investigation holds this work. soc-ai links no other record to this lead.',
  bad_analytic_logic:
    'Records that the analytic logic is wrong. The analytic keeps its status and still runs. Its ledger counts this dismissal.',
  lab_host:
    'Records that the host is a lab host or a test host. The host gets no mark, and a new observation on it can form a new lead.',
  other: 'Records no specific cause. State the cause in the note.',
};

/** The line under the reason select: the effect of the chosen reason, then
 *  what every reason does. With no reason chosen it is the common line. */
export function dismissReasonEffect(reason: string): string {
  const own = DISMISS_REASON_EFFECT[reason];
  return own ? `${own} ${DISMISS_REASON_COMMON}` : DISMISS_REASON_COMMON;
}

/** The mark on a lead whose live weight is under the weight a lead forms at.
 *  "weight now 0.32" sat behind the Scoring toggle, and a lead forms at 0.85. */
export const WEIGHT_DECAYED =
  'The live weight of this lead is under the weight at which a lead forms. ' +
  `${SIGHTING_HALF_WEIGHT} A sweep that sees it again adds weight.`;

/** The hover of "Open an investigation" on a finding that has no
 *  investigation. The hunt investigates its findings, and this is the manual
 *  control for a finding it left. */
export const ACTION_OPEN_INVESTIGATION =
  'Open an investigation on this finding. The control starts the model on the evidence ' +
  'that the finding cites. The investigation ends in a verdict and recommended actions.';

/** The depth chip on an investigation: how far the run was allowed to go.
 *
 *  The stored keys stay cheap, standard, deep and rule_prior. The screen says
 *  "Depth: quick / standard / deep". "class" and "cheap" were budget words,
 *  and "rule prior" named a mechanism where the analyst needs the source of
 *  the verdict: the history of the rule. */
export const CHIP_RUN_CLASS: Record<string, { label: string; title: string }> = {
  cheap: {
    label: 'Depth: quick',
    title:
      'Quick. The model wrote the verdict from the context soc-ai gathered, in one request. ' +
      'The model called no tool. The Oracle did not review it. A decision template cleared the alert first.',
  },
  standard: {
    label: 'Depth: standard',
    title:
      'Standard. The model investigated with the read tools at the standard budget. ' +
      'The Oracle reviews an uncertain verdict.',
  },
  deep: {
    label: 'Depth: deep',
    title:
      'Deep. An analyst asked for a deep investigation. The model investigated with every read tool ' +
      'at the full budget. The Oracle reviews an uncertain verdict.',
  },
  rule_prior: {
    label: 'rule history',
    title: 'No model ran. soc-ai copied the latest model verdict of this rule.',
  },
};

/** The depth chip on a row with no recorded depth, on a list where other rows
 *  have one. A list shows the chip on every row or on none: a chip on some
 *  rows only read as a property the other rows lack. */
export const CHIP_RUN_CLASS_NONE = {
  label: 'Depth: not recorded',
  title: 'soc-ai recorded no depth for this investigation. An investigation from before depths existed has none.',
};

/** The same chip on a run still in progress. The depth is written when it ends. */
export const CHIP_RUN_CLASS_PENDING = {
  label: 'Depth: pending',
  title: 'The investigation is in progress. soc-ai records its depth when it ends.',
};

/** Why a verdict went to the Oracle. The codes the uncertainty rule and the
 * classic rule write. The sentences name a verdict in the words the console
 * shows, never as a stored key. */
export const ORACLE_REASON: Record<string, string> = {
  confidence_in_band: 'The confidence is in the gate band, from 0.4 to below 0.7.',
  template_split: 'The decision template and the model disagree on the verdict.',
  deep_needs_more_info: 'A deep investigation ended with the verdict Needs more info.',
  needs_more_info: 'The local verdict is Needs more info.',
  malware_non_tp: 'A malware or attack rule has a local verdict other than True positive.',
  below_confidence: 'The local confidence is below 0.6.',
  fallback_route: 'A fallback model route served this investigation.',
};

/** The Oracle rule shadow tally in the Detection tuning panel. */
export const ORACLE_SHADOW_CAPTION =
  'The Oracle rule mode is shadow. The classic rule decides which verdicts go to the Oracle. ' +
  'This table counts what the uncertainty rule would send. No Oracle call comes from it.';

/** The Rule prior column of the Detection tuning panel. */
export const RULE_PRIOR_COLUMN =
  'The rule prior gives a scheduled alert the verdict of the latest investigation of its rule by the model. ' +
  'The column counts the alerts it covered in the last 30 days. ' +
  'It counts the real verdicts that agreed and disagreed.';

export const RULE_PRIOR_SUSPENDED =
  'The model disagreed with the rule prior on an alert of this rule. The prior stays off for the rule. ' +
  'Read the investigation that disagreed. Then clear the suspension.';

export const RULE_PRIOR_UNCHECKED =
  'Covered alerts that the model did not read. Live mode skips the model on a covered alert unless the sample picks it.';

/** The covered alerts with two internal addresses, and their disagreements. */
export const RULE_PRIOR_INTERNAL =
  'Covered alerts with two internal addresses. The second count is the real verdicts that disagreed.';

/** The covered alerts with a known external address, and their disagreements. */
export const RULE_PRIOR_KNOWN_EXTERNAL =
  'Covered alerts with one external address that the rule knows on the same internal machine. ' +
  'Two or more false positives of the rule in the last 7 days had a matching external address. ' +
  'The second count is the real verdicts that disagreed.';

/** Why the rule prior held back on the newest alert of a rule it did not cover. */
export const RULE_PRIOR_REASON: Record<string, string> = {
  no_rule: 'The alert names no rule.',
  critical_severity: 'The alert is critical.',
  severity_unknown: 'The alert carries no severity label.',
  no_flow_endpoints: 'The alert has no source or no destination address.',
  external_endpoint: 'Both addresses are external, or an address is unreadable.',
  external_endpoint_new: 'The external address is new for this rule on this internal machine.',
  campaign_machine: 'An address belongs to a machine of an open campaign that is not closed.',
  nomination_unavailable: 'The grid could not list the nominated rules.',
  not_nominated: 'Detection tuning did not nominate the rule.',
  analyst_override: 'An analyst overrode a verdict of this rule.',
  suspended: 'The model disagreed with the prior on an earlier alert.',
  non_false_positive_in_window: 'An investigation of the rule by the model this week was not a false positive.',
  too_few_runs: 'The rule has too few model false positives this week.',
  lapsed: 'The model read no alert of the rule in the last 24 hours.',
  open_lead_or_fresh_observation: 'A host carries an open lead or a fresh observation.',
  evaluation_failed: 'The prior could not read its inputs.',
};

/** The type chip on an investigation whose subject is a hunt. A finding run
 *  judges one finding (change E). A lead run and an older finding run judge
 *  the whole hunt. The list row does not read which, so the tip covers both. */
export const CHIP_SUBJECT_HUNT =
  'An investigation of a hunt. Its subject is one finding of the hunt or the whole hunt.';

export const SUBJECT_OBJECTIVE =
  'The objective the hunt ran with. This investigation answers it.';

export const SUBJECT_FINDINGS = 'The findings of the hunt this investigation read.';

/** A run that judged one finding (change E). The two tips above stay true for
 *  a lead run and for a finding run stored before the change. */
export const SUBJECT_FINDING =
  'The finding this investigation judges. The rest of the hunt is context.';

export const SUBJECT_HUNT_CONTEXT =
  'The hunt this finding came from. The investigation read it as context.';

export const SUBJECT_OBJECTIVE_CONTEXT =
  'The objective the hunt ran with. It is context for the finding.';

export const SUBJECT_DOCUMENTS =
  'The documents the findings cite. The investigation read every one of them.';

export const SUBJECT_HUNT_LINK = 'Open the hunt this investigation read.';

export const SUBJECT_LEAD =
  'The lead this hunt started from. Open it to read its observations.';

// ── The related leads ───────────────────────────────────────────────────────

/** The chip on a lead row that names how many open leads relate to it. The
 *  server joins two leads on four things, and the sentence named three: the
 *  reason an analyst read on the range was the alert rule. */
export const CHIP_RELATED =
  'Open leads from the last 7 days that share an analytic, an alert rule, an external ' +
  'address or a technique with this one.';

/** The reason column of the Related leads panel. */
export const RELATED_REASON =
  'What the two leads share: an analytic, an alert rule, an external address or a technique.';

// ── The lead quality block ──────────────────────────────────────────────────

export const LEAD_QUALITY =
  'What the lead rule produced: leads formed, hunted, promoted and dismissed.';

export const QUALITY_WEEK = 'The week the leads formed in. Each row counts that week alone.';

export const QUALITY_FORMED = 'Leads that formed in the week.';

export const QUALITY_HUNTED = 'Leads from the week that a hunt has run on.';

export const QUALITY_THREAT = 'Leads from the week whose hunt reported a threat finding.';

export const QUALITY_PROMOTED = 'Leads from the week an analyst promoted to an investigation.';
export const QUALITY_CLOSED_BY_HUNT = 'Leads from the week that soc-ai closed because the hunt found no threat.';

export const QUALITY_DISMISSED =
  'Leads from the week an analyst dismissed, under the reason the analyst chose.';

export const QUALITY_TYPES = 'The observation types that formed the lead, as one set.';

export const QUALITY_TYPES_FORMED = 'Leads these types formed over the window.';

export const QUALITY_TYPES_DISMISSED = 'Leads these types formed that an analyst dismissed.';
export const QUALITY_TYPES_CLOSED_BY_HUNT =
  'Leads these types formed that soc-ai closed because the hunt found no threat.';

export const QUALITY_TYPES_THREAT =
  'Leads these types formed whose hunt reported a threat finding.';

// ── The Event timeline ──────────────────────────────────────────────────────

/** The chip on a row of the Event timeline that the verdict cites. */
export const EVENT_CITED = 'The verdict cites this document.';

/** The chip on a row of the hunt Event timeline: "F2". `n` counts from 1. */
export function eventFindingTitle(n: number): string {
  return `Finding ${n} cites this document.`;
}
