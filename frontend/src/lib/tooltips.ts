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
  'A hit is one match of one analytic on one entity. A live hit adds weight to a lead. A ' +
  'shadow hit adds no weight. It waits for you to read it and to approve or reject the ' +
  'analytic that wrote it.';

export const DEFINE_LEAD =
  'A lead is a set of observations on one entity that are worth one decision: hunt it or ' +
  'dismiss it.';

export const DEFINE_HUNT =
  'A hunt is one run against one objective. The model or a catalog query runs it. soc-ai ' +
  'investigates each threat finding when the hunt ends. You, a schedule or a lead can start one.';

export const DEFINE_SCHEDULE =
  'A schedule starts a hunt on an interval and writes a hunt row on every run.';

export const DEFINE_ANALYTIC =
  'An analytic is one written detection. The sweep runs each analytic. A live analytic ' +
  'records hits that can form a lead. A shadow analytic records hits for you to read.';

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

export const TAB_ALL = 'Every lead, in every state.';

// ── The analytic chips ──────────────────────────────────────────────────────

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

// ── The hunt type chips ─────────────────────────────────────────────────────

export const TYPE_ALL = 'Every hunt in the window. The catalog runs are included.';

export const TYPE_MANUAL = 'Hunts an analyst started from an objective.';

export const TYPE_SCHEDULE = 'Hunts a schedule started.';

export const TYPE_LEAD = 'Hunts started from a lead.';

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
  `a lead when its hunt finds no threat, or when ${CLOSE_RULE_CLAUSE}.`;

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
  'Where the investigation is. A run that is still going has no verdict yet.';

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

export const COUNT_AGE = 'When the run started.';

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

export const DIFF_RESOLVED = 'Findings the last run reported and this run did not.';

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
  'soc-ai investigates alerts and runs hunts. You make each decision in Needs you. ' +
  'soc-ai sends your actions to Security Onion.';

export const COUNT_NEEDS_YOU =
  'The work that waits on you: leads to decide, unread shadow hits, alert groups with no verdict, verdicts that need more info and recommended actions. The sidebar badges and the bell state the same count.';

export const COUNT_TRUE_POSITIVES =
  'Investigations in this window with a true positive verdict. The Investigations list counts the same runs with the same query.';

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

/** The hover of "Open an investigation" on a finding that has no
 *  investigation. The hunt investigates its findings, and this is the manual
 *  control for a finding it left. */
export const ACTION_OPEN_INVESTIGATION =
  'Open an investigation on this finding. The control starts one run of the model on the ' +
  'evidence that the finding cites. The run ends in a verdict and recommended actions.';

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
      'Deep. An analyst asked for a deep re-run. The model investigated with every read tool ' +
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
  title: 'soc-ai recorded no depth for this run. A run from before depths existed has none.',
};

/** The same chip on a run still in progress. The depth is written when it ends. */
export const CHIP_RUN_CLASS_PENDING = {
  label: 'Depth: pending',
  title: 'The run is in progress. soc-ai records its depth when it ends.',
};

/** Why a verdict went to the Oracle. The codes the uncertainty rule and the
 * classic rule write. The sentences name a verdict in the words the console
 * shows, never as a stored key. */
export const ORACLE_REASON: Record<string, string> = {
  confidence_in_band: 'The confidence is in the gate band, from 0.4 to below 0.7.',
  template_split: 'The decision template and the model disagree on the verdict.',
  deep_needs_more_info: 'A deep re-run ended with the verdict Needs more info.',
  needs_more_info: 'The local verdict is Needs more info.',
  malware_non_tp: 'A malware or attack rule has a local verdict other than True positive.',
  below_confidence: 'The local confidence is below 0.6.',
};

/** The Oracle rule shadow tally in the Detection tuning panel. */
export const ORACLE_SHADOW_CAPTION =
  'The Oracle rule mode is shadow. The classic rule decides which verdicts go to the Oracle. ' +
  'This table counts what the uncertainty rule would send. No Oracle call comes from it.';

/** The Rule prior column of the Detection tuning panel. */
export const RULE_PRIOR_COLUMN =
  'The rule prior gives a scheduled alert the verdict of its rule\'s latest model run. ' +
  'The column counts the alerts it covered in the last 30 days. It counts how many real verdicts agreed.';

export const RULE_PRIOR_SUSPENDED =
  'A real run disagreed with the rule prior on this rule. The prior stays off for the rule. ' +
  'Read the disagreeing run. Then clear the suspension.';

export const RULE_PRIOR_UNCHECKED =
  'Covered alerts that got no real run. Live mode skips the model on a covered alert unless the sample picks it.';

/** Why the rule prior held back on the newest alert of a rule it did not cover. */
export const RULE_PRIOR_REASON: Record<string, string> = {
  no_rule: 'The alert names no rule.',
  critical_severity: 'The alert is critical.',
  severity_unknown: 'The alert carries no severity label.',
  no_flow_endpoints: 'The alert has no source or no destination address.',
  external_endpoint: 'An endpoint is outside the estate.',
  nomination_unavailable: 'The grid could not list the nominated rules.',
  not_nominated: 'Detection tuning did not nominate the rule.',
  analyst_override: 'An analyst overrode a verdict of this rule.',
  suspended: 'A real run disagreed with the prior.',
  non_false_positive_in_window: 'A model run of the rule this week was not a false positive.',
  too_few_runs: 'The rule has too few model false positives this week.',
  lapsed: 'No model ran on the rule in the last 24 hours.',
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
