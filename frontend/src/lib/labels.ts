// ---------------------------------------------------------------------------
// The one map from a stored word to the word on screen.
//
// Read this module for every verdict, hunt outcome and run status that the
// console shows. Each entry holds one label, one tone, one colour and one chip
// class. A screen that prints a stored value such as `true_positive` or
// `could_not_run` reads it from here and from nowhere else.
//
// The console had five spellings of needs_more_info, two colours for a clean
// hunt and a green chip on a failed run. Each screen held its own copy of the
// words, and the copies drifted.
//
// How to use it:
//
//   import { verdictLabel, verdictMeta, outcomeMeta, huntOutcome, chipProps } from '../lib/labels';
//
//   verdictLabel('needs_more_info')          // "Needs more info"
//   outcomeLabel(huntOutcome(row))           // "Could not run" for a failed run
//   statusLabel('interrupted')               // "Failed"
//   <span {...chipProps(verdictMeta(v))}>{verdictLabel(v)}</span>
//   confidenceText(0.7)                      // "0.70"
//   confidenceWord(0.83)                     // "High"
//
// Rules:
//
// - Keys stay in snake_case. Labels are sentence case.
// - The tone names the colour. `danger` is red, `warn` is amber, `ok` is
//   green, `muted` is grey, `info` is blue, `caution` is gold.
// - Green means a clean result and nothing else. A failed run is grey.
// - An unknown key reads as its own words with the underscores removed. It
//   never renders blank and it never throws.
// - Times and durations live in lib/timeRange.ts: `ago`, `absoluteTime`,
//   `formatDuration`.
// ---------------------------------------------------------------------------

/** The seven colours a label can wear. */
export type Tone = 'danger' | 'warn' | 'caution' | 'ok' | 'muted' | 'info' | 'none';

export interface ToneMeta {
  /** The Tailwind colour name, or an arbitrary value where no name exists. */
  token: string;
  /** The hex colour for an inline style, a chart fill or an SVG mark. */
  color: string;
  /** A wash behind the label. */
  bg: string;
  /** The chip border. */
  border: string;
  /** The Tailwind classes of a chip in this tone. Text, wash and border. */
  chipClass: string;
}

// The chip classes are whole literal strings. Tailwind reads this file to
// build its CSS, and a class assembled at runtime would not exist.
export const TONE: Record<Tone, ToneMeta> = {
  danger: {
    token: 'danger',
    color: '#f04438',
    bg: 'rgba(240,68,56,.10)',
    border: 'rgba(240,68,56,.32)',
    chipClass: 'text-danger bg-danger/10 border-danger/30',
  },
  warn: {
    token: 'warn',
    color: '#f5a623',
    bg: 'rgba(245,166,35,.10)',
    border: 'rgba(245,166,35,.32)',
    chipClass: 'text-warn bg-warn/10 border-warn/30',
  },
  caution: {
    token: '[#d29922]',
    color: '#d29922',
    bg: 'rgba(210,153,34,.10)',
    border: 'rgba(210,153,34,.32)',
    chipClass: 'text-[#d29922] bg-[#d29922]/10 border-[#d29922]/30',
  },
  ok: {
    token: 'success',
    color: '#3fb950',
    bg: 'rgba(63,185,80,.10)',
    border: 'rgba(63,185,80,.32)',
    chipClass: 'text-success bg-success/10 border-success/30',
  },
  muted: {
    token: 'dim',
    color: '#8b949e',
    bg: 'rgba(139,148,158,.10)',
    border: 'rgba(139,148,158,.32)',
    chipClass: 'text-dim bg-dim/10 border-dim/30',
  },
  info: {
    token: 'accent',
    color: '#4b8bf5',
    bg: 'rgba(75,139,245,.10)',
    border: 'rgba(75,139,245,.32)',
    chipClass: 'text-accent bg-accent/10 border-accent/30',
  },
  none: {
    token: 'verdict-untriaged',
    color: '#6b7484',
    bg: 'rgba(107,116,132,.08)',
    border: 'rgba(107,116,132,.25)',
    chipClass: 'text-verdict-untriaged bg-verdict-untriaged/10 border-verdict-untriaged/25',
  },
};

/** One label on screen: the words, the tone and the tone's colours. */
export interface LabelMeta extends ToneMeta {
  label: string;
  tone: Tone;
}

function meta(label: string, tone: Tone): LabelMeta {
  return { label, tone, ...TONE[tone] };
}

/** "could_not_run" reads "Could not run". The fallback for a key this build
 *  does not know, so a newer backend never blanks a cell. */
export function humanize(key: string): string {
  const words = key.replace(/_/g, ' ').trim();
  return words ? words.charAt(0).toUpperCase() + words.slice(1) : '';
}

// ---- Verdicts ----------------------------------------------------------------

/** The verdict keys the API sends. `untriaged` is the absence of a verdict. */
export type VerdictKey =
  | 'true_positive'
  | 'false_positive'
  | 'needs_more_info'
  | 'inconclusive'
  | 'untriaged';

export const VERDICT_LABELS: Record<VerdictKey, LabelMeta> = {
  true_positive: meta('True positive', 'danger'),
  false_positive: meta('False positive', 'muted'),
  needs_more_info: meta('Needs more info', 'warn'),
  // The vote did not settle. Gold, apart from the amber of needs_more_info,
  // because needs_more_info asks the analyst for input and this does not.
  inconclusive: meta('Inconclusive', 'caution'),
  untriaged: meta('Untriaged', 'none'),
};

/** The three verdicts an analyst can set. The override select lists these. */
export const VERDICT_OPTIONS: { value: VerdictKey; label: string }[] = (
  ['true_positive', 'false_positive', 'needs_more_info'] as const
).map((v) => ({ value: v, label: VERDICT_LABELS[v].label }));

export function verdictMeta(verdict: string | null | undefined): LabelMeta {
  if (verdict && verdict in VERDICT_LABELS) return VERDICT_LABELS[verdict as VerdictKey];
  return meta(humanize(verdict ?? '') || 'No verdict', 'none');
}

/** "true_positive" reads "True positive". */
export function verdictLabel(verdict: string | null | undefined): string {
  return verdictMeta(verdict).label;
}

// ---- Hunt outcomes -----------------------------------------------------------

/** How a hunt ended, in one word set for the hunt list, the hunt page, the
 *  lead pill and the bell. */
export type HuntOutcomeKey =
  | 'threat_found'
  | 'no_threat'
  | 'no_threat_gap'
  | 'no_answer'
  | 'could_not_run'
  | 'running'
  | 'investigating'
  | 'threats_confirmed'
  | 'no_threat_confirmed';

export const OUTCOME_LABELS: Record<HuntOutcomeKey, LabelMeta> = {
  threat_found: meta('Threat found', 'danger'),
  no_threat: meta('No threat found', 'ok'),
  // A gap is a coverage statement. The hunt could not see part of what it
  // looked for, so the result is not a clean all clear.
  no_threat_gap: meta('No threat found, visibility gap', 'muted'),
  // The hunt ran and did not test its objective. Amber, because the analyst
  // has to act.
  no_answer: meta('No answer', 'warn'),
  could_not_run: meta('Could not run', 'muted'),
  running: meta('Running', 'info'),
  // A hunt investigates its subject findings as part of the hunt. These three
  // come from that phase. `outcomeLabel` writes the counts when it has them:
  // "Investigating 2 of 3 findings", "2 of 3 findings are threats".
  investigating: meta('Investigating findings', 'info'),
  threats_confirmed: meta('Threats confirmed', 'danger'),
  no_threat_confirmed: meta('No threat confirmed', 'ok'),
};

/** The counts of the investigation phase, as the hunt row and page carry them.
 *  `threats` is the true positives among the verdicts. */
export interface OutcomeCounts {
  investigated?: number | null;
  total?: number | null;
  threats?: number | null;
}

function findingsWord(n: number): string {
  return n === 1 ? '1 finding' : `${n} findings`;
}

/** The outcome words the hunts API writes today, mapped to the keys above. */
const API_OUTCOME: Record<string, HuntOutcomeKey> = {
  threats: 'threat_found',
  clean: 'no_threat',
  gap: 'no_threat_gap',
  failed: 'could_not_run',
  no_answer: 'no_answer',
};

const STOPPED = new Set(['error', 'cancelled', 'interrupted']);
const RUNNING = new Set(['running', 'queued']);

/** The outcome of one hunt from its status and the outcome the API wrote.
 *  A stopped run reads "Could not run" whatever its outcome field says. A
 *  complete hunt with no outcome field returns null, because an older row
 *  does not say. */
export function huntOutcome(row: {
  status?: string | null;
  outcome?: string | null;
}): HuntOutcomeKey | null {
  const status = row.status ?? '';
  if (status === 'investigating') return 'investigating';
  if (RUNNING.has(status)) return 'running';
  if (STOPPED.has(status)) return 'could_not_run';
  const outcome = row.outcome ?? '';
  if (outcome in OUTCOME_LABELS) return outcome as HuntOutcomeKey;
  return API_OUTCOME[outcome] ?? null;
}

/** The meta of an outcome. Takes a key above or a word the API writes. */
export function outcomeMeta(outcome: string | null | undefined): LabelMeta {
  const key = outcome ? ((outcome in OUTCOME_LABELS ? outcome : API_OUTCOME[outcome]) as HuntOutcomeKey | undefined) : undefined;
  if (key) return OUTCOME_LABELS[key];
  return meta(humanize(outcome ?? '') || 'No outcome', 'muted');
}

/** "could_not_run" and the API's "failed" both read "Could not run".
 *  With the phase counts, `investigating` reads "Investigating 2 of 3
 *  findings" and `threats_confirmed` reads "2 of 3 findings are threats". */
export function outcomeLabel(outcome: string | null | undefined, counts?: OutcomeCounts): string {
  const total = counts?.total ?? 0;
  if (total > 0 && outcome === 'investigating') {
    return `Investigating ${counts?.investigated ?? 0} of ${findingsWord(total)}`;
  }
  if (total > 0 && outcome === 'threats_confirmed' && counts?.threats != null) {
    const verb = counts.threats === 1 ? 'is a threat' : 'are threats';
    return `${counts.threats} of ${findingsWord(total)} ${verb}`;
  }
  return outcomeMeta(outcome).label;
}

/** The outcome text of one hunt row. The server's words win, because only the
 *  server counts the true positives among the verdicts. Without them the
 *  counts the row carries write the progress of an investigating hunt. */
export function huntOutcomeText(row: {
  status?: string | null;
  outcome?: string | null;
  outcome_label?: string | null;
  findingsInvestigated?: number | null;
  findingsTotal?: number | null;
}): string | null {
  const key = huntOutcome(row);
  if (!key) return null;
  if (row.outcome_label && (key === row.outcome || key === 'investigating')) return row.outcome_label;
  return outcomeLabel(key, { investigated: row.findingsInvestigated, total: row.findingsTotal });
}

// ---- Run statuses ------------------------------------------------------------

/** The lifecycle status of an investigation, a hunt or a backtest run. */
export type RunStatusKey = 'complete' | 'running' | 'queued' | 'error' | 'cancelled' | 'interrupted';

// Three stops read as one word. The analyst acts the same way on each: run it
// again. `statusDetail` keeps the cause for a tooltip.
export const STATUS_LABELS: Record<RunStatusKey, LabelMeta> = {
  complete: meta('Complete', 'ok'),
  running: meta('Running', 'info'),
  queued: meta('Queued', 'info'),
  error: meta('Failed', 'muted'),
  cancelled: meta('Failed', 'muted'),
  interrupted: meta('Failed', 'muted'),
};

const STATUS_DETAIL: Record<string, string> = {
  complete: 'The run finished.',
  running: 'The run is in progress.',
  queued: 'The run waits for a free worker.',
  error: 'An error stopped the run before it finished.',
  cancelled: 'A cancel request stopped the run before it finished.',
  interrupted: 'A service restart stopped the run before it finished.',
};

export function statusMeta(status: string | null | undefined): LabelMeta {
  if (status && status in STATUS_LABELS) return STATUS_LABELS[status as RunStatusKey];
  return meta(humanize(status ?? '') || 'Unknown', 'muted');
}

/** "error", "cancelled" and "interrupted" read "Failed". */
export function statusLabel(status: string | null | undefined): string {
  return statusMeta(status).label;
}

/** One sentence on why a run is in its status. Use it as the tooltip of a
 *  "Failed" chip, because the chip no longer names the cause. */
export function statusDetail(status: string | null | undefined): string {
  return (status && STATUS_DETAIL[status]) || 'soc-ai recorded no status for this run.';
}

/** True for a status that stopped the run before it finished. */
export function isFailedStatus(status: string | null | undefined): boolean {
  return status != null && STOPPED.has(status);
}

// ---- Chips -------------------------------------------------------------------

/** The props of one chip in a tone. Spread them on a span:
 *  `<span {...chipProps(verdictMeta(v))}>{verdictLabel(v)}</span>`.
 *  `size` picks the list chip or the larger header chip. */
export function chipProps(
  m: Pick<LabelMeta, 'tone' | 'chipClass'>,
  opts: { size?: 'sm' | 'lg'; className?: string; title?: string } = {},
): { className: string; 'data-tone': Tone; title?: string } {
  const size =
    opts.size === 'lg'
      ? 'px-3 py-[5px] text-[12.5px] uppercase tracking-[.01em]'
      : 'px-[9px] py-[2.5px] text-[11.5px]';
  const cls = [
    'inline-flex items-center gap-1.5 whitespace-nowrap rounded-pill border font-semibold',
    size,
    m.chipClass,
    opts.className ?? '',
  ]
    .join(' ')
    .trim();
  return opts.title ? { className: cls, 'data-tone': m.tone, title: opts.title } : { className: cls, 'data-tone': m.tone };
}

// ---- Confidence --------------------------------------------------------------

/** Confidence always prints with two decimals: "0.70", never "0.7". A missing
 *  value prints `missing`, "Not recorded" by default. */
export function confidenceText(value: number | null | undefined, missing = 'Not recorded'): string {
  if (value == null || !Number.isFinite(value)) return missing;
  return value.toFixed(2);
}

/** The thresholds behind `confidenceWord`. They follow the server:
 *
 *  - 0.80 is `oracle_skip_after_confident_loop`: at or above it the server
 *    keeps a verdict local after an investigation loop. "High".
 *  - 0.70 is the top of the gate band `[0.4, 0.7)` (gates.gate_band), the
 *    default `oracle_escalate_below_confidence` and the default
 *    `auto_ack_fp_threshold`. Under it the Oracle reviews the verdict and no
 *    false positive is acknowledged by itself. "Low".
 *  - Between them the verdict stands but the loop did not settle it. "Medium".
 */
export const CONFIDENCE_HIGH = 0.8;
export const CONFIDENCE_MEDIUM = 0.7;

export type ConfidenceWord = 'High' | 'Medium' | 'Low';

/** "High" at 0.80 and above, "Medium" from 0.70 to 0.79, "Low" under 0.70.
 *  The value is rounded to two decimals first, so the word agrees with the
 *  number printed beside it. */
export function confidenceWord(value: number): ConfidenceWord {
  const v = Math.round(value * 100) / 100;
  if (v >= CONFIDENCE_HIGH) return 'High';
  if (v >= CONFIDENCE_MEDIUM) return 'Medium';
  return 'Low';
}

/** The tone of a confidence word. Low is amber, because a low verdict goes to
 *  review. High is blue and never green, because green means a clean result. */
export function confidenceMeta(value: number): LabelMeta {
  const word = confidenceWord(value);
  return meta(word, word === 'High' ? 'info' : word === 'Medium' ? 'muted' : 'warn');
}
