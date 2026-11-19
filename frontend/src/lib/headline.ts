import { isKnownTool, toolNoun } from './toolLabels';
// ---------------------------------------------------------------------------
// The verdict headline in plain words.
//
// The headline is the sentence an analyst reads first. On the range it held
// field paths "(alert.rule_metadata.metadata_tags,
// community_id_events.1.payload_printable)" and tool ids "per
// t_rule_prevalence" (dogfood 2026-10-06, investigation C1). The paths move
// to the cited evidence chips. A tool id reads as what the tool is.
// ---------------------------------------------------------------------------

/** The roots of the alert and event fields a report cites. */
const FIELD_ROOTS = new Set([
  'alert',
  'event',
  'source',
  'destination',
  'network',
  'process',
  'host',
  'user',
  'file',
  'dns',
  'http',
  'tls',
  'ssl',
  'zeek',
  'suricata',
  'winlog',
  'rule',
  'message',
  'observer',
  'community_id_events',
  'payload',
]);

/** One dotted field path, such as `alert.rule_metadata.metadata_tags`. A
 *  domain such as `example.com` is not one: a path has an underscore, an
 *  index or a known root. */
export function isFieldPath(token: string): boolean {
  const t = token.trim();
  if (!/^[A-Za-z_][\w]*(\.[\w]+)+$/.test(t)) return false;
  const root = t.split('.')[0];
  return t.includes('_') || /\.\d+(\.|$)/.test(t) || FIELD_ROOTS.has(root);
}

/** The words for a tool a headline names: "the event search". They come from
 *  the one label map of the tools (lib/toolLabels, AB5). A tool the map does
 *  not hold reads as "the <name> check". */
export function toolWords(id: string): string {
  return isKnownTool(id) ? `the ${toolNoun(id)}` : `the ${id.replace(/^t_/, '').replace(/_/g, ' ')} check`;
}

// A tool id in prose, with the citation form around it: "t_beacon_profile",
// "tool t_web_search:result.results" or "t_prevalence:result.is_novel". The
// word "tool" and the result path are mechanics, and the words of the tool
// replace all of it (dogfood 2026-11-17, F20 and N9).
const TOOL_REF = /(?:\btool\s+)?\b(t_[a-z][a-z0-9_]*)(?::[A-Za-z0-9_.=\[\]]+)?/g;

/** One part of a text: plain text, or the words of a tool with the text that
 *  the model wrote for it. */
export interface ToolSegment {
  text: string;
  /** The text that the model wrote, for the tooltip. Absent on plain text. */
  tool?: string;
}

/** A text split at each tool id it names. The console renders the words of
 *  the tool, and the tooltip keeps what the model wrote. A tool id at the
 *  start of a sentence reads with a capital: "The beacon profile flagged". */
export function toolSegments(text: string): ToolSegment[] {
  const out: ToolSegment[] = [];
  let last = 0;
  for (const m of text.matchAll(TOOL_REF)) {
    const at = m.index ?? 0;
    if (at > last) out.push({ text: text.slice(last, at) });
    const before = text.slice(0, at);
    const words = toolWords(m[1]);
    const start = /(^|[.!?]\s+)$/.test(before);
    out.push({ text: start ? words.charAt(0).toUpperCase() + words.slice(1) : words, tool: m[0] });
    last = at + m[0].length;
  }
  if (last < text.length) out.push({ text: text.slice(last) });
  return out;
}

/** The stored verdict keys, as the console words them. */
const VERDICT_WORDS: Record<string, string> = {
  true_positive: 'true positive',
  false_positive: 'false positive',
  needs_more_info: 'needs more info',
};

/** A text with its tool ids and stored verdict keys in words. A headline
 *  read "a prior true_positive stands on this same session", and a finding
 *  read "Evidence: t_rule_prevalence ..." (review 2026-11-12, console
 *  finding 15). */
export function plainText(text: string, opts: { tools?: boolean } = {}): string {
  const tools = opts.tools ?? true;
  const worded = tools ? toolSegments(text).map((seg) => seg.text).join('') : text;
  return (
    worded
      .replace(/\b(true_positive|false_positive|needs_more_info)\b/g, (key) => VERDICT_WORDS[key])
      // The machine words of a run that the model copied into its text: the
      // tag of an older Oracle answer, "the local <verdict> verdict" and the
      // status code of the host-name check (dogfood 2026-11-17, N9).
      .replace(/^\s*\[oracle adjudicated\]\s*/i, '')
      .replace(/\blocal (true positive|false positive|needs more info) verdict\b/gi, 'soc-ai $1 verdict')
      .replace(/\bskipped_field_absent\b/g, 'no host name on the alert')
  );
}

// The first sentence of a text: up to the first full stop, question mark or
// exclamation mark that ends a word. A dotted address or a field path holds
// no stop of that kind, so it stays inside its sentence.
const SENTENCE_END = /[.!?](?=\s|$)/g;
// The abbreviations whose full stop does not end a sentence. A headline was
// cut at "e.g." and at "vs." (review 2026-11-13, post wave 2).
const ABBREVIATION = /(?:^|[\s([])(?:e\.g|i\.e|vs|etc|cf|approx)$/i;
// "No." ends no sentence when a number follows it: "No. 4".
const NUMBER_SIGN = /(?:^|[\s([])no$/i;

function collapse(s: string): string {
  return s.replace(/\s+/g, ' ').trim();
}

function endsSentence(text: string, index: number): boolean {
  if (text[index] !== '.') return true;
  const before = text.slice(0, index);
  if (ABBREVIATION.test(before)) return false;
  return !(NUMBER_SIGN.test(before) && /^\s*\d/.test(text.slice(index + 1)));
}

function firstOf(text: string): { first: string; rest: string } {
  for (const m of text.matchAll(SENTENCE_END)) {
    if (!endsSentence(text, m.index)) continue;
    return { first: text.slice(0, m.index + 1).trim(), rest: text.slice(m.index + 1).trim() };
  }
  return { first: text, rest: '' };
}

/**
 * The headline of a run, and the body text under it.
 *
 * The headline is one sentence. A run whose stored headline was missing or
 * held the whole summary printed the summary in the headline type and then
 * a second time as the body (review 2026-11-13, post wave 1). The headline
 * is the stored headline when it is one sentence that is not the summary,
 * else the first sentence of the summary. The body is the summary without
 * a leading copy of the headline, so the page never prints the headline
 * twice.
 */
export function splitHeadline(
  stored: string | null | undefined,
  summary: string | null | undefined,
): { headline: string; body: string } {
  const head = collapse(stored ?? '');
  const sum = collapse(summary ?? '');
  const source = head && head !== sum ? head : sum;
  const { first, rest } = firstOf(source);
  if (!sum) return { headline: first, body: source === head ? rest : '' };
  return { headline: first, body: bodyAfter(sum, first) };
}

/** The summary without a leading copy of the headline.
 *
 *  A stored headline with no full stop left the stop of the summary behind,
 *  and the body read ". At 2026-10-31T20:15:42Z blue ran" (dogfood
 *  2026-11-17, AB5). The copy counts only when a sentence end or a space
 *  follows it: a headline that stops inside the first sentence of the
 *  summary leaves the whole summary as the body. */
function bodyAfter(sum: string, first: string): string {
  if (!first || !sum.startsWith(first)) return sum;
  const after = sum.slice(first.length);
  if (after === '') return '';
  const stop = after.match(/^[.!?]+(?=\s|$)/);
  if (stop) return after.slice(stop[0].length).trim();
  return /^\s/.test(after) ? after.trim() : sum;
}

/** The headline with its field paths and tool ids out. `paths` holds the
 *  paths it took out, for the cited evidence chips. */
export function plainHeadline(text: string): { text: string; paths: string[] } {
  const paths: string[] = [];
  let out = text.replace(/\s*\(([^()]*)\)/g, (whole, inner: string) => {
    const items = inner.split(/[,;]\s*|\s+and\s+/).map((x) => x.trim()).filter(Boolean);
    if (items.length > 0 && items.every(isFieldPath)) {
      paths.push(...items);
      return '';
    }
    return whole;
  });
  out = plainText(out);
  return { text: out.replace(/\s+([.,;:])/g, '$1').trim(), paths };
}
