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

/** The words for the tools a headline names. */
const TOOL_WORDS: Record<string, string> = {
  t_rule_prevalence: 'the rule history',
  t_host_dossier: 'the host record',
  t_prevalence: 'the prevalence check',
  t_enrich_ip: 'the address look-up',
  t_search_events: 'the event search',
  t_origin_chain: 'the origin chain',
  t_suggest_rule_tuning: 'the rule tuning check',
  t_query_zeek_logs: 'the Zeek logs',
  t_query_events_oql: 'the event search',
};

export function toolWords(id: string): string {
  return TOOL_WORDS[id] ?? `the ${id.replace(/^t_/, '').replace(/_/g, ' ')} check`;
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
export function plainText(text: string): string {
  return text
    .replace(/\bt_[a-z][a-z0-9_]*\b/g, (id) => toolWords(id))
    .replace(/\b(true_positive|false_positive|needs_more_info)\b/g, (key) => VERDICT_WORDS[key]);
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
  const body = sum.startsWith(first) ? sum.slice(first.length).trim() : sum;
  return { headline: first, body };
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
