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
  out = out.replace(/\bt_[a-z][a-z0-9_]*\b/g, (id) => toolWords(id));
  return { text: out.replace(/\s+([.,;:])/g, '$1').trim(), paths };
}
