// ---------------------------------------------------------------------------
// The words an observation wears on screen.
//
// Four screens rendered an observation and each carried its own copy of the
// vocabulary. The copies drifted. One observation then had three names, and an
// analyst reading a lead beside a host page saw two products.
// ---------------------------------------------------------------------------

/** One label per observation kind. Every screen reads this and nothing else.
 *  Three screens held a copy and the copies drifted: one kind read "analytic
 *  matched" on a lead, "catalog match" on the lead page and "finding" on the
 *  host page. */
export const KIND_LABEL: Record<string, string> = {
  novel_destination: 'new destination',
  novel_served_port: 'new served port',
  novel_consumed_port: 'new outbound port',
  novel_process: 'new process',
  novel_process_pair: 'new process pair',
  novel_binding: 'first logon here',
  rare_for_peers: 'rare for peers',
  off_hours: 'off hours',
  below_baseline: 'rate collapsed',
  above_baseline: 'rate spiked',
  scope_count: 'across many hosts',
  alert: 'alert',
  prior_no_baseline: 'finding with no benign baseline',
  catalog_match: 'analytic match',
  hunt_finding: 'hunt finding',
};

/** The label for one kind. A label the API sends wins, because the server
 *  knows the analytic that wrote the row. An unknown kind reads as its own
 *  word, so a kind a newer backend adds is never blank. */
export function kindLabel(kind: string, apiLabel?: string | null): string {
  if (apiLabel) return apiLabel;
  return KIND_LABEL[kind] ?? kind.replace(/_/g, ' ');
}

/** The source words the API writes. `candidate` is a status and never a
 *  source. An analytic in candidate runs nothing and writes nothing, so a row
 *  that carries the word came from the catalog. */
const SOURCE_LABEL: Record<string, string> = {
  profile: 'profile',
  catalog: 'catalog',
  candidate: 'catalog',
  alert: 'alert',
  hunt: 'hunt',
};

/** The one word the source chip carries. A shadow observation reads "shadow",
 *  because that is the fact an analyst acts on first. */
export function sourceLabel(source: string, shadow = false): string {
  if (shadow) return 'shadow';
  return SOURCE_LABEL[source] ?? source;
}

const SOURCE_TITLE: Record<string, string> = {
  profile:
    'A behavioural profile of this entity produced this observation. The profile sweep wrote it.',
  catalog: 'A query analytic matched this entity. The catalog sweep wrote it.',
  alert:
    'A triage verdict on an alert produced this observation. A false positive is not recorded.',
  hunt: 'An analyst promoted a hunt finding on this entity.',
};

/** What the source chip means. A shadow chip names the source it came from,
 *  because the chip itself no longer can. */
export function sourceTitle(source: string, shadow = false): string {
  const word = SOURCE_LABEL[source] ?? source;
  if (shadow) return `An analytic in shadow wrote this ${word} observation. It raises nothing.`;
  return SOURCE_TITLE[word] ?? `The ${word} source wrote this observation.`;
}
