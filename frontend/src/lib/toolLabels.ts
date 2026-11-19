import { utcTimesInText } from './timeRange';
// ---------------------------------------------------------------------------
// The one label map of the agent tools, for the analyst.
//
// A model cites a tool call as evidence: "t_origin_chain(10.99.0.40)" or
// "t_query_events_oql BPFDoor groupby". The chips printed the tool name, and
// three surfaces kept three maps of tool words (dogfood 2026-11-17, AB5). A
// chip now shows the words of this map and keeps the tool name in its
// tooltip. The headline words of the investigation page read the same map.
// ---------------------------------------------------------------------------

/** The noun of each tool, by its name without the `t_` prefix. */
export const TOOL_LABELS: Record<string, string> = {
  origin_chain: 'Origin chain',
  decode_payload: 'Decoded payload',
  host_dossier: 'Host record',
  host_summary: 'Host summary',
  query_events_oql: 'Event search',
  search_events: 'Event search',
  query_zeek_logs: 'Zeek logs',
  get_event_raw: 'Document',
  get_alert_context: 'Alert context',
  get_rule_content: 'Rule text',
  prevalence: 'Prevalence check',
  rule_prevalence: 'Rule history',
  first_seen: 'First sighting',
  beacon_profile: 'Beacon profile',
  dns_entropy_scan: 'DNS entropy scan',
  run_analytic: 'Analytic run',
  describe_dataset: 'Dataset description',
  enrich_ip: 'Address look-up',
  enrich_domain: 'Domain look-up',
  enrich_hash: 'File-hash look-up',
  suggest_rule_tuning: 'Rule tuning check',
  query_cases: 'Case search',
  get_playbooks: 'Playbooks',
  lookup_runbook: 'Runbook',
  web_search: 'Web search',
  crawl_page: 'Web page read',
  cve_lookup: 'CVE look-up',
  dcerpc_histogram: 'DCE-RPC histogram',
  field_values: 'Field values',
  get_pcap: 'Packet capture',
  greynoise: 'GreyNoise look-up',
  query_detections: 'Detection search',
  shodan_host: 'Shodan look-up',
  shodan_internetdb: 'Shodan look-up',
};

/** A noun that keeps its capital inside a sentence. */
const PROPER = /^(Zeek|DNS|CVE|DCE-RPC|GreyNoise|Shodan)\b/;

/** The noun of a tool: from the map, else its name in words. */
export function toolLabel(name: string): string {
  const key = name.replace(/^t_/, '').toLowerCase();
  return TOOL_LABELS[key] ?? key.replace(/_/g, ' ').replace(/^./, (ch) => ch.toUpperCase());
}

/** The noun of a tool inside a sentence: "the event search", "the Zeek logs". */
export function toolNoun(name: string): string {
  const label = toolLabel(name);
  return PROPER.test(label) ? label : label.replace(/^./, (ch) => ch.toLowerCase());
}

/** True when the map holds the tool. */
export function isKnownTool(name: string): boolean {
  return name.replace(/^t_/, '').toLowerCase() in TOOL_LABELS;
}

const CALL_FORM = /^t_([a-z][a-z0-9_]*)\s*\((.*)\)\s*$/i;
const SPACE_FORM = /^t_([a-z][a-z0-9_]*)\s+(\S.*)$/;
const BARE_FORM = /^t_([a-z][a-z0-9_]*)$/;

/**
 * A tool citation in words, or null for a document id.
 *
 * "t_origin_chain(10.99.0.40)" reads "Origin chain of 10.99.0.40".
 * "t_query_events_oql BPFDoor groupby" reads "Event search: BPFDoor groupby".
 * A bare "t_first_seen" reads "First sighting" when the map holds the tool. A
 * document id holds no space and no parenthesis, so an id that starts with
 * "t_" stays an id unless the map names it.
 */
export function citationWords(citation: string): string | null {
  // A time in the citation reads in the UTC form of the page (F15).
  const words = toolCitationWords(citation);
  return words === null ? null : utcTimesInText(words);
}

function toolCitationWords(citation: string): string | null {
  const text = citation.trim();
  const call = text.match(CALL_FORM);
  if (call) {
    const args = call[2]
      .split(',')
      .map((a) => a.replace(/^\s*[a-z_]+\s*=\s*/i, '').replace(/^["']|["']$/g, '').trim())
      .filter(Boolean);
    const noun = toolLabel(call[1]);
    return args.length ? `${noun} of ${args.join(', ')}` : noun;
  }
  const spaced = text.match(SPACE_FORM);
  if (spaced) return `${toolLabel(spaced[1])}: ${spaced[2].trim()}`;
  const bare = text.match(BARE_FORM);
  if (bare && isKnownTool(bare[1])) return toolLabel(bare[1]);
  return null;
}
