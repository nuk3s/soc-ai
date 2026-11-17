import { toolWords } from './headline';

// ---------------------------------------------------------------------------
// A cited field of an investigation report, in words.
//
// The cited evidence chips printed the raw path the model wrote:
// "alert.payload_printable", "community_id_events.0.zeek_http_status". A chip
// was a span that did nothing, and the payload that made the verdict was not
// on the page (review 2026-11-12, console finding 6). A chip now names the
// field in words, with its value when the value is short, and it opens the
// grid document that holds the field. The raw path stays in the tooltip.
// ---------------------------------------------------------------------------

/** The words for the leaf of a field path the model cites. */
const FIELD_WORDS: Record<string, string> = {
  payload_printable: 'Payload',
  payload: 'Payload',
  message: 'Message',
  rule_name: 'Rule name',
  signature_severity: 'Signature severity',
  metadata_tags: 'Rule tags',
  severity_label: 'Severity',
  alert_action: 'Alert action',
  event_action: 'Event action',
  classtype: 'Rule class',
  source_ip: 'Source address',
  source_port: 'Source port',
  destination_ip: 'Destination address',
  destination_port: 'Destination port',
  host_name: 'Host name',
  user_name: 'User name',
  dns_query: 'DNS query',
  dns_rcode_name: 'DNS answer code',
  zeek_conn_state: 'Connection state',
  zeek_conn_duration: 'Connection duration',
  zeek_conn_history: 'Connection history',
  zeek_conn_orig_bytes: 'Bytes sent',
  zeek_conn_resp_bytes: 'Bytes received',
  zeek_conn_service: 'Service',
  zeek_dns_query: 'DNS query',
  zeek_dns_rcode_name: 'DNS answer code',
  zeek_dns_qtype: 'DNS query type',
  zeek_ssl_server_name: 'TLS server name',
  zeek_ssl_ja3: 'JA3',
  zeek_ssl_ja3s: 'JA3S',
  zeek_ssl_established: 'TLS established',
  zeek_http_method: 'HTTP method',
  zeek_http_host: 'HTTP host',
  zeek_http_uri: 'HTTP URI',
  zeek_http_status: 'HTTP status',
  zeek_http_user_agent: 'User agent',
  zeek_files_mime_type: 'File type',
  zeek_files_sha256: 'File SHA-256',
  zeek_files_md5: 'File MD5',
  file_hash_sha256: 'File SHA-256',
  as_source: 'Alerts as source',
  as_destination: 'Alerts as destination',
  planes: 'Coverage planes',
};

/** The leaf of a path that names something. An index names nothing. */
function leafOf(path: string): string {
  const parts = path.split('.').filter((p) => p !== '' && !/^\d+$/.test(p));
  return parts[parts.length - 1] ?? path;
}

/** The words for a field path: "community_id_events.0.zeek_http_status"
 *  reads "HTTP status". A leaf with no entry reads as its words. */
export function fieldWords(path: string): string {
  const leaf = leafOf(path);
  const known = FIELD_WORDS[leaf];
  if (known) return known;
  const words = leaf.replace(/^zeek_/, '').replace(/_/g, ' ').trim();
  return words ? words.charAt(0).toUpperCase() + words.slice(1) : path;
}

/** A value short enough to sit on a chip: one line, at most 32 characters. */
const SHORT_VALUE = 32;

/** The chip label: the words, and the value when it is short. */
export function fieldChipLabel(path: string, value: string | null | undefined): string {
  const words = fieldWords(path);
  const v = (value ?? '').trim();
  if (!v || v.length > SHORT_VALUE || /[\r\n]/.test(v) || v.startsWith('{') || v.startsWith('[')) {
    return words;
  }
  return `${words} ${v}`;
}

/** Which document of the run a path names, in words. */
export function fieldDocumentWords(path: string): string {
  const parts = path.split('.');
  if (parts[0] === 'alert') return 'the alert';
  if (parts.length > 1 && /^\d+$/.test(parts[1])) {
    const n = Number(parts[1]) + 1;
    if (parts[0] === 'community_id_events') return `session event ${n}`;
    return `document ${n} of ${parts[0].replace(/_/g, ' ')}`;
  }
  return 'the context of the investigation';
}

/** The tooltip of a field chip. It keeps the raw path. */
export function fieldChipTitle(
  path: string,
  opts: { documentId?: string | null; value?: string | null; resolved?: boolean | null },
): string {
  const raw = `Field ${path}.`;
  if (opts.resolved === false) {
    return `${raw} The validator did not resolve this citation. The investigation retrieved nothing that it names.`;
  }
  if (opts.documentId) return `${raw} Open ${fieldDocumentWords(path)} at this field.`;
  if (opts.value != null && opts.value !== '') {
    return `${raw} soc-ai read this value from the context of the investigation. No grid document holds it.`;
  }
  return `${raw} soc-ai cannot find this field in a stored document, so the chip opens nothing.`;
}

/** One citation of a hunt finding, as the page shows it. */
export type FindingCitation =
  | { kind: 'document'; id: string }
  | { kind: 'text'; label: string; title: string };

/**
 * A citation of a hunt finding. A finding cites grid documents by id, and it
 * also cites tool results and queries in the words of the model:
 * "t_rule_prevalence ET CINS ... group 148", "t_enrich_ip 10.20.30.5". The
 * page showed each one as a document chip, which printed the tool name and
 * opened a drawer that found no document (review 2026-11-12, console
 * finding 15). A tool result reads in words, and a query or a flow id is a
 * plain chip that says why it opens nothing.
 */
export function findingCitation(raw: string): FindingCitation {
  const text = raw.trim();
  const tool = text.match(/^(t_[a-z0-9_]+)\b[:\s]*(.*)$/);
  if (tool) {
    const words = toolWords(tool[1]).replace(/^the /, '');
    const head = words.charAt(0).toUpperCase() + words.slice(1);
    return {
      kind: 'text',
      label: tool[2] ? `${head}: ${tool[2]}` : head,
      title: `A tool result that the finding cites. It names no single document. The finding wrote: ${text}`,
    };
  }
  if (/^\d+:[A-Za-z0-9+/]+=*$/.test(text)) {
    return {
      kind: 'text',
      label: `Flow ${text}`,
      title: 'A community id. It names a flow, and no single document.',
    };
  }
  if (/\s/.test(text)) {
    return {
      kind: 'text',
      label: text,
      title: 'A query result that the finding cites. It names no single document.',
    };
  }
  return { kind: 'document', id: text };
}
