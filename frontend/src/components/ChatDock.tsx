import { Send, Wrench } from 'lucide-react';
import { type ReactNode, useEffect, useRef } from 'react';
import { DocumentChip } from './DocumentDrawer';
import { Markdown } from './Markdown';
import { linkifyChatAnswer } from '../lib/chatLinks';
import { findEventIds } from '../lib/eventIds';

// ---------------------------------------------------------------------------
// Shared chat rendering. The console has one chat, the Ask soc-ai panel
// (AskPanel.tsx), and every scope renders its thread through ChatThreadView
// below. The THREAD state (loading, polling while the assistant works,
// posting a turn) lives in useChatThread.
// ---------------------------------------------------------------------------

/** The message shape the shared renderer needs; screens may carry richer types. */
export interface ChatDockMessage {
  role: 'user' | 'assistant';
  text?: string | null;
  tools?: string | null;
}

interface ChatThreadViewProps<M extends ChatDockMessage> {
  /** The accessible name of the message list. */
  label: string;
  placeholder: string;
  messages: M[];
  pending: boolean;
  /** Tools the in-flight turn has called so far (oldest first). */
  progressTools?: string[];
  draft: string;
  onDraft: (v: string) => void;
  onSend: () => void;
  /** Optional hint rendered when the thread is empty and idle. */
  emptyHint?: ReactNode;
  /**
   * Screen-specific message kinds (e.g. the investigation chat's verdict
   * proposals): return a node (carrying its own key) to replace the default
   * bubble for that message, or null to fall through to it.
   *
   * It replaces the WHOLE row, so a card that should appear ALONGSIDE the
   * agent's prose composes {@link AssistantBubble} itself rather than
   * re-implementing it. The hunt proposal rides on the same row as the
   * answer, and dropping that prose would throw away the half of the reply
   * the analyst judges the proposal by.
   */
  renderSpecial?: (m: M, i: number) => ReactNode | null;
  /** Document ids the scope already cites. An answer that names one, or any
   *  id with the Elasticsearch shape, lists it as a control that opens it. */
  linkIds?: string[];
  /** Move the focus into the input on mount. The panel opens with it. */
  autoFocus?: boolean;
  /** Render addresses, leads and investigation ids in answers as links. */
  linkEntities?: boolean;
  /** Why a send cannot work now. The send control is off while it is set. */
  blockedReason?: string | null;
  /** A state the answer depends on, said above the input. */
  stateNote?: string | null;
}

// Tool name -> what the analyst would call it, as a step in progress. Unknown
// tools fall back to "Running <name>" so a new tool still reads as a step.
// The panel showed "Host dossier" and "Field values" for two tools this map
// did not hold (dogfood 2026-10-19, R1-D23).
const TOOL_LABELS: Record<string, string> = {
  t_query_events_oql: 'Querying events',
  t_query_zeek_logs: 'Reading Zeek logs',
  t_describe_dataset: 'Reading the dataset fields',
  t_field_values: 'Reading field values',
  t_get_event_raw: 'Reading the raw event',
  t_run_analytic: 'Running an analytic',
  t_enrich_ip: 'Enriching IP',
  t_enrich_domain: 'Enriching domain',
  t_enrich_hash: 'Enriching hash',
  t_host_summary: 'Profiling host',
  t_host_dossier: 'Reading the dossier',
  t_origin_chain: 'Checking who used the host',
  t_prevalence: 'Checking prevalence',
  t_rule_prevalence: 'Checking rule prevalence',
  t_beacon_profile: 'Measuring the beacon cadence',
  t_dns_entropy_scan: 'Scanning DNS names',
  t_dcerpc_histogram: 'Counting DCE/RPC calls',
  t_first_seen: 'Checking the first sighting',
  t_suggest_rule_tuning: 'Checking the rule tuning',
  t_shodan_internetdb: 'Looking up the address on Shodan',
  t_shodan_host: 'Looking up the address on Shodan',
  t_greynoise: 'Looking up the address on GreyNoise',
  t_cve_lookup: 'Looking up the CVE',
  t_get_pcap: 'Fetching PCAP',
  t_decode_payload: 'Decoding payload',
  t_get_rule_content: 'Reading the rule',
  t_query_cases: 'Searching cases',
  t_query_detections: 'Searching detections',
  t_lookup_runbook: 'Consulting runbooks',
  t_get_playbooks: 'Reading the playbook',
  t_web_search: 'Searching the web',
  t_crawl_page: 'Reading a page',
  propose_verdict: 'Drafting a verdict',
  propose_hunt: 'Drafting a hunt',
  // The server's step when the time ran out and the model writes an answer
  // from the results so far (chat_turn.PARTIAL_ANSWER_STEP).
  partial_answer: 'Writing an answer from the results so far',
};

// Tool name -> the noun for one call and for several. The footer counts
// calls by tool. It printed the raw identifiers before, for example
// "t_query_events_oql, t_query_events_oql, ..." (fleet P11, 2026-10-01).
const TOOL_NOUNS: Record<string, [string, string]> = {
  t_query_events_oql: ['event query', 'event queries'],
  t_query_zeek_logs: ['Zeek log query', 'Zeek log queries'],
  t_describe_dataset: ['dataset read', 'dataset reads'],
  t_field_values: ['field value read', 'field value reads'],
  t_run_analytic: ['analytic run', 'analytic runs'],
  t_beacon_profile: ['beacon check', 'beacon checks'],
  t_dns_entropy_scan: ['DNS scan', 'DNS scans'],
  t_dcerpc_histogram: ['DCE/RPC count', 'DCE/RPC counts'],
  t_first_seen: ['first-sighting check', 'first-sighting checks'],
  t_suggest_rule_tuning: ['rule tuning check', 'rule tuning checks'],
  t_shodan_internetdb: ['Shodan lookup', 'Shodan lookups'],
  t_shodan_host: ['Shodan lookup', 'Shodan lookups'],
  t_greynoise: ['GreyNoise lookup', 'GreyNoise lookups'],
  t_cve_lookup: ['CVE lookup', 'CVE lookups'],
  propose_hunt: ['hunt draft', 'hunt drafts'],
  t_enrich_ip: ['IP lookup', 'IP lookups'],
  t_enrich_domain: ['domain lookup', 'domain lookups'],
  t_enrich_hash: ['hash lookup', 'hash lookups'],
  t_host_summary: ['host summary', 'host summaries'],
  t_host_dossier: ['dossier read', 'dossier reads'],
  t_origin_chain: ['origin check', 'origin checks'],
  t_prevalence: ['prevalence check', 'prevalence checks'],
  t_rule_prevalence: ['rule prevalence check', 'rule prevalence checks'],
  t_get_pcap: ['PCAP fetch', 'PCAP fetches'],
  t_decode_payload: ['payload decode', 'payload decodes'],
  t_get_rule_content: ['rule read', 'rule reads'],
  t_get_event_raw: ['raw event read', 'raw event reads'],
  t_query_cases: ['case search', 'case searches'],
  t_query_detections: ['detection search', 'detection searches'],
  t_lookup_runbook: ['runbook lookup', 'runbook lookups'],
  t_get_playbooks: ['playbook read', 'playbook reads'],
  t_web_search: ['web search', 'web searches'],
  t_crawl_page: ['page read', 'page reads'],
  propose_verdict: ['verdict draft', 'verdict drafts'],
};

/** "Tools used: 14 event queries, 2 IP lookups" from the stored tool list. */
export function toolsSummary(tools: string | null | undefined): string | null {
  const names = (tools ?? '')
    .split(',')
    .map((t) => t.trim())
    .filter(Boolean);
  if (names.length === 0) return null;
  const counts = new Map<string, number>();
  for (const n of names) counts.set(n, (counts.get(n) ?? 0) + 1);
  const parts = [...counts.entries()].map(([name, n]) => {
    const nouns = TOOL_NOUNS[name];
    const bare = name.replace(/^t_/, '').replace(/_/g, ' ');
    const [one, many] = nouns ?? [`${bare} call`, `${bare} calls`];
    return `${n} ${n === 1 ? one : many}`;
  });
  return `Tools used: ${parts.join(', ')}`;
}

export function toolLabel(name: string): string {
  return TOOL_LABELS[name] ?? `Running ${name.replace(/^t_/, '').replace(/_/g, ' ')}`;
}

/**
 * What the agent said: the markdown bubble plus the tools footer under it.
 *
 * Exported because a caller that decorates a row (a proposal card) still has to
 * render the prose, and a private copy is exactly how this project's chat
 * surfaces drift — the hunt chat forked its manager and missed every feature
 * shipped after. Emits a fragment, so the CALLER owns the row wrapper (width,
 * self-alignment, fade-in) and supplies the vertical rhythm as `gap-1.5`.
 *
 * Renders nothing for an empty turn rather than an empty bubble: a proposal row
 * whose agent proposed without prose should show the card alone.
 */
export function AssistantBubble({
  text,
  tools,
  linkIds,
  linkEntities = false,
}: {
  text?: string | null;
  tools?: string | null;
  linkIds?: string[];
  /** Render addresses, leads and investigation ids as links to their pages. */
  linkEntities?: boolean;
}) {
  const summary = toolsSummary(tools);
  // Ids only when the caller asked for them: the Dashboard chat has no scope
  // to cite, and its answers name datasets that can share the id shape.
  const ids = linkIds && text ? findEventIds(text, linkIds) : [];
  return (
    <>
      {text ? (
        <div
          className="overflow-hidden break-words rounded-[12px_12px_12px_3px] border border-border-2 bg-surface-3 px-[13px] py-2.5 text-[13px] leading-[1.55] text-text-2 [&_pre]:max-w-full [&_pre]:overflow-x-auto"
          style={{ textWrap: 'pretty' }}
        >
          {linkEntities ? <Markdown appLinks>{linkifyChatAnswer(text)}</Markdown> : <Markdown>{text}</Markdown>}
        </div>
      ) : null}
      {ids.length > 0 ? (
        <div className="flex flex-wrap items-center gap-1.5 text-[11px] text-faint">
          <span>Cited events:</span>
          {ids.map((id) => (
            <DocumentChip key={id} id={id} />
          ))}
        </div>
      ) : null}
      {summary ? (
        <div className="flex items-center gap-1.5 text-[11px] text-faint">
          <span className="text-accent">
            <Wrench size={11} />
          </span>
          {summary}
        </div>
      ) : null}
    </>
  );
}

/**
 * One thread: the scrolling bubble list (with autoscroll and a fade-in on
 * messages that arrive after mount), the typing indicator and the input row.
 * It fills its parent. The panel owns the header.
 */
export function ChatThreadView<M extends ChatDockMessage>({
  label,
  placeholder,
  messages,
  pending,
  progressTools,
  draft,
  onDraft,
  onSend,
  emptyHint,
  renderSpecial,
  linkIds,
  autoFocus,
  linkEntities = false,
  blockedReason = null,
  stateNote = null,
}: ChatThreadViewProps<M>) {
  const blocked = !!blockedReason;
  const listRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const didMountRef = useRef(false);
  // Tracks the highest message index seen at mount-time so subsequent new
  // messages (added while the panel is open) can receive a fade-in.
  const seedLengthRef = useRef(-1);

  // autoscroll on new messages / typing indicator (skip the initial mount)
  useEffect(() => {
    if (!didMountRef.current) {
      didMountRef.current = true;
      seedLengthRef.current = messages.length;
      return;
    }
    const el = listRef.current;
    if (el) el.scrollTo({ top: el.scrollHeight, behavior: 'smooth' });
  }, [messages.length, pending]);

  useEffect(() => {
    if (autoFocus) inputRef.current?.focus();
  }, [autoFocus]);

  // Grow the draft box with its content (up to a cap) so a long question stays
  // fully visible instead of scrolling off a single line.
  useEffect(() => {
    const el = inputRef.current;
    if (!el) return;
    el.style.height = 'auto';
    el.style.height = `${Math.min(el.scrollHeight, 120)}px`;
  }, [draft]);

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      {/* role="log" makes the list a polite live region: a screen reader
          announces each new answer without moving focus (fleet P13). */}
      <div
        ref={listRef}
        role="log"
        aria-live="polite"
        aria-label={label}
        className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto p-[15px]"
      >
        {emptyHint != null && messages.length === 0 && !pending && emptyHint}
        {messages.map((m, i) => {
          // Messages that arrived after the panel mounted get a subtle fade-in.
          // History / seed messages (present at mount) render immediately.
          const isNew = i >= seedLengthRef.current;

          const special = renderSpecial?.(m, i);
          if (special != null) return special;

          return m.role === 'user' ? (
            <div
              key={i}
              className="max-w-[82%] min-w-0 self-end break-words rounded-[12px_12px_3px_12px] border border-accent-deep bg-[#1d3a6b] px-[13px] py-[9px] text-[13px] leading-[1.5]"
            >
              {m.text}
            </div>
          ) : (
            <div
              key={i}
              className={`flex min-w-0 max-w-[88%] flex-col gap-1.5 self-start${isNew ? ' animate-fadeUp' : ''}`}
            >
              <AssistantBubble text={m.text} tools={m.tools} linkIds={linkIds} linkEntities={linkEntities} />
            </div>
          );
        })}
        {pending && (
          <div className="flex flex-col items-start gap-1 self-start">
            <div className="flex items-center gap-1 rounded-[12px_12px_12px_3px] border border-border-2 bg-surface-3 px-3.5 py-[11px]">
              <span className="h-1.5 w-1.5 animate-blink rounded-full bg-faint" />
              <span className="h-1.5 w-1.5 animate-blink rounded-full bg-faint" style={{ animationDelay: '.2s' }} />
              <span className="h-1.5 w-1.5 animate-blink rounded-full bg-faint" style={{ animationDelay: '.4s' }} />
            </div>
            {/* What the agent is actually DOING. A long multi-tool turn used to
                look identical to a hung one (dogfood 2026-08-06). */}
            {progressTools != null && progressTools.length > 0 && (
              <span className="pl-1 text-[11px] text-faint">
                {toolLabel(progressTools[progressTools.length - 1])}
                {progressTools.length > 1 && ` · ${progressTools.length} steps`}
              </span>
            )}
          </div>
        )}
      </div>
      {(blockedReason || stateNote) && (
        <div
          data-testid="chat-state"
          role="status"
          className={`flex-none border-t border-border px-[13px] pt-2 text-[11.5px] leading-[1.45] ${blocked ? 'text-warn' : 'text-faint'}`}
        >
          {blockedReason ?? stateNote}
          {blockedReason && stateNote ? ` ${stateNote}` : ''}
        </div>
      )}
      <div
        className={`flex items-end gap-[9px] px-[13px] py-[11px]${blockedReason || stateNote ? '' : ' border-t border-border'}`}
      >
        <textarea
          ref={inputRef}
          rows={1}
          aria-label="Your question"
          value={draft}
          onChange={(e) => onDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault();
              if (!blocked) onSend();
            }
          }}
          placeholder={placeholder}
          className="max-h-[120px] flex-1 resize-none overflow-y-auto rounded-control border border-border-input bg-bg px-3 py-[9px] text-[13px] leading-[1.45] text-text outline-none focus:border-accent"
        />
        <button
          onClick={onSend}
          aria-label="Send"
          disabled={blocked}
          title={blockedReason ?? undefined}
          className="flex h-9 w-[38px] flex-none items-center justify-center rounded-control bg-accent text-white hover:bg-accent-deep disabled:cursor-not-allowed disabled:opacity-50 disabled:hover:bg-accent"
        >
          <Send size={16} />
        </button>
      </div>
    </div>
  );
}
