// The Event timeline section (change D).
//
// The step timelines list what the pipeline did, in tool-call order. This
// section lists what happened on the network, in event time: the documents
// the run cites, oldest first, grouped into waves. A new wave starts after a
// gap longer than the gap the server names. Every time is UTC, and the section
// says so, because the documents and the queries the server writes are UTC.
//
// The server builds the list from the documents the run already stores, so
// the page makes no grid query. No time is sliced from an ISO string here:
// every time goes through the one formatter in lib/timeRange.ts.
import { formatDuration, utcStamp, utcWindow } from '../lib/timeRange';
import { EVENT_CITED, eventFindingTitle } from '../lib/tooltips';
import type { EventTimeline, EventTimelineEntry, EventTimelineWave } from '../lib/types';
import { DocumentChip } from './DocumentDrawer';
import { Panel } from './Panel';

const CHIP_CLASS =
  'rounded-chip border border-border-strong bg-surface-2 px-1.5 py-px text-[10.5px] text-text-2';

function count(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

function seconds(fromIso: string, toIso: string): number | null {
  const a = new Date(fromIso).getTime();
  const b = new Date(toIso).getTime();
  return Number.isNaN(a) || Number.isNaN(b) ? null : (b - a) / 1000;
}

/** The meta of the section header: "5 documents · 2 waves · UTC". */
export function eventTimelineMeta(timeline: EventTimeline): string {
  return `${count(timeline.entries.length, 'document', 'documents')} · ${count(
    timeline.waves.length,
    'wave',
    'waves',
  )} · UTC`;
}

function intro(timeline: EventTimeline): string {
  const what =
    timeline.basis === 'hunt'
      ? 'This list shows the documents that the findings cite, in the order of their event time.'
      : timeline.basis === 'finding'
        ? 'This list shows the documents that the finding cites and the documents that the verdict cites, in the order of their event time.'
        : timeline.basis === 'hunt_subject'
          ? 'This list shows the documents that soc-ai loaded for this investigation and the documents that the verdict cites, in the order of their event time.'
          : 'This list shows the alert and the documents that the verdict cites, in the order of their event time.';
  return (
    `${what} The times are UTC. A new wave starts after a gap of more than ` +
    `${timeline.gapMinutes} minutes between two documents on this list. ` +
    'A wave groups documents by time only.'
  );
}

function ends(source?: string | null, destination?: string | null, host?: string | null): string | null {
  if (source && destination) return `${source} → ${destination}`;
  if (source) return `from ${source}`;
  if (destination) return `to ${destination}`;
  if (host) return `on ${host}`;
  return null;
}

function waveLine(wave: EventTimelineWave): string {
  const parts = [
    utcWindow(wave.start, wave.end, { seconds: true }),
    count(wave.documents, 'document', 'documents'),
  ];
  const flow = ends(wave.sources.join(', '), wave.destinations.join(', '));
  if (flow) parts.push(flow);
  return parts.join(' · ');
}

function EntryRow({ entry, markCited }: { entry: EventTimelineEntry; markCited: boolean }) {
  const lasted = entry.end ? seconds(entry.at, entry.end) : null;
  const flow = ends(entry.source, entry.destination, entry.host);
  return (
    <li data-testid="event-row" className="px-[15px] py-2 text-[12.5px]">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <span className="font-mono text-[11.5px] text-text-2">{utcStamp(entry.at, { seconds: true })}</span>
        {entry.dataset && <span className="font-mono text-[11.5px] text-dim">{entry.dataset}</span>}
        {flow && <span className="font-mono text-[11.5px] text-dim">{flow}</span>}
        {lasted != null && lasted > 0 && <span className="text-[11.5px] text-dim">{`lasted ${formatDuration(lasted)}`}</span>}
        {markCited && entry.cited && (
          <span className={CHIP_CLASS} title={EVENT_CITED}>
            cited
          </span>
        )}
        {entry.findings.map((ordinal) => (
          <span key={ordinal} className={CHIP_CLASS} title={eventFindingTitle(ordinal + 1)}>
            {`F${ordinal + 1}`}
          </span>
        ))}
        <DocumentChip id={entry.id} className="rounded-chip border border-border-strong bg-surface-2 px-1.5 py-px font-mono text-[10.5px] text-accent hover:bg-surface-3" />
      </div>
      {entry.label && (
        // The label is attacker-written text, shown whole. React escapes it.
        <div className="mt-0.5 whitespace-pre-wrap break-words text-text">{entry.label}</div>
      )}
    </li>
  );
}

/** The Event timeline of an investigation or a hunt. */
export function EventTimelinePanel({ timeline }: { timeline: EventTimeline }) {
  // The cited chip marks a row only when some rows are not cited: on a list
  // where every row is cited, the chip says nothing.
  const markCited = timeline.entries.some((e) => !e.cited);
  const byWave = new Map<number, EventTimelineEntry[]>();
  for (const e of timeline.entries) byWave.set(e.wave, [...(byWave.get(e.wave) ?? []), e]);
  return (
    <Panel>
      <p className="px-[15px] pt-3 text-[12.5px] text-dim">{intro(timeline)}</p>
      {timeline.waves.map((wave, i) => {
        const previous = i > 0 ? timeline.waves[i - 1] : null;
        const gap = previous ? seconds(previous.end, wave.start) : null;
        return (
          <section key={wave.n} data-testid="event-wave" className="pt-2.5">
            {previous && gap != null && (
              <p className="px-[15px] pb-1.5 text-[12px] italic text-faint">
                {`This wave starts ${formatDuration(gap)} after wave ${previous.n} ends.`}
              </p>
            )}
            <div className="flex flex-wrap items-baseline gap-x-2 border-t border-border px-[15px] pt-2">
              <span className="text-[12.5px] font-semibold text-text">{`Wave ${wave.n}`}</span>
              <span className="font-mono text-[11.5px] text-dim">{waveLine(wave)}</span>
            </div>
            <ul>
              {(byWave.get(wave.n) ?? []).map((e) => (
                <EntryRow key={e.id} entry={e} markCited={markCited} />
              ))}
            </ul>
          </section>
        );
      })}
      {(timeline.untimed > 0 || timeline.omitted > 0) && (
        <div className="border-t border-border px-[15px] py-2.5 text-[12px] text-dim">
          {timeline.untimed > 0 && (
            <p>
              {timeline.untimed === 1
                ? 'soc-ai holds no event time for 1 cited document. It is not on this list.'
                : `soc-ai holds no event time for ${timeline.untimed} cited documents. They are not on this list.`}
            </p>
          )}
          {timeline.omitted > 0 && (
            <p>
              {timeline.omitted === 1
                ? `This list stops at ${timeline.entries.length} documents. 1 later document is not on it.`
                : `This list stops at ${timeline.entries.length} documents. ${timeline.omitted} later documents are not on it.`}
            </p>
          )}
        </div>
      )}
    </Panel>
  );
}
