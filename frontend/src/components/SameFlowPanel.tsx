import { AlertTriangle, ArrowUpRight, Link2, ListTree } from 'lucide-react';
import { Link } from 'react-router-dom';

import { getInvestigationSiblings } from '../lib/api';
import { plural } from '../lib/plural';
import type { AlertSibling, Verdict } from '../lib/types';
import { useAsync } from '../lib/useAsync';
import { VerdictPill } from './Badges';
import { Panel } from './Panel';
import { PARTIAL_NOTE, oppositeVerdictSentence, shareSentence, signalWords } from './SameFlowChip';

const MINUTE_MS = 60_000;

/** A datetime-local value in the browser zone, the shape the Alerts custom
 *  window reads: "2026-10-01T11:37". */
function localInput(ms: number): string {
  const d = new Date(ms);
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}

/**
 * The Alerts list on the row of one sibling: the window of the read, with
 * acknowledged alerts in, and `show` naming the row to open.
 *
 * The read covers an hour either side of the alert, so each sibling has an
 * alert in that window. The bounds round outward to the minute, the step of
 * the custom window. An older server sends no window, and the 30 day list is
 * then the widest the page reads.
 */
export function siblingRowHref(s: AlertSibling, windowFrom: string | null | undefined, windowTo: string | null | undefined): string {
  const p = new URLSearchParams();
  const lo = windowFrom ? Date.parse(windowFrom) : NaN;
  const hi = windowTo ? Date.parse(windowTo) : NaN;
  if (Number.isFinite(lo) && Number.isFinite(hi)) {
    p.set('range', 'custom');
    p.set('from', localInput(Math.floor(lo / MINUTE_MS) * MINUTE_MS));
    p.set('to', localInput(Math.ceil(hi / MINUTE_MS) * MINUTE_MS));
  } else {
    p.set('range', '30d');
  }
  p.set('hide_acked', 'false');
  p.set('show', `${s.kind}:${s.name}`);
  return `/alerts?${p}`;
}

/**
 * The same-flow block of a report (dogfood 2026-10-19, R2-D9).
 *
 * The NTLMv1 report, a false positive, and the WMIExec report, a true
 * positive, covered one attack step 2.6 s apart between the same two hosts.
 * Neither report named the other. This block names the other detections on
 * the flow of the alert, with their verdicts, and links each report. Show
 * opens the Alerts row of a sibling, so an untriaged sibling is one press
 * away too. In the Alerts drawer the screen takes Show through `onShow`. The
 * block draws nothing when the flow holds no other detection, when the run
 * investigated no alert, and when the grid did not answer.
 */
export function SameFlowPanel({
  invId,
  verdict,
  className,
  onShow,
}: {
  invId: string;
  verdict: Verdict | string | null | undefined;
  className?: string;
  /** Show a sibling on the screen around the report. Without it, Show is a
   *  link to the Alerts list. */
  onShow?: (sibling: AlertSibling) => void;
}) {
  // Read once per report. A failure of any kind draws no block: the panel is
  // an aid, and the report stands without it.
  const { data } = useAsync(() => Promise.resolve().then(() => getInvestigationSiblings(invId)), [invId]);
  const siblings = data?.siblings ?? [];
  const count = data?.siblingCount ?? siblings.length;
  if (!siblings.length || count <= 0) return null;
  const partial = !!data?.partial;
  const opposite = oppositeVerdictSentence(verdict, siblings);
  const more = count - siblings.length;
  const showCls = 'inline-flex flex-none items-center gap-0.5 font-sans text-[11px] font-semibold text-accent hover:underline';
  return (
    <Panel className={className}>
      <div data-testid="same-flow-panel" data-tone={opposite ? 'warning' : 'neutral'} className="flex flex-col gap-2 px-[15px] py-[11px]">
        <div className="flex items-center gap-[9px]">
          <span className={`flex ${opposite ? 'text-warn' : 'text-accent'}`}>
            {opposite ? <AlertTriangle size={15} /> : <Link2 size={15} />}
          </span>
          <div className="text-[13px] font-semibold">Same flow</div>
          <span className="font-mono text-[11px] text-faint">
            {count}
            {partial ? '+' : ''}
          </span>
        </div>
        <div className="text-[12px] text-dim">{shareSentence(count, partial, 'the flow of this alert')}</div>
        {opposite && <div className="text-[12px] font-semibold text-warn">{opposite}</div>}
        <ul className="flex flex-col gap-1.5">
          {siblings.map((s) => (
            <li
              key={`${s.kind}:${s.name}`}
              data-testid="same-flow-sibling"
              className="flex flex-col gap-0.5 rounded-[5px] border border-border-faint px-2 py-1.5"
            >
              <div className="flex min-w-0 items-center gap-2">
                {s.verdict ? (
                  <VerdictPill verdict={s.verdict as Verdict} conf={s.conf} inherited={false} showConf={false} showInherited={false} />
                ) : (
                  <span className="flex-none font-mono text-[10.5px] text-danger">Pipeline error</span>
                )}
                <span className="min-w-0 break-words text-[12px] font-medium text-text">{s.name}</span>
              </div>
              <div className="flex items-center justify-between gap-2 font-mono text-[10.5px] text-faint">
                <span>{signalWords(s.signals)}</span>
                <span className="flex flex-none items-center gap-3">
                  {onShow ? (
                    <button type="button" aria-label={`Show ${s.name} in Alerts`} onClick={() => onShow(s)} className={showCls}>
                      Show in Alerts
                      <ListTree size={11} />
                    </button>
                  ) : (
                    <Link
                      to={siblingRowHref(s, data?.windowFrom, data?.windowTo)}
                      aria-label={`Show ${s.name} in Alerts`}
                      className={showCls}
                    >
                      Show in Alerts
                      <ListTree size={11} />
                    </Link>
                  )}
                  {s.invId && (
                    <Link to={`/investigation/${s.invId}`} aria-label={`Open the report of ${s.name}`} className={showCls}>
                      Open report
                      <ArrowUpRight size={11} />
                    </Link>
                  )}
                </span>
              </div>
            </li>
          ))}
        </ul>
        {more > 0 && (
          <div className="text-[11.5px] text-faint">
            {plural(more, 'more detection')} {more === 1 ? 'shares' : 'share'} this flow.
          </div>
        )}
        <div className="text-[11px] text-faint">
          Another detection shares this flow when one of its alerts has the same community ID within 1 hour of
          this alert. It also shares it when one of its alerts runs between the same two hosts within 5 minutes of
          this alert. soc-ai changes no verdict because of it.
          {partial && ` ${PARTIAL_NOTE}`}
        </div>
      </div>
    </Panel>
  );
}
