import { AlertTriangle, ArrowUpRight, Link2 } from 'lucide-react';
import { useEffect, useState } from 'react';

import { plural } from '../lib/plural';
import type { AlertSibling, Verdict } from '../lib/types';
import { VerdictPill } from './Badges';

// ---------------------------------------------------------------------------
// The same-flow chip of an Alerts row (dogfood 2026-10-19, R2-I9, R2-D9).
//
// On the range an SQL injection alert and a Geoserver alert shared one flow
// and showed as two unrelated rows. The NTLMv1 group, a false positive, and
// the WMIExec group, a true positive, fired 2.6 s apart between the same two
// hosts, and neither row named the other. The chip names how many other
// detections share the flow of the row. It opens a list of them with their
// verdicts. When one of them holds the opposite verdict, the chip takes the
// warning tone and says so.
//
// The server decides what a shared flow is (soc_ai/webui/alert_siblings.py):
// an alert of each group with the same network.community_id within 1 hour of
// the other, or an alert of each group between the same two hosts within 5
// minutes of the other. A community id repeats across days for fixed-port
// traffic such as NTP, so the flow signal has a time bound too. The first rule compared the spans
// of the two groups, and 50 of 64 rows of a 90 day window carried a chip
// (V3-N5). When a size limit of the read cut data, the count is a floor and
// the chip says so (V3-N1).
// ---------------------------------------------------------------------------

/** The sentence of a partial list, after the note. */
export const PARTIAL_NOTE = 'The read of the grid stopped at a size limit. The list can be partial.';

/** The sentence for an opposite verdict on the flow, or null.
 *
 * Opposite means one true positive and one false positive. Any other pair of
 * verdicts gives no sentence. */
export function oppositeVerdictSentence(
  verdict: Verdict | string | null | undefined,
  siblings: AlertSibling[],
): string | null {
  if (verdict === 'false_positive' && siblings.some((s) => s.verdict === 'true_positive')) {
    return 'A true positive shares this flow.';
  }
  if (verdict === 'true_positive' && siblings.some((s) => s.verdict === 'false_positive')) {
    return 'A false positive shares this flow.';
  }
  return null;
}

/** "2 other detections share this flow.", or "At least 2 ..." when the
 *  read was cut and the count is a floor. */
export function shareSentence(count: number, partial: boolean, flow = 'this flow'): string {
  const head = `${partial ? 'At least ' : ''}${plural(count, 'other detection')}`;
  return `${head} ${count === 1 ? 'shares' : 'share'} ${flow}.`;
}

/** How the server linked a sibling, in words. */
export function signalWords(signals: AlertSibling['signals']): string {
  return signals.includes('flow') ? 'Same community ID within 1 hour' : 'Same two hosts within 5 minutes';
}

const NEUTRAL = { borderColor: 'rgba(148,163,184,.32)', background: 'rgba(148,163,184,.08)', color: '#cbd5e1' };
const WARNING = { borderColor: 'rgba(245,166,35,.45)', background: 'rgba(245,166,35,.12)', color: '#f5a623' };

export interface SameFlowChipProps {
  /** The verdict the row shows. */
  verdict: Verdict | string | null | undefined;
  siblings: AlertSibling[];
  /** How many siblings there are. The list can hold fewer. */
  count: number;
  /** True when the read was cut, so `count` is a floor. */
  partial?: boolean;
  /** Show the row of a sibling on the page. */
  onShow: (sibling: AlertSibling) => void;
  /** Open the report of a sibling. */
  onOpen: (invId: string) => void;
}

export function SameFlowChip({ verdict, siblings, count, partial = false, onShow, onOpen }: SameFlowChipProps) {
  const [open, setOpen] = useState(false);
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      e.stopPropagation();
      setOpen(false);
    };
    window.addEventListener('keydown', onKey, true);
    return () => window.removeEventListener('keydown', onKey, true);
  }, [open]);
  if (count <= 0 || siblings.length === 0) return null;
  const opposite = oppositeVerdictSentence(verdict, siblings);
  const share = shareSentence(count, partial);
  const more = count - siblings.length;
  return (
    <span className="relative inline-flex" onClick={(e) => e.stopPropagation()}>
      <button
        type="button"
        data-testid="same-flow-chip"
        data-tone={opposite ? 'warning' : 'neutral'}
        aria-label={`${opposite ? `${opposite} ` : ''}${share} Show them.`}
        aria-expanded={open}
        title={`${opposite ? `${opposite} ` : ''}${share}`}
        onClick={() => setOpen((o) => !o)}
        className="inline-flex flex-none items-center gap-1 rounded-chip border px-[5px] py-[1px] font-sans text-[10.5px] font-semibold hover:brightness-125"
        style={opposite ? WARNING : NEUTRAL}
      >
        {opposite ? <AlertTriangle size={10} /> : <Link2 size={10} />}
        <span>{opposite ?? 'Same flow'}</span>
        <span className="font-mono opacity-80">
          · {count}
          {partial ? '+' : ''}
        </span>
      </button>
      {open && (
        <>
          <span className="fixed inset-0 z-[39]" onClick={() => setOpen(false)} />
          {/* The height is capped and the list scrolls inside it. At
              1280x800 the popover of 16 siblings was 1149 px tall, and the
              note sat below the screen (V3-N7). */}
          <div
            role="dialog"
            aria-label="Detections on the same flow"
            data-testid="same-flow-popover"
            className="absolute left-0 top-[calc(100%+6px)] z-40 flex max-h-[min(440px,60vh)] w-[440px] max-w-[calc(100vw-48px)] animate-fadeUp flex-col whitespace-normal rounded-panel border border-border-2 bg-surface-1 p-3 font-sans text-[12px] text-text-2 shadow-[0_12px_40px_rgba(0,0,0,.5)]"
          >
            <div className="mb-2 flex-none text-text">{share}</div>
            {opposite && <div className="mb-2 flex-none font-semibold text-warn">{opposite}</div>}
            <ul data-testid="same-flow-list" className="flex min-h-0 flex-1 flex-col gap-1.5 overflow-y-auto pr-1">
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
                    <button
                      type="button"
                      aria-label={`Show ${s.name}`}
                      onClick={() => {
                        setOpen(false);
                        onShow(s);
                      }}
                      className="min-w-0 break-words text-left text-[12px] font-medium text-text hover:text-accent hover:underline"
                    >
                      {s.name}
                    </button>
                  </div>
                  <div className="flex items-center justify-between gap-2 font-mono text-[10.5px] text-faint">
                    <span>{signalWords(s.signals)}</span>
                    {s.invId && (
                      <button
                        type="button"
                        aria-label={`Open the report of ${s.name}`}
                        onClick={() => {
                          setOpen(false);
                          onOpen(s.invId as string);
                        }}
                        className="inline-flex flex-none items-center gap-0.5 font-sans text-[11px] font-semibold text-accent hover:underline"
                      >
                        Open report
                        <ArrowUpRight size={11} />
                      </button>
                    )}
                  </div>
                </li>
              ))}
            </ul>
            {more > 0 && (
              <div className="mt-2 flex-none text-faint">
                {plural(more, 'more detection')} {more === 1 ? 'shares' : 'share'} this flow.
              </div>
            )}
            <div data-testid="same-flow-note" className="mt-2 flex-none text-[11px] text-faint">
              Two detections share a flow when an alert of each has the same community ID within 1 hour of the
              other. They also share a flow when an alert of each runs between the same two hosts within 5 minutes
              of the other. soc-ai changes no verdict because of it.
              {partial && ` ${PARTIAL_NOTE}`}
            </div>
          </div>
        </>
      )}
    </span>
  );
}
