// One KPI card, and the vocabulary for a number that could not be read.
//
// Shared by the two strips this app has: the host page's (what one machine is
// doing) and the host list's (what the network looks like). They sit one
// navigation apart, so a padding or a type step that moved on one of them would
// read as two components rather than one idea at two altitudes.

import type { ReactNode } from 'react';
import { cn } from '../lib/cn';

export function Kpi({
  testId,
  label,
  value,
  sub,
  icon,
  tone,
  title,
  chart,
}: {
  testId: string;
  label: string;
  value: ReactNode;
  sub: ReactNode;
  icon: ReactNode;
  /** Text colour class for the icon + the number. */
  tone: string;
  /** Card-level hover text, for a number whose SCOPE the label cannot carry —
   *  "every host, whatever the table below is filtered to". A sub-line can only
   *  hold that in one of its branches; this holds it in all of them. */
  title?: string;
  /** An optional in-card chart, rendered between the number and the sub-line
   *  (the Events card's volume sparkline). Callers pass nothing rather than an
   *  empty box when there is nothing honest to draw. */
  chart?: ReactNode;
}) {
  return (
    <div
      data-testid={testId}
      title={title}
      className="rounded-panel border border-border bg-surface-1 px-4 py-3.5"
    >
      <div className="flex items-start justify-between gap-2">
        <div className="text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint">
          {label}
        </div>
        <span className={cn('flex flex-none', tone)}>{icon}</span>
      </div>
      <div className={cn('mt-2 text-[27px] font-semibold leading-none tabular-nums', tone)}>
        {value}
      </div>
      {chart}
      <div className="mt-1.5 text-[11.5px] leading-[1.4] text-dim">{sub}</div>
    </div>
  );
}

/** The dash, and the muted tone that goes with it. Kept together so a degraded
 *  number can never accidentally render in a confident colour. */
export const UNKNOWN = '—';
export const UNKNOWN_TONE = 'text-ghost';
