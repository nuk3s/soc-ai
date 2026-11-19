import type { ReactNode } from 'react';
import { useConsoleTimeZone } from '../lib/clock';
import { ago, timeTitle } from '../lib/timeRange';

/** A relative time as a page shows it: "4h ago". The tooltip states the
 *  time in UTC and the local time with its zone, "2026-11-18 15:08 UTC. Local
 *  time: 2026-11-18 10:08 EST" (round 3 part 2, P1). The Alerts rows gave
 *  the local time alone, the Hunts rows a raw ISO time, and the
 *  Investigations list the UTC time alone.
 *
 *  `text` replaces the relative label, for a row that carries the label the
 *  server wrote ("14h"). `what` names the time in the tooltip, "Event".
 *  `note` adds a sentence after the two clocks, "Recorded 2026-11-18 15:20 UTC.".
 *  `data-time="relative"` lets a test find each one on a page. */
export function RelTime({
  iso,
  text,
  what,
  note,
  className,
  testId,
}: {
  iso: string | number | null | undefined;
  text?: ReactNode;
  what?: string;
  note?: string;
  className?: string;
  testId?: string;
}) {
  // The local zone of the console. A change of the second clock of the top
  // bar renders the time again, so an open page follows it (round 4, C4).
  const timeZone = useConsoleTimeZone();
  const clocks = timeTitle(iso, { timeZone });
  const title = clocks ? `${what ? `${what} ${clocks}` : clocks}${note ? `. ${note}` : ''}` : undefined;
  return (
    <time
      dateTime={typeof iso === 'string' && iso ? iso : undefined}
      title={title}
      className={className}
      data-testid={testId}
      data-time="relative"
    >
      {text ?? ago(iso)}
    </time>
  );
}
