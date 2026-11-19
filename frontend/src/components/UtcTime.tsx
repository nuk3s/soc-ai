import { useConsoleTimeZone } from '../lib/clock';
import { absTime, absoluteTime, localTitle, utcStamp, utcWindow } from '../lib/timeRange';

/** An absolute time as a page shows it: UTC with the zone named, in the form
 *  of the investigation page. The tooltip states the local time with its
 *  zone (round 3, T3). An empty value reads as '—'.
 *
 *  `to` makes it a span, "2026-10-05 04:00 to 05:00 UTC", with both ends in
 *  local time in the tooltip. `seconds` is on by default, the form of
 *  `absTime`; a list that reads to the minute turns it off. Every absolute
 *  time of the console renders through here, and `data-time="absolute"` lets
 *  a test find each one on a page (round 3 part 2, P1). */
export function UtcTime({
  iso,
  to,
  seconds = true,
  className,
  testId,
}: {
  iso: string | null | undefined;
  to?: string | null;
  seconds?: boolean;
  className?: string;
  testId?: string;
}) {
  // The local zone of the console. A change of the second clock of the top
  // bar renders the time again, so an open page follows it (round 4, C4).
  const timeZone = useConsoleTimeZone();
  const span = !!(iso && to);
  const text = !iso ? absTime(iso) : span ? utcWindow(iso, to!, { seconds }) : utcStamp(iso, { seconds });
  const local =
    span && localTitle(iso) && localTitle(to)
      ? `Local time: ${absoluteTime(iso, { timeZone })} to ${absoluteTime(to, { timeZone })}`
      : localTitle(iso, { timeZone });
  return (
    <time
      dateTime={iso || undefined}
      title={local}
      className={className}
      data-testid={testId}
      data-time="absolute"
    >
      {text}
    </time>
  );
}
