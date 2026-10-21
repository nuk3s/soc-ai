import { absoluteTime } from './timeRange';

// ---------------------------------------------------------------------------
// The words of an observation, read after the fact.
//
// The sweep writes its summary in the present: "3 documents in the last
// 24 h". The row keeps those words, and on an observation 20 days old the
// window had ended 20 days before the page read it (dogfood 2026-10-19,
// R4-D18). The row anchors the window to the time the sweep wrote it.
// ---------------------------------------------------------------------------

const LAST_HOURS = /\bin the last (\d+) h\b/g;
const IN_WINDOW = /\bin the window\b/g;

/** The summary with each relative window anchored to `bornAt`, when the
 *  observation is older than the window it names. A fresh observation and a
 *  summary with no window read as written. */
export function anchoredSummary(text: string, bornAt: string | null | undefined, now = Date.now()): string {
  if (!bornAt) return text;
  const born = new Date(bornAt).getTime();
  if (!Number.isFinite(born)) return text;
  const age = now - born;
  const stamp = absoluteTime(bornAt);
  let out = text.replace(LAST_HOURS, (whole, hours: string) =>
    age > Number(hours) * 3_600_000 ? `in the ${hours} h before ${stamp}` : whole,
  );
  // "the window" is the window of the sweep, 24 hours by default.
  if (age > 24 * 3_600_000) out = out.replace(IN_WINDOW, `in the window before ${stamp}`);
  return out;
}
