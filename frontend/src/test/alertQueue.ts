import type { AlertQueue } from '../lib/api';
import type { AlertGroup } from '../lib/types';

/** A queue envelope around `groups`, untruncated unless told otherwise.
 *
 * `GET /alerts` returns the rows plus whether the rows are all the rows: the
 * grid caps every terms aggregation, and past the cap the console's "N
 * detections · M events in window" is a floor rendered as a total. Almost
 * every test here only ever meant "these rows came back", so this spells the
 * uncut case once instead of in thirty places. A test about the cap passes
 * `{ truncated: true }` and says so out loud. */
export function queueOf(groups: AlertGroup[] = [], over: Partial<AlertQueue> = {}): AlertQueue {
  return { groups, truncated: false, other_docs: 0, ...over };
}
