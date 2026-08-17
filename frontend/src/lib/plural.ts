/**
 * "1 investigation", "2 investigations" — a count and its noun, agreeing.
 *
 * The list headers all wrote `{n} investigations` / `{n} detections` and read
 * "1 investigations" on a one-row result. That used to be hard to reach; the
 * search boxes those screens grew make a single match a normal outcome, and a
 * header that cannot count to one undermines every other number beside it.
 *
 * `toLocaleString` for free, because these are the same counts that reach five
 * figures on a busy deployment.
 */
export function plural(n: number, one: string, many = `${one}s`): string {
  return `${n.toLocaleString()} ${n === 1 ? one : many}`;
}
