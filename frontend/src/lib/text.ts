/**
 * Middle-ellipsize: keep the head and the tail of a long name. The tail is the
 * differentiating part of Suricata rule names ("… from Backup Intermediate,
 * E2"), which CSS end-truncation always cuts first. Callers keep the Tailwind
 * `truncate` class on the element as the backstop for widths where even the
 * shortened string overflows.
 */
export function middleEllipsis(s: string, max = 72): string {
  const chars = Array.from(s); // code points — never split a surrogate pair
  if (chars.length <= max) return s;
  const head = Math.ceil((max - 1) * 0.6);
  const tail = max - 1 - head;
  return `${chars.slice(0, head).join('').trimEnd()}…${chars.slice(chars.length - tail).join('').trimStart()}`;
}
