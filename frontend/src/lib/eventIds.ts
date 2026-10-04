// Document ids inside prose: the investigation headline, its summary and the
// chat answers cite Elasticsearch ids as plain text (fleet P3, 2026-10-01).
// These helpers find them so the page can render each one as a control that
// opens the document.

import type { InvestigationCitation } from './types';

/** The ids an investigation's report cites as documents. */
export function citedEventIds(citations: InvestigationCitation[] | undefined): string[] {
  const out: string[] = [];
  for (const c of citations ?? []) {
    const id = c.kind === 'id' ? (c.target ?? '').trim() : '';
    if (id && !out.includes(id)) out.push(id);
  }
  return out;
}

// An Elasticsearch auto-generated id: 20 characters of base64url. Prose words
// of that length are rare, and one that mixes both cases with a digit or a
// separator is rarer still, so the shape test keeps ordinary words plain.
const ES_ID_SHAPE = /^[A-Za-z0-9_-]{20}$/;
function looksLikeEsId(token: string): boolean {
  return (
    ES_ID_SHAPE.test(token) &&
    /[A-Z]/.test(token) &&
    /[a-z]/.test(token) &&
    /[0-9_-]/.test(token)
  );
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

export type IdSegment = { t: 'text'; v: string } | { t: 'id'; v: string };

/**
 * Split `text` into plain runs and document ids. An id is one of `known` or a
 * token with the Elasticsearch id shape. An id inside a longer token stays
 * text, so a URL or a hash that contains an id-shaped run is not cut apart.
 */
export function splitEventIds(text: string, known: string[] = []): IdSegment[] {
  if (!text) return [];
  const alternatives = [...known.filter(Boolean).map(escapeRe), '[A-Za-z0-9_-]{20}'];
  const re = new RegExp(`(?<![A-Za-z0-9_-])(${alternatives.join('|')})(?![A-Za-z0-9_-])`, 'g');
  const out: IdSegment[] = [];
  let last = 0;
  for (const m of text.matchAll(re)) {
    const token = m[0];
    if (!known.includes(token) && !looksLikeEsId(token)) continue;
    const at = m.index ?? 0;
    if (at > last) out.push({ t: 'text', v: text.slice(last, at) });
    out.push({ t: 'id', v: token });
    last = at + token.length;
  }
  if (last < text.length) out.push({ t: 'text', v: text.slice(last) });
  return out;
}

/** The distinct document ids in `text`, in order of first use. */
export function findEventIds(text: string, known: string[] = []): string[] {
  const ids: string[] = [];
  for (const seg of splitEventIds(text, known)) {
    if (seg.t === 'id' && !ids.includes(seg.v)) ids.push(seg.v);
  }
  return ids;
}
