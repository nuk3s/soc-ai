import { entityHref } from './entityPath';

// ---------------------------------------------------------------------------
// Links in a chat answer.
//
// The general chat named "10.99.0.40", "Lead 11" and an investigation id as
// plain text, so the analyst who read the answer had to copy each one into a
// search (dogfood 2026-10-19, R1-D5). This rewrites those three shapes in the
// answer's Markdown as links to the page that answers for each one. The
// Markdown renderer opens a same-app path in the console.
//
// Code, links and URLs that the answer already holds stay as they are: a link
// inside a code span would show as Markdown source, and a link inside a URL
// would break the URL.
// ---------------------------------------------------------------------------

const OCTET = '(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)';

// An IPv4 address that stands alone. Not a part of a longer dotted number, a
// URL, an IPv6 address or a CIDR block ("192.0.2.0/24" names a network, and
// the address page would answer for one host only). A port after it is fine.
const IPV4 = new RegExp(
  `(?<![\\w.:/@-])(${OCTET}(?:\\.${OCTET}){3})(?![\\w-]|\\.\\d|/\\d)`,
  'g',
);

// "Lead 11", "lead 11", "Lead #11".
const LEAD = /\b([Ll]ead #?(\d{1,9}))\b/g;

// An investigation id is a ULID: 26 characters of Crockford base32. A ULID
// minted before the year 2109 starts with a digit from 0 to 7, and the ones
// soc-ai mints now start with "0".
const ULID = /(?<![A-Za-z0-9])(0[0-9A-HJKMNP-TV-Z]{25})(?![A-Za-z0-9])/g;

// The parts of Markdown that are left alone: fenced code, inline code, a link
// or an image with its target, an autolink and a bare URL.
const PROTECTED = /```[\s\S]*?(?:```|$)|`[^`\n]*`|!?\[[^\]\n]*\]\([^)\n]*\)|<[a-z][a-z0-9+.-]*:[^>\s]*>|\bhttps?:\/\/[^\s<>()]+/gi;

function linkPlain(text: string): string {
  return text
    .replace(IPV4, (ip: string) => `[${ip}](${entityHref(ip, 'address')})`)
    .replace(LEAD, (whole: string, _label: string, id: string) => `[${whole}](/leads/${id})`)
    .replace(ULID, (id: string) => `[${id}](/investigation/${id})`);
}

/**
 * The answer with each address, lead and investigation id as a Markdown link
 * to its page. Text inside code, a link or a URL is unchanged.
 */
export function linkifyChatAnswer(text: string): string {
  if (!text) return text;
  let out = '';
  let last = 0;
  for (const m of text.matchAll(PROTECTED)) {
    const at = m.index ?? 0;
    out += linkPlain(text.slice(last, at)) + m[0];
    last = at + m[0].length;
  }
  return out + linkPlain(text.slice(last));
}
