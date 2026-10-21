import { Fragment, type ReactNode } from 'react';
import { Link, useInRouterContext } from 'react-router-dom';
import { type ConfigParent, PANELS, RESERVED_IDS, slug } from '../lib/configLayout';

// ---------------------------------------------------------------------------
// HelpText renders a help string that the backend wrote for the console: a
// setting's help, a data source note, an API key hint. Two marks in that text
// get markup:
//
//   `code`                       -> a <code> element, without the backticks
//   Settings > <Section title>   -> a link to /config#<section id>
//
// The Settings page shows one section at a time, so a help string that said
// "the panel below" pointed at a panel the operator could not see (dogfood
// 2026-10-19, R5-D18). A help string now names the section, and this component
// makes the name a link. A title it does not know stays plain text.
// ---------------------------------------------------------------------------

/** The server settings sections, in SECTION_ORDER of
 * soc_ai/store/config_overrides.py. tests/test_config_help_links.py pins this
 * list to the backend, so a new server section fails that test until it is
 * added here. */
export const SETTINGS_SECTION_TITLES: readonly string[] = [
  'Agent',
  'Oracle',
  'Quality',
  'Triage automation',
  'Hunting',
  'Notifications',
  'Audit trail',
  'Retrieval (RAG)',
  'Memory',
  'Discovery',
  'Updates',
  'Security Onion',
  'Queries',
  'PCAP',
  'Web research',
  'Online enrichment',
  'Host dossier',
  'Behavioural profiles',
];

/** The id that buildConfigLayout gives a server section title. Same rule:
 * slug(title), moved off a reserved panel id with a -2 suffix. The current
 * titles slug to free ids, so the suffix never applies today. */
export function sectionIdFor(title: string): string {
  const base = slug(title) || 'section';
  return RESERVED_IDS.has(base) ? `${base}-2` : base;
}

/** Section title -> section id for every section a built layout renders. Pass
 * the result as `sections` where the live layout is at hand (the Config page),
 * so a server section this file does not list still links. */
export function sectionIdsFromLayout(layout: ConfigParent[]): Record<string, string> {
  const map: Record<string, string> = {};
  for (const parent of layout) {
    for (const child of parent.children) map[child.label] = child.id;
  }
  return map;
}

function defaultSectionIds(): Record<string, string> {
  const map: Record<string, string> = {};
  for (const title of SETTINGS_SECTION_TITLES) map[title] = sectionIdFor(title);
  for (const panel of PANELS) map[panel.label] = panel.id;
  return map;
}

/** The known sections: every server section plus every standalone panel. */
export const DEFAULT_SECTION_IDS: Readonly<Record<string, string>> = defaultSectionIds();

const PREFIX = 'Settings > ';
const WORD_CHAR = /[A-Za-z0-9]/;

function linkify(
  text: string,
  sections: Record<string, string>,
  keyBase: string,
  canLink: boolean,
): ReactNode[] {
  // Longest title first, so "Notification webhook" wins over "Notifications"
  // and "Agent tools" over "Agent".
  const titles = Object.keys(sections).sort((a, b) => b.length - a.length);
  const out: ReactNode[] = [];
  let plainStart = 0;
  let at = text.indexOf(PREFIX);
  while (at !== -1) {
    const titleStart = at + PREFIX.length;
    const title = titles.find((t) => {
      if (!text.startsWith(t, titleStart)) return false;
      const next = text.charAt(titleStart + t.length);
      return next === '' || !WORD_CHAR.test(next);
    });
    if (title && canLink) {
      if (at > plainStart) out.push(text.slice(plainStart, at));
      out.push(
        <Link key={`${keyBase}-${at}`} to={`/config#${sections[title]}`} className="text-accent hover:underline">
          {PREFIX}
          {title}
        </Link>,
      );
      plainStart = titleStart + title.length;
      at = text.indexOf(PREFIX, plainStart);
    } else {
      at = text.indexOf(PREFIX, at + PREFIX.length);
    }
  }
  if (plainStart < text.length) out.push(text.slice(plainStart));
  return out;
}

export interface HelpTextProps {
  /** The help string. Empty, null or undefined renders nothing. */
  text: string | null | undefined;
  /** Section title -> section id. The default is DEFAULT_SECTION_IDS. */
  sections?: Record<string, string>;
  /** Class names for the outer <span>. */
  className?: string;
}

/** Render a backend help string with its code spans and section links. */
export function HelpText({ text, sections = DEFAULT_SECTION_IDS, className }: HelpTextProps) {
  // Outside a router (an isolated render) a section name stays plain text.
  const canLink = useInRouterContext();
  if (!text) return null;
  // A code span is a pair of backticks with no backtick inside. The odd parts
  // of the split are the code spans. An unpaired backtick stays in the text.
  const parts = text.split(/`([^`\n]+)`/);
  return (
    <span className={className}>
      {parts.map((part, i) =>
        i % 2 === 1 ? (
          <code key={i} className="rounded-[4px] bg-bg px-1 py-px font-mono text-[0.95em] text-text-2">
            {part}
          </code>
        ) : (
          <Fragment key={i}>{linkify(part, sections, String(i), canLink)}</Fragment>
        ),
      )}
    </span>
  );
}
