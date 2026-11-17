// ---------------------------------------------------------------------------
// The fix of one doctor row, from the words of its hint.
//
// The review of 2026-11-12 found three warnings at rows 21, 34 and 35 of 36,
// as text only: "Open the account menu and select Change password", "set
// ABUSE_CH_AUTH_KEY ... See docs/BLOCKLISTS.md", "See docs/DOCKER.md". Each
// FAIL and WARN row now carries a control to the place that fixes it. The
// rules read the hint, so a new doctor check gets its controls with no change
// here:
//
//   "Change password"            -> a button that opens the password dialog
//   an UPPER_SNAKE setting name  -> a link to the setting in Settings
//   `a command` in backticks     -> the command, with a Copy button
//   "See docs/<FILE>.md[, <h>]." -> a link to the doc section on the docs site
//
// The panel of a check, where one exists, comes from DOCTOR_PANELS.
// ---------------------------------------------------------------------------

import { docUrl } from './docsSite';
import type { PreflightRow } from './types';

export interface DoctorDocLink {
  href: string;
  /** "docs/DOCKER.md, Backup schedule and retention". */
  label: string;
}

export interface DoctorFix {
  /** The row asks the operator to change the admin password. */
  changePassword: boolean;
  /** The setting names the hint asks the operator to set, lowercase: the
   *  setting key of Settings. */
  settings: string[];
  /** The first command of the hint. */
  command: string | null;
  doc: DoctorDocLink | null;
  /** The Settings panel that shows the state of the check. */
  panel: { id: string; label: string } | null;
}

/** The Settings panel that shows the state of a check, by check name. */
const DOCTOR_PANELS: Record<string, { id: string; label: string }> = {
  backups: { id: 'maintenance', label: 'Scheduled maintenance' },
  blocklists: { id: 'data-sources', label: 'Data sources' },
  tls: { id: 'tls', label: 'TLS' },
};

// The first word of a span that is a command. A span such as `feodo` or
// `blocklist_sources` names a value, and the row offers no Copy for it.
const COMMAND_START = /^(?:soc-ai|scripts\/|docker|sudo|uv|python|systemctl|crontab|mkdir|cd|pg_dump|curl)\b/;

/** The commands in the backtick spans of a hint, in order. */
export function hintCommands(hint: string): string[] {
  const out: string[] = [];
  for (const m of hint.matchAll(/`([^`]+)`/g)) {
    const span = m[1].trim();
    if (COMMAND_START.test(span)) out.push(span);
  }
  return out;
}

// An environment name of a setting: ABUSE_CH_AUTH_KEY, ES_PASSWORD. The
// pattern needs one underscore, so a word in capitals is no setting.
const SETTING_NAME = /\b([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)\b/g;

/** The setting keys a hint names, lowercase, once each. */
export function hintSettings(hint: string): string[] {
  const out: string[] = [];
  // A command span can hold capitals too. The settings come from the prose.
  const prose = hint.replace(/`[^`]*`/g, ' ');
  for (const m of prose.matchAll(SETTING_NAME)) {
    const key = m[1].toLowerCase();
    if (!out.includes(key)) out.push(key);
  }
  return out;
}

/** The doc reference of a hint: "See docs/DOCKER.md, TLS." */
export function hintDoc(hint: string): DoctorDocLink | null {
  const m = hint.match(/\bSee (docs\/[A-Za-z0-9_.-]+\.md)(?:,\s*([^.]+?))?\./);
  if (!m) return null;
  const [, path, section] = m;
  // "section 3" names a numbered part, which is no heading of the page.
  const heading = section && !/^section\s+\d+$/i.test(section.trim()) ? section.trim() : undefined;
  return {
    href: docUrl(path, heading),
    label: section ? `${path}, ${section.trim()}` : path,
  };
}

/** The fix of one row. A PASS or INFO row has none. */
export function doctorFix(row: PreflightRow): DoctorFix | null {
  const grade = row.status.toUpperCase();
  if (grade !== 'FAIL' && grade !== 'WARN') return null;
  const hint = row.hint ?? '';
  return {
    changePassword: /\bChange password\b/.test(hint),
    settings: hintSettings(hint),
    command: hintCommands(hint)[0] ?? null,
    doc: hintDoc(hint),
    panel: DOCTOR_PANELS[row.name] ?? null,
  };
}

const RANK: Record<string, number> = { FAIL: 0, WARN: 1 };

/** The rows with FAIL first, then WARN, then the rest in the doctor order. */
export function rowsByGrade(rows: PreflightRow[]): PreflightRow[] {
  return rows
    .map((row, i) => ({ row, i, rank: RANK[row.status.toUpperCase()] ?? 2 }))
    .sort((a, b) => a.rank - b.rank || a.i - b.i)
    .map((x) => x.row);
}
