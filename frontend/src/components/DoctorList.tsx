import { Copy, ExternalLink, KeyRound, RotateCw, Settings2 } from 'lucide-react';
import { type ReactNode, useEffect, useRef, useState } from 'react';
import { Link, useInRouterContext } from 'react-router-dom';

import { ApiError, getApiKeys, getPreflightDetail, refreshPreflight } from '../lib/api';
import { type DoctorFix, doctorFix, rowsByGrade } from '../lib/doctorFix';
import type { PreflightDetail, PreflightRow } from '../lib/types';
import { ago, timeTitle, utcTimesInText } from '../lib/timeRange';
import { ChangePasswordModal } from '../shell/ChangePasswordModal';
import { HelpText } from './HelpText';
import { LoadingInline } from './States';

// ---------------------------------------------------------------------------
// Every doctor row. FAIL and WARN rows come first, each with a control to the
// place that fixes it (lib/doctorFix.ts). The rest keep the doctor order.
//
// The Setup health card on the Dashboard shows the FAIL and WARN rows only.
// The INFO and PASS rows ("estate model", "prompt assets", "oracle route")
// existed only in GET /health/preflight/detail, so an operator who turned a
// setting off could not read what the doctor said about it. This list reads
// the same endpoint when the Diagnostics pane opens and shows each row.
// ---------------------------------------------------------------------------

interface Grade {
  color: string;
  border: string;
  title: string;
}

const GRADE: Record<string, Grade> = {
  FAIL: {
    color: '#f04438',
    border: 'rgba(240,68,56,.4)',
    title: 'The check failed. Read the line under the row to fix it.',
  },
  WARN: {
    color: '#f5a623',
    border: 'rgba(245,166,35,.4)',
    title: 'The check found a problem. soc-ai runs with less coverage.',
  },
  PASS: {
    color: '#12b76a',
    border: 'rgba(18,183,106,.4)',
    title: 'The check passed.',
  },
  INFO: {
    color: '#8b949e',
    border: 'rgba(139,148,158,.4)',
    title: 'The check states a fact. No action is necessary.',
  },
};

function gradeOf(status: string): Grade {
  return GRADE[status.toUpperCase()] ?? GRADE.INFO;
}

/** One sentence per count, for the line above the rows. */
export function doctorCounts(rows: PreflightRow[]): string {
  const order = ['FAIL', 'WARN', 'INFO', 'PASS'];
  const counts = new Map<string, number>();
  for (const r of rows) {
    const key = r.status.toUpperCase();
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  const known = order.filter((k) => counts.has(k)).map((k) => `${counts.get(k)} ${k}`);
  const other = [...counts.keys()].filter((k) => !order.includes(k)).map((k) => `${counts.get(k)} ${k}`);
  return [...known, ...other].join(' · ');
}

function readFailure(e: unknown): string {
  if (e instanceof ApiError && e.status === 403) return 'Only an admin can read the doctor rows.';
  return 'The doctor read failed. The result is unknown. Select Refresh to try again.';
}

/** The WARN rows of a doctor read. */
export function warnRows(rows: PreflightRow[]): PreflightRow[] {
  return rows.filter((r) => r.status.toUpperCase() === 'WARN');
}

/** A grade the Diagnostics header can filter on. null = every row. */
export type DoctorFilter = 'FAIL' | 'WARN' | 'INFO' | null;

/** How many rows each grade has. The Diagnostics header shows a chip for
 *  FAIL, WARN and INFO, FAIL first. Its one chip counted WARN only, and read
 *  "4 warnings" while 6 checks failed (dogfood 2026-10-19, H1-D9). */
export function statusCounts(rows: PreflightRow[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const r of rows) {
    const key = r.status.toUpperCase();
    out[key] = (out[key] ?? 0) + 1;
  }
  return out;
}

/** Where a setting lives in Settings: the section and the row to flash. */
export interface SettingTarget {
  sectionId: string;
  highlightKey: string;
  label: string;
}

const CONTROL =
  'inline-flex items-center gap-1 rounded-control border border-border bg-surface-2 px-2 py-0.5 text-[11px] font-semibold text-text-2 hover:bg-surface-3 hover:text-text';

/** A link inside the console. A list rendered outside a router (a test, a
 *  story) gets a plain anchor. */
function ConsoleLink({
  to,
  state,
  children,
  testId,
}: {
  to: { pathname: string; hash: string };
  state?: unknown;
  children: ReactNode;
  testId: string;
}) {
  const routed = useInRouterContext();
  if (!routed) {
    return (
      <a data-testid={testId} href={`/app${to.pathname}#${to.hash}`} className={CONTROL}>
        {children}
      </a>
    );
  }
  return (
    <Link data-testid={testId} to={to} state={state} className={CONTROL}>
      {children}
    </Link>
  );
}

function CopyCommand({ command }: { command: string }) {
  const [copied, setCopied] = useState(false);
  const canCopy = typeof navigator !== 'undefined' && !!navigator.clipboard;
  return (
    <span className="inline-flex min-w-0 flex-wrap items-center gap-1.5">
      <code
        data-testid="doctor-fix-command"
        className="break-all rounded-chip bg-surface-2 px-1.5 py-px font-mono text-[11px] text-text-2"
      >
        {command}
      </code>
      {canCopy && (
        <button
          type="button"
          data-testid="doctor-fix-copy"
          className={CONTROL}
          onClick={() => {
            navigator.clipboard
              .writeText(command)
              .then(() => setCopied(true))
              .catch(() => setCopied(false));
          }}
        >
          <Copy size={11} />
          {copied ? 'Copied' : 'Copy the command'}
        </button>
      )}
    </span>
  );
}

/** The controls of one FAIL or WARN row. */
function FixControls({
  fix,
  settingTarget,
  onChangePassword,
}: {
  fix: DoctorFix;
  settingTarget: (key: string) => SettingTarget | null;
  onChangePassword: () => void;
}) {
  const settings = fix.settings
    .map((key) => settingTarget(key))
    .filter((t): t is SettingTarget => t != null);
  const any = fix.changePassword || settings.length > 0 || fix.command || fix.doc || fix.panel;
  if (!any) return null;
  return (
    <div data-testid="doctor-fix-controls" className="mt-1.5 flex flex-wrap items-center gap-1.5">
      {fix.changePassword && (
        <button type="button" data-testid="doctor-fix-password" className={CONTROL} onClick={onChangePassword}>
          <KeyRound size={11} />
          Change password
        </button>
      )}
      {settings.map((t) => (
        <ConsoleLink
          key={t.highlightKey}
          testId="doctor-fix-setting"
          to={{ pathname: '/config', hash: t.sectionId }}
          state={{ highlightKey: t.highlightKey }}
        >
          <Settings2 size={11} />
          {`Open the setting ${t.label}`}
        </ConsoleLink>
      ))}
      {fix.panel && (
        <ConsoleLink testId="doctor-fix-panel" to={{ pathname: '/config', hash: fix.panel.id }}>
          <Settings2 size={11} />
          {`Open ${fix.panel.label}`}
        </ConsoleLink>
      )}
      {fix.command && <CopyCommand command={fix.command} />}
      {fix.doc && (
        <a
          data-testid="doctor-fix-doc"
          href={fix.doc.href}
          target="_blank"
          rel="noopener noreferrer"
          className={CONTROL}
        >
          <ExternalLink size={11} />
          {`Read ${fix.doc.label}`}
        </a>
      )}
    </div>
  );
}

export function DoctorList({
  warnOnly = false,
  filter = null,
  onRows,
  settingTarget,
}: {
  /** Show the WARN rows only. Kept for older callers; `filter` replaces it. */
  warnOnly?: boolean;
  /** Show the rows of one grade only. */
  filter?: DoctorFilter;
  /** Called with the rows of each read, so the header can count them. */
  onRows?: (rows: PreflightRow[]) => void;
  /** Where a setting key lives in Settings. The Settings page knows its
   *  sections. An API key that it does not know resolves to API keys. */
  settingTarget?: (key: string) => SettingTarget | null;
} = {}) {
  const [detail, setDetail] = useState<PreflightDetail | null>(null);
  const [failed, setFailed] = useState<string | null>(null);
  const [busy, setBusy] = useState(true);

  // The newest stored read, when the pane opens. The server keeps the doctor
  // result for 10 minutes, and Refresh runs the checks again.
  useEffect(() => {
    let live = true;
    getPreflightDetail()
      .then((d) => {
        if (!live) return;
        setDetail(d);
        setFailed(null);
      })
      .catch((e: unknown) => {
        if (live) setFailed(readFailure(e));
      })
      .finally(() => {
        if (live) setBusy(false);
      });
    return () => {
      live = false;
    };
  }, []);

  const refresh = () => {
    setBusy(true);
    setFailed(null);
    refreshPreflight()
      .then((d) => setDetail(d))
      .catch((e: unknown) => setFailed(readFailure(e)))
      .finally(() => setBusy(false));
  };

  const rows = detail?.rows ?? [];
  useEffect(() => {
    if (detail) onRows?.(detail.rows);
    // onRows is a setter from the caller. A new closure must not read again.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [detail]);
  // The API keys of the API keys panel. A hint that names one ("set
  // ABUSE_CH_AUTH_KEY") links to its row there. Read once, when a FAIL or WARN
  // row names a setting that the caller does not resolve.
  const [apiKeys, setApiKeys] = useState<Record<string, string> | null>(null);
  const askedKeys = useRef(false);
  useEffect(() => {
    if (!detail || askedKeys.current) return;
    const unresolved = detail.rows.some((r) =>
      (doctorFix(r)?.settings ?? []).some((key) => !settingTarget?.(key)),
    );
    if (!unresolved) return;
    askedKeys.current = true;
    getApiKeys()
      .then((keys) => setApiKeys(Object.fromEntries(keys.map((k) => [k.key, k.label]))))
      .catch(() => setApiKeys({}));
  }, [detail, settingTarget]);
  const resolveSetting = (key: string): SettingTarget | null => {
    const found = settingTarget?.(key);
    if (found) return found;
    const label = apiKeys?.[key];
    return label ? { sectionId: 'api-keys', highlightKey: `apikey:${key}`, label } : null;
  };
  const [passwordOpen, setPasswordOpen] = useState(false);
  const passwordReturn = useRef<HTMLElement | null>(null);
  const only: DoctorFilter = filter ?? (warnOnly ? 'WARN' : null);
  // FAIL and WARN first. Three warnings sat at rows 21, 34 and 35 of 36
  // (review 2026-11-12).
  const ordered = rowsByGrade(rows);
  const shown = only ? ordered.filter((r) => r.status.toUpperCase() === only) : ordered;
  return (
    <div data-testid="doctor-list" className="border-t border-border-faint">
      <div className="flex flex-wrap items-center gap-2 px-4 py-2.5">
        <span className="text-[12.5px] font-semibold text-text-2">Doctor</span>
        {detail && (
          <span className="text-[11.5px] text-dim" title={timeTitle(detail.checked_at)}>
            {rows.length ? `${doctorCounts(rows)} · ` : ''}checked {ago(detail.checked_at)}
          </span>
        )}
        <div className="flex-1" />
        <button
          type="button"
          onClick={refresh}
          disabled={busy}
          title="Refresh runs every doctor check now and ignores the 10 min cache."
          className="flex items-center gap-1 rounded px-2.5 py-1 text-[11.5px] font-medium border border-border bg-surface-2 hover:bg-surface-3 transition-colors disabled:opacity-60"
        >
          <RotateCw size={11} />
          {busy ? 'Reading' : 'Refresh'}
        </button>
      </div>
      {failed && (
        <div data-testid="doctor-failed" className="px-4 pb-3 text-[12px] text-warn">
          {failed}
        </div>
      )}
      {!detail && !failed && busy && (
        <div className="px-4 pb-3 text-[12px] text-dim"><LoadingInline>Reading the doctor rows</LoadingInline></div>
      )}
      {detail && rows.length === 0 && (
        <div className="px-4 pb-3 text-[12px] text-dim">The doctor returned no row.</div>
      )}
      {only && detail && shown.length === 0 && (
        <div className="px-4 pb-3 text-[12px] text-dim">No row is {only}.</div>
      )}
      {shown.length > 0 && (
        <ul className="divide-y divide-border-faint border-t border-border-faint">
          {shown.map((r, i) => {
            const grade = gradeOf(r.status);
            return (
              <li
                key={`${r.name}-${i}`}
                data-testid={`doctor-row-${r.name}`}
                className="flex items-start gap-2.5 px-4 py-2 text-[12px] leading-[1.5]"
              >
                <span
                  data-testid="doctor-status"
                  className="mt-px w-[44px] flex-none rounded-chip border px-1.5 py-px text-center font-mono text-[10px] font-semibold"
                  style={{ color: grade.color, borderColor: grade.border }}
                  title={grade.title}
                >
                  {r.status.toUpperCase()}
                </span>
                <div className="min-w-0 flex-1">
                  <span className="font-semibold text-text-2">{r.name}</span>
                  <span className="text-dim">: {utcTimesInText(r.detail)}</span>
                  {r.hint && (
                    // A remedy names a command in backticks. HelpText renders
                    // it as code (dogfood round 2, V2-3).
                    <div data-testid="doctor-fix" className="mt-0.5 text-faint">
                      <HelpText text={r.hint} />
                    </div>
                  )}
                  {(() => {
                    const fix = doctorFix(r);
                    return fix ? (
                      <FixControls
                        fix={fix}
                        settingTarget={resolveSetting}
                        onChangePassword={() => {
                          passwordReturn.current = document.activeElement as HTMLElement | null;
                          setPasswordOpen(true);
                        }}
                      />
                    ) : null;
                  })()}
                </div>
              </li>
            );
          })}
        </ul>
      )}
      {passwordOpen && (
        <ChangePasswordModal
          open
          onClose={() => setPasswordOpen(false)}
          returnFocusRef={passwordReturn}
        />
      )}
    </div>
  );
}
