import { RotateCw } from 'lucide-react';
import { useEffect, useState } from 'react';

import { ApiError, getPreflightDetail, refreshPreflight } from '../lib/api';
import type { PreflightDetail, PreflightRow } from '../lib/types';
import { absTime, ago } from '../lib/timeRange';

// ---------------------------------------------------------------------------
// Every doctor row, in the order the doctor writes them.
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

export function DoctorList() {
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
  return (
    <div data-testid="doctor-list" className="border-t border-border-faint">
      <div className="flex flex-wrap items-center gap-2 px-4 py-2.5">
        <span className="text-[12.5px] font-semibold text-text-2">Doctor</span>
        {detail && (
          <span className="text-[11.5px] text-dim" title={absTime(detail.checked_at)}>
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
          {busy ? 'Reading…' : 'Refresh'}
        </button>
      </div>
      {failed && (
        <div data-testid="doctor-failed" className="px-4 pb-3 text-[12px] text-warn">
          {failed}
        </div>
      )}
      {!detail && !failed && busy && (
        <div className="px-4 pb-3 text-[12px] text-dim">Reading the doctor rows…</div>
      )}
      {detail && rows.length === 0 && (
        <div className="px-4 pb-3 text-[12px] text-dim">The doctor returned no row.</div>
      )}
      {rows.length > 0 && (
        <ul className="divide-y divide-border-faint border-t border-border-faint">
          {rows.map((r, i) => {
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
                  <span className="text-dim">: {r.detail}</span>
                  {r.hint && (
                    <div data-testid="doctor-fix" className="mt-0.5 text-faint">
                      {r.hint}
                    </div>
                  )}
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
