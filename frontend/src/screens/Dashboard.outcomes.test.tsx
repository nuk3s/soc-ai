// The outcome breakdown counts each detection group under the worst verdict
// among its alerts (prod 2026-10-13). The rule "GPL SHELLCODE x86 setuid 0"
// held one true positive and five later false positives on other sources.
// The breakdown took the verdict of the newest run and read "True positive 0",
// while the true-positive tile and the Investigations list both read 1.
//
// A run in flight and a pipeline fallback must not hide a settled verdict
// either: each one is a newer run of the rule, the same as the false positives.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { AlertGroup, Verdict } from '../lib/types';

const group = (id: string, verdict: Verdict, over: Partial<AlertGroup> = {}): AlertGroup => ({
  id,
  name: `ET TEST ${id}`,
  kind: 'suricata',
  sev: 'high',
  count: 3,
  verdict,
  conf: verdict === 'untriaged' ? null : 0.8,
  latest: '2m ago',
  inherited: false,
  events: [],
  ...over,
});

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAlerts: vi.fn().mockResolvedValue({ groups: [], truncated: false, other_docs: 0 }),
  getDossierConflicts: vi.fn().mockResolvedValue({ pending: 0, rows: [] }),
  getQualityEvalStatus: vi.fn().mockResolvedValue({ running: false }),
  listInvestigations: vi.fn().mockResolvedValue({ rows: [], total: 0, running: 0, truePositives: 1, totalAll: 0, active: false, limit: 100, offset: 0 }),
  getAutoTriageStatus: vi.fn().mockResolvedValue({ active: false, hunted: 0, total: 0 }),
  getDataSources: vi.fn().mockResolvedValue({ sources: [] }),
  getQualityTrend: vi.fn().mockResolvedValue({ points: [] }),
  getHealth: vi.fn().mockResolvedValue(null),
  getDetectionTuningSummary: vi.fn().mockResolvedValue(null),
  getMe: vi.fn().mockResolvedValue({ username: 'ana', role: 'analyst', status: '' }),
  getPreflight: vi.fn().mockResolvedValue({ status: 'green', failing: 0, warned: 0, checked_at: '2026-08-19T00:00:00+00:00' }),
  getPreflightDetail: vi.fn().mockResolvedValue({ rows: [], checked_at: '2026-08-19T00:00:00+00:00' }),
  getNeedsYouCount: vi.fn().mockResolvedValue({
    leads_needing_decision: 0,
    unread_shadow_hits: 0,
    untriaged_groups: 0,
    needs_more_info: 0,
    pending_actions: 0,
    total: 0,
    unknown: [],
    alert_window: '7d',
    verdict_window: '30d',
    alert_floor: false,
  }),
}));

import { queueOf } from '../test/alertQueue';
import { Dashboard } from './Dashboard';
import { getAlerts } from '../lib/api';

const mount = async (groups: AlertGroup[]) => {
  vi.mocked(getAlerts).mockResolvedValue(queueOf(groups));
  render(
    <MemoryRouter initialEntries={['/']}>
      <Dashboard />
    </MemoryRouter>,
  );
  await screen.findByText('Investigation outcomes');
};

/** The number on the breakdown tile for one verdict. */
const count = async (label: string): Promise<string> => {
  const btn = (await screen.findByText(label)).closest('button')!;
  return btn.lastElementChild!.textContent ?? '';
};

describe('Dashboard outcome breakdown: the verdict each group counts under', () => {
  it('counts a true positive that later false positives followed', async () => {
    await mount([
      group('g-buried', 'false_positive', {
        verdictCounts: { false_positive: 19, true_positive: 1 },
        worstVerdict: 'true_positive',
        worstConf: 0.75,
        worstInvId: 'INV-TP',
      }),
      group('g-fp', 'false_positive'),
    ]);
    expect(await count('True positive')).toBe('1');
    expect(await count('False positive')).toBe('1');
  });

  it('keeps counting a settled verdict while a new run is in flight', async () => {
    await mount([group('g-run', 'true_positive', { triaging: true })]);
    expect(await count('True positive')).toBe('1');
  });

  it('does not count a group in flight with no verdict as untriaged', async () => {
    // NEGATIVE CONTROL. The first run of a group is not "awaiting triage".
    await mount([group('g-new', 'untriaged', { triaging: true })]);
    expect(await count('Untriaged')).toBe('0');
  });

  it('counts the true positive that a pipeline fallback followed', async () => {
    await mount([
      group('g-fb-tp', 'needs_more_info', { fallback: true, worstVerdict: 'true_positive' }),
      group('g-fb', 'needs_more_info', { fallback: true }),
    ]);
    expect(await count('True positive')).toBe('1');
    // NEGATIVE CONTROL. A fallback with nothing worse is a pipeline error,
    // counted on its own tile, and never a "needs more info".
    expect(await count('Needs more info')).toBe('0');
  });
});

// Runs made inside the page window decide the verdict of a group (owner rule,
// 2026-10-14). A group with no run in the window keeps the older verdict that
// covers it, and the panel states how many groups carry such a verdict.
describe('Dashboard outcome breakdown: the window verdict', () => {
  it('counts a group under the worst verdict of its runs in the window', async () => {
    await mount([
      group('g-win', 'false_positive', {
        verdictCounts: { false_positive: 2, true_positive: 1 },
        windowVerdict: 'true_positive',
        windowConf: 0.62,
        windowInvId: 'INV-TP',
      }),
    ]);
    expect(await count('True positive')).toBe('1');
    expect(await count('False positive')).toBe('0');
  });

  it('does not count a true positive from outside the window', async () => {
    // NEGATIVE CONTROL. The standing true positive ran after the end of a
    // custom window. The runs inside the window are false positives.
    await mount([
      group('g-out', 'true_positive', {
        verdictCounts: { false_positive: 2 },
        windowVerdict: 'false_positive',
        windowConf: 0.9,
        windowInvId: 'INV-FP',
      }),
    ]);
    expect(await count('True positive')).toBe('0');
    expect(await count('False positive')).toBe('1');
  });

  it('counts an inherited verdict and states how many groups carry one', async () => {
    await mount([
      group('g-old', 'true_positive', { windowVerdict: null, verdictAt: '2026-10-10T09:00:00+00:00' }),
      group('g-win', 'false_positive', { windowVerdict: 'false_positive', verdictCounts: { false_positive: 1 } }),
      group('g-new', 'untriaged', { windowVerdict: null }),
    ]);
    expect(await count('True positive')).toBe('1');
    expect(await count('Untriaged')).toBe('1');
    expect(screen.getByTestId('outcome-inherited').textContent).toBe(
      '1 of 3 groups: verdict inherited from a run before this window.',
    );
  });

  it('states nothing about inheritance when every verdict comes from the window', async () => {
    // NEGATIVE CONTROL. An untriaged group inherits nothing.
    await mount([
      group('g-win', 'false_positive', { windowVerdict: 'false_positive' }),
      group('g-new', 'untriaged', { windowVerdict: null }),
    ]);
    expect(screen.queryByTestId('outcome-inherited')).toBeNull();
  });
});
