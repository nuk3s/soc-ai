// The Investigations tour names anchors on the screen. This smoke test renders
// the list of waiting actions with data, so every anchor of the tour is on
// the page, and fails when a renamed or removed `data-tour` drops one.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ToastProvider } from '../lib/toast';
import type { InvestigationList, InvestigationRow, WaitingAction } from '../lib/types';
import { INVESTIGATIONS_TOUR } from '../tours/content';
import { missingAnchors } from '../tours/testing';

const escalate = (rule: string): WaitingAction => ({
  id: 'a0',
  index: 0,
  type: 'escalate',
  label: 'Escalate to case',
  target: rule,
  targetType: 'alert',
  rationale: 'The beacon matches a known C2 address.',
  executable: true,
  reason: null,
});

const row = (id: string, name: string, over: Partial<InvestigationRow> = {}): InvestigationRow => ({
  id,
  name,
  kind: 'suricata',
  verdict: 'true_positive',
  conf: 0.8,
  host: '192.0.2.10',
  dst: '198.51.100.7',
  status: 'complete',
  when: '2h',
  // Relative to now, so the row stays inside the window.
  ts: new Date(Date.now() - 2 * 3_600_000).toISOString(),
  alertId: `ev-${id}`,
  isPrimary: true,
  fallback: false,
  ranBy: 'scheduler',
  pendingActions: 1,
  waitingActions: [escalate(name)],
  ...over,
});

const list = (rows: InvestigationRow[]): InvestigationList => ({
  rows,
  total: rows.length,
  running: 0,
  truePositives: rows.length,
  totalAll: rows.length,
  active: false,
  limit: 50,
  offset: 0,
});

const listInvestigations = vi.hoisted(() => vi.fn());
const listSavedViews = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  listInvestigations,
  listSavedViews,
}));

import { Investigations } from './Investigations';

beforeEach(() => {
  listInvestigations.mockReset();
  listSavedViews.mockReset();
  listSavedViews.mockResolvedValue([]);
});

describe('the Investigations tour', () => {
  it('finds every anchor on the list of waiting actions', async () => {
    listInvestigations.mockResolvedValue(
      list([
        row('INV-A', 'ET MALWARE Known C2 Beacon'),
        row('INV-B', 'ET TROJAN Second Stage Download'),
      ]),
    );
    render(
      <MemoryRouter initialEntries={['/investigations?range=30d&actions=pending']}>
        <ToastProvider>
          <Investigations />
        </ToastProvider>
      </MemoryRouter>,
    );
    await screen.findByTestId('waiting-actions-INV-A');
    expect(missingAnchors(INVESTIGATIONS_TOUR)).toEqual([]);
    // One row carries the waiting-action anchor, so the step points at one row.
    expect(document.querySelectorAll('[data-tour="investigations-waiting-actions"]')).toHaveLength(1);
  });
});
