// The smoke test of the Alerts tour. It renders the page with a gap in the
// window and a row that shares its flow with another detection, and checks
// that every anchor the tour names is on the page. A renamed or removed
// `data-tour` attribute fails here.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ToastProvider } from '../lib/toast';
import type { AlertGroup, AlertSibling, GridGap } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => {
  const orig = await importOriginal<typeof import('../lib/api')>();
  return {
    ...orig,
    getAlerts: vi.fn(),
    getAlertsEmptyReason: vi.fn(() => new Promise(() => {})),
    getMe: vi.fn(),
    getAlertGroupEvents: vi.fn(),
    getInvestigation: vi.fn(() => new Promise(() => {})),
    getRepresentative: vi.fn(),
    startHunt: vi.fn(),
    ackGroup: vi.fn(),
    ackEvents: vi.fn(),
    escalateGroup: vi.fn(),
    assignAlert: vi.fn(),
    startAutoTriage: vi.fn(),
    getAutoTriageStatus: vi.fn(),
    stopAutoTriage: vi.fn(),
    listSavedViews: vi.fn(),
    getGridGaps: vi.fn(),
  };
});

import { getAlerts, getAutoTriageStatus, getGridGaps, getMe, listSavedViews } from '../lib/api';
import { queueOf } from '../test/alertQueue';
import { ALERTS_TOUR } from '../tours/content';
import { missingAnchors } from '../tours/testing';
import { ShellProvider } from '../shell/ShellContext';
import { Alerts } from './Alerts';

const HOUR = 3_600_000;
const SCAN = 'ET SCAN Example Port Sweep';
const LOGIN = 'ET POLICY Example Cleartext Login';

const sib = (o: Partial<AlertSibling> = {}): AlertSibling => ({
  name: LOGIN,
  kind: 'suricata',
  verdict: 'true_positive',
  conf: 0.7,
  invId: 'inv-login',
  signals: ['hosts'],
  ...o,
});

const mkGroup = (o: Partial<AlertGroup> = {}): AlertGroup => ({
  id: `es-${o.name ?? SCAN}`,
  name: SCAN,
  kind: 'suricata',
  sev: 'high',
  count: 4,
  verdict: 'false_positive',
  conf: 0.8,
  invId: 'inv-scan',
  latest: '5m ago',
  latestTs: new Date(Date.now() - 5 * 60_000).toISOString(),
  inherited: false,
  events: [],
  ackedCount: 0,
  escalatedCount: 0,
  src: '192.0.2.20',
  dst: '198.51.100.40',
  siblings: [sib()],
  siblingCount: 1,
  cases: [],
  ...o,
});

/** A closed gap inside the default 24 hour window, relative to now. */
const gap = (): GridGap => ({
  id: 1,
  source: 'probe',
  plane: null,
  started_at: new Date(Date.now() - 6 * HOUR).toISOString(),
  ended_at: new Date(Date.now() - 4 * HOUR).toISOString(),
  open: false,
  duration_s: 2 * 3_600,
  detail: 'Elasticsearch did not answer the health probe.',
});

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(getAlerts).mockResolvedValue(
    queueOf([
      mkGroup(),
      mkGroup({
        name: LOGIN,
        sev: 'medium',
        verdict: 'true_positive',
        invId: 'inv-login',
        src: '198.51.100.40',
        dst: '192.0.2.20',
        siblings: [sib({ name: SCAN, verdict: 'false_positive', invId: 'inv-scan' })],
      }),
    ]),
  );
  vi.mocked(getMe).mockResolvedValue({ username: 'analyst', role: 'analyst', status: '' });
  vi.mocked(getAutoTriageStatus).mockResolvedValue({
    active: false,
    total: 0,
    hunted: 0,
    skipped: 0,
    failed: 0,
  } as never);
  vi.mocked(listSavedViews).mockResolvedValue([]);
  vi.mocked(getGridGaps).mockImplementation(async (window) => ({
    since: window.since,
    until: window.until ?? new Date().toISOString(),
    gaps: [gap()],
  }));
});

function renderAlerts() {
  return render(
    <ToastProvider>
      <MemoryRouter initialEntries={['/alerts']}>
        <ShellProvider>
          <Alerts />
        </ShellProvider>
      </MemoryRouter>
    </ToastProvider>,
  );
}

describe('the Alerts tour', () => {
  it('finds every anchor it names on a page with rows and a grid gap', async () => {
    renderAlerts();
    await screen.findByText(SCAN);
    await screen.findByTestId('grid-gap-strip');
    expect(missingAnchors(ALERTS_TOUR)).toEqual([]);
  });

  it('puts the row anchors on the first row only', async () => {
    renderAlerts();
    await screen.findByText(SCAN);
    for (const anchor of ['alerts-row', 'alerts-select', 'alerts-row-actions']) {
      expect(document.querySelectorAll(`[data-tour="${anchor}"]`)).toHaveLength(1);
    }
    const first = document.querySelector('[data-group-key]');
    expect(first?.querySelector('[data-tour="alerts-row"]')).not.toBeNull();
  });
});
