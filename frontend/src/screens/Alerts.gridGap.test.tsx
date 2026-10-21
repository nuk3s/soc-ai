// The Alerts list names a grid gap inside the page window (2026-10-19).
//
// The range grid was down for 93 hours. After it came back, the list read the
// hole as a quiet grid, and the empty state said the window held no alert.
// The strip above the list names each recorded gap that overlaps the window.
// It shows over a list with rows and over the empty state.
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AlertGroup, GridGap } from '../lib/types';
import { absoluteTime } from '../lib/timeRange';

vi.mock('../lib/api', async (importOriginal) => {
  const orig = await importOriginal<typeof import('../lib/api')>();
  return {
    ...orig,
    getAlerts: vi.fn(),
    getAlertsEmptyReason: vi.fn(),
    getMe: vi.fn(),
    getAlertGroupEvents: vi.fn(),
    getInvestigation: vi.fn(() => new Promise(() => {})),
    getRepresentative: vi.fn(),
    startHunt: vi.fn(),
    ackGroup: vi.fn(),
    escalateGroup: vi.fn(),
    assignAlert: vi.fn(),
    startAutoTriage: vi.fn(),
    getAutoTriageStatus: vi.fn(),
    stopAutoTriage: vi.fn(),
    listSavedViews: vi.fn(),
    getGridGaps: vi.fn(),
  };
});

import {
  getAlerts,
  getAlertsEmptyReason,
  getAutoTriageStatus,
  getGridGaps,
  getMe,
  listSavedViews,
} from '../lib/api';
import { queueOf } from '../test/alertQueue';
import { Alerts } from './Alerts';
import { ShellProvider } from '../shell/ShellContext';

const GAP: GridGap = {
  id: 1,
  source: 'probe',
  plane: null,
  started_at: '2026-10-15T13:36:00Z',
  ended_at: '2026-10-19T10:15:00Z',
  open: false,
  duration_s: 333_540,
  detail: 'Elasticsearch did not answer the health probe.',
};

const GAP_TEXT =
  `The grid was unreadable from ${absoluteTime('2026-10-15T13:36:00Z')} to ${absoluteTime('2026-10-19T10:15:00Z')} (93 h). Counts in this window are incomplete.`;

const mkGroup = (o: Partial<AlertGroup> = {}): AlertGroup => ({
  id: 'es-1',
  name: 'ET SCAN Test Detection',
  kind: 'suricata',
  sev: 'high',
  count: 3,
  verdict: 'untriaged',
  conf: null,
  latest: '1m ago',
  inherited: false,
  events: [],
  ...o,
});

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(getAlerts).mockResolvedValue(queueOf([mkGroup()]));
  vi.mocked(getAlertsEmptyReason).mockResolvedValue({
    reason: 'gap',
    hint: 'This window overlaps a grid gap of 93 h.',
  });
  vi.mocked(getMe).mockResolvedValue({ username: 'me', role: 'analyst', status: '' });
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
    gaps: [GAP],
  }));
});

const mount = () =>
  render(
    <MemoryRouter initialEntries={['/alerts']}>
      <ShellProvider>
        <Alerts />
      </ShellProvider>
    </MemoryRouter>,
  );

describe('the Alerts grid gap strip', () => {
  it('names the gap above a list with rows', async () => {
    mount();
    await screen.findByText('ET SCAN Test Detection');
    expect((await screen.findByTestId('grid-gap')).textContent).toBe(GAP_TEXT);
  });

  it('names the gap above the empty state', async () => {
    vi.mocked(getAlerts).mockResolvedValue(queueOf([]));
    mount();
    await waitFor(() => expect(document.querySelector('[data-empty-reason="gap"]')).not.toBeNull());
    expect((await screen.findByTestId('grid-gap')).textContent).toBe(GAP_TEXT);
    expect(screen.getByText('This window overlaps a grid gap of 93 h.')).toBeTruthy();
  });
});
