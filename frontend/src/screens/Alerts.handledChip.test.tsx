// What the row says about work already done — and about work it cannot see.
//
// The green check chip is drawn from a count the server derives from an
// Elasticsearch filter aggregation. On Elastic Defend's endpoint alert index
// that aggregation cannot reach `event.acknowledged`, so it answers 0 for a
// group an analyst cleared this morning exactly as it does for one nobody has
// opened. The server now sends `null` for those groups instead of 0.
//
// A `?? 0` on the way in would turn that null straight back into the lie. These
// tests hold the three renderings apart: a number, nothing, and a chip that
// says the question has no answer here.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { ToastProvider } from '../lib/toast';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AlertGroup } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => {
  const orig = await importOriginal<typeof import('../lib/api')>();
  return {
    ...orig,
    getAlerts: vi.fn(),
    getMe: vi.fn(),
    getAlertGroupEvents: vi.fn(),
    getInvestigation: vi.fn(() => new Promise(() => {})),
    getInvestigations: vi.fn(),
    getRepresentative: vi.fn(),
    getAutoTriageStatus: vi.fn(),
    getWorkspaces: vi.fn(),
    getNotifications: vi.fn(),
    getHealth: vi.fn(),
    listSavedViews: vi.fn(),
  };
});
vi.mock('../lib/notifications', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/notifications')>()),
  getDismissed: () => new Set<string>(),
  dismissNotification: vi.fn(),
  dismissMany: vi.fn(),
  formatNotificationTitle: (t: string) => t,
}));

import {
  getAlertGroupEvents,
  getAlerts,
  getAutoTriageStatus,
  getHealth,
  getInvestigations,
  getMe,
  getNotifications,
  getRepresentative,
  getWorkspaces,
  listSavedViews,
} from '../lib/api';
import { Alerts } from './Alerts';
import { ShellProvider } from '../shell/ShellContext';
import { queueOf } from '../test/alertQueue';

const GROUP: AlertGroup = {
  id: 'es-1',
  name: 'Malicious Behavior Detection Alert',
  kind: 'alert',
  sev: 'high',
  count: 16,
  verdict: 'untriaged',
  conf: null,
  latest: '1m ago',
  inherited: false,
  events: [],
};

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(getAlertGroupEvents).mockResolvedValue([]);
  vi.mocked(getMe).mockResolvedValue({ username: 'me', role: 'analyst', status: '' });
  vi.mocked(getInvestigations).mockResolvedValue([]);
  vi.mocked(getRepresentative).mockResolvedValue({ alert_id: 'rep', reason: 'x' } as never);
  vi.mocked(getAutoTriageStatus).mockResolvedValue({
    active: false,
    total: 0,
    hunted: 0,
    skipped: 0,
    failed: 0,
  } as never);
  vi.mocked(getWorkspaces).mockResolvedValue([]);
  vi.mocked(getNotifications).mockResolvedValue([]);
  vi.mocked(getHealth).mockResolvedValue({
    es: { ok: true, detail: '' },
    llm: { ok: true, detail: '' },
  } as never);
  vi.mocked(listSavedViews).mockResolvedValue([]);
});

async function showGroup(group: AlertGroup) {
  vi.mocked(getAlerts).mockResolvedValue(queueOf([group]));
  render(
    <ToastProvider>
      <MemoryRouter initialEntries={['/alerts']}>
        <ShellProvider>
          <Alerts />
        </ShellProvider>
      </MemoryRouter>
    </ToastProvider>,
  );
  await screen.findByText(group.name);
}

describe('the handled-count chips', () => {
  it('shows the number when the grid can count', async () => {
    await showGroup({ ...GROUP, ackedCount: 3, escalatedCount: 1 });
    expect(screen.getByTitle('3 acknowledged')).toBeTruthy();
    expect(screen.getByTitle('1 escalated')).toBeTruthy();
  });

  it('shows nothing when the grid counted zero', async () => {
    await showGroup({ ...GROUP, ackedCount: 0, escalatedCount: 0 });
    expect(screen.queryByTitle(/^\d+ acknowledged$/)).toBeNull();
    expect(screen.queryByTitle(/^The acknowledged count is unknown/)).toBeNull();
  });

  it('says the count is unknown rather than drawing nothing', async () => {
    // null, not 0 — the row must not read as untouched.
    await showGroup({ ...GROUP, ackedCount: null, escalatedCount: null });
    const acked = screen.getByTitle(/^The acknowledged count is unknown/);
    expect(acked.textContent).toBe('?');
    expect(acked.getAttribute('title')).toMatch(/cannot search the flag/);
    expect(screen.getByTitle(/^The escalated count is unknown/)).toBeTruthy();
    // And it must not have invented a number to put beside the question mark.
    expect(screen.queryByTitle(/^0 acknowledged/)).toBeNull();
  });
});
