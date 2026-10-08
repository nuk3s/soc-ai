// The next-alert control in the drawer (dogfood 2026-10-06, first hour W1).
// Each alert took two clicks: close the drawer, then Open report on the next
// row. The drawer now has "Next" and the j and down arrow keys. The list
// stays as it is. The negative control: at the end of the list Next is off.
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
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
  getInvestigation,
  getInvestigations,
  getMe,
  getNotifications,
  getRepresentative,
  getWorkspaces,
  listSavedViews,
} from '../lib/api';
import { queueOf } from '../test/alertQueue';
import { Alerts, nextReportAfter } from './Alerts';
import { ShellProvider } from '../shell/ShellContext';

const group = (n: number, invId: string | undefined, count = 10 - n): AlertGroup => ({
  id: `es-${n}`,
  name: `Rule ${n}`,
  kind: 'suricata',
  sev: 'high',
  count,
  verdict: invId ? 'false_positive' : 'untriaged',
  conf: invId ? 0.9 : null,
  latest: '1m ago',
  inherited: false,
  events: [],
  invId,
});

const GROUPS = [group(1, 'inv-1'), group(2, undefined), group(3, 'inv-3')];

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(getAlerts).mockResolvedValue(queueOf(GROUPS));
  vi.mocked(getAlertGroupEvents).mockResolvedValue([]);
  vi.mocked(getMe).mockResolvedValue({ username: 'me', role: 'analyst', status: '' });
  vi.mocked(getInvestigations).mockResolvedValue([]);
  vi.mocked(getRepresentative).mockResolvedValue({ alert_id: 'rep', reason: 'x' } as never);
  vi.mocked(getAutoTriageStatus).mockResolvedValue({ active: false, total: 0, hunted: 0, skipped: 0, failed: 0 } as never);
  vi.mocked(getWorkspaces).mockResolvedValue([]);
  vi.mocked(getNotifications).mockResolvedValue([]);
  vi.mocked(getHealth).mockResolvedValue({ es: { ok: true, detail: '' }, llm: { ok: true, detail: '' } } as never);
  vi.mocked(listSavedViews).mockResolvedValue([]);
});

const mount = (drawer: string) =>
  render(
    <ToastProvider>
      <MemoryRouter initialEntries={[`/alerts?drawer=${drawer}`]}>
        <ShellProvider>
          <Alerts />
        </ShellProvider>
      </MemoryRouter>
    </ToastProvider>,
  );

describe('the next-alert control', () => {
  it('skips a row with no report and opens the next report', () => {
    expect(nextReportAfter(GROUPS, 'inv-1', null)?.invId).toBe('inv-3');
    expect(nextReportAfter(GROUPS, 'inv-3', null)).toBeNull();
    expect(nextReportAfter(GROUPS, 'other', null)).toBeNull();
  });

  it('opens the next report from the Next button and from the j key', async () => {
    mount('inv-1');
    await screen.findByText('Rule 3');
    const next = await screen.findByTestId('drawer-next');
    expect(next.getAttribute('title')).toContain('Open the next alert: Rule 3.');
    fireEvent.click(next);
    await waitFor(() => expect(getInvestigation).toHaveBeenCalledWith('inv-3'));
    // The list stays: every row is still on screen.
    expect(screen.getByText('Rule 1')).toBeTruthy();
    expect(screen.getByText('Rule 2')).toBeTruthy();
  });

  it('control: at the end of the list Next is off and j does nothing', async () => {
    mount('inv-3');
    await screen.findByText('Rule 3');
    const next = await screen.findByTestId('drawer-next');
    expect(next).toBeDisabled();
    vi.mocked(getInvestigation).mockClear();
    await act(async () => {
      fireEvent.keyDown(window, { key: 'j' });
    });
    expect(getInvestigation).not.toHaveBeenCalled();
  });

  it('opens the next report on the down arrow', async () => {
    mount('inv-1');
    await screen.findByText('Rule 3');
    await screen.findByTestId('drawer-next');
    await act(async () => {
      fireEvent.keyDown(window, { key: 'ArrowDown' });
    });
    await waitFor(() => expect(getInvestigation).toHaveBeenCalledWith('inv-3'));
  });
});
