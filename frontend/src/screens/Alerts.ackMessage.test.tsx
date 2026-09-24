// What the acknowledge strip says after a press.
//
// The button used to report "Acknowledged N alerts" and, over the cap, "press a
// again to finish". Both sentences were true of the write and false of the
// outcome: on Elastic Defend's endpoint alert index Security Onion cannot hide
// an acknowledged alert from a query, so the rows stayed and every further
// press re-acknowledged the same events and said the same thing. The operator
// had no way to tell a working button from a broken one.
//
// These tests hold the two facts the strip now has to separate: how much is
// left for another press, and how much the grid will keep showing whatever
// anyone does.
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
    startHunt: vi.fn(),
    ackGroup: vi.fn(),
    ackEvents: vi.fn(),
    escalateGroup: vi.fn(),
    assignAlert: vi.fn(),
    startAutoTriage: vi.fn(),
    getAutoTriageStatus: vi.fn(),
    stopAutoTriage: vi.fn(),
    getWorkspaces: vi.fn(),
    getNotifications: vi.fn(),
    getHealth: vi.fn(),
    listSavedViews: vi.fn(),
    signOut: vi.fn(),
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
  ackGroup,
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
import { queueOf } from '../test/alertQueue';
import { Alerts } from './Alerts';
import { ShellProvider } from '../shell/ShellContext';

const GROUP: AlertGroup = {
  id: 'es-1',
  name: 'Ingress Tool Transfer via CURL',
  kind: 'suricata',
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
  vi.mocked(getAlerts).mockResolvedValue(queueOf([GROUP]));
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

async function pressAcknowledge() {
  render(
    <ToastProvider>
      <MemoryRouter initialEntries={['/alerts']}>
        <ShellProvider>
          <Alerts />
        </ShellProvider>
      </MemoryRouter>
    </ToastProvider>,
  );
  await screen.findByText(GROUP.name);
  await act(async () => {
    fireEvent.keyDown(window, { key: 'j' });
  });
  await act(async () => {
    fireEvent.keyDown(window, { key: 'a' });
  });
  await waitFor(() => expect(ackGroup).toHaveBeenCalled());
}

describe('the acknowledge strip', () => {
  it('says how many are left and that another press continues', async () => {
    vi.mocked(ackGroup).mockResolvedValue({
      acked: 199,
      failed: 0,
      total: 199,
      capped: true,
      already_acked: 0,
      remaining: 1332,
    } as never);

    await pressAcknowledge();

    const strip = await screen.findByText(/Acknowledged 199 alerts/);
    expect(strip.textContent).toMatch(/1,332 alerts left/);
    expect(strip.textContent).toMatch(/Press again to continue/);
  });

  it('names the alerts the grid will keep listing however many times it is pressed', async () => {
    // The endpoint-alert case: everything is already acknowledged in Security
    // Onion and nothing is left to write, yet the group will not shrink.
    vi.mocked(ackGroup).mockResolvedValue({
      acked: 0,
      failed: 0,
      total: 0,
      capped: false,
      already_acked: 17,
      remaining: 0,
    } as never);

    await pressAcknowledge();

    const strip = await screen.findByText(/Acknowledged 0 alerts/);
    expect(strip.textContent).toMatch(/17 alerts already acknowledged in Security Onion/);
    expect(strip.textContent).toMatch(/stay listed/);
    // Nothing is outstanding, so it must not ask for another press.
    expect(strip.textContent).not.toMatch(/press again/);
  });

  it('says nothing extra when the group is simply done', async () => {
    vi.mocked(ackGroup).mockResolvedValue({
      acked: 12,
      failed: 0,
      total: 12,
      capped: false,
      already_acked: 0,
      remaining: 0,
    } as never);

    await pressAcknowledge();

    const strip = await screen.findByText(/Acknowledged 12 alerts/);
    expect(strip.textContent).not.toMatch(/left/);
    expect(strip.textContent).not.toMatch(/already acknowledged/);
  });
});
