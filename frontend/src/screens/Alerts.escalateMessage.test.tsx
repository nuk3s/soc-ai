// What the strip says after a group escalate.
//
// It used to read "Escalated 1 of 1 event in <group> to a case · 17 events
// already escalated, not opening a second case". Measured on the range, that
// sentence was false in both directions at once: none of the seventeen had a
// case, so no second case was withheld from any of them, and the one alert that
// really did get a second case was reported as a clean escalate.
//
// Three things the operator now has to be able to tell apart: cases opened,
// cases withheld because one already exists, and alerts skipped because
// Security Onion had already acknowledged them.
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
  escalateGroup,
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
  name: 'Execution via Interactive Secondary Logon',
  kind: 'suricata',
  sev: 'high',
  count: 18,
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

async function pressEscalate() {
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
    fireEvent.keyDown(window, { key: 'e' });
  });
  await waitFor(() => expect(escalateGroup).toHaveBeenCalled());
}

describe('the escalate strip', () => {
  it('does not claim a duplicate was prevented where no case existed', async () => {
    // The first press on the live group: one case opened, seventeen alerts
    // skipped as acknowledged, and no case withheld from anything.
    vi.mocked(escalateGroup).mockResolvedValue({
      escalated: 1,
      failed: 0,
      total: 1,
      capped: false,
      already_escalated: 0,
      already_acked: 17,
      unresolved: 0,
      remaining: 0,
    } as never);

    await pressEscalate();

    const strip = await screen.findByText(/Opened 1 case/);
    expect(strip.textContent).toMatch(/17 alerts already acknowledged in Security Onion/);
    expect(strip.textContent).not.toMatch(/already on a case/);
  });

  it('says which alerts a second case was withheld from', async () => {
    // The second press: nothing to do, and the reason is a case that exists.
    vi.mocked(escalateGroup).mockResolvedValue({
      escalated: 0,
      failed: 0,
      total: 0,
      capped: false,
      already_escalated: 1,
      already_acked: 17,
      unresolved: 0,
      remaining: 0,
    } as never);

    await pressEscalate();

    const strip = await screen.findByText(/Opened no cases/);
    expect(strip.textContent).toMatch(/1 alert already on a case, no second case opened/);
    expect(strip.textContent).toMatch(/17 alerts already acknowledged in Security Onion/);
    expect(strip.textContent).not.toMatch(/press again/);
  });

  it('names alerts whose earlier escalate never came back', async () => {
    vi.mocked(escalateGroup).mockResolvedValue({
      escalated: 2,
      failed: 0,
      total: 2,
      capped: false,
      already_escalated: 0,
      already_acked: 0,
      unresolved: 1,
      remaining: 0,
    } as never);

    await pressEscalate();

    const strip = await screen.findByText(/Opened 2 cases/);
    expect(strip.textContent).toMatch(
      /1 alert from an earlier escalate whose outcome is unknown, left alone/,
    );
  });

  it('reports failures and what is left', async () => {
    vi.mocked(escalateGroup).mockResolvedValue({
      escalated: 23,
      failed: 2,
      total: 25,
      capped: true,
      already_escalated: 0,
      already_acked: 0,
      unresolved: 0,
      remaining: 40,
    } as never);

    await pressEscalate();

    const strip = await screen.findByText(/Opened 23 cases/);
    expect(strip.textContent).toMatch(/2 alerts failed/);
    expect(strip.textContent).toMatch(/40 alerts left\. Press again to continue/);
  });

  it('names the cases Security Onion created and attached nothing to', async () => {
    // The alert had rolled off the grid by the time the write ran, so Security
    // Onion made the case, matched no document, and attached nothing. The alert
    // is on no case and the case is empty, and only the operator can close or
    // reuse it, so it has to be named.
    vi.mocked(escalateGroup).mockResolvedValue({
      escalated: 0,
      failed: 1,
      total: 1,
      capped: false,
      already_escalated: 0,
      already_acked: 0,
      unresolved: 0,
      empty_cases: ['case-9f3'],
      remaining: 0,
    } as never);

    await pressEscalate();

    const strip = await screen.findByText(/Opened no cases/);
    expect(strip.textContent).toMatch(
      /1 case created with nothing attached, left empty in Security Onion: case-9f3/,
    );
  });

  it('says nothing extra when the group escalated cleanly', async () => {
    vi.mocked(escalateGroup).mockResolvedValue({
      escalated: 5,
      failed: 0,
      total: 5,
      capped: false,
      already_escalated: 0,
      already_acked: 0,
      unresolved: 0,
      remaining: 0,
    } as never);

    await pressEscalate();

    const strip = await screen.findByText(/Opened 5 cases/);
    expect(strip.textContent).not.toMatch(/already/);
    expect(strip.textContent).not.toMatch(/left/);
    expect(strip.textContent).not.toMatch(/failed/);
    expect(strip.textContent).not.toMatch(/nothing attached/);
  });
});
