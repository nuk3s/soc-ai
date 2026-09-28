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
  ackEvents,
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
  startHunt,
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

function renderAlerts() {
  render(
    <ToastProvider>
      <MemoryRouter initialEntries={['/alerts']}>
        <ShellProvider>
          <Alerts />
        </ShellProvider>
      </MemoryRouter>
    </ToastProvider>,
  );
}

async function pressAcknowledge() {
  renderAlerts();
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

// The per-event acknowledge button awaited its write inside try/finally with no
// catch: a 503 or a demo refusal escaped as an unhandled rejection, no notice
// was shown, and the button simply re-enabled, which reads as the write having
// landed. The sibling group path reports every failure and keeps the failed
// rows selected for a retry; the event path has to do the same.
describe('the loose-event acknowledge button', () => {
  // The shared beforeEach clears calls but not implementations, so the
  // rejection this block installs is reset here rather than leaking onward.
  // Block body on purpose: mockReset() returns the mock, and a function
  // returned from beforeEach runs as a cleanup hook after the test — which
  // would call the rejecting mock once more and fail the test on its own.
  beforeEach(() => {
    vi.mocked(ackEvents).mockReset();
  });

  it('reports a rejected acknowledge and keeps the selection for a retry', async () => {
    vi.mocked(getAlertGroupEvents).mockResolvedValue([
      { id: 'ev-1', src: '10.0.0.1', dst: '10.0.0.2', host: 'so-sensor', sev: 'high', ts: '2026-07-30T00:00:00Z' },
    ]);
    vi.mocked(ackEvents).mockImplementation(() => Promise.reject(new Error('grid unavailable')));
    renderAlerts();
    await screen.findByText(GROUP.name);

    // Expand the group, wait for its event row to RENDER (called is not
    // rendered), then tick that one event.
    const before = screen.getAllByRole('checkbox').length;
    fireEvent.click(screen.getByText(GROUP.name));
    await waitFor(() => expect(screen.getAllByRole('checkbox').length).toBeGreaterThan(before));
    const boxes = screen.getAllByRole('checkbox');
    fireEvent.click(boxes[boxes.length - 1]);

    fireEvent.click(await screen.findByText('Acknowledge 1 event'));
    await waitFor(() => expect(ackEvents).toHaveBeenCalledWith(['ev-1']));

    await screen.findByText('grid unavailable');
    // The failed selection stays, so the same click retries it.
    expect(screen.getByText('Acknowledge 1 event')).toBeTruthy();
    const after = screen.getAllByRole('checkbox');
    expect(after[after.length - 1].getAttribute('aria-checked')).toBe('true');
  });
});

// The row's Investigate button (also Retry, and the o/Enter/i keys) resolved
// the representative event, started the hunt, and on ANY rejection only closed
// the "Starting investigation…" drawer. A 409 because a hunt was already
// running, or a 503 from the grid, left the operator with a drawer that
// flashed and closed and nothing to say why; the single-event Investigate
// beside it quotes the server's sentence for exactly this case.
describe('the row Investigate button', () => {
  beforeEach(() => {
    vi.mocked(startHunt).mockReset();
  });

  it('quotes the refusal when the hunt cannot start, and takes the reason strip with it', async () => {
    vi.mocked(startHunt).mockImplementation(() => Promise.reject(new Error('hunt in progress')));
    renderAlerts();
    await screen.findByText(GROUP.name);

    fireEvent.click(screen.getAllByLabelText('Investigate')[0]);
    await waitFor(() => expect(startHunt).toHaveBeenCalledWith('rep'));

    await screen.findByText('hunt in progress');
    expect(screen.queryByText(/Starting investigation on/)).toBeNull();
    // The strip naming the chosen event described a hunt that never started.
    expect(screen.queryByText(/uses the representative event/)).toBeNull();
  });

  it('reports a failed representative lookup the same way', async () => {
    vi.mocked(getRepresentative).mockImplementation(() => Promise.reject(new Error('grid unavailable')));
    renderAlerts();
    await screen.findByText(GROUP.name);

    fireEvent.click(screen.getAllByLabelText('Investigate')[0]);
    await waitFor(() => expect(getRepresentative).toHaveBeenCalled());

    await screen.findByText('grid unavailable');
    expect(startHunt).not.toHaveBeenCalled();
  });
});
