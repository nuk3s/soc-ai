// Write UX on the Alerts console (dogfood 2026-10-01: RL1, RL2, RL7, RL9).
//
// RL2: on a slow grid the client gave up at 20 s and said "Could not escalate"
// while the case landed 60 to 75 s later. The red toast stayed after the row
// was gone. RL1: a group write cleared the group box and left its expanded
// event boxes ticked, under a bar whose group buttons then did nothing. RL7:
// the escalate toast named no case. RL9: the owner avatar released a group with
// no toast and no pending state.
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ToastProvider } from '../lib/toast';
import type { AlertEvent, AlertGroup } from '../lib/types';

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
  };
});

import {
  RequestTimeoutError,
  SO_WRITE_TIMEOUT_MS,
  WRITE_TIMEOUT_NOTE,
  assignAlert,
  escalateGroup,
  getAlertGroupEvents,
  getAlerts,
  getAutoTriageStatus,
  getMe,
  listSavedViews,
} from '../lib/api';
import { queueOf } from '../test/alertQueue';
import { Alerts } from './Alerts';
import { ShellProvider } from '../shell/ShellContext';

const mkGroup = (o: Partial<AlertGroup> = {}): AlertGroup => ({
  id: 'es-1',
  name: 'NTLM Session Setup',
  kind: 'suricata',
  sev: 'high',
  count: 2,
  verdict: 'untriaged',
  conf: null,
  latest: '1m ago',
  inherited: false,
  events: [],
  escalatedCount: 0,
  ackedCount: 0,
  ...o,
});
const mkEvent = (id: string, dst: string): AlertEvent => ({
  id,
  src: '192.0.2.10',
  dst,
  host: 'sensor',
  ts: '2026-09-30T00:00:00Z',
});

const TIMEOUT_COPY =
  'The request did not return in 90 s. The grid is slow. The change may still land. Check the row in a minute.';

let intervalSpy: { mock: { calls: unknown[][] }; mockRestore: () => void };

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(getAlerts).mockResolvedValue(queueOf([mkGroup()]));
  vi.mocked(getAlertGroupEvents).mockResolvedValue([]);
  vi.mocked(getMe).mockResolvedValue({ username: 'me', role: 'analyst', status: '' });
  vi.mocked(getAutoTriageStatus).mockResolvedValue({
    active: false,
    total: 0,
    hunted: 0,
    skipped: 0,
    failed: 0,
  } as never);
  vi.mocked(listSavedViews).mockResolvedValue([]);
  intervalSpy = vi.spyOn(window, 'setInterval');
});

afterEach(() => {
  intervalSpy.mockRestore();
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

/** The alerts screen's 10 s poll, driven by hand. */
async function poll() {
  const call = intervalSpy.mock.calls.find((c) => c[1] === 10000);
  expect(call).toBeTruthy();
  await act(async () => {
    (call![0] as () => void)();
  });
}

async function pressEscalateKey() {
  await screen.findByText('NTLM Session Setup');
  await act(async () => {
    fireEvent.keyDown(window, { key: 'j' });
  });
  await act(async () => {
    fireEvent.keyDown(window, { key: 'e' });
  });
}

const timedOut = () => new RequestTimeoutError(SO_WRITE_TIMEOUT_MS, WRITE_TIMEOUT_NOTE);

describe('a write the console stopped waiting for (RL2)', () => {
  it('says the change may still land, then clears the notice when the poll shows it landed', async () => {
    vi.mocked(escalateGroup).mockRejectedValue(timedOut());
    renderAlerts();
    await pressEscalateKey();

    const notice = await screen.findByText(new RegExp(TIMEOUT_COPY.replace(/\./g, '\\.')));
    expect(notice.textContent).toContain('NTLM Session Setup');
    expect(screen.queryByText(/Could not escalate/)).toBeNull();

    // The case landed late: hide-acknowledged drops the escalated group.
    vi.mocked(getAlerts).mockResolvedValue(queueOf([]));
    await poll();

    await waitFor(() => expect(screen.queryByText(/did not return in 90 s/)).toBeNull());
    expect(screen.getByText('The escalate of NTLM Session Setup landed.')).toBeTruthy();
  });

  it('NEGATIVE CONTROL: keeps the notice while the poll shows nothing changed', async () => {
    vi.mocked(escalateGroup).mockRejectedValue(timedOut());
    renderAlerts();
    await pressEscalateKey();
    await screen.findByText(/did not return in 90 s/);

    await poll(); // same row, same escalated count
    await act(async () => {});

    expect(screen.getByText(/did not return in 90 s/)).toBeTruthy();
    expect(screen.queryByText(/landed\./)).toBeNull();
  });

  it('NEGATIVE CONTROL: a real refusal still reads as a failure', async () => {
    vi.mocked(escalateGroup).mockRejectedValue(new Error('Security Onion refused the write.'));
    renderAlerts();
    await pressEscalateKey();
    expect(await screen.findByText(/Could not escalate NTLM Session Setup/)).toBeTruthy();
  });

  it('shows a pending line while the escalate is in flight', async () => {
    let finish: (v: unknown) => void = () => {};
    vi.mocked(escalateGroup).mockReturnValue(new Promise((r) => { finish = r; }) as never);
    renderAlerts();
    await pressEscalateKey();

    expect(await screen.findByText('Security Onion opens cases for NTLM Session Setup.')).toBeTruthy();
    await act(async () => {
      finish({ escalated: 1, failed: 0, total: 1, capped: false, cases: [] });
    });
    await waitFor(() =>
      expect(screen.queryByText('Security Onion opens cases for NTLM Session Setup.')).toBeNull(),
    );
  });
});

describe('the escalate toast names its cases (RL7)', () => {
  it('names each case id and links the case in Security Onion', async () => {
    vi.mocked(escalateGroup).mockResolvedValue({
      escalated: 2,
      failed: 0,
      total: 2,
      capped: false,
      cases: [
        { id: 'case-a1', url: 'https://so.example.test/#/case/case-a1' },
        { id: 'case-b2', url: null },
      ],
    });
    renderAlerts();
    await pressEscalateKey();

    const text = await screen.findByText(/Opened 2 cases for NTLM Session Setup: case-a1, case-b2/);
    expect(text).toBeTruthy();
    const link = screen.getByRole('link', { name: 'Open case case-a1' });
    expect(link.getAttribute('href')).toBe('https://so.example.test/#/case/case-a1');
    // A case with no console URL is named, not linked.
    expect(screen.queryByRole('link', { name: 'Open case case-b2' })).toBeNull();
  });

  it('offers Escalate in the bulk bar, not only on the `e` key', async () => {
    vi.mocked(escalateGroup).mockResolvedValue({ escalated: 1, failed: 0, total: 1, capped: false });
    renderAlerts();
    await screen.findByText('NTLM Session Setup');
    fireEvent.click(screen.getByRole('checkbox', { name: 'Select NTLM Session Setup' }));
    const strip = await screen.findByTestId('list-toolbar-selection');
    fireEvent.click(within(strip).getByRole('button', { name: 'Escalate to cases' }));
    await waitFor(() => expect(escalateGroup).toHaveBeenCalledTimes(1));
    expect(vi.mocked(escalateGroup).mock.calls[0][0].name).toBe('NTLM Session Setup');
  });
});

describe('a group write clears the event boxes the group ticked (RL1)', () => {
  it('leaves no ticked event and no dead group button after Assign to me', async () => {
    vi.mocked(getAlertGroupEvents).mockResolvedValue([
      mkEvent('ev-1', '198.51.100.11'),
      mkEvent('ev-2', '198.51.100.12'),
    ]);
    vi.mocked(assignAlert).mockResolvedValue({ rule_name: 'NTLM Session Setup', owner: 'me' });
    renderAlerts();
    await screen.findByText('NTLM Session Setup');
    fireEvent.click(screen.getByText('NTLM Session Setup')); // expand
    await waitFor(() => expect(screen.getAllByRole('checkbox').length).toBeGreaterThan(2));

    fireEvent.click(screen.getByRole('checkbox', { name: 'Select NTLM Session Setup' }));
    const strip = await screen.findByTestId('list-toolbar-selection');
    fireEvent.click(within(strip).getByRole('button', { name: 'Assign to me' }));
    await waitFor(() => expect(assignAlert).toHaveBeenCalled());

    await waitFor(() => expect(screen.queryByTestId('list-toolbar-selection')).toBeNull());
    const ticked = screen
      .getAllByRole('checkbox')
      .filter((b) => b.getAttribute('aria-checked') === 'true' || (b as HTMLInputElement).checked);
    expect(ticked).toHaveLength(0);
  });

  it('offers no group action when only events are selected', async () => {
    vi.mocked(getAlertGroupEvents).mockResolvedValue([mkEvent('ev-1', '198.51.100.11')]);
    renderAlerts();
    await screen.findByText('NTLM Session Setup');
    fireEvent.click(screen.getByText('NTLM Session Setup'));
    await waitFor(() => expect(screen.getAllByRole('checkbox').length).toBeGreaterThan(2));
    const boxes = screen.getAllByRole('checkbox');
    fireEvent.click(boxes[boxes.length - 1]); // one event, no group

    const strip = await screen.findByTestId('list-toolbar-selection');
    // The event action stays. It acts on the selected events.
    expect(within(strip).getByRole('button', { name: 'Acknowledge 1 event' })).toBeTruthy();
    expect(within(strip).queryByRole('button', { name: 'Assign to me' })).toBeNull();
    expect(within(strip).queryByRole('button', { name: /^Acknowledge$/ })).toBeNull();
    expect(within(strip).queryByRole('button', { name: 'Escalate to cases' })).toBeNull();
  });
});

describe('the owner avatar reports its write (RL9)', () => {
  it('holds the avatar while the release is in flight and toasts the outcome', async () => {
    vi.mocked(getAlerts).mockResolvedValue(queueOf([mkGroup({ owner: 'me', state: 'owned' })]));
    let finish: (v: unknown) => void = () => {};
    vi.mocked(assignAlert).mockReturnValue(new Promise((r) => { finish = r; }) as never);
    renderAlerts();
    fireEvent.click(await screen.findByRole('button', { name: 'Release NTLM Session Setup' }));

    expect(await screen.findByRole('status', { name: 'Releasing NTLM Session Setup' })).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Release NTLM Session Setup' })).toBeNull();
    expect(assignAlert).toHaveBeenCalledWith('NTLM Session Setup', true);

    await act(async () => {
      finish({ rule_name: 'NTLM Session Setup', owner: null });
    });
    expect(await screen.findByText('Released NTLM Session Setup.')).toBeTruthy();
  });
});
