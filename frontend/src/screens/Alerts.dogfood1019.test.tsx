// Dogfood 2026-10-19 (R2), the Alerts screen.
//
// R2-D7, R2-I1: an event acknowledge showed no result, and a timeout left a
// red toast and the selection. R2-D16: the bulk bar left the view. R2-D8,
// R2-I2: the escalate confirm promised cases that one press does not open.
// R2-D15: a second press wore a green check and named no case. R2-D18: the
// event checkbox had no name. R2-D20, R2-I8: the empty list offered a window
// that was empty too. R2-D17: times without a date or a zone.
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
  ackEvents,
  ackGroup,
  escalateGroup,
  getAlertGroupEvents,
  getAlerts,
  getAutoTriageStatus,
  getMe,
  listSavedViews,
} from '../lib/api';
import { queueOf } from '../test/alertQueue';
import {
  ACK_CAP,
  Alerts,
  COUNTS_UNKNOWN,
  ESCALATE_CAP,
  ackButtonOffReason,
  analystHint,
  bulkAckMessage,
  escalateConfirmText,
  pressPlan,
  utcBound,
} from './Alerts';
import { ShellProvider } from '../shell/ShellContext';

const NAME = 'ET TOR Known Tor Exit Node Traffic group 46';

const mkGroup = (o: Partial<AlertGroup> = {}): AlertGroup => ({
  id: 'es-1',
  name: NAME,
  kind: 'suricata',
  sev: 'high',
  count: 2,
  verdict: 'untriaged',
  conf: null,
  latest: '1m ago',
  inherited: false,
  events: [],
  ackedCount: 0,
  escalatedCount: 0,
  ...o,
});

/** An event a few hours old: the seed moves with the clock. */
const mkEvent = (id: string, dst: string, hoursAgo = 3): AlertEvent => ({
  id,
  src: '192.0.2.10',
  dst,
  host: 'sensor',
  sev: 'high',
  ts: new Date(Date.now() - hoursAgo * 3_600_000).toISOString(),
  ago: `${hoursAgo}h`,
});

let intervalSpy: { mock: { calls: unknown[][] }; mockRestore: () => void };

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(getAlerts).mockResolvedValue(queueOf([mkGroup()]));
  vi.mocked(getAlertGroupEvents).mockResolvedValue([
    mkEvent('ev-1', '198.51.100.11'),
    mkEvent('ev-2', '198.51.100.12', 5),
  ]);
  vi.mocked(getMe).mockResolvedValue({ username: 'me', role: 'analyst', status: '' });
  vi.mocked(getAutoTriageStatus).mockResolvedValue({
    active: false,
    total: 0,
    hunted: 0,
    skipped: 0,
    failed: 0,
  } as never);
  vi.mocked(listSavedViews).mockResolvedValue([]);
  vi.mocked(ackEvents).mockReset();
  intervalSpy = vi.spyOn(window, 'setInterval');
});

afterEach(() => {
  intervalSpy.mockRestore();
});

function renderAlerts(path = '/alerts') {
  return render(
    <ToastProvider>
      <MemoryRouter initialEntries={[path]}>
        <ShellProvider>
          <Alerts />
        </ShellProvider>
      </MemoryRouter>
    </ToastProvider>,
  );
}

/** Expand the group and wait for its event rows. */
async function expandGroup() {
  await screen.findByText(NAME);
  fireEvent.click(screen.getByText(NAME));
  await waitFor(() =>
    expect(screen.getAllByRole('checkbox', { name: /^Select the event at / })).toHaveLength(2),
  );
}

/** The tone of the toast that holds `text`: its icon carries the tint. */
function toneOf(el: HTMLElement): 'success' | 'danger' | 'info' {
  const toast = el.closest('[role="status"]') as HTMLElement;
  if (toast.querySelector('.text-success')) return 'success';
  if (toast.querySelector('.text-danger')) return 'danger';
  return 'info';
}

const timedOut = () => new RequestTimeoutError(SO_WRITE_TIMEOUT_MS, WRITE_TIMEOUT_NOTE);

describe('the event checkbox has a name (R2-D18)', () => {
  it('names each event box after the time of its event', async () => {
    renderAlerts();
    await expandGroup();
    const boxes = screen.getAllByRole('checkbox', { name: /^Select the event at / });
    expect(boxes[0].getAttribute('aria-label')).toMatch(/\w{3} \d{2}, \d{2}:\d{2}:\d{2} \S+$/);
  });
});

describe('an event acknowledge reports its result (R2-D7, R2-I1)', () => {
  it('toasts the count it wrote and clears the selection', async () => {
    vi.mocked(ackEvents).mockResolvedValue({ acked: 2, failed: 0, total: 2, capped: false });
    renderAlerts();
    await expandGroup();
    screen.getAllByRole('checkbox', { name: /^Select the event at / }).forEach((b) => fireEvent.click(b));
    const strip = await screen.findByTestId('list-toolbar-selection');
    fireEvent.click(within(strip).getByRole('button', { name: 'Acknowledge 2 events' }));
    await waitFor(() => expect(ackEvents).toHaveBeenCalledWith(['ev-1', 'ev-2']));

    const msg = await screen.findByText('Acknowledged 2 events.');
    expect(toneOf(msg)).toBe('success');
    await waitFor(() => expect(screen.queryByTestId('list-toolbar-selection')).toBeNull());
  });

  it('says how many failed on a 200 that holds a failure, and keeps the selection', async () => {
    vi.mocked(ackEvents).mockResolvedValue({ acked: 1, failed: 1, total: 2, capped: false });
    renderAlerts();
    await expandGroup();
    screen.getAllByRole('checkbox', { name: /^Select the event at / }).forEach((b) => fireEvent.click(b));
    fireEvent.click(await screen.findByRole('button', { name: 'Acknowledge 2 events' }));

    const msg = await screen.findByText(/Acknowledged 1 of 2 events\. 1 event failed\./);
    expect(toneOf(msg)).toBe('danger');
    expect(screen.getByTestId('list-toolbar-selection')).toBeTruthy();
  });

  it('on a timeout says the write can still complete, reads the list again and clears the selection', async () => {
    vi.mocked(ackEvents).mockRejectedValue(timedOut());
    renderAlerts();
    await expandGroup();
    const reads = vi.mocked(getAlerts).mock.calls.length;
    fireEvent.click(screen.getAllByRole('checkbox', { name: /^Select the event at / })[0]);
    fireEvent.click(await screen.findByRole('button', { name: 'Acknowledge 1 event' }));

    const msg = await screen.findByText(
      'No answer yet for the acknowledgement of 1 event. The request did not return in 90 s. ' +
        'The grid is slow. The change can still complete. Check the row in a minute.',
    );
    expect(toneOf(msg)).toBe('info');
    await waitFor(() => expect(screen.queryByTestId('list-toolbar-selection')).toBeNull());
    await waitFor(() => expect(vi.mocked(getAlerts).mock.calls.length).toBeGreaterThan(reads));
  });

  it('NEGATIVE CONTROL: a refusal stays red and keeps the selection', async () => {
    vi.mocked(ackEvents).mockRejectedValue(new Error('grid unavailable'));
    renderAlerts();
    await expandGroup();
    fireEvent.click(screen.getAllByRole('checkbox', { name: /^Select the event at / })[0]);
    fireEvent.click(await screen.findByRole('button', { name: 'Acknowledge 1 event' }));
    const msg = await screen.findByText('grid unavailable');
    expect(toneOf(msg)).toBe('danger');
    expect(screen.getByTestId('list-toolbar-selection')).toBeTruthy();
  });

  it('acknowledges one event from its own row', async () => {
    vi.mocked(ackEvents).mockResolvedValue({ acked: 1, failed: 0, total: 1, capped: false });
    renderAlerts();
    await expandGroup();
    const rowAcks = screen.getAllByRole('button', { name: /^Acknowledge the event at / });
    expect(rowAcks).toHaveLength(2);
    fireEvent.click(rowAcks[0]);
    await waitFor(() => expect(ackEvents).toHaveBeenCalledWith(['ev-1']));
    expect(await screen.findByText('Acknowledged 1 event.')).toBeTruthy();
    // The row says it is done and takes no second press.
    const done = await screen.findByRole('button', { name: /^Acknowledged the event at / });
    expect((done as HTMLButtonElement).disabled).toBe(true);
    // No selection was made, so no bulk bar opens.
    expect(screen.queryByTestId('list-toolbar-selection')).toBeNull();
  });
});

describe('the bulk bar stays in view (R2-D16)', () => {
  it('holds the selection strip sticky to the top of the page', async () => {
    renderAlerts();
    await screen.findByText(NAME);
    fireEvent.click(screen.getByRole('checkbox', { name: `Select ${NAME}` }));
    const strip = await screen.findByTestId('list-toolbar-selection');
    const holder = strip.closest('[data-testid="alerts-toolbar"]') as HTMLElement;
    expect(holder).toBeTruthy();
    expect(holder.className).toContain('[&_[data-testid=list-toolbar-selection]]:sticky');
    // The toolbar box steps aside, so the strip sticks for the whole page.
    expect(holder.className).toContain('[&>div]:contents');
  });
});

describe('the escalate confirm states what one press does (R2-D8, R2-I2)', () => {
  async function openConfirm() {
    renderAlerts();
    await screen.findByText(NAME);
    return waitFor(
      () => {
        fireEvent.keyDown(window, { key: 'j' });
        fireEvent.keyDown(window, { key: 'e' });
        return screen.getByTestId('escalate-confirm');
      },
      { timeout: 5000 },
    );
  }

  it('caps the cases at the per-press cap and says a further press opens the rest', async () => {
    vi.mocked(getAlerts).mockResolvedValue(queueOf([mkGroup({ count: 51 })]));
    const dialog = await openConfirm();
    expect(dialog.textContent).toContain(
      `Open 25 Security Onion cases for 25 of the 51 alerts of ${NAME}.`,
    );
    expect(dialog.textContent).toContain('One press opens at most 25 cases. Press Escalate again for the other 26 alerts.');
    expect(within(dialog).getByRole('button', { name: 'Open 25 cases' })).toBeTruthy();
  });

  it('counts only the alerts still to write when Hide acknowledged is off', async () => {
    vi.mocked(getAlerts).mockResolvedValue(
      queueOf([mkGroup({ count: 1531, ackedCount: 1520, escalatedCount: 4 })]),
    );
    const dialog = await openConfirm();
    expect(dialog.textContent).toContain(`Open 11 Security Onion cases for 11 of the 1,531 alerts of ${NAME}.`);
    expect(dialog.textContent).toContain('4 alerts are already on a case. 1,516 alerts are already acknowledged.');
    expect(dialog.textContent).not.toMatch(/Press Escalate again/);
    expect(within(dialog).getByRole('button', { name: 'Open 11 cases' })).toBeTruthy();
  });

  it('says a group already on a case opens no case, and offers no write', async () => {
    vi.mocked(getAlerts).mockResolvedValue(
      queueOf([mkGroup({ count: 1, ackedCount: 1, escalatedCount: 1 })]),
    );
    const dialog = await openConfirm();
    expect(dialog.textContent).toContain(`The alert of ${NAME} is already on a case. soc-ai opens no case.`);
    expect(within(dialog).queryByRole('button', { name: /^Open/ })).toBeNull();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Close' }));
    expect(screen.queryByTestId('escalate-confirm')).toBeNull();
    expect(escalateGroup).not.toHaveBeenCalled();
  });

  it('says "at most" where the grid cannot count the handled alerts', async () => {
    vi.mocked(getAlerts).mockResolvedValue(
      queueOf([mkGroup({ count: 16, ackedCount: null, escalatedCount: null })]),
    );
    const dialog = await openConfirm();
    expect(dialog.textContent).toContain(
      `Open at most 16 Security Onion cases for the 16 alerts of ${NAME}. ` +
        'soc-ai skips an alert that is already acknowledged or on a case.',
    );
    expect(within(dialog).getByRole('button', { name: 'Open at most 16 cases' })).toBeTruthy();
  });

  it('NEGATIVE CONTROL: a small open group keeps the plain sentence', () => {
    const g = mkGroup({ count: 1 });
    expect(escalateConfirmText([g], pressPlan([g], [g], ESCALATE_CAP))).toBe(
      `Open 1 Security Onion case for the alert of ${NAME}.`,
    );
  });
});

describe('the acknowledge button states what one press does (R2-D8)', () => {
  it('caps the alerts at the per-press cap', async () => {
    vi.mocked(getAlerts).mockResolvedValue(queueOf([mkGroup({ count: 1531 })]));
    renderAlerts();
    await screen.findByText(NAME);
    fireEvent.click(screen.getByRole('checkbox', { name: `Select ${NAME}` }));
    const strip = await screen.findByTestId('list-toolbar-selection');
    const button = within(strip).getByRole('button', { name: 'Acknowledge 1 group · 199 of 1,531 alerts' });
    expect(button.getAttribute('title')).toBe(
      'One press acknowledges at most 199 alerts of each group. Press Acknowledge again for the other 1,332 alerts.',
    );
  });

  it('NEGATIVE CONTROL: a group under the cap names its own count', async () => {
    vi.mocked(getAlerts).mockResolvedValue(queueOf([mkGroup({ count: 12, ackedCount: 2 })]));
    renderAlerts();
    await screen.findByText(NAME);
    fireEvent.click(screen.getByRole('checkbox', { name: `Select ${NAME}` }));
    const strip = await screen.findByTestId('list-toolbar-selection');
    expect(within(strip).getByRole('button', { name: 'Acknowledge 1 group · 10 alerts' })).toBeTruthy();
  });

  it('plans per group against the server caps', () => {
    const big = mkGroup({ count: 500 });
    const small = mkGroup({ name: 'Other', count: 30, ackedCount: 10 });
    expect(pressPlan([big, small], [big, small], ACK_CAP)).toMatchObject({
      total: 530,
      press: 199 + 20,
      rest: 301,
      upTo: false,
    });
    // A group not on the page has no count to plan with.
    expect(pressPlan([{ name: 'X', kind: 'suricata' }], [big], ESCALATE_CAP)).toBeNull();
  });
});

describe('a second press says what remains (R2-D15)', () => {
  async function pressKey(key: 'a' | 'e') {
    renderAlerts();
    await screen.findByText(NAME);
    if (key === 'a') {
      await waitFor(() => {
        fireEvent.keyDown(window, { key: 'j' });
        fireEvent.keyDown(window, { key: 'a' });
        expect(ackGroup).toHaveBeenCalled();
      });
      return;
    }
    const dialog = await waitFor(
      () => {
        fireEvent.keyDown(window, { key: 'j' });
        fireEvent.keyDown(window, { key: 'e' });
        return screen.getByTestId('escalate-confirm');
      },
      { timeout: 5000 },
    );
    fireEvent.click(within(dialog).getByRole('button', { name: /^Open/ }));
  }

  it('an ack that wrote nothing names the acknowledged alerts and wears no check', async () => {
    vi.mocked(ackGroup).mockResolvedValue({
      acked: 0,
      failed: 0,
      total: 0,
      capped: false,
      already_acked: 2,
      remaining: 0,
    });
    await pressKey('a');
    const msg = await screen.findByText(`The 2 alerts of ${NAME} are already acknowledged. soc-ai wrote nothing.`);
    expect(toneOf(msg)).toBe('info');
  });

  it('an escalate that opened nothing names the case and links it', async () => {
    vi.mocked(escalateGroup).mockResolvedValue({
      escalated: 0,
      failed: 0,
      total: 0,
      capped: false,
      already_escalated: 1,
      already_acked: 0,
      existing_cases: [{ id: 'case-tor-1', url: 'https://so.example.test/#/case/case-tor-1' }],
    });
    await pressKey('e');
    const msg = await screen.findByText(`The alert of ${NAME} is already on case case-tor-1. soc-ai opened no case.`);
    expect(toneOf(msg)).toBe('info');
    expect(screen.getByRole('link', { name: 'Open case case-tor-1' }).getAttribute('href')).toBe(
      'https://so.example.test/#/case/case-tor-1',
    );
  });

  it('NEGATIVE CONTROL: an escalate that opened a case keeps the check', async () => {
    vi.mocked(escalateGroup).mockResolvedValue({ escalated: 2, failed: 0, total: 2, capped: false });
    await pressKey('e');
    const msg = await screen.findByText(`Opened 2 cases for ${NAME}`);
    expect(toneOf(msg)).toBe('success');
  });

  it('a bulk ack of one group that wrote nothing says so', async () => {
    vi.mocked(ackGroup).mockResolvedValue({
      acked: 0,
      failed: 0,
      total: 0,
      capped: false,
      already_acked: 2,
      remaining: 0,
    });
    renderAlerts();
    await screen.findByText(NAME);
    fireEvent.click(screen.getByRole('checkbox', { name: `Select ${NAME}` }));
    const strip = await screen.findByTestId('list-toolbar-selection');
    fireEvent.click(within(strip).getByRole('button', { name: /^Acknowledge 1 group/ }));
    const msg = await screen.findByText(`The 2 alerts of ${NAME} are already acknowledged. soc-ai wrote nothing.`);
    expect(toneOf(msg)).toBe('info');
  });
});

describe('a bulk ack of several groups says which wrote nothing (R2-D15)', () => {
  const r = (o: Partial<import('../lib/api').AckGroupResult>) => ({
    acked: 0,
    failed: 0,
    total: 0,
    capped: false,
    already_acked: 0,
    remaining: 0,
    ...o,
  });
  const a = mkGroup({ name: 'A' });
  const b = mkGroup({ name: 'B' });

  it('says nothing was written when no group wrote, with no check', () => {
    expect(bulkAckMessage([{ g: a, r: r({ already_acked: 3 }) }, { g: b, r: r({ already_acked: 2 }) }], 0, 0)).toEqual([
      '5 alerts of the 2 groups are already acknowledged. soc-ai wrote nothing.',
      'info',
    ]);
    expect(bulkAckMessage([{ g: a, r: r({ already_acked: 1 }) }, { g: b, r: r({}) }], 0, 0)[0]).toBe(
      '1 alert of the 2 groups is already acknowledged. soc-ai wrote nothing.',
    );
  });

  it('keeps the groups that wrote apart from the groups that did not', () => {
    expect(bulkAckMessage([{ g: a, r: r({ acked: 4, total: 4 }) }, { g: b, r: r({ already_acked: 2 }) }], 0, 0)).toEqual([
      'Acknowledged 4 alerts across 1 group · 1 group already acknowledged',
      'success',
    ]);
  });

  it('NEGATIVE CONTROL: a failed group still reads as a failure', () => {
    const [text, tone] = bulkAckMessage([{ g: a, r: r({ acked: 4, total: 4 }) }], 1, 0);
    expect(text).toMatch(/1 group failed\. The failed groups stay selected\./);
    expect(tone).toBe('danger');
  });
});

describe('the empty list offers the window the probe found (R2-D20, R2-I8)', () => {
  const byRange = (rows: Record<string, AlertGroup[]>) =>
    vi.mocked(getAlerts).mockImplementation((q) => Promise.resolve(queueOf(rows[q?.range ?? ''] ?? [])));

  it('offers the narrowest wider window that holds a detection, with its count', async () => {
    byRange({ '30d': [mkGroup({ name: 'ET OLD Detection' })] });
    renderAlerts('/alerts?range=24h');
    const widen = await screen.findByTestId('alerts-widen');
    expect(widen.textContent).toBe('Show the last 30 days · 1 detection');
    fireEvent.click(widen);
    expect(await screen.findByText('ET OLD Detection')).toBeTruthy();
  });

  it('NEGATIVE CONTROL: offers no window when no wider window holds a detection', async () => {
    byRange({});
    renderAlerts('/alerts?range=24h');
    await screen.findByText(/No open detection in this window/);
    await waitFor(() =>
      expect(vi.mocked(getAlerts).mock.calls.some((c) => c[0]?.range === '30d')).toBe(true),
    );
    await act(async () => {});
    expect(screen.queryByTestId('alerts-widen')).toBeNull();
  });

  it('counts only the detections the filters on screen let through', async () => {
    byRange({
      '7d': [mkGroup({ name: 'ET FP Detection', verdict: 'false_positive' })],
      '30d': [
        mkGroup({ name: 'ET FP Detection', verdict: 'false_positive' }),
        mkGroup({ id: 'es-2', name: 'ET TP Detection', verdict: 'true_positive' }),
      ],
    });
    renderAlerts('/alerts?range=24h&verdict=true_positive');
    const widen = await screen.findByTestId('alerts-widen');
    expect(widen.textContent).toBe('Show the last 30 days · 1 detection');
  });
});

describe('times state the date and the zone (R2-D17)', () => {
  it('dates each event row and names the zone', async () => {
    renderAlerts();
    await expandGroup();
    const cells = screen.getAllByTestId('event-time');
    expect(cells[0].textContent).toMatch(/^\w{3} \d{2}, \d{2}:\d{2}:\d{2} \S+/);
  });

  it('dates both ends of a collapsed run of identical events', async () => {
    vi.mocked(getAlertGroupEvents).mockResolvedValue([
      mkEvent('ev-1', '198.51.100.11', 30),
      mkEvent('ev-2', '198.51.100.11', 40),
      mkEvent('ev-3', '198.51.100.11', 50),
    ]);
    renderAlerts();
    await screen.findByText(NAME);
    fireEvent.click(screen.getByText(NAME));
    const bucket = await screen.findByTestId('event-bucket-row');
    const span = within(bucket).getByTestId('event-time').textContent ?? '';
    expect(span).toMatch(/^\w{3} \d{2}, \d{2}:\d{2}:\d{2} to \w{3} \d{2}, \d{2}:\d{2}:\d{2} \S+/);
  });
});

describe('a custom window reaches the API as UTC', () => {
  it('sends each bound with its offset, read in the browser zone', async () => {
    const from = '2026-08-25T00:00';
    const to = '2026-08-26T12:30';
    renderAlerts(`/alerts?range=custom&from=${from}&to=${to}`);
    await screen.findByText(NAME);
    const q = vi.mocked(getAlerts).mock.calls[0][0];
    expect(q?.range).toBe('custom');
    expect(q?.from).toBe(new Date(from).toISOString());
    expect(q?.to).toBe(new Date(to).toISOString());
    expect(q?.from).toMatch(/Z$/);
  });

  it('NEGATIVE CONTROL: a value that does not parse goes as it is', () => {
    expect(utcBound('not-a-time')).toBe('not-a-time');
    expect(utcBound('2026-08-25T04:00:00.000Z')).toBe('2026-08-25T04:00:00.000Z');
  });
});

describe('STE text (items 19 and 20)', () => {
  it('names the index of the detection', () => {
    expect(COUNTS_UNKNOWN).toBe(
      'Security Onion cannot count the acknowledged and escalated alerts of this detection. ' +
        'The index of this detection cannot search the flags. Expand the group to see what each event says.',
    );
  });
});

// ── Round 2 (V1-A3, V1-A6) ──────────────────────────────────────────────────

describe('the row names an analyst verdict a newer run hides (V1-A3)', () => {
  const hidden = {
    verdict: 'false_positive' as const,
    conf: 0.8,
    invId: 'INV-NEW',
    analystVerdict: 'true_positive',
    analystBy: 'alice',
    analystInvId: 'INV-OLD',
  };

  it('shows the analyst verdict and opens its run', async () => {
    vi.mocked(getAlerts).mockResolvedValue(queueOf([mkGroup(hidden)]));
    renderAlerts();
    const chip = await screen.findByTestId('analyst-verdict-es-1');
    expect(chip.textContent).toBe('· analyst: true positive');
    expect(chip.getAttribute('title')).toBe(
      'alice set the verdict of this alert to true positive on another run. Open that run.',
    );
  });

  it('NEGATIVE CONTROL: no chip when the pill shows the analyst run', () => {
    expect(analystHint({ ...hidden, analystInvId: 'INV-NEW' }, 'INV-NEW')).toBeNull();
    expect(analystHint({ analystVerdict: null, analystBy: null, analystInvId: null }, 'INV-NEW')).toBeNull();
  });
});

describe('the acknowledge button is off when a press writes nothing (V1-A6)', () => {
  it('turns off on a group whose every alert is on a case, with the reason', async () => {
    vi.mocked(getAlerts).mockResolvedValue(
      queueOf([mkGroup({ count: 1, ackedCount: 1, escalatedCount: 1 })]),
    );
    renderAlerts();
    await screen.findByText(NAME);
    fireEvent.click(screen.getByRole('checkbox', { name: `Select ${NAME}` }));
    const strip = await screen.findByTestId('list-toolbar-selection');
    const button = within(strip).getByRole('button', { name: /^Acknowledge 1 group/ });
    expect(button).toBeDisabled();
    expect(button.getAttribute('title')).toBe(
      'Every alert of the selected groups is already acknowledged or on a case. A press writes nothing.',
    );
    fireEvent.click(button);
    expect(ackGroup).not.toHaveBeenCalled();
  });

  it('NEGATIVE CONTROL: a group with an open alert keeps the button on', async () => {
    vi.mocked(getAlerts).mockResolvedValue(queueOf([mkGroup({ count: 2, ackedCount: 1 })]));
    renderAlerts();
    await screen.findByText(NAME);
    fireEvent.click(screen.getByRole('checkbox', { name: `Select ${NAME}` }));
    const strip = await screen.findByTestId('list-toolbar-selection');
    expect(within(strip).getByRole('button', { name: 'Acknowledge 1 group · 1 alert' })).not.toBeDisabled();
  });

  it('NEGATIVE CONTROL: a grid that cannot count keeps the button on', () => {
    const blind = mkGroup({ count: 3, ackedCount: null, escalatedCount: null });
    expect(ackButtonOffReason(pressPlan([blind], [blind], ACK_CAP))).toBeNull();
  });
});
