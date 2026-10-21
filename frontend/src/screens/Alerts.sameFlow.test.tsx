// Dogfood 2026-10-19 (R2). R2-I9, R2-D9: groups that share a flow showed as
// unrelated rows, and one attack sequence carried opposite verdicts with no
// pointer. R2-I2: the escalate confirm said "already on a case" and named no
// case, and the row marker had no link.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ToastProvider } from '../lib/toast';
import type { AlertGroup, AlertSibling, Investigation as Inv } from '../lib/types';

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
    getInvestigationSiblings: vi.fn(),
    getChatThread: vi.fn(() => Promise.resolve({ messages: [], pending: false })),
  };
});

import {
  escalateGroup,
  getAlertGroupEvents,
  getAlerts,
  getAutoTriageStatus,
  getInvestigation,
  getInvestigationSiblings,
  getMe,
  listSavedViews,
} from '../lib/api';
import { queueOf } from '../test/alertQueue';
import { ESCALATE_CAP, Alerts, escalateConfirmText, pressPlan } from './Alerts';
import { ShellProvider } from '../shell/ShellContext';

const NTLM = 'ET INFO NTLMv1 Session Setup Response - Challenge';
const WMI = 'ET INFO Suspected Impacket WMIExec Activity';
const TOR = 'ET TOR Known Tor Exit Node Traffic group 46';

const mkGroup = (o: Partial<AlertGroup> = {}): AlertGroup => ({
  id: `es-${o.name ?? NTLM}`,
  name: NTLM,
  kind: 'suricata',
  sev: 'high',
  count: 2,
  verdict: 'untriaged',
  conf: null,
  latest: '1m ago',
  latestTs: new Date(Date.now() - 60_000).toISOString(),
  inherited: false,
  events: [],
  ackedCount: 0,
  escalatedCount: 0,
  src: '192.0.2.20',
  dst: '192.0.2.40',
  siblings: [],
  siblingCount: 0,
  cases: [],
  ...o,
});

const sib = (o: Partial<AlertSibling> = {}): AlertSibling => ({
  name: WMI,
  kind: 'suricata',
  verdict: 'true_positive',
  conf: 0.72,
  invId: 'inv-wmi',
  signals: ['hosts'],
  ...o,
});

/** The NTLMv1 false positive and the WMIExec true positive, each naming the other. */
function pairOfRows(): AlertGroup[] {
  return [
    mkGroup({
      verdict: 'false_positive',
      conf: 0.8,
      invId: 'inv-ntlm',
      siblings: [sib()],
      siblingCount: 1,
    }),
    mkGroup({
      name: WMI,
      src: '192.0.2.40',
      dst: '192.0.2.20',
      verdict: 'true_positive',
      conf: 0.72,
      invId: 'inv-wmi',
      siblings: [sib({ name: NTLM, verdict: 'false_positive', conf: 0.8, invId: 'inv-ntlm' })],
      siblingCount: 1,
    }),
  ];
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(getAlerts).mockResolvedValue(queueOf(pairOfRows()));
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

function rowOf(name: string): HTMLElement {
  const title = screen.getAllByTestId('alert-name').find((el) => el.textContent === name);
  if (!title) throw new Error(`no row named ${name}`);
  return title.closest('[data-group-key]') as HTMLElement;
}

describe('the same-flow chip on the Alerts rows (R2-I9, R2-D9)', () => {
  it('asks the list for the links of each row', async () => {
    renderAlerts();
    await screen.findAllByTestId('same-flow-chip');
    expect(vi.mocked(getAlerts).mock.calls[0][0]?.links).toBe(true);
  });

  it('warns on both rows of one sequence with opposite verdicts', async () => {
    renderAlerts();
    await screen.findAllByTestId('same-flow-chip');
    const ntlm = within(rowOf(NTLM)).getByTestId('same-flow-chip');
    const wmi = within(rowOf(WMI)).getByTestId('same-flow-chip');
    expect(ntlm.getAttribute('data-tone')).toBe('warning');
    expect(ntlm.textContent).toContain('A true positive shares this flow.');
    expect(wmi.getAttribute('data-tone')).toBe('warning');
    expect(wmi.textContent).toContain('A false positive shares this flow.');
  });

  it('NEGATIVE CONTROL: a row with no siblings, or no sibling data, has no chip', async () => {
    vi.mocked(getAlerts).mockResolvedValue(
      queueOf([mkGroup(), mkGroup({ name: WMI, siblings: null, siblingCount: null })]),
    );
    renderAlerts();
    await screen.findByText(WMI);
    expect(screen.queryByTestId('same-flow-chip')).toBeNull();
  });

  it('opening the chip does not expand the row', async () => {
    renderAlerts();
    await screen.findAllByTestId('same-flow-chip');
    fireEvent.click(within(rowOf(NTLM)).getByTestId('same-flow-chip'));
    expect(screen.getByTestId('same-flow-popover')).toBeTruthy();
    expect(getAlertGroupEvents).not.toHaveBeenCalled();
  });

  it('Show expands the sibling row and moves the focus to it', async () => {
    renderAlerts();
    await screen.findAllByTestId('same-flow-chip');
    fireEvent.click(within(rowOf(NTLM)).getByTestId('same-flow-chip'));
    fireEvent.click(within(screen.getByTestId('same-flow-popover')).getByRole('button', { name: `Show ${WMI}` }));
    await waitFor(() =>
      expect(vi.mocked(getAlertGroupEvents).mock.calls.some((c) => c[0].name === WMI)).toBe(true),
    );
    expect(screen.queryByTestId('same-flow-popover')).toBeNull();
  });

  it('Open report opens the report of the sibling', async () => {
    renderAlerts();
    await screen.findAllByTestId('same-flow-chip');
    fireEvent.click(within(rowOf(NTLM)).getByTestId('same-flow-chip'));
    fireEvent.click(
      within(screen.getByTestId('same-flow-popover')).getByRole('button', { name: `Open the report of ${WMI}` }),
    );
    await waitFor(() => expect(getInvestigation).toHaveBeenCalledWith('inv-wmi'));
  });

  it('Show on a sibling the list hides turns Hide acknowledged off', async () => {
    // The NTLMv1 false positive was auto-acknowledged, so the default list
    // hides it. The WMIExec row still names it.
    const [, wmiRow] = pairOfRows();
    vi.mocked(getAlerts).mockImplementation(async (q) =>
      queueOf(q?.hideAcked ? [wmiRow] : pairOfRows()),
    );
    renderAlerts();
    const chip = await screen.findByTestId('same-flow-chip');
    expect(vi.mocked(getAlerts).mock.calls[0][0]?.hideAcked).toBe(true);
    fireEvent.click(chip);
    fireEvent.click(within(screen.getByTestId('same-flow-popover')).getByRole('button', { name: `Show ${NTLM}` }));
    await waitFor(() => expect(vi.mocked(getAlerts).mock.calls.some((c) => !c[0]?.hideAcked)).toBe(true));
    await waitFor(() =>
      expect(vi.mocked(getAlertGroupEvents).mock.calls.some((c) => c[0].name === NTLM)).toBe(true),
    );
  });
});

describe('the Show link of a report (V3 interaction)', () => {
  function LocationProbe() {
    const loc = useLocation();
    return <div data-testid="location">{loc.search}</div>;
  }

  it('a link with show= expands that row on the window of the link', async () => {
    const from = '2026-09-03T19:48';
    const to = '2026-09-05T19:49';
    const show = `suricata:${WMI}`;
    render(
      <ToastProvider>
        <MemoryRouter
          initialEntries={[
            `/alerts?${new URLSearchParams({ range: 'custom', from, to, hide_acked: 'false', show })}`,
          ]}
        >
          <ShellProvider>
            <Alerts />
            <LocationProbe />
          </ShellProvider>
        </MemoryRouter>
      </ToastProvider>,
    );
    await waitFor(() =>
      expect(vi.mocked(getAlertGroupEvents).mock.calls.some((c) => c[0].name === WMI)).toBe(true),
    );
    // NEGATIVE CONTROL. The other row stays closed.
    expect(vi.mocked(getAlertGroupEvents).mock.calls.some((c) => c[0].name === NTLM)).toBe(false);
    const q = vi.mocked(getAlerts).mock.calls[0][0];
    expect(q?.range).toBe('custom');
    expect(q?.hideAcked).toBeFalsy();
    // The link did its work once. A reload does not open the row again.
    await waitFor(() => expect(screen.getByTestId('location').textContent).not.toContain('show='));
  });

  it('Show in the report drawer closes the drawer and expands the sibling row', async () => {
    vi.mocked(getInvestigation).mockResolvedValue({
      id: 'inv-wmi',
      groupId: 'ev-1',
      name: WMI,
      kind: 'suricata',
      host: '192.0.2.40',
      ip: '192.0.2.20',
      verdict: 'true_positive',
      conf: 0.72,
      rationale: 'Remote execution over WMI.',
      summary: [{ t: 'text', v: 'evidence' }],
      status: 'complete',
      elapsedLabel: '1m',
      actions: [],
      timeline: [],
      nodes: [],
      edges: [],
      seedChat: [],
      alert: {
        id: 'ev-1',
        rule: WMI,
        src: '192.0.2.40:49152',
        dst: '192.0.2.20:135',
        proto: 'tcp',
        action: 'allowed',
        time: new Date(Date.now() - 3_600_000).toISOString(),
        count: 2,
      },
    } as unknown as Inv);
    vi.mocked(getInvestigationSiblings).mockResolvedValue({
      siblings: [sib({ name: NTLM, verdict: 'false_positive', conf: 0.8, invId: 'inv-ntlm' })],
      siblingCount: 1,
      reason: null,
    });
    render(
      <ToastProvider>
        <MemoryRouter initialEntries={['/alerts?drawer=inv-wmi']}>
          <ShellProvider>
            <Alerts />
            <LocationProbe />
          </ShellProvider>
        </MemoryRouter>
      </ToastProvider>,
    );
    const panel = await screen.findByTestId('same-flow-panel');
    fireEvent.click(within(panel).getByRole('button', { name: `Show ${NTLM} in Alerts` }));
    await waitFor(() => expect(screen.getByTestId('location').textContent).not.toContain('drawer='));
    await waitFor(() =>
      expect(vi.mocked(getAlertGroupEvents).mock.calls.some((c) => c[0].name === NTLM)).toBe(true),
    );
  });

  it('NEGATIVE CONTROL: a show= the list does not hold says so', async () => {
    render(
      <ToastProvider>
        <MemoryRouter initialEntries={[`/alerts?hide_acked=false&show=${encodeURIComponent('suricata:ET NOT ON THE PAGE')}`]}>
          <ShellProvider>
            <Alerts />
          </ShellProvider>
        </MemoryRouter>
      </ToastProvider>,
    );
    expect(await screen.findByText(/The list does not show ET NOT ON THE PAGE\./)).toBeTruthy();
    expect(getAlertGroupEvents).not.toHaveBeenCalled();
  });
});

describe('the case a group is on (R2-I2)', () => {
  const CASE = { id: 'hyi7U6EBEk5LYVVZ3SYT', url: 'https://so.example.com/#/case/hyi7U6EBEk5LYVVZ3SYT' };

  it('the escalate confirm names the case and links to it', async () => {
    vi.mocked(getAlerts).mockResolvedValue(
      queueOf([
        mkGroup({ name: TOR, count: 1, ackedCount: 1, escalatedCount: 1, cases: [CASE], casesComplete: true }),
      ]),
    );
    renderAlerts();
    await screen.findByText(TOR);
    const dialog = await waitFor(
      () => {
        fireEvent.keyDown(window, { key: 'j' });
        fireEvent.keyDown(window, { key: 'e' });
        return screen.getByTestId('escalate-confirm');
      },
      { timeout: 5000 },
    );
    expect(dialog.textContent).toContain(`The alert of ${TOR} is already on case ${CASE.id}. soc-ai opens no case.`);
    const link = within(dialog).getByRole('link', { name: `Open case ${CASE.id} in Security Onion` });
    expect(link.getAttribute('href')).toBe(CASE.url);
    expect(link.getAttribute('target')).toBe('_blank');
    expect(escalateGroup).not.toHaveBeenCalled();
  });

  it('the escalated marker of the row links to the case', async () => {
    vi.mocked(getAlerts).mockResolvedValue(
      queueOf([mkGroup({ name: TOR, count: 1, escalatedCount: 1, cases: [CASE] })]),
    );
    renderAlerts();
    await screen.findByText(TOR);
    // STE: "1 escalated." was a sentence with no noun (dogfood 2026-10-19, V3).
    const marker = within(rowOf(TOR)).getByRole('link', {
      name: `1 alert is on a case. Open case ${CASE.id} in Security Onion.`,
    });
    expect(marker.getAttribute('href')).toBe(CASE.url);
  });

  it('NEGATIVE CONTROL: a marker with no known case stays a plain count', async () => {
    vi.mocked(getAlerts).mockResolvedValue(queueOf([mkGroup({ name: TOR, count: 1, escalatedCount: 1 })]));
    renderAlerts();
    await screen.findByText(TOR);
    expect(within(rowOf(TOR)).queryByRole('link')).toBeNull();
    expect(within(rowOf(TOR)).getByTitle('1 alert is on a case')).toBeTruthy();
  });

  it('names each case of a group, and a case with no page in the console has no link', () => {
    const g = mkGroup({
      name: TOR,
      count: 3,
      ackedCount: 3,
      escalatedCount: 3,
      cases: [CASE, { id: 'case-2', url: null }],
      casesComplete: true,
    });
    const plan = pressPlan([g], [g], ESCALATE_CAP);
    expect(plan?.cases.map((c) => c.id)).toEqual([CASE.id, 'case-2']);
    expect(escalateConfirmText([g], plan)).toBe(
      `The 3 alerts of ${TOR} are already on cases ${CASE.id}, case-2. soc-ai opens no case.`,
    );
  });

  it('NEGATIVE CONTROL: a partial case list is a finding, never the whole answer', () => {
    // The row read the ids of the newest escalated alerts only.
    const g = mkGroup({ name: TOR, count: 40, ackedCount: 40, escalatedCount: 40, cases: [CASE], casesComplete: false });
    expect(escalateConfirmText([g], pressPlan([g], [g], ESCALATE_CAP))).toBe(
      `The 40 alerts of ${TOR} are already on a case. soc-ai found case ${CASE.id}. soc-ai opens no case.`,
    );
  });

  it('NEGATIVE CONTROL: one partial target makes the plan partial', () => {
    const a = mkGroup({ name: TOR, count: 1, ackedCount: 1, escalatedCount: 1, cases: [CASE], casesComplete: true });
    const b = mkGroup({ name: NTLM, count: 5, ackedCount: 5, escalatedCount: 5, cases: [], casesComplete: false });
    const plan = pressPlan([a, b], [a, b], ESCALATE_CAP);
    expect(plan?.casesComplete).toBe(false);
    expect(escalateConfirmText([a, b], plan)).toContain(`already on a case. soc-ai found case ${CASE.id}.`);
  });

  it('NEGATIVE CONTROL: a group with no known case keeps the sentence without an id', () => {
    const g = mkGroup({ name: TOR, count: 1, ackedCount: 1, escalatedCount: 1 });
    expect(escalateConfirmText([g], pressPlan([g], [g], ESCALATE_CAP))).toBe(
      `The alert of ${TOR} is already on a case. soc-ai opens no case.`,
    );
  });
});
