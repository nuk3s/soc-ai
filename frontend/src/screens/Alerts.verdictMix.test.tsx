// An alert group row named one verdict and hid a true positive inside the
// group (dogfood 2026-10-06, S5). The row said "False positive · inherited 1d
// ago", and the expanded events said "inherited 4d ago" with no verdict. The
// row now names the worst verdict among its alerts with the count of each, and
// each event chip names its own verdict.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ShellProvider } from '../shell/ShellContext';
import type { AlertEvent, AlertGroup } from '../lib/types';

const GROUP = vi.hoisted(
  (): AlertGroup => ({
    id: 'g1',
    name: 'Security Onion - Grid Node Login Failure (SSH)',
    kind: 'suricata',
    sev: 'medium',
    count: 9,
    verdict: 'false_positive',
    conf: 0.9,
    latest: '2m ago',
    inherited: true,
    invId: 'INV-FP',
    inheritedReason: 'Inherited from the same detection, investigated 1d ago.',
    events: [],
    verdictCounts: { false_positive: 8, true_positive: 1 },
    worstVerdict: 'true_positive',
    worstConf: 0.62,
    worstInvId: 'INV-TP',
  }),
);

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAlerts: vi.fn(),
  getMe: vi.fn().mockResolvedValue({ username: 'me', role: 'analyst', status: '' }),
  getAlertGroupEvents: vi.fn(),
  getInvestigation: vi.fn(() => new Promise(() => {})),
}));

import { getAlertGroupEvents, getAlerts } from '../lib/api';
import { queueOf } from '../test/alertQueue';
import { Alerts, verdictCountsLine } from './Alerts';

const mount = () =>
  render(
    <MemoryRouter initialEntries={['/alerts?range=30d']}>
      <ShellProvider>
        <Alerts />
      </ShellProvider>
    </MemoryRouter>,
  );

const row = async () =>
  (await screen.findByText(GROUP.name)).closest('[data-group-key]') as HTMLElement;

beforeEach(() => {
  vi.mocked(getAlerts).mockResolvedValue(queueOf([GROUP]));
});

describe('the group row names the worst verdict among its alerts', () => {
  it('shows the true positive and the count of each verdict', async () => {
    mount();
    const mix = within(await row()).getByTestId('verdict-mix');
    expect(within(mix).getByRole('button', { name: 'True positive 0.62' })).toBeTruthy();
    expect(mix.textContent).toContain('1 true positive, 8 false positives');
  });

  // NEGATIVE CONTROL. A group of one verdict shows its pill and nothing more.
  it('adds nothing to a group of one verdict', async () => {
    vi.mocked(getAlerts).mockResolvedValue(
      queueOf([{ ...GROUP, verdictCounts: { false_positive: 9 }, worstVerdict: null, worstInvId: null }]),
    );
    mount();
    expect(within(await row()).queryByTestId('verdict-mix')).toBeNull();
  });

  it('names the counts worst first', () => {
    expect(verdictCountsLine({ false_positive: 2, needs_more_info: 3, true_positive: 1 })).toBe(
      '1 true positive, 3 need more info, 2 false positives',
    );
    expect(verdictCountsLine({})).toBe('');
  });
});

describe('each event chip names its verdict', () => {
  it('reads "True positive 0.62, 4d ago" on the event that holds it', async () => {
    const events: AlertEvent[] = [
      {
        id: 'ev-tp',
        ts: '2026-10-02T09:15:00Z',
        ago: '4d',
        sev: 'medium',
        src: '192.0.2.29',
        dst: '192.0.2.1',
        host: '—',
        investigated: false,
        invId: 'INV-TP',
        inheritedReason: 'Inherited from the same detection, investigated 4d ago.',
        investigatedAt: '4d',
        verdict: 'true_positive',
        conf: 0.62,
      },
      {
        id: 'ev-old',
        ts: '2026-10-02T09:16:00Z',
        ago: '4d',
        sev: 'medium',
        src: '192.0.2.26',
        dst: '192.0.2.1',
        host: '—',
        investigated: false,
        invId: 'INV-FP',
        inheritedReason: 'Inherited from the same detection, investigated 4d ago.',
        investigatedAt: '4d',
      },
    ];
    vi.mocked(getAlertGroupEvents).mockResolvedValue(events);
    mount();
    fireEvent.click(await screen.findByText(GROUP.name));
    await waitFor(() => expect(screen.getByText('True positive 0.62, 4d ago')).toBeTruthy());
    // NEGATIVE CONTROL. An older server sends no verdict, and the chip keeps
    // its old words.
    expect(screen.getByText('inherited 4d ago')).toBeTruthy();
  });
});
