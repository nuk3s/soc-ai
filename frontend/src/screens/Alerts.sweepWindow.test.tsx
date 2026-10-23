// The header Bulk Investigate sweeps the last 24 hours, whatever window the
// Alerts list shows. The owner rule: a part of a page that the time filter
// does not filter says so in visible words. The button, the progress line and
// the summary now say "last 24 hours". A selection is not a window, so the
// selection path says nothing of one.
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ToastProvider } from '../lib/toast';
import { ShellProvider } from '../shell/ShellContext';

const GROUP = vi.hoisted(() => ({
  id: 'g1',
  name: 'ET SCAN Test Detection',
  kind: 'suricata',
  sev: 'high',
  count: 3,
  verdict: 'untriaged',
  conf: null,
  latest: '2m ago',
  inherited: false,
  events: [],
}));

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAlerts: vi.fn().mockResolvedValue({ groups: [GROUP], truncated: false, other_docs: 0 }),
  getMe: vi.fn().mockResolvedValue({ username: 'me', role: 'analyst', status: '' }),
  startAutoTriage: vi.fn(),
  getAutoTriageStatus: vi.fn(),
}));

import { type AutoTriageStatus, getAutoTriageStatus, startAutoTriage } from '../lib/api';
import { Alerts } from './Alerts';

const status = (over: Partial<AutoTriageStatus> = {}): AutoTriageStatus => ({
  active: true,
  total: 5,
  hunted: 0,
  skipped: 0,
  failed: 0,
  finished_at: null,
  severities: ['critical', 'high'],
  note: null,
  current: null,
  tool_calls: 0,
  ...over,
});

const mount = async () => {
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
};

/** The header button: the sweep. A selection bar holds a second one. */
const sweepButton = () => screen.getAllByRole('button', { name: /Bulk Investigate/ })[0];

beforeEach(() => {
  vi.mocked(startAutoTriage).mockReset();
  vi.mocked(getAutoTriageStatus).mockReset();
  vi.mocked(getAutoTriageStatus).mockResolvedValue(status());
});

describe('Bulk Investigate names its window', () => {
  it('says last 24 hours on the header button', async () => {
    await mount();
    expect(sweepButton().textContent).toContain('last 24 hours');
  });

  it('asks the server for the 24 hours the button names', async () => {
    vi.mocked(startAutoTriage).mockResolvedValue(status({ active: false, hunted: 1 }));
    await mount();
    fireEvent.click(sweepButton());
    await waitFor(() => expect(startAutoTriage).toHaveBeenCalled());
    expect(startAutoTriage).toHaveBeenCalledWith({ minSeverity: 'high', range: '24h' });
  });

  it('says last 24 hours on the progress line of a sweep', async () => {
    vi.mocked(startAutoTriage).mockResolvedValue(status());
    await mount();
    fireEvent.click(sweepButton());
    const line = await screen.findByTestId('bulk-investigate-progress');
    // The severities come with the first status poll, a real 2 s interval. The
    // default 5 s wait leaves a loaded runner 3 s for it, so allow 10 s.
    await waitFor(
      () => expect(line.textContent).toBe('Bulk Investigate runs on critical, high · last 24 hours'),
      { timeout: 10_000 },
    );
  });

  it('says last 24 hours in the summary of a sweep', async () => {
    vi.mocked(startAutoTriage).mockResolvedValue(
      status({ active: false, hunted: 2, skipped: 0, total: 2 }),
    );
    await mount();
    fireEvent.click(sweepButton());
    expect(await screen.findByText('Last 24 hours: 2 investigated')).toBeTruthy();
  });

  it('says last 24 hours when a sweep finds nothing', async () => {
    vi.mocked(startAutoTriage).mockResolvedValue(
      status({ active: false, total: 0, note: 'nothing to hunt' }),
    );
    await mount();
    fireEvent.click(sweepButton());
    expect(await screen.findByText('Last 24 hours: nothing to hunt')).toBeTruthy();
  });

  it('names no window for a selection', async () => {
    vi.mocked(startAutoTriage).mockResolvedValue(status({ note: 'triaging 1 selected' }));
    await mount();
    fireEvent.click(screen.getByTitle('Select all'));
    const buttons = screen.getAllByRole('button', { name: /Bulk Investigate/ });
    fireEvent.click(buttons[buttons.length - 1]);
    await waitFor(() => expect(startAutoTriage).toHaveBeenCalledWith({ alertIds: ['g1'] }));
    const line = await screen.findByTestId('bulk-investigate-progress');
    expect(line.textContent).not.toContain('24 hours');
  });
});
