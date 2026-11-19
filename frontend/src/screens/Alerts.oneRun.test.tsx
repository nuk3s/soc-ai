// One investigation for one alert row (dogfood 2026-11-17, AA4). The row
// showed the worst verdict of the window, the hosts of the newest alert and
// "Open report" on the newest run: a false positive under a true positive
// pill. The verdict, the sentence, the hosts and "Open report" now come from
// the run behind the pill. A later run that disagrees states one line.
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { ShellProvider } from '../shell/ShellContext';
import type { AlertGroup } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAlerts: vi.fn(),
  getMe: vi.fn().mockResolvedValue({ username: 'me', role: 'analyst', status: '' }),
}));

import { getAlerts } from '../lib/api';
import { queueOf } from '../test/alertQueue';
import { Alerts, laterRun, reportRunId, rowFlow } from './Alerts';

/** A true positive in the window under a newer false positive. */
const mixed = (o: Partial<AlertGroup> = {}): AlertGroup => ({
  id: 'g1',
  name: 'GPL SHELLCODE x86 setgid 0',
  kind: 'suricata',
  sev: 'medium',
  count: 302,
  verdict: 'false_positive',
  conf: 0.82,
  latest: '2h ago',
  inherited: false,
  events: [],
  invId: 'INV-FP',
  src: '198.51.100.149',
  dst: '192.0.2.119',
  windowVerdict: 'true_positive',
  windowConf: 0.75,
  windowInvId: 'INV-TP',
  headline: 'The payload is encrypted data with no shellcode structure.',
  windowHeadline: 'Shellcode bytes in traffic from an external node.',
  verdictSrc: '198.51.100.149',
  verdictDst: '192.0.2.119',
  windowSrc: '203.0.113.44',
  windowDst: '192.0.2.119',
  ...o,
});

describe('the run behind the pill', () => {
  it('gives the hosts and the report of the true positive run', () => {
    const g = mixed();
    expect(rowFlow(g)).toEqual({ src: '203.0.113.44', dst: '192.0.2.119' });
    expect(reportRunId(g)).toBe('INV-TP');
    expect(laterRun(g)).toEqual({ invId: 'INV-FP', text: 'A later investigation reached false positive.' });
  });

  it('states no later line when one run gives the pill (NEGATIVE CONTROL)', () => {
    const g = mixed({ verdict: 'true_positive', invId: 'INV-TP', verdictSrc: '203.0.113.44' });
    expect(laterRun(g)).toBeNull();
    expect(reportRunId(g)).toBe('INV-TP');
  });

  it('states no later line when the later run agrees (NEGATIVE CONTROL)', () => {
    expect(laterRun(mixed({ verdict: 'true_positive' }))).toBeNull();
  });

  it('keeps the flow of the newest alert on an older server', () => {
    const g = mixed({ verdictSrc: undefined, verdictDst: undefined, windowSrc: undefined, windowDst: undefined });
    expect(rowFlow(g)).toEqual({ src: '198.51.100.149', dst: '192.0.2.119' });
  });

  it('shows the hosts, the sentence and the later line on the row', async () => {
    vi.mocked(getAlerts).mockResolvedValue(queueOf([mixed()]));
    render(
      <MemoryRouter initialEntries={['/alerts?range=30d']}>
        <ShellProvider>
          <Alerts />
        </ShellProvider>
      </MemoryRouter>,
    );
    const row = (await screen.findByText('GPL SHELLCODE x86 setgid 0')).closest('[data-group-key]') as HTMLElement;
    expect(within(row).getByTestId('group-who').textContent).toContain('203.0.113.44');
    expect(within(row).getByTestId('group-who').textContent).not.toContain('198.51.100.149');
    expect(within(row).getByTestId('alert-reason')).toHaveTextContent('Shellcode bytes in traffic');
    const later = within(row).getByTestId('alert-later');
    expect(later).toHaveTextContent('A later investigation reached false positive.');
    expect(within(later).getByRole('button', { name: 'Open it' })).toBeInTheDocument();
  });
});
