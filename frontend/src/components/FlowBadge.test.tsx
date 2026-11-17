// J2 (prod review 2026-11-12, ui-core 9 and 11). The verdict card and both
// lists showed "10.x.x.x → 10.y.y.y" while the Hosts page knew that one end
// was a named workstation and the other a server. The analyst held an address
// table in memory to know that a workstation attacked a server. Each end now
// names its machine when the Hosts data has a name or a role. The group row of
// Alerts showed the source in amber and its event rows showed it in green.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ShellProvider } from '../shell/ShellContext';
import type { AlertEvent, AlertGroup } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getHostNames: vi.fn(),
  getAlerts: vi.fn(),
  getAlertGroupEvents: vi.fn(),
  getMe: vi.fn().mockResolvedValue({ username: 'me', role: 'analyst', status: '' }),
}));

import { getAlertGroupEvents, getAlerts, getHostNames, type HostName } from '../lib/api';
import { resetHostNames } from '../lib/hostNames';
import { Alerts } from '../screens/Alerts';
import { FlowBadge } from './FlowBadge';

const HOSTS: Record<string, HostName> = {
  '10.20.30.5': { key: 'agent:a-ws', name: 'ws-01', role: 'workstation', roleGuess: false },
  '10.40.50.7': { key: 'ip:10.40.50.7', name: null, role: 'server', roleGuess: true },
  '10.40.50.8': { key: 'agent:a-dc', name: 'mainsrv', role: 'domain_controller', roleGuess: false },
};

beforeEach(() => {
  resetHostNames();
  vi.mocked(getHostNames).mockReset();
  vi.mocked(getHostNames).mockImplementation(async (ips) => ({
    hosts: Object.fromEntries(ips.filter((ip) => ip in HOSTS).map((ip) => [ip, HOSTS[ip]])),
  }));
});

describe('FlowBadge names each end', () => {
  it('prints the name and the role before a known address', async () => {
    render(<FlowBadge src="10.20.30.5" dst="10.40.50.8" />);
    const src = await screen.findByTestId('flow-src');
    await waitFor(() => expect(src.textContent).toBe('ws-01 (workstation)10.20.30.5'));
    expect(within(src).getByTestId('host-label').textContent).toBe('ws-01 (workstation)');
    // The role reads in words.
    expect(screen.getByTestId('flow-dst').textContent).toBe('mainsrv (domain controller)10.40.50.8');
    expect(screen.getByTestId('flow-badge').getAttribute('title')).toBe(
      'ws-01 (workstation) 10.20.30.5 → mainsrv (domain controller) 10.40.50.8',
    );
  });

  it('marks a guessed role and prints a role with no name in brackets', async () => {
    render(<FlowBadge src="10.20.30.5" dst="10.40.50.7" />);
    await waitFor(() => expect(screen.getByTestId('flow-dst').textContent).toBe('(server, guess)10.40.50.7'));
  });

  it('prints an address with no name alone, with no empty brackets', async () => {
    // NEGATIVE CONTROL. The Hosts data knows nothing of 10.40.50.9.
    render(<FlowBadge src="10.20.30.5" dst="10.40.50.9" />);
    await waitFor(() => expect(screen.getByTestId('flow-src').textContent).toContain('ws-01'));
    const dst = screen.getByTestId('flow-dst');
    expect(dst.textContent).toBe('10.40.50.9');
    expect(within(dst).queryByTestId('host-label')).toBeNull();
    expect(screen.getByTestId('flow-badge').textContent).not.toContain('()');
  });

  it('asks once for every badge of a render, and not again on the next render', async () => {
    const { rerender } = render(
      <>
        <FlowBadge src="10.20.30.5" dst="10.40.50.7" />
        <FlowBadge src="10.20.30.5" dst="10.40.50.8:445" />
        <FlowBadge src="10.40.50.9" dst="—" />
      </>,
    );
    await waitFor(() => expect(getHostNames).toHaveBeenCalledTimes(1));
    expect([...vi.mocked(getHostNames).mock.calls[0][0]].sort()).toEqual([
      '10.20.30.5',
      '10.40.50.7',
      '10.40.50.8',
      '10.40.50.9',
    ]);
    await screen.findAllByText('ws-01 (workstation)');
    rerender(
      <>
        <FlowBadge src="10.20.30.5" dst="10.40.50.7" />
        <FlowBadge src="10.40.50.9" dst="10.40.50.8" />
      </>,
    );
    await Promise.resolve();
    expect(getHostNames).toHaveBeenCalledTimes(1);
  });

  it('keeps the bare address when the read fails', async () => {
    vi.mocked(getHostNames).mockRejectedValue(new Error('Network error.'));
    render(<FlowBadge src="10.20.30.5" dst="10.40.50.8" />);
    await waitFor(() => expect(getHostNames).toHaveBeenCalled());
    await Promise.resolve();
    expect(screen.getByTestId('flow-badge').textContent).toBe('10.20.30.5→10.40.50.8');
  });
});

describe('the source and the destination keep one colour', () => {
  it('colours the group row and the event row the same way', async () => {
    const group: AlertGroup = {
      id: 'g1',
      name: 'ET EXPLOIT Example Request',
      kind: 'suricata',
      sev: 'medium',
      count: 2,
      verdict: 'untriaged',
      conf: null,
      latest: '2m',
      inherited: false,
      events: [],
      src: '10.20.30.5',
      dst: '10.40.50.8',
    };
    const events: AlertEvent[] = [
      { id: 'e1', src: '10.20.30.5', dst: '10.40.50.8', port: 443, host: 'so-sensor', sev: 'medium', ts: '2026-11-12T10:00:00Z', ago: '2m' },
    ];
    vi.mocked(getAlerts).mockResolvedValue({ groups: [group], truncated: false, other_docs: 0 });
    vi.mocked(getAlertGroupEvents).mockResolvedValue(events);
    render(
      <MemoryRouter initialEntries={['/alerts']}>
        <ShellProvider>
          <Alerts />
        </ShellProvider>
      </MemoryRouter>,
    );
    fireEvent.click(await screen.findByText(group.name));
    await waitFor(() => expect(screen.getAllByTestId('flow-badge')).toHaveLength(2));
    const [groupRow, eventRow] = screen.getAllByTestId('flow-badge');
    const tone = (badge: HTMLElement, end: string) => {
      const value = within(within(badge).getByTestId(end)).getByText(end === 'flow-src' ? '10.20.30.5' : '10.40.50.8');
      return value.className.split(' ').filter((c) => c.startsWith('text-mono-'));
    };
    expect(tone(groupRow, 'flow-src')).toEqual(['text-mono-amber']);
    expect(tone(groupRow, 'flow-dst')).toEqual(['text-mono-green']);
    expect(tone(eventRow, 'flow-src')).toEqual(tone(groupRow, 'flow-src'));
    expect(tone(eventRow, 'flow-dst')).toEqual(tone(groupRow, 'flow-dst'));
    // The port prints once, against the destination of the event row.
    expect(eventRow.textContent).toContain('10.40.50.8:443');
    // Both rows name the machines.
    await waitFor(() => expect(within(eventRow).getAllByTestId('host-label')).toHaveLength(2));
    expect(within(groupRow).getAllByTestId('host-label').map((e) => e.textContent)).toEqual([
      'ws-01 (workstation)',
      'mainsrv (domain controller)',
    ]);
  });
});
