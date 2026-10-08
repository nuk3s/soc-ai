// The Alerts row named the rule, the count, the severity and the verdict, and
// no machine. The source showed only after the analyst expanded the row
// (dogfood 2026-10-06, W3). The row now names the flow of its latest alert,
// how many other sources the group holds, and the machine.
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
import { Alerts } from './Alerts';

const group = (o: Partial<AlertGroup>): AlertGroup => ({
  id: 'g1',
  name: 'ET SCAN Potential SSH Scan',
  kind: 'suricata',
  sev: 'medium',
  count: 9,
  verdict: 'untriaged',
  conf: null,
  latest: '2m ago',
  inherited: false,
  events: [],
  ...o,
});

const mount = () =>
  render(
    <MemoryRouter initialEntries={['/alerts?range=30d']}>
      <ShellProvider>
        <Alerts />
      </ShellProvider>
    </MemoryRouter>,
  );

const who = async (name: string) =>
  within((await screen.findByText(name)).closest('[data-group-key]') as HTMLElement).getByTestId('group-who');

describe('the group row names who is involved', () => {
  it('names the flow, the other sources and the sensor', async () => {
    vi.mocked(getAlerts).mockResolvedValue(
      queueOf([group({ src: '192.0.2.26', dst: '192.0.2.1', host: 'so-sensor', srcCount: 3 })]),
    );
    mount();
    const line = await who('ET SCAN Potential SSH Scan');
    expect(line.textContent).toContain('192.0.2.26');
    expect(line.textContent).toContain('+2');
    expect(line.textContent).toContain('· on so-sensor');
  });

  it('names the machine of a host log, and says it has no flow', async () => {
    vi.mocked(getAlerts).mockResolvedValue(
      queueOf([group({ name: 'Execution via Interactive Secondary Logon', kind: 'sigma', host: 'ws-01', srcCount: 0 })]),
    );
    mount();
    const line = await who('Execution via Interactive Secondary Logon');
    expect(line.textContent).toBe('on ws-01 · host log');
  });

  // NEGATIVE CONTROL. One source has no "+0".
  it('adds no count for a group with one source', async () => {
    vi.mocked(getAlerts).mockResolvedValue(
      queueOf([group({ src: '192.0.2.26', dst: '192.0.2.1', srcCount: 1 })]),
    );
    mount();
    const line = await who('ET SCAN Potential SSH Scan');
    expect(line.textContent).not.toMatch(/\+\d/);
  });
});
