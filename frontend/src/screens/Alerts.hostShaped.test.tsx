// The expanded events table, seen through a HOST-shaped detection (a Sigma
// process/file rule off an endpoint agent). That alert class carries no
// source.ip/destination.ip at all, so the backend fills src/dst/host with its
// "—" placeholder string and hands the agent's own address over in `hostIp`.
//
// Two behaviours are pinned here:
//
//   1. "—" is a PLACEHOLDER, not a pivot target. It is a truthy string, so a
//      bare `ev.host ? <link> : <text>` guard turned every absent endpoint into
//      a clickable link to /entity/%E2%80%94 — an entity page for a dash.
//   2. `hostIp` is rendered, and rendered OUTSIDE the src → dst flow. On these
//      alerts it is the only address an analyst can pivot on; putting it in the
//      flow cell would assert a connection nobody observed (which is also why
//      the backend keeps it out of src_ip/dst_ip — those are the sweep's
//      cluster key). On ordinary flow alerts it is absent and must show nothing.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ShellProvider } from '../shell/ShellContext';
import type { AlertEvent } from '../lib/types';

const GROUP = vi.hoisted(() => ({
  id: 'g1',
  name: 'Sigma Suspicious PowerShell Download',
  kind: 'suricata',
  sev: 'high',
  count: 2,
  verdict: 'untriaged',
  conf: null,
  latest: '2m ago',
  inherited: false,
  events: [],
}));

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAlerts: vi.fn().mockResolvedValue([GROUP]),
  getMe: vi.fn().mockResolvedValue({ username: 'me', role: 'analyst', status: '' }),
  getAlertGroupEvents: vi.fn(),
}));

import { getAlertGroupEvents } from '../lib/api';
import { Alerts } from './Alerts';

/** Host-shaped: no flow whatsoever, so the backend sends its "—" placeholder
 *  for both endpoints and resolves the endpoint agent's address instead. */
const HOST_EVENT: AlertEvent = {
  id: 'ev-host',
  ts: '2026-08-07T09:15:00Z',
  ago: '3m',
  sev: 'high',
  src: '—',
  dst: '—',
  host: 'win-ws-01',
  hostIp: '192.168.10.51',
};

/** Ordinary Suricata flow alert: real endpoints, no host address at all. */
const FLOW_EVENT: AlertEvent = {
  id: 'ev-flow',
  ts: '2026-08-07T09:16:00Z',
  ago: '3m',
  sev: 'high',
  src: '192.168.10.77',
  dst: '203.0.113.9',
  host: 'so-sensor',
};

function LocationProbe() {
  const l = useLocation();
  return <div data-testid="loc">{l.pathname}</div>;
}

/** Render the screen and expand the one group so its events table is on screen.
 *  Each event row carries its own checkbox, so the checkbox count is the signal
 *  that the table has actually rendered — awaiting the fetch alone would let
 *  assertions run against the collapsed group row. */
async function expandEvents(events: AlertEvent[]): Promise<void> {
  vi.mocked(getAlertGroupEvents).mockResolvedValue(events);
  render(
    <MemoryRouter initialEntries={['/alerts']}>
      <ShellProvider>
        <Alerts />
        <LocationProbe />
      </ShellProvider>
    </MemoryRouter>,
  );
  await screen.findByText(GROUP.name);
  const before = screen.getAllByRole('checkbox').length;
  fireEvent.click(screen.getByText(GROUP.name));
  await waitFor(() =>
    expect(screen.getAllByRole('checkbox').length).toBe(before + events.length),
  );
}

const path = () => screen.getByTestId('loc').textContent;

/** The single expanded EVENT row. Scoping matters: the collapsed group row above
 *  it renders its own "—"s, and clicking one of those toggles the group shut,
 *  detaching the very cells under test. Anchored on the event's own relative age
 *  ("3m ago"), which the group row ("2m ago") cannot collide with. */
const eventRow = (): HTMLElement =>
  screen.getByText('3m ago').closest('.grid') as HTMLElement;

describe('events table — the "—" placeholder is not an entity', () => {
  beforeEach(() => vi.mocked(getAlertGroupEvents).mockReset());

  it('offers no pivot on an absent source, destination or host', async () => {
    // Worst case: the backend resolved nothing at all for this event.
    await expandEvents([{ ...HOST_EVENT, host: '—', hostIp: null }]);

    // Nothing in the row advertises itself as a pivot to the placeholder.
    // Pre-fix all three cells did — "—" is a truthy string.
    expect(within(eventRow()).queryAllByTitle('Pivot to —')).toHaveLength(0);
  });

  it('does not navigate to /entity/— when a placeholder is clicked', async () => {
    await expandEvents([{ ...HOST_EVENT, host: '—', hostIp: null }]);
    const dashes = within(eventRow()).getAllByText('—');
    expect(dashes.length).toBeGreaterThanOrEqual(3); // at least src, dst, host
    dashes.forEach((el) => fireEvent.click(el));

    // Pre-fix this landed on /entity/%E2%80%94 — an entity page for a character.
    expect(path()).toBe('/alerts');
  });

  it('still pivots on endpoints that are real', async () => {
    await expandEvents([FLOW_EVENT]);
    fireEvent.click(await screen.findByTitle('Pivot to 203.0.113.9'));
    await waitFor(() => expect(path()).toBe('/entity/203.0.113.9'));
  });
});

describe('events table — hostIp gives a host detection an address', () => {
  beforeEach(() => vi.mocked(getAlertGroupEvents).mockReset());

  it('renders the endpoint agent address for a host-shaped alert', async () => {
    await expandEvents([HOST_EVENT]);
    expect(within(eventRow()).getByText('192.168.10.51')).toBeTruthy();
  });

  it('pivots to the host address entity page', async () => {
    await expandEvents([HOST_EVENT]);
    fireEvent.click(within(eventRow()).getByTitle('Pivot to 192.168.10.51'));
    await waitFor(() => expect(path()).toBe('/entity/192.168.10.51'));
  });

  it('renders it outside the src → dst flow, never as an endpoint', async () => {
    await expandEvents([HOST_EVENT]);
    const row = eventRow();
    const addr = within(row).getByText('192.168.10.51');
    // The flow cell is the one holding the src → dst arrow.
    const flowCell = within(row).getByText('→').closest('div') as HTMLElement;
    // It must not have swallowed the host address: an analyst reading
    // "192.168.10.51 → —" would believe a connection was observed.
    expect(flowCell.contains(addr)).toBe(false);
    // ...and it must sit alongside the host NAME, which is what it describes.
    expect(within(row).getByText('win-ws-01').closest('div')!.contains(addr)).toBe(true);
  });

  it('shows nothing extra on an ordinary flow alert', async () => {
    await expandEvents([FLOW_EVENT]);
    const row = eventRow();
    expect(within(row).getByText('so-sensor')).toBeTruthy();
    // Absence is the quiet default — no empty slot, no placeholder line.
    expect(within(row).queryByTitle(/^Pivot to 10\.9\.8\.51$/)).toBeNull();
    expect(within(row).queryByText('null')).toBeNull();
    expect(within(row).queryByText('undefined')).toBeNull();
  });
});
