// A detection group can carry hundreds of events that are visually
// IDENTICAL — same endpoints, severity, host, and verdict provenance,
// differing only in their own timestamp and es_id. Rendering one row per
// event turns those into a useless wall (BPFDoor: ×327 in one minute).
// bucketEvents (lib/alertEventBuckets) collapses a consecutive run of ≥3
// such events into a single summary row; these tests pin the UI wiring:
// the bucket row itself, the "Show each" unfold, and that the bucket
// checkbox is a true stand-in for every event id it covers.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ShellProvider } from '../shell/ShellContext';
import type { AlertEvent } from '../lib/types';

const GROUP = vi.hoisted(() => ({
  id: 'g1',
  name: 'ET SCAN Nmap Sweep',
  kind: 'suricata',
  sev: 'high',
  count: 5,
  verdict: 'untriaged',
  conf: null,
  latest: '9m ago', // distinct from every FLOOD event's own "ago" below
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

/** Five events indistinguishable on every rendered column — a flood. */
const FLOOD: AlertEvent[] = Array.from({ length: 5 }, (_, i) => ({
  id: `flood-${i}`,
  src: '192.168.10.1',
  dst: '192.168.10.15',
  host: 'so-sensor',
  sev: 'high',
  ts: `2026-08-22T07:3${i}:00Z`,
  ago: `${i}m`,
  inheritedReason: 'inherited 2d ago',
  invId: 'inv-1',
}));

/** Two events differing on dst — must stay as plain rows, never a bucket. */
const DISTINCT: AlertEvent[] = [
  { id: 'd1', src: '192.168.10.1', dst: '192.168.10.15', host: 'so-sensor', sev: 'high', ts: '2026-08-22T07:30:00Z', ago: '1m' },
  { id: 'd2', src: '192.168.10.1', dst: '192.168.9.22', host: 'so-sensor', sev: 'high', ts: '2026-08-22T07:31:00Z', ago: '2m' },
];

/** Render the screen and expand the one group so its events table is on screen. */
async function expandGroup(events: AlertEvent[]): Promise<void> {
  vi.mocked(getAlertGroupEvents).mockResolvedValue(events);
  render(
    <MemoryRouter initialEntries={['/alerts']}>
      <ShellProvider>
        <Alerts />
      </ShellProvider>
    </MemoryRouter>,
  );
  await screen.findByText(GROUP.name);
  fireEvent.click(screen.getByText(GROUP.name));
  await waitFor(() => expect(getAlertGroupEvents).toHaveBeenCalled());
}

describe('event floods collapse into summary buckets', () => {
  beforeEach(() => vi.mocked(getAlertGroupEvents).mockReset());

  it('a run of 5 identical events renders one bucket row, not five plain rows', async () => {
    await expandGroup(FLOOD);
    const rows = await screen.findAllByTestId('event-bucket-row');
    expect(rows).toHaveLength(1);
    expect(within(rows[0]).getByText('×5')).toBeTruthy();
  });

  it('"Show each" unfolds the bucket into its individual rows', async () => {
    await expandGroup(FLOOD);
    await screen.findAllByTestId('event-bucket-row');
    fireEvent.click(screen.getByRole('button', { name: 'Show each (5)' }));
    await waitFor(() => expect(screen.queryAllByTestId('event-bucket-row')).toHaveLength(0));
    // Each unfolded event carries its own relative age, one per event.
    for (const e of FLOOD) {
      expect(screen.getByText(`${e.ago} ago`)).toBeTruthy();
    }
  });

  it('the bucket checkbox selects all 5 covered event ids', async () => {
    await expandGroup(FLOOD);
    const row = (await screen.findAllByTestId('event-bucket-row'))[0];
    fireEvent.click(within(row).getByRole('checkbox'));
    const strip = await screen.findByTestId('list-toolbar-selection');
    // No group is selected — only the 5 events the bucket covers.
    expect(within(strip).queryByText(/group/)).toBeNull();
    expect(within(strip).getByText(/5 event/)).toBeTruthy();
  });

  it('two distinct events never render as a bucket', async () => {
    await expandGroup(DISTINCT);
    await waitFor(() => expect(screen.getAllByRole('checkbox').length).toBeGreaterThan(1));
    expect(screen.queryAllByTestId('event-bucket-row')).toHaveLength(0);
  });

  it('an unfolded bucket comes back summarized after a filter change', async () => {
    await expandGroup(FLOOD);
    await screen.findAllByTestId('event-bucket-row');
    fireEvent.click(screen.getByRole('button', { name: 'Show each (5)' }));
    await waitFor(() => expect(screen.queryAllByTestId('event-bucket-row')).toHaveLength(0));

    // Changing the time range resets expansion + cached events (F59-style
    // reset effect) — the group key is stable, so without also clearing
    // openBuckets a stale "<groupKey>:0" entry would re-unfold the fresh
    // page on re-expand.
    fireEvent.click(screen.getByRole('button', { name: '7d' }));

    fireEvent.click(await screen.findByText(GROUP.name));
    await waitFor(() => expect(screen.queryAllByTestId('event-bucket-row')).toHaveLength(1));
  });
});
