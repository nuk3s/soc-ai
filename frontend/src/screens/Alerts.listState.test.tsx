// What the Alerts list says about its own state (dogfood 2026-10-01: P5, P7,
// P8, P9, D16, RL8, RL12, RL13, RL15).
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { AlertGroup } from '../lib/types';

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
    escalateGroup: vi.fn(),
    assignAlert: vi.fn(),
    startAutoTriage: vi.fn(),
    getAutoTriageStatus: vi.fn(),
    stopAutoTriage: vi.fn(),
    listSavedViews: vi.fn(),
  };
});

import { ApiError, getAlerts, getAutoTriageStatus, getMe, listSavedViews } from '../lib/api';
import { queueOf } from '../test/alertQueue';
import { Alerts } from './Alerts';
import { ShellProvider } from '../shell/ShellContext';

const mkGroup = (o: Partial<AlertGroup> = {}): AlertGroup => ({
  id: 'es-1',
  name: 'ET SCAN Test Detection',
  kind: 'suricata',
  sev: 'high',
  count: 3,
  verdict: 'untriaged',
  conf: null,
  latest: '1m ago',
  inherited: false,
  events: [],
  ...o,
});

let intervalSpy: { mock: { calls: unknown[][] }; mockRestore: () => void };
let location = '';

function LocationProbe() {
  const l = useLocation();
  location = l.pathname + l.search;
  return null;
}

beforeEach(() => {
  vi.clearAllMocks();
  location = '';
  vi.mocked(getAlerts).mockResolvedValue(queueOf([mkGroup()]));
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

function mount(path = '/alerts') {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <ShellProvider>
        <Alerts />
        <LocationProbe />
      </ShellProvider>
    </MemoryRouter>,
  );
}

async function poll() {
  const call = intervalSpy.mock.calls.find((c) => c[1] === 10000);
  expect(call).toBeTruthy();
  await act(async () => {
    (call![0] as () => void)();
  });
}

const headerLine = () => screen.getByText(/untriaged ·/).textContent ?? '';

describe('a range change shows that the new window is loading (P5)', () => {
  it('does not caption the old window with the new chip pressed', async () => {
    mount();
    await screen.findByText('ET SCAN Test Detection');
    expect(headerLine()).toContain('1 detection');

    vi.mocked(getAlerts).mockReturnValue(new Promise(() => {}));
    fireEvent.click(screen.getByRole('button', { name: '30d' }));

    expect(await screen.findByText(/Loading the 30d window/)).toBeTruthy();
    expect(headerLine()).not.toContain('1 detection');
    expect(headerLine()).toContain('counting');
  });

  it('NEGATIVE CONTROL: a background poll does not flash the loading line', async () => {
    mount();
    await screen.findByText('ET SCAN Test Detection');
    await poll();
    expect(screen.queryByText(/Loading the/)).toBeNull();
    expect(headerLine()).toContain('1 detection');
  });
});

describe('the filters live in the URL (P8, RL15)', () => {
  it('writes the range, the hide-acknowledged toggle and the sort back on change', async () => {
    mount('/alerts?view=all');
    await screen.findByText('ET SCAN Test Detection');
    expect(location).toBe('/alerts?view=all');

    fireEvent.click(screen.getByRole('button', { name: '7d' }));
    await waitFor(() => expect(location).toContain('range=7d'));
    fireEvent.click(screen.getByRole('button', { name: /Hide acknowledged/ }));
    await waitFor(() => expect(location).toContain('hide_acked=false'));
    fireEvent.click(screen.getByText(/^Last seen/));
    await waitFor(() => expect(location).toContain('sort=latest%3Adesc'));
    // Other parameters stay.
    expect(location).toContain('view=all');
  });

  it('seeds the sort from the URL', async () => {
    mount('/alerts?sort=count:asc');
    await screen.findByText('ET SCAN Test Detection');
    expect(screen.getByText(/^Sort/).textContent).toContain('count ↑');
  });

  it('NEGATIVE CONTROL: default values leave the URL clean', async () => {
    mount('/alerts');
    await screen.findByText('ET SCAN Test Detection');
    expect(location).toBe('/alerts');
  });
});

describe('a failing poll names the age of the rows (RL12)', () => {
  it('says the rows are the last good read', async () => {
    mount();
    await screen.findByText('ET SCAN Test Detection');
    vi.mocked(getAlerts).mockRejectedValue(new ApiError('The grid did not answer.', 503));
    await poll();

    const line = await screen.findByText(/^Showing the last good read from \d\d:\d\d\. The grid did not answer\.$/);
    expect(line).toBeTruthy();
    expect(screen.getByText('ET SCAN Test Detection')).toBeTruthy();
  });

  it('NEGATIVE CONTROL: a good poll shows no stale line', async () => {
    mount();
    await screen.findByText('ET SCAN Test Detection');
    await poll();
    expect(screen.queryByText(/last good read/)).toBeNull();
  });
});

describe('an invalid filter is the analyst to fix, not an outage (P7, RL8)', () => {
  const HINT = 'The filter names a field the grid does not allow.';

  it('shows the hint inline, offers no Retry and stops polling', async () => {
    vi.mocked(getAlerts).mockRejectedValue(new ApiError(HINT, 400, 'bad_oql'));
    mount('/alerts?q=bogus:field');

    expect(await screen.findByText('The filter is not valid')).toBeTruthy();
    expect(screen.getByText(HINT)).toBeTruthy();
    expect(screen.queryByText('Could not load this view')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Retry' })).toBeNull();

    const sent = vi.mocked(getAlerts).mock.calls.length;
    await poll();
    await poll();
    expect(vi.mocked(getAlerts).mock.calls.length).toBe(sent);
  });

  it('NEGATIVE CONTROL: a grid outage keeps the Retry card', async () => {
    vi.mocked(getAlerts).mockRejectedValue(new ApiError('The grid did not answer.', 503));
    mount();
    expect(await screen.findByText('Could not load this view')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Retry' })).toBeTruthy();
    expect(screen.queryByText('The filter is not valid')).toBeNull();
  });
});

describe('the empty state names the filter that emptied the list (D16, P9, RL13)', () => {
  it('names the Mine view', async () => {
    vi.mocked(getAlerts).mockResolvedValue(queueOf([mkGroup({ owner: 'someone-else' })]));
    mount('/alerts?view=mine');
    expect(await screen.findByText('No detection is assigned to you in this window.')).toBeTruthy();
    expect(screen.queryByText(/Widen the time range/)).toBeNull();
  });

  it('names the verdict filter', async () => {
    vi.mocked(getAlerts).mockResolvedValue(queueOf([mkGroup({ verdict: 'false_positive' })]));
    mount('/alerts?verdict=true_positive');
    expect(
      await screen.findByText('No detection matches the verdict filter in this window.'),
    ).toBeTruthy();
  });

  it('does not offer to widen the widest window', async () => {
    vi.mocked(getAlerts).mockResolvedValue(queueOf([]));
    mount('/alerts?range=30d&hide_acked=false');
    expect(await screen.findByText('No detection fired in this window.')).toBeTruthy();
  });

  it('NEGATIVE CONTROL: a narrow window with no filter still offers to widen it', async () => {
    vi.mocked(getAlerts).mockResolvedValue(queueOf([]));
    mount('/alerts?range=1h&hide_acked=false');
    expect(await screen.findByText('No detection fired in this window. Widen the time range.')).toBeTruthy();
  });
});

// The default 24 h list was empty and pointed nowhere, while the last 30 days
// held 4 groups (dogfood 2026-10-06, W2).
describe('the empty state offers the wider window, and the landing widens to the newest row', () => {
  const byRange = (rows: Record<string, AlertGroup[]>) =>
    vi.mocked(getAlerts).mockImplementation((q) => Promise.resolve(queueOf(rows[q?.range ?? ''] ?? [])));

  it('offers "Show the last 7 days" on an empty narrow window, and reads that window on a press', async () => {
    vi.mocked(getAlerts).mockResolvedValue(queueOf([]));
    mount('/alerts?range=1h');
    const widen = await screen.findByTestId('alerts-widen');
    expect(widen.textContent).toBe('Show the last 7 days');
    fireEvent.click(widen);
    await waitFor(() =>
      expect(vi.mocked(getAlerts).mock.calls.some((c) => c[0]?.range === '7d')).toBe(true),
    );
    await waitFor(() => expect(screen.getByTestId('alerts-widen').textContent).toBe('Show the last 30 days'));
  });

  it('offers no wider window at the widest one', async () => {
    vi.mocked(getAlerts).mockResolvedValue(queueOf([]));
    mount('/alerts?range=30d');
    await screen.findByText(/No open detection in this window/);
    expect(screen.queryByTestId('alerts-widen')).toBeNull();
  });

  it('lands on the narrowest window that holds a group, and says so', async () => {
    byRange({ '30d': [mkGroup({ name: 'ET OLD Detection' })] });
    mount('/alerts');
    expect(await screen.findByText('ET OLD Detection')).toBeTruthy();
    expect(screen.getByTestId('alerts-widened').textContent).toBe(
      'The last 24 hours held no open detection. The list shows the last 30 days.',
    );
    expect(vi.mocked(getAlerts).mock.calls.some((c) => c[0]?.range === '7d')).toBe(true);
  });

  // NEGATIVE CONTROL. A link names its window, and the screen keeps it.
  it('keeps a window a link named, empty or not', async () => {
    byRange({ '30d': [mkGroup({ name: 'ET OLD Detection' })] });
    mount('/alerts?range=24h');
    await screen.findByText(/No open detection in this window/);
    expect(vi.mocked(getAlerts).mock.calls.every((c) => c[0]?.range === '24h')).toBe(true);
    expect(screen.queryByTestId('alerts-widened')).toBeNull();
  });

  // NEGATIVE CONTROL. A list with rows reads nothing more.
  it('reads no wider window when the default one has a group', async () => {
    mount('/alerts');
    await screen.findByText('ET SCAN Test Detection');
    expect(vi.mocked(getAlerts).mock.calls.every((c) => c[0]?.range === '24h')).toBe(true);
  });
});
