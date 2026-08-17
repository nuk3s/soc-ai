// Review bucket FE1_alerts_shell — regression tests for the confirmed findings
// in Alerts.tsx + the shell chrome. Each test FAILS against the pre-fix code and
// PASSES after: they drive the real components (real ShellProvider / router /
// keyboard layer), mocking only the network layer.
//
//   F11 — row/selection state keyed on a STABLE identity, not the newest-event
//         ES `_id` that changes every poll.
//   F12 — keyboard focus tracked by group identity, not list index.
//   F13 — command-palette "Bulk investigate all untriaged" carries intent in the
//         navigation state so it works before Alerts mounts.
//   F40 — Drawer's Escape handler is gated on the shared paletteOpen signal.
//   F59 — per-event selection is cleared when the filter that discarded its rows
//         changes.
//   F61 — sub-minute notification time renders "just now", not "now ago".
//   F62 — the sidebar lights "Investigations" on /investigation/:id and /entity.
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { ToastProvider } from '../lib/toast';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AlertEvent, AlertGroup } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => {
  const orig = await importOriginal<typeof import('../lib/api')>();
  return {
    ...orig,
    getAlerts: vi.fn(),
    getMe: vi.fn(),
    getAlertGroupEvents: vi.fn(),
    getInvestigation: vi.fn(() => new Promise(() => {})),
    getInvestigations: vi.fn(),
    getRepresentative: vi.fn(),
    startHunt: vi.fn(),
    ackGroup: vi.fn(),
    ackEvents: vi.fn(),
    escalateGroup: vi.fn(),
    assignAlert: vi.fn(),
    startAutoTriage: vi.fn(),
    getAutoTriageStatus: vi.fn(),
    stopAutoTriage: vi.fn(),
    getWorkspaces: vi.fn(),
    getNotifications: vi.fn(),
    getHealth: vi.fn(),
    listSavedViews: vi.fn(),
    signOut: vi.fn(),
  };
});
// Spread the real module and override only what these tests need held still: a
// hand-listed mock silently drops any export the module later grows, and the
// break then lands on whichever screen imports it next rather than here. F61
// below asserts the real relative-time formatter, so it must NOT be stubbed.
vi.mock('../lib/notifications', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/notifications')>()),
  getDismissed: () => new Set<string>(),
  dismissNotification: vi.fn(),
  dismissMany: vi.fn(),
  formatNotificationTitle: (t: string) => t,
}));

import {
  ackGroup,
  getAlertGroupEvents,
  getAlerts,
  getAutoTriageStatus,
  getHealth,
  listSavedViews,
  getInvestigations,
  getMe,
  getNotifications,
  getRepresentative,
  getWorkspaces,
  startAutoTriage,
} from '../lib/api';
import { Alerts } from './Alerts';
import { CommandPalette } from '../shell/CommandPalette';
import { Sidebar } from '../shell/Sidebar';
import { Topbar } from '../shell/Topbar';
import { Drawer } from '../components/Drawer';
import { ShellProvider } from '../shell/ShellContext';

const mkGroup = (o: Partial<AlertGroup> & Pick<AlertGroup, 'id' | 'name'>): AlertGroup => ({
  kind: 'suricata',
  sev: 'high',
  count: 1,
  verdict: 'untriaged',
  conf: null,
  latest: '1m ago',
  inherited: false,
  events: [],
  ...o,
});
const mkEvent = (o: Partial<AlertEvent> & Pick<AlertEvent, 'id'>): AlertEvent => ({
  src: '10.0.0.1',
  dst: '10.0.0.2',
  host: 'sensor',
  ...o,
});

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(getAlerts).mockResolvedValue([]);
  vi.mocked(getAlertGroupEvents).mockResolvedValue([]);
  vi.mocked(getMe).mockResolvedValue({ username: 'me', role: 'analyst', status: '' });
  vi.mocked(getInvestigations).mockResolvedValue([]);
  vi.mocked(getRepresentative).mockResolvedValue({ alert_id: 'rep', reason: 'x' } as never);
  vi.mocked(ackGroup).mockResolvedValue({ acked: 1, failed: 0, capped: false } as never);
  vi.mocked(startAutoTriage).mockResolvedValue({ active: false, total: 0, hunted: 0, skipped: 0, failed: 0 } as never);
  vi.mocked(getAutoTriageStatus).mockResolvedValue({ active: false, total: 0, hunted: 0, skipped: 0, failed: 0 } as never);
  vi.mocked(getWorkspaces).mockResolvedValue([]);
  vi.mocked(getNotifications).mockResolvedValue([]);
  vi.mocked(getHealth).mockResolvedValue({ es: { ok: true, detail: '' }, llm: { ok: true, detail: '' } } as never);
  vi.mocked(listSavedViews).mockResolvedValue([]);
});

function renderAlerts({ toasts = false }: { toasts?: boolean } = {}) {
  // The toaster is opt-in: most tests assert on in-table DOM and useToast is a
  // no-op outside a provider, so only the tests that read a notice pay for it.
  const tree = (
    <MemoryRouter initialEntries={['/alerts']}>
      <ShellProvider>
        <Alerts />
      </ShellProvider>
    </MemoryRouter>
  );
  return render(toasts ? <ToastProvider>{tree}</ToastProvider> : tree);
}

// Grab the alerts screen's 10s background-poll callback (the one useAsync
// registers) so we can drive a refetch by hand instead of waiting real time.
function capturePoll(spy: { mock: { calls: unknown[][] } }): () => void {
  const call = spy.mock.calls.find((c) => c[1] === 10000);
  expect(call).toBeTruthy();
  return call![0] as () => void;
}

describe('F11 — selection survives the ES-id churn of a background poll', () => {
  it('bulk-investigates the CURRENT representative id, not the stale key/id', async () => {
    // Same detection (kind+name) across polls, but a new event landed so the
    // backend hands back a new representative `id` and a higher count.
    const before = mkGroup({ id: 'es-1', name: 'ET SCAN Noisy', count: 2000 });
    const after = mkGroup({ id: 'es-2', name: 'ET SCAN Noisy', count: 2001 });
    vi.mocked(getAlerts).mockResolvedValueOnce([before]).mockResolvedValue([after]);
    const intervalSpy = vi.spyOn(window, 'setInterval');
    try {
      renderAlerts();
      await screen.findByText('ET SCAN Noisy');

      // Tick the group (via the header "Select all", which selects every visible
      // row) — this is the selection an analyst makes before a new event lands.
      fireEvent.click(screen.getByTitle('Select all'));
      // Bulk bar is up.
      expect(screen.getAllByRole('button', { name: 'Bulk Investigate' }).length).toBe(2);

      // A poll lands with the fresh id.
      capturePoll(intervalSpy)();
      await waitFor(() => expect(getAlerts).toHaveBeenCalledTimes(2));

      // Fire the bulk-bar Bulk Investigate.
      const buttons = screen.getAllByRole('button', { name: 'Bulk Investigate' });
      fireEvent.click(buttons[buttons.length - 1]);

      // The payload must be the CURRENT representative id (es-2). Pre-fix this
      // posted the stale key (es-1) and the backend reported it not_found.
      await waitFor(() => expect(startAutoTriage).toHaveBeenCalled());
      expect(startAutoTriage).toHaveBeenCalledWith({ alertIds: ['es-2'] });
    } finally {
      intervalSpy.mockRestore();
    }
  });
});

describe('F12 — keyboard focus follows the group, not the row index', () => {
  it('acks the highlighted detection after a poll re-sorts the list above it', async () => {
    const a = mkGroup({ id: 'a1', name: 'AAA', sev: 'high' });
    const b = mkGroup({ id: 'b1', name: 'BBB', sev: 'high' });
    const c = mkGroup({ id: 'c1', name: 'CCC', sev: 'critical' });
    // First render: [AAA, BBB]. After the poll a new CRITICAL group sorts to the
    // top, pushing AAA from index 0 to index 1.
    vi.mocked(getAlerts).mockResolvedValueOnce([a, b]).mockResolvedValue([c, a, b]);
    const intervalSpy = vi.spyOn(window, 'setInterval');
    try {
      renderAlerts();
      await screen.findByText('AAA');

      // Highlight the first row (AAA) with `j`.
      fireEvent.keyDown(window, { key: 'j' });

      // Poll re-sorts: CCC appears above, AAA is now index 1. `act` flushes the
      // poll's already-resolved fetch and the re-render it schedules, so the
      // list below is settled rather than raced — this test failed ONLY on a
      // contended runner, where a bare findByText/waitFor can miss a hop the
      // mock has in fact already completed.
      await act(async () => {
        capturePoll(intervalSpy)();
      });
      expect(screen.getByText('CCC')).toBeTruthy();

      // `a` must acknowledge AAA (the row the analyst highlighted), never the
      // Cobalt-Strike-shaped CCC that slid into index 0.
      await act(async () => {
        fireEvent.keyDown(window, { key: 'a' });
      });
      expect(ackGroup).toHaveBeenCalled();
      expect(vi.mocked(ackGroup).mock.calls[0][0].name).toBe('AAA');
    } finally {
      intervalSpy.mockRestore();
    }
  });
});

describe('F59 / context-row morph — a selection cannot be stranded by a filter change', () => {
  it('keeps the filters usable during a selection, and drops the selection out loud if one changes', async () => {
    // This used to assert the opposite: the filter row was REPLACED by the bulk
    // bar, which prevented a stranded selection structurally — by removing the
    // controls. Generalised to the shared toolbar that rule deleted the only
    // filter Hunts has and blanked a live search term on Investigations, so the
    // same guarantee is made a different way: the filters stay, and changing one
    // clears the selection and says so.
    const g = mkGroup({ id: 'es-1', name: 'ET SCAN Noisy', count: 3 });
    vi.mocked(getAlerts).mockResolvedValue([g]);
    vi.mocked(getAlertGroupEvents).mockResolvedValue([mkEvent({ id: 'ev-1', ts: '2026-07-30T00:00:00Z' })]);
    renderAlerts({ toasts: true });
    await screen.findByText('ET SCAN Noisy');

    expect(screen.getByRole('button', { name: /Hide acknowledged/ })).toBeTruthy();

    // Expand the group (row click) → its events load, then tick one event.
    const beforeExpand = screen.getAllByRole('checkbox').length;
    fireEvent.click(screen.getByText('ET SCAN Noisy'));
    await waitFor(() => expect(getAlertGroupEvents).toHaveBeenCalled());
    // CALLED is not RENDERED. Without this wait the last checkbox is still the
    // GROUP's, so the click selects all 3 events and the bar reads "Ack 3
    // events" — which `findByText('Ack 1 event')` then waits out and fails on,
    // with a message that blames the label rather than the selection. Passed on
    // an idle box, failed the loaded CI runner.
    await waitFor(() =>
      expect(screen.getAllByRole('checkbox').length).toBeGreaterThan(beforeExpand),
    );
    const boxes = screen.getAllByRole('checkbox');
    fireEvent.click(boxes[boxes.length - 1]);
    await screen.findByText('Ack 1 event');

    // The filter is STILL there and still operable while the selection stands.
    const hideAcked = screen.getByRole('button', { name: /Hide acknowledged/ });
    expect(hideAcked).toBeTruthy();

    // Using it discards the selection rather than stranding it — and says so.
    fireEvent.click(hideAcked);
    await waitFor(() => expect(screen.queryByText('Ack 1 event')).toBeNull());
    expect(await screen.findByText(/selection cleared/i)).toBeTruthy();
  });
});

describe('selection counts are a true partition, not a double count', () => {
  // Ticking a group's checkbox also ticks every LOADED event under it, so the
  // expanded rows agree with the header box. Counting those events AGAIN beside
  // the group — and submitting them again — is the counts-that-lie disease:
  // "1 group · 3 events" for one group of three loaded events, and four ids
  // sent for one group's worth of work.
  const groupWithEvents = () => {
    vi.mocked(getAlerts).mockResolvedValue([
      mkGroup({ id: 'es-1', name: 'ET SCAN Noisy', count: 2000 }),
    ]);
    vi.mocked(getAlertGroupEvents).mockResolvedValue([
      mkEvent({ id: 'ev-1', ts: '2026-07-30T00:00:00Z' }),
      mkEvent({ id: 'ev-2', ts: '2026-07-30T00:01:00Z' }),
      mkEvent({ id: 'ev-3', ts: '2026-07-30T00:02:00Z' }),
    ]);
  };

  it('does not count a selected group\'s own events a second time', async () => {
    groupWithEvents();
    renderAlerts();
    await screen.findByText('ET SCAN Noisy');
    fireEvent.click(screen.getByText('ET SCAN Noisy')); // expand → events load
    await waitFor(() => expect(getAlertGroupEvents).toHaveBeenCalled());

    // Tick the GROUP box, which also ticks its three loaded events.
    fireEvent.click(screen.getAllByRole('checkbox')[1]);
    const strip = await screen.findByTestId('list-toolbar-selection');

    expect(within(strip).getByText(/1 group/)).toBeTruthy();
    // The three covered events are NOT announced as separate work…
    expect(within(strip).queryByText(/event/)).toBeNull();
    // …and the whole-window fire count is labelled as such, not as a selection.
    expect(within(strip).getByText(/2,000 alerts in window/)).toBeTruthy();
  });

  it('submits one id per selected group, not one per covered event', async () => {
    groupWithEvents();
    renderAlerts();
    await screen.findByText('ET SCAN Noisy');
    fireEvent.click(screen.getByText('ET SCAN Noisy'));
    await waitFor(() => expect(getAlertGroupEvents).toHaveBeenCalled());
    fireEvent.click(screen.getAllByRole('checkbox')[1]);

    const strip = await screen.findByTestId('list-toolbar-selection');
    fireEvent.click(within(strip).getByText('Bulk Investigate'));
    await waitFor(() => expect(vi.mocked(startAutoTriage)).toHaveBeenCalled());
    const arg = vi.mocked(startAutoTriage).mock.calls[0][0] as { alertIds?: string[] };
    expect(arg.alertIds).toEqual(['es-1']);
  });

  it('still counts an event the operator picked OUTSIDE any selected group', async () => {
    groupWithEvents();
    renderAlerts();
    await screen.findByText('ET SCAN Noisy');
    fireEvent.click(screen.getByText('ET SCAN Noisy'));
    await waitFor(() => expect(getAlertGroupEvents).toHaveBeenCalled());

    // Only one event, no group.
    const boxes = screen.getAllByRole('checkbox');
    fireEvent.click(boxes[boxes.length - 1]);
    const strip = await screen.findByTestId('list-toolbar-selection');
    expect(within(strip).getByText(/Ack 1 event/)).toBeTruthy();
    // No group is selected, so nothing claims one.
    expect(within(strip).queryByText(/group/)).toBeNull();
  });
});

describe('saved views on Alerts', () => {
  const VIEW = {
    id: 3,
    screen: 'alerts' as const,
    name: 'Critical, unacked',
    // Deliberately PARTIAL — saved before `hideAcked` existed as a key. The
    // range is here so applying the view provably reaches the server query.
    query: { view: 'critical', sevs: ['critical'], range: '7d' },
    created_at: null,
  };

  it('applying a partial view does not flip hide-acknowledged off', async () => {
    // `!!saved.hideAcked` forced the ON-by-default filter OFF for any view that
    // omitted the key. A saved view that silently unhides acknowledged alerts
    // is worse than no saved views at all.
    vi.mocked(listSavedViews).mockResolvedValue([VIEW]);
    vi.mocked(getAlerts).mockResolvedValue([mkGroup({ id: 'es-1', name: 'ET SCAN Noisy' })]);
    renderAlerts();
    await screen.findByText('ET SCAN Noisy');

    const before = vi.mocked(getAlerts).mock.calls.length;
    fireEvent.click(await screen.findByTitle(/Apply the saved view "Critical, unacked"/));
    await waitFor(() => expect(vi.mocked(getAlerts).mock.calls.length).toBeGreaterThan(before));
    const q = vi.mocked(getAlerts).mock.calls.slice(-1)[0][0] as { hideAcked?: boolean };
    expect(q.hideAcked).toBe(true);
  });

  it('un-lights the chip once a facet moves on from what it described', async () => {
    vi.mocked(listSavedViews).mockResolvedValue([VIEW]);
    vi.mocked(getAlerts).mockResolvedValue([mkGroup({ id: 'es-1', name: 'ET SCAN Noisy' })]);
    renderAlerts();
    await screen.findByText('ET SCAN Noisy');

    const chip = await screen.findByTitle(/Apply the saved view "Critical, unacked"/);
    fireEvent.click(chip);
    await waitFor(() => expect(chip).toHaveAttribute('aria-pressed', 'true'));

    // Edit a facet by hand: the chip no longer describes what is applied.
    fireEvent.click(screen.getByRole('button', { name: /Hide acknowledged/ }));
    await waitFor(() => expect(chip).toHaveAttribute('aria-pressed', 'false'));
  });
});

// ── shell chrome ────────────────────────────────────────────────────────────

function LocationProbe() {
  const l = useLocation();
  return <div data-testid="loc">{`${l.pathname}|${JSON.stringify(l.state)}`}</div>;
}

describe('F13 — command palette bulk-investigate carries intent in nav state', () => {
  it('navigates to /alerts with { autoTriage: true }', async () => {
    render(
      <MemoryRouter initialEntries={['/dashboard']}>
        <ShellProvider>
          <CommandPalette />
          <LocationProbe />
        </ShellProvider>
      </MemoryRouter>,
    );
    // Open the palette (Cmd+K) and run the action.
    fireEvent.keyDown(window, { key: 'k', metaKey: true });
    fireEvent.click(await screen.findByText('Bulk investigate all untriaged'));

    await waitFor(() => {
      const loc = screen.getByTestId('loc').textContent ?? '';
      expect(loc).toContain('/alerts');
      expect(loc).toContain('"autoTriage":true');
    });
  });
});

describe('F40 — Drawer Escape is gated on the command palette', () => {
  it('closes the drawer on Escape when the palette is closed', () => {
    const onClose = vi.fn();
    render(
      <MemoryRouter>
        <ShellProvider>
          <Drawer open onClose={onClose}>
            <div>body</div>
          </Drawer>
        </ShellProvider>
      </MemoryRouter>,
    );
    fireEvent.keyDown(window, { key: 'Escape' });
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('does NOT close the drawer on Escape while the palette is open', async () => {
    const onClose = vi.fn();
    render(
      <MemoryRouter>
        <ShellProvider>
          <CommandPalette />
          <Drawer open onClose={onClose}>
            <div>body</div>
          </Drawer>
        </ShellProvider>
      </MemoryRouter>,
    );
    // Open the palette, then press Escape (which should dismiss only the palette).
    fireEvent.keyDown(window, { key: 'k', metaKey: true });
    await screen.findByPlaceholderText('Search commands, screens, hosts…');
    fireEvent.keyDown(window, { key: 'Escape' });
    expect(onClose).not.toHaveBeenCalled();
  });
});

describe('F61 — sub-minute notification time reads "just now"', () => {
  it('renders "just now" instead of "now ago" for when === "now"', async () => {
    vi.mocked(getNotifications).mockResolvedValue([
      { id: 'n1', title: 'Investigating: ET SCAN', when: 'now', tone: 'accent' },
    ]);
    render(
      <MemoryRouter>
        <ShellProvider>
          <Topbar />
        </ShellProvider>
      </MemoryRouter>,
    );
    await waitFor(() => expect(getNotifications).toHaveBeenCalled());
    fireEvent.click(screen.getByLabelText('Notifications'));
    expect(await screen.findByText('just now')).toBeInTheDocument();
    expect(screen.queryByText('now ago')).toBeNull();
  });
});

describe('F62 — sidebar highlights Investigations on its detail routes', () => {
  const activeBg = (label: string): string =>
    (screen.getByText(label).closest('a') as HTMLElement).style.background;

  it('lights "Investigations" on an /entity pivot', () => {
    render(
      <MemoryRouter initialEntries={['/entity/192.0.2.5']}>
        <ShellProvider>
          <Sidebar />
        </ShellProvider>
      </MemoryRouter>,
    );
    expect(activeBg('Investigations')).not.toBe('transparent');
    expect(activeBg('Dashboard')).toBe('transparent');
  });

  it('lights "Investigations" on an /investigation/:id permalink', () => {
    render(
      <MemoryRouter initialEntries={['/investigation/INV-1']}>
        <ShellProvider>
          <Sidebar />
        </ShellProvider>
      </MemoryRouter>,
    );
    expect(activeBg('Investigations')).not.toBe('transparent');
  });
});
