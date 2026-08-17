// Notifications joins the list family (dogfood B2, 2026-08-12).
//
// It sits in the same nav group as Alerts, Investigations, Hunts and Hosts, all
// four of which now open with the shared ListToolbar — a chip row over a facet
// row. Notifications had neither, so the round read as having forgotten it.
//
// These tests pin the two things that adoption has to be true for: the toolbar
// really is the SHARED one (same testids the siblings render, so a change to the
// component reaches here too), and every control on it filters real rows. A
// facet that filters nothing is decoration, and decoration is what the screen
// was already accused of.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// Hoisted: `vi.mock`'s factory runs before module-level consts are initialised.
const { ROWS, navigate } = vi.hoisted(() => ({
  navigate: vi.fn(),
  ROWS: [
  // system · danger — a standing dependency outage, no href
  {
    id: 'dep-down:es:20260812120000',
    tone: 'danger',
    title: 'Security Onion / Elasticsearch unreachable — investigations degraded',
    when: '3m',
    href: null,
  },
  // host · warn — a dossier disagreement
  {
    id: 'dossier-conflict:10.0.0.14:hostname:2',
    tone: 'warn',
    title: 'Dossier conflict on 10.0.0.14 — hostname: telemetry disagrees',
    when: '1h',
    href: '/entity/10.0.0.14',
  },
  // investigation · accent — in flight
  {
    id: 'inv:INV-1',
    tone: 'accent',
    title: 'Investigating: ET SCAN Suspicious inbound to mySQL port 3306',
    when: '2m',
    href: '/investigation/INV-1',
  },
  // investigation · danger — a true positive
  {
    id: 'inv-done:INV-2',
    tone: 'danger',
    title: 'Verdict true_positive: ET MALWARE Beacon Observed',
    when: '9m',
    href: '/investigation/INV-2',
  },
  // hunt · warn — finished with findings
  {
    id: 'hunt-done:HUNT-1',
    tone: 'warn',
    title: 'Hunt finished — 3 findings: beaconing from the finance subnet',
    when: '20m',
    href: '/hunts/HUNT-1',
  },
  ],
}));

vi.mock('react-router-dom', async (importOriginal) => ({
  ...(await importOriginal<typeof import('react-router-dom')>()),
  useNavigate: () => navigate,
}));

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getNotifications: vi.fn().mockResolvedValue(ROWS),
}));

import { Notifications } from './Notifications';

function renderNotifications() {
  return render(
    <MemoryRouter>
      <Notifications />
    </MemoryRouter>,
  );
}

/** The visible notification titles, in order. */
function visibleTitles(): string[] {
  return screen
    .getAllByTestId('notification-row')
    .map((r) => r.querySelector('[data-testid="notification-title"]')?.textContent ?? '');
}

describe('Notifications — the shared list toolbar', () => {
  beforeEach(() => {
    localStorage.clear();
    navigate.mockClear();
  });
  afterEach(() => localStorage.clear());

  it('renders the same chip row and facet row its siblings do', async () => {
    renderNotifications();
    await screen.findByText(/ET SCAN Suspicious inbound/);
    // Same testid Alerts/Investigations/Hunts/Hosts get from ListToolbar — this
    // is the shared component, not a lookalike.
    const chips = screen.getByTestId('list-toolbar-views');
    expect(within(chips).getByText('Views')).toBeTruthy();
    expect(within(chips).getByRole('button', { name: /^All/ })).toBeTruthy();
    // …and the screen's own facet, rendered as the toolbar's children.
    expect(screen.getByRole('button', { name: /Urgency/ })).toBeTruthy();
  });

  it('offers no search box — a notification title is a generated sentence', () => {
    // Deliberate divergence from Investigations/Alerts: there is nothing here to
    // search that the two facets and a 12-row cap do not already reach.
    renderNotifications();
    expect(screen.queryByRole('searchbox')).toBeNull();
  });

  it('counts each kind on its chip and filters the list to it', async () => {
    renderNotifications();
    await screen.findByText(/ET SCAN Suspicious inbound/);
    expect(visibleTitles()).toHaveLength(5);

    const investigations = screen.getByRole('button', { name: /Investigations/ });
    expect(investigations.textContent).toContain('2');
    fireEvent.click(investigations);

    await waitFor(() => expect(visibleTitles()).toHaveLength(2));
    expect(visibleTitles().join(' ')).toContain('ET SCAN Suspicious inbound');
    expect(visibleTitles().join(' ')).toContain('ET MALWARE Beacon Observed');
    expect(visibleTitles().join(' ')).not.toContain('Hunt finished');
  });

  it('filters to hunts, to hosts and back to everything', async () => {
    renderNotifications();
    await screen.findByText(/ET SCAN Suspicious inbound/);

    fireEvent.click(screen.getByRole('button', { name: /^Hunts/ }));
    await waitFor(() => expect(visibleTitles()).toHaveLength(1));
    expect(visibleTitles()[0]).toContain('Hunt finished');

    fireEvent.click(screen.getByRole('button', { name: /^Hosts/ }));
    await waitFor(() => expect(visibleTitles()).toHaveLength(1));
    expect(visibleTitles()[0]).toContain('Dossier conflict');

    fireEvent.click(screen.getByRole('button', { name: /^All/ }));
    await waitFor(() => expect(visibleTitles()).toHaveLength(5));
  });

  it('marks the active kind chip pressed and leaves the others unpressed', async () => {
    renderNotifications();
    await screen.findByText(/ET SCAN Suspicious inbound/);
    expect(screen.getByRole('button', { name: /^All/ })).toHaveAttribute('aria-pressed', 'true');

    fireEvent.click(screen.getByRole('button', { name: /^Hunts/ }));
    await waitFor(() =>
      expect(screen.getByRole('button', { name: /^Hunts/ })).toHaveAttribute('aria-pressed', 'true'),
    );
    expect(screen.getByRole('button', { name: /^All/ })).toHaveAttribute('aria-pressed', 'false');
  });

  it('filters by urgency, the axis the row dot already draws', async () => {
    renderNotifications();
    await screen.findByText(/ET SCAN Suspicious inbound/);

    fireEvent.click(screen.getByRole('button', { name: /Urgency/ }));
    fireEvent.click(screen.getByText('Urgent'));

    // Only the two danger-toned rows survive — one system, one investigation.
    await waitFor(() => expect(visibleTitles()).toHaveLength(2));
    expect(visibleTitles().join(' ')).toContain('Elasticsearch unreachable');
    expect(visibleTitles().join(' ')).toContain('ET MALWARE Beacon Observed');
  });

  it('combines the kind chip with the urgency facet', async () => {
    renderNotifications();
    await screen.findByText(/ET SCAN Suspicious inbound/);

    fireEvent.click(screen.getByRole('button', { name: /Investigations/ }));
    fireEvent.click(screen.getByRole('button', { name: /Urgency/ }));
    fireEvent.click(screen.getByText('Informational'));

    // Of the two investigations only the in-flight one is accent-toned.
    await waitFor(() => expect(visibleTitles()).toHaveLength(1));
    expect(visibleTitles()[0]).toContain('ET SCAN Suspicious inbound');
  });

  it('re-counts the kind chips under the urgency facet, so a count is a promise', async () => {
    // Press a chip reading "2" and you get two rows — which means the count has
    // to respect the facet beside it. The chip stays on the row at zero rather
    // than vanishing: "no urgent hunts" is the answer, not the absence of one.
    renderNotifications();
    await screen.findByText(/ET SCAN Suspicious inbound/);
    expect(screen.getByRole('button', { name: /Investigations/ }).textContent).toContain('2');

    fireEvent.click(screen.getByRole('button', { name: /Urgency/ }));
    fireEvent.click(screen.getByText('Urgent'));

    await waitFor(() =>
      expect(screen.getByRole('button', { name: /Investigations/ }).textContent).toContain('1'),
    );
    expect(screen.getByRole('button', { name: /^Hunts/ }).textContent).toContain('0');
    expect(screen.getByRole('button', { name: /^All/ }).textContent).toContain('2');

    fireEvent.click(screen.getByRole('button', { name: /Investigations/ }));
    await waitFor(() => expect(visibleTitles()).toHaveLength(1));
  });

  it('says so — and offers a way out — when the filters match nothing', async () => {
    renderNotifications();
    await screen.findByText(/ET SCAN Suspicious inbound/);

    fireEvent.click(screen.getByRole('button', { name: /^Hunts/ }));
    fireEvent.click(screen.getByRole('button', { name: /Urgency/ }));
    fireEvent.click(screen.getByText('Urgent'));

    await waitFor(() => expect(screen.queryAllByTestId('notification-row')).toHaveLength(0));
    // NOT the "No active notifications." empty state — five notifications are
    // active; the filters are what is hiding them.
    expect(screen.queryByText('No active notifications.')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: /show all notifications/i }));
    await waitFor(() => expect(screen.queryAllByTestId('notification-row')).toHaveLength(5));
  });

  it('groups the rows by kind while more than one kind is on screen', async () => {
    renderNotifications();
    await screen.findByText(/ET SCAN Suspicious inbound/);
    const headings = screen.getAllByTestId('notification-group').map((h) => h.textContent);
    expect(headings).toEqual(['System', 'Hosts', 'Investigations', 'Hunts']);

    // One kind on screen needs no headers — they would only repeat the chip.
    fireEvent.click(screen.getByRole('button', { name: /Investigations/ }));
    await waitFor(() => expect(screen.queryAllByTestId('notification-group')).toHaveLength(0));
  });
});

describe('Notifications — behaviour the toolbar must not have changed', () => {
  beforeEach(() => {
    localStorage.clear();
    navigate.mockClear();
  });
  afterEach(() => localStorage.clear());

  it('still deep-links a row to its investigation or hunt', async () => {
    renderNotifications();
    await screen.findByText(/ET SCAN Suspicious inbound/);
    fireEvent.click(screen.getByText(/Hunt finished — 3 findings/));
    expect(navigate).toHaveBeenCalledWith('/hunts/HUNT-1');
  });

  it('does not navigate for a row with no destination', async () => {
    renderNotifications();
    await screen.findByText(/Elasticsearch unreachable/);
    fireEvent.click(screen.getByText(/Elasticsearch unreachable/));
    expect(navigate).not.toHaveBeenCalled();
  });

  it('still dismisses one row without dismissing its neighbours', async () => {
    renderNotifications();
    await screen.findByText(/ET SCAN Suspicious inbound/);
    const row = screen
      .getAllByTestId('notification-row')
      .find((r) => r.textContent?.includes('Hunt finished'))!;
    fireEvent.click(within(row).getByRole('button', { name: /dismiss/i }));

    await waitFor(() => expect(screen.queryByText(/Hunt finished/)).toBeNull());
    expect(screen.getByText(/ET SCAN Suspicious inbound/)).toBeTruthy();
    // The dismissed id is what the Topbar bell reads to keep its badge honest.
    expect(JSON.parse(localStorage.getItem('soc-ai:dismissed-notifications')!)).toContain(
      'hunt-done:HUNT-1',
    );
  });

  it('Clear all clears rows the active filter is hiding, not just the visible ones', async () => {
    // "Clear all" has always meant every active notification, and the count
    // beside it is unfiltered too — narrowing it to the filtered subset would
    // leave the bell badge counting rows this screen claims it just cleared.
    renderNotifications();
    await screen.findByText(/ET SCAN Suspicious inbound/);
    fireEvent.click(screen.getByRole('button', { name: /^Hunts/ }));
    await waitFor(() => expect(visibleTitles()).toHaveLength(1));

    fireEvent.click(screen.getByRole('button', { name: /clear all/i }));
    await waitFor(() => expect(screen.getByText('No active notifications.')).toBeTruthy());
    const dismissed = JSON.parse(localStorage.getItem('soc-ai:dismissed-notifications')!);
    expect(dismissed).toHaveLength(ROWS.length);
  });
});

describe('Notifications — row timestamp', () => {
  beforeEach(() => localStorage.clear());
  afterEach(() => localStorage.clear());

  it('reads "just now" for a sub-minute row, never "now ago"', async () => {
    // The backend's _ago() returns the WORD "now" under 60s, so the row's
    // unconditional " ago" produced "now ago" on every fresh notification —
    // which is most of them, on a screen whose whole point is what just
    // happened. The Topbar bell shows the same rows and already said "just
    // now"; the two surfaces now share one formatter (F61).
    const api = await import('../lib/api');
    vi.mocked(api.getNotifications).mockResolvedValueOnce([
      { id: 'inv:INV-9', tone: 'accent', title: 'Investigating: ET SCAN fresh', when: 'now', href: null },
    ] as never);
    renderNotifications();
    expect(await screen.findByText('just now')).toBeTruthy();
    expect(screen.queryByText('now ago')).toBeNull();
  });
});
