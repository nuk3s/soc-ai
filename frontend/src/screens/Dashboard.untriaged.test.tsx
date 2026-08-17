// The "Awaiting investigation" KPI and the Untriaged bar of the outcome
// breakdown count ALERT GROUPS with no standing investigation. Both used to
// link to /investigations?verdict=untriaged, which lists investigation ROWS —
// a group nobody has investigated has no row, and cannot get one while it
// stays untriaged, so the destination was empty BY CONSTRUCTION ("1x untriaged
// that when clicked reveals no investigations", prod 2026-08-07).
//
// Untriaged has to land on /alerts: same endpoint (GET /alerts), same unit
// (groups), and the place the operator can actually start the investigation.
// The two carried params are load-bearing — Alerts defaults to range=24h and
// hide_acked=true while the Dashboard queries the operator's range with
// hide_acked OFF, so without them a 7d dashboard, or a fully-acked untriaged
// group, still lands on an empty screen.
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { AlertGroup, Verdict } from '../lib/types';

const group = (id: string, verdict: Verdict): AlertGroup => ({
  id,
  name: `ET TEST ${id}`,
  kind: 'suricata',
  sev: 'high',
  count: 3,
  verdict,
  conf: verdict === 'untriaged' ? null : 0.8,
  latest: '2m ago',
  inherited: false,
  events: [],
});

const GROUPS = vi.hoisted(() => [
  { id: 'g-tp', verdict: 'true_positive' },
  { id: 'g-nmi', verdict: 'needs_more_info' },
  { id: 'g-inc', verdict: 'inconclusive' },
  { id: 'g-fp', verdict: 'false_positive' },
  { id: 'g-unt', verdict: 'untriaged' },
]);

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAlerts: vi.fn().mockResolvedValue([]),
  getDossierConflicts: vi.fn().mockResolvedValue({ pending: 0, rows: [] }),
  getQualityEvalStatus: vi.fn().mockResolvedValue({ running: false }),
  listInvestigations: vi.fn().mockResolvedValue({ rows: [], total: 0, running: 0, truePositives: 0, totalAll: 0, active: false, limit: 100, offset: 0 }),
  getAutoTriageStatus: vi.fn().mockResolvedValue({ active: false, hunted: 0, total: 0 }),
  getDataSources: vi.fn().mockResolvedValue({ sources: [] }),
  getQualityTrend: vi.fn().mockResolvedValue({ points: [] }),
  getHealth: vi.fn().mockResolvedValue(null),
  getDetectionTuningSummary: vi.fn().mockResolvedValue(null),
}));

import { Dashboard } from './Dashboard';
import { getAlerts } from '../lib/api';

function Here() {
  const loc = useLocation();
  return <div data-testid="here">{loc.pathname + loc.search}</div>;
}

const mount = async () => {
  vi.mocked(getAlerts).mockResolvedValue(
    GROUPS.map((g) => group(g.id, g.verdict as Verdict)),
  );
  render(
    <MemoryRouter initialEntries={['/']}>
      <Dashboard />
      <Here />
    </MemoryRouter>,
  );
  // wait for the outcome breakdown (needs resolved alert data to render)
  await screen.findByText('Investigation outcomes');
};

/** The breakdown tile for one verdict — located by its pill label, not its
 * title, so the tooltip copy can change without breaking the test.
 *
 * findByText, not getByText: the Dashboard settles in more than one step (the
 * alert fetch, then the /about probe that gates the chat panel), so a tile can
 * still be a render away when the section heading is already up. A synchronous
 * query turns that into a machine-speed race — it passed on every local run and
 * failed twice on a slower CI runner (2026-08-07). */
const tile = async (label: string) =>
  (await screen.findByText(label)).closest('button')!;

const here = () => screen.getByTestId('here').textContent;

describe('Dashboard outcome breakdown — where each verdict lands', () => {
  it.each([
    ['True positive', 'true_positive'],
    ['Needs info', 'needs_more_info'],
    ['Inconclusive', 'inconclusive'],
    ['False positive', 'false_positive'],
  ])('sends %s to the Investigations list', async (label, value) => {
    await mount();
    fireEvent.click(await tile(label));
    expect(here()).toBe(`/investigations?verdict=${value}`);
  });

  it('sends Untriaged to the Alerts list, carrying range and hide_acked=false', async () => {
    await mount();
    fireEvent.click(await tile('Untriaged'));
    const dest = new URL(here()!, 'http://x');
    expect(dest.pathname).toBe('/alerts');
    expect(dest.searchParams.get('verdict')).toBe('untriaged');
    // Dashboard range (24h default here) must survive: an Alerts view on a
    // narrower window cannot contain the group the tile counted.
    expect(dest.searchParams.get('range')).toBe('24h');
    // Alerts hides acked groups by default; the Dashboard count does not.
    expect(dest.searchParams.get('hide_acked')).toBe('false');
  });

  it('carries a non-default Dashboard range to Alerts', async () => {
    await mount();
    fireEvent.click(screen.getByText('7d'));
    fireEvent.click(await tile('Untriaged'));
    expect(new URL(here()!, 'http://x').searchParams.get('range')).toBe('7d');
  });

  it('carries a custom Dashboard window with both endpoints', async () => {
    await mount();
    fireEvent.click(screen.getByLabelText('Custom date range'));
    // The picker's From/To labels aren't wired to their inputs, so select by type.
    const [from, to] = Array.from(
      document.querySelectorAll<HTMLInputElement>('input[type="datetime-local"]'),
    );
    fireEvent.change(from, { target: { value: '2026-08-01T00:00' } });
    fireEvent.change(to, { target: { value: '2026-08-02T00:00' } });
    fireEvent.click(screen.getByText('Apply'));
    fireEvent.click(await tile('Untriaged'));
    const q = new URL(here()!, 'http://x').searchParams;
    // A bare range=custom would be dropped by Alerts and silently fall back to
    // its 24h default — the exact narrowing this link exists to avoid.
    expect(q.get('range')).toBe('custom');
    expect(q.get('from')).toBe('2026-08-01T00:00');
    expect(q.get('to')).toBe('2026-08-02T00:00');
  });

  it('names the real destination in the Untriaged tooltip', async () => {
    await mount();
    const title = (await tile('Untriaged')).getAttribute('title')!;
    // It used to read "Show Untriaged investigations" — a list that cannot exist.
    expect(title).not.toMatch(/untriaged investigations/i);
    expect(title).toMatch(/alerts/i);
    // The settled verdicts still promise investigations, because they have them.
    expect((await tile('True positive')).getAttribute('title')).toMatch(
      /investigations/i,
    );
  });
});

// "auto-investigate idle" blamed the sweep for a group sitting untriaged. The
// Dashboard cannot know that: the sweep may be running fine and simply skipping
// the group (severity floor, already acked, schedule off). Naming a culprit it
// can't verify sent the operator to the scheduler config instead of to the row.
describe('Dashboard "Awaiting investigation" subline', () => {
  it('does not blame an idle sweep when a group is untriaged', async () => {
    await mount();
    await screen.findByText('Awaiting investigation');
    // queryAll, not query: the matcher would otherwise also hit every ancestor
    // of the subline. (The auto-triage panel's "Idle — no auto-investigate
    // batch has run yet" is a different, true claim and stays.)
    expect(screen.queryAllByText(/auto-investigate idle/i)).toHaveLength(0);
  });

  it('points at the screen where the group can actually be triaged', async () => {
    await mount();
    fireEvent.click(await screen.findByText(/triage from Alerts/i));
    expect(here()).toContain('/alerts?verdict=untriaged');
  });
});
