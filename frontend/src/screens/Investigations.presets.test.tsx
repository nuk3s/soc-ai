// The preset views of the Investigations list (production review 2026-11-12,
// ui-core 7).
//
// The nav badge said 39 (9 verdicts that need more info plus 30 actions) and
// the list opened on 64 other rows: 24 hours, every verdict. No control showed
// the 39. The list now has the views Needs you, True positives and Failed. One
// press each, and `?view=` names the active one. The badge opens Needs you,
// and the view asks the server query the badge counts.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { NeedsYouCount } from '../lib/api';
import type { InvestigationList, InvestigationRow } from '../lib/types';

const row = (over: Partial<InvestigationRow>): InvestigationRow => ({
  id: 'INV-X',
  name: 'ET INFO NTLM Session Setup Request',
  kind: 'suricata',
  verdict: 'false_positive',
  conf: 0.8,
  host: '192.0.2.10',
  dst: '198.51.100.7',
  status: 'complete',
  when: '2h',
  ts: new Date(Date.now() - 2 * 3_600_000).toISOString(),
  alertId: 'ev-x',
  isPrimary: true,
  fallback: false,
  ...over,
});

const list = (rows: InvestigationRow[], over: Partial<InvestigationList> = {}): InvestigationList => ({
  rows,
  total: rows.length,
  running: 0,
  truePositives: 0,
  totalAll: rows.length,
  active: false,
  limit: 50,
  offset: 0,
  ...over,
});

const COUNT: NeedsYouCount = {
  leads_needing_decision: 0,
  unread_shadow_hits: 0,
  untriaged_groups: 0,
  needs_more_info: 1,
  pending_actions: 2,
  decisions: 3,
  review: 0,
  investigations_waiting: 2,
  total: 3,
  unknown: [],
  alert_window: '7d',
  verdict_window: '30d',
  alert_floor: false,
};

const listInvestigations = vi.hoisted(() => vi.fn());
const listSavedViews = vi.hoisted(() => vi.fn());
const getNeedsYouCount = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  listInvestigations,
  listSavedViews,
  getNeedsYouCount,
}));

import { activePreset, cmpImpact, filtersFromSearch, Investigations, presetFromSearch } from './Investigations';

function Probe() {
  const location = useLocation();
  return <div data-testid="loc">{location.pathname + location.search}</div>;
}

const mount = (url: string) =>
  render(
    <MemoryRouter initialEntries={[url]}>
      <Investigations />
      <Probe />
    </MemoryRouter>,
  );

const params = () => new URL(screen.getByTestId('loc').textContent ?? '', 'http://x').searchParams;
const lastQuery = () => listInvestigations.mock.calls[listInvestigations.mock.calls.length - 1][0];
const daysBack = (since: string) => (Date.now() - new Date(since).getTime()) / 86_400_000;
const chips = () => within(screen.getByTestId('list-toolbar-views'));
const chip = (name: RegExp) => chips().getByRole('button', { name });

beforeEach(() => {
  listInvestigations.mockReset();
  listInvestigations.mockResolvedValue(list([row({})]));
  listSavedViews.mockReset();
  listSavedViews.mockResolvedValue([]);
  getNeedsYouCount.mockReset();
  getNeedsYouCount.mockResolvedValue(COUNT);
});

describe('the preset views', () => {
  it('offers Needs you with the badge count, True positives, Failed and All', async () => {
    mount('/investigations');
    await screen.findByTestId('inv-name-INV-X');
    await waitFor(() => expect(chip(/^Needs you/).textContent).toBe('Needs you2'));
    expect(chip(/^True positives/)).toBeTruthy();
    expect(chip(/^Failed/)).toBeTruthy();
    expect(chip(/^All/).getAttribute('aria-pressed')).toBe('true');
  });

  it('opens Needs you in one press, with the query and the window of the badge', async () => {
    mount('/investigations');
    await screen.findByTestId('inv-name-INV-X');
    fireEvent.click(chip(/^Needs you/));
    await waitFor(() => expect(lastQuery().needsYou).toBe(true));
    expect(daysBack(lastQuery().since)).toBeCloseTo(30, 0);
    expect(lastQuery().verdict).toEqual([]);
    await waitFor(() => expect(params().get('view')).toBe('needs_you'));
    expect(params().get('range')).toBe('30d');
    expect(chip(/^Needs you/).getAttribute('aria-pressed')).toBe('true');
    expect(chip(/^All/).getAttribute('aria-pressed')).toBe('false');
  });

  it('opens Needs you from the badge link, and the list total is the badge number', async () => {
    listInvestigations.mockResolvedValue(
      list(
        [
          row({ id: 'INV-NMI', verdict: 'needs_more_info' }),
          row({ id: 'INV-TP', verdict: 'true_positive', alertId: 'ev-tp' }),
        ],
        { total: 2 },
      ),
    );
    mount('/investigations?view=needs_you&range=30d');
    await screen.findByTestId('inv-name-INV-NMI');
    expect(listInvestigations.mock.calls[0][0].needsYou).toBe(true);
    expect(daysBack(listInvestigations.mock.calls[0][0].since)).toBeCloseTo(30, 0);
    expect(screen.getByTestId('investigations-count').textContent).toContain(
      '2 investigations in the last 30 days',
    );
    await waitFor(() => expect(chip(/^Needs you/).textContent).toBe('Needs you2'));
    expect(chip(/^Needs you/).getAttribute('aria-pressed')).toBe('true');
  });

  it('links the Needs you view to the Needs you page with the total of the top bar', async () => {
    mount('/investigations?view=needs_you&range=30d');
    const note = await screen.findByTestId('needs-you-page-note');
    expect(note.textContent).toBe('This view lists the investigations that wait on you. The Needs you page lists all 3 decisions.');
    expect(within(note).getByRole('link', { name: 'Needs you page' }).getAttribute('href')).toBe('/needs-you');
  });

  it('states no Needs you note outside the Needs you view', async () => {
    mount('/investigations');
    await screen.findByTestId('inv-name-INV-X');
    expect(screen.queryByTestId('needs-you-page-note')).toBeNull();
  });

  it('opens True positives in one press and keeps the window on screen', async () => {
    mount('/investigations?range=7d');
    await screen.findByTestId('inv-name-INV-X');
    fireEvent.click(chip(/^True positives/));
    await waitFor(() => expect(lastQuery().verdict).toEqual(['true_positive']));
    expect(lastQuery().needsYou).toBeUndefined();
    expect(daysBack(lastQuery().since)).toBeCloseTo(7, 0);
    await waitFor(() => expect(params().get('view')).toBe('true_positives'));
    expect(params().get('verdict')).toBe('true_positive');
  });

  it('opens Failed in one press, with the query of the Dashboard tile', async () => {
    mount('/investigations');
    await screen.findByTestId('inv-name-INV-X');
    fireEvent.click(chip(/^Failed/));
    await waitFor(() => expect(lastQuery().verdict).toEqual(['pipeline_error']));
    expect(lastQuery().errorState).toBe('live');
    expect(daysBack(lastQuery().since)).toBeCloseTo(30, 0);
    await waitFor(() => expect(params().get('view')).toBe('failed'));
  });

  it('puts the true positives with the worst impact first', async () => {
    const hoursAgo = (h: number) => new Date(Date.now() - h * 3_600_000).toISOString();
    listInvestigations.mockResolvedValue(
      list([
        row({ id: 'INV-NEW', verdict: 'true_positive', alertId: 'a1', ts: hoursAgo(1) }),
        { ...row({ id: 'INV-ATTEMPT', verdict: 'true_positive', alertId: 'a2', ts: hoursAgo(2) }), impact: 'attempted' } as InvestigationRow,
        { ...row({ id: 'INV-OWNED', verdict: 'true_positive', alertId: 'a3', ts: hoursAgo(3) }), impact: 'succeeded' } as InvestigationRow,
      ]),
    );
    mount('/investigations?view=true_positives');
    await screen.findByTestId('inv-name-INV-OWNED');
    const order = screen.getAllByTestId(/^inv-name-/).map((el) => el.getAttribute('data-testid'));
    expect(order).toEqual(['inv-name-INV-OWNED', 'inv-name-INV-ATTEMPT', 'inv-name-INV-NEW']);
  });

  // NEGATIVE CONTROL. Outside the True positives view the list keeps its
  // time order, whatever impact a row states.
  it('keeps the time order outside the True positives view', async () => {
    const hoursAgo = (h: number) => new Date(Date.now() - h * 3_600_000).toISOString();
    listInvestigations.mockResolvedValue(
      list([
        row({ id: 'INV-NEW', verdict: 'true_positive', alertId: 'a1', ts: hoursAgo(1) }),
        { ...row({ id: 'INV-OWNED', verdict: 'true_positive', alertId: 'a3', ts: hoursAgo(3) }), impact: 'succeeded' } as InvestigationRow,
      ]),
    );
    mount('/investigations');
    await screen.findByTestId('inv-name-INV-OWNED');
    const order = screen.getAllByTestId(/^inv-name-/).map((el) => el.getAttribute('data-testid'));
    expect(order).toEqual(['inv-name-INV-NEW', 'inv-name-INV-OWNED']);
  });

  it('leaves the view with All, and keeps the window', async () => {
    mount('/investigations?view=needs_you&range=30d');
    await screen.findByTestId('inv-name-INV-X');
    fireEvent.click(chip(/^All/));
    await waitFor(() => expect(lastQuery().needsYou).toBeUndefined());
    await waitFor(() => expect(params().get('view')).toBeNull());
    expect(daysBack(lastQuery().since)).toBeCloseTo(30, 0);
  });
});

describe('the preset rules', () => {
  it('reads a view from the URL and fills the facets the URL leaves out', () => {
    expect(presetFromSearch('?view=needs_you')).toBe('needs_you');
    expect(filtersFromSearch('?view=failed')).toMatchObject({
      range: '30d',
      verdicts: ['pipeline_error'],
      errorState: 'live',
    });
    expect(filtersFromSearch('?view=true_positives&range=7d')).toMatchObject({
      range: '7d',
      verdicts: ['true_positive'],
    });
  });

  // NEGATIVE CONTROLS. An unknown view names nothing, and a chip lights only
  // when the filters on screen are the view's own.
  it('names no view for an unknown value or for changed filters', () => {
    expect(presetFromSearch('?view=everything')).toBeNull();
    expect(filtersFromSearch('?view=everything').verdicts).toEqual([]);
    const off = { errorState: null, needsYou: false, pendingOnly: false };
    expect(activePreset({ ...off, verdicts: ['true_positive'] })).toBe('true_positives');
    expect(activePreset({ ...off, verdicts: ['true_positive', 'false_positive'] })).toBeNull();
    expect(activePreset({ ...off, verdicts: ['pipeline_error'] })).toBeNull();
    expect(activePreset({ ...off, verdicts: ['true_positive'], pendingOnly: true })).toBeNull();
  });

  it('orders by impact and leaves a row with no impact last', () => {
    const r = (impact?: string) => ({ ...row({}), ...(impact ? { impact } : {}) }) as InvestigationRow;
    expect(cmpImpact(r('succeeded'), r('attempted'))).toBeLessThan(0);
    expect(cmpImpact(r(), r('none'))).toBeGreaterThan(0);
    expect(cmpImpact(r(), r())).toBe(0);
  });
});
