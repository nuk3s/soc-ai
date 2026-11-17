// The hunts of a campaign on the Hunts list (2026-11-16): the chip of the
// campaign on the row, the starter word, and the type "Campaign".
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { DemoProvider } from '../lib/demo';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getHunts: vi.fn().mockResolvedValue([]),
  getHuntStats: vi.fn().mockResolvedValue([]),
  getHuntTemplates: vi.fn().mockResolvedValue([]),
  getHuntSchedules: vi.fn().mockResolvedValue({ schedules: [], masterSwitchEnabled: true }),
  listSavedViews: vi.fn().mockResolvedValue([]),
  getShadowHits: vi.fn().mockResolvedValue({ hits: [], unread: 0 }),
  getAnalytics: vi.fn().mockResolvedValue({ analytics: [], counts: {} }),
  getAnalytic: vi.fn(),
  getAnalyticHits: vi.fn().mockResolvedValue({
    hits: [],
    counts: { all: 0, unread: 0, live: 0, shadow: 0 },
  }),
  getNeedsYou: vi.fn().mockResolvedValue({ unread_shadow_hits: 0, leads_needing_decision: 0, total: 0 }),
  getLeads: vi.fn().mockResolvedValue([]),
  getHuntCatalog: vi.fn().mockResolvedValue({
    specs: [],
    sweeps_enabled: true,
    sweep_interval_minutes: 60,
    sweep_window_minutes: 61,
    last_sweep_at: null,
  }),
}));

import { getHunts, type HuntsQuery } from '../lib/api';
import type { HuntRow } from '../lib/types';
import { forbiddenWords } from '../test/analystWords';
import { LINK } from '../test/campaign';
import { ShellProvider } from '../shell/ShellContext';
import { Hunts } from './Hunts';

const ROW = {
  id: 'H-MANUAL',
  objective: 'typed by an analyst',
  kind: 'chat',
  status: 'complete',
  findingCount: 1,
  threatFindingCount: 1,
  outcome: 'threats',
  affectedHosts: 1,
  confidence: 0.8,
  startedBy: 'analyst',
  starter: 'analyst',
  leadId: null,
  when: '4m',
  ts: '2026-11-14T10:00:00+00:00',
  chatCount: 0,
} as HuntRow;

const CAMPAIGN_ROW = {
  ...ROW,
  id: 'H-CAMPAIGN',
  objective: 'checks the campaign after a change',
  kind: 'triggered',
  startedBy: 'campaign-hunt',
  starter: 'campaign',
  campaign: LINK,
} as HuntRow;

function renderHunts(at = '/hunts') {
  return render(
    <MemoryRouter initialEntries={[at]}>
      <DemoProvider demo={false}>
        <ShellProvider>
          <Routes>
            <Route path="/hunts" element={<Hunts />} />
          </Routes>
        </ShellProvider>
      </DemoProvider>
    </MemoryRouter>,
  );
}

// The leads strip and the hits block carry their own chips. A type chip is the one outside them.
const chip = (label: string) => {
  const strip = screen.queryByTestId('leads-strip');
  const hits = document.getElementById('analytic-hits');
  const el = screen
    .getAllByText(label)
    .find((c) => !strip?.contains(c) && !hits?.contains(c) && c.closest('button')?.hasAttribute('aria-pressed'))!;
  return el.closest('button')!;
};

beforeEach(() => {
  vi.mocked(getHunts).mockReset().mockResolvedValue([ROW, CAMPAIGN_ROW]);
});

describe('a hunt of a campaign on the Hunts list', () => {
  it('wears the campaign chip and the starter word "campaign"', async () => {
    renderHunts();
    await screen.findByText('checks the campaign after a change');
    const tags = screen.getByTestId('hunt-tags-H-CAMPAIGN');
    expect(within(tags).getByTestId('hunt-campaign-H-CAMPAIGN')).toHaveAttribute('href', '/campaigns/7');
    const row = tags.parentElement as HTMLElement;
    expect(row).toHaveTextContent('campaign');
    expect(row.textContent).not.toContain('campaign-hunt');
    // The words this change adds: the tags and the starter cell.
    const starter = within(row).getByTitle('Who or what started this hunt.');
    expect(starter.textContent).toBe('campaign');
    expect([...forbiddenWords(tags), ...forbiddenWords(starter)]).toEqual([]);
    // NEGATIVE CONTROL: a hunt of no campaign wears no chip.
    expect(within(screen.getByTestId('hunt-tags-H-MANUAL')).queryByTestId('hunt-campaign-H-MANUAL')).toBeNull();
  });

  it('holds a Campaign type that asks the server for the campaign hunts and shows only them', async () => {
    // An older server does not know the type and sends every hunt.
    vi.mocked(getHunts).mockImplementation(async (_q?: HuntsQuery) => [ROW, CAMPAIGN_ROW]);
    renderHunts();
    await screen.findByText('typed by an analyst');
    fireEvent.click(chip('Campaign'));
    await waitFor(() => expect(vi.mocked(getHunts).mock.lastCall?.[0]).toMatchObject({ kind: 'campaign' }));
    await waitFor(() => expect(screen.queryByText('typed by an analyst')).toBeNull());
    expect(screen.getByText('checks the campaign after a change')).toBeTruthy();
    expect(chip('Campaign').getAttribute('aria-pressed')).toBe('true');
  });

  it('keeps the type in the address', async () => {
    renderHunts('/hunts?kind=campaign');
    await screen.findByText('checks the campaign after a change');
    expect(screen.queryByText('typed by an analyst')).toBeNull();
    expect(chip('Campaign').getAttribute('aria-pressed')).toBe('true');
  });
});
