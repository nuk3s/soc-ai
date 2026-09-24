// The lead page under the 2026-09-22 design.
//
// Three things change here. The lead's own hunt may already be queued, so the
// page wears the strip's pill and the strip's words. An investigation of a
// lead reads the hunt's findings, so Promote waits on a hunt and says why.
// And a lead relates to other open leads, so the page lists them: one entity
// is one lead, and a coordinated attack is several.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async () => {
  const actual = await vi.importActual<typeof import('../lib/api')>('../lib/api');
  return {
    ...actual,
    getLead: vi.fn(),
    getHunts: vi.fn(),
    getNeedsYou: vi.fn(),
    huntLead: vi.fn(),
    dismissLead: vi.fn(),
    promoteLead: vi.fn(),
    reopenLead: vi.fn(),
    getEvent: vi.fn(),
  };
});

import {
  ApiError,
  getHunts,
  getLead,
  getNeedsYou,
  huntLead,
  promoteLead,
  type NeedsYou,
} from '../lib/api';
import { LEAD_ACTION } from '../components/LeadsStrip';
import {
  ACTION_HUNT_NOW,
  CHIP_LEFT_TO_YOU,
  LEGEND_AUTO_HUNT,
  PILL_HUNT_QUEUED,
  PROMOTE_NEEDS_HUNT,
  RELATED_REASON,
} from '../lib/tooltips';
import { ShellProvider } from '../shell/ShellContext';

const LEAD = {
  id: 12,
  status: 'open',
  formed_at: '2026-09-21T10:00:00Z',
  updated_at: null,
  entities: [['host', '10.1.2.3']],
  kinds: ['catalog_match', 'off_hours'],
  weight_at_formation: 0.92,
  weight_now: 0.9,
  scope_count: 1,
  hunt_id: null,
  shadow: false,
  single_signal: false,
  dismissed_reason: null,
  dismissed_note: null,
  dismissed_by: null,
  dismissed_at: null,
  investigation_id: null,
  dismiss_reasons: ['expected_for_role', 'other'],
  observations: [],
};

/** The counts the page reads the setting from. A server that sends no setting
 *  leaves the page to read this lead's own queued hunt. */
const NEEDS_YOU: NeedsYou = {
  unread_shadow_hits: 0,
  leads_needing_decision: 1,
  total: 1,
};

const HUNTED = {
  ...LEAD,
  status: 'hunting',
  hunt_id: 'H-LEAD-1',
  hunt_status: 'complete',
  hunt_outcome_label: 'No threat observed',
};

function mount() {
  return render(
    <MemoryRouter initialEntries={['/leads/12']}>
      <ShellProvider>
        <Routes>
          <Route path="/leads/:id" element={<LeadDetailScreen />} />
        </Routes>
      </ShellProvider>
    </MemoryRouter>,
  );
}

// Imported after the mock so the screen reads the mocked module.
import { LeadDetail as LeadDetailScreen } from './LeadDetail';

beforeEach(() => {
  vi.mocked(getLead).mockReset().mockResolvedValue(LEAD as never);
  vi.mocked(getHunts).mockReset().mockResolvedValue([]);
  vi.mocked(getNeedsYou).mockReset().mockResolvedValue(NEEDS_YOU);
  vi.mocked(huntLead).mockReset().mockResolvedValue({ hunt_id: 'H-NEW' });
  vi.mocked(promoteLead).mockReset().mockResolvedValue({ investigation_id: 'INV-9' });
});

describe('a queued hunt on the lead page', () => {
  it('wears the same pill the strip wears', async () => {
    vi.mocked(getLead).mockResolvedValue({ ...LEAD, hunt_queued: true } as never);
    mount();
    const pill = await screen.findByTestId('lead-status');
    expect(pill.textContent).toBe('New · hunt queued');
    expect(pill.getAttribute('title')).toBe(PILL_HUNT_QUEUED);
  });

  it('offers Dismiss and Promote, with Hunt now as the secondary act', async () => {
    vi.mocked(getLead).mockResolvedValue({ ...LEAD, hunt_queued: true } as never);
    mount();
    const now = await screen.findByRole('button', { name: LEAD_ACTION.huntNow });
    expect(now.getAttribute('title')).toBe(ACTION_HUNT_NOW);
    expect(screen.getByRole('button', { name: LEAD_ACTION.dismiss })).toBeTruthy();
    expect(screen.getByRole('button', { name: LEAD_ACTION.promote })).toBeTruthy();
    expect(screen.queryByRole('button', { name: LEAD_ACTION.hunt })).toBeNull();
  });

  it('starts the hunt from Hunt now', async () => {
    vi.mocked(getLead).mockResolvedValue({ ...LEAD, hunt_queued: true } as never);
    mount();
    fireEvent.click(await screen.findByRole('button', { name: LEAD_ACTION.huntNow }));
    await waitFor(() => expect(huntLead).toHaveBeenCalledWith(12));
  });

  it('adds the auto-hunt sentence to the legend', async () => {
    vi.mocked(getLead).mockResolvedValue({ ...LEAD, hunt_queued: true } as never);
    mount();
    const legend = await screen.findByTestId('lead-legend');
    expect(legend.textContent).toContain(LEGEND_AUTO_HUNT);
  });

  it('leaves the legend alone when no hunt is queued', async () => {
    mount();
    const legend = await screen.findByTestId('lead-legend');
    expect(legend.textContent).not.toContain(LEGEND_AUTO_HUNT);
  });

  // The legend states what the deployment does, not what this one lead is
  // doing. The page appended the sentence only on a queued lead, so every
  // hunted, promoted and reopened lead read the legend without it.
  it('appends the sentence while the setting is on, on a lead with no queued hunt', async () => {
    vi.mocked(getNeedsYou).mockResolvedValue({ ...NEEDS_YOU, lead_auto_hunt: true });
    vi.mocked(getLead).mockResolvedValue(HUNTED as never);
    mount();
    const legend = await screen.findByTestId('lead-legend');
    await waitFor(() => expect(legend.textContent).toContain(LEGEND_AUTO_HUNT));
  });

  it('drops the sentence while the setting is off', async () => {
    vi.mocked(getNeedsYou).mockResolvedValue({ ...NEEDS_YOU, lead_auto_hunt: false });
    vi.mocked(getLead).mockResolvedValue({ ...LEAD, hunt_queued: true } as never);
    mount();
    const legend = await screen.findByTestId('lead-legend');
    await waitFor(() => expect(legend.textContent).not.toContain(LEGEND_AUTO_HUNT));
  });

  // The same chip the strip carries. The loop leaves a shadow lead, a
  // reopened lead and a lead with no documents, and the lead page said
  // nothing about it.
  it('names a lead the loop leaves, beside the pill', async () => {
    vi.mocked(getNeedsYou).mockResolvedValue({ ...NEEDS_YOU, lead_auto_hunt: true });
    vi.mocked(getLead).mockResolvedValue({ ...LEAD, hunt_queued: false } as never);
    mount();
    const chip = await screen.findByTestId('lead-left-to-you');
    expect(chip.textContent).toBe('left to you');
    expect(chip.getAttribute('title')).toBe(CHIP_LEFT_TO_YOU);
  });

  it('names nothing on a lead whose hunt the loop has taken', async () => {
    vi.mocked(getNeedsYou).mockResolvedValue({ ...NEEDS_YOU, lead_auto_hunt: true });
    vi.mocked(getLead).mockResolvedValue({ ...LEAD, hunt_queued: true } as never);
    mount();
    await screen.findByTestId('lead-meta');
    expect(screen.queryByTestId('lead-left-to-you')).toBeNull();
  });
});

// An investigation of a lead reads the hunt's findings. Promoting a lead that
// has never been hunted starts an investigation of nothing, and the button
// that offered it said nothing about why the server refuses.
describe('Promote waits on a hunt', () => {
  it('refuses on a lead with no finished hunt and says why', async () => {
    mount();
    const promote = await screen.findByRole('button', { name: LEAD_ACTION.promote });
    expect((promote as HTMLButtonElement).disabled).toBe(true);
    expect(promote.getAttribute('title')).toBe(PROMOTE_NEEDS_HUNT);
  });

  it('opens once the hunt has finished', async () => {
    vi.mocked(getLead).mockResolvedValue(HUNTED as never);
    mount();
    const promote = await screen.findByRole('button', { name: LEAD_ACTION.promote });
    expect((promote as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(promote);
    await waitFor(() => expect(promoteLead).toHaveBeenCalledWith(12));
  });

  // The click landed and the page said nothing. The API already held the
  // promotion and the running investigation, and the page still read
  // "Hunted · Threat findings" with Promote live.
  it('says the promotion landed and links the investigation', async () => {
    vi.mocked(getLead).mockResolvedValue(HUNTED as never);
    mount();
    fireEvent.click(await screen.findByRole('button', { name: LEAD_ACTION.promote }));
    const note = await screen.findByTestId('lead-promoted');
    expect(note.textContent).toContain('Promoted. The investigation is running.');
    expect(within(note).getByRole('link', { name: LEAD_ACTION.openInvestigation })).toHaveAttribute(
      'href',
      '/investigation/INV-9',
    );
  });

  it('reads the lead again, so the page catches up with the record', async () => {
    vi.mocked(getLead).mockResolvedValue(HUNTED as never);
    mount();
    fireEvent.click(await screen.findByRole('button', { name: LEAD_ACTION.promote }));
    await waitFor(() => expect(vi.mocked(getLead).mock.calls.length).toBeGreaterThan(1));
  });

  it('shows the sentence the server sent on a refusal', async () => {
    vi.mocked(getLead).mockResolvedValue(HUNTED as never);
    vi.mocked(promoteLead).mockRejectedValue(
      new ApiError(
        "Hunt this lead first. The investigation reads the hunt's findings.",
        409,
        'lead_not_hunted',
      ),
    );
    mount();
    fireEvent.click(await screen.findByRole('button', { name: LEAD_ACTION.promote }));
    await waitFor(() =>
      expect(
        screen.getByText("Hunt this lead first. The investigation reads the hunt's findings."),
      ).toBeTruthy(),
    );
  });
});

// A title is read, not parsed. Two entity names ran together under one dot.
describe('the title of a lead on two entities', () => {
  it('joins the names with a space on each side of the dot', async () => {
    vi.mocked(getLead).mockResolvedValue({
      ...LEAD,
      entities: [
        ['host', '10.1.2.3'],
        ['host', '10.1.2.9'],
      ],
    } as never);
    mount();
    const heading = await screen.findByRole('heading', { level: 1 });
    expect(heading.textContent).toBe('Lead 12 · 10.1.2.3 · 10.1.2.9');
  });
});

describe('related leads', () => {
  const RELATED = {
    ...LEAD,
    related: [
      {
        lead_id: 31,
        entities: [['host', '10.1.2.9']],
        reason: 'the same analytic within 24 hours',
        formed_at: '2026-09-21T08:00:00Z',
        status: 'open',
      },
      {
        lead_id: 32,
        entities: [['host', '10.1.2.44']],
        reason: 'the same external address',
        formed_at: '2026-09-20T22:00:00Z',
        status: 'hunting',
      },
    ],
  };

  it('lists each one with its entity, its lead, its reason and its state', async () => {
    vi.mocked(getLead).mockResolvedValue(RELATED as never);
    mount();
    const panel = await screen.findByTestId('lead-related');
    const first = within(panel).getByTestId('related-lead-31');
    expect(within(first).getByText('10.1.2.9').getAttribute('href')).toBe('/hosts/10.1.2.9');
    expect(within(first).getByText('Lead 31').getAttribute('href')).toBe('/leads/31');
    const reason = within(first).getByText('the same analytic within 24 hours');
    expect(reason.getAttribute('title')).toBe(RELATED_REASON);
    expect(within(first).getByTestId('lead-status').textContent).toBe('New');
    const second = within(panel).getByTestId('related-lead-32');
    expect(within(second).getByTestId('lead-status').textContent).toBe('In progress');
  });

  // The same lead reads the same on every surface. The panel read the stored
  // status alone, so a lead whose hunt had finished 47 minutes before read
  // "In progress" here and "Hunted" everywhere else.
  it('reads a finished hunt as Hunted, with the outcome the hunt reported', async () => {
    vi.mocked(getLead).mockResolvedValue({
      ...LEAD,
      related: [
        {
          lead_id: 41,
          entities: [['host', '10.1.2.9']],
          reason: 'the same alert rule within 24 hours',
          formed_at: '2026-09-21T08:00:00Z',
          status: 'hunting',
          hunt_status: 'complete',
          hunt_outcome_label: 'Threat findings',
        },
      ],
    } as never);
    mount();
    const row = await screen.findByTestId('related-lead-41');
    expect(within(row).getByTestId('lead-status').textContent).toBe('Hunted \u00b7 Threat findings');
  });

  it('states the absence rather than hiding the panel', async () => {
    vi.mocked(getLead).mockResolvedValue({ ...LEAD, related: [] } as never);
    mount();
    const panel = await screen.findByTestId('lead-related');
    expect(within(panel).getByText('No related lead in the last 7 days.')).toBeTruthy();
  });

  // A deployment whose API does not compute the related leads has given no
  // answer. An empty panel there would read as "nothing relates", which is an
  // answer nobody made.
  it('shows no panel at all when the API sends none', async () => {
    mount();
    await screen.findByTestId('lead-meta');
    expect(screen.queryByTestId('lead-related')).toBeNull();
  });
});
