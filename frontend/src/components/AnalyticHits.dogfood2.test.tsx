// Analytic hits after the second hunting dogfood (2026-10-06). Each block
// names the review item it holds.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAnalyticHits: vi.fn(),
  getEvent: vi.fn(),
  getHuntCatalog: vi.fn(),
  markShadowHitRead: vi.fn(),
  markObservationBenign: vi.fn(),
  setAnalyticStatus: vi.fn(),
  startHuntConsole: vi.fn(),
}));

import {
  getAnalyticHits,
  getHuntCatalog,
  markObservationBenign,
  type AnalyticHit,
} from '../lib/api';
import { ShellProvider } from '../shell/ShellContext';
import { AnalyticHits } from './AnalyticHits';

const HOUR = 3_600_000;
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();

const LIVE: AnalyticHit = {
  id: 41,
  analytic_id: 'local-remote-exec-tooling',
  analytic_title: 'A workstation runs remote-execution tooling',
  analytic_status: 'live',
  recorded_in_shadow: false,
  tier: 'local',
  entity_kind: 'host',
  entity_key: '192.0.2.21',
  born_at: iso(6 * HOUR),
  first_seen_at: iso(6 * HOUR),
  occurrences: 5,
  summary: null,
  state: 'hit',
  missing: [],
  receipts: null,
  read: null,
  lead_id: 7,
  lead_status: 'open',
  document_count: 3,
};

const mount = (path = '/hunts') =>
  render(
    <MemoryRouter initialEntries={[path]}>
      <ShellProvider>
        <Routes>
          <Route path="/hunts" element={<AnalyticHits />} />
        </Routes>
      </ShellProvider>
    </MemoryRouter>,
  );

beforeEach(() => {
  vi.mocked(getAnalyticHits)
    .mockReset()
    .mockResolvedValue({ hits: [LIVE], counts: { all: 12, unread: 0, live: 12, shadow: 0 } });
  vi.mocked(getHuntCatalog).mockReset().mockResolvedValue({
    specs: [],
    sweeps_enabled: true,
    sweep_interval_minutes: 60,
    sweep_window_minutes: 61,
    last_sweep_at: new Date().toISOString(),
  } as never);
});

describe('W2: Show evidence lists the documents a hit counts', () => {
  const open = async () => {
    mount('/hunts?hits=live');
    return await screen.findByTestId('analytic-hit-41');
  };

  it('lists the stored ids of a live hit, each a document chip', async () => {
    vi.mocked(getAnalyticHits).mockResolvedValue({
      hits: [{ ...LIVE, document_ids: ['d1', 'd2', 'd3'] }],
      counts: { all: 1, unread: 0, live: 1, shadow: 0 },
    });
    const card = await open();
    fireEvent.click(within(card).getByRole('button', { name: 'Show evidence' }));
    const panel = within(card).getByTestId('analytic-hit-evidence');
    for (const id of ['d1', 'd2', 'd3']) expect(within(panel).getByText(id)).toBeTruthy();
    expect(within(card).queryByText('No evidence.')).toBeNull();
  });

  // Negative control: no id is stored, so no button opens an empty panel.
  it('drops the button and names the lead when no id is stored', async () => {
    vi.mocked(getAnalyticHits).mockResolvedValue({
      hits: [{ ...LIVE, document_ids: [] }],
      counts: { all: 1, unread: 0, live: 1, shadow: 0 },
    });
    const card = await open();
    expect(within(card).queryByRole('button', { name: 'Show evidence' })).toBeNull();
    expect(within(card).getByTestId('analytic-hit-no-ids').textContent).toBe(
      'Open lead 7 to read the documents.',
    );
  });
});

describe('C7: a live hit can be marked benign, and a hit with no lead says why', () => {
  const NO_LEAD = {
    ...LIVE,
    lead_id: null,
    lead_status: null,
    no_lead_reason: 'One type at weight 0.35. A lead needs 0.85 over 2 types, or 1.50 on one type.',
  };

  it('offers Mark benign beside Hunt this entity, with no reason chosen', async () => {
    vi.mocked(getAnalyticHits).mockResolvedValue({
      hits: [NO_LEAD],
      counts: { all: 1, unread: 0, live: 1, shadow: 0 },
    });
    vi.mocked(markObservationBenign).mockReset().mockResolvedValue({
      id: 41,
      dismissed_reason: 'known_change',
      dismissed_by: 'alice',
    });
    mount('/hunts?hits=live');
    const card = await screen.findByTestId('analytic-hit-41');
    expect(within(card).getByRole('button', { name: 'Hunt this entity' })).toBeTruthy();
    fireEvent.click(within(card).getByRole('button', { name: 'Mark benign' }));
    const form = within(card).getByTestId('benign-form');
    const select = within(form).getByLabelText('Reason') as HTMLSelectElement;
    expect(select.value).toBe('');
    const confirm = within(form).getByRole('button', { name: 'Confirm benign' }) as HTMLButtonElement;
    expect(confirm.disabled).toBe(true);
    fireEvent.change(select, { target: { value: 'known_change' } });
    fireEvent.change(within(form).getByPlaceholderText('Note, optional'), {
      target: { value: 'Windows update.' },
    });
    fireEvent.click(confirm);
    await waitFor(() =>
      expect(markObservationBenign).toHaveBeenCalledWith(41, 'known_change', 'Windows update.'),
    );
  });

  it('gives the cause in the no-lead hover', async () => {
    vi.mocked(getAnalyticHits).mockResolvedValue({
      hits: [NO_LEAD],
      counts: { all: 1, unread: 0, live: 1, shadow: 0 },
    });
    mount('/hunts?hits=live');
    const card = await screen.findByTestId('analytic-hit-41');
    expect(within(card).getByText('no lead').getAttribute('title')).toBe(
      'One type at weight 0.35. A lead needs 0.85 over 2 types, or 1.50 on one type.',
    );
  });

  // Negative controls: a hit marked benign says so and offers no second
  // mark, and a shadow hit offers the analytic decisions in place of it.
  it('states the mark on a benign hit and offers no second one', async () => {
    vi.mocked(getAnalyticHits).mockResolvedValue({
      hits: [
        {
          ...NO_LEAD,
          no_lead_reason: null,
          dismissed_reason: 'known_change',
          dismissed_by: 'alice',
          dismissed_at: iso(HOUR),
        },
        {
          ...NO_LEAD,
          id: 42,
          recorded_in_shadow: true,
          analytic_status: 'shadow',
          read: true,
        },
      ],
      counts: { all: 2, unread: 0, live: 1, shadow: 1 },
    });
    mount('/hunts?hits=all');
    const card = await screen.findByTestId('analytic-hit-41');
    expect(within(card).getByTestId('analytic-hit-benign').textContent).toBe(
      'Marked benign by alice: A known change. It counts toward no lead.',
    );
    expect(within(card).queryByRole('button', { name: 'Mark benign' })).toBeNull();
    const shadow = screen.getByTestId('analytic-hit-42');
    expect(within(shadow).queryByRole('button', { name: 'Mark benign' })).toBeNull();
  });
});

describe('W1: no unread hit folds the block to one line', () => {
  it('states the count and that none waits, and opens on Show hits', async () => {
    mount();
    const line = await screen.findByTestId('analytic-hits-quiet');
    expect(line.textContent).toBe('12 hits in 7 days. None waits on you.Show hits');
    expect(screen.queryByTestId('analytic-hit-41')).toBeNull();
    fireEvent.click(within(line).getByRole('button', { name: 'Show hits' }));
    expect(await screen.findByTestId('analytic-hit-41')).toBeTruthy();
    expect(screen.queryByTestId('analytic-hits-quiet')).toBeNull();
  });

  // Negative controls: an unread hit waits on the analyst, and a filter in
  // the address asks for the list.
  it('keeps the list when a hit is unread', async () => {
    vi.mocked(getAnalyticHits).mockResolvedValue({
      hits: [{ ...LIVE, recorded_in_shadow: true, analytic_status: 'shadow', read: false }],
      counts: { all: 12, unread: 1, live: 11, shadow: 1 },
    });
    mount();
    expect(await screen.findByTestId('analytic-hit-41')).toBeTruthy();
    expect(screen.queryByTestId('analytic-hits-quiet')).toBeNull();
  });

  it('keeps the list when the address names a filter', async () => {
    mount('/hunts?hits=live');
    expect(await screen.findByTestId('analytic-hit-41')).toBeTruthy();
    expect(screen.queryByTestId('analytic-hits-quiet')).toBeNull();
  });

  it('keeps the empty-state sentence when the window holds no hit', async () => {
    vi.mocked(getAnalyticHits).mockResolvedValue({
      hits: [],
      counts: { all: 0, unread: 0, live: 0, shadow: 0 },
    });
    mount();
    await waitFor(() => expect(screen.getByText(/No analytic hit in the last 7 days/)).toBeTruthy());
    expect(screen.queryByTestId('analytic-hits-quiet')).toBeNull();
  });
});

// R3-D11: a hit recorded live sat under Live with a "shadow" chip and Approve
// and Reject after soc-ai held its analytic, and no card said so.
describe('a live hit of a held analytic', () => {
  it('says where the hit was recorded and why the analytic reads shadow', async () => {
    const reason = 'It went over its daily hit limit.';
    vi.mocked(getAnalyticHits).mockResolvedValue({
      hits: [{ ...LIVE, analytic_status: 'shadow', analytic_held_by_system: reason }],
      counts: { all: 1, unread: 0, live: 1, shadow: 0 },
    });
    mount('/hunts?hits=live');
    const card = await screen.findByTestId('analytic-hit-41');
    expect(within(card).getByText('recorded live')).toBeTruthy();
    expect(within(card).getByTestId('analytic-hit-held').textContent).toBe(
      `soc-ai held this analytic in shadow after this hit. ${reason} The hit counts toward a lead. Approve or reject the analytic.`,
    );
  });

  it('carries no held line on a live analytic', async () => {
    mount('/hunts?hits=live');
    const card = await screen.findByTestId('analytic-hit-41');
    expect(within(card).queryByText('recorded live')).toBeNull();
    expect(within(card).queryByTestId('analytic-hit-held')).toBeNull();
  });
});
