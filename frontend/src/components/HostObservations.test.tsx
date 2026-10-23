// One host, one list, every source. Before the spine the profile layer, the
// catalog and the alert layer each wrote to their own table, so one host had
// three partial stories and no list. A repeated single signal is visible here
// before it forms a lead, so the repeat count and the live weight are on the
// row and not behind a click.
import { render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getObservations: vi.fn(),
}));

import { getObservations, type EntityObservation } from '../lib/api';
import {
  CHIP_IN_LEAD,
  CHIP_NO_LEAD,
  CHIP_SWEEPS,
  CHIP_TYPE,
  UNREAD_DOT,
} from '../lib/tooltips';
import { HostObservations } from './HostObservations';

const HOUR = 3_600_000;
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();

const ROWS: EntityObservation[] = [
  {
    id: 1,
    kind: 'prior_no_baseline',
    spec_id: 'identity-4662-dcsync-nonmachine',
    source: 'catalog',
    shadow: false,
    summary: 'a non-machine account read replication rights',
    weight_now: 0.94,
    lead_id: 12,
    born_at: iso(2 * HOUR),
    occurrences: 1,
    read: false,
  },
  {
    id: 2,
    kind: 'off_hours',
    spec_id: 'p',
    source: 'profile',
    shadow: false,
    summary: 'active around 03:00 UTC',
    weight_now: 0.21,
    lead_id: 12,
    born_at: iso(9 * HOUR),
    first_seen_at: iso(3 * 24 * HOUR),
    occurrences: 3,
    read: false,
  },
  {
    id: 3,
    kind: 'catalog_match',
    spec_id: 'local-svc-ticket',
    source: 'candidate',
    shadow: true,
    summary: '4769 for a service account from a workstation',
    weight_now: 0.68,
    lead_id: null,
    born_at: iso(30 * HOUR),
    occurrences: 1,
    read: false,
  },
];

const mount = () =>
  render(
    <MemoryRouter>
      <HostObservations entityKey="10.1.2.3" />
    </MemoryRouter>,
  );

beforeEach(() => {
  vi.mocked(getObservations)
    .mockReset()
    .mockResolvedValue({ entity: '10.1.2.3', days: 7, observations: ROWS });
});

describe('HostObservations', () => {
  it('lists every source with its kind, its weight and its lead', async () => {
    mount();
    await screen.findByText('Observations on this host · last 7 days · 3');

    const catalog = screen.getByTestId('observation-1');
    expect(within(catalog).getByText('catalog')).toBeTruthy();
    expect(within(catalog).getByText('no benign baseline')).toBeTruthy();
    expect(within(catalog).getByText('weight 0.94')).toBeTruthy();
    expect(within(catalog).getByText('in lead 12').getAttribute('href')).toBe('/leads/12');

    const profile = screen.getByTestId('observation-2');
    expect(within(profile).getByText('profile')).toBeTruthy();
    expect(within(profile).getByText('seen on 3 sweeps, first seen 3d ago')).toBeTruthy();
  });

  it('marks an unread shadow hit and says it is in no lead', async () => {
    mount();
    const shadow = await screen.findByTestId('observation-3');
    expect(within(shadow).getByText('shadow')).toBeTruthy();
    expect(within(shadow).getByText('shadow hit · unread')).toBeTruthy();
    expect(within(shadow).getByText('not yet in a lead')).toBeTruthy();
  });

  // Every chip on the row states what it means. The type chip, the repeat
  // count and the two lead words said nothing.
  it('states what every chip on a row means', async () => {
    mount();
    const catalog = await screen.findByTestId('observation-1');
    expect(within(catalog).getByText('no benign baseline').getAttribute('title')).toBe(
      CHIP_TYPE,
    );
    expect(within(catalog).getByText('in lead 12').getAttribute('title')).toBe(CHIP_IN_LEAD);
    const profile = screen.getByTestId('observation-2');
    expect(
      within(profile).getByText('seen on 3 sweeps, first seen 3d ago').getAttribute('title'),
    ).toBe(CHIP_SWEEPS);
    const shadow = screen.getByTestId('observation-3');
    expect(within(shadow).getByText('shadow hit · unread').getAttribute('title')).toBe(UNREAD_DOT);
    expect(within(shadow).getByText('not yet in a lead').getAttribute('title')).toBe(CHIP_NO_LEAD);
  });

  // `candidate` is a status and never a source. An analytic in candidate runs
  // nothing and writes nothing, so the word on a row was always wrong.
  it('never names candidate as a source', async () => {
    mount();
    const shadow = await screen.findByTestId('observation-3');
    expect(within(shadow).queryByText('candidate')).toBeNull();
  });

  it('prefers the label the API sends over the table', async () => {
    vi.mocked(getObservations).mockResolvedValue({
      entity: '10.1.2.3',
      days: 7,
      observations: [{ ...ROWS[0], id: 5, kind_label: 'directory replication' }],
    });
    mount();
    const row = await screen.findByTestId('observation-5');
    expect(within(row).getByText('directory replication')).toBeTruthy();
  });

  it('reads a live row that carries the legacy word as catalog', async () => {
    vi.mocked(getObservations).mockResolvedValue({
      entity: '10.1.2.3',
      days: 7,
      observations: [{ ...ROWS[2], id: 4, shadow: false }],
    });
    mount();
    const row = await screen.findByTestId('observation-4');
    expect(within(row).getByText('catalog')).toBeTruthy();
    expect(within(row).queryByText('candidate')).toBeNull();
  });

  it('states the absence and where to read what could not be scored', async () => {
    vi.mocked(getObservations).mockResolvedValue({
      entity: '10.1.2.3',
      days: 7,
      observations: [],
    });
    mount();
    await waitFor(() => expect(getObservations).toHaveBeenCalledWith('10.1.2.3', 7));
    // The call is on record before its answer renders.
    expect(await screen.findByText(/No observations on this host in the last 7 days/)).toBeTruthy();
  });

  // The row states the statistic it carries. The numbers lived only in the
  // summary sentence.
  it('states the statistic a row carries and none for a row without one', async () => {
    vi.mocked(getObservations).mockResolvedValue({
      entity: '10.1.2.3',
      days: 7,
      observations: [
        { ...ROWS[1], id: 6, statistic: 'documents', statistic_value: 6, baseline_value: 2 },
        { ...ROWS[0], id: 7 },
      ],
    });
    mount();
    const line = await screen.findByTestId('observation-statistic-6');
    expect(line.textContent).toBe(
      '6 documents in the recent window. The set it is new to holds 2 members.',
    );
    // Negative control: a row with no statistic states none.
    expect(screen.queryByTestId('observation-statistic-7')).toBeNull();
  });
});

// Dogfood 2026-10-19, R4-D18: an old observation kept "in the last 24 h".
describe('an old observation', () => {
  it('anchors its window to the sweep that wrote it', async () => {
    const born = iso(20 * 24 * HOUR);
    vi.mocked(getObservations).mockResolvedValue({
      entity: '192.0.2.10',
      days: 30,
      observations: [{ ...ROWS[0], id: 9, summary: 'new port for this host: 4444. 3 documents in the last 24 h', born_at: born }],
    });
    render(
      <MemoryRouter>
        <HostObservations entityKey="192.0.2.10" />
      </MemoryRouter>,
    );
    const row = await screen.findByTestId('observation-9');
    expect(row.textContent).toContain('3 documents in the 24 h before');
    expect(row.textContent).not.toContain('in the last 24 h');
  });
});

// Dogfood 2026-10-19, R4 STE: "A residual z of -52.0 against an expected 2759
// per hour" on the host page. The summary states the count and the expected
// count, so the z score stays off the row.
describe('a rate departure', () => {
  it('states no z score on the row', async () => {
    vi.mocked(getObservations).mockResolvedValue({
      entity: '192.0.2.10',
      days: 7,
      observations: [
        {
          ...ROWS[0],
          id: 21,
          kind: 'below_baseline',
          summary: 'The connection rate on Sunday 16:00 is 0 per hour. The baseline expects 2759 per hour',
          statistic: 'residual_z',
          statistic_value: -52,
          baseline_value: 2759,
        },
        {
          // NEGATIVE CONTROL: a statistic that is no z score keeps its line.
          ...ROWS[0],
          id: 22,
          statistic: 'plane_documents',
          statistic_value: 0,
          baseline_value: 412,
        },
      ],
    });
    render(
      <MemoryRouter>
        <HostObservations entityKey="192.0.2.10" />
      </MemoryRouter>,
    );
    const row = await screen.findByTestId('observation-21');
    expect(row.textContent).not.toMatch(/residual z/);
    expect(screen.queryByTestId('observation-statistic-21')).toBeNull();
    expect(screen.getByTestId('observation-statistic-22').textContent).toBe(
      '0 documents from the log source in the hours it stopped. The baseline expects 412 in those hours.',
    );
  });
});
