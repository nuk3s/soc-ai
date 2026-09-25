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
    expect(within(catalog).getByText('finding with no benign baseline')).toBeTruthy();
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
    expect(within(catalog).getByText('finding with no benign baseline').getAttribute('title')).toBe(
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
    expect(
      screen.getByText(/No observations on this host in the last 7 days/),
    ).toBeTruthy();
  });
});
