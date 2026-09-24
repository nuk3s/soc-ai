// 1.5.1 renamed this panel and gave every row its tier and its status. One
// analytic is one detection logic, and the word "spec" left every screen with
// it. Without the status a retired analytic and a quiet live one render the
// same row of zeros.
//
// The panel keeps the operator's question, "does this analytic run and what
// can it see". The Analytics tab on Hunts answers the analyst's question,
// "what did it find". The foot link is what joins the two.
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getHuntCatalog: vi.fn(),
}));

import { getHuntCatalog, type HuntCatalog, type HuntCatalogSpec } from '../lib/api';
import { HuntCatalogPanel } from './HuntCatalogPanel';

const HOUR = 3_600_000;
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();

const SPEC: HuntCatalogSpec = {
  id: 'lateral-psexec-service-install',
  title: 'Remote service installed over SMB',
  level: 'medium',
  scope_kind: 'host',
  evaluator: 'match',
  coverage: null,
  attack: ['T1569.002'],
  last_swept_at: iso(HOUR),
  last_fired_at: iso(2 * HOUR),
  blind: false,
  last_error: null,
  sweeps_24h: 24,
  fired_24h: 3,
  fresh_24h: 1,
  already_handled_24h: 2,
  shadow_24h: 0,
  undecided_docs: 0,
  unattributed_docs: 0,
  truncated_docs: 0,
};

const CATALOG: HuntCatalog = {
  specs: [SPEC],
  sweeps_enabled: true,
  sweep_interval_minutes: 60,
  sweep_window_minutes: 1440,
  last_sweep_at: iso(HOUR),
};

const mount = () =>
  render(
    <MemoryRouter>
      <HuntCatalogPanel />
    </MemoryRouter>,
  );

beforeEach(() => {
  vi.mocked(getHuntCatalog).mockReset().mockResolvedValue(CATALOG);
});

describe('HuntCatalogPanel', () => {
  it('is titled Analytics', async () => {
    mount();
    expect(await screen.findByText('Analytics')).toBeTruthy();
  });

  it('puts the tier and the status on every row', async () => {
    mount();
    const row = (await screen.findByText(SPEC.title)).closest('li')!;
    // The fixture carries neither field. A shipped analytic with no state row
    // is shipped and live, which is the backend's default for the catalog.
    expect(within(row).getByText('shipped')).toBeTruthy();
    expect(within(row).getByText('live')).toBeTruthy();
  });

  it('reads the status a local analytic in shadow carries', async () => {
    vi.mocked(getHuntCatalog).mockResolvedValue({
      ...CATALOG,
      specs: [{ ...SPEC, id: 'local-x', tier: 'local', status: 'shadow' }],
    });
    mount();
    const row = (await screen.findByText(SPEC.title)).closest('li')!;
    expect(within(row).getByText('local')).toBeTruthy();
    expect(within(row).getByText('shadow')).toBeTruthy();
    expect(within(row).queryByText('live')).toBeNull();
  });

  // The sweep writes an observation, and the observation is an analytic hit.
  // "Open catalog hunts" named a hunt row the sweep no longer writes.
  it('links to the Analytics tab beside the analytic hits link', async () => {
    mount();
    await screen.findByText(SPEC.title);
    expect(screen.getByText('Open in Hunts').closest('a')!.getAttribute('href')).toBe(
      '/hunts?tab=analytics',
    );
    expect(screen.getByText('Open analytic hits').closest('a')!.getAttribute('href')).toBe(
      '/hunts',
    );
    expect(screen.queryByText('Open catalog hunts')).toBeNull();
  });
});
