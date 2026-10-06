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
import { CHIP_HELD_BY_SYSTEM } from '../lib/tooltips';
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

// F2, RH14, H5. The Operate panel said "live" on analytics no sweep had run,
// showed "live" and "shadow" on one profile row, and printed "blind 489" on a
// 336-host estate with no word on the cap.
describe('HuntCatalogPanel run state', () => {
  const PROFILE: HuntCatalogSpec = {
    ...SPEC,
    id: 'prior-hypervisor-novel-served-port',
    title: 'A hypervisor serves a new port',
    evaluator: 'profile',
    status: 'live',
    coverage: {
      last_run_at: iso(HOUR / 6),
      measured: 11,
      learning: 0,
      blind: 489,
      not_applicable: 0,
      fired: 0,
      shadow: true,
      recent_cap: 500,
      capped: true,
    },
  };

  it('says live, not running on a match analytic when the sweeps are off', async () => {
    vi.mocked(getHuntCatalog).mockResolvedValue({
      ...CATALOG,
      specs: [SPEC, PROFILE],
      sweeps_enabled: false,
      last_sweep_at: null,
      prior_sweeps_enabled: true,
      last_prior_run_at: iso(HOUR / 6),
    });
    mount();
    const match = (await screen.findByText(SPEC.title)).closest('li')!;
    expect(within(match).getByText('live, not running')).toBeTruthy();
    const profile = screen.getByText(PROFILE.title).closest('li')!;
    expect(within(profile).getByText('live')).toBeTruthy();
  });

  it('lists a model analytic with the profile sweep, which runs it', async () => {
    const model: HuntCatalogSpec = {
      ...PROFILE,
      id: 'model-cross-plane-silence',
      title: 'One telemetry plane of a machine goes silent',
      evaluator: 'model',
      status: 'shadow',
    };
    vi.mocked(getHuntCatalog).mockResolvedValue({
      ...CATALOG,
      specs: [SPEC, model],
      sweeps_enabled: false,
      last_sweep_at: null,
      prior_sweeps_enabled: true,
      last_prior_run_at: iso(HOUR / 6),
    });
    mount();
    // A learned detector reads no stored profile, so it has its own group.
    const group = await screen.findByTestId('detector-group');
    expect(group.textContent).toContain('Learned detectors · 1');
    expect(screen.queryByText(/Evaluated against behavioural profiles/)).toBeNull();
    // The legend still defines the words on the row.
    expect(screen.getByTestId('profile-legend')).toBeTruthy();
    const row = screen.getByText(model.title).closest('li')!;
    // The profile sweep runs, so the status reads without "not running".
    expect(within(row).getByTestId('status-dot').textContent).toBe('shadow');
  });

  it('lists the profile analytics and the learned detectors under two labels', async () => {
    const model: HuntCatalogSpec = {
      ...PROFILE,
      id: 'model-logon-chain',
      title: 'A logon chain the estate model has not seen',
      evaluator: 'model',
      status: 'shadow',
    };
    vi.mocked(getHuntCatalog).mockResolvedValue({
      ...CATALOG,
      specs: [SPEC, PROFILE, model],
      prior_sweeps_enabled: true,
      last_prior_run_at: iso(HOUR / 6),
    });
    mount();
    expect(await screen.findByText(/Evaluated against behavioural profiles · 1/)).toBeTruthy();
    const group = screen.getByTestId('detector-group');
    expect(group.textContent).toContain('Learned detectors · 1');
    expect(group.textContent).toContain('counts are detector-host evaluations');
    // One legend for both groups.
    expect(screen.getAllByTestId('profile-legend')).toHaveLength(1);
    expect(screen.getByText(model.title)).toBeTruthy();
    expect(screen.getByText(PROFILE.title)).toBeTruthy();
  });

  it('reads the shadow marker from the status, not the trail', async () => {
    vi.mocked(getHuntCatalog).mockResolvedValue({
      ...CATALOG,
      specs: [PROFILE],
      last_prior_run_at: iso(HOUR / 6),
    });
    mount();
    const row = (await screen.findByText(PROFILE.title)).closest('li')!;
    expect(within(row).getByText('live')).toBeTruthy();
    expect(within(row).queryByText('shadow')).toBeNull();
  });

  // N4 of the 2026-10-05 verification. Operate showed a held analytic with
  // the same "shadow" chip as an analyst's shadow. The Analytics tab said
  // "held by soc-ai" for the same three analytics.
  it('marks an analytic soc-ai holds in shadow apart from an analyst shadow', async () => {
    const REASON = 'The analytic wrote 18 hits in 24 hours. Its fire budget is 3 a day.';
    const held = {
      ...PROFILE,
      id: 'profile-held',
      title: 'A held profile analytic',
      status: 'shadow',
      held_by_system: REASON,
    };
    const chosen = {
      ...PROFILE,
      id: 'profile-chosen',
      title: 'A profile analytic an analyst put in shadow',
      status: 'shadow',
      held_by_system: null,
    };
    const heldMatch = {
      ...SPEC,
      id: 'match-held',
      title: 'A held match analytic',
      status: 'shadow',
      held_by_system: REASON,
    };
    vi.mocked(getHuntCatalog).mockResolvedValue({
      ...CATALOG,
      specs: [heldMatch, held, chosen],
      last_prior_run_at: iso(HOUR / 6),
    });
    mount();
    const heldRow = (await screen.findByText(held.title)).closest('li')!;
    const chip = within(heldRow).getByTestId('catalog-held-profile-held');
    expect(chip.textContent).toBe('held by soc-ai');
    expect(chip.title).toBe(`${CHIP_HELD_BY_SYSTEM} ${REASON}`);
    // The status stays. The amber "shadow" chip of an analyst's shadow goes.
    expect(within(heldRow).getAllByText('shadow')).toHaveLength(1);

    const matchRow = screen.getByText(heldMatch.title).closest('li')!;
    expect(within(matchRow).getByTestId('catalog-held-match-held')).toBeTruthy();

    // Negative control: an analyst's shadow keeps its chip and gets no hold.
    const chosenRow = screen.getByText(chosen.title).closest('li')!;
    expect(within(chosenRow).queryByText('held by soc-ai')).toBeNull();
    expect(within(chosenRow).getAllByText('shadow')).toHaveLength(2);
  });

  it('shows no hold on an analytic that is no longer in shadow', async () => {
    vi.mocked(getHuntCatalog).mockResolvedValue({
      ...CATALOG,
      specs: [{ ...PROFILE, status: 'live', held_by_system: 'an old reason' }],
      last_prior_run_at: iso(HOUR / 6),
    });
    mount();
    const row = (await screen.findByText(PROFILE.title)).closest('li')!;
    expect(within(row).queryByText('held by soc-ai')).toBeNull();
  });

  it('says a coverage at the cap is capped', async () => {
    vi.mocked(getHuntCatalog).mockResolvedValue({
      ...CATALOG,
      specs: [PROFILE],
      last_prior_run_at: iso(HOUR / 6),
    });
    mount();
    const row = (await screen.findByText(PROFILE.title)).closest('li')!;
    expect(row.textContent).toContain('blind 489 · capped at 500');
  });

  it('says when the profile sweep is off', async () => {
    vi.mocked(getHuntCatalog).mockResolvedValue({
      ...CATALOG,
      specs: [PROFILE],
      prior_sweeps_enabled: false,
      last_prior_run_at: iso(HOUR / 6),
    });
    mount();
    expect(
      await screen.findByText('The profile sweep is off. These analytics do not run.'),
    ).toBeTruthy();
    const row = screen.getByText(PROFILE.title).closest('li')!;
    expect(within(row).getByText('live, not running')).toBeTruthy();
  });
});
