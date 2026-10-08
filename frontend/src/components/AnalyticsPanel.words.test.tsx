// Dogfood 2026-10-06 C6: "held" was nowhere on the screen, a candidate read
// "candidate", the filters said tier, evaluator and scope, and "shadow, not
// running" after "Run in shadow" made an analytic that waits for the hourly
// sweep look broken.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAnalytics: vi.fn(),
  getAnalytic: vi.fn(),
  getHuntCatalog: vi.fn(),
  getLeadQuality: vi.fn().mockResolvedValue({ weeks: [], by_types: [], rule: '', note: '' }),
}));

import { getAnalytics, getHuntCatalog, type AnalyticDetail, type AnalyticRow } from '../lib/api';
import {
  appliesWord,
  intervalWords,
  methodWord,
  sourceWord,
  statusLabel,
  windowWords,
} from '../lib/analyticRuns';
import { ShellProvider } from '../shell/ShellContext';
import { drawerRunState } from './AnalyticDrawer';
import { AnalyticsPanel } from './AnalyticsPanel';

const base = {
  level: 'high',
  evaluator: 'match',
  scope_kind: 'host',
  tier: 'local',
  no_benign_baseline: false,
  observations_7d: 0,
  leads_7d: 0,
  hunted_7d: 0,
  dismissed_7d: 0,
  shadow_hits_7d: 0,
  unread_shadow_hits: 0,
};

const LIVE: AnalyticRow = { ...base, id: 'shipped-live', title: 'Live', tier: 'shipped', status: 'live' };
const SHADOW: AnalyticRow = { ...base, id: 'local-shadow', title: 'Shadow', status: 'shadow' };
const PAUSED: AnalyticRow = {
  ...base,
  id: 'local-paused',
  title: 'Paused',
  status: 'shadow',
  held_by_system: 'It went over its daily hit limit.',
};
const DRAFT: AnalyticRow = { ...base, id: 'local-draft', title: 'Draft', status: 'candidate' };

const mount = (at = '/hunts?tab=analytics') =>
  render(
    <MemoryRouter initialEntries={[at]}>
      <ShellProvider>
        <AnalyticsPanel />
      </ShellProvider>
    </MemoryRouter>,
  );

const rowIds = () =>
  screen
    .getAllByTestId(/^analytic-(?!blind-|held-|specific-|no-hunt)/)
    .map((el) => el.getAttribute('data-testid')?.replace('analytic-', ''));

describe('AnalyticsPanel words', () => {
  beforeEach(() => {
    vi.mocked(getHuntCatalog).mockReset().mockRejectedValue(new Error('no catalog'));
    vi.mocked(getAnalytics).mockReset().mockResolvedValue({
      analytics: [LIVE, SHADOW, PAUSED, DRAFT],
      counts: { live: 1, shadow: 2, candidate: 1 },
    });
  });

  it('shows the paused analytics in their own view', async () => {
    mount('/hunts?tab=analytics&status=held');
    await screen.findByTestId(`analytic-${PAUSED.id}`);
    // Negative control: an analyst's own shadow is no paused analytic.
    expect(rowIds()).toEqual([PAUSED.id]);
    expect(screen.getByRole('button', { name: /Paused by soc-ai/ })).toBeTruthy();
    expect(screen.getByRole('button', { name: /^Draft/ })).toBeTruthy();
    expect(screen.getByTestId(`analytic-held-${PAUSED.id}`).textContent).toBe('Paused by soc-ai');
  });

  it('names the source, the method and what an analytic applies to', async () => {
    vi.mocked(getAnalytics).mockResolvedValue({
      analytics: [LIVE, { ...SHADOW, evaluator: 'profile', scope_kind: 'ip' }],
      counts: { live: 1, shadow: 1 },
    });
    mount();
    await screen.findByTestId(`analytic-${LIVE.id}`);
    const options = (name: string) =>
      [...screen.getByRole('combobox', { name }).querySelectorAll('option')].map(
        (o) => o.textContent,
      );
    expect(options('Source')).toEqual([
      'Source: any',
      'Source: written here',
      'Source: shipped with soc-ai',
    ]);
    expect(options('Method')).toEqual(['Method: any', 'Method: query', 'Method: baseline']);
    expect(options('Applies to')).toEqual([
      'Applies to: any',
      'Applies to: host',
      'Applies to: address',
    ]);
  });
});

describe('analytic words', () => {
  it('says an analytic waits for the next sweep', () => {
    expect(statusLabel('shadow', 'waiting', 'every hour')).toBe(
      'shadow, waits for the next sweep, every hour',
    );
    // Negative control: a sweep that is off still reads "not running".
    expect(statusLabel('shadow', false)).toBe('shadow, not running');
    expect(statusLabel('live', true)).toBe('live');
    expect(statusLabel('candidate', true)).toBe('draft');
  });

  it('reads the waiting state off the drawer analytic', () => {
    const d = (over: Partial<AnalyticDetail>) => over as AnalyticDetail;
    expect(drawerRunState(d({ last_run_at: null, runner_enabled: true }))).toBe('waiting');
    expect(drawerRunState(d({ last_run_at: null, runner_enabled: false }))).toBe(false);
    expect(drawerRunState(d({ last_run_at: '2026-10-06T00:00:00Z', runner_enabled: true }))).toBe(
      true,
    );
    expect(drawerRunState(d({}))).toBeUndefined();
  });

  it('states windows, intervals and fields in words', () => {
    expect(windowWords(1440)).toBe('24 h');
    expect(windowWords(43200)).toBe('30 days');
    expect(windowWords(61)).toBe('61 min');
    expect(intervalWords(60)).toBe('every hour');
    expect(intervalWords(120)).toBe('every 2 h');
    expect(sourceWord('shipped')).toBe('shipped with soc-ai');
    expect(sourceWord('local')).toBe('written here');
    expect(methodWord('match')).toBe('query');
    expect(methodWord('model')).toBe('learned');
    expect(appliesWord('user')).toBe('account');
    // Negative control: a value this build does not know reads as itself.
    expect(methodWord('quantum_thing')).toBe('quantum thing');
  });
});
