// P0 regression: the model-battery panel crashed the WHOLE admin Config page.
//
// The quick fitness check that fires on Config mount persists a battery row with
// an empty-dict result marker (no full battery has run). A degraded gateway can
// still put that shape on the wire, and the panel's table did `result.configs.map`
// on a truthy `{}` — `.configs` undefined → "Cannot read properties of undefined
// (reading 'map')" → the ErrorBoundary swallowed all 8 sub-panels. These tests
// pin the guard: an empty result renders the same quiet buttons-only state as no
// result at all, and a populated result still renders the per-config table.
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ErrorBoundary } from '../components/ErrorBoundary';

vi.mock('./AgentToolsPanel', () => ({ AgentToolsPanel: () => null }));
vi.mock('./ApiKeysPanel', () => ({ ApiKeysPanel: () => null }));
vi.mock('./DataSourcesPanel', () => ({ DataSourcesPanel: () => null }));
vi.mock('./EgressPolicyPanel', () => ({ EgressPolicyPanel: () => null }));
vi.mock('./NotificationsPanel', () => ({ NotificationsPanel: () => null }));
vi.mock('./RedactionPreviewPanel', () => ({ RedactionPreviewPanel: () => null }));
vi.mock('./DetectionTuningPanel', () => ({ DetectionTuningPanel: () => null }));
vi.mock('./MaintenancePanel', () => ({ MaintenancePanel: () => null }));
vi.mock('./RunbooksPanel', () => ({ RunbooksPanel: () => null }));
vi.mock('./AboutPanel', () => ({ AboutPanel: () => null }));

const MODEL = vi.hoisted(() => 'analyst-model-x');

const GROUPS = vi.hoisted(() => [
  {
    title: 'Agent',
    parent: 'Models & Reasoning',
    items: [
      {
        key: 'analyst_model',
        label: 'Analyst model',
        help: 'The model that triages alerts.',
        source: 'db',
        apply: 'hot-apply',
        type: 'text',
        value: 'analyst-model-x',
      },
    ],
  },
]);

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getConfig: vi.fn(() => Promise.resolve({ groups: GROUPS, tokens: [], users: [], dangerHost: '' })),
  listUsers: vi.fn().mockResolvedValue({ users: [] }),
  listDangerSettings: vi.fn().mockResolvedValue([]),
  // Empty gateway list → the free-text analyst-model branch, which mounts the
  // same ModelBatteryPanel as the dropdown branch.
  getGatewayModels: vi.fn().mockResolvedValue({ ok: true, models: [] }),
  getInternalIdentifiers: vi.fn().mockResolvedValue({
    groups: [],
    last_scan: { running: false, last_scan: null, last_summary: null, note: null },
  }),
  // The mount-time debounced fitness probe must resolve to a real shape so its
  // effect never throws (unmocked → the setup rejects the fetch).
  getModelFitness: vi.fn().mockResolvedValue({
    grade: 'pass',
    model: MODEL,
    legs: [],
    detail: 'ok',
  }),
  getModelBattery: vi.fn(),
}));

import { Config } from './Config';
import { getModelBattery } from '../lib/api';
import type { ModelBatteryStatus } from '../lib/api';

/** A battery poll result with only the fields under test spelled out. */
const battery = (over: Partial<ModelBatteryStatus>): ModelBatteryStatus => ({
  running: false,
  model: MODEL,
  current_config: null,
  completed: 0,
  total: 4,
  error: null,
  result: null,
  stored_at: null,
  ...over,
});

function renderConfig() {
  return render(
    <ErrorBoundary>
      <MemoryRouter initialEntries={['/config']}>
        <Config />
      </MemoryRouter>
    </ErrorBoundary>,
  );
}

beforeEach(() => {
  localStorage.clear();
  vi.mocked(getModelBattery).mockReset();
});

describe('the empty-result marker is a quiet state, not a crash', () => {
  it('renders the buttons-only empty state for { running:false, result:{} }', async () => {
    // The exact degraded shape: a truthy empty object with NO configs array. The
    // stored_at is set the way a fitness-only row's created_at would be — the
    // panel must not read it as a battery age either.
    vi.mocked(getModelBattery).mockResolvedValue(
      // deliberately off-type: this is the wire shape a degraded backend can send
      battery({ result: {} as never, stored_at: '2026-08-11T00:00:00' }),
    );

    renderConfig();

    // The buttons anchor the panel and appear at mount; wait for the poll to land
    // its empty result and re-render — that re-render is where the crash lived.
    await screen.findByText('Run full battery');
    await waitFor(() => expect(vi.mocked(getModelBattery)).toHaveBeenCalled());

    // Did NOT fall into the boundary…
    expect(screen.queryByText('Something went wrong loading this page')).toBeNull();
    // …renders the same quiet state as "no result at all": buttons, no table.
    expect(screen.getByText('Run full battery')).toBeTruthy();
    expect(screen.getByText('Run all checks')).toBeTruthy();
    expect(screen.queryByRole('table')).toBeNull();
  });
});

describe('a populated battery result still renders the per-config table', () => {
  it('shows one row per config with its ok/n and elapsed time', async () => {
    vi.mocked(getModelBattery).mockResolvedValue(
      battery({
        stored_at: '2026-08-11T00:00:00',
        result: {
          model: MODEL,
          n_per_config: 2,
          configs: [
            {
              output_mode: 'native',
              tool_choice_required: false,
              ok: 2,
              n: 2,
              usable_rate: 1,
              tally: { OK: 2 },
              failures: [],
              elapsed_s: 12.3,
            },
            {
              output_mode: 'tool',
              tool_choice_required: true,
              ok: 1,
              n: 2,
              usable_rate: 0.5,
              tally: { OK: 1 },
              failures: [],
              elapsed_s: 41.7,
            },
          ],
          recommendation: null,
          elapsed_s: 54,
        },
      }),
    );

    renderConfig();

    // The table appears only after the poll result lands.
    expect(await screen.findByText('native')).toBeTruthy();
    expect(screen.getByText('tool+required')).toBeTruthy();
    expect(screen.getByText('2/2')).toBeTruthy();
    expect(screen.getByText('1/2')).toBeTruthy();
    expect(screen.getByRole('table')).toBeTruthy();
    expect(screen.queryByText('Something went wrong loading this page')).toBeNull();
  });
});
