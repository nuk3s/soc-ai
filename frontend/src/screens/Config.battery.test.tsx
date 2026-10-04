// P0 regression: the model-battery panel crashed the WHOLE admin Config page.
//
// The quick fitness check that fires on Config mount persists a battery row with
// an empty-dict result marker (no full battery has run). A degraded gateway can
// still put that shape on the wire, and the panel's table did `result.configs.map`
// on a truthy `{}` — `.configs` undefined → "Cannot read properties of undefined
// (reading 'map')" → the ErrorBoundary swallowed all 8 sub-panels. These tests
// pin the guard: an empty result renders the same quiet buttons-only state as no
// result at all, and a populated result still renders the per-config table.
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
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
        // analyst_model IS one of the real curated day1 keys — day1: true
        // keeps this group's Advanced fold empty so the battery panel under
        // test renders on mount, same as before the tier split existed.
        day1: true,
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
  startModelBattery: vi.fn(),
}));

import { Config } from './Config';
import { ApiError, getModelBattery, startModelBattery } from '../lib/api';
import type { BatteryResult, ModelBatteryStatus } from '../lib/api';

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

/** A finished two-config result, the shape the table renders from. */
const CONFIGS: BatteryResult = {
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
  ],
  recommendation: null,
  elapsed_s: 54,
};

beforeEach(() => {
  localStorage.clear();
  vi.mocked(getModelBattery).mockReset();
  vi.mocked(startModelBattery).mockReset();
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
    await screen.findByText('Run the model battery');
    await waitFor(() => expect(vi.mocked(getModelBattery)).toHaveBeenCalled());

    // Did NOT fall into the boundary…
    expect(screen.queryByText('Something went wrong loading this page')).toBeNull();
    // …renders the same quiet state as "no result at all": buttons, no table.
    expect(screen.getByText('Run the model battery')).toBeTruthy();
    expect(screen.getByText('Check fitness and run the battery')).toBeTruthy();
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

// The only poll loop lived in the effect keyed on the selected model, and it
// re-armed its 2s timer only while the server said running — so the mount poll
// of an idle model left no timer behind, and nothing re-ran the effect after
// "Run the full check". The start handler then forced running:true itself,
// which pinned "Full check: … 1 of 4…" with both buttons disabled until a hard
// reload, whether the server finished, refused the start (5xx), or never ran.
describe('Run the model battery keeps polling until the server reports the result', () => {
  /** Mount, wait for the idle poll to land, and hand back the Run button. */
  async function mountIdle(): Promise<HTMLButtonElement> {
    renderConfig();
    const run = (await screen.findByText('Run the model battery')) as HTMLButtonElement;
    await waitFor(() => expect(vi.mocked(getModelBattery)).toHaveBeenCalledTimes(1));
    return run;
  }

  it('re-arms the poll after a start and renders the finished table', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      vi.mocked(getModelBattery)
        .mockResolvedValueOnce(battery({})) // mount: idle, so no timer is pending
        .mockResolvedValueOnce(battery({ running: true, current_config: 'tool', completed: 1 }))
        .mockResolvedValue(battery({ stored_at: '2026-08-11T00:00:00', result: CONFIGS }));
      vi.mocked(startModelBattery).mockResolvedValue({ started: true, model: MODEL });

      const run = await mountIdle();
      fireEvent.click(run);
      await waitFor(() => expect(vi.mocked(startModelBattery)).toHaveBeenCalledWith(MODEL));

      // Two poll periods: the first answer says running, the second is the result.
      await act(() => vi.advanceTimersByTimeAsync(2100));
      await act(() => vi.advanceTimersByTimeAsync(2100));

      expect(vi.mocked(getModelBattery).mock.calls.length).toBeGreaterThanOrEqual(3);
      expect(screen.getByRole('table')).toBeTruthy();
      expect(screen.getByText('native')).toBeTruthy();
      expect(screen.queryByText(/Model battery:/)).toBeNull();
      expect(run.disabled).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });

  it('settles back to idle and names the refusal when the start fails', async () => {
    vi.mocked(getModelBattery).mockResolvedValue(battery({}));
    vi.mocked(startModelBattery).mockRejectedValue(
      new ApiError('The model gateway is unreachable.', 502),
    );

    const run = await mountIdle();
    fireEvent.click(run);

    // The refusal is shown, not swallowed…
    const err = await screen.findByText(/The model battery could not start/);
    expect(err.textContent).toContain('The model gateway is unreachable.');
    // …and the panel reflects the server's state (idle), not a run that never began.
    expect(screen.queryByText(/Model battery:/)).toBeNull();
    expect(run.disabled).toBe(false);
  });

  it('treats 409 (already running) as a run to pick up, not a failure', async () => {
    vi.mocked(getModelBattery)
      .mockResolvedValueOnce(battery({}))
      .mockResolvedValue(battery({ running: true, current_config: 'native', completed: 0 }));
    vi.mocked(startModelBattery).mockRejectedValue(new ApiError('A battery is already running.', 409));

    const run = await mountIdle();
    fireEvent.click(run);

    expect(await screen.findByText(/Model battery:/)).toBeTruthy();
    expect(screen.queryByText(/could not start/)).toBeNull();
    expect(run.disabled).toBe(true);
  });
});
