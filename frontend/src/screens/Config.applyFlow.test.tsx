// The Config apply flow and the model checks (dogfood 2026-10-01: RC1, RC3,
// RC5, RC13, C12).
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

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

/** The server's values. A test changes them to model a save landing. */
const SERVER = vi.hoisted(() => ({
  sweep_interval_minutes: 61 as number,
  case_prefix: 'old-prefix',
  synthesizer_output_mode: 'tool',
  analyst_tool_choice_required: false as boolean,
}));

const groups = () => [
  {
    title: 'Agent',
    parent: 'Models & Reasoning',
    items: [
      { key: 'analyst_model', label: 'Analyst model', help: '', source: 'db', apply: 'hot-apply', type: 'text', value: MODEL, day1: true },
      { key: 'synthesizer_output_mode', label: 'Synthesizer output mode', help: '', source: 'db', apply: 'hot-apply', type: 'text', value: SERVER.synthesizer_output_mode, day1: true },
      { key: 'analyst_tool_choice_required', label: 'Tool choice required', help: '', source: 'db', apply: 'hot-apply', type: 'toggle', value: SERVER.analyst_tool_choice_required, day1: true },
    ],
  },
  {
    title: 'Sweep',
    parent: 'Hunting',
    items: [
      { key: 'sweep_interval_minutes', label: 'Sweep interval', help: '', source: 'db', apply: 'hot-apply', type: 'number', value: SERVER.sweep_interval_minutes, day1: true },
      { key: 'case_prefix', label: 'Case prefix', help: '', source: 'db', apply: 'hot-apply', type: 'text', value: SERVER.case_prefix, day1: true },
    ],
  },
];

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getConfig: vi.fn(),
  setSetting: vi.fn(),
  listUsers: vi.fn().mockResolvedValue({ users: [] }),
  listDangerSettings: vi.fn().mockResolvedValue([]),
  getGatewayModels: vi.fn().mockResolvedValue({ ok: true, models: [] }),
  getInternalIdentifiers: vi.fn().mockResolvedValue({
    groups: [],
    last_scan: { running: false, last_scan: null, last_summary: null, note: null },
  }),
  getModelFitness: vi.fn(),
  getModelBattery: vi.fn(),
  startModelBattery: vi.fn(),
}));

import { Config } from './Config';
import {
  MODEL_FITNESS_TIMEOUT_MS,
  RequestTimeoutError,
  getConfig,
  getModelBattery,
  getModelFitness,
  setSetting,
} from '../lib/api';
import type { ModelBatteryStatus } from '../lib/api';

const PASS = { grade: 'pass', model: MODEL, legs: [], detail: 'ok' } as never;

const configNow = () =>
  Promise.resolve({ groups: groups(), tokens: [], users: [], dangerHost: '' } as never);

const idle: ModelBatteryStatus = {
  running: false,
  model: MODEL,
  current_config: null,
  completed: 0,
  total: 4,
  error: null,
  result: null,
  stored_at: null,
};

beforeEach(() => {
  localStorage.clear();
  SERVER.sweep_interval_minutes = 61;
  SERVER.case_prefix = 'old-prefix';
  SERVER.synthesizer_output_mode = 'tool';
  SERVER.analyst_tool_choice_required = false;
  vi.mocked(getConfig).mockReset().mockImplementation(configNow);
  vi.mocked(setSetting).mockReset();
  vi.mocked(getModelFitness).mockReset().mockResolvedValue(PASS);
  vi.mocked(getModelBattery).mockReset().mockResolvedValue(idle);
});

afterEach(() => {
  vi.useRealTimers();
});

function renderConfig(hash = '#sweep') {
  return render(
    <MemoryRouter initialEntries={[`/config${hash}`]}>
      <Config />
    </MemoryRouter>,
  );
}

const input = (key: string) =>
  document.querySelector(`[data-setting-key="${key}"] input`) as HTMLInputElement;

describe('Apply shows the applied value without a reload (RC1)', () => {
  it('keeps the applied number and text in their fields while the refetch is out, and after it', async () => {
    renderConfig();
    await waitFor(() => expect(input('sweep_interval_minutes')).toBeTruthy());
    expect(input('sweep_interval_minutes').value).toBe('61');

    fireEvent.change(input('sweep_interval_minutes'), { target: { value: '60' } });
    fireEvent.change(input('case_prefix'), { target: { value: 'new-prefix' } });

    // The save lands. The refetch that follows is slow.
    vi.mocked(setSetting).mockImplementation(async (key: string, value: string) => {
      if (key === 'sweep_interval_minutes') SERVER.sweep_interval_minutes = Number(value);
      if (key === 'case_prefix') SERVER.case_prefix = value;
      return { key, value, restart_required: false } as never;
    });
    let land: () => void = () => {};
    vi.mocked(getConfig).mockImplementation(
      () => new Promise((r) => { land = () => r(configNow() as never); }),
    );

    fireEvent.click(screen.getByRole('button', { name: /Apply changes/ }));
    await screen.findByText(/Applied 2 changes\./);
    // The old fields remounted here, on the OLD server value.
    expect(input('sweep_interval_minutes').value).toBe('60');
    expect(input('case_prefix').value).toBe('new-prefix');

    await act(async () => land());
    await waitFor(() => expect(input('sweep_interval_minutes').value).toBe('60'));
    expect(input('case_prefix').value).toBe('new-prefix');
  });

  it('NEGATIVE CONTROL: Discard still puts the server value back at once', async () => {
    renderConfig();
    await waitFor(() => expect(input('sweep_interval_minutes')).toBeTruthy());
    fireEvent.change(input('sweep_interval_minutes'), { target: { value: '5' } });
    fireEvent.click(screen.getByRole('button', { name: 'Discard' }));
    await waitFor(() => expect(input('sweep_interval_minutes').value).toBe('61'));
  });
});

describe('the "Applied" notice leaves (RC13)', () => {
  it('goes after 8 s', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    vi.mocked(setSetting).mockResolvedValue({ restart_required: false } as never);
    renderConfig();
    await waitFor(() => expect(input('sweep_interval_minutes')).toBeTruthy());
    fireEvent.change(input('sweep_interval_minutes'), { target: { value: '60' } });
    fireEvent.click(screen.getByRole('button', { name: /Apply changes/ }));
    await screen.findByText(/Applied 1 change\./);

    await act(async () => {
      vi.advanceTimersByTime(8000);
    });
    expect(screen.queryByText(/Applied 1 change\./)).toBeNull();
  });

  it('goes on a section change', async () => {
    vi.mocked(setSetting).mockResolvedValue({ restart_required: false } as never);
    renderConfig();
    await waitFor(() => expect(input('sweep_interval_minutes')).toBeTruthy());
    fireEvent.change(input('sweep_interval_minutes'), { target: { value: '60' } });
    fireEvent.click(screen.getByRole('button', { name: /Apply changes/ }));
    await screen.findByText(/Applied 1 change\./);

    fireEvent.click(screen.getAllByText('Agent')[0]);
    await waitFor(() => expect(screen.queryByText(/Applied 1 change\./)).toBeNull());
  });

  it('NEGATIVE CONTROL: a failed apply keeps its error and its staged edit', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    vi.mocked(setSetting).mockRejectedValue(new Error('The value is out of bounds.'));
    renderConfig();
    await waitFor(() => expect(input('sweep_interval_minutes')).toBeTruthy());
    fireEvent.change(input('sweep_interval_minutes'), { target: { value: '9999' } });
    fireEvent.click(screen.getByRole('button', { name: /Apply changes/ }));
    await screen.findByText(/The value is out of bounds\./);
    await act(async () => {
      vi.advanceTimersByTime(8000);
    });
    expect(screen.getByText(/The value is out of bounds\./)).toBeTruthy();
    expect(screen.getByTestId('chip-sweep_interval_minutes')).toBeTruthy();
  });
});

describe('Check fitness keeps the previous grade and names an abort (RC3)', () => {
  it('shows the old chip with "checking…" during the run, and one error line on abort', async () => {
    renderConfig('#agent');
    const chip = await screen.findByTestId('fitness-chip', {}, { timeout: 3000 });
    expect(chip.textContent).toBeTruthy();

    let fail: (e: unknown) => void = () => {};
    vi.mocked(getModelFitness).mockReturnValue(new Promise((_r, j) => { fail = j; }) as never);
    fireEvent.click(screen.getAllByRole('button', { name: 'Check fitness' })[0]);

    expect(await screen.findByTestId('fitness-checking')).toBeTruthy();
    expect(screen.getByTestId('fitness-chip')).toBeTruthy();
    expect(getModelFitness).toHaveBeenLastCalledWith(true);

    await act(async () => fail(new RequestTimeoutError(MODEL_FITNESS_TIMEOUT_MS)));
    const err = await screen.findByTestId('fitness-error');
    expect(err.textContent).toMatch(/^The fitness check did not finish\. The request did not return in 90 s\./);
    // The previous grade is still on screen.
    expect(screen.getByTestId('fitness-chip')).toBeTruthy();
  });
});

describe('the battery match line (RC5, C12)', () => {
  const REC = {
    config: 'native',
    synthesizer_output_mode: 'native',
    analyst_tool_choice_required: false,
    reason: 'Native mode passed every case.',
  };
  const daysAgo = (d: number) => new Date(Date.now() - d * 86_400_000).toISOString().replace('Z', '');
  const withRec = (stored_at: string): ModelBatteryStatus => ({
    ...idle,
    stored_at,
    result: {
      model: MODEL,
      n_per_config: 2,
      configs: [],
      recommendation: REC,
      elapsed_s: 10,
    } as never,
  });

  it('says "staged, not applied" after the recommendation Apply, until Apply changes', async () => {
    vi.mocked(getModelBattery).mockResolvedValue(withRec(daysAgo(2)));
    renderConfig('#agent');
    fireEvent.click(await screen.findByRole('button', { name: 'Apply' }));

    const line = await screen.findByTestId('battery-match');
    expect(line.textContent).toMatch(/staged, not applied/);
    expect(screen.queryByText(/The current settings match/)).toBeNull();
  });

  it('NEGATIVE CONTROL: a live value that matches still says so', async () => {
    SERVER.synthesizer_output_mode = 'native';
    vi.mocked(getModelBattery).mockResolvedValue(withRec(daysAgo(2)));
    renderConfig('#agent');
    const line = await screen.findByTestId('battery-match');
    expect(line.textContent).toMatch(/^✓ The current settings match the native recommendation of 2d ago\.$/);
  });

  it('ambers a result older than 30 days and names its age', async () => {
    SERVER.synthesizer_output_mode = 'native';
    vi.mocked(getModelBattery).mockResolvedValue(withRec(daysAgo(57)));
    renderConfig('#agent');
    const line = await screen.findByTestId('battery-match');
    expect(line.textContent).toContain('57d ago');
    expect(line.textContent).toContain('older than 30 days');
    expect(line.textContent).not.toContain('✓');
    expect(line.className).not.toContain('text-success');
  });
});
