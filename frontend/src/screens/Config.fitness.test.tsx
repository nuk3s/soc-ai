// The analyst-model fitness chip, after the 2026-08-07 probe rebuild.
//
// The chip used to paint itself red whenever `grade === 'fail'`. Of the first 50
// stored checks for the live model, 25 graded FAIL and every one was a timeout —
// several of them measured while soc-ai's own eval was saturating the same
// gateway, and one of those "unfit" verdicts landed while the model was scoring
// 5/5 on that eval. So the backend now decides the red state itself (`alarm`:
// two consecutive fails) and ships the window it decided from, plus which
// backend served the probe and whether a probe ran at all. These tests pin the
// chip to that wire shape: RED KEYS ON `alarm`, a lone fail is a caution, and a
// declined measurement is a quiet state rather than a stale verdict in a fresh
// coat of paint.
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

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

// Hoisted with the mock factories that read it (vi.mock is lifted to the top).
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
  // Empty gateway list → the free-text analyst-model branch, which renders the
  // same chip as the dropdown branch (one control, one chip under test).
  getGatewayModels: vi.fn().mockResolvedValue({ ok: true, models: [] }),
  getInternalIdentifiers: vi.fn().mockResolvedValue({
    groups: [],
    last_scan: { running: false, last_scan: null, last_summary: null, note: null },
  }),
  getModelBattery: vi.fn().mockResolvedValue({
    running: false,
    model: MODEL,
    current_config: null,
    completed: 0,
    total: 4,
    result: null,
    stored_at: null,
  }),
  getModelFitness: vi.fn(),
}));

import { Config } from './Config';
import { getModelFitness } from '../lib/api';
import type { ModelFitness } from '../lib/api';

/** A fitness response with only the field(s) a test cares about spelled out. */
const fit = (over: Partial<ModelFitness> = {}): ModelFitness => ({
  grade: 'pass',
  model: MODEL,
  legs: [],
  detail: `${MODEL} passed all fitness checks`,
  ...over,
});

/** ISO timestamp `hours` in the past, the way the audit index stores it. */
const isoAgo = (hours: number) => new Date(Date.now() - hours * 3_600_000).toISOString();
/** …and the way the fitness cache stores it: naive UTC, no trailing Z. */
const naiveAgo = (hours: number) => isoAgo(hours).replace('Z', '');

/**
 * Render the Config page with `fitness` as the probe result and return the chip.
 * Clicking "Check fitness" is deterministic where the mount-time debounce is
 * not, and both call the same loader.
 */
async function showChip(fitness: ModelFitness): Promise<HTMLElement> {
  vi.mocked(getModelFitness).mockResolvedValue(fitness);
  render(
    <MemoryRouter initialEntries={['/config']}>
      <Config />
    </MemoryRouter>,
  );
  fireEvent.click(await screen.findByText('Check fitness'));
  return await screen.findByTestId('fitness-chip');
}

const detailText = () => screen.getByTestId('fitness-detail').textContent;

beforeEach(() => {
  localStorage.clear();
});

describe('red keys on `alarm`, not on the grade', () => {
  it('renders a lone fail (alarm=false) in the caution colours, still labelled unfit', async () => {
    // Same grade, three different histories. Comparing the rendered colours to
    // each other (rather than to hard-coded hex) pins the RELATIONSHIP the
    // backend now expresses: alarm is the red, a single fail is a caution.
    const colorOf = async (fitness: ModelFitness) => {
      const view = render(
        <MemoryRouter initialEntries={['/config']}>
          <Config />
        </MemoryRouter>,
      );
      vi.mocked(getModelFitness).mockResolvedValue(fitness);
      fireEvent.click(await screen.findByText('Check fitness'));
      const chip = await screen.findByTestId('fitness-chip');
      const seen = { color: chip.style.color, label: chip.textContent };
      view.unmount();
      return seen;
    };

    const history = { recent_checks: 5, last_pass_at: isoAgo(3) };
    const lone = await colorOf(
      fit({ grade: 'fail', alarm: false, recent_fails: 1, consecutive_fails: 1, ...history }),
    );
    const degraded = await colorOf(fit({ grade: 'degraded', detail: `${MODEL}: reasoning_budget=degraded` }));
    const alarmed = await colorOf(
      fit({ grade: 'fail', alarm: true, recent_fails: 2, consecutive_fails: 2, ...history }),
    );

    expect(lone.color).not.toBe('');
    expect(lone.color).toBe(degraded.color);
    expect(alarmed.color).not.toBe(lone.color);
    // The grade itself is never softened — only the colour it wears.
    expect(lone.label).toBe('unfit');
    expect(alarmed.label).toBe('unfit');
  });

  it('falls back to the single sample when the server sends no alarm field', async () => {
    // An older server (or an unreadable audit index, where the backend degrades
    // to single-sample) must keep today's behaviour: one fail is the verdict.
    const chip = await showChip(fit({ grade: 'fail', detail: `${MODEL}: structured_output=fail` }));
    expect(chip.textContent).toBe('unfit');
    expect(chip.style.color).not.toBe('');
    expect(detailText()).toBe(`${MODEL}: structured_output=fail`);
  });
});

describe('the detail line carries the n-of-m history', () => {
  it('reads "2 of last 5 checks failed, last pass 3h ago"', async () => {
    const chip = await showChip(
      fit({
        grade: 'fail',
        detail: `${MODEL}: structured_output=fail`,
        alarm: true,
        recent_checks: 5,
        recent_fails: 2,
        consecutive_fails: 2,
        last_pass_at: isoAgo(3),
      }),
    );
    expect(chip.textContent).toBe('unfit');
    expect(detailText()).toBe('2 of last 5 checks failed, last pass 3h ago');
  });

  it('says so plainly when the whole window passed', async () => {
    await showChip(fit({ grade: 'pass', alarm: false, recent_checks: 5, recent_fails: 0, consecutive_fails: 0, last_pass_at: isoAgo(1) }));
    expect(detailText()).toBe('last 5 checks passed');
  });

  it('reads a last_pass_at that carries an explicit UTC offset', async () => {
    // last_pass_at is a passthrough of the AUDIT index timestamp, and that field
    // is whatever the indexing writer wrote — "…+00:00" as readily as "…Z". A
    // helper that only knows the cache's naive-UTC shape turns the offset form
    // into an unparseable date, i.e. "no pass in window" over a window that had
    // one. Silently wrong beats loudly wrong for exactly nobody.
    await showChip(
      fit({
        grade: 'fail',
        alarm: true,
        recent_checks: 5,
        recent_fails: 2,
        consecutive_fails: 2,
        last_pass_at: isoAgo(4).replace(/\.\d+Z$/, '+00:00'),
      }),
    );
    expect(detailText()).toBe('2 of last 5 checks failed, last pass 4h ago');
  });

  it('renders the probe detail unchanged when the history fields are null', async () => {
    await showChip(
      fit({
        grade: 'degraded',
        detail: `${MODEL}: reasoning_budget=degraded`,
        alarm: false,
        recent_checks: null,
        recent_fails: null,
        consecutive_fails: null,
        last_pass_at: null,
      }),
    );
    expect(detailText()).toBe(`${MODEL}: reasoning_budget=degraded`);
  });
});

describe('a measured verdict served from the daily cache', () => {
  it('still shows its age on its own (unchanged by the history rework)', async () => {
    await showChip(fit({ grade: 'pass', cached: true, checked_at: naiveAgo(5), measured: true }));
    expect(screen.getByText('5h ago')).toBeTruthy();
    expect(screen.queryByTestId('fitness-stale')).toBeNull();
  });
});

describe('measured=false is a quiet state, not a verdict', () => {
  it('shows the note and marks the carried-over verdict as stale', async () => {
    const chip = await showChip(
      fit({
        grade: 'fail',
        detail: `${MODEL}: structured_output=fail`,
        cached: true,
        checked_at: naiveAgo(3),
        measured: false,
        note: 'not measured: quality-eval batch in flight',
        alarm: false,
        recent_checks: 5,
        recent_fails: 1,
        consecutive_fails: 1,
        last_pass_at: isoAgo(9),
      }),
    );
    expect(chip.textContent).toBe('not measured');
    // Colourless: no probe ran, so the chip claims neither health nor alarm.
    expect(chip.style.color).toBe('');
    // The badge already says "not measured" — the truncated line spends its
    // width on WHY. The full note stays in the tooltip.
    expect(detailText()).toBe('quality-eval batch in flight');
    expect(screen.getByTestId('fitness-detail').title).toContain('not measured: quality-eval batch in flight');
    expect(screen.getByTestId('fitness-stale').textContent).toBe('unfit — last verdict, 3h ago');
    // …and NOT also as a bare cache age, which would read as a fresh check.
    expect(screen.queryByText('3h ago')).toBeNull();
  });

  it('shows the note alone when there is no previous verdict to carry', async () => {
    const chip = await showChip(
      fit({
        grade: 'unknown',
        detail: 'not measured: auto-triage batch in flight',
        measured: false,
        note: 'not measured: auto-triage batch in flight',
      }),
    );
    expect(chip.textContent).toBe('not measured');
    expect(detailText()).toBe('auto-triage batch in flight');
    expect(screen.queryByTestId('fitness-stale')).toBeNull();
  });
});

describe('served_backend names WHICH backend was measured', () => {
  it('joins the detail line as a host, not the whole api_base', async () => {
    await showChip(
      fit({
        grade: 'pass',
        served_backend: { api_base: 'https://gateway.example.test:4000/v1' },
        alarm: false,
        recent_checks: 5,
        recent_fails: 0,
        consecutive_fails: 0,
        last_pass_at: isoAgo(2),
      }),
    );
    expect(detailText()).toBe('last 5 checks passed · via gateway.example.test:4000');
    expect(detailText()).not.toContain('https://');
  });
});

describe('the tooltip keeps the falsifiable per-leg numbers', () => {
  it('carries the probe detail and each leg elapsed/budget line', async () => {
    const chip = await showChip(
      fit({
        grade: 'fail',
        detail: `${MODEL}: structured_output=fail`,
        legs: [
          {
            name: 'structured_output',
            ok: false,
            grade: 'fail',
            detail: 'structured_output timed out after 27.4s (budget 30s)',
            elapsed_s: 27.4,
            backend: 'https://gateway.example.test:4000/v1',
          },
        ],
        alarm: true,
        recent_checks: 5,
        recent_fails: 2,
        consecutive_fails: 2,
        last_pass_at: isoAgo(6),
      }),
    );
    // The visible line is the history now, so the diagnosis has to live here.
    expect(chip.title).toContain(`${MODEL}: structured_output=fail`);
    expect(chip.title).toContain('structured_output timed out after 27.4s (budget 30s)');
  });
});
