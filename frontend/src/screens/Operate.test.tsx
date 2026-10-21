// /operate hub — behavior contract from the Wave-2 plan (Task 6): a grid of
// Panel cards, one per "trust instrument" (spec: "prove your model is fit,
// prove the verdicts held up, prove the audit chain is intact, replay
// history"). Table-driven over the exported CARDS so these assertions can
// never silently drift from what actually renders — a card added to or
// removed from CARDS extends or shrinks this suite for free.
//
// The last test pins the YAGNI decision the plan calls out explicitly: the
// six link cards fetch and poll NOTHING (the Dashboard's persistent
// setup-health card already owns live status; the cards are pure
// orientation). Proven by mocking every api fn a "show live status on this
// card" temptation could plausibly reach for and asserting none of them
// fired — stronger than "no spinner visible", which a future poller could
// satisfy while still leaking a network call under load (the class of gap
// src/test/setup.ts's fetch guard exists for).
//
// The live panels are the admitted exceptions, each reading because it answers
// a question about unattended machinery with no other owner: the dependency
// block (GET /health), the job list (GET /config, /auto-triage,
// /dossiers/sweep-health, /discovery/scan, /audit/verify-schedule,
// /quality/trend, /quality/eval/status, /maintenance), the hunt catalog
// (GET /hunt-catalog, and GET /hunts/hits for the 7-day hit total the Hunts
// page counts) and the escalation ledger (GET /escalations/stranded).
// StatusDependenciesPanel.test.tsx, StatusJobsPanel.test.tsx,
// Operate.catalog.test.tsx and Operate.escalations.test.tsx cover the panels
// themselves.
//
// The guard below admits those reads by name. Each fires once on mount and
// once per 5-minute tick, never faster: a panel that re-read on every render
// or on a short timer fails it. Every other candidate still fails the test if
// it fires. getHealth, getQualityTrend and getQualityEvalStatus moved from the
// forbidden list to the admitted list on purpose (H1-D14, R5-I4): the job list
// and the dependency block need them, and the cards still read nothing.
import { act, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getHealth: vi.fn(),
  getPreflight: vi.fn(),
  getPreflightDetail: vi.fn(),
  refreshPreflight: vi.fn(),
  getModelFitness: vi.fn(),
  getModelBattery: vi.fn(),
  getQualityTrend: vi.fn(),
  getQualityEvalStatus: vi.fn(),
  getBacktest: vi.fn(),
  getHuntCatalog: vi.fn(),
  getStrandedEscalations: vi.fn(),
  getAnalyticHits: vi.fn().mockResolvedValue({ hits: [], counts: { all: 0, unread: 0, live: 0, shadow: 0 } }),
  getConfig: vi.fn(),
  getAutoTriageStatus: vi.fn(),
  getDossierSweepHealth: vi.fn(),
  getDiscoveryScan: vi.fn(),
  getAuditVerifySchedule: vi.fn(),
  getMaintenance: vi.fn(),
}));

import {
  getAnalyticHits,
  getAuditVerifySchedule,
  getAutoTriageStatus,
  getBacktest,
  getConfig,
  getDiscoveryScan,
  getDossierSweepHealth,
  getHealth,
  getHuntCatalog,
  getMaintenance,
  getModelBattery,
  getModelFitness,
  getPreflight,
  getPreflightDetail,
  getQualityEvalStatus,
  getQualityTrend,
  getStrandedEscalations,
  refreshPreflight,
} from '../lib/api';
import { CARDS, Operate } from './Operate';

// An installed-but-idle catalog: the loop off, no specs — the panel renders
// its header and empty state and nothing that could collide with the card
// assertions below.
beforeEach(() => {
  vi.mocked(getHuntCatalog).mockReset().mockResolvedValue({
    specs: [],
    sweeps_enabled: false,
    sweep_interval_minutes: 60,
    sweep_window_minutes: 1440,
    last_sweep_at: null,
  });
  // A settled ledger: nothing claimed and unanswered, so the panel renders its
  // empty state and nothing that could collide with the card assertions.
  vi.mocked(getStrandedEscalations).mockReset().mockResolvedValue({
    claims: [],
    total: 0,
    settling_minutes: 15,
  });
  // The dependency block and the job list. Their content is their own suites'
  // business. Here each read only has to answer, so the count can be pinned.
  vi.mocked(getHealth).mockReset().mockResolvedValue({
    es: { ok: true, detail: 'es' },
    llm: { ok: true, detail: 'llm' },
    so: { ok: true, detail: 'so' },
  });
  vi.mocked(getConfig).mockReset().mockResolvedValue({ groups: [], tokens: [], users: [], dangerHost: '' });
  vi.mocked(getAutoTriageStatus).mockReset().mockResolvedValue({
    active: false,
    total: 0,
    hunted: 0,
    skipped: 0,
    failed: 0,
    finished_at: null,
    severities: [],
    note: null,
    current: null,
    tool_calls: 0,
  });
  vi.mocked(getDossierSweepHealth).mockReset().mockResolvedValue({
    running: false,
    degraded: false,
    last_run: null,
    error_count: 0,
  });
  vi.mocked(getDiscoveryScan).mockReset().mockResolvedValue({
    running: false,
    last_scan: null,
    last_summary: null,
    note: null,
  });
  vi.mocked(getAuditVerifySchedule).mockReset().mockResolvedValue({
    enabled: true,
    interval_hours: 24,
    window_days: 7,
    last_run: null,
    broken: false,
    broken_since: null,
    detail: null,
  });
  vi.mocked(getQualityTrend).mockReset().mockResolvedValue({
    points: [],
    freshness: {
      latest_ts: null,
      scheduled: false,
      stale: false,
      last_attempt_at: null,
      last_exit_code: null,
      last_detail: null,
    },
  });
  vi.mocked(getQualityEvalStatus).mockReset().mockResolvedValue({
    running: false,
    last_run: null,
    last_exit_code: null,
    last_detail: '',
  });
  vi.mocked(getMaintenance).mockReset().mockResolvedValue({
    backups: [],
    backups_dir: '/data/backups',
    blocklists_dir: '/data/blocklists',
    blocklists_refreshed: null,
    blocklist_files: 0,
  });
  for (const fn of FORBIDDEN) vi.mocked(fn).mockReset();
});

// Every api fn a "live status on this card" addition could plausibly reach
// for, across all six cards (preflight = diagnostics & audit chain,
// fitness/battery = model fitness, backtest = backtest). Not exhaustive of the
// whole api surface. These are the shapes that would tempt someone back toward
// a poller here.
const FORBIDDEN = [
  getPreflight,
  getPreflightDetail,
  refreshPreflight,
  getModelFitness,
  getModelBattery,
  getBacktest,
];

// The reads the live panels make, by name. Each fires once per tick.
const ADMITTED = {
  getHealth,
  getConfig,
  getAutoTriageStatus,
  getDossierSweepHealth,
  getDiscoveryScan,
  getAuditVerifySchedule,
  getQualityTrend,
  getQualityEvalStatus,
  getMaintenance,
  getHuntCatalog,
  getStrandedEscalations,
  getAnalyticHits,
};

function callCounts(): Record<string, number> {
  return Object.fromEntries(
    Object.entries(ADMITTED).map(([name, fn]) => [name, vi.mocked(fn).mock.calls.length]),
  );
}

const every = (n: number) => Object.fromEntries(Object.keys(ADMITTED).map((name) => [name, n]));

function mount() {
  return render(
    <MemoryRouter>
      <Operate />
    </MemoryRouter>,
  );
}

describe('Operate hub', () => {
  it('exports exactly the six trust-instrument cards, in the spec order', () => {
    expect(CARDS.map((c) => c.title)).toEqual([
      'Model fitness',
      'Verdict quality',
      'Audit chain',
      'Backtest',
      'Diagnostics',
      'Runbooks',
    ]);
  });

  // Hardcoded rather than read off CARDS[i].to: comparing a rendered href
  // against the very `to` field it was rendered from is a tautology — a
  // wrong link in Operate.tsx would still "pass" because the test and the
  // render share the same source value. These six are the actual product of
  // a link hub; get one wrong and an analyst clicks through to nowhere
  // useful. Order and targets verified against Operate.tsx's CARD_DEFS
  // comment (2026-08-19, branch head fe12fb6).
  const EXPECTED_HREFS = [
    '/config#agent', // Model fitness
    '/config#quality', // Verdict quality
    '/config#diagnostics', // Audit chain
    '/backtest', // Backtest
    '/config#diagnostics', // Diagnostics
    '/runbooks', // Runbooks
  ];

  it('renders every card title, its one-line purpose, and a link to its target — in CARDS order', () => {
    mount();
    // The card links only: the catalog panel carries its own footer link
    // (and, sweeps off, a config link) once its read lands, and which of
    // those is on screen at this instant is the panel's business, not the
    // hub's. Each card link is named "Open <title>"; nothing else is.
    const links = screen
      .getAllByRole('link')
      .filter((l) => CARDS.some((c) => l.getAttribute('aria-label') === `Open ${c.title}`));
    expect(links).toHaveLength(CARDS.length);
    expect(links).toHaveLength(EXPECTED_HREFS.length);
    CARDS.forEach((card, i) => {
      expect(screen.getByText(card.title)).toBeInTheDocument();
      expect(screen.getByText(card.purpose)).toBeInTheDocument();
      expect(links[i]).toHaveAttribute('href', EXPECTED_HREFS[i]);
    });
  });

  it('the cards fetch and poll nothing; only the live panels read, once each', async () => {
    vi.mocked(getAnalyticHits).mockClear();
    mount();
    // Awaited so the guard below runs AFTER the effects have fired. A
    // synchronous check would pass trivially before any effect ran.
    await waitFor(() => expect(callCounts()).toEqual(every(1)));
    for (const fn of FORBIDDEN) {
      expect(fn).not.toHaveBeenCalled();
    }
  });
});

// Fake timers scoped to this describe: it is ABOUT the tick.
describe('Operate hub poll cadence', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('every live read repeats on the 5-minute tick and not before', async () => {
    vi.mocked(getAnalyticHits).mockClear();
    mount();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(callCounts()).toEqual(every(1));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(299_000);
    });
    expect(callCounts()).toEqual(every(1));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_000);
    });
    expect(callCounts()).toEqual(every(2));
    for (const fn of FORBIDDEN) {
      expect(fn).not.toHaveBeenCalled();
    }
  });
});
