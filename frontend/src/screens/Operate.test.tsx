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
// Two panels are the admitted exceptions, both reading because they answer a
// question about unattended machinery with no other owner: the hunt catalog
// (GET /hunt-catalog — is the sweep loop running at all) and the escalation
// ledger (GET /escalations/stranded — which alerts are held by a claim that
// never got an answer). Operate.catalog.test.tsx and
// Operate.escalations.test.tsx cover the panels themselves. The guard below is
// NOT weakened for anything else — it admits those two calls by name, and
// every other candidate still fails the test if it fires.
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

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
}));

import {
  getBacktest,
  getHealth,
  getHuntCatalog,
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
});

// Every api fn a "live status on this card" addition could plausibly reach
// for, across all six cards (health/preflight = diagnostics & audit chain,
// fitness/battery = model fitness, quality = verdict quality, backtest =
// backtest). Not exhaustive of the whole api surface — just the shapes that
// would actually tempt someone back toward a poller here.
const POLL_CANDIDATES = [
  getHealth,
  getPreflight,
  getPreflightDetail,
  refreshPreflight,
  getModelFitness,
  getModelBattery,
  getQualityTrend,
  getQualityEvalStatus,
  getBacktest,
];

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

  it('the cards fetch and poll nothing — the Dashboard card owns live health; only the two panels read', async () => {
    mount();
    // The two admitted reads, awaited so the guard below runs AFTER their
    // effects have fired — a synchronous check would pass trivially before
    // any effect ran.
    await waitFor(() => expect(getHuntCatalog).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(getStrandedEscalations).toHaveBeenCalledTimes(1));
    for (const fn of POLL_CANDIDATES) {
      expect(fn).not.toHaveBeenCalled();
    }
  });
});
