// /operate hub — behavior contract from the Wave-2 plan (Task 6): a grid of
// Panel cards, one per "trust instrument" (spec: "prove your model is fit,
// prove the verdicts held up, prove the audit chain is intact, replay
// history"). Table-driven over the exported CARDS so these assertions can
// never silently drift from what actually renders — a card added to or
// removed from CARDS extends or shrinks this suite for free.
//
// The last test pins the YAGNI decision the plan calls out explicitly: this
// screen fetches and polls NOTHING (the Dashboard's persistent setup-health
// card already owns live status; Operate is pure orientation). Proven by
// mocking every api fn a "show live status on this card" temptation could
// plausibly reach for and asserting none of them fired — stronger than "no
// spinner visible", which a future poller could satisfy while still leaking
// a network call under load (the class of gap src/test/setup.ts's fetch
// guard exists for).
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';

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
}));

import {
  getBacktest,
  getHealth,
  getModelBattery,
  getModelFitness,
  getPreflight,
  getPreflightDetail,
  getQualityEvalStatus,
  getQualityTrend,
  refreshPreflight,
} from '../lib/api';
import { CARDS, Operate } from './Operate';

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
    const links = screen.getAllByRole('link');
    expect(links).toHaveLength(CARDS.length);
    expect(links).toHaveLength(EXPECTED_HREFS.length);
    CARDS.forEach((card, i) => {
      expect(screen.getByText(card.title)).toBeInTheDocument();
      expect(screen.getByText(card.purpose)).toBeInTheDocument();
      expect(links[i]).toHaveAttribute('href', EXPECTED_HREFS[i]);
    });
  });

  it('fetches and polls nothing — the Dashboard card owns live health, this page only orients', () => {
    mount();
    for (const fn of POLL_CANDIDATES) {
      expect(fn).not.toHaveBeenCalled();
    }
  });
});
