// Pins the Quality card's pure seams (sparkline math, series selection, grade
// composition, alarm identity) and its honest render states: empty ("schedule
// the nightly"), a healthy graded trend, and an alarmed run (red highlight +
// the detector's own reasons + the bundle path behind them).
import { fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { QualityPoint } from '../lib/api';
import { absTime } from '../lib/timeRange';
import {
  QualityCard,
  alarmBanner,
  gradeBreakdown,
  pct,
  seriesFor,
  sparklinePoints,
} from './QualityCard';

// Defaults are the PRE-MIGRATION shape on purpose: grade counts and batch_dir
// are NULL on every row written before migration 0026, so the existing render
// assertions in this file keep pinning the layout those rows must still get.
function point(overrides: Partial<QualityPoint> = {}): QualityPoint {
  return {
    id: 1,
    ts: '2026-07-10T02:17:00+00:00',
    mode: 'graded',
    n_ok: 5,
    n_error: 0,
    agreement_rate: 0.8,
    n_yes: null,
    n_partial: null,
    n_no: null,
    n_classified: null,
    fallback_rate: 0.0,
    error_rate: 0.0,
    latency_p50_ms: 90_000,
    verdict_counts: { false_positive: 4, true_positive: 1 },
    alarmed: false,
    alarm_reasons: [],
    batch_dir: null,
    ...overrides,
  };
}

describe('sparklinePoints', () => {
  it('maps a 0..1 series onto the fixed-domain box (0 = bottom, 1 = top)', () => {
    // width 100, height 40, pad 2 → inner 96×36.
    const pts = sparklinePoints([0, 1, 0.5], 100, 40, 2).split(' ');
    expect(pts).toHaveLength(3);
    expect(pts[0]).toBe('2.0,38.0'); // value 0 sits at the bottom edge
    expect(pts[1]).toBe('50.0,2.0'); // value 1 sits at the top edge
    expect(pts[2]).toBe('98.0,20.0'); // value 0.5 sits mid-height
  });

  it('duplicates a single point across the width so one night still draws a line', () => {
    const pts = sparklinePoints([0.5], 100, 40, 2).split(' ');
    expect(pts).toHaveLength(2);
    expect(pts[0]).toBe('2.0,20.0');
    expect(pts[1]).toBe('98.0,20.0');
  });

  it('clamps out-of-range values instead of drawing outside the box', () => {
    const pts = sparklinePoints([-1, 2], 100, 40, 2).split(' ');
    expect(pts[0]).toBe('2.0,38.0'); // clamped to 0
    expect(pts[1]).toBe('98.0,2.0'); // clamped to 1
  });

  it('returns empty for no values', () => {
    expect(sparklinePoints([], 100, 40)).toBe('');
  });
});

describe('seriesFor', () => {
  it('plots agreement for a graded trend and drops null-agreement points', () => {
    const s = seriesFor([
      point({ agreement_rate: 0.9 }),
      point({ agreement_rate: null }), // oracle classified nothing — skipped, not 0
      point({ agreement_rate: 0.7 }),
    ]);
    expect(s).not.toBeNull();
    expect(s?.mode).toBe('graded');
    expect(s?.label).toBe('agreement');
    expect(s?.lowerIsBetter).toBe(false);
    expect(s?.values).toEqual([0.9, 0.7]);
  });

  it('plots fallback rate for a local trend and never blends in graded points', () => {
    const s = seriesFor([
      point({ mode: 'graded', agreement_rate: 0.9, fallback_rate: 0.0 }),
      point({ mode: 'local', agreement_rate: null, fallback_rate: 0.2 }),
      point({ mode: 'local', agreement_rate: null, fallback_rate: 0.4 }),
    ]);
    expect(s?.mode).toBe('local'); // the LATEST point's mode wins
    expect(s?.label).toBe('fallback rate');
    expect(s?.lowerIsBetter).toBe(true);
    expect(s?.values).toEqual([0.2, 0.4]); // graded point excluded
  });

  it('returns null for an empty trend', () => {
    expect(seriesFor([])).toBeNull();
  });
});

describe('pct', () => {
  it('renders a rate as a whole percent and null as an em dash', () => {
    expect(pct(0.834)).toBe('83%');
    expect(pct(0)).toBe('0%');
    expect(pct(null)).toBe('—');
  });
});

describe('gradeBreakdown', () => {
  it('returns null for a pre-migration row (the counts were never recorded)', () => {
    // NOT "0 agree · 0 partial": "we never wrote this down" and "the oracle
    // agreed with nothing" are different facts.
    expect(gradeBreakdown(point({ agreement_rate: 0.6 }))).toBeNull();
  });

  it('returns null for a local row (no oracle, so nothing was classified)', () => {
    expect(
      gradeBreakdown(
        point({
          mode: 'local',
          agreement_rate: null,
          n_yes: 0,
          n_partial: 0,
          n_no: 0,
          n_classified: 0,
        }),
      ),
    ).toBeNull();
  });

  it('tells a 0.60-from-partials apart from a 0.60-from-wrong-verdicts', () => {
    const partials = gradeBreakdown(point({ n_yes: 3, n_partial: 2, n_no: 0, n_classified: 5 }));
    const wrong = gradeBreakdown(point({ n_yes: 3, n_partial: 0, n_no: 2, n_classified: 5 }));
    expect(partials).toBe('3 agree · 2 partial');
    expect(wrong).toBe('3 agree · 2 disagree');
    expect(partials).not.toBe(wrong); // same 0.60 rate, different story
  });

  it('names every non-zero grade, and always the numerator', () => {
    expect(gradeBreakdown(point({ n_yes: 3, n_partial: 1, n_no: 1, n_classified: 5 }))).toBe(
      '3 agree · 1 partial · 1 disagree',
    );
    expect(gradeBreakdown(point({ n_yes: 5, n_partial: 0, n_no: 0, n_classified: 5 }))).toBe(
      '5 agree',
    );
    // A zero numerator is the most important number on the card — never dropped.
    expect(gradeBreakdown(point({ n_yes: 0, n_partial: 0, n_no: 5, n_classified: 5 }))).toBe(
      '0 agree · 5 disagree',
    );
  });
});

// ---- alarm identity (migration 0027) ---------------------------------------
// The alarm was a LATCH: one alarmed run lit the banner for up to 24h with
// "Last run tripped..." even when the condition had persisted for days, and an
// error_ceiling alarm (the eval pipeline died) wore the verdict-quality
// headline. These pin the three facts the server now records: WHICH condition,
// SINCE WHEN, and therefore whether this is news.

const T1 = '2026-08-05T03:07:00+00:00';
const T2 = '2026-08-06T03:07:00+00:00';
const T3 = '2026-08-07T03:07:00+00:00';

/** An alarmed point. Defaults stay pre-0027 (no codes/key/since) so each test
 * opts into the identity fields it is actually about. */
function alarmed(overrides: Partial<QualityPoint> = {}): QualityPoint {
  return point({ alarmed: true, alarm_reasons: ['a reason'], ...overrides });
}

/** An alarmed point carrying the full 0027 identity for one condition. */
function condition(
  codes: string[],
  since: string,
  overrides: Partial<QualityPoint> = {},
): QualityPoint {
  return alarmed({
    alarm_codes: codes,
    alarm_key: codes.slice().sort().join('+'),
    alarm_since: since,
    ...overrides,
  });
}

describe('alarmBanner', () => {
  it('is silent on an empty trend and on a clean latest point', () => {
    expect(alarmBanner([])).toBeNull();
    expect(alarmBanner([point({ ts: T1 }), point({ id: 2, ts: T2 })])).toBeNull();
  });

  it('leaves a pre-0027 alarmed row on exactly the banner it has today', () => {
    // The server never recorded which condition fired, so the card must not
    // guess one — and with no identity there is nothing to key a dismissal on.
    const b = alarmBanner([point({ ts: T1 }), alarmed({ id: 2, ts: T2 })]);
    expect(b?.kind).toBe('quality');
    expect(b?.headline).toBe('Last run tripped the regression alarm');
    expect(b?.pipelineNote).toBeNull();
    expect(b?.dismissId).toBeNull();
  });

  it('calls an error_ceiling-only alarm pipeline health, not verdict quality', () => {
    // "The grader never ran" and "verdict quality regressed" demand different
    // responses; prod's 08-07 03:07 event was misread because they shared copy.
    const b = alarmBanner([
      point({ ts: T1 }),
      condition(['error_ceiling'], T2, {
        id: 2,
        ts: T2,
        n_ok: 0,
        n_error: 5,
        error_rate: 1,
        agreement_rate: null,
      }),
    ]);
    expect(b?.kind).toBe('pipeline');
    expect(b?.headline).toBe('Eval pipeline failing — 5 of 5 eval runs errored');
    expect(b?.pipelineNote).toBeNull(); // the headline already says it
  });

  it('keeps the verdict-quality banner for agreement_drop and fallback_jump', () => {
    for (const code of ['agreement_drop', 'fallback_jump']) {
      const b = alarmBanner([point({ ts: T1 }), condition([code], T2, { id: 2, ts: T2 })]);
      expect(b?.kind).toBe('quality');
      expect(b?.headline).toBe('Last run tripped the regression alarm');
      expect(b?.pipelineNote).toBeNull();
    }
  });

  it('puts the pipeline line BENEATH the quality banner on mixed codes', () => {
    // Not a blended sentence: both conditions are true and each needs its own
    // response, so neither headline may swallow the other.
    const b = alarmBanner([
      point({ ts: T1 }),
      condition(['agreement_drop', 'error_ceiling'], T2, {
        id: 2,
        ts: T2,
        n_ok: 3,
        n_error: 2,
        error_rate: 0.4,
      }),
    ]);
    expect(b?.kind).toBe('quality');
    expect(b?.headline).toBe('Last run tripped the regression alarm');
    expect(b?.pipelineNote).toBe('Eval pipeline also failing — 2 of 5 eval runs errored.');
  });

  it('reads ONGOING when alarm_since predates the latest run, and counts the runs', () => {
    const b = alarmBanner([
      point({ ts: T1 }),
      condition(['agreement_drop'], T2, { id: 2, ts: T2 }),
      condition(['agreement_drop'], T2, { id: 3, ts: T3 }),
    ]);
    expect(b?.ongoing).toBe(true);
    expect(b?.runs).toBe(2);
    expect(b?.headline).toBe(`Regression alarm — ongoing since ${absTime(T2)} (2 runs)`);
  });

  it('reads NEW on the run that raised the alarm (alarm_since === ts)', () => {
    const b = alarmBanner([point({ ts: T1 }), condition(['agreement_drop'], T2, { id: 2, ts: T2 })]);
    expect(b?.ongoing).toBe(false);
    expect(b?.runs).toBe(1);
    expect(b?.headline).toBe('Last run tripped the regression alarm');
  });

  it('restarts the count after a clean night — a re-raise is not the old condition', () => {
    const b = alarmBanner([
      condition(['agreement_drop'], T1, { id: 1, ts: T1 }),
      point({ id: 2, ts: T2 }), // clean run clears the key
      condition(['agreement_drop'], T3, { id: 3, ts: T3 }),
    ]);
    expect(b?.ongoing).toBe(false);
    expect(b?.runs).toBe(1);
  });

  it('counts only trailing runs on the SAME key (a different condition is a different alarm)', () => {
    const b = alarmBanner([
      condition(['error_ceiling'], T1, { id: 1, ts: T1 }),
      condition(['agreement_drop'], T2, { id: 2, ts: T2 }),
      condition(['agreement_drop'], T2, { id: 3, ts: T3 }),
    ]);
    expect(b?.runs).toBe(2);
  });

  it('keys the dismissal on alarm_key AND alarm_since', () => {
    const first = alarmBanner([point({ ts: T1 }), condition(['agreement_drop'], T1, { id: 2, ts: T1 })]);
    const persisting = alarmBanner([
      point({ ts: T1 }),
      condition(['agreement_drop'], T1, { id: 2, ts: T1 }),
      condition(['agreement_drop'], T1, { id: 3, ts: T2 }),
    ]);
    const reRaised = alarmBanner([point({ ts: T1 }), condition(['agreement_drop'], T3, { id: 2, ts: T3 })]);
    // Same condition, still true tomorrow → same id, so a dismissal sticks.
    expect(persisting?.dismissId).toBe(first?.dismissId);
    // A fresh instance of the same code → new id, so the banner comes back.
    expect(reRaised?.dismissId).not.toBe(first?.dismissId);
    expect(first?.dismissId).toContain('agreement_drop');
  });
});

describe('QualityCard', () => {
  it('renders the schedule-it empty state when no snapshot exists', () => {
    render(<QualityCard points={[]} error={null} loading={false} />);
    expect(screen.getByText(/No quality history yet/)).toBeInTheDocument();
    expect(screen.getByText('soc-ai eval-nightly')).toBeInTheDocument();
    expect(screen.getByText(/docs\/DOCKER\.md/)).toBeInTheDocument();
  });

  it('renders the admin hint on an error (the endpoint is admin-gated)', () => {
    render(<QualityCard points={[]} error={new Error('403 Forbidden')} loading={false} />);
    expect(screen.getByText(/Sign in as an admin/)).toBeInTheDocument();
  });

  it('degrades to a neutral demo line on a 403 in demo mode — no admin-login prompt, no alarm', () => {
    // On the public demo admin reads are 403 by design and there is no admin to
    // sign in as, so the card must not show the admin prompt or a scary error.
    render(<QualityCard points={[]} error={new Error('403 Forbidden')} loading={false} demo />);
    expect(screen.getByText(/not shown in the demo/i)).toBeInTheDocument();
    expect(screen.queryByText(/Sign in as an admin/)).toBeNull();
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('shows the mode badge + agreement headline for a healthy graded trend', () => {
    render(
      <QualityCard
        points={[point({ agreement_rate: 0.9 }), point({ id: 2, agreement_rate: 0.8 })]}
        error={null}
        loading={false}
      />,
    );
    expect(screen.getByText('oracle graded')).toBeInTheDocument();
    expect(screen.getByText('80%')).toBeInTheDocument(); // latest point's agreement
    expect(screen.getByText('agreement')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).toBeNull(); // no red strip when clean
  });

  it('badges local mode and headlines fallback rate (agreement is not faked)', () => {
    render(
      <QualityCard
        points={[point({ mode: 'local', agreement_rate: null, fallback_rate: 0.2 })]}
        error={null}
        loading={false}
      />,
    );
    expect(screen.getByText('locally measured')).toBeInTheDocument();
    expect(screen.getByText('20%')).toBeInTheDocument();
    expect(screen.getByText('fallback rate')).toBeInTheDocument();
  });

  it('red-flags an alarmed latest run and lists the detector reasons verbatim', () => {
    const reason = 'agreement_rate 0.40 is more than 0.15 below the trailing median 0.80';
    render(
      <QualityCard
        points={[
          point({ agreement_rate: 0.8 }),
          point({ id: 2, agreement_rate: 0.4, alarmed: true, alarm_reasons: [reason] }),
        ]}
        error={null}
        loading={false}
      />,
    );
    expect(screen.getByRole('alert')).toBeInTheDocument();
    expect(screen.getByText('Last run tripped the regression alarm')).toBeInTheDocument();
    expect(screen.getByText(reason)).toBeInTheDocument();
  });

  // ---- honest counts (migration 0026) --------------------------------------

  it('shows the grade composition behind the rate', () => {
    render(
      <QualityCard
        points={[point({ agreement_rate: 0.6, n_yes: 3, n_partial: 2, n_no: 0, n_classified: 5 })]}
        error={null}
        loading={false}
      />,
    );
    expect(screen.getByText('60%')).toBeInTheDocument();
    expect(screen.getByTestId('quality-grade-counts')).toHaveTextContent('3 agree · 2 partial');
  });

  // THE backward-compatible path: every count column is NULL on rows written
  // before migration 0026, and those rows outlive the upgrade by ~3 months.
  // They must render exactly as they did before this feature existed — same
  // lines, no gap where the composition would go, and no "null" on screen.
  it('renders a pre-migration row exactly as before — no counts line, nothing null', () => {
    const { container } = render(
      <QualityCard points={[point({ agreement_rate: 0.6 })]} error={null} loading={false} />,
    );
    expect(screen.getByText('60%')).toBeInTheDocument();
    expect(screen.getByText('agreement')).toBeInTheDocument();
    expect(screen.getByText(/5 ok · 0 err · error 0%/)).toBeInTheDocument();
    expect(screen.queryByTestId('quality-grade-counts')).toBeNull();
    expect(container.textContent).not.toMatch(/null|undefined|NaN/);
  });

  it('keeps the composition off a local row (there is no oracle to compose)', () => {
    render(
      <QualityCard
        points={[
          point({
            mode: 'local',
            agreement_rate: null,
            fallback_rate: 0.2,
            n_yes: 0,
            n_partial: 0,
            n_no: 0,
            n_classified: 0,
          }),
        ]}
        error={null}
        loading={false}
      />,
    );
    expect(screen.getByText('locally measured')).toBeInTheDocument();
    expect(screen.queryByTestId('quality-grade-counts')).toBeNull();
  });

  // ---- the evidence behind an alarm ----------------------------------------

  it('names the bundle path on an alarmed run, as a server path and not a link', () => {
    const dir = '/var/lib/soc-ai/evals/20260806-021700';
    render(
      <QualityCard
        points={[
          point({ agreement_rate: 0.8 }),
          point({
            id: 2,
            agreement_rate: 0.2,
            alarmed: true,
            alarm_reasons: ['agreement_rate 0.20 is a real drop'],
            batch_dir: dir,
          }),
        ]}
        error={null}
        loading={false}
      />,
    );
    const evidence = screen.getByTestId('quality-evidence');
    expect(evidence).toHaveTextContent(dir);
    // No endpoint serves these bundles — an <a> here would be a broken promise.
    expect(evidence.querySelector('a')).toBeNull();
  });

  it('omits the evidence block when the alarmed row predates the batch_dir column', () => {
    const { container } = render(
      <QualityCard
        points={[
          point({ agreement_rate: 0.8 }),
          point({ id: 2, agreement_rate: 0.2, alarmed: true, alarm_reasons: ['a reason'] }),
        ]}
        error={null}
        loading={false}
      />,
    );
    expect(screen.getByRole('alert')).toBeInTheDocument();
    expect(screen.getByText('a reason')).toBeInTheDocument();
    expect(screen.queryByTestId('quality-evidence')).toBeNull();
    expect(container.textContent).not.toMatch(/null|undefined|NaN/);
  });

  it('keeps the bundle path off a healthy card (it is alarm evidence, not chrome)', () => {
    const dir = '/var/lib/soc-ai/evals/20260806-021700';
    render(
      <QualityCard points={[point({ batch_dir: dir })]} error={null} loading={false} />,
    );
    expect(screen.queryByTestId('quality-evidence')).toBeNull();
    expect(screen.queryByText(dir)).toBeNull();
  });

  // ---- honest headlines + dismiss (migration 0027) -------------------------

  it('renders pipeline health, not a verdict-quality regression, for error_ceiling', () => {
    render(
      <QualityCard
        points={[
          point({ ts: T1 }),
          condition(['error_ceiling'], T2, {
            id: 2,
            ts: T2,
            n_ok: 0,
            n_error: 5,
            error_rate: 1,
            agreement_rate: null,
            alarm_reasons: ['error_rate 1.00 exceeds the 0.30 ceiling'],
          }),
        ]}
        error={null}
        loading={false}
      />,
    );
    expect(screen.getByText('Eval pipeline failing — 5 of 5 eval runs errored')).toBeInTheDocument();
    expect(screen.queryByText('Last run tripped the regression alarm')).toBeNull();
    // The detector's own words still show — this replaces the headline, not the evidence.
    expect(screen.getByText('error_rate 1.00 exceeds the 0.30 ceiling')).toBeInTheDocument();
  });

  it('says how long a condition has persisted instead of blaming the last run', () => {
    render(
      <QualityCard
        points={[
          point({ ts: T1 }),
          condition(['agreement_drop'], T2, { id: 2, ts: T2 }),
          condition(['agreement_drop'], T2, { id: 3, ts: T3 }),
        ]}
        error={null}
        loading={false}
      />,
    );
    expect(
      screen.getByText(`Regression alarm — ongoing since ${absTime(T2)} (2 runs)`),
    ).toBeInTheDocument();
    expect(screen.queryByText('Last run tripped the regression alarm')).toBeNull();
  });

  it('shows the pipeline line under the quality banner on mixed codes', () => {
    render(
      <QualityCard
        points={[
          point({ ts: T1 }),
          condition(['agreement_drop', 'error_ceiling'], T2, {
            id: 2,
            ts: T2,
            n_ok: 3,
            n_error: 2,
            error_rate: 0.4,
          }),
        ]}
        error={null}
        loading={false}
      />,
    );
    expect(screen.getByText('Last run tripped the regression alarm')).toBeInTheDocument();
    expect(screen.getByTestId('quality-pipeline-note')).toHaveTextContent(
      'Eval pipeline also failing — 2 of 5 eval runs errored.',
    );
  });

  describe('dismiss', () => {
    beforeEach(() => {
      localStorage.clear();
    });

    function alarmedTrend(codes: string[], since: string, extra: Partial<QualityPoint> = {}) {
      return [point({ ts: T1 }), condition(codes, since, { id: 2, ts: T2, ...extra })];
    }

    it('hides the banner while the trend and the counts stay', () => {
      render(
        <QualityCard points={alarmedTrend(['agreement_drop'], T2)} error={null} loading={false} />,
      );
      fireEvent.click(screen.getByRole('button', { name: /dismiss/i }));
      expect(screen.queryByRole('alert')).toBeNull();
      // The banner is the only thing that goes: the numbers are the record.
      expect(screen.getByRole('img', { name: 'quality trend sparkline' })).toBeInTheDocument();
      expect(screen.getByText(/5 ok · 0 err · error 0%/)).toBeInTheDocument();
    });

    it('survives a remount (the dismissal is persisted, not component state)', () => {
      const trend = alarmedTrend(['agreement_drop'], T2);
      const first = render(<QualityCard points={trend} error={null} loading={false} />);
      fireEvent.click(screen.getByRole('button', { name: /dismiss/i }));
      first.unmount();
      render(<QualityCard points={trend} error={null} loading={false} />);
      expect(screen.queryByRole('alert')).toBeNull();
    });

    it('scopes the dismissal to THIS condition — a different code shows immediately', () => {
      const first = render(
        <QualityCard points={alarmedTrend(['agreement_drop'], T2)} error={null} loading={false} />,
      );
      fireEvent.click(screen.getByRole('button', { name: /dismiss/i }));
      first.unmount();
      render(
        <QualityCard
          points={alarmedTrend(['fallback_jump'], T2)}
          error={null}
          loading={false}
        />,
      );
      expect(screen.getByRole('alert')).toBeInTheDocument();
    });

    it('re-shows the same code raised afresh after a clean run', () => {
      const first = render(
        <QualityCard points={alarmedTrend(['agreement_drop'], T2)} error={null} loading={false} />,
      );
      fireEvent.click(screen.getByRole('button', { name: /dismiss/i }));
      first.unmount();
      // Same code, new alarm_since = a NEW condition, not the one that was read
      // and set aside.
      render(
        <QualityCard
          points={[
            point({ ts: T1 }),
            condition(['agreement_drop'], T3, { id: 3, ts: T3 }),
          ]}
          error={null}
          loading={false}
        />,
      );
      expect(screen.getByRole('alert')).toBeInTheDocument();
    });

    it('offers no dismiss control on a pre-0027 alarmed row', () => {
      // No recorded identity means no way to tell a later alarm apart from this
      // one — dismissing would risk hiding a different condition.
      render(
        <QualityCard
          points={[point({ ts: T1 }), alarmed({ id: 2, ts: T2 })]}
          error={null}
          loading={false}
        />,
      );
      expect(screen.getByRole('alert')).toBeInTheDocument();
      expect(screen.queryByRole('button', { name: /dismiss/i })).toBeNull();
    });
  });

  describe('copy affordance', () => {
    afterEach(() => {
      Reflect.deleteProperty(navigator, 'clipboard');
    });

    function stubClipboard(clipboard: unknown) {
      Object.defineProperty(navigator, 'clipboard', { value: clipboard, configurable: true });
    }

    function renderAlarmed(dir: string) {
      render(
        <QualityCard
          points={[
            point({ agreement_rate: 0.8 }),
            point({
              id: 2,
              agreement_rate: 0.2,
              alarmed: true,
              alarm_reasons: ['a reason'],
              batch_dir: dir,
            }),
          ]}
          error={null}
          loading={false}
        />,
      );
    }

    it('copies the whole path so the operator can paste it into a shell', async () => {
      const dir = '/var/lib/soc-ai/evals/20260806-021700';
      const writeText = vi.fn().mockResolvedValue(undefined);
      stubClipboard({ writeText });
      renderAlarmed(dir);

      fireEvent.click(screen.getByRole('button', { name: /copy path/i }));
      expect(writeText).toHaveBeenCalledWith(dir);
      expect(await screen.findByText('Copied')).toBeInTheDocument();
    });

    it('hides the button where the clipboard API is unavailable (plain-http install)', () => {
      stubClipboard(undefined);
      renderAlarmed('/var/lib/soc-ai/evals/20260806-021700');
      // A dead button is worse than none: the path is selectable text either way.
      expect(screen.queryByRole('button', { name: /copy path/i })).toBeNull();
      expect(screen.getByTestId('quality-evidence')).toBeInTheDocument();
    });
  });
});
