// Pins the Quality card's pure seams (sparkline math, series selection) and its
// three honest render states: empty ("schedule the nightly"), a healthy graded
// trend, and an alarmed run (red highlight + the detector's own reasons).
import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { QualityPoint } from '../lib/api';
import { QualityCard, pct, seriesFor, sparklinePoints } from './QualityCard';

function point(overrides: Partial<QualityPoint> = {}): QualityPoint {
  return {
    id: 1,
    ts: '2026-07-10T02:17:00+00:00',
    mode: 'graded',
    n_ok: 5,
    n_error: 0,
    agreement_rate: 0.8,
    fallback_rate: 0.0,
    error_rate: 0.0,
    latency_p50_ms: 90_000,
    verdict_counts: { false_positive: 4, true_positive: 1 },
    alarmed: false,
    alarm_reasons: [],
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
});
