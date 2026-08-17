// D15 (degraded-grid dogfood) — "MUTED RULES (0)" was asserted off a FAILED
// fetch. Both halves of this panel come from one `getDetectionTuning` call, and
// the count read `data?.overrides ?? []` — so an outage rendered as the number
// zero, with the healthy state's explanatory caption gone and a bare column
// header underneath. A team that relies on mutes reads "nothing is suppressed"
// at the one moment nobody can check.
//
// Unknown is not zero. The count says so, and a genuinely empty list on a
// healthy grid keeps its 0 and its caption — the over-correction guard is the
// last test here.
import { fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { DetectionTuning } from '../lib/api';

const getDetectionTuningMock = vi.hoisted(() => vi.fn());
const unmuteRuleMock = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getDetectionTuning: getDetectionTuningMock,
  unmuteRule: unmuteRuleMock,
}));

import { DetectionTuningPanel } from './DetectionTuningPanel';

const EMPTY: DetectionTuning = { nominations: [], overrides: [] };

const ONE_MUTE: DetectionTuning = {
  nominations: [],
  overrides: [
    {
      id: 1,
      rule_name: 'ET DOC TEST Noisy Rule',
      action: 'mute',
      reason: 'benign scanner',
      created_by: 'analyst',
      created_at: '2026-08-01T00:00:00+00:00',
      active: true,
    },
  ],
};

afterEach(() => {
  getDetectionTuningMock.mockReset();
  unmuteRuleMock.mockReset();
});

describe('DetectionTuningPanel muted-rules count', () => {
  it('does not print a zero it never read', async () => {
    getDetectionTuningMock.mockRejectedValue(new Error('grid unavailable'));
    render(<DetectionTuningPanel />);

    // findBy, not getBy: the header paints on first render while the count
    // depends on the rejected fetch settling.
    expect(await screen.findByText('Muted rules (—)')).toBeTruthy();
    expect(screen.queryByText('Muted rules (0)')).toBeNull();
  });

  it('does not leave the failed table as a bare header', async () => {
    getDetectionTuningMock.mockRejectedValue(new Error('grid unavailable'));
    render(<DetectionTuningPanel />);

    expect(await screen.findByText(/this is not a claim that none are muted/i)).toBeTruthy();
    // ...and it never borrows the healthy state's wording, which asserts a fact.
    expect(screen.queryByText(/No muted rules\./i)).toBeNull();
  });

  it('still renders a real zero and its caption on a healthy grid', async () => {
    // The over-correction guard: an em dash where a measured zero belongs would
    // make the panel useless in the state it is normally in.
    getDetectionTuningMock.mockResolvedValue(EMPTY);
    render(<DetectionTuningPanel />);

    expect(await screen.findByText('Muted rules (0)')).toBeTruthy();
    expect(
      screen.getByText(/No muted rules\. Mute a nominated rule above/i),
    ).toBeTruthy();
    expect(screen.queryByText('Muted rules (—)')).toBeNull();
  });

  it('counts the overrides it actually loaded', async () => {
    getDetectionTuningMock.mockResolvedValue(ONE_MUTE);
    render(<DetectionTuningPanel />);

    expect(await screen.findByText('Muted rules (1)')).toBeTruthy();
  });

  it('does not blank the count of rows it is still showing', async () => {
    // useAsync keeps the last good data through a failed refetch, so a row is
    // on screen. "—" over a visible row would be its own small lie; the count
    // is unknown only when nothing ever loaded.
    getDetectionTuningMock.mockResolvedValue(ONE_MUTE);
    unmuteRuleMock.mockResolvedValue({ removed: true });
    render(<DetectionTuningPanel />);
    await screen.findByText('Muted rules (1)');

    // The un-mute succeeds, which bumps the nonce; the refetch behind it fails.
    getDetectionTuningMock.mockRejectedValue(new Error('grid unavailable'));
    fireEvent.click(screen.getByText('Un-mute'));

    expect(await screen.findByText(/couldn't load this view/i)).toBeTruthy();
    expect(screen.getByText('Muted rules (1)')).toBeTruthy();
    expect(screen.queryByText(/this is not a claim that none are muted/i)).toBeNull();
  });
});
