// The grid gap strip (2026-10-19).
//
// The range grid was down from Oct 15 13:36 UTC to Oct 19 10:15 UTC. After it
// came back, every windowed page read the hole as a quiet grid. The backend
// keeps a ledger of grid gaps, and this strip names each gap that overlaps the
// page window. A failed read and an empty ledger show nothing: the strip only
// states a gap the server recorded.
import { act, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getGridGaps: vi.fn(),
}));

import { getGridGaps } from '../lib/api';
import { absoluteTime } from '../lib/timeRange';
import type { GridGap, GridGaps } from '../lib/types';
import { GridGapStrip, gapDuration, gapSentence, gapTime } from './GridGapStrip';

const CLOSED: GridGap = {
  id: 1,
  source: 'probe',
  plane: null,
  started_at: '2026-10-15T13:36:00Z',
  ended_at: '2026-10-19T10:15:00Z',
  open: false,
  duration_s: 333_540,
  detail: 'Elasticsearch did not answer the health probe.',
};

const OPEN: GridGap = { ...CLOSED, id: 2, ended_at: null, open: true };

const SHORT: GridGap = {
  id: 3,
  source: 'sweep',
  plane: 'connection_rate',
  started_at: '2026-10-15T13:36:00Z',
  ended_at: '2026-10-15T14:21:00Z',
  open: false,
  duration_s: 2_700,
  detail: 'Documents stopped on most hosts of the connection_rate plane.',
};

// V1-S5: the strip states the console's one absolute time, with its zone,
// the time the Dashboard panels state. It read "Oct 18 14:00 UTC" beside
// "2026-10-19 09:15 EDT". V1-S6: each line names the type of its gap.
const T15 = absoluteTime('2026-10-15T13:36:00Z');
const T19 = absoluteTime('2026-10-19T10:15:00Z');
const T15B = absoluteTime('2026-10-15T14:21:00Z');
const CLOSED_TEXT = `The grid was unreadable from ${T15} to ${T19} (93 h). Counts in this window are incomplete.`;
const OPEN_TEXT = `The grid is unreadable since ${T15} (93 h so far). Counts in this window are incomplete.`;
const SHORT_TEXT =
  `Most hosts sent no network flow documents from ${T15} to ${T15B} (45 min). ` +
  'Counts in this window are incomplete.';

function reply(gaps: GridGap[]): GridGaps {
  const now = Date.now();
  return {
    since: new Date(now - 7 * 86_400_000).toISOString(),
    until: new Date(now).toISOString(),
    gaps,
  };
}

/** Let the read settle: a macrotask runs every queued promise step of useAsync. */
async function settle() {
  await act(async () => {
    await new Promise((r) => setTimeout(r, 0));
  });
}

beforeEach(() => {
  vi.mocked(getGridGaps).mockReset().mockResolvedValue(reply([]));
});

describe('the gap sentence', () => {
  it('names both edges and the hours of a closed gap', () => {
    expect(gapSentence(CLOSED)).toBe(CLOSED_TEXT);
  });

  it('names the start and the hours so far of an open gap', () => {
    expect(gapSentence(OPEN)).toBe(OPEN_TEXT);
  });

  it('states a gap under an hour in minutes', () => {
    expect(gapSentence(SHORT)).toBe(SHORT_TEXT);
  });

  it('states a time in the console format with its zone', () => {
    expect(gapTime('2026-03-05T04:07:00Z')).toBe(absoluteTime('2026-03-05T04:07:00Z'));
    expect(gapTime('2026-03-05T04:07:00Z')).toMatch(/^2026-03-0[45] \d\d:\d\d \S+$/);
  });

  it('names an open sweep gap and the plane it read', () => {
    expect(gapSentence({ ...SHORT, ended_at: null, open: true, duration_s: 7_200 })).toBe(
      `Most hosts send no network flow documents since ${T15} (2 h so far). Counts in this window are incomplete.`,
    );
    expect(gapSentence({ ...SHORT, plane: 'dns_queries' })).toContain('Most hosts sent no dns queries documents');
    expect(gapSentence({ ...SHORT, plane: null })).toContain('Most hosts sent no grid documents');
  });

  it('names an operator gap and its detail', () => {
    const op: GridGap = { ...CLOSED, id: 4, source: 'operator', detail: 'The sensor VM was down' };
    expect(gapSentence(op)).toBe(
      `An operator recorded a grid gap from ${T15} to ${T19} (93 h). Note: The sensor VM was down. ` +
        'Counts in this window are incomplete.',
    );
    // An operator gap with no detail states no note.
    expect(gapSentence({ ...op, detail: '' })).toBe(
      `An operator recorded a grid gap from ${T15} to ${T19} (93 h). Counts in this window are incomplete.`,
    );
  });

  // Control: a source this build does not know keeps the plain sentence.
  it('states a gap of an unknown source as a gap in the grid data', () => {
    expect(gapSentence({ ...CLOSED, source: 'future' as GridGap['source'] })).toBe(
      `No grid data from ${T15} to ${T19} (93 h). Counts in this window are incomplete.`,
    );
  });

  it('rounds hours to the nearest and never states zero minutes', () => {
    expect(gapDuration(3_600)).toBe('1 h');
    expect(gapDuration(5_399)).toBe('1 h');
    expect(gapDuration(5_400)).toBe('2 h');
    expect(gapDuration(2_700)).toBe('45 min');
    expect(gapDuration(20)).toBe('1 min');
  });
});

describe('the grid gap strip', () => {
  it('states a closed gap in one line and puts the detail in the title', async () => {
    vi.mocked(getGridGaps).mockResolvedValue(reply([CLOSED]));
    render(<GridGapStrip range="7d" />);
    const line = await screen.findByTestId('grid-gap');
    expect(line.textContent).toBe(CLOSED_TEXT);
    expect(line).toHaveAttribute('title', CLOSED.detail);
    expect(screen.getByTestId('grid-gap-strip')).toHaveAttribute('role', 'status');
  });

  it('states an open gap', async () => {
    vi.mocked(getGridGaps).mockResolvedValue(reply([OPEN]));
    render(<GridGapStrip range="7d" />);
    expect((await screen.findByTestId('grid-gap')).textContent).toBe(OPEN_TEXT);
  });

  it('states each gap on its own line, oldest first', async () => {
    vi.mocked(getGridGaps).mockResolvedValue(reply([SHORT, CLOSED]));
    render(<GridGapStrip range="7d" />);
    await screen.findByTestId('grid-gap-strip');
    expect(screen.getAllByTestId('grid-gap').map((l) => l.textContent)).toEqual([SHORT_TEXT, CLOSED_TEXT]);
  });

  it('shows nothing when the window holds no gap', async () => {
    render(<GridGapStrip range="7d" />);
    await waitFor(() => expect(getGridGaps).toHaveBeenCalledTimes(1));
    await settle();
    expect(screen.queryByTestId('grid-gap-strip')).toBeNull();
  });

  it('shows nothing when the read fails', async () => {
    vi.mocked(getGridGaps).mockRejectedValue(new Error('grid down'));
    render(<GridGapStrip range="7d" />);
    await waitFor(() => expect(getGridGaps).toHaveBeenCalledTimes(1));
    await settle();
    expect(screen.queryByTestId('grid-gap-strip')).toBeNull();
  });

  it('sends the start of the 7d window and no upper edge for a preset', async () => {
    const before = Date.now();
    render(<GridGapStrip range="7d" />);
    await waitFor(() => expect(getGridGaps).toHaveBeenCalledTimes(1));
    const after = Date.now();
    const sent = vi.mocked(getGridGaps).mock.calls[0][0];
    const since = new Date(sent.since).getTime();
    expect(since).toBeGreaterThanOrEqual(before - 7 * 86_400_000);
    expect(since).toBeLessThanOrEqual(after - 7 * 86_400_000);
    expect(sent.until).toBeUndefined();
  });

  it('sends both edges of a custom window', async () => {
    const from = new Date(Date.now() - 6 * 3_600_000).toISOString();
    const to = new Date(Date.now() - 2 * 3_600_000).toISOString();
    render(<GridGapStrip range="custom" custom={{ from, to }} />);
    await waitFor(() => expect(getGridGaps).toHaveBeenCalledTimes(1));
    expect(vi.mocked(getGridGaps).mock.calls[0][0]).toEqual({ since: from, until: to });
  });

  it('does not read again when the page renders with the same preset', async () => {
    const { rerender } = render(<GridGapStrip range="7d" />);
    await waitFor(() => expect(getGridGaps).toHaveBeenCalledTimes(1));
    rerender(<GridGapStrip range="7d" custom={null} />);
    await settle();
    expect(getGridGaps).toHaveBeenCalledTimes(1);
  });
});
