// The first line of the Hunts page. It counts what waits on the analyst and
// jumps to it. Three things are pinned here: the count is the server's, each
// link sets the filter of the block below, and a failed read reads as a
// failure. A strip that answers "nothing needs you" while the server is down
// is the false all-clear this page exists to prevent.
import { act, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getNeedsYou: vi.fn(),
}));

import { ApiError, emitNeedsYouChanged, getNeedsYou } from '../lib/api';
import { NeedsYouStrip } from './NeedsYouStrip';

const mount = (path = '/hunts') =>
  render(
    <MemoryRouter initialEntries={[path]}>
      <NeedsYouStrip />
    </MemoryRouter>,
  );

beforeEach(() => {
  vi.mocked(getNeedsYou)
    .mockReset()
    .mockResolvedValue({ unread_shadow_hits: 2, leads_needing_decision: 2, total: 4 });
});

describe('NeedsYouStrip', () => {
  it('counts what waits and names each waiting thing', async () => {
    mount();
    const strip = await screen.findByTestId('needs-you');
    expect(strip.textContent).toContain('Needs you');
    expect(await screen.findByTestId('needs-you-count')).toHaveProperty('textContent', '4');
    expect(screen.getByText('2 shadow hits are unread')).toBeTruthy();
    expect(screen.getByText('2 leads wait on a decision')).toBeTruthy();
  });

  it('sets the hit filter and the lead tab from the links', async () => {
    mount();
    const hits = await screen.findByText('2 shadow hits are unread');
    expect(hits.getAttribute('href')).toBe('/hunts?hits=unread#analytic-hits');
    const leads = screen.getByText('2 leads wait on a decision');
    expect(leads.getAttribute('href')).toBe('/hunts?leads=needs_decision#leads');
  });

  it('keeps the parameters the address already carries', async () => {
    mount('/hunts?range=7d');
    const hits = await screen.findByText('2 shadow hits are unread');
    expect(hits.getAttribute('href')).toBe('/hunts?range=7d&hits=unread#analytic-hits');
  });

  it('counts one hit and one lead in the singular', async () => {
    vi.mocked(getNeedsYou).mockResolvedValue({
      unread_shadow_hits: 1,
      leads_needing_decision: 1,
      total: 2,
    });
    mount();
    expect(await screen.findByText('1 shadow hit is unread')).toBeTruthy();
    expect(screen.getByText('1 lead waits on a decision')).toBeTruthy();
  });

  it('names only the thing that waits', async () => {
    vi.mocked(getNeedsYou).mockResolvedValue({
      unread_shadow_hits: 0,
      leads_needing_decision: 3,
      total: 3,
    });
    mount();
    expect(await screen.findByText('3 leads wait on a decision')).toBeTruthy();
    expect(screen.queryByText(/unread/)).toBeNull();
  });

  it('takes one line when nothing waits', async () => {
    vi.mocked(getNeedsYou).mockResolvedValue({
      unread_shadow_hits: 0,
      leads_needing_decision: 0,
      total: 0,
    });
    mount();
    expect(await screen.findByText('Nothing needs you.')).toBeTruthy();
    expect(screen.getByText('No unread shadow hit. No lead waits on a decision.')).toBeTruthy();
    expect(screen.queryByTestId('needs-you-count')).toBeNull();
  });

  it('reads a failed read as a failure and never as a zero', async () => {
    vi.mocked(getNeedsYou).mockRejectedValue(new ApiError('down', 503));
    mount();
    expect(await screen.findByText('Could not read what needs you.')).toBeTruthy();
    expect(screen.queryByText('Nothing needs you.')).toBeNull();
  });

  it('reads the count again when a hit or a lead changes', async () => {
    mount();
    await screen.findByTestId('needs-you-count');
    expect(getNeedsYou).toHaveBeenCalledTimes(1);
    emitNeedsYouChanged();
    await waitFor(() => expect(getNeedsYou).toHaveBeenCalledTimes(2));
  });
});

// The first read failing reads as a failure. A poll failing after a good read
// kept the last number with nothing on screen to date it, so a dead API read as
// a fresh count. `failCount >= 2` is the house threshold: one missed poll is a
// blip, and a marker that fires on every hiccup is one an analyst stops
// reading.
describe('NeedsYouStrip on a failing poll', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  const settle = () => act(async () => { await vi.advanceTimersByTimeAsync(0); });
  const poll = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });

  it('dates the count it is still showing once the polls are failing', async () => {
    vi.mocked(getNeedsYou)
      .mockResolvedValueOnce({ unread_shadow_hits: 2, leads_needing_decision: 2, total: 4 })
      .mockRejectedValue(new ApiError('down', 503));
    mount();
    await settle();
    expect(screen.getByTestId('needs-you-count').textContent).toBe('4');
    expect(screen.queryByText(/This data is from/)).toBeNull();

    await poll(130_000);
    expect(screen.getByText(/This data is from/)).toBeTruthy();
    // The number stays: last-known beats a blank, as long as it is dated.
    expect(screen.getByTestId('needs-you-count').textContent).toBe('4');
  });

  it('rides out one missed poll without a marker', async () => {
    vi.mocked(getNeedsYou)
      .mockResolvedValueOnce({ unread_shadow_hits: 2, leads_needing_decision: 2, total: 4 })
      .mockRejectedValueOnce(new ApiError('down', 503))
      .mockResolvedValue({ unread_shadow_hits: 2, leads_needing_decision: 2, total: 4 });
    mount();
    await settle();
    await poll(70_000);
    expect(screen.queryByText(/This data is from/)).toBeNull();
  });
});
