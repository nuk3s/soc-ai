import { act, renderHook, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { useAsync } from './useAsync';

describe('useAsync — freshness + refetch (2026-07-31 visual pass)', () => {
  it('records lastUpdated on success and re-runs on refetch()', async () => {
    let n = 0;
    const loader = vi.fn(async () => `v${++n}`);
    const { result } = renderHook(() => useAsync(loader, []));

    await waitFor(() => expect(result.current.data).toBe('v1'));
    expect(result.current.failCount).toBe(0);
    expect(typeof result.current.lastUpdated).toBe('number');
    expect(result.current.lastUpdated).toBeGreaterThan(0);

    act(() => result.current.refetch());
    await waitFor(() => expect(result.current.data).toBe('v2'));
    expect(loader).toHaveBeenCalledTimes(2);
  });

  it('counts consecutive background-poll failures, keeps last-good data, resets on recovery', async () => {
    let n = 0;
    const loader = vi.fn(async () => {
      n += 1;
      if (n === 1) return 'ok';
      if (n <= 3) throw new Error('poll down');
      return 'recovered';
    });
    vi.useFakeTimers();
    try {
      const { result } = renderHook(() => useAsync(loader, [], { refetchInterval: 1000 }));
      // flush the initial foreground load
      await act(async () => {
        await vi.advanceTimersByTimeAsync(0);
      });
      expect(result.current.data).toBe('ok');
      expect(result.current.failCount).toBe(0);

      // two background polls fail — data stays, failCount climbs (stale at >= 2)
      await act(async () => {
        await vi.advanceTimersByTimeAsync(1000);
      });
      await act(async () => {
        await vi.advanceTimersByTimeAsync(1000);
      });
      expect(result.current.failCount).toBe(2);
      expect(result.current.data).toBe('ok'); // last-good retained, no flap

      // recovery poll succeeds → failCount resets, data refreshes
      await act(async () => {
        await vi.advanceTimersByTimeAsync(1000);
      });
      expect(result.current.failCount).toBe(0);
      expect(result.current.data).toBe('recovered');
    } finally {
      vi.useRealTimers();
    }
  });
});
