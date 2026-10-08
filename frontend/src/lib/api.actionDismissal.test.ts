// A dismissed recommendation leaves the pending-action part of the needs-you
// count, and an undo puts it back. The sidebar, the bell and the Dashboard
// poll on their own timers, so the action card announces the change, as the
// execute call does.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { dismissAction, executeAction, onNeedsYouChanged, restoreAction } from './api';

let fetchMock: ReturnType<typeof vi.fn>;

const ok = (body: unknown = {}) =>
  Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) } as Response);

beforeEach(() => {
  fetchMock = vi.fn(() => ok({ dismissed: true, by: 'ana', at: '2026-10-06T10:00:00Z' }));
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('the action card moves the needs-you count', () => {
  it('announces a dismissal, an undo and an execution', async () => {
    const heard = vi.fn();
    const stop = onNeedsYouChanged(heard);
    await dismissAction('INV-1', 0);
    expect(String(fetchMock.mock.calls[0][0])).toBe('/api/v1/investigations/INV-1/actions/0/dismiss');
    expect(heard).toHaveBeenCalledTimes(1);
    await restoreAction('INV-1', 0);
    expect(String(fetchMock.mock.calls[1][0])).toBe('/api/v1/investigations/INV-1/actions/0/restore');
    expect(heard).toHaveBeenCalledTimes(2);
    await executeAction('INV-1', 0, 'alert');
    expect(heard).toHaveBeenCalledTimes(3);
    stop();
  });

  it('announces nothing when the server refuses the dismissal', async () => {
    fetchMock.mockImplementation(() =>
      Promise.resolve({
        ok: false,
        status: 409,
        json: () => Promise.resolve({ detail: { reason: 'already_executed' } }),
        text: () => Promise.resolve(''),
      } as Response),
    );
    const heard = vi.fn();
    const stop = onNeedsYouChanged(heard);
    await expect(dismissAction('INV-1', 0)).rejects.toBeTruthy();
    expect(heard).not.toHaveBeenCalled();
    stop();
  });
});
