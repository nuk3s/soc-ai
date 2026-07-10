// useUpdateCheck tells an open tab that a deploy replaced the hashed bundles
// it may still lazy-import. False negatives waste the heads-up; false alarms
// (or console noise on a flaky fetch) train the operator to ignore it. These
// tests pin the compare, the fail-soft contract, and dismissal re-arming.
import { act, renderHook, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useUpdateCheck } from './useUpdateCheck';

const RUNNING = '/app/assets/index-AAA111.js';

const htmlWith = (entry: string) =>
  `<!doctype html><html><head><script type="module" crossorigin src="${entry}"></script></head></html>`;

const okResponse = (body: string) =>
  ({ ok: true, text: () => Promise.resolve(body) }) as Response;

let script: HTMLScriptElement;
let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  // The entry <script> this "tab" booted from, as Vite bakes it into index.html.
  script = document.createElement('script');
  script.type = 'module';
  script.setAttribute('src', RUNNING);
  document.head.appendChild(script);
  fetchMock = vi.fn();
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  script.remove();
  vi.unstubAllGlobals();
});

/** Let the in-flight check (fetch → text → setState) settle. */
const flush = () => act(async () => {});

describe('useUpdateCheck', () => {
  it('flags stale when the served entry hash differs from the running one', async () => {
    fetchMock.mockResolvedValue(okResponse(htmlWith('/app/assets/index-BBB222.js')));
    const { result } = renderHook(() => useUpdateCheck());
    await waitFor(() => expect(result.current.stale).toBe(true));
    expect(fetchMock).toHaveBeenCalledWith('/app/index.html', { cache: 'no-store' });
  });

  it('stays quiet when the entries match (suffix compare tolerates the /app base path)', async () => {
    // The regex match starts at /assets/… while the DOM src is /app/assets/… —
    // a base-path difference must not false-alarm.
    fetchMock.mockResolvedValue(okResponse(htmlWith(RUNNING)));
    const { result } = renderHook(() => useUpdateCheck());
    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    await flush();
    expect(result.current.stale).toBe(false);
  });

  it('fails soft: a fetch error never raises the banner (and never throws)', async () => {
    fetchMock.mockRejectedValue(new TypeError('backend restarting'));
    const { result } = renderHook(() => useUpdateCheck());
    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    await flush();
    expect(result.current.stale).toBe(false);
  });

  it('dismiss hides the banner, and a NEWER deploy (different entry) re-arms it', async () => {
    fetchMock.mockResolvedValue(okResponse(htmlWith('/app/assets/index-BBB222.js')));
    const { result } = renderHook(() => useUpdateCheck());
    await waitFor(() => expect(result.current.stale).toBe(true));

    act(() => result.current.dismiss());
    expect(result.current.stale).toBe(false);

    // Yet another deploy changes the entry again; window focus re-checks.
    fetchMock.mockResolvedValue(okResponse(htmlWith('/app/assets/index-CCC333.js')));
    act(() => {
      window.dispatchEvent(new Event('focus'));
    });
    await waitFor(() => expect(result.current.stale).toBe(true));
  });
});
