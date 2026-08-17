// useChatThread is the transport slice every chat surface shares: the mount
// fetch, a poll that re-arms ONLY while a turn is pending, send with a
// one-in-flight guard, network-error surfacing, and the per-subject draft.
//
// These tests pin the contract that makes it reusable rather than a third
// copy-paste: the idle cost (exactly one GET — a dashboard-resident chat that
// polls forever is a cost bug, not a cosmetic one), the pending-only poll, and
// the fact that the endpoints and the subject are PARAMETERS. A surface with no
// investigation id (the Dashboard general chat) passes a constant subject and
// endpoints that ignore it; nothing investigation-shaped may be baked in.
//
// Fake timers throughout (the poll is a 1.5s setTimeout). Note: no `waitFor` —
// testing-library only recognises JEST fake timers, so under vitest's it waits
// on a clock nothing advances and the test dies on the 5s timeout. `flush()`
// below is the fake-timer-safe equivalent.
import { act, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ChatThread } from './api';
import { loadChatDraft, saveChatDraft } from './chatDraft';
import { useChatThread } from './useChatThread';

const NET_ERR = 'Could not reach the server — please try again.';
const POLL_MS = 1500;

/** A settled thread snapshot — no turn in flight, so the poll must not re-arm. */
const idle = (...texts: string[]): ChatThread => ({
  messages: texts.map((text) => ({ role: 'assistant' as const, text })),
  pending: false,
});

/** A snapshot with a turn still running — the only state that arms the poll. */
const busy = (...texts: string[]): ChatThread => ({ ...idle(...texts), pending: true });

/** A promise the test settles by hand, to hold a request in flight. */
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((res) => {
    resolve = res;
  });
  return { promise, resolve };
}

let fetchThread: ReturnType<typeof vi.fn>;
let sendMessage: ReturnType<typeof vi.fn>;

const mount = (subject = 'INV-A', seed?: ChatThread['messages']) =>
  renderHook(({ s }: { s: string }) => useChatThread({ subject: s, seed, fetchThread, sendMessage }), {
    initialProps: { s: subject },
  });

/** Advance the clock (firing the poll) AND settle the promise chains it starts. */
const tick = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });
/** Settle already-resolved promises without moving the clock. */
const flush = () => tick(0);

const texts = (thread: { messages: { text: string }[] }) => thread.messages.map((m) => m.text);

beforeEach(() => {
  vi.useFakeTimers();
  sessionStorage.clear();
  fetchThread = vi.fn().mockResolvedValue(idle());
  sendMessage = vi.fn().mockResolvedValue(idle());
});

afterEach(() => {
  vi.useRealTimers();
});

describe('useChatThread transport', () => {
  it('costs exactly one GET while the thread is idle', async () => {
    fetchThread.mockResolvedValue(idle('older reply'));
    const { result } = mount();
    await flush();

    expect(texts(result.current)).toEqual(['older reply']);
    expect(fetchThread).toHaveBeenCalledTimes(1);
    expect(fetchThread).toHaveBeenCalledWith('INV-A');

    // No turn is pending, so nothing may re-arm — 20 poll intervals later the
    // surface has still issued exactly the one mount GET.
    await tick(POLL_MS * 20);
    expect(fetchThread).toHaveBeenCalledTimes(1);
  });

  it('leaves a freshly-seeded thread alone when the server has nothing to add', async () => {
    // An empty, idle server thread adds nothing over the seed — applying it
    // would blank the seeded conversation the screen already rendered.
    fetchThread.mockResolvedValue(idle());
    const { result } = mount('INV-A', [{ role: 'assistant', text: 'seeded verdict' }]);
    await flush();

    expect(fetchThread).toHaveBeenCalledTimes(1);
    expect(texts(result.current)).toEqual(['seeded verdict']);
  });

  it('re-arms the poll only while a turn is pending, and stops when the reply lands', async () => {
    const { result } = mount();
    await flush();

    sendMessage.mockResolvedValue(busy());
    act(() => result.current.setDraft('why not a false positive?'));
    await act(async () => { result.current.send(); });

    expect(result.current.pending).toBe(true);
    fetchThread.mockResolvedValue(busy());
    await tick(POLL_MS);
    expect(fetchThread).toHaveBeenCalledTimes(2); // poll armed by the pending turn
    await tick(POLL_MS);
    expect(fetchThread).toHaveBeenCalledTimes(3);

    // The reply lands: pending clears and the poll must NOT re-arm.
    fetchThread.mockResolvedValue(idle('here is why'));
    await tick(POLL_MS);
    expect(fetchThread).toHaveBeenCalledTimes(4);
    expect(result.current.pending).toBe(false);
    await tick(POLL_MS * 10);
    expect(fetchThread).toHaveBeenCalledTimes(4);
  });

  it('carries the in-flight turn tool progress, and drops it once idle', async () => {
    const { result } = mount();
    await flush();

    sendMessage.mockResolvedValue({ ...busy(), progress_tools: ['t_events_query'] });
    act(() => result.current.setDraft('dig'));
    await act(async () => { result.current.send(); });
    expect(result.current.progressTools).toEqual(['t_events_query']);

    fetchThread.mockResolvedValue({ ...idle('done'), progress_tools: ['t_events_query'] });
    await tick(POLL_MS);
    expect(result.current.progressTools).toEqual([]);
  });

  it('blocks a second send while a turn is in flight', async () => {
    const { result } = mount();
    await flush();

    const first = deferred<ChatThread>();
    sendMessage.mockReturnValueOnce(first.promise);
    act(() => result.current.setDraft('first'));
    act(() => result.current.send());
    expect(result.current.pending).toBe(true);

    act(() => result.current.setDraft('second'));
    act(() => result.current.send());
    expect(sendMessage).toHaveBeenCalledTimes(1);

    first.resolve(idle('answer'));
    await flush();
    expect(result.current.pending).toBe(false);
  });

  it('surfaces an unreachable server on send as an assistant bubble', async () => {
    const { result } = mount();
    await flush();

    sendMessage.mockRejectedValueOnce(new TypeError('network down'));
    act(() => result.current.setDraft('question'));
    await act(async () => { result.current.send(); });

    expect(result.current.pending).toBe(false);
    expect(texts(result.current)).toEqual(['question', NET_ERR]);
  });

  it('surfaces a failed poll and stops polling instead of spinning forever', async () => {
    const { result } = mount();
    await flush();

    sendMessage.mockResolvedValue(busy('q'));
    act(() => result.current.setDraft('q'));
    await act(async () => { result.current.send(); });

    fetchThread.mockRejectedValue(new TypeError('network down'));
    await tick(POLL_MS);
    expect(result.current.pending).toBe(false);
    expect(texts(result.current)).toEqual(['q', NET_ERR]);

    const callsAfterFailure = fetchThread.mock.calls.length;
    await tick(POLL_MS * 5);
    expect(fetchThread).toHaveBeenCalledTimes(callsAfterFailure);
  });

  it('drops a reply for a subject the surface has since left', async () => {
    // F40: the Investigation component is reused across investigations. A send
    // still in flight when the screen swaps subject must not clobber the new
    // subject's thread.
    const late = deferred<ChatThread>();
    sendMessage.mockReturnValueOnce(late.promise);
    const { result, rerender } = mount('INV-A');
    await flush();

    act(() => result.current.setDraft('question to A'));
    act(() => result.current.send());
    expect(texts(result.current)).toEqual(['question to A']);

    fetchThread.mockResolvedValue(idle('B thread'));
    rerender({ s: 'INV-B' });
    await flush();
    expect(texts(result.current)).toEqual(['B thread']);

    late.resolve(idle('reply to A'));
    await flush();
    expect(texts(result.current)).toEqual(['B thread']);
  });

  it('stops polling after unmount', async () => {
    sendMessage.mockResolvedValue(busy('q'));
    const { result, unmount } = mount();
    await flush();

    act(() => result.current.setDraft('q'));
    await act(async () => { result.current.send(); });
    expect(result.current.pending).toBe(true);

    unmount();
    await tick(POLL_MS * 5);
    expect(fetchThread).toHaveBeenCalledTimes(1); // the armed poll was cleared
  });

  it('restores the draft per subject and clears it once sent', async () => {
    const { result, rerender } = mount('INV-A');
    await flush();

    act(() => result.current.setDraft('half-typed for A'));
    expect(loadChatDraft('INV-A')).toBe('half-typed for A');

    // Swapping subject must not bleed A's text into B's stored draft.
    rerender({ s: 'INV-B' });
    await flush();
    expect(result.current.draft).toBe('');
    expect(loadChatDraft('INV-B')).toBe('');
    expect(loadChatDraft('INV-A')).toBe('half-typed for A');

    rerender({ s: 'INV-A' });
    await flush();
    expect(result.current.draft).toBe('half-typed for A');

    await act(async () => { result.current.send(); });
    expect(result.current.draft).toBe('');
    expect(loadChatDraft('INV-A')).toBe('');
  });

  it('serves a surface with no investigation id — endpoints may ignore the subject', async () => {
    // The Dashboard general chat is one rolling per-user thread: its endpoints
    // take no id at all. It passes a constant subject, which still keys the
    // draft and the stale-response guard.
    const getGeneral = vi.fn().mockResolvedValue(idle('what can I help with?'));
    const postGeneral = vi.fn().mockResolvedValue(idle('what can I help with?', 'answer'));
    saveChatDraft('general', 'restored on return');

    const { result } = renderHook(() =>
      useChatThread({
        subject: 'general',
        fetchThread: () => getGeneral(),
        sendMessage: (_subject: string, text: string) => postGeneral(text),
      }),
    );
    await flush();

    expect(getGeneral).toHaveBeenCalledWith();
    expect(texts(result.current)).toEqual(['what can I help with?']);
    expect(result.current.draft).toBe('restored on return');

    await act(async () => { result.current.send(); });
    expect(postGeneral).toHaveBeenCalledWith('restored on return');
    expect(texts(result.current)).toEqual(['what can I help with?', 'answer']);
  });

  it('refreshes on demand (an applied verdict re-reads the thread)', async () => {
    const { result } = mount();
    await flush();

    fetchThread.mockResolvedValue(idle('proposal applied'));
    await act(async () => { await result.current.refresh(); });
    expect(texts(result.current)).toEqual(['proposal applied']);
  });
});
