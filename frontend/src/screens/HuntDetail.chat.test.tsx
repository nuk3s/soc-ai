// The hunt follow-up chat (HuntChatPanel) was the last surface still forking
// the chat transport by hand. Its applyThread re-armed a 1.5s setTimeout with
// no alive guard, so a poll GET that resolved after the panel unmounted re-armed
// the loop with nothing left to clear it — polling the endpoint and setState-ing
// an unmounted component until the server turn finished, indefinitely if it
// wedged. Porting the panel onto the shared useChatThread hook carries that
// hook's aliveRef guard. These pin the guard (and the ordinary send path) on
// the ported panel.
import { act, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { HuntChatThread } from '../lib/api';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getHuntChat: vi.fn(),
  postHuntChat: vi.fn(),
}));

import { getHuntChat, postHuntChat } from '../lib/api';
import { HuntChatPanel } from './HuntDetail';

const POLL_MS = 1500;

/** A turn still running — the only state that arms the poll. */
const pending: HuntChatThread = { messages: [], pending: true };
/** A settled thread — assistant lines, no turn in flight. */
const thread = (...texts: string[]): HuntChatThread => ({
  messages: texts.map((text) => ({ role: 'assistant' as const, text, tools: null })),
  pending: false,
});

/** A promise the test settles by hand, to hold a poll GET in flight. */
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((res) => {
    resolve = res;
  });
  return { promise, resolve };
}

describe('HuntChatPanel poll lifecycle (fake timers)', () => {
  const tick = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });
  const flush = () => tick(0);

  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
    sessionStorage.clear();
    vi.mocked(getHuntChat).mockResolvedValue(pending);
    vi.mocked(postHuntChat).mockResolvedValue(thread());
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('polls the hunt chat endpoint while a turn is pending', async () => {
    const { unmount } = render(<HuntChatPanel huntId="H-1" />);
    await flush();
    expect(getHuntChat).toHaveBeenCalledTimes(1); // mount fetch, pending → poll armed
    await tick(POLL_MS);
    expect(getHuntChat).toHaveBeenCalledTimes(2); // the armed poll fired
    unmount();
  });

  it('does not re-arm the poll when a response resolves after unmount', async () => {
    const late = deferred<HuntChatThread>();
    const { unmount } = render(<HuntChatPanel huntId="H-1" />);
    await flush();
    expect(getHuntChat).toHaveBeenCalledTimes(1);

    vi.mocked(getHuntChat).mockReturnValueOnce(late.promise);
    await tick(POLL_MS); // the armed poll fires and is held in flight
    expect(getHuntChat).toHaveBeenCalledTimes(2);

    unmount(); // the analyst navigates away mid-poll
    late.resolve(pending); // it comes back STILL pending — the fork re-armed here
    await tick(POLL_MS * 5);
    expect(getHuntChat).toHaveBeenCalledTimes(2); // guarded: the loop stays dead
  });
});

describe('HuntChatPanel send (real timers)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    sessionStorage.clear();
    vi.mocked(getHuntChat).mockResolvedValue(thread());
  });

  it('sends through the hunt endpoints with the page id and renders the reply', async () => {
    vi.mocked(postHuntChat).mockResolvedValue(thread('The DC was worst — 4 findings.'));
    render(<HuntChatPanel huntId="H-1" />);

    fireEvent.change(await screen.findByPlaceholderText(/ask a follow-up/i), {
      target: { value: 'which host was worst?' },
    });
    fireEvent.click(screen.getByLabelText('Send'));

    expect(await screen.findByText('The DC was worst — 4 findings.')).toBeTruthy();
    expect(vi.mocked(postHuntChat).mock.calls[0]).toEqual(['H-1', 'which host was worst?']);
  });

  it('renders the honest error bubble when the transport fails, not a hang', async () => {
    vi.mocked(postHuntChat).mockRejectedValue(new Error('boom'));
    render(<HuntChatPanel huntId="H-1" />);

    fireEvent.change(await screen.findByPlaceholderText(/ask a follow-up/i), {
      target: { value: 'why?' },
    });
    fireEvent.click(screen.getByLabelText('Send'));

    expect(await screen.findByText(/could not reach the server/i)).toBeTruthy();
  });
});
