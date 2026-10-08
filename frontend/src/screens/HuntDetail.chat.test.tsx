// The hunt follow-up chat, now the Ask soc-ai panel on the hunt scope.
//
// The hunt chat was the last surface to fork the chat transport by hand. Its
// applyThread re-armed a 1.5s setTimeout with no alive guard, so a poll GET
// that resolved after the panel unmounted re-armed the loop with nothing left
// to clear it. The shared useChatThread hook carries the aliveRef guard. These
// pin the guard, the send path, and the scope the hunt page claims.
import { act, fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { HuntChatThread } from '../lib/api';
import type { HuntDetailData } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getHuntChat: vi.fn(),
  postHuntChat: vi.fn(),
  getHunt: vi.fn(),
  getAbout: vi.fn().mockResolvedValue({}),
  getHunts: vi.fn().mockResolvedValue([]),
}));

import { getHunt, getHuntChat, postHuntChat } from '../lib/api';
import { ScopedPage, WithChat } from '../test/chatHarness';
import { HuntDetail } from './HuntDetail';

const POLL_MS = 1500;

/** A turn still running: the only state that arms the poll. */
const pending: HuntChatThread = { messages: [], pending: true };
/** A settled thread: assistant lines, no turn in flight. */
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

/** A page that shows hunt H-1 and claims the panel for it. */
const mountScope = () =>
  render(
    <MemoryRouter>
      <WithChat>
        <ScopedPage scope={{ kind: 'hunt', id: 'H-1', name: 'Sweep zeek.conn over 7d' }} />
      </WithChat>
    </MemoryRouter>,
  );

const openPanel = () =>
  fireEvent.click(screen.getByRole('button', { name: 'Ask soc-ai about this hunt' }));

describe('the hunt scope: poll lifecycle (fake timers)', () => {
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

  it('reads nothing while the panel is closed, and polls while a turn is pending', async () => {
    mountScope();
    await flush();
    // A closed panel costs no request.
    expect(getHuntChat).not.toHaveBeenCalled();
    openPanel();
    await flush();
    expect(getHuntChat).toHaveBeenCalledTimes(1); // mount fetch, pending: poll armed
    expect(vi.mocked(getHuntChat).mock.calls[0][0]).toBe('H-1');
    await tick(POLL_MS);
    expect(getHuntChat).toHaveBeenCalledTimes(2); // the armed poll fired
  });

  it('does not re-arm the poll when a response resolves after the panel closed', async () => {
    const late = deferred<HuntChatThread>();
    mountScope();
    openPanel();
    await flush();
    expect(getHuntChat).toHaveBeenCalledTimes(1);

    vi.mocked(getHuntChat).mockReturnValueOnce(late.promise);
    await tick(POLL_MS); // the armed poll fires and is held in flight
    expect(getHuntChat).toHaveBeenCalledTimes(2);

    // The analyst closes the panel mid-poll.
    fireEvent.click(screen.getByRole('button', { name: 'Close Ask soc-ai' }));
    late.resolve(pending); // it comes back STILL pending: the fork re-armed here
    await tick(POLL_MS * 5);
    expect(getHuntChat).toHaveBeenCalledTimes(2); // guarded: the loop stays dead
  });
});

describe('the hunt scope: send (real timers)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    sessionStorage.clear();
    vi.mocked(getHuntChat).mockResolvedValue(thread());
  });

  it('sends through the hunt endpoints with the page id and renders the reply', async () => {
    vi.mocked(postHuntChat).mockResolvedValue(thread('The DC was worst, with 4 findings.'));
    mountScope();
    openPanel();

    fireEvent.change(await screen.findByPlaceholderText(/ask a follow-up/i), {
      target: { value: 'which host was worst?' },
    });
    fireEvent.click(screen.getByLabelText('Send'));

    expect(await screen.findByText('The DC was worst, with 4 findings.')).toBeTruthy();
    expect(vi.mocked(postHuntChat).mock.calls[0]).toEqual(['H-1', 'which host was worst?']);
  });

  it('renders the error bubble when the transport fails, not a hang', async () => {
    vi.mocked(postHuntChat).mockRejectedValue(new Error('boom'));
    mountScope();
    openPanel();

    fireEvent.change(await screen.findByPlaceholderText(/ask a follow-up/i), {
      target: { value: 'why?' },
    });
    fireEvent.click(screen.getByLabelText('Send'));

    expect(await screen.findByText(/could not reach the server/i)).toBeTruthy();
  });

  it('offers no proposal card: the hunt chat is read-only', async () => {
    vi.mocked(getHuntChat).mockResolvedValue({
      messages: [{ role: 'assistant', text: 'Two hosts beaconed.', tools: null }],
      pending: false,
    });
    mountScope();
    openPanel();
    expect(await screen.findByText('Two hosts beaconed.')).toBeTruthy();
    expect(screen.queryByRole('button', { name: /start.*hunt/i })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Apply verdict' })).toBeNull();
  });
});

// The hunt page claims the hunt scope once the hunt has ended. The chat answers
// from the report, so a running hunt has no thread to ask yet.
describe('the hunt page claims the scope', () => {
  const hunt = (status: HuntDetailData['status']): HuntDetailData => ({
    id: 'H-9',
    objective: 'Sweep zeek.conn for periodic egress over 7d',
    title: 'Periodic egress, last 7 days',
    kind: 'chat',
    status,
    narrative: '',
    findings: [],
    affectedHosts: [],
    mitreTechniques: [],
    recommendedActions: [],
    confidence: null,
    startedBy: 'analyst',
    elapsedLabel: '2s',
    elapsedSec: 2,
    ts: '2026-10-06T00:00:00Z',
    timeline: [],
    diff: null,
  });

  const mountPage = () =>
    render(
      <MemoryRouter initialEntries={['/hunts/H-9']}>
        <WithChat>
          <Routes>
            <Route path="/hunts/:id" element={<HuntDetail />} />
          </Routes>
        </WithChat>
      </MemoryRouter>,
    );

  beforeEach(() => {
    vi.clearAllMocks();
    sessionStorage.clear();
    vi.mocked(getHuntChat).mockResolvedValue(thread());
  });

  it('names the hunt in the top bar button and on the scope line', async () => {
    vi.mocked(getHunt).mockResolvedValue(hunt('complete'));
    mountPage();
    fireEvent.click(await screen.findByRole('button', { name: 'Ask soc-ai about this hunt' }));
    expect(screen.getByTestId('ask-scope-title').textContent).toBe('This hunt');
    expect(screen.getByTestId('ask-scope-name').textContent).toBe('Periodic egress, last 7 days');
  });

  it('offers the general thread while the hunt runs', async () => {
    vi.mocked(getHunt).mockResolvedValue(hunt('running'));
    mountPage();
    expect(await screen.findByRole('button', { name: 'Ask soc-ai' })).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Ask soc-ai about this hunt' })).toBeNull();
  });
});
