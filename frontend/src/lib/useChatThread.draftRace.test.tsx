// Task #98: a Send button that did nothing at all.
//
// This shipped as "a flaky Dashboard chat test" and was twice mistaken for a
// slow-reply race — the assertion was wrapped in act(), then switched to
// findByText, and it came back both times. The reply never appeared because the
// SEND NEVER HAPPENED. Probed under load, at the moment of failure: the composer
// was still mounted, the user's own message was absent from the DOM, and
// postGeneralChat had been called ZERO times.
//
// The mechanism: `useState(() => loadChatDraft(subject))` restores the saved
// draft on mount, and the reset effect restored it AGAIN. Between the composer
// becoming visible and that effect flushing, an analyst can already have typed —
// and the second restore silently replaces their text with the stored (usually
// empty) draft. `send()` then bails on an empty draft without surfacing anything.
//
// For the analyst that is: type a question into the Dashboard chat on a slow
// load, press Send, and nothing happens. No request, no error, and the text gone.
//
// The race itself is a scheduling artifact and cannot be staged deterministically
// in RTL (render flushes effects inside act()). So this pins the PROPERTY that
// removes it: on the subject it mounted with, the hook restores the draft exactly
// once — the useState initializer — and the reset effect must not repeat it.
import { renderHook, act } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import * as chatDraft from './chatDraft';
import { useChatThread } from './useChatThread';

const opts = (subject: string) => ({
  subject,
  fetchThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  sendMessage: vi.fn().mockResolvedValue({ messages: [], pending: false }),
});

beforeEach(() => {
  sessionStorage.clear();
  localStorage.clear();
  vi.restoreAllMocks();
});

describe('useChatThread draft restore (#98)', () => {
  it('restores the mount subject\'s draft once, so it cannot overwrite typing', () => {
    const load = vi.spyOn(chatDraft, 'loadChatDraft');
    renderHook(() => useChatThread(opts('inv-1')));

    // Once, from the useState initializer. A second call is the bug: it is the
    // reset effect reloading a draft the analyst may already have replaced.
    expect(load.mock.calls.filter((c) => c[0] === 'inv-1')).toHaveLength(1);
  });

  it('holds the text the analyst typed', () => {
    // DOCUMENTS the user-visible property; it does NOT guard it. RTL flushes
    // effects inside render(), so by the time this can type, the second restore
    // has already happened harmlessly — it passes against the unfixed hook too.
    // The call-count test above is the guard. Kept because it states, in the
    // language of the screen, what the guard is protecting.
    const { result } = renderHook(() => useChatThread(opts('inv-1')));

    act(() => result.current.setDraft('what datasets do I have?'));

    expect(result.current.draft).toBe('what datasets do I have?');
  });

  it('still swaps drafts when the surface moves to another subject', () => {
    // The negative control, and the reason the restore exists at all: a reused
    // drawer must never bleed one investigation's text into the next. A fix that
    // simply stopped restoring would pass both tests above and break this.
    chatDraft.saveChatDraft('inv-2', 'draft belonging to the second thread');

    const { result, rerender } = renderHook(({ s }) => useChatThread(opts(s)), {
      initialProps: { s: 'inv-1' },
    });
    act(() => result.current.setDraft('draft belonging to the first thread'));

    rerender({ s: 'inv-2' });

    expect(result.current.draft).toBe('draft belonging to the second thread');
  });

  it('leaves a subject with no saved draft empty rather than inheriting one', () => {
    const { result, rerender } = renderHook(({ s }) => useChatThread(opts(s)), {
      initialProps: { s: 'inv-1' },
    });
    act(() => result.current.setDraft('typed on the first thread'));

    rerender({ s: 'inv-3' });

    expect(result.current.draft).toBe('');
  });
});
