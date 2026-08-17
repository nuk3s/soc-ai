import { useEffect, useRef, useState } from 'react';
import { clearChatDraft, loadChatDraft, saveChatDraft } from './chatDraft';
import type { ChatThread } from './api';
import type { ChatMessage } from './types';

// The soc-ai chat surfaces (investigation follow-up, Dashboard general chat,
// and eventually the hunt console) all speak the same transport: GET the
// thread, POST a message, poll while the backend runs the turn in the
// background. Forking that slice per screen is what left the hunt chat without
// tool progress, without the grounding loop, and without draft persistence —
// it drifted because it was a copy, not a caller. This hook is the one
// implementation; a surface joins by calling it.
//
// HuntDetail's HuntChatPanel is still its own copy. Retrofitting it is a caller
// change plus one type fix: `HuntChatMessage.tools` is `string | null` where
// `ChatMessage.tools` is `string | undefined`, so the hunt thread isn't
// assignable to this hook's `ChatThread` until that null goes.

/** How long between polls of an in-flight turn. */
const POLL_MS = 1500;

/** Shown as an assistant bubble when the transport itself fails. */
const NET_ERR_TEXT = 'Could not reach the server — please try again.';

/** Stable empty seed — a fresh array per render would say nothing new. */
const NO_MESSAGES: ChatMessage[] = [];

export interface UseChatThreadOptions {
  /**
   * What the thread is about, and the id its endpoints are scoped to — an
   * investigation id for the investigation chat, a constant thread key for a
   * surface that has no subject (the Dashboard general chat is one rolling
   * per-user thread). It doubles as the draft key and as the identity the
   * stale-response guard compares against, so it must change exactly when the
   * conversation does.
   */
  subject: string;
  /** GET the thread. A surface whose endpoint takes no id may ignore `subject`. */
  fetchThread: (subject: string) => Promise<ChatThread>;
  /** POST a message and return the updated thread (usually still `pending`). */
  sendMessage: (subject: string, text: string) => Promise<ChatThread>;
  /**
   * Messages the screen already has (the investigation's `seedChat`). Rendered
   * until the mount fetch has something better; a screen without one omits it.
   */
  seed?: ChatMessage[];
}

export interface ChatThreadState {
  messages: ChatMessage[];
  /** A turn is running: show the typing indicator and refuse a second send. */
  pending: boolean;
  /** Tools the in-flight turn has called so far (empty while idle). */
  progressTools: string[];
  draft: string;
  setDraft: (text: string) => void;
  /** Send the trimmed draft. No-op on an empty draft or while `pending`. */
  send: () => void;
  /**
   * Re-read the thread and apply it — for a screen action that changes the
   * thread server-side (applying a chat verdict proposal). Rejects on a
   * transport failure so the caller can decide; unlike the poll it adds no
   * error bubble.
   */
  refresh: () => Promise<void>;
}

/**
 * The chat transport slice: mount fetch, pending-only poll, send, and draft.
 *
 * Rendering stays in the screen — this returns state and actions, never JSX,
 * so surfaces that look nothing alike (a drawer panel, a floating dock, a
 * dashboard card) can share one transport.
 *
 * The poll re-arms ONLY while a turn is pending. That is the property that
 * makes an always-resident chat affordable: an idle thread costs exactly one
 * GET on mount, not a heartbeat for as long as the tab is open.
 */
export function useChatThread({
  subject,
  fetchThread,
  sendMessage,
  seed = NO_MESSAGES,
}: UseChatThreadOptions): ChatThreadState {
  const [messages, setMessages] = useState<ChatMessage[]>(seed);
  const [pending, setPending] = useState(false);
  const [progressTools, setProgressTools] = useState<string[]>([]);
  // Restore any draft saved before this surface last unmounted (drawer close,
  // or navigating off the Dashboard and back).
  const [draft, setDraft] = useState(() => loadChatDraft(subject));

  const pollTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  // False once the surface has unmounted. Guards the poll continuations: an
  // in-flight send/fetch that resolves after unmount must not re-arm pollTimer
  // (a detached loop nothing would ever clear) or setState.
  const aliveRef = useRef(true);
  // The subject the current `draft` belongs to. Lets the persist effect skip
  // the render where `subject` just changed (draft still holds the PREVIOUS
  // subject's text then) so it can't clobber the new subject's stored draft.
  const draftSubjectRef = useRef(subject);
  // The subject whose saved draft has already been restored. Seeded with the
  // mount subject because `useState` above did that restore, so the reset
  // effect must not repeat it and overwrite what the analyst has since typed.
  const restoredDraftFor = useRef(subject);
  // The subject this hook is CURRENTLY on. An in-flight request closes over the
  // subject it was fired for; applyThread compares against this ref so a
  // response that lands after the screen has moved on (an investigation re-hunt
  // before the reply arrives) is dropped instead of clobbering the new thread.
  const currentSubjectRef = useRef(subject);
  // Latest endpoints. The effects below are keyed on `subject` alone, so
  // without this a caller that builds its endpoints inline (a closure over its
  // own state — likely for a surface with no id) would be polled through a
  // stale closure for the life of the thread.
  const fetchRef = useRef(fetchThread);
  const sendRef = useRef(sendMessage);
  // Declared FIRST so every effect below runs against this commit's endpoints.
  useEffect(() => {
    fetchRef.current = fetchThread;
    sendRef.current = sendMessage;
  });

  // Persist the draft so it survives the surface unmounting. Skip the render
  // where `subject` JUST changed: at that point `draft` still holds the
  // PREVIOUS subject's text (the reset effect below hasn't reloaded it yet),
  // and since this effect runs before that one, persisting here would clobber
  // the new subject's stored draft — bleeding the old text into it.
  useEffect(() => {
    if (draftSubjectRef.current !== subject) {
      draftSubjectRef.current = subject;
      return;
    }
    saveChatDraft(subject, draft);
  }, [subject, draft]);

  // Reset transient state only when the subject changes (the drawer is reused
  // across investigations) — never on a re-render of the same conversation.
  useEffect(() => {
    currentSubjectRef.current = subject;
    setMessages(seed);
    setPending(false);
    // Restore this subject's saved draft (a reused surface must not bleed the
    // previous conversation's text through) — but ONLY on a real subject
    // change. The initial draft is already loaded by useState above, so on
    // mount this reload is a no-op in the happy case and destructive in the
    // racy one: between the composer becoming visible and this effect flushing,
    // an analyst can already have typed, and reloading then silently replaces
    // their text with the stored (usually empty) draft. `send` bails on an
    // empty draft WITHOUT surfacing anything, so the symptom is a Send button
    // that does nothing at all — no request, no error, no text.
    //
    // That is the whole of task #98: it read as a flaky test ("the reply never
    // appears") and was twice mistaken for a slow-reply race, but the reply
    // never appeared because the send never happened. Probed under load: at
    // failure the composer was still mounted, the user's own message was
    // absent, and postGeneralChat had been called ZERO times.
    if (restoredDraftFor.current !== subject) {
      restoredDraftFor.current = subject;
      setDraft(loadChatDraft(subject));
    }
    if (pollTimer.current) clearTimeout(pollTimer.current);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [subject]);

  // Re-sync from the server on mount / subject change. `seed` is a one-shot
  // snapshot: a reply that completed while this surface was unmounted exists
  // only in the DB, and the poll loop is armed by send() — so without this
  // fetch the reply never appears until the user types (dogfood 2026-08-05).
  // applyThread restores `pending` (re-arming the typing indicator and the poll
  // for an in-flight turn) and is guarded against stale responses. Declared
  // AFTER the reset effect above so its result lands on the reset state, not
  // under it.
  useEffect(() => {
    fetchRef
      .current(subject)
      .then((t) => {
        // An empty, idle thread adds nothing over the seed — applying it would
        // blank a freshly-seeded conversation. Sync only when the server has
        // messages or an in-flight turn to restore.
        if (t.messages.length > 0 || t.pending) applyThread(t);
      })
      .catch(() => undefined); // the seed already rendered — a failed sync is cosmetic
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [subject]);

  // Stop any poll when the surface unmounts.
  useEffect(() => {
    aliveRef.current = true;
    return () => {
      aliveRef.current = false;
      if (pollTimer.current) clearTimeout(pollTimer.current);
    };
  }, []);

  // Apply a thread from the API; keep polling while the assistant works. The
  // pending assistant turn comes back with empty text — drop it and let the
  // typing indicator stand in until the real reply lands.
  const applyThread = (thread: ChatThread) => {
    // This closure was created for whichever subject was current when the
    // request fired. If the screen has since moved to another one, applying it
    // would clobber that conversation — drop it.
    if (!aliveRef.current) return; // unmounted mid-flight — don't re-arm the poll
    if (currentSubjectRef.current !== subject) return;
    setMessages(thread.messages.filter((m) => m.text || m.role === 'user'));
    setPending(thread.pending);
    // Live tool progress for the in-flight turn — the poll already carries it,
    // so a long turn reads as work-in-progress instead of a hung typing
    // indicator (dogfood 2026-08-06).
    setProgressTools(thread.pending ? (thread.progress_tools ?? []) : []);
    if (pollTimer.current) clearTimeout(pollTimer.current);
    if (thread.pending) {
      pollTimer.current = setTimeout(() => {
        fetchRef.current(subject).then(applyThread).catch(() => {
          if (!aliveRef.current || currentSubjectRef.current !== subject) return;
          setPending(false);
          // Only push the error message if the last message isn't already it
          // (repeated poll failures must not stack duplicate error bubbles).
          setMessages((c) => {
            const last = c[c.length - 1];
            if (last?.role === 'assistant' && last.text === NET_ERR_TEXT) return c;
            return [...c, { role: 'assistant', text: NET_ERR_TEXT }];
          });
        });
      }, POLL_MS);
    }
  };

  const send = () => {
    const t = draft.trim();
    // Block double-submit while a turn is in flight — the backend answers one
    // turn per thread and would 409 the second.
    if (!t || pending) return;
    setMessages((c) => [...c, { role: 'user', text: t }]);
    setDraft('');
    clearChatDraft(subject); // sent — drop the persisted draft
    setPending(true);
    sendRef.current(subject, t).then(applyThread).catch(() => {
      if (currentSubjectRef.current !== subject) return; // screen moved on — don't clobber the new thread
      setPending(false);
      setMessages((c) => [...c, { role: 'assistant', text: NET_ERR_TEXT }]);
    });
  };

  const refresh = () => fetchRef.current(subject).then(applyThread);

  return { messages, pending, progressTools, draft, setDraft, send, refresh };
}
