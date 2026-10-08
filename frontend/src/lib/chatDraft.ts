// Persist the in-progress chat draft for one chat scope so it survives the
// Ask soc-ai panel closing, a scope switch and a reload, without lifting state
// into a parent. Keyed on the scope key ("general", "host:<ip>",
// "investigation:<id>" and so on) and stored in sessionStorage, so it lives for
// the tab session and never leaks across scopes or to disk.

const KEY = (invId: string) => `soc-ai:chat-draft:${invId}`;

/** Read the saved draft for an investigation (empty string if none / unavailable). */
export function loadChatDraft(invId: string): string {
  if (!invId) return '';
  try {
    return sessionStorage.getItem(KEY(invId)) ?? '';
  } catch {
    // sessionStorage can throw (private mode / disabled) — degrade to no draft.
    return '';
  }
}

/** Save (or clear, when text is empty) the draft for an investigation. */
export function saveChatDraft(invId: string, text: string): void {
  if (!invId) return;
  try {
    if (text) sessionStorage.setItem(KEY(invId), text);
    else sessionStorage.removeItem(KEY(invId));
  } catch {
    /* best-effort — a lost draft on a storage failure is acceptable. */
  }
}

/** Drop the saved draft for an investigation (called once the message is sent). */
export function clearChatDraft(invId: string): void {
  saveChatDraft(invId, '');
}
