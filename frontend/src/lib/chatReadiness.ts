import { useEffect, useState } from 'react';
import { type Health, type HealthComponent, getHealth } from './api';

// ---------------------------------------------------------------------------
// Can a chat question work now?
//
// With the model gateway and the grid both down, the chat panel and the
// Dashboard Ask card offered their starter questions and a Send button with
// no word about the state. The send failed after the turn started (dogfood
// 2026-10-19, H1-D13). A chat answer needs the model, so a dead gateway
// blocks the send and says why. A chat answer can still read the store
// while the grid is down, so a dead grid only gets a note.
//
// The read is shared: every chat surface on a page reads one /health answer
// per HEALTH_TTL_MS.
// ---------------------------------------------------------------------------

const HEALTH_TTL_MS = 15_000;
const HEALTH_POLL_MS = 30_000;

let cached: { at: number; value: Health | null } | null = null;
let inflight: Promise<Health | null> | null = null;

/** For tests: forget the shared answer. */
export function resetSharedHealth(): void {
  cached = null;
  inflight = null;
}

/** The /health answer, shared by every caller for HEALTH_TTL_MS. A failed
 *  read is null: it says nothing about the dependencies. */
export function readSharedHealth(now = Date.now()): Promise<Health | null> {
  if (cached && now - cached.at < HEALTH_TTL_MS) return Promise.resolve(cached.value);
  if (inflight) return inflight;
  inflight = getHealth()
    .then(
      (h) => h,
      () => null,
    )
    .then((value) => {
      cached = { at: Date.now(), value };
      inflight = null;
      return value;
    });
  return inflight;
}

/** The shared /health answer, read on mount and every HEALTH_POLL_MS. */
export function useSharedHealth(): Health | null {
  const [health, setHealth] = useState<Health | null>(cached?.value ?? null);
  useEffect(() => {
    let live = true;
    const read = () => {
      void readSharedHealth().then((h) => {
        if (live) setHealth(h);
      });
    };
    read();
    const t = setInterval(read, HEALTH_POLL_MS);
    return () => {
      live = false;
      clearInterval(t);
    };
  }, []);
  return health;
}

export interface ChatReadiness {
  /** Why a send cannot work now. The send control is off while it is set. */
  blocked: string | null;
  /** A state the answer depends on, said beside a send that can work. */
  note: string | null;
}

function kindOf(c: HealthComponent): string {
  const kind = (c as HealthComponent & { kind?: unknown }).kind;
  return typeof kind === 'string' ? kind : '';
}

/** What the chat surfaces say about the model gateway and the grid. */
export function chatReadiness(h: Health | null): ChatReadiness {
  if (!h) return { blocked: null, note: null };
  const notes: string[] = [];
  let blocked: string | null = null;
  if (h.llm && !h.llm.ok) {
    if (kindOf(h.llm) === 'slow') {
      notes.push('The model gateway is slow. An answer can take longer.');
    } else {
      blocked = 'The model gateway does not answer. soc-ai cannot answer a question until the gateway answers.';
    }
  }
  if (h.es && !h.es.ok) {
    notes.push(
      kindOf(h.es) === 'slow'
        ? 'The grid is slow. A query in the answer can take longer.'
        : 'The grid does not answer. An answer can use only the records soc-ai stores.',
    );
  }
  return { blocked, note: notes.length ? notes.join(' ') : null };
}

/** The chat readiness of the current page, from the shared /health read. */
export function useChatReadiness(): ChatReadiness {
  return chatReadiness(useSharedHealth());
}
