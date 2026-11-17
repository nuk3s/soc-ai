// ---------------------------------------------------------------------------
// The cause of a failed run, in plain words.
//
// The failed-run card opened with the raw error: "Recorded cause:
// status_code: 500, model_name: ..., ssl.SSLContext object at 0x75b7..."
// (review 2026-11-12, console finding 14). The card now leads with one
// sentence for the class of the cause, then the step the analyst can take.
// The raw error sits behind a toggle. The server sends the class, from the
// classifier of the nightly snapshot.
// ---------------------------------------------------------------------------

export type FailureKind = 'gateway' | 'token_limit' | 'time_limit' | 'grid' | 'other';

const CAUSE: Record<FailureKind, string> = {
  gateway: 'The model gateway did not answer. The investigation has no verdict.',
  token_limit: 'The model hit its output limit before it wrote a verdict.',
  time_limit: 'The investigation hit its time limit before it reached a verdict.',
  grid: 'The grid did not answer. The investigation has no verdict.',
  other: 'The investigation stopped on an error before it reached a verdict.',
};

const ACTION: Record<FailureKind, string> = {
  gateway: 'Re-run it when the gateway answers again.',
  token_limit: 'Re-run it to try again.',
  time_limit: 'Re-run it to try again.',
  grid: 'Re-run it when the grid answers again.',
  other: 'Re-run it to try again.',
};

/** The class of a recorded failure. An unknown or absent class is `other`. */
export function failureKind(failure: { kind?: string | null } | null | undefined): FailureKind {
  const k = failure?.kind;
  return k === 'gateway' || k === 'token_limit' || k === 'time_limit' || k === 'grid' ? k : 'other';
}

/** The plain cause sentence of a failure class. */
export function failureCause(kind: FailureKind): string {
  return CAUSE[kind];
}

/** What the analyst can do about a failure class, on a run that has Re-run. */
export function failureAction(kind: FailureKind): string {
  return ACTION[kind];
}

/** A stored hint starts with a lower-case word ("the LLM gateway could not
 *  ..."). The card prints it as a sentence. */
export function asSentence(text: string): string {
  const t = text.trim();
  return t ? t.charAt(0).toUpperCase() + t.slice(1) : t;
}
