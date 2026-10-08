// ---------------------------------------------------------------------------
// The open question of an unsettled verdict, when the run recorded none.
//
// Every needs more info verdict on the range read "The model needs more
// evidence to settle this verdict. The run recorded no open questions." The
// two sentences contradict each other, and the rationale above them named the
// real gap (dogfood 2026-10-06, investigation W2). This reads that gap out of
// the rationale, then the summary.
// ---------------------------------------------------------------------------

/** Words that mark a sentence as the statement of a gap. */
const GAP_WORDS =
  /\b(would|need|needs|needed|missing|lacks?|lacking|without|cannot|can't|could not|couldn't|unknown|unclear|unable|not (?:yet )?(?:confirm|known|clear|available|visible|present)|no (?:evidence|record|data|log|logs|telemetry|visibility)|whether|if the|to confirm|to rule out|to settle)\b/i;

/** The sentences of a text. Only a stop followed by a space ends a
 *  sentence, so an address or a version number stays whole. */
export function sentences(text: string): string[] {
  return text
    .split(/(?<=[.!?])\s+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

/** The first sentence of the texts that names a gap, or null. */
export function gapSentence(...texts: (string | null | undefined)[]): string | null {
  for (const text of texts) {
    if (!text) continue;
    const hit = sentences(text).find((s) => GAP_WORDS.test(s));
    if (hit) return /[.!?]$/.test(hit) ? hit : `${hit}.`;
  }
  return null;
}
