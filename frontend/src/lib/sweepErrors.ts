// What a background run could not read, off the run's own record.
//
// Two long-running jobs report the same way — the network sweep
// (`GET /dossiers/refresh`) and the discovery scan (`GET /discovery/scan`) —
// and three screens now speak for one or the other. They read the list
// identically, so they read it from here: the Hosts list, the Config
// identifiers section and the host page each carried their own copy of this
// four-line guard (deliberately, while lib/ belonged to an in-flight branch),
// and three copies of a rule about how to tell trouble from calm is two too
// many.

/**
 * The `errors` list off a run's `last_summary`, read defensively.
 *
 * The wire type is `Record<string, unknown>` — the summary is a dataclass
 * dumped whole — and both routes also write a bare `{"errors": [...]}` when the
 * background task died before producing one. Anything that is not a list of
 * strings reads as no errors: an unrecognised shape is not evidence of trouble.
 *
 * `errors` ONLY. DossierSummary and DiscoverySummary both keep advisory notes in
 * a separate field on purpose: a healthy run that hit a cap or a cadence ceiling
 * must not paint a degraded badge every night, because that is how an operator
 * learns to stop reading the badge. Counts are not a signal either — a sweep
 * that rebuilt nothing on a settled estate, or a scan that found no new suffixes
 * on a settled network, is a correct run.
 */
export function sweepErrorList(summary: Record<string, unknown> | null | undefined): string[] {
  const raw = summary?.['errors'];
  return Array.isArray(raw) ? raw.filter((e): e is string => typeof e === 'string') : [];
}

/** How many error strings a degraded note prints before it starts counting. */
export const SHOWN_ERRORS = 2;
