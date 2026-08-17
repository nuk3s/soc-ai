// ---------------------------------------------------------------------------
// The host page's colour language, in one place.
//
// Two facts about a host get a hue: what KIND of machine it is (its role) and
// how directly we came to believe each thing about it (its provenance). Both
// are read at a glance long before the words are, so both are mapped here once
// rather than re-decided per surface. The three places a role or a provenance is
// actually rendered — the host list's role cell, the host page's hero, and the
// twelve field cards' source chips — must not disagree about what violet means.
//
// Every value is a string of Tailwind utilities built from the app's existing
// tokens (tailwind.config.js, backed by the CSS variables in index.css). No hex
// literals: a palette re-tune happens in index.css and this file follows it for
// free. The class strings are written out in full — Tailwind's JIT scans source
// text, so a string assembled at runtime from fragments would produce classes
// that never make it into the stylesheet.
// ---------------------------------------------------------------------------

/** Border + wash + text, for anything that carries the accent: the hero panel,
 *  the role chip, a provenance chip. */
type AccentClasses = string;

// ---- roles ------------------------------------------------------------------
//
// The classifier emits six roles (soc_ai/dossier/infer.py `_match_role`) and an
// operator can declare anything at all, so this maps FAMILIES rather than one
// hue per string. Four of them, in the shape an operator triages by: kit that
// hosts other machines, kit that serves, kit people sit at, and kit on the
// wire. Precision stays in the chip's text — the hue only has to answer "what
// kind of thing is this?" from across the room.

const ROLE_FAMILY: Record<string, AccentClasses> = {
  // Violet — infrastructure that other machines live inside. The blast radius
  // of being wrong about one of these is every guest on it.
  hypervisor: 'border-kind-sigma/45 bg-kind-sigma/10 text-kind-sigma',
  // Blue, the app's "this is a host doing its job" accent. A domain controller
  // is a server with an unusually bad day when it is wrong, but it is a server.
  server: 'border-accent/45 bg-accent/10 text-accent',
  domain_controller: 'border-accent/45 bg-accent/10 text-accent',
  // Green — a box a person sits at. The one role where "a user logged in" is
  // unremarkable, which is exactly why it must not look like the ones where it
  // is not.
  workstation: 'border-mono-green/45 bg-mono-green/10 text-mono-green',
  // Cyan — appliances on the wire rather than general-purpose machines. A SIEM
  // sensor and a switch are the same kind of thing to an analyst deciding
  // whether a strange flow is the box doing its job.
  network_device: 'border-kind-notice/45 bg-kind-notice/10 text-kind-notice',
  security_appliance: 'border-kind-notice/45 bg-kind-notice/10 text-kind-notice',
};

/** Solid fill for the hero's left rail, per family — same hue as the chip. */
const ROLE_RAIL: Record<string, string> = {
  hypervisor: 'bg-kind-sigma',
  server: 'bg-accent',
  domain_controller: 'bg-accent',
  workstation: 'bg-mono-green',
  network_device: 'bg-kind-notice',
  security_appliance: 'bg-kind-notice',
};

/** No colour claim: the role is absent, still "unknown", or an operator's own
 *  word that this map has never heard of. Inventing a hue for it would assert a
 *  family the data does not support. */
const ROLE_NEUTRAL: AccentClasses = 'border-border-input bg-surface-3 text-dim';
const ROLE_RAIL_NEUTRAL = 'bg-border-strong';

/** Normalise a role for lookup. It arrives either from the classifier's closed
 *  vocabulary or from a free-text operator declaration typed into a form. */
function roleKey(role: string | null | undefined): string {
  return (role ?? '').trim().toLowerCase();
}

/** Border, wash and text colour for a host's role — the hero panel and the role
 *  chip on it. Unrecognised and absent roles both resolve to the neutral token. */
export function roleAccent(role: string | null | undefined): AccentClasses {
  return ROLE_FAMILY[roleKey(role)] ?? ROLE_NEUTRAL;
}

/** The solid left rail on the hero banner — the page's single largest piece of
 *  colour, and the thing that makes a host page recognisable at a glance. */
export function roleRail(role: string | null | undefined): string {
  return ROLE_RAIL[roleKey(role)] ?? ROLE_RAIL_NEUTRAL;
}

// ---- criticality ------------------------------------------------------------
//
// Free text (usually operator-declared), so the map is by family and an
// unrecognised word stays neutral rather than wearing a severity it has not
// earned. Danger red for the two words that mean "handle with care" — this is
// the one chip on the host page whose whole job is to be seen first.

const CRITICALITY: Record<string, AccentClasses> = {
  critical: 'border-danger/45 bg-danger/10 text-danger',
  high: 'border-danger/45 bg-danger/10 text-danger',
  medium: 'border-warn/45 bg-warn/10 text-warn',
  moderate: 'border-warn/45 bg-warn/10 text-warn',
};

const CRITICALITY_NEUTRAL: AccentClasses = 'border-border-input bg-surface-3 text-text-2';

export function criticalityAccent(value: string | null | undefined): AccentClasses {
  return CRITICALITY[(value ?? '').trim().toLowerCase()] ?? CRITICALITY_NEUTRAL;
}

// ---- provenance -------------------------------------------------------------
//
// The ladder (soc_ai/dossier/types.py PROVENANCE_LADDER) is explicitly a scale
// of DIRECTNESS, not of certainty: what the host did, leaked, announced,
// reported, then answered. That is what the colour carries here, in three steps
// plus the operator lane — which is not on the ladder at all and must never be
// confusable with anything on it, because "somebody declared this" and "we
// worked it out" are the two halves of the whole feature.

const PROVENANCE: Record<string, AccentClasses> = {
  // Blue — the operator lane. Same accent as every other "a human did this" in
  // the app, and the strongest chip on the card, because it outranks the rest.
  operator: 'border-accent/45 bg-accent/10 text-accent',
  // Neutral — we inferred it from what the host DID. Nothing said this; traffic
  // implied it. The weakest claim on the page wears the quietest chip.
  behaviour: 'border-border-input bg-surface-3 text-faint',
  // Cyan — the host emitted it without being asked: a DHCP hostname it leaked,
  // a banner it announced. Not a claim about itself so much as a side effect.
  telemetry: 'border-kind-notice/40 bg-kind-notice/[0.07] text-kind-notice',
  banner: 'border-kind-notice/40 bg-kind-notice/[0.07] text-kind-notice',
  // Green — the host itself told us, in its own logs or in answer to a query.
  // The most direct evidence short of an operator saying so.
  hostlog: 'border-mono-green/40 bg-mono-green/[0.07] text-mono-green',
  osquery: 'border-mono-green/40 bg-mono-green/[0.07] text-mono-green',
};

/** A rung the SPA has not been taught yet (the ladder is server-side and can
 *  grow) renders as the neutral chip rather than as nothing. */
const PROVENANCE_NEUTRAL: AccentClasses = 'border-border-input bg-surface-3 text-dim';

/** Border, wash and text colour for one provenance source. */
export function provenanceChip(source: string | null | undefined): AccentClasses {
  return PROVENANCE[(source ?? '').trim().toLowerCase()] ?? PROVENANCE_NEUTRAL;
}

/** Just the text colour of that chip, for a surface that colours a NUMBER
 *  rather than a chip — the host list's KPI strip, where "hosts reporting at the
 *  hostlog rung" has to be the same green a hostlog chip is on a field card.
 *
 *  Read back out of the chip rather than kept in a second map: two maps is one
 *  more thing to keep in step, and the drift would show up as one surface
 *  disagreeing with another about what green means. Every entry above carries
 *  exactly one `text-*` class, and the fallback covers a future one that does
 *  not. */
export function provenanceTone(source: string | null | undefined): string {
  return provenanceChip(source).split(' ').find((c) => c.startsWith('text-')) ?? 'text-dim';
}

// ---- strength ---------------------------------------------------------------
//
// The field card's second chip: how much weight is behind the answer, beside
// the chip saying where it came from. The two are one statement — "the host's
// own logs, and it held all week" is a different sentence from "the host's own
// logs, once" — so the second half cannot be the one chip on the card wearing
// no colour.
//
// The scale is not arbitrary. soc_ai/dossier/types.py maps strong/weak/none to
// 0.9/0.5/0.0 and `dossier_min_confidence` defaults to 0.60, which puts a WEAK
// answer within a whisker of the floor that withholds a field entirely. That
// proximity is the thing worth showing: it is the difference between a value a
// reader can act on and one the sweep nearly declined to assert.

// These are OUTLINE chips — border and text, no wash — and that is the load-
// bearing part, not the hues. Strength and provenance can land on the same
// colour honestly (a hostlog answer is green because the host reported it; a
// strong answer is green because it held), and a filled green chip beside an
// identical filled green chip is one indistinguishable run of colour rather
// than the pair the mockup drew. Filled = where it came from, outlined = how
// much is behind it, at every hue and for every rung added later.

const STRENGTH: Record<string, AccentClasses> = {
  // Green — sustained: seen from several peers over several hours, or reported
  // by the machine itself. The app's settled colour.
  strong: 'border-mono-green/50 text-mono-green',
  // Amber — this cleared the floor and not much else. Deliberately the app's
  // caution colour rather than a quieter neutral: a weak answer is the one an
  // operator most wants to know they are about to act on.
  weak: 'border-warn/50 text-warn',
  // No weight at all behind a value that nonetheless stands — reachable only
  // with the floor turned down. Nothing to claim, so no colour claimed.
  none: 'border-border-input text-faint',
};

/** A strength the SPA has not been taught. Strength is a closed three-valued
 *  vocabulary server-side, but a row written by an older schema must render
 *  rather than throw — and must not borrow a colour it has not earned. */
const STRENGTH_NEUTRAL: AccentClasses = 'border-border-input text-dim';

/** Border, wash and text colour for one answer's strength. */
export function strengthChip(strength: string | null | undefined): AccentClasses {
  return STRENGTH[(strength ?? '').trim().toLowerCase()] ?? STRENGTH_NEUTRAL;
}
