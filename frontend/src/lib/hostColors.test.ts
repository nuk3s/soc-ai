// Colour is the host page's fastest read: an operator scanning the network sees
// the hue before the word. So what is pinned here is the RELATIONSHIPS — which
// roles share a family, which sources must never look alike, and that every
// answer is a real class string — plus the token NAMES for the two anchors the
// design named out loud. Nothing here asserts a hex value: the palette lives in
// index.css as CSS variables and is allowed to be re-tuned without breaking a
// test that was only ever about "these two must not be confusable".
import { describe, expect, it } from 'vitest';
import { provenanceChip, provenanceTone, roleAccent, roleRail, strengthChip } from './hostColors';

/** Every role the classifier can emit (soc_ai/dossier/infer.py `_match_role`). */
const INFERRED_ROLES = [
  'hypervisor',
  'security_appliance',
  'network_device',
  'domain_controller',
  'server',
  'workstation',
];

/** The provenance ladder plus the operator lane, which is not a rung on it. */
const SOURCES = ['behaviour', 'telemetry', 'banner', 'hostlog', 'osquery', 'operator'];

describe('roleAccent', () => {
  it('gives a hypervisor the violet token the design named', () => {
    // kind-sigma IS the app's violet (tailwind.config.js / --kind-sigma). The
    // token name is the contract; its hex is not.
    expect(roleAccent('hypervisor')).toContain('kind-sigma');
  });

  it('falls back to the neutral token for a role nobody has classified', () => {
    const neutral = roleAccent(null);
    expect(neutral).toContain('border-input');
    // An unrecognised operator-declared role is the same "no colour claim" case
    // as no role at all — the host list's role filter accepts free text, so this branch is
    // reachable in production and must not throw or invent a hue.
    expect(roleAccent('coffee_machine')).toBe(neutral);
    expect(roleAccent('unknown')).toBe(neutral);
  });

  it('answers with a non-empty class string for every role the classifier emits', () => {
    for (const role of INFERRED_ROLES) {
      expect(roleAccent(role).trim().length).toBeGreaterThan(0);
      expect(roleRail(role).trim().length).toBeGreaterThan(0);
    }
  });

  it('separates the four families an operator actually triages by', () => {
    // Infrastructure that hosts other machines, boxes that serve, boxes people
    // sit at, and gear on the wire. Precision lives in the chip's TEXT; the hue
    // only has to get the family right.
    const families = [
      roleAccent('hypervisor'),
      roleAccent('server'),
      roleAccent('workstation'),
      roleAccent('network_device'),
      roleAccent(null),
    ];
    expect(new Set(families).size).toBe(families.length);
  });

  it('reads a role case- and whitespace-insensitively', () => {
    // An operator declaration is free text off a form field.
    expect(roleAccent('  Hypervisor ')).toBe(roleAccent('hypervisor'));
  });

  it('keeps the rail and the chip in the same hue', () => {
    // The hero's left rail and its role chip are one statement; a rail that
    // disagreed with the chip beside it would read as two facts.
    expect(roleRail('hypervisor')).toContain('kind-sigma');
    expect(roleRail('workstation')).toContain('mono-green');
    expect(roleAccent('workstation')).toContain('mono-green');
  });
});

describe('provenanceChip', () => {
  it('never lets a declaration look like an inference', () => {
    // The whole two-lane model collapses if "an operator said so" and "a log
    // said so" wear the same chip.
    expect(provenanceChip('operator')).not.toBe(provenanceChip('hostlog'));
    expect(provenanceChip('operator')).not.toBe(provenanceChip('behaviour'));
  });

  it('separates what the host reported from what its traffic implied', () => {
    // The ladder is a scale of DIRECTNESS (soc_ai/dossier/types.py), and that is
    // what the colour carries: inferred from behaviour vs. told to us.
    expect(provenanceChip('hostlog')).not.toBe(provenanceChip('behaviour'));
    expect(provenanceChip('osquery')).not.toBe(provenanceChip('behaviour'));
  });

  it('answers with a non-empty class string for every source, including none', () => {
    for (const source of SOURCES) {
      expect(provenanceChip(source).trim().length).toBeGreaterThan(0);
    }
    expect(provenanceChip(null).trim().length).toBeGreaterThan(0);
    // A rung added server-side lands here before the SPA knows about it; it must
    // render as the neutral chip rather than as nothing.
    expect(provenanceChip('dns')).toBe(provenanceChip(null));
  });
});

describe('provenanceTone', () => {
  it('is the chip’s own text colour, not a second opinion about it', () => {
    // The host list's KPI strip colours a NUMBER rather than a chip, and green
    // there has to mean what green means on a field card: the host itself told
    // us. Derived from provenanceChip so there is nothing to keep in step.
    for (const source of [...SOURCES, null, 'dns']) {
      const tone = provenanceTone(source);
      expect(tone.startsWith('text-')).toBe(true);
      expect(provenanceChip(source).split(' ')).toContain(tone);
    }
  });

  it('keeps the hostlog rung green and behaviour quiet', () => {
    expect(provenanceTone('hostlog')).toContain('mono-green');
    expect(provenanceTone('behaviour')).not.toContain('mono-green');
  });
});

describe('strengthChip', () => {
  it('gives each of the three strengths its own colour', () => {
    // The field card's second chip is the answer's own weight, and it was the
    // one chip on the card wearing no colour at all — so "sustained across the
    // window" and "barely cleared the floor" read identically.
    const tones = [strengthChip('strong'), strengthChip('weak'), strengthChip('none')];
    expect(new Set(tones).size).toBe(tones.length);
    for (const tone of tones) expect(tone.trim().length).toBeGreaterThan(0);
  });

  it('marks a weak answer, because weak is nearly under the floor', () => {
    // soc_ai/dossier/types.py maps strong/weak/none to 0.9/0.5/0.0 and
    // dossier_min_confidence defaults to 0.60 — so a weak answer is one that
    // only just cleared the bar that would have withheld it entirely. That is a
    // caution, and it wears the app's caution colour.
    expect(strengthChip('weak')).toContain('warn');
    expect(strengthChip('strong')).not.toContain('warn');
  });

  it('never lets a weak answer look as settled as a strong one', () => {
    expect(strengthChip('weak')).not.toBe(strengthChip('strong'));
  });

  it('never wears the same chip as the source beside it, on any rung', () => {
    // The two sit side by side on every field card, and they are ALLOWED to
    // share a hue honestly — a hostlog answer is green because the host reported
    // it, a strong answer is green because it held. Measured on the rendered
    // page, that collapsed the pair into one indistinguishable run of colour.
    // The separation is structural (filled vs. outlined), so it survives a
    // palette re-tune and a rung added server-side.
    for (const source of [...SOURCES, null, 'dns']) {
      for (const strength of ['strong', 'weak', 'none', null]) {
        expect(strengthChip(strength)).not.toBe(provenanceChip(source));
      }
    }
  });

  it('falls back to neutral rather than inventing a colour it has no word for', () => {
    // Strength is a closed three-valued vocabulary server-side, but a value read
    // back off an older row must render rather than throw.
    expect(strengthChip(null).trim().length).toBeGreaterThan(0);
    expect(strengthChip('unheard-of')).toBe(strengthChip(null));
  });
});
