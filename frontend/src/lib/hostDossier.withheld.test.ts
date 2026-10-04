// The words a withheld guess and a removed declaration wear (dogfood
// 2026-10-01: H1, H7, RO4, RO7, RO16). Every unknown row wore "possibly" with
// a tooltip that claimed an inference, and the remove button promised that the
// sweep's answer "then stands" over a 0.50 guess.
import { describe, expect, it } from 'vitest';
import type { DossierField, DossierFieldBrief } from './types';
import { removeOutcome, unresolvedPhrase, valueText, withheldGuess, withheldPhrase } from './hostDossier';

const DAY = 86_400_000;

const brief = (over: Partial<DossierFieldBrief>): DossierFieldBrief => ({
  field: 'role',
  value: null,
  value_json: null,
  source: null,
  confidence: 0,
  strength: 'none',
  reason: 'no_signal',
  overridden: false,
  conflict_kind: null,
  ...over,
});

const declared = (over: Partial<DossierField>): DossierField => ({
  ...brief({ value: 'hypervisor', source: 'operator', reason: null, overridden: true }),
  evidence: {},
  observed_at: null,
  first_seen: null,
  last_run_at: null,
  retracted_at: null,
  operator_actor: 'admin',
  operator_note: null,
  operator_set_at: null,
  inferred_value: 'server',
  inferred_value_json: null,
  inferred_confidence: 0.5,
  inferred_source: 'behaviour',
  conflict: null,
  ...over,
});

describe('withheldGuess', () => {
  it('names a fresh guess below the gate as low confidence', () => {
    const g = withheldGuess(brief({ reason: 'low_confidence', inferred_value: 'domain_controller' }));
    expect(g).toEqual({ state: 'low_confidence', value: 'domain_controller', age: null });
    expect(withheldPhrase(g!)).toBe('domain controller · low confidence');
  });

  it('names a stale guess as stale, with the age', () => {
    const now = Date.parse('2026-10-01T12:00:00Z');
    const g = withheldGuess(
      brief({ reason: 'stale', inferred_value: 'server', last_run_at: '2026-09-23T12:00:00Z' }),
      now,
    );
    expect(g?.state).toBe('stale');
    expect(withheldPhrase(g!)).toBe('server · stale 8d ago');
  });

  it('names no guess for the classifier’s "unknown", an empty lane or a declaration', () => {
    expect(withheldGuess(brief({ reason: 'stale', inferred_value: 'unknown' }))).toBeNull();
    expect(withheldGuess(brief({ reason: 'low_confidence', inferred_value: 'Unknown' }))).toBeNull();
    expect(withheldGuess(brief({ reason: 'stale', inferred_value: null }))).toBeNull();
    expect(withheldGuess(brief({ reason: 'no_signal', inferred_value: 'server' }))).toBeNull();
    expect(
      withheldGuess(brief({ reason: 'low_confidence', inferred_value: 'server', overridden: true })),
    ).toBeNull();
  });
});

describe('removeOutcome', () => {
  it('says a thin guess shows as a low-confidence guess, with the label', () => {
    const text = removeOutcome(declared({ inference_reason: 'low_confidence' }));
    expect(text).toBe(
      "Remove my declaration. The sweep's answer, server at 0.50, then shows as a low-confidence guess.",
    );
  });

  it('says a strong answer stands, and uses the label, never the slug', () => {
    const text = removeOutcome(
      declared({ inferred_value: 'domain_controller', inferred_confidence: 0.9, inference_reason: null }),
    );
    expect(text).toContain('domain controller at 0.90, then stands');
    expect(text).not.toContain('domain_controller');
  });

  it('says a stale answer shows as a stale guess', () => {
    expect(removeOutcome(declared({ inference_reason: 'stale' }))).toContain('stale guess');
  });

  it('says the field goes back to unknown when nothing, or "unknown", is underneath', () => {
    const unknown = 'Remove my declaration. This field then goes back to unknown.';
    expect(removeOutcome(declared({ inferred_value: null, inference_reason: 'no_signal' }))).toBe(unknown);
    expect(removeOutcome(declared({ inferred_value: 'unknown', inference_reason: null }))).toBe(unknown);
  });
});

describe('the reading forms', () => {
  it('renders a port payload as ports, never as JSON', () => {
    const text = valueText('services_offered', null, [
      { port: 389, proto: 'tcp', count: 12 },
      { port: 53, proto: 'udp', count: 4 },
    ]);
    expect(text).toBe('tcp/389, udp/53');
  });

  it('says low confidence and stale in the unknown line, never "possibly"', () => {
    expect(unresolvedPhrase({ reason: 'low_confidence', last_run_at: null, retracted_at: null, inferred_value: 'CORP' })).toBe(
      'low confidence: "CORP". The evidence is too thin to say',
    );
    const stale = unresolvedPhrase({
      reason: 'stale',
      last_run_at: new Date(Date.now() - 8 * DAY).toISOString(),
      retracted_at: null,
    });
    expect(stale).toMatch(/^stale\. The sweep last checked it 8d ago/);
  });
});
