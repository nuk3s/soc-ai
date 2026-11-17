// A gate that changes a verdict (B2, review 2026-11-12, console finding 1).
// The largest text of run 01M6WEC0CG156GP1YX38YEAKV5 was "soc-ai changed the
// verdict from a true positive to needs more info", and Open questions held
// that sentence as its one bullet. The headline is the sentence of the model
// now. The change is one labeled line under it, and Open questions lists the
// missing evidence.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { Investigation as Inv } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getChatThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getMe: vi.fn().mockResolvedValue({ username: 'analyst' }),
  getAbout: vi.fn().mockResolvedValue({}),
}));

import { Investigation } from './Investigation';

const HEADLINE = 'Host ws-1 opened a TLS session to a developer domain';
const MISSING = [
  'A blocklist or MISP entry that matches an indicator.',
  'A record of the host with content of the event that the report cites by its id.',
];
const NOTE = 'soc-ai changed the verdict from a true positive to needs more info. No blocklist or MISP entry matches an indicator.';

const inv = (over: Partial<Inv>): Inv =>
  ({
    id: 'INV-1',
    groupId: 'ev-1',
    name: 'ET INFO Observed Developer Domain',
    kind: 'suricata',
    host: '192.0.2.1',
    ip: '—',
    verdict: 'needs_more_info',
    conf: 0.5,
    rationale: HEADLINE,
    summary: [{ t: 'text', v: `${HEADLINE}. Two sandbox reports flag the URL.` }],
    status: 'complete',
    elapsedLabel: '4m',
    actions: [],
    timeline: [],
    nodes: [],
    edges: [],
    seedChat: [],
    openQuestions: MISSING,
    validatorNote: NOTE,
    verdictChange: {
      gate: 'ungrounded_host_anchored_tp_downgrade',
      fromVerdict: 'true_positive',
      toVerdict: 'needs_more_info',
      reason: 'The run found no direct evidence of an attack beyond the alert history of the host.',
      missing: MISSING,
    },
    ...over,
  }) as Inv;

const mount = (i: Inv) =>
  render(
    <MemoryRouter>
      <Investigation inv={i} layout="page" />
    </MemoryRouter>,
  );

describe('the verdict change of a gate', () => {
  it('prints one labeled line under the headline of the model', () => {
    const { container } = mount(inv({}));
    const line = screen.getByTestId('gate-line');
    expect(line.textContent).toBe(
      'Verdict change: soc-ai changed the verdict from true positive to needs more info. ' +
        'The run found no direct evidence of an attack beyond the alert history of the host.',
    );
    // The headline is the sentence of the model, and it comes before the line.
    const text = container.textContent ?? '';
    expect(text.indexOf(HEADLINE)).toBeGreaterThanOrEqual(0);
    expect(text.indexOf(HEADLINE)).toBeLessThan(text.indexOf('Verdict change:'));
  });

  it('lists the missing evidence in Open questions', () => {
    mount(inv({}));
    for (const item of MISSING) expect(screen.getByText(item)).toBeTruthy();
    expect(screen.queryByTestId('open-question-gap')).toBeNull();
  });

  it('states the change one time: the note block does not repeat it', () => {
    const { container } = mount(inv({}));
    expect(container.textContent).not.toContain('Verdict check');
    expect((container.textContent ?? '').split('soc-ai changed the verdict').length - 1).toBe(1);
  });

  it('lists the missing evidence on a finding run', () => {
    mount(inv({ kind: 'hunt', huntId: '01HUNT0000000000000000000' }));
    expect(screen.getByTestId('gate-line')).toBeTruthy();
    for (const item of MISSING) expect(screen.getByText(item)).toBeTruthy();
  });

  it('control: a lowered run prints the model text one time, with no second label', () => {
    mount(inv({}));
    expect(screen.queryByTestId('model-wrote')).toBeNull();
  });

  it('control: a run with no gate change has no line and keeps its note', () => {
    const { container } = mount(inv({ verdictChange: null, validatorNote: 'A validator wrote this note.' }));
    expect(screen.queryByTestId('gate-line')).toBeNull();
    // K3: the note reads under a plain label.
    expect(container.textContent).toContain('Verdict check');
    expect(container.textContent).toContain('A validator wrote this note.');
  });

  it('control: a pipeline error shows no gate line', () => {
    mount(
      inv({
        fallback: { phase: 'synth_first_round1', errorType: 'ModelHTTPError', hint: null } as Inv['fallback'],
      }),
    );
    expect(screen.queryByTestId('gate-line')).toBeNull();
  });
});

// A gate that refutes the claim of the model. The final verdict is a false
// positive, so a headline of the model that states C2 contradicts the chip
// beside it. The headline is the reason of the gate, and the text of the
// model stays on the page under its own label.
describe('a refuted claim', () => {
  const REASON =
    'The traffic is an echo request and its reply between two internal hosts. ' +
    'No blocklist or MISP entry matches an endpoint. The rule matched packet content only.';
  const GATE_HEADLINE = 'The traffic is an echo request and its reply between two internal hosts';
  const MODEL = 'BPFDoor ICMP heartbeat confirms a C2 tunnel. Escalate the host.';
  const refuted = (over: Partial<Inv> = {}): Inv =>
    inv({
      verdict: 'false_positive',
      conf: 0.8,
      rationale: GATE_HEADLINE,
      summary: [{ t: 'text', v: REASON }],
      modelText: MODEL,
      openQuestions: [],
      validatorNote: `soc-ai changed the verdict from a true positive to a false positive. ${REASON}`,
      verdictChange: {
        gate: 'icmp_solicited_downgrade',
        fromVerdict: 'true_positive',
        toVerdict: 'false_positive',
        reason: REASON,
        missing: [],
      },
      ...over,
    });

  it('shows the reason of the gate as the headline, before the text of the model', () => {
    const { container } = mount(refuted());
    const text = container.textContent ?? '';
    expect(text.indexOf(GATE_HEADLINE)).toBeGreaterThanOrEqual(0);
    expect(text.indexOf(GATE_HEADLINE)).toBeLessThan(text.indexOf('BPFDoor ICMP heartbeat'));
  });

  it('keeps the text of the model under its own label', () => {
    mount(refuted());
    expect(screen.getByTestId('model-wrote').textContent).toBe(`The model wrote: ${MODEL}`);
  });

  it('prints the text of the model one time, inside that label only', () => {
    const { container } = mount(refuted());
    const text = container.textContent ?? '';
    expect(text.split('BPFDoor ICMP heartbeat').length - 1).toBe(1);
    expect(screen.getByTestId('model-wrote').textContent).toContain('BPFDoor ICMP heartbeat');
  });

  it('states the change in one line and does not repeat the reason there', () => {
    mount(refuted());
    expect(screen.getByTestId('gate-line').textContent).toBe(
      'Verdict change: soc-ai changed the verdict from true positive to false positive.',
    );
  });

  it('control: an analyst verdict hides the label with the gate line', () => {
    mount(
      refuted({
        resolution: {
          resolved_via: 'manual',
          resolved_by: 'analyst',
          original_verdict: 'false_positive',
        } as Inv['resolution'],
      }),
    );
    expect(screen.queryByTestId('gate-line')).toBeNull();
    expect(screen.queryByTestId('model-wrote')).toBeNull();
  });
});

