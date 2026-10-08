// The flow strip: one line under the page header that names where the object
// sits in the flow (owner, 2026-10-07: "What is the user flow?").
//
// These tests pin the state of each step from the object's real data, the
// control the next step names, the links of the done steps, and the negative
// control: a failed run names Re-run and never reads its verdict as done.
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import type { LeadDetail } from '../lib/api';
import {
  type FlowHunt,
  type FlowStep,
  findingInvestigation,
  huntFlow,
  investigationFlow,
  leadFlow,
} from '../lib/flowSteps';
import type { HuntFinding, Investigation, RecommendedAction } from '../lib/types';
import { FlowStrip } from './FlowStrip';

function mount(steps: FlowStep[]) {
  return render(
    <MemoryRouter>
      <FlowStrip steps={steps} />
    </MemoryRouter>,
  );
}

/** "key:state" for every step, in order. */
const shape = (steps: FlowStep[]) => steps.map((s) => `${s.key}:${s.state}`);
const step = (steps: FlowStep[], key: string) => {
  const s = steps.find((x) => x.key === key);
  if (!s) throw new Error(`no step ${key}`);
  return s;
};

// ── fixtures ────────────────────────────────────────────────────────────────

type LeadFields = Pick<
  LeadDetail,
  'status' | 'hunt_id' | 'hunt_status' | 'hunt_queued' | 'investigation_id' | 'dismissed_reason'
>;

const NEW_LEAD: LeadFields = {
  status: 'open',
  hunt_id: null,
  hunt_status: null,
  hunt_queued: false,
  investigation_id: null,
  dismissed_reason: null,
};

const HUNTED_LEAD: LeadFields = { ...NEW_LEAD, hunt_id: 'H-1', hunt_status: 'complete' };

const threat = (over: Partial<HuntFinding> & Record<string, unknown> = {}): HuntFinding =>
  ({
    title: 'Beaconing to a rare external address',
    detail: 'd',
    severity: 'high',
    category: 'threat',
    hosts: ['10.0.0.5'],
    citations: ['doc-1'],
    ...over,
  }) as HuntFinding;

function hunt(over: Partial<FlowHunt> = {}): FlowHunt {
  return {
    id: 'H-1',
    objective: '[lead 12] Investigate 10.0.0.5.',
    kind: 'lead',
    status: 'complete',
    narrative: 'n',
    findings: [],
    affectedHosts: [],
    mitreTechniques: [],
    recommendedActions: [],
    confidence: 0.8,
    startedBy: 'auto-hunt',
    elapsedLabel: '2m',
    elapsedSec: 120,
    ts: '2026-10-07T09:00:00Z',
    timeline: [],
    ...over,
  } as FlowHunt;
}

const action = (over: Partial<RecommendedAction> = {}): RecommendedAction => ({
  id: 'a1',
  title: 'Acknowledge the alert',
  tag: 'ack',
  rationale: 'r',
  ...over,
});

function inv(over: Partial<Investigation> = {}): Investigation {
  return {
    id: 'INV-1',
    groupId: 'g',
    name: 'ET POLICY curl user agent',
    kind: 'suricata',
    host: '10.0.0.5',
    ip: '203.0.113.9',
    verdict: 'false_positive',
    conf: 0.9,
    rationale: 'r',
    summary: [],
    status: 'complete',
    elapsedLabel: '1m',
    actions: [],
    timeline: [],
    nodes: [],
    edges: [],
    seedChat: [],
    ...over,
  } as Investigation;
}

// ── the strip itself ────────────────────────────────────────────────────────

describe('FlowStrip', () => {
  it('marks the current step, links a done step and names the next control', () => {
    mount(leadFlow(HUNTED_LEAD, hunt({ findings: [threat()] })));
    const strip = screen.getByTestId('flow-strip');
    expect(strip.tagName).toBe('NAV');
    const lead = screen.getByTestId('flow-step-lead');
    expect(lead.getAttribute('aria-current')).toBe('step');
    expect(lead.dataset.state).toBe('current');
    const huntStep = screen.getByTestId('flow-step-hunt');
    expect(huntStep.dataset.state).toBe('done');
    expect(within(huntStep).getByRole('link', { name: 'Hunt' }).getAttribute('href')).toBe(
      '/hunts/H-1',
    );
    // An older server: no investigation phase, so the analyst opens one.
    expect(screen.getByTestId('flow-control-investigations').textContent).toBe(
      '· Open an investigation',
    );
    // Exactly one current step and at most one next step.
    expect(strip.querySelectorAll('[data-state="current"]')).toHaveLength(1);
    expect(strip.querySelectorAll('[data-state="next"]')).toHaveLength(1);
  });

  it('wraps on a narrow window and never cuts a word', () => {
    mount(investigationFlow(inv({ actions: [action()] })));
    const list = screen.getByTestId('flow-strip').querySelector('ol');
    expect(list?.className).toContain('flex-wrap');
    const html = screen.getByTestId('flow-strip').outerHTML;
    expect(html).not.toMatch(/truncate|text-ellipsis|line-clamp/);
    expect(screen.getByTestId('flow-strip').textContent).not.toMatch(/…|\.\.\./);
  });

  it('states each state to a screen reader', () => {
    mount(investigationFlow(inv({ status: 'error', verdict: 'untriaged' })));
    expect(screen.getByTestId('flow-step-alert').textContent).toContain('done');
    expect(screen.getByTestId('flow-step-investigation').textContent).toContain('current step');
    expect(screen.getByTestId('flow-step-verdict').textContent).toContain('next');
    expect(screen.getByTestId('flow-step-action').textContent).toContain('not yet');
  });

  it('renders nothing for no steps', () => {
    const { container } = mount([]);
    expect(container.textContent).toBe('');
  });
});

// ── the lead ────────────────────────────────────────────────────────────────

describe('leadFlow', () => {
  it('a lead with no hunt: the lead is current and the next control is Hunt this lead', () => {
    const steps = leadFlow(NEW_LEAD, null);
    expect(shape(steps)).toEqual([
      'hit:done',
      'lead:current',
      'hunt:next',
      'investigations:not_yet',
      'verdicts:not_yet',
      'actions:not_yet',
    ]);
    expect(step(steps, 'hunt').control).toBe('Hunt this lead');
  });

  it('a lead whose hunt is queued names no control: auto-hunt starts it', () => {
    const steps = leadFlow({ ...NEW_LEAD, hunt_queued: true }, null);
    expect(step(steps, 'hunt').state).toBe('next');
    expect(step(steps, 'hunt').note).toBe('queued');
    expect(step(steps, 'hunt').control).toBeUndefined();
  });

  it('a lead with a running hunt: the hunt is next, running, and links to the hunt', () => {
    const steps = leadFlow({ ...NEW_LEAD, status: 'hunting', hunt_id: 'H-1', hunt_status: 'running' }, null);
    expect(step(steps, 'hunt')).toMatchObject({ state: 'next', note: 'running', to: '/hunts/H-1' });
    expect(step(steps, 'investigations').state).toBe('not_yet');
  });

  it('a lead with a finished hunt shows Hunt done, and counts the investigations', () => {
    const steps = leadFlow(
      HUNTED_LEAD,
      hunt({
        findingsInvestigated: 2,
        findingsTotal: 3,
        findings: [
          threat({ investigationId: 'I-1', investigationStatus: 'complete', verdict: 'true_positive' }),
          threat({ investigationId: 'I-2', investigationStatus: 'complete', verdict: 'false_positive' }),
          threat({ investigationId: 'I-3', investigationStatus: 'running' }),
        ],
      }),
    );
    expect(step(steps, 'hunt').state).toBe('done');
    expect(step(steps, 'investigations')).toMatchObject({ state: 'next', note: '2 of 3 done' });
    // The hunt investigates its findings, so the step names no control.
    expect(step(steps, 'investigations').control).toBeUndefined();
    expect(step(steps, 'verdicts').state).toBe('not_yet');
  });

  it('a lead whose findings are all investigated shows the verdicts and the actions that wait', () => {
    const steps = leadFlow(
      HUNTED_LEAD,
      hunt({
        findingsInvestigated: 2,
        findingsTotal: 2,
        findings: [
          threat({ investigationId: 'I-1', investigationStatus: 'complete', verdict: 'true_positive', pendingActions: 1 }),
          threat({ investigationId: 'I-2', investigationStatus: 'complete', verdict: 'false_positive', pendingActions: 0 }),
        ],
      }),
    );
    expect(shape(steps)).toEqual([
      'hit:done',
      'lead:current',
      'hunt:done',
      'investigations:done',
      'verdicts:done',
      'actions:next',
    ]);
    expect(step(steps, 'investigations').note).toBe('2 of 2 done');
    expect(step(steps, 'verdicts').note).toBe('1 of 2 threats');
    expect(step(steps, 'actions')).toMatchObject({
      note: '1 wait for you',
      control: 'Acknowledge or Escalate to case',
    });
  });

  it('reads the older investigation block when the new fields are absent', () => {
    const steps = leadFlow(
      HUNTED_LEAD,
      hunt({
        findings: [
          threat({ investigation: { id: 'I-9', status: 'complete', verdict: 'false_positive', conf: 0.8 } }),
          // A visibility gap names no evidence, so it is not a subject.
          threat({ category: 'visibility_gap', title: 'dce_rpc: could not run' }),
        ],
      }),
    );
    expect(step(steps, 'investigations')).toMatchObject({
      state: 'done',
      note: '1 of 1 done',
      to: '/investigation/I-9',
    });
    expect(step(steps, 'verdicts').note).toBe('no threat confirmed');
    // The older server does not count the actions that wait.
    expect(step(steps, 'actions')).toMatchObject({ state: 'next', control: 'View investigation' });
  });

  it('a lead closed as promoted links its investigation and asks to read the verdict', () => {
    const steps = leadFlow({ ...HUNTED_LEAD, status: 'promoted', investigation_id: 'INV-7' }, null);
    expect(step(steps, 'lead')).toMatchObject({ state: 'current', note: 'closed' });
    expect(step(steps, 'hunt').state).toBe('done');
    expect(step(steps, 'investigations')).toMatchObject({ state: 'done', to: '/investigation/INV-7' });
    expect(step(steps, 'verdicts')).toMatchObject({ state: 'next', control: 'View investigation' });
    expect(step(steps, 'actions').state).toBe('not_yet');
  });

  it('a dismissed lead names Reopen as the next control', () => {
    const steps = leadFlow(
      { ...NEW_LEAD, status: 'dismissed', dismissed_reason: 'benign_repeat' },
      null,
    );
    expect(step(steps, 'lead').note).toBe('dismissed');
    expect(step(steps, 'hunt')).toMatchObject({ state: 'next', control: 'Reopen' });
    expect(steps.filter((s) => s.state === 'next')).toHaveLength(1);
  });

  it('a lead a clean hunt closed ends at its hunt, with no findings to investigate', () => {
    const steps = leadFlow(
      { ...HUNTED_LEAD, status: 'dismissed', dismissed_reason: 'hunt_clean' },
      hunt({ findings: [] }),
    );
    expect(step(steps, 'lead').note).toBe('closed');
    expect(step(steps, 'investigations')).toMatchObject({ state: 'not_yet', note: 'no findings' });
    expect(steps.some((s) => s.state === 'next')).toBe(false);
  });

  it('a lead its hunt closed on finding verdicts reads the verdicts and the actions', () => {
    const inv = {
      investigationId: 'I-9',
      investigationStatus: 'complete' as const,
      verdict: 'true_positive',
      pendingActions: 2,
    };
    const steps = leadFlow(
      { ...HUNTED_LEAD, status: 'promoted', investigation_id: 'I-9' },
      hunt({ findings: [threat(inv), threat(inv)], findingsTotal: 2, findingsInvestigated: 2 }),
    );
    expect(step(steps, 'lead').note).toBe('closed');
    expect(step(steps, 'investigations')).toMatchObject({ state: 'done', note: '2 of 2 done' });
    expect(step(steps, 'verdicts').state).toBe('done');
    expect(step(steps, 'actions').state).toBe('next');
    // Control: the same lead with a hunt that investigated nothing keeps the
    // manual path, where the verdict is behind "View investigation".
    const manual = leadFlow({ ...HUNTED_LEAD, status: 'promoted', investigation_id: 'I-9' }, hunt());
    expect(step(manual, 'verdicts')).toMatchObject({ state: 'next', control: 'View investigation' });
  });

  it('a hunt whose findings name no threat says so, not "no findings"', () => {
    const steps = leadFlow(
      { ...HUNTED_LEAD, status: 'dismissed', dismissed_reason: 'hunt_clean' },
      hunt({ findings: [threat({ category: 'observation', severity: 'info' })] }),
    );
    expect(step(steps, 'investigations')).toMatchObject({ state: 'not_yet', note: 'no threat finding' });
    expect(steps.some((s) => s.state === 'next')).toBe(false);
  });
});

// ── the hunt ────────────────────────────────────────────────────────────────

describe('huntFlow', () => {
  it('a lead hunt: the hunt is current, the lead links back', () => {
    const steps = huntFlow(hunt({ findings: [threat()] }), 12);
    expect(shape(steps).slice(0, 3)).toEqual(['hit:done', 'lead:done', 'hunt:current']);
    expect(step(steps, 'lead').to).toBe('/leads/12');
    expect(step(steps, 'investigations')).toMatchObject({
      state: 'next',
      control: 'Open an investigation',
    });
  });

  it('a manual hunt starts at its objective', () => {
    const steps = huntFlow(hunt({ kind: 'chat', starter: 'analyst', findings: [] }));
    expect(shape(steps)).toEqual([
      'objective:done',
      'hunt:current',
      'investigations:not_yet',
      'verdicts:not_yet',
      'actions:not_yet',
    ]);
  });

  it('a running hunt says soc-ai investigates when it ends, with no control', () => {
    const steps = huntFlow(hunt({ status: 'running', findings: [threat()] }), 12);
    expect(step(steps, 'hunt').note).toBe('running');
    expect(step(steps, 'investigations').state).toBe('next');
    expect(step(steps, 'investigations').control).toBeUndefined();
  });

  it('a hunt that investigates its findings says so on the hunt step', () => {
    const steps = huntFlow(
      hunt({ findingsInvestigated: 1, findingsTotal: 3, findings: [threat(), threat(), threat()] }),
      12,
    );
    expect(step(steps, 'hunt').note).toBe('investigating');
    expect(step(steps, 'investigations').note).toBe('1 of 3 done');
  });

  // Negative control: a stopped hunt is never a hunt with findings.
  it('a stopped hunt names Re-hunt and no investigation', () => {
    const steps = huntFlow(hunt({ status: 'error', findings: [] }), 12);
    expect(step(steps, 'hunt').note).toBe('stopped');
    expect(step(steps, 'investigations')).toMatchObject({ state: 'next', control: 'Re-hunt' });
    expect(step(steps, 'verdicts').state).toBe('not_yet');
  });
});

// ── the investigation ──────────────────────────────────────────────────────

describe('investigationFlow', () => {
  it('an investigation with a verdict and no action: Verdict done, Action next', () => {
    const steps = investigationFlow(inv({ actions: [] }));
    expect(shape(steps)).toEqual([
      'alert:done',
      'investigation:current',
      'verdict:done',
      'action:next',
    ]);
    expect(step(steps, 'verdict').note).toBe('false positive');
    // The settled bar offers the two writes.
    expect(step(steps, 'action').control).toBe('Acknowledge or Escalate to case');
    expect(step(steps, 'action').label).toBe('Action in Security Onion');
  });

  it('names the control of the action that waits', () => {
    const steps = investigationFlow(
      inv({ verdict: 'true_positive', actions: [action({ tag: 'escalate' })] }),
    );
    expect(step(steps, 'action')).toMatchObject({ state: 'next', control: 'Escalate to case' });
  });

  it('an investigation with an executed action: Action done', () => {
    const steps = investigationFlow(
      inv({ actions: [action({ applied: true, appliedBy: 'auto-ack' })] }),
    );
    expect(shape(steps)).toEqual([
      'alert:done',
      'investigation:current',
      'verdict:done',
      'action:done',
    ]);
    expect(steps.some((s) => s.state === 'next')).toBe(false);
  });

  it('reads an action executed in this tab as done before the next read', () => {
    const steps = investigationFlow(inv({ actions: [action()] }), { actedHere: true });
    expect(step(steps, 'action').state).toBe('done');
  });

  it('reads an alert Security Onion holds as acknowledged as done', () => {
    const steps = investigationFlow(inv({ actions: [], alertAcked: true }));
    expect(step(steps, 'action').state).toBe('done');
  });

  // Negative control: the failed run reached no verdict. The strip names
  // Re-run as the next control and never reads Verdict as done.
  it('a failed run shows Investigation current and Re-run next, not Verdict', () => {
    for (const status of ['error', 'cancelled', 'interrupted'] as const) {
      const steps = investigationFlow(inv({ status, verdict: 'untriaged' }));
      expect(step(steps, 'investigation')).toMatchObject({ state: 'current', note: 'no verdict' });
      expect(step(steps, 'verdict').state).toBe('next');
      expect(step(steps, 'verdict').state).not.toBe('done');
      expect(step(steps, 'verdict').control).toBe('Re-run investigation');
      expect(step(steps, 'action').state).toBe('not_yet');
    }
  });

  it('a stuck run the page gave up on reads as failed', () => {
    const steps = investigationFlow(inv({ status: 'investigating', verdict: 'untriaged' }), {
      failed: true,
    });
    expect(step(steps, 'verdict').control).toBe('Re-run investigation');
  });

  it('a running investigation: the verdict is next, and soc-ai reaches it', () => {
    const steps = investigationFlow(inv({ status: 'investigating', verdict: 'untriaged' }));
    expect(step(steps, 'investigation').note).toBe('running');
    expect(step(steps, 'verdict').state).toBe('next');
    expect(step(steps, 'verdict').control).toBeUndefined();
  });

  it('a verdict that needs more info names Request more info', () => {
    const steps = investigationFlow(inv({ verdict: 'needs_more_info' }));
    expect(step(steps, 'verdict')).toMatchObject({
      state: 'next',
      note: 'needs more info',
      control: 'Request more info',
    });
  });

  it('an investigation of a hunt finding starts at its lead and its hunt', () => {
    const steps = investigationFlow(
      inv({
        kind: 'hunt',
        huntId: 'H-1',
        subject: {
          type: 'hunt',
          hunt_id: 'H-1',
          objective: 'o',
          finding_ordinals: [0],
          lead_id: 12,
          document_ids: [],
          observation_ids: [],
        },
      }),
    );
    expect(shape(steps).slice(0, 3)).toEqual(['lead:done', 'hunt:done', 'investigation:current']);
    expect(step(steps, 'hunt').to).toBe('/hunts/H-1');
    // No alert to act on and no recommendation: no write waits.
    expect(step(steps, 'action')).toMatchObject({ state: 'not_yet', note: 'none recommended' });
  });

  it('a failed run of a hunt finding names Open an investigation, on its hunt', () => {
    const steps = investigationFlow(inv({ kind: 'hunt', huntId: 'H-1', status: 'error', verdict: 'untriaged' }));
    expect(step(steps, 'verdict').control).toBe('Open an investigation');
  });

  it('a backtest replay writes nothing, so no write waits', () => {
    const steps = investigationFlow(inv({ actions: [] }), { noWrites: true });
    expect(step(steps, 'action').state).toBe('not_yet');
  });
});

describe('findingInvestigation', () => {
  it('prefers the new fields and reads queued as running', () => {
    expect(
      findingInvestigation(threat({ investigationId: 'I-1', investigationStatus: 'queued' })),
    ).toEqual({ id: 'I-1', status: 'running', verdict: null, pendingActions: null });
  });

  it('falls back to the older block, and to null', () => {
    expect(
      findingInvestigation(threat({ investigation: { id: 'I-2', status: 'error', verdict: null } })),
    ).toMatchObject({ id: 'I-2', status: 'error' });
    expect(findingInvestigation(threat())).toBeNull();
  });
});
