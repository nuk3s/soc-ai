// L1 (review 2026-11-12): the hunt page states its bottom line first, and the
// findings come before the charts and the timelines. The findings started
// about 2,000 px down, under the lead timeline, two charts, a node map and the
// diff. The strip read "Investigations 4 of 4" with a check beside a card that
// read "Investigation failed, re-run." Every time is an offset from Date.now().
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { HuntDetailData, HuntFinding } from '../lib/types';

const HOUR = 3_600_000;
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();

const finding = (title: string, over: Partial<HuntFinding> & Record<string, unknown> = {}) =>
  ({
    title,
    detail: 'The host sent 40 connections at a fixed interval to 203.0.113.5.',
    severity: 'high',
    category: 'threat',
    hosts: ['192.0.2.10'],
    citations: ['doc-0001-first'],
    ...over,
  }) as HuntFinding;

const tp = (n: number) => ({
  investigationId: `I-${n}`,
  investigationStatus: 'complete' as const,
  verdict: 'true_positive',
  pendingActions: 0,
});

const HUNT: HuntDetailData = {
  id: 'H-9',
  objective: 'Hunt for beacons from 192.0.2.10',
  kind: 'scheduled',
  status: 'complete',
  narrative:
    '## Assessment\n**The host beaconed** to one rare external address. The beacon ran for six hours.',
  findings: [
    finding('Beacon one', tp(1)),
    finding('Beacon two', tp(2)),
    finding('Beacon three', tp(3)),
    finding('Beacon four', { investigationId: 'I-4', investigationStatus: 'failed' as const }),
    finding('No DNS logs', { category: 'visibility_gap' }),
  ],
  affectedHosts: ['192.0.2.10'],
  mitreTechniques: [],
  recommendedActions: [],
  charts: [],
  confidence: 0.7,
  startedBy: 'scheduler',
  elapsedLabel: '6m 0s',
  elapsedSec: 360,
  ts: iso(2 * HOUR),
  timeline: [],
  diff: null,
  outcome: 'threats_confirmed',
  outcome_label: '3 confirmed · 1 not judged · of 4 threat findings',
  findingsInvestigated: 4,
  findingsTotal: 4,
  findingsConfirmed: 3,
  findingsFalsePositive: 0,
  threatFindingCount: 4,
};

const getHunt = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getHunt,
  getHunts: vi.fn().mockResolvedValue([]),
  getHuntChat: vi.fn().mockResolvedValue({ messages: [], pending: false }),
}));

import { HuntDetail, bottomLineCount, narrativeLead } from './HuntDetail';

function mount() {
  return render(
    <MemoryRouter initialEntries={['/hunts/H-9']}>
      <Routes>
        <Route path="/hunts/:id" element={<HuntDetail />} />
      </Routes>
    </MemoryRouter>,
  );
}

const follows = (a: Node, b: Node) => !!(a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING);

beforeEach(() => {
  getHunt.mockReset().mockResolvedValue(HUNT);
});

describe('the bottom line of the hunt page', () => {
  it('states the count sentence and the first sentence of the narrative first', async () => {
    mount();
    const line = await screen.findByTestId('hunt-bottom-line');
    expect(within(line).getByTestId('hunt-bottom-line-count').textContent).toBe(
      '3 confirmed · 1 not judged · of 4 threat findings',
    );
    expect(within(line).getByTestId('hunt-bottom-line-narrative').textContent?.trim()).toBe(
      'The host beaconed to one rare external address.',
    );
    // First on the page: before the flow strip and the hero.
    expect(follows(line, screen.getByTestId('flow-strip'))).toBe(true);
    expect(follows(line, screen.getByTestId('hunt-title'))).toBe(true);
  });

  it('puts the findings before the charts and the timelines', async () => {
    mount();
    const findings = await screen.findByText('Findings');
    expect(follows(screen.getByText('Narrative'), findings)).toBe(true);
    expect(follows(findings, screen.getByText('Visual summary'))).toBe(true);
    expect(follows(findings, screen.getByText('Hunt timeline'))).toBe(true);
  });

  it('leaves the Investigations step amber when one investigation failed', async () => {
    mount();
    const strip = await screen.findByTestId('flow-strip');
    const step = within(strip).getByTestId('flow-step-investigations');
    expect(step.dataset.state).toBe('next');
    expect(step.dataset.tone).toBe('warn');
    expect(step.textContent).toContain('3 of 4 findings with a verdict');
    expect(within(strip).getByTestId('flow-step-verdicts').textContent).toContain(
      '3 confirmed · 1 not judged · of 4 threat findings',
    );
  });
});

describe('bottomLineCount', () => {
  it('counts a threat found that no investigation judged', () => {
    expect(
      bottomLineCount({
        status: 'complete',
        outcome: 'threat_found',
        outcome_label: 'Threat found',
        findings: [finding('a'), finding('b'), finding('gap', { category: 'visibility_gap' })],
      }),
    ).toBe('0 confirmed · 2 not judged · of 2 threat findings');
  });

  it('reads the outcome label of a hunt with no threat finding', () => {
    // Control: a clean hunt has no count sentence.
    expect(
      bottomLineCount({
        status: 'complete',
        outcome: 'no_threat',
        outcome_label: 'No threat found',
        findings: [finding('quiet', { category: 'observation' })],
      }),
    ).toBe('No threat found');
  });
});

describe('narrativeLead', () => {
  it('drops a heading and the Markdown marks', () => {
    expect(narrativeLead('# Summary\n- **Two hosts** scan each other. Then more.')).toBe(
      'Two hosts scan each other.',
    );
    expect(narrativeLead(null)).toBe('');
  });
});
