// The confidence word and the rule severity (dogfood 2026-10-06, W1 and C2).
// 0.62 rendered like 0.90, and the rule severity sat in the confidence row at
// equal weight. The word comes from confidenceWord, with the thresholds in
// the tooltip. The severity moves to a row of its own, labelled.
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

import { CONFIDENCE_TIP, Investigation, RULE_SEVERITY_TIP } from './Investigation';

const inv = (conf: number): Inv =>
  ({
    id: 'INV-1',
    groupId: 'ev-1',
    name: 'Rule',
    kind: 'suricata',
    host: '192.0.2.1',
    ip: '198.51.100.2',
    srcIp: '192.0.2.1',
    dstIp: '198.51.100.2',
    verdict: 'true_positive',
    conf,
    sev: 'high',
    rationale: 'Bad.',
    summary: [{ t: 'text', v: 'x' }],
    status: 'complete',
    elapsedLabel: '1m',
    actions: [],
    timeline: [],
    nodes: [],
    edges: [],
    seedChat: [],
  }) as Inv;

const mount = (conf: number) =>
  render(
    <MemoryRouter>
      <Investigation inv={inv(conf)} layout="page" />
    </MemoryRouter>,
  );

describe('the confidence word', () => {
  it.each([
    [0.9, 'High confidence'],
    [0.75, 'Medium confidence'],
    [0.62, 'Low confidence'],
  ])('reads %s as "%s"', (conf, word) => {
    mount(conf);
    expect(screen.getByTestId('confidence-word').textContent).toBe(word);
  });

  it('names the thresholds in the tooltip', () => {
    mount(0.62);
    expect(screen.getByTestId('confidence-word').closest('[title]')?.getAttribute('title')).toBe(
      CONFIDENCE_TIP,
    );
    expect(CONFIDENCE_TIP).toContain('0.80');
    expect(CONFIDENCE_TIP).toContain('0.70');
  });

  it('labels the severity as the rule severity, apart from the confidence', () => {
    mount(0.9);
    const sev = screen.getByTestId('rule-severity');
    expect(sev.getAttribute('title')).toBe(RULE_SEVERITY_TIP);
    expect(sev.textContent).toContain('rule severity');
    // Negative control: the severity is not in the row that holds the confidence.
    const confRow = screen.getByTestId('confidence-word').closest('[title]')?.parentElement;
    expect(confRow?.contains(sev)).toBe(false);
    expect(screen.getByTestId('verdict-context').contains(sev)).toBe(true);
  });
});
