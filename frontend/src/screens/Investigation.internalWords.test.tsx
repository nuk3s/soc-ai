// Internal words leave the report page (K3, review 2026-11-12, console
// finding 15). The page showed "Subject: F1", tool names such as
// "t_rule_prevalence", "Post-validator override", "Local: needs_more_info",
// "true_positive" in a headline, "Oracle consulted" beside "Oracle did not
// return a verdict", and "Depth: standard" on every run. The scan reads the
// text of a whole page of a fixture run that holds each of them.
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

const BANNED: Array<[string, RegExp]> = [
  ['a finding code label', /Subject: F\d/],
  ['a tool name', /\bt_[a-z][a-z0-9_]*\b/],
  ['the validator label', /Post-validator/],
  ['the local label', /\bLocal:/],
  ['a stored verdict key', /\b(true_positive|false_positive|needs_more_info)\b/],
  ['an Oracle chip with no answer', /Oracle consulted/],
  ['the old Oracle line', /did not return a verdict/],
  ['the default depth', /Depth: standard/],
];

const fixture = (over: Partial<Inv> = {}): Inv =>
  ({
    id: 'INV-1',
    groupId: 'doc-1',
    name: 'Inbound TCP probe from a listed address',
    kind: 'hunt',
    host: '10.20.30.5',
    ip: '10.40.50.7',
    verdict: 'needs_more_info',
    conf: 0.5,
    rationale: 'A prior true_positive stands on this same session per t_rule_prevalence.',
    summary: [
      {
        t: 'text',
        v: 'A prior true_positive stands on this same session per t_rule_prevalence. t_prevalence shows 3 peers.',
      },
    ],
    status: 'complete',
    elapsedLabel: '7m',
    actions: [],
    timeline: [],
    nodes: [],
    edges: [],
    seedChat: [],
    runClass: 'standard',
    validatorNote: 'The gate read t_enrich_ip and kept needs_more_info.',
    oracle: {
      escalated: true,
      reason: 'needs_more_info',
      localVerdict: 'needs_more_info',
      localConfidence: 0.5,
      noAnswer: 'The Oracle route hit a usage limit.',
    },
    huntId: 'H1',
    subject: {
      type: 'hunt',
      hunt_id: 'H1',
      objective: 'Investigate 10.40.50.7.',
      finding_ordinals: [0],
      finding_titles: ['Inbound TCP probe from a listed address'],
      lead_id: 53,
      document_ids: ['v08vkqEB6RQ6BUvoLzu6'],
      observation_ids: [],
      judges: 'finding',
    },
    promotedFinding: {
      ordinal: 0,
      label: 'F1',
      title: 'Inbound TCP probe from a listed address',
      detail: 'The rule fired twice per t_rule_prevalence.',
      hosts: ['10.40.50.7'],
      citations: [
        'v08vkqEB6RQ6BUvoLzu6',
        't_rule_prevalence ET CINS Poor Reputation IP group 148',
        't_prevalence 10.40.50.7 peer 10.20.30.5',
      ],
      attacker: '10.20.30.5',
      victim: '10.40.50.7',
      huntId: 'H1',
      huntTitle: 'Lead 53',
    },
    ...over,
  }) as Inv;

const mount = (i: Inv) =>
  render(
    <MemoryRouter>
      <Investigation inv={i} layout="page" />
    </MemoryRouter>,
  );

describe('the report page holds no internal word', () => {
  it.each(BANNED)('shows no %s', (_name, re) => {
    const { container } = mount(fixture());
    const text = container.textContent ?? '';
    expect(text.match(re)?.[0] ?? null).toBeNull();
  });

  it('says what the Oracle answered and why', () => {
    mount(fixture());
    expect(screen.getByText('Oracle gave no answer')).toBeTruthy();
    expect(screen.getByTestId('oracle-no-answer').textContent).toContain(
      'The Oracle gave no answer. The Oracle route hit a usage limit.',
    );
    expect(screen.getByTestId('promoted-finding').textContent).toContain(
      'Finding 1: Inbound TCP probe from a listed address',
    );
  });

  it('control: a depth that is not the default keeps its chip', () => {
    const { container } = mount(fixture({ runClass: 'deep' }));
    expect(container.textContent).toContain('Depth: deep');
  });

  it('control: an Oracle verdict reads in words', () => {
    const { container } = mount(
      fixture({
        oracle: {
          escalated: true,
          localVerdict: 'needs_more_info',
          localConfidence: 0.5,
          oracleVerdict: 'true_positive',
          oracleConfidence: 0.8,
          changed: true,
        },
      }),
    );
    const text = container.textContent ?? '';
    expect(text).toContain('soc-ai verdict:Needs more info');
    expect(text).toContain('Oracle verdict:True positive');
    expect(text).not.toContain('The Oracle gave no answer');
  });
});
