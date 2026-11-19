// The investigation page of an open false positive (round 3, RC4). The page
// hands `ruleDecision` of the payload to the card of the Acknowledge.
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { Investigation as Inv } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getChatThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getMe: vi.fn().mockResolvedValue({ username: 'analyst' }),
  getActionScope: vi.fn().mockResolvedValue({
    tool: 'ack_alert',
    scope: 'alert',
    count: 1,
    sentence: 'Acknowledge this alert in Security Onion.',
  }),
}));

import { Investigation } from './Investigation';

const HREF = '/needs-you/rule/RVQgUE9MSUNZIEV4YW1wbGUgVExTIGNsaWVudA';

const inv = (over: Partial<Inv>): Inv =>
  ({
    id: 'INV-FP',
    groupId: 'ev-1',
    name: 'ET POLICY Example TLS client',
    kind: 'suricata',
    host: '192.0.2.10',
    ip: '198.51.100.7',
    verdict: 'false_positive',
    conf: 0.86,
    rationale: 'r',
    summary: [{ t: 'text', v: 'Vendor update traffic.' }],
    status: 'complete',
    elapsedLabel: '4m 5s',
    actions: [{ id: 'a0', title: 'Acknowledge alert', tag: 'ack', rationale: 'Benign.' }],
    timeline: [],
    nodes: [],
    edges: [],
    seedChat: [],
    ...over,
  }) as Inv;

function page(i: Inv) {
  render(
    <MemoryRouter>
      <Investigation inv={i} layout="page" />
    </MemoryRouter>,
  );
}

describe('the investigation page of an open false positive', () => {
  it('links the rule decision beside the open Acknowledge', async () => {
    page(inv({ ruleDecision: { href: HREF, count: 471, group: 'confident' } }));
    const line = await screen.findByTestId('action-rule-decision');
    expect(line).toHaveTextContent('This rule has 471 open false positives.');
    expect(within(line).getByRole('link', { name: /Decide on the rule/ })).toHaveAttribute('href', HREF);
  });

  // NEGATIVE CONTROL: a payload with no rule decision shows no line.
  it('shows no rule line when the payload holds none', async () => {
    page(inv({ ruleDecision: null }));
    await screen.findByTestId('action-scope');
    expect(screen.queryByTestId('action-rule-decision')).toBeNull();
  });

  it('names the rule decision in the head of the actions and in the step strip', async () => {
    page(
      inv({
        ruleDecision: { href: HREF, count: 29, group: 'confident' },
        actions: [{ id: 'a0', title: 'Acknowledge alert', tag: 'ack', rationale: 'Benign.', waits: false }],
      }),
    );
    const head = await screen.findByTestId('actions-rule-decision');
    expect(head).toHaveTextContent('This false positive is 1 of 29 open on its rule. Decide on the rule');
    expect(within(head).getByRole('link', { name: 'Decide on the rule' })).toHaveAttribute('href', HREF);
    expect(screen.queryByText('0 actions wait for you')).toBeNull();
    expect(screen.getByTestId('flow-control-action')).toHaveTextContent('Decide on the rule');
    expect(screen.queryByText(/Acknowledge, next/)).toBeNull();
  });

  // NEGATIVE CONTROL: with no rule decision the head counts the actions and the strip names the write.
  it('keeps the count and the write in the strip for an investigation with no rule decision', async () => {
    page(inv({ ruleDecision: null }));
    await screen.findByTestId('action-scope');
    expect(screen.queryByTestId('actions-rule-decision')).toBeNull();
    expect(screen.getByText('1 action waits for you')).toBeInTheDocument();
    expect(screen.getByTestId('flow-control-action')).not.toHaveTextContent('Decide on the rule');
  });
});
