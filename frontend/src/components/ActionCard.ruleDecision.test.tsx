// The action card of an open false positive (round 3, RC4). A guard held the
// automatic acknowledge. Beside the open Acknowledge one line states the open
// false positives of the rule and links the rule page. After a rule decision
// the card reads the receipt of that decision with its link.
import { render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { RecommendedAction } from '../lib/types';

const getActionScope = vi.fn();
vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getActionScope: (...a: unknown[]) => getActionScope(...a),
}));

import { ActionCard } from './ActionCard';
import type { InvestigationRuleDecision } from '../lib/api';
import { forbiddenWords } from '../test/analystWords';

const HREF = '/needs-you/rule/RVQgUE9MSUNZIEV4YW1wbGUgVExTIGNsaWVudA';
const RULE: InvestigationRuleDecision = { href: HREF, count: 471, group: 'confident' };

const ack: RecommendedAction = {
  id: 'a0',
  title: 'Acknowledge alert',
  tag: 'ack',
  rationale: 'Vendor update traffic.',
  pendingNote: 'The rule is high stakes. The acknowledge waits for a person.',
};
const esc: RecommendedAction = { id: 'a1', title: 'Escalate to case', tag: 'escalate', rationale: 'Bad.' };

function mount(action: RecommendedAction, ruleDecision: InvestigationRuleDecision | null = RULE) {
  return render(
    <MemoryRouter>
      <ActionCard
        action={action}
        index={0}
        invId="inv-a"
        onExecute={vi.fn()}
        onDismiss={vi.fn()}
        onUndoDismiss={vi.fn()}
        ruleDecision={ruleDecision}
      />
    </MemoryRouter>,
  );
}

beforeEach(() => {
  getActionScope.mockReset().mockResolvedValue({
    tool: 'ack_alert',
    scope: 'alert',
    count: 1,
    sentence: 'Acknowledge this alert in Security Onion.',
  });
});

describe('ActionCard: the rule decision', () => {
  it('states the open false positives of the rule beside the open Acknowledge, with the link', async () => {
    mount(ack);
    const line = await screen.findByTestId('action-rule-decision');
    expect(line).toHaveTextContent('This rule has 471 open false positives.');
    expect(within(line).getByRole('link', { name: /Decide on the rule/ })).toHaveAttribute('href', HREF);
    // The sentence of the hold keeps its words, and the Acknowledge stays.
    expect(screen.getByText('The rule is high stakes. The acknowledge waits for a person.')).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole('button', { name: /^Acknowledge$/ })).toBeEnabled());
  });

  it('says one open false positive in the singular', async () => {
    mount(ack, { ...RULE, count: 1 });
    expect(await screen.findByTestId('action-rule-decision')).toHaveTextContent('This rule has 1 open false positive.');
  });

  // NEGATIVE CONTROL: an investigation that is no open false positive, and an
  // action that is no acknowledge, show no rule line.
  it('shows no rule line on another investigation and on another action', async () => {
    const { unmount } = mount(ack, null);
    await screen.findByTestId('action-scope');
    expect(screen.queryByTestId('action-rule-decision')).toBeNull();
    unmount();
    mount(esc);
    await screen.findByTestId('action-scope');
    expect(screen.queryByTestId('action-rule-decision')).toBeNull();
  });

  it('reads the receipt of a rule decision, with its link', async () => {
    mount(
      {
        ...ack,
        pendingNote: null,
        applied: true,
        appliedBy: 'ana',
        appliedAt: '2026-11-14T12:03:00Z',
        ruleDecisionReceipt: { id: 9, at: '2026-11-14T12:00:00Z', href: HREF },
      },
      null,
    );
    const record = await screen.findByTestId('action-record');
    expect(record).toHaveTextContent('The analyst acknowledged this with the rule decision of 2026-11-14 12:00 UTC.');
    expect(screen.getByTestId('action-rule-receipt-link')).toHaveAttribute('href', HREF);
    expect(screen.getByTestId('action-rule-receipt-link')).toHaveTextContent('Open the rule decision');
    // A done action offers no write.
    expect(screen.queryByRole('button', { name: /^Acknowledge$/ })).toBeNull();
  });

  // NEGATIVE CONTROL: an acknowledge of another path keeps its own record.
  it('keeps the record of another acknowledge', async () => {
    mount({ ...ack, pendingNote: null, applied: true, appliedBy: 'auto-ack', appliedAt: '2026-11-14T12:03:00Z' }, null);
    const record = await screen.findByTestId('action-record');
    expect(record).toHaveTextContent('Executed by auto-ack at 2026-11-14 12:03 UTC');
    expect(record.textContent).not.toContain('rule decision');
    expect(screen.queryByTestId('action-rule-receipt-link')).toBeNull();
  });

  it('cuts no text and holds no banned word', async () => {
    const { container } = mount(ack);
    await screen.findByTestId('action-rule-decision');
    expect(container.querySelector('.truncate, [class*="line-clamp"], .text-ellipsis')).toBeNull();
    expect(forbiddenWords(container)).toEqual([]);
  });
});
