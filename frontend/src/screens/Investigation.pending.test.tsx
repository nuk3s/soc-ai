// (1) The RECOMMENDED ACTIONS header must not count an action the system already
//     carried out (auto-ack). A completed FP run with a single applied action
//     used to read "1 pending" while the only card said "✓ Auto-acknowledged".
// (2) Opening chat on a message-less investigation shows a starter hint with
//     suggested questions instead of a blank void.
import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { Investigation as Inv, RecommendedAction } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getChatThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getMe: vi.fn().mockResolvedValue({ username: 'analyst' }),
}));

import { Investigation } from './Investigation';
import { WithChat } from '../test/chatHarness';

const baseInv = (over: Partial<Inv>): Inv =>
  ({
    id: 'INV-1',
    groupId: 'ev-1',
    name: 'ET INFO Suspicious Beacon',
    kind: 'suricata',
    host: '192.0.2.10',
    ip: '198.51.100.7',
    verdict: 'false_positive',
    conf: 0.92,
    rationale: 'benign scanner',
    summary: [{ t: 'text', v: 'benign' }],
    status: 'complete',
    elapsedLabel: '1m 2s',
    actions: [],
    timeline: [],
    nodes: [],
    edges: [],
    seedChat: [],
    ...over,
  }) as Inv;

const appliedAction: RecommendedAction = {
  id: 'a1',
  title: 'Acknowledge detection',
  tag: 'ack',
  rationale: 'auto-ack: benign',
  applied: true,
  appliedNote: null,
};

describe('recommended-actions pending count', () => {
  it('excludes an already auto-acked action from the pending count', () => {
    render(
      <MemoryRouter>
        <Investigation inv={baseInv({ actions: [appliedAction] })} layout="page" />
      </MemoryRouter>,
    );
    // header meta: "0 actions wait for you"
    expect(screen.getByText(/0 actions wait for you/)).toBeTruthy();
    expect(screen.queryByText(/1 action waits for you/)).toBeNull();
  });

  // NY5 (macro review 2026-11-17, m14). The server states whether an action
  // waits, by the rule of Needs you. The acknowledge of a false positive
  // stays open and waits for no one.
  it('counts no open acknowledge of a false positive that the server rules out', () => {
    render(
      <MemoryRouter>
        <Investigation
          inv={baseInv({ actions: [{ ...appliedAction, applied: false, waits: false }] })}
          layout="page"
        />
      </MemoryRouter>,
    );
    expect(screen.getByText(/0 actions wait for you/)).toBeTruthy();
    expect(screen.queryByText(/1 action waits for you/)).toBeNull();
  });

  // NEGATIVE CONTROL. An action that the server rules as waiting still counts.
  it('counts an action that waits by the rule of the server', () => {
    render(
      <MemoryRouter>
        <Investigation
          inv={baseInv({
            verdict: 'true_positive',
            actions: [
              { id: 'e1', title: 'Escalate to case', tag: 'escalate', rationale: 'Bad.', waits: true },
              { ...appliedAction, id: 'a9', applied: false, waits: false },
            ],
          })}
          layout="page"
        />
      </MemoryRouter>,
    );
    expect(screen.getByText(/1 action waits for you/)).toBeTruthy();
  });

  it('still counts a genuinely un-executed action of an older server', () => {
    render(
      <MemoryRouter>
        <Investigation
          inv={baseInv({ actions: [{ ...appliedAction, applied: false }] })}
          layout="page"
        />
      </MemoryRouter>,
    );
    expect(screen.getByText(/1 action waits for you/)).toBeTruthy();
  });
});

describe('empty investigation chat', () => {
  it('renders suggested starter questions when the thread is empty', () => {
    render(
      <MemoryRouter>
        <WithChat>
          <Investigation inv={baseInv({ seedChat: [] })} layout="drawer" />
        </WithChat>
      </MemoryRouter>,
    );
    // The chat is the Ask soc-ai panel. The drawer header opens it.
    fireEvent.click(screen.getAllByRole('button', { name: 'Ask soc-ai about this investigation' })[0]);
    expect(screen.getByText('Why not a true positive?')).toBeTruthy();
    expect(screen.getByText(/Ask a follow-up about this investigation/i)).toBeTruthy();
  });
});

describe('recommended actions of an investigation that a campaign holds', () => {
  const campaign = {
    id: 7,
    title: 'actor-a against web-1',
    status: 'open' as const,
    stage: 'action' as const,
    differs: false,
    decision: null,
    waitsSince: '2026-10-24T00:40:00Z',
  };
  const waiting: RecommendedAction = { id: 'a2', title: 'Escalate to case', tag: 'escalate', rationale: 'Bad.' };

  it('counts no action that waits, and each card names the campaign', () => {
    render(
      <MemoryRouter>
        <Investigation inv={baseInv({ verdict: 'true_positive', actions: [waiting], campaign })} layout="page" />
      </MemoryRouter>,
    );
    expect(screen.getByText(/0 actions wait for you/)).toBeTruthy();
    expect(screen.getByTestId('action-campaign')).toHaveTextContent('Decide on the campaign.');
  });

  it('offers no Escalate button and sends the analyst to the case on the campaign', () => {
    const blocked: RecommendedAction = {
      ...waiting,
      blockedReason: 'Open the case on the campaign.',
      noteCode: 'campaign',
      note: 'Part of the campaign actor-a against web-1. Decide on the campaign.',
      noteHref: '/campaigns/7',
    };
    render(
      <MemoryRouter>
        <Investigation inv={baseInv({ verdict: 'true_positive', actions: [blocked], campaign })} layout="page" />
      </MemoryRouter>,
    );
    const line = screen.getByTestId('action-campaign-case');
    expect(line).toHaveTextContent('Part of the campaign actor-a against web-1. Open the case on the campaign.');
    expect(within(line).getByRole('link', { name: 'Open the campaign' }).getAttribute('href')).toBe('/campaigns/7');
    expect(screen.queryByRole('button', { name: /Escalate to case/ })).toBeNull();
  });

  it('still counts the action of a verdict that differs', () => {
    // NEGATIVE CONTROL. A verdict that differs waits under its own rules.
    render(
      <MemoryRouter>
        <Investigation
          inv={baseInv({ verdict: 'true_positive', actions: [waiting], campaign: { ...campaign, differs: true } })}
          layout="page"
        />
      </MemoryRouter>,
    );
    expect(screen.getByText(/1 action waits for you/)).toBeTruthy();
    expect(screen.queryByTestId('action-campaign')).toBeNull();
  });
});
