// Verify 2026-10-20, V3-N2. The action card of the run page read the kind of
// the run and nothing else. On a lead run, and on an alert run that a
// promoted lead anchors, the card offered "Escalate to case" while the row
// of the pending-action list and the server refused it. The card now obeys
// the reason the server states, from the one rule of every surface.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { Investigation as Inv, RecommendedAction } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getChatThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getMe: vi.fn().mockResolvedValue({ username: 'analyst' }),
}));

import { Investigation } from './Investigation';

const LEAD_REASON = 'A promoted lead has no Security Onion alert to act on.';
const ANCHOR_REASON =
  'A promoted lead uses this document as its anchor. The document is not a Security Onion alert.';

const escalate = (over: Partial<RecommendedAction> = {}): RecommendedAction => ({
  id: 'a0',
  title: 'Escalate to case',
  tag: 'escalate',
  rationale: 'Payload confirms remote command execution.',
  ...over,
});

const inv = (over: Partial<Inv>): Inv =>
  ({
    id: 'INV-1',
    groupId: 'ev-1',
    name: 'ET INFO Suspected Impacket WMIExec Activity',
    kind: 'suricata',
    host: '192.0.2.10',
    ip: '198.51.100.7',
    verdict: 'true_positive',
    conf: 0.8,
    rationale: 'r',
    summary: [{ t: 'text', v: 'evidence' }],
    status: 'complete',
    elapsedLabel: '4m 5s',
    actions: [],
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

describe('the action card obeys the server rule', () => {
  it('turns the write off on a lead run, which the card read as a live alert', () => {
    page(
      inv({
        // A lead run lands kind "lead". The client type names the detection
        // kinds only, as in the other lead tests.
        kind: 'lead' as never,
        actions: [escalate({ blockedReason: LEAD_REASON })],
        writeBlockedReason: LEAD_REASON,
      }),
    );
    const write = screen.getByRole('button', { name: /^Escalate to case$/ });
    expect(write).toBeDisabled();
    expect(write).toHaveAttribute('title', LEAD_REASON);
    expect(screen.getByTestId('action-blocked').textContent).toBe(LEAD_REASON);
    expect(screen.getByRole('button', { name: /Dismiss/ })).toBeEnabled();
  });

  it('turns the write off on an alert run that a promoted lead anchors, and links its cases', () => {
    page(
      inv({
        actions: [escalate({ blockedReason: ANCHOR_REASON })],
        writeBlockedReason: ANCHOR_REASON,
        alertCases: [
          { id: 'case-a', url: 'https://so.example/#/case/case-a' },
          { id: 'case-b', url: 'https://so.example/#/case/case-b' },
        ],
        alertCasesComplete: true,
      }),
    );
    expect(screen.getByRole('button', { name: /^Escalate to case$/ })).toBeDisabled();
    expect(screen.getByTestId('action-blocked').textContent).toBe(ANCHOR_REASON);
    expect(screen.getByTestId('action-cases').textContent).toBe(
      'The alert is already on cases case-a, case-b.',
    );
    expect(screen.getByRole('link', { name: 'case-b' })).toHaveAttribute(
      'href',
      'https://so.example/#/case/case-b',
    );
  });

  it('NEGATIVE CONTROL: a promoted finding with no reason from the server keeps the write on', () => {
    // The card follows the server. A kind alone does not turn the write off.
    page(inv({ kind: 'hunt', actions: [escalate()] }));
    expect(screen.getByRole('button', { name: /^Escalate to case$/ })).toBeEnabled();
  });

  it('offers no settled bar on a run the server marks with no alert to act on', () => {
    page(inv({ actions: [], writeBlockedReason: ANCHOR_REASON }));
    expect(screen.queryByText('No automatic action')).toBeNull();
  });

  it('NEGATIVE CONTROL: a run with an alert to act on keeps the settled bar', () => {
    page(inv({ actions: [], writeBlockedReason: null }));
    expect(screen.getByText('No automatic action')).toBeTruthy();
  });
});
