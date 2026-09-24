// A pipeline-fallback run failed BEFORE reaching a verdict — the red panel says
// "re-run it to get a real verdict". Rendering "VERDICT SETTLED — TAKE ACTION"
// (ack/escalate) directly under it contradicts that guidance (dogfood
// 2026-07-15): there is no settled verdict to act on.
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Investigation as Inv } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getChatThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getMe: vi.fn().mockResolvedValue({ username: 'analyst' }),
  ackGroup: vi.fn(),
  escalateGroup: vi.fn(),
}));

import { ackGroup, escalateGroup } from '../lib/api';
import { Investigation } from './Investigation';

const baseInv = (over: Partial<Inv>): Inv =>
  ({
    id: 'INV-1',
    groupId: 'ev-1',
    name: 'GPL ICMP Large ICMP Packet',
    kind: 'suricata',
    host: '192.0.2.10',
    ip: '198.51.100.7',
    verdict: 'needs_more_info',
    conf: 0.3,
    rationale: 'pipeline fallback',
    summary: [{ t: 'text', v: 'fallback' }],
    status: 'complete',
    elapsedLabel: '4m 5s',
    actions: [],
    timeline: [],
    nodes: [],
    edges: [],
    seedChat: [],
    ...over,
  }) as Inv;

describe('settled-action bar vs pipeline fallback', () => {
  it('suppresses the settled bar on a fallback run', () => {
    render(
      <MemoryRouter>
        <Investigation
          inv={baseInv({ fallback: { provenance: 'pipeline_fallback' } })}
          layout="page"
        />
      </MemoryRouter>,
    );
    expect(screen.queryByText(/Verdict settled\. Take action\./i)).toBeNull();
    expect(screen.getByText(/failed before it reached a verdict/i)).toBeTruthy();
  });

  it('keeps the settled bar on a genuine actionless complete run', () => {
    render(
      <MemoryRouter>
        <Investigation inv={baseInv({ fallback: null })} layout="page" />
      </MemoryRouter>,
    );
    expect(screen.getByText(/Verdict settled\. Take action\./i)).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------
// What the bar reports back. These two buttons call the SAME endpoints the
// Alerts console does, and those endpoints learned to distinguish their
// outcomes while this bar went on reading `escalated`/`total` and discarding
// everything else. So it called an empty case a successful escalate, and an
// ack that changed nothing visible read as a button that did not work.
//
// Rendered in the drawer layout deliberately: that is where an analyst
// finishing a triage actually presses these.

const mountDrawer = () =>
  render(
    <MemoryRouter>
      <Investigation inv={baseInv({ fallback: null })} layout="drawer" />
    </MemoryRouter>,
  );

beforeEach(() => {
  vi.mocked(ackGroup).mockReset();
  vi.mocked(escalateGroup).mockReset();
});

describe('what the settled-action bar reports', () => {
  it('names an empty case rather than calling it an escalate', async () => {
    // Security Onion created the case and attached nothing, so the alert is on
    // no case and an empty one is now sitting in the queue under a title that
    // reads like an incident. The old bar rendered "Escalated 0 of 1 event to
    // a case" and never named case-9f3, which only a human can close.
    vi.mocked(escalateGroup).mockResolvedValue({
      escalated: 0,
      failed: 1,
      total: 1,
      capped: false,
      empty_cases: ['case-9f3'],
    });
    mountDrawer();
    fireEvent.click(screen.getByRole('button', { name: /escalate to case/i }));
    const msg = await screen.findByText(/nothing attached/i);
    expect(msg).toHaveTextContent('case-9f3');
    expect(msg).toHaveTextContent(/Opened no cases/i);
  });

  it('says why a press opened nothing, instead of reporting it as a clean escalate', async () => {
    // The three reasons a press withholds a case, each with its own source and
    // its own sentence. Summed into one number they produced the original
    // defect: seventeen "already escalated" alerts, not one of which had a
    // case.
    vi.mocked(escalateGroup).mockResolvedValue({
      escalated: 1,
      failed: 0,
      total: 20,
      capped: false,
      already_escalated: 3,
      already_acked: 5,
      unresolved: 2,
    });
    mountDrawer();
    fireEvent.click(screen.getByRole('button', { name: /escalate to case/i }));
    const msg = await screen.findByText(/already on a case/i);
    expect(msg).toHaveTextContent(/3 alerts already on a case, no second case opened/i);
    expect(msg).toHaveTextContent(/5 alerts already acknowledged in Security Onion, skipped/i);
    expect(msg).toHaveTextContent(/2 alerts from an earlier escalate whose outcome is unknown/i);
  });

  it('tells the analyst when acknowledged alerts will stay on screen anyway', async () => {
    // The index cannot hide an alert Security Onion has already acknowledged,
    // so those rows do not go away however many times the button is pressed.
    // Unsaid, a working button reads as a broken one.
    vi.mocked(ackGroup).mockResolvedValue({
      acked: 1,
      failed: 0,
      total: 18,
      capped: false,
      already_acked: 17,
    });
    mountDrawer();
    fireEvent.click(screen.getByRole('button', { name: /^acknowledge$/i }));
    const msg = await screen.findByText(/already acknowledged in Security Onion/i);
    expect(msg).toHaveTextContent(/so they stay listed/i);
  });

  it('a clean press says only what happened', async () => {
    // NEGATIVE CONTROL. Every clause is conditional, so a press with nothing
    // withheld, nothing empty and nothing left must not manufacture a caveat —
    // a message that always carries one is a message nobody reads.
    vi.mocked(escalateGroup).mockResolvedValue({
      escalated: 2,
      failed: 0,
      total: 2,
      capped: false,
    });
    mountDrawer();
    fireEvent.click(screen.getByRole('button', { name: /escalate to case/i }));
    await waitFor(() => expect(escalateGroup).toHaveBeenCalledTimes(1));
    const msg = await screen.findByText(/Opened 2 cases/i);
    expect(msg.textContent).toBe('Opened 2 cases for GPL ICMP Large ICMP Packet');
  });
});
