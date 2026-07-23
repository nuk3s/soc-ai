// F40 — the Investigation component instance is reused across investigations
// (the Alerts drawer and the permalink route both re-render it with a new
// `inv` prop on re-hunt / request-more-info). If a chat send is still in
// flight when the parent swaps `inv` to a different investigation, the
// eventual response must not clobber the newly-shown investigation's chat.
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { Investigation as Inv } from '../lib/types';
import type { ChatThread } from '../lib/api';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getChatThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  postChat: vi.fn(),
}));

import { Investigation } from './Investigation';
import { postChat } from '../lib/api';

const baseInv = (over: Partial<Inv>): Inv =>
  ({
    id: 'INV-A',
    groupId: 'ev-1',
    name: 'GPL ICMP Large ICMP Packet',
    kind: 'suricata',
    host: '192.0.2.10',
    ip: '198.51.100.7',
    verdict: 'needs_more_info',
    conf: 0.3,
    rationale: 'r',
    summary: [{ t: 'text', v: 's' }],
    status: 'complete',
    elapsedLabel: '4m 5s',
    actions: [],
    timeline: [],
    nodes: [],
    edges: [],
    seedChat: [],
    ...over,
  }) as Inv;

describe('chat identity across an inv swap (F40)', () => {
  it('drops a late chat reply for an investigation the drawer has since left', async () => {
    // Deferred — resolved by hand after the drawer has already switched to B.
    let resolvePostChat!: (t: ChatThread) => void;
    vi.mocked(postChat).mockReturnValueOnce(
      new Promise<ChatThread>((res) => { resolvePostChat = res; }),
    );

    const invA = baseInv({ id: 'INV-A', seedChat: [{ role: 'assistant', text: 'Seed A' }] });
    const invB = baseInv({ id: 'INV-B', seedChat: [{ role: 'assistant', text: 'Seed B' }] });

    const { rerender } = render(
      <MemoryRouter>
        <Investigation inv={invA} layout="drawer" />
      </MemoryRouter>,
    );

    await screen.findByText('Seed A');
    fireEvent.change(screen.getByPlaceholderText(/ask a follow-up/i), { target: { value: 'question to A' } });
    fireEvent.click(screen.getByLabelText('Send'));
    await screen.findByText('question to A');

    // The container re-hunts / swaps the drawer to a different investigation
    // before A's chat turn resolves.
    rerender(
      <MemoryRouter>
        <Investigation inv={invB} layout="drawer" />
      </MemoryRouter>,
    );
    await screen.findByText('Seed B');
    expect(screen.queryByText('question to A')).toBeNull();

    // A's reply now lands.
    resolvePostChat({
      messages: [
        { role: 'assistant', text: 'Seed A' },
        { role: 'user', text: 'question to A' },
        { role: 'assistant', text: 'Reply to A' },
      ],
      pending: false,
    });
    // Flush the resolved chain (Markdown render is async, so a plain
    // microtask flush isn't enough — wait a tick).
    await new Promise((r) => setTimeout(r, 0));

    expect(screen.queryByText('Reply to A')).toBeNull();
    expect(screen.getByText('Seed B')).toBeTruthy();
  });
});
