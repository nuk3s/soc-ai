// The open questions block of an unsettled verdict (dogfood 2026-10-06, W2).
// With no recorded question it showed boilerplate that contradicted itself.
// It now shows the gap the rationale names. The negative control: a recorded
// question still wins, and no copy says "recorded no open questions".
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

const inv = (over: Partial<Inv>): Inv =>
  ({
    id: 'INV-1',
    groupId: 'ev-1',
    name: 'Kerberoast',
    kind: 'suricata',
    host: '192.0.2.1',
    ip: '—',
    verdict: 'needs_more_info',
    conf: 0.55,
    rationale: 'A TGS request for a service account. The 4769 log of the DC would show the encryption type.',
    summary: [{ t: 'text', v: 'x' }],
    status: 'complete',
    elapsedLabel: '1m',
    actions: [],
    timeline: [],
    nodes: [],
    edges: [],
    seedChat: [],
    ...over,
  }) as Inv;

const mount = (i: Inv) =>
  render(
    <MemoryRouter>
      <Investigation inv={i} layout="page" />
    </MemoryRouter>,
  );

describe('the open questions block', () => {
  it('shows the gap the rationale names when the run recorded none', () => {
    const { container } = mount(inv({ openQuestions: [] }));
    expect(screen.getByTestId('open-question-gap').textContent).toContain(
      'The 4769 log of the DC would show the encryption type.',
    );
    expect(container.textContent).not.toContain('recorded no open questions');
  });

  it('control: a recorded question wins over the rationale', () => {
    mount(inv({ openQuestions: ['Was the ticket RC4?'] }));
    expect(screen.getByText('Was the ticket RC4?')).toBeTruthy();
    expect(screen.queryByTestId('open-question-gap')).toBeNull();
  });
});
