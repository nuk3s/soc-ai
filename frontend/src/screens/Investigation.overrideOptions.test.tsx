// The override select printed the stored keys: "true_positive",
// "false_positive", "needs_more_info". The options now read the words from
// lib/labels.ts, and the values stay the keys the API takes.
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { Investigation as Inv } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getChatThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getMe: vi.fn().mockResolvedValue({ username: 'analyst' }),
}));

import { Investigation } from './Investigation';

const inv = {
  id: 'INV-1',
  groupId: 'ev-1',
  name: 'GPL ICMP Large ICMP Packet',
  kind: 'suricata',
  host: '192.0.2.10',
  ip: '198.51.100.7',
  verdict: 'false_positive',
  conf: 0.82,
  rationale: 'benign',
  summary: [{ t: 'text', v: 'benign' }],
  status: 'complete',
  elapsedLabel: '4m 5s',
  actions: [],
  timeline: [],
  nodes: [],
  edges: [],
  seedChat: [],
} as unknown as Inv;

describe('override verdict select', () => {
  it('lists the verdicts in words and keeps the stored keys as values', () => {
    render(
      <MemoryRouter>
        <Investigation inv={inv} layout="page" />
      </MemoryRouter>,
    );
    fireEvent.click(screen.getByRole('button', { name: /Override verdict/ }));
    // The first option is the "Choose a verdict" prompt: nothing is
    // preselected (dogfood 2026-10-06, first hour C5). The current verdict is
    // marked and cannot be chosen again.
    const all = screen.getAllByRole('option') as HTMLOptionElement[];
    expect(all[0].value).toBe('');
    const options = all.slice(1);
    expect(options.map((o) => o.textContent)).toEqual([
      'True positive',
      'False positive (the current verdict)',
      'Needs more info',
    ]);
    expect(options.map((o) => o.value)).toEqual(['true_positive', 'false_positive', 'needs_more_info']);
    // Negative control: no option prints a stored key.
    for (const o of options) expect(o.textContent).not.toMatch(/_/);
  });
});
