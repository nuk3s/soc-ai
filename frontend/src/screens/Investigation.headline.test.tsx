// The headline holds no field path; the path is a cited evidence chip
// (dogfood 2026-10-06, investigation C1). The control: a headline with no
// path shows no path chip.
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

const inv = (rationale: string): Inv =>
  ({
    id: 'INV-1',
    groupId: 'ev-1',
    name: 'Rule',
    kind: 'suricata',
    host: '192.0.2.1',
    ip: '—',
    verdict: 'true_positive',
    conf: 0.9,
    rationale,
    summary: [{ t: 'text', v: 'x' }],
    status: 'complete',
    elapsedLabel: '1m',
    actions: [],
    timeline: [],
    nodes: [],
    edges: [],
    seedChat: [],
  }) as Inv;

const mount = (i: Inv) =>
  render(
    <MemoryRouter>
      <Investigation inv={i} layout="page" />
    </MemoryRouter>,
  );

describe('the headline', () => {
  it('moves a field path to a cited evidence chip', () => {
    const { container } = mount(inv('The exploit ran (alert.rule_metadata.metadata_tags).'));
    expect(screen.getByText('The exploit ran.')).toBeTruthy();
    expect(screen.getByTestId('cited-path').textContent).toBe('alert.rule_metadata.metadata_tags');
    expect(container.querySelector('.text-\\[21px\\]')?.textContent).not.toContain('alert.rule_metadata');
  });

  it('control: a plain headline has no path chip', () => {
    mount(inv('The exploit ran.'));
    expect(screen.queryByTestId('cited-path')).toBeNull();
  });
});
