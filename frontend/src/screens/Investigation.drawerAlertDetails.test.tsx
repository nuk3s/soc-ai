// Alert details in the drawer (dogfood 2026-10-06, first hour W4). The panel
// was on the full page only. The drawer now shows four lines: rule, source,
// destination and user, with the other fields behind a toggle. The source
// links its address, with the port as text.
import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { Investigation as Inv } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getChatThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getMe: vi.fn().mockResolvedValue({ username: 'analyst' }),
  getAbout: vi.fn().mockResolvedValue({}),
}));

import { Investigation, splitEndpoint } from './Investigation';

const inv = {
  id: 'INV-1',
  groupId: 'ev-1',
  name: 'Grid Node Login Failure',
  kind: 'sigma',
  host: '192.0.2.226',
  ip: '—',
  verdict: 'false_positive',
  conf: 0.68,
  rationale: 'Benign.',
  summary: [{ t: 'text', v: 'x' }],
  status: 'complete',
  elapsedLabel: '1m',
  actions: [],
  timeline: [],
  nodes: [],
  edges: [],
  seedChat: [],
  alert: {
    id: 'es-1',
    rule: 'Grid Node Login Failure',
    sid: '1001',
    src: '192.0.2.226:52100',
    dst: '192.0.2.10:22',
    proto: 'tcp',
    action: 'allowed',
    count: 6,
    user: 'svc_backup',
  },
} as unknown as Inv;

describe('Alert details in the drawer', () => {
  it('shows rule, source, destination and user, and the rest behind a toggle', () => {
    render(
      <MemoryRouter>
        <Investigation inv={inv} layout="drawer" />
      </MemoryRouter>,
    );
    const panel = screen.getByTestId('drawer-alert-details');
    expect(panel.textContent).toContain('Grid Node Login Failure');
    expect(panel.textContent).toContain('svc_backup');
    const src = within(panel).getAllByTestId('entity-link')[0];
    expect(src.textContent).toBe('192.0.2.226');
    expect(panel.textContent).toContain(':52100');
    // The other fields wait behind the toggle.
    expect(panel.textContent).not.toContain('1001');
    fireEvent.click(within(panel).getByRole('button', { name: 'Show all fields' }));
    expect(panel.textContent).toContain('1001');
  });

  it('splits an address from its port and keeps any other value whole', () => {
    expect(splitEndpoint('10.0.0.1:443')).toEqual({ addr: '10.0.0.1', port: '443' });
    expect(splitEndpoint('ws-01')).toEqual({ addr: 'ws-01', port: null });
  });
});
