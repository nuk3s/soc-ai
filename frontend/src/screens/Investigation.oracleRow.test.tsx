// The Oracle row and the model scratch work (dogfood 2026-10-06, O1). The
// word "Oracle" had no explanation, and the raw model monologue carried the
// weight of the narrative. The control: the scratch work stays folded until
// the analyst opens it.
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { Investigation as Inv } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getChatThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getMe: vi.fn().mockResolvedValue({ username: 'analyst' }),
  getAbout: vi.fn().mockResolvedValue({}),
}));

import { Investigation, ORACLE_TIP } from './Investigation';

const inv = {
  id: 'INV-1',
  groupId: 'ev-1',
  name: 'Rule',
  kind: 'suricata',
  host: '192.0.2.1',
  ip: '—',
  verdict: 'false_positive',
  conf: 0.7,
  rationale: 'Benign.',
  summary: [{ t: 'text', v: 'x' }],
  status: 'complete',
  elapsedLabel: '1m',
  actions: [],
  timeline: [],
  nodes: [],
  edges: [],
  seedChat: [],
  reasoning: ['I think the scan is routine.'],
  meta: {
    model: 'm',
    oracle: 'Oracle review: not needed. Confidence 0.70 is above the review band.',
    ranBy: 'analyst',
    ranAt: '2026-10-06T01:00:00+00:00',
    toolCalls: 2,
    pivots: 1,
  },
} as unknown as Inv;

describe('the Oracle row and the scratch work', () => {
  it('explains the Oracle on hover and says why no review ran', () => {
    render(
      <MemoryRouter>
        <Investigation inv={inv} layout="page" />
      </MemoryRouter>,
    );
    expect(screen.getByTestId('oracle-term').getAttribute('title')).toBe(ORACLE_TIP);
    expect(screen.getByTestId('oracle-line').textContent).toBe(
      'Oracle review: not needed. Confidence 0.70 is above the review band.',
    );
  });

  it('marks the model reasoning as scratch work and keeps it folded', () => {
    render(
      <MemoryRouter>
        <Investigation inv={inv} layout="page" />
      </MemoryRouter>,
    );
    expect(screen.getByText('Model notes')).toBeTruthy();
    expect(screen.queryByText('I think the scan is routine.')).toBeNull();
    fireEvent.click(screen.getByText('Model notes'));
    expect(screen.getByTestId('scratch-note').textContent).toContain('not evidence');
    expect(screen.getByText('I think the scan is routine.')).toBeTruthy();
  });
});
