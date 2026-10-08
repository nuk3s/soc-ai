// A promoted investigation names its finding first (dogfood 2026-10-06,
// hunting C4). The page read as a hunt of the whole lead, marked no finding,
// and showed the raw model prompt as the objective. The control: a hunt
// subject with no promoted finding keeps its objective open.
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

import { Investigation } from './Investigation';

const PROMPT = 'Read each document id with get_event_raw.';

const inv = (over: Partial<Inv> = {}): Inv =>
  ({
    id: 'INV-1',
    groupId: 'doc-1',
    name: 'HTTP service executes id command as root',
    kind: 'hunt',
    host: '192.0.2.30',
    ip: '192.0.2.40',
    verdict: 'true_positive',
    conf: 0.75,
    rationale: 'The response holds uid=0.',
    summary: [{ t: 'text', v: 'x' }],
    status: 'complete',
    elapsedLabel: '4m',
    actions: [],
    timeline: [],
    nodes: [],
    edges: [],
    seedChat: [],
    huntId: 'H1',
    subject: {
      type: 'hunt',
      hunt_id: 'H1',
      objective: PROMPT,
      finding_ordinals: [0, 1],
      finding_titles: ['Port scan', 'HTTP service executes id command as root'],
      lead_id: 16,
      document_ids: ['doc-1', 'doc-2'],
      observation_ids: [],
    },
    promotedFinding: {
      ordinal: 1,
      label: 'F2',
      title: 'HTTP service executes id command as root',
      detail: 'The response from 192.0.2.40 holds uid=0.',
      hosts: ['192.0.2.40', '198.51.100.30'],
      citations: ['doc-1', 'doc-2'],
      attacker: '198.51.100.30',
      victim: '192.0.2.40',
      huntId: 'H1',
      huntTitle: 'Command execution on the web server',
    },
    ...over,
  }) as Inv;

const mount = (i: Inv) =>
  render(
    <MemoryRouter>
      <Investigation inv={i} layout="page" />
    </MemoryRouter>,
  );

describe('a promoted investigation', () => {
  it('names the finding first, with its evidence and its direction', () => {
    mount(inv());
    const panel = screen.getByTestId('promoted-finding');
    expect(panel.textContent).toContain('Promoted finding: F2, HTTP service executes id command as root');
    expect(within(screen.getByTestId('promoted-direction')).getAllByTestId('entity-link').map((a) => a.textContent)).toEqual([
      '198.51.100.30',
      '192.0.2.40',
    ]);
    expect(within(screen.getByTestId('promoted-evidence')).getAllByRole('button').length).toBe(2);
    expect(screen.getByTestId('verdict-subject').textContent).toBe(
      'F2, HTTP service executes id command as root',
    );
    expect(screen.getByTestId('subject-promoted')).toBeTruthy();
  });

  it('puts the prompt behind "Show objective"', () => {
    mount(inv());
    expect(screen.queryByText(PROMPT)).toBeNull();
    fireEvent.click(screen.getByTestId('show-objective'));
    expect(screen.getByText(PROMPT)).toBeTruthy();
  });

  it('lists the hosts when the finding states no direction', () => {
    mount(inv({ promotedFinding: { ...inv().promotedFinding!, attacker: null, victim: null } }));
    expect(screen.queryByTestId('promoted-direction')).toBeNull();
    expect(screen.getByTestId('promoted-hosts').textContent).toContain('Hosts the finding names:');
  });

  it('control: a hunt subject with no promoted finding keeps its objective open', () => {
    mount(inv({ promotedFinding: null }));
    expect(screen.queryByTestId('promoted-finding')).toBeNull();
    expect(screen.queryByTestId('show-objective')).toBeNull();
    expect(screen.getAllByText(PROMPT).length).toBeGreaterThan(0);
  });
});
