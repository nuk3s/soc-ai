// A promoted finding names the hunt it came from. The API cut the hunt's
// objective at 160 characters, in the middle of a word, and the link showed
// the cut text. The API now sends the whole objective. The link shows its head
// line whole, and the hover holds the whole objective.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { Investigation as Inv } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getChatThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getMe: vi.fn().mockResolvedValue({ username: 'analyst' }),
}));

import { TITLE_180, bareCuts, showsWhole } from '../test/wholeTitle';
import { Investigation } from './Investigation';

const HUNT_ID = '01HUNTABC000000000000000000';

const promoted = (huntObjective: string | null): Inv =>
  ({
    id: 'INV-1',
    groupId: 'ev-1',
    name: 'Beaconing to rare external IP',
    kind: 'hunt',
    host: '192.0.2.10',
    ip: '198.51.100.7',
    verdict: 'true_positive',
    conf: 0.8,
    rationale: 'promoted finding',
    summary: [{ t: 'text', v: 'evidence' }],
    status: 'complete',
    elapsedLabel: '4m 5s',
    actions: [],
    timeline: [],
    nodes: [],
    edges: [],
    seedChat: [],
    huntId: HUNT_ID,
    huntObjective,
  }) as Inv;

const mount = (inv: Inv) =>
  render(
    <MemoryRouter>
      <Investigation inv={inv} layout="page" />
    </MemoryRouter>,
  );

describe('Investigation names its source hunt whole', () => {
  it('shows a 180 character objective whole on every source hunt link', () => {
    mount(promoted(TITLE_180));
    const links = screen.getAllByTestId('source-hunt-link');
    expect(links.length).toBeGreaterThan(0);
    for (const link of links) {
      expect(link.textContent).toBe(TITLE_180);
      expect(link.getAttribute('title')).toBe(TITLE_180);
      expect(link.getAttribute('href')).toBe(`/hunts/${HUNT_ID}`);
    }
    expect(showsWhole(document.body, TITLE_180)).toBe(true);
    expect(bareCuts(document.body, TITLE_180)).toEqual([]);
  });

  it('shows the head line of a multi-line objective and holds the rest on the hover', () => {
    const head =
      '[lead 7] Investigate 192.0.2.10. The lead formed from a new destination and off hours and a collapsed rate on the weekend.';
    const objective = `${head}\nObservations:\n- first connection to 198.51.100.4\n- active at 03:00`;
    mount(promoted(objective));
    const [link] = screen.getAllByTestId('source-hunt-link');
    expect(link.textContent).toBe(head);
    expect(link.getAttribute('title')).toBe(objective);
  });

  it('renders a short objective unchanged', () => {
    mount(promoted('Sweep for beaconing to rare external IPs'));
    const [link] = screen.getAllByTestId('source-hunt-link');
    expect(link.textContent).toBe('Sweep for beaconing to rare external IPs');
  });

  it('falls back to the hunt id when the hunt was deleted', () => {
    mount(promoted(null));
    const [link] = screen.getAllByTestId('source-hunt-link');
    expect(link.textContent).toBe(HUNT_ID);
    expect(link.getAttribute('title')).toBeNull();
  });
});
