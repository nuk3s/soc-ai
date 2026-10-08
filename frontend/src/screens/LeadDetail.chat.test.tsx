// The lead page and the Ask soc-ai panel (owner, 2026-10-07). The lead page
// had no chat. It claims the lead scope now, and the panel talks to the lead's
// own shared thread.
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { ChatThread } from '../lib/api';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getLead: vi.fn(),
  getHunts: vi.fn().mockResolvedValue([]),
  getNeedsYou: vi.fn().mockResolvedValue(null),
  resolveMachine: vi.fn().mockRejectedValue(new Error('no machine')),
  getMachine: vi.fn(),
  getEvent: vi.fn().mockRejectedValue(new Error('not read in this test')),
  getLeadChat: vi.fn(),
  postLeadChat: vi.fn(),
  clearLeadChat: vi.fn(),
  getGeneralChat: vi.fn(),
  startHuntConsole: vi.fn(),
}));

import { clearLeadChat, getGeneralChat, getLead, getLeadChat, postLeadChat } from '../lib/api';
import { WithChat } from '../test/chatHarness';
import { LeadDetail } from './LeadDetail';

const LEAD = {
  id: 12,
  status: 'open',
  formed_at: '2026-09-18T10:00:00Z',
  updated_at: null,
  entities: [['host', '10.1.2.3']],
  kinds: ['off_hours'],
  weight_at_formation: 1.3,
  weight_now: 1.28,
  scope_count: 1,
  hunt_id: null,
  shadow: false,
  single_signal: false,
  dismissed_reason: null,
  dismissed_note: null,
  dismissed_by: null,
  dismissed_at: null,
  investigation_id: null,
  dismiss_reasons: ['other'],
  observations: [
    {
      id: 2, kind: 'off_hours', spec_id: 'profile-activity-outside-measured-hours',
      summary: 'active around 03:00 UTC, outside the hours this host is normally active',
      occurrences: 1, born_at: '2026-09-18T07:00:00Z', first_seen_at: '2026-09-18T07:00:00Z',
      source: 'profile', shadow: false, weight_now: 0.28, birth_weight: 0.3, evidence: null,
    },
  ],
};

const thread = (messages: ChatThread['messages'], over: Partial<ChatThread> = {}): ChatThread => ({
  messages,
  pending: false,
  ...over,
});

const mount = (at = '/leads/12') =>
  render(
    <MemoryRouter initialEntries={[at]}>
      <WithChat>
        <Routes>
          <Route path="/leads/:id" element={<LeadDetail />} />
        </Routes>
      </WithChat>
    </MemoryRouter>,
  );

beforeEach(() => {
  sessionStorage.clear();
  vi.mocked(getLead).mockReset().mockResolvedValue(LEAD as never);
  vi.mocked(getLeadChat).mockReset().mockResolvedValue(thread([]));
  vi.mocked(postLeadChat).mockReset().mockResolvedValue(thread([], { pending: true }));
  vi.mocked(clearLeadChat).mockReset().mockResolvedValue(thread([]));
  vi.mocked(getGeneralChat).mockReset().mockResolvedValue(thread([]));
});

describe('the lead scope', () => {
  it('opens from the top bar button with the lead on the scope line', async () => {
    mount();
    fireEvent.click(await screen.findByRole('button', { name: 'Ask soc-ai about this lead' }));
    expect(screen.getByTestId('ask-scope-title').textContent).toBe('This lead');
    expect(screen.getByTestId('ask-scope-name').textContent).toBe('Lead 12');
    await waitFor(() => expect(getLeadChat).toHaveBeenCalledWith('12'));
    // Negative control: the lead scope reads the lead's thread, not the general one.
    expect(getGeneralChat).not.toHaveBeenCalled();
  });

  it('a starter asks the lead thread on click', async () => {
    mount();
    fireEvent.click(await screen.findByRole('button', { name: 'Ask soc-ai about this lead' }));
    await act(async () => {
      fireEvent.click(await screen.findByRole('button', { name: 'Why did this lead form?' }));
    });
    await waitFor(() => expect(postLeadChat).toHaveBeenCalledWith('12', 'Why did this lead form?'));
  });

  it('shows the hunt card when the answer proposes a sweep, and none for a plain answer', async () => {
    vi.mocked(getLeadChat).mockResolvedValue(
      thread([
        { role: 'assistant', text: 'The host was active at 03:00 once.' },
        {
          role: 'assistant',
          text: 'One night is not a pattern.',
          messageId: 9,
          kind: 'hunt_proposal',
          applied: false,
          proposal: { objective: 'Sweep the host logons over 14d', why: 'a pattern needs two weeks' },
        },
      ]),
    );
    mount();
    fireEvent.click(await screen.findByRole('button', { name: 'Ask soc-ai about this lead' }));
    expect(await screen.findByText('Sweep the host logons over 14d')).toBeTruthy();
    // One card for the one proposal. The plain answer carries no control.
    expect(screen.getAllByRole('button', { name: /start.*hunt/i })).toHaveLength(1);
  });

  it('clears the lead thread only', async () => {
    vi.mocked(getLeadChat).mockResolvedValue(thread([{ role: 'assistant', text: 'An answer.' }]));
    mount();
    fireEvent.click(await screen.findByRole('button', { name: 'Ask soc-ai about this lead' }));
    await screen.findByText('An answer.');
    vi.mocked(getLeadChat).mockResolvedValue(thread([]));
    fireEvent.click(screen.getByRole('button', { name: 'Clear conversation' }));
    await waitFor(() => expect(clearLeadChat).toHaveBeenCalledWith('12'));
  });

  it('offers the general thread on a lead that could not be read', async () => {
    vi.mocked(getLead).mockRejectedValue(new Error('grid down'));
    mount();
    expect(await screen.findByRole('button', { name: 'Ask soc-ai' })).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Ask soc-ai about this lead' })).toBeNull();
  });
});
