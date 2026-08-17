// The Dashboard's "Ask soc-ai" box was a hand-off: it prefilled the Hunt
// Console's objective and navigated, so "what datasets do I have?" became a
// multi-minute background job producing a formal report. This panel answers in
// the turn instead, and when a question genuinely needs a sweep the agent
// PROPOSES one that the analyst confirms.
//
// The properties pinned here are the ones that make it more than a chat window:
// the answer lands on the Dashboard, a long turn shows what the agent is doing
// (a bare typing indicator reads as "hung" — dogfood 2026-08-06), and the
// proposed hunt never starts itself.
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { ChatThread } from '../lib/api';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getGeneralChat: vi.fn(),
  postGeneralChat: vi.fn(),
  clearGeneralChat: vi.fn(),
  startHuntConsole: vi.fn(),
}));

import { GeneralChatPanel } from './GeneralChatPanel';
import { clearGeneralChat, getGeneralChat, postGeneralChat, startHuntConsole } from '../lib/api';

type Msg = ChatThread['messages'][number];

const thread = (messages: Msg[], over: Partial<ChatThread> = {}): ChatThread => ({
  messages,
  pending: false,
  ...over,
});

const said = (text: string): Msg => ({ role: 'assistant', text });

/** A hunt-proposal row exactly as the backend serializes it — `applied` is
 *  `false`, not absent, on these rows. No cast: `ChatMessage` discriminates on
 *  `kind`, so this fixture is checked against the same union the panel reads. */
const proposed = (objective: string, why: string, text = 'Nothing obvious in the last hour.'): Msg => ({
  role: 'assistant',
  text,
  messageId: 7,
  kind: 'hunt_proposal',
  applied: false,
  proposal: { objective, why },
});

function Here() {
  const loc = useLocation();
  return <div data-testid="here">{loc.pathname}</div>;
}

const here = () => screen.getByTestId('here').textContent;

const mount = () =>
  render(
    <MemoryRouter initialEntries={['/dashboard']}>
      <GeneralChatPanel />
      <Here />
    </MemoryRouter>,
  );

const ask = (text: string) => {
  fireEvent.change(screen.getByPlaceholderText(/ask/i), { target: { value: text } });
  fireEvent.click(screen.getByLabelText('Send'));
};

beforeEach(() => {
  sessionStorage.clear(); // the draft is persisted per thread
  vi.clearAllMocks(); // calls accumulate across tests; several assert on call[0]
  vi.mocked(getGeneralChat).mockResolvedValue(thread([]));
  vi.mocked(postGeneralChat).mockResolvedValue(thread([]));
  vi.mocked(clearGeneralChat).mockResolvedValue(thread([]));
  vi.mocked(startHuntConsole).mockResolvedValue({ hunt_id: 'H-1' });
});

describe('GeneralChatPanel — the answer arrives here', () => {
  it('restores the rolling thread on mount', async () => {
    // Persistent per-analyst thread: the Dashboard is a launcher screen and the
    // analyst navigates away constantly, so history has to survive the mount.
    vi.mocked(getGeneralChat).mockResolvedValue(thread([said('You have 3 datasets.')]));
    mount();
    expect(await screen.findByText('You have 3 datasets.')).toBeTruthy();
  });

  it('answers in the panel instead of navigating to the Hunt Console', async () => {
    mount();
    vi.mocked(postGeneralChat).mockResolvedValue(
      thread([{ role: 'user', text: 'noisiest rule?' }, said('ET SCAN, 412 events.')]),
    );
    ask('noisiest rule?');

    expect(await screen.findByText('ET SCAN, 412 events.')).toBeTruthy();
    expect(vi.mocked(postGeneralChat).mock.calls[0][0]).toBe('noisiest rule?');
    // The old box's whole behaviour was this navigation. It must be gone.
    expect(here()).toBe('/dashboard');
  });

  it('says what the agent is doing while the turn is in flight', async () => {
    vi.mocked(getGeneralChat).mockResolvedValue(
      thread([], { pending: true, progress_tools: ['t_query_events_oql'] }),
    );
    mount();
    expect(await screen.findByText(/Querying events/i)).toBeTruthy();
  });
});

describe('GeneralChatPanel — the hunt proposal', () => {
  it('shows the objective and why the sweep is needed, alongside the answer', async () => {
    vi.mocked(getGeneralChat).mockResolvedValue(
      thread([proposed('Sweep zeek.conn for periodic egress over 7d', 'one turn cannot cover a week')]),
    );
    mount();

    expect(await screen.findByText('Sweep zeek.conn for periodic egress over 7d')).toBeTruthy();
    expect(screen.getByText(/one turn cannot cover a week/)).toBeTruthy();
    // The proposal rides on the SAME row as the answer; a card that replaced it
    // would throw away what the agent already established.
    expect(screen.getByText('Nothing obvious in the last hour.')).toBeTruthy();
  });

  it('never starts the hunt on its own', async () => {
    vi.mocked(getGeneralChat).mockResolvedValue(thread([proposed('Sweep zeek.conn over 7d', 'why')]));
    mount();
    await screen.findByText('Sweep zeek.conn over 7d');

    // The analyst confirms — nothing about rendering a proposal may launch a
    // multi-minute background job.
    expect(startHuntConsole).not.toHaveBeenCalled();
    expect(here()).toBe('/dashboard');
  });

  it('starts the agent-written objective on confirm and opens the hunt', async () => {
    vi.mocked(getGeneralChat).mockResolvedValue(thread([proposed('Sweep zeek.conn over 7d', 'why')]));
    mount();
    fireEvent.click(await screen.findByRole('button', { name: /start.*hunt/i }));

    expect(startHuntConsole).toHaveBeenCalledWith('Sweep zeek.conn over 7d');
    // Optimistic navigation to the live hunt, same as the Hunt Console's own box.
    expect(await screen.findByText('/hunts/H-1')).toBeTruthy();
  });

  it('clamps the objective to what the hunt endpoint accepts', async () => {
    // A model that runs long must not produce a card that 422s on click
    // (dogfood r3: "422 on large hunt objective").
    const long = 'x'.repeat(13_000);
    vi.mocked(getGeneralChat).mockResolvedValue(thread([proposed(long, 'why')]));
    mount();
    fireEvent.click(await screen.findByRole('button', { name: /start.*hunt/i }));

    expect(vi.mocked(startHuntConsole).mock.calls[0][0].length).toBe(12_000);
  });

  it('keeps the analyst on the Dashboard when the hunt will not start', async () => {
    vi.mocked(getGeneralChat).mockResolvedValue(thread([proposed('Sweep zeek.conn over 7d', 'why')]));
    vi.mocked(startHuntConsole).mockRejectedValue(new Error('hunts are disabled'));
    mount();
    fireEvent.click(await screen.findByRole('button', { name: /start.*hunt/i }));

    expect(await screen.findByText(/hunts are disabled/)).toBeTruthy();
    expect(here()).toBe('/dashboard');
  });

  it('renders an ordinary answer as prose, with no start control', async () => {
    vi.mocked(getGeneralChat).mockResolvedValue(thread([said('You have 3 datasets.')]));
    mount();
    await screen.findByText('You have 3 datasets.');
    expect(screen.queryByRole('button', { name: /start.*hunt/i })).toBeNull();
  });
});

describe('GeneralChatPanel — starting over', () => {
  it('offers no clear control on a thread with nothing in it', async () => {
    mount();
    await screen.findByPlaceholderText(/ask/i);
    expect(screen.queryByRole('button', { name: /clear/i })).toBeNull();
  });

  it('discards this analyst’s thread and re-reads it', async () => {
    // The thread is PERSISTENT and per-analyst, so without this the scratchpad
    // is permanent — and its history is what the next turn's prompt carries.
    vi.mocked(getGeneralChat).mockResolvedValue(thread([said('You have 3 datasets.')]));
    mount();
    await screen.findByText('You have 3 datasets.');

    vi.mocked(getGeneralChat).mockResolvedValue(thread([]));
    fireEvent.click(screen.getByRole('button', { name: /clear/i }));

    expect(clearGeneralChat).toHaveBeenCalled();
    expect(await screen.findByText(/answered here/i)).toBeTruthy(); // back to the empty hint
  });
});
