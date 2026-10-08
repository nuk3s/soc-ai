// The chat on the investigation page (dogfood 2026-10-06, C3, C4, K3, K4 and
// first hour W9), now the Ask soc-ai panel on the investigation scope (owner,
// 2026-10-07). "Resolve in chat" did nothing visible, a starter chip only
// filled the box, a proposal offered the verdict the page already had, and a
// cited recommendation had no control to act on it.
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { ChatMessage, Investigation as Inv } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getChatThread: vi.fn(),
  postChat: vi.fn(),
  resolveInvestigation: vi.fn(),
  getMe: vi.fn().mockResolvedValue({ username: 'analyst' }),
  getAbout: vi.fn().mockResolvedValue({}),
  getActionScope: vi.fn().mockResolvedValue(null),
}));

import { getChatThread, postChat, resolveInvestigation } from '../lib/api';
import { WithChat } from '../test/chatHarness';
import { Investigation, RESOLVE_PROMPT } from './Investigation';

const proposal = (verdict: 'true_positive' | 'false_positive'): ChatMessage =>
  ({
    role: 'assistant',
    text: 'x',
    kind: 'verdict_proposal',
    messageId: 7,
    token: 't',
    validation: 'pass',
    applied: false,
    proposal: { verdict, confidence: 0.8, rationale: 'The PCAP shows exfiltration.', citations: [] },
  }) as unknown as ChatMessage;

const inv = (over: Partial<Inv> = {}): Inv =>
  ({
    id: 'INV-1',
    groupId: 'ev-1',
    name: 'ET POLICY Rule',
    kind: 'suricata',
    host: '192.0.2.1',
    ip: '—',
    verdict: 'needs_more_info',
    conf: 0.5,
    rationale: 'The auth log would settle it.',
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

beforeEach(() => {
  sessionStorage.clear();
  vi.mocked(getChatThread).mockReset().mockResolvedValue({ messages: [], pending: false });
  vi.mocked(postChat).mockReset().mockResolvedValue({ messages: [], pending: true });
  vi.mocked(resolveInvestigation).mockReset().mockResolvedValue({});
});

const mount = (i: Inv, layout: 'page' | 'drawer' = 'page', onVerdictApplied?: () => void) =>
  render(
    <MemoryRouter>
      <WithChat>
        <Investigation inv={i} layout={layout} onVerdictApplied={onVerdictApplied} />
      </WithChat>
    </MemoryRouter>,
  );

/** The button in the top bar on the page; the drawer header carries a copy. */
const openPanel = () =>
  fireEvent.click(screen.getAllByRole('button', { name: 'Ask soc-ai about this investigation' })[0]);

describe('the investigation scope', () => {
  it('opens from the top bar button with the investigation on the scope line', () => {
    mount(inv());
    // Negative control: the panel is closed before the click.
    expect(screen.queryByRole('dialog', { name: 'Ask soc-ai' })).toBeNull();
    openPanel();
    expect(screen.getByRole('dialog', { name: 'Ask soc-ai' })).toBeTruthy();
    expect(screen.getByTestId('ask-scope-title').textContent).toBe('This investigation');
    expect(screen.getByTestId('ask-scope-name').textContent).toBe('ET POLICY Rule');
    expect(getChatThread).toHaveBeenCalledWith('INV-1');
  });

  it('puts the same button in the drawer header, because the drawer covers the top bar', () => {
    mount(inv(), 'drawer');
    // One in the harness top bar, one in the drawer's toolbar.
    expect(screen.getAllByRole('button', { name: 'Ask soc-ai about this investigation' })).toHaveLength(2);
  });

  it('mounts no in-page chat and no floating launcher', () => {
    mount(inv(), 'drawer');
    expect(screen.queryByPlaceholderText(/Ask a follow-up/)).toBeNull();
    expect(screen.queryByRole('button', { name: /chat about this/i })).toBeNull();
  });

  it('"Resolve in chat" opens the panel and asks the question', async () => {
    mount(inv());
    // Negative control: the panel is closed before the click.
    expect(screen.queryByPlaceholderText(/Ask a follow-up/)).toBeNull();
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /Resolve in chat/ }));
    });
    expect(screen.getByPlaceholderText(/Ask a follow-up/)).toBeTruthy();
    await waitFor(() => expect(postChat).toHaveBeenCalledWith('INV-1', RESOLVE_PROMPT));
  });

  it('"Resolve in chat" fills the box and sends nothing while a turn runs', async () => {
    vi.mocked(getChatThread).mockResolvedValue({ messages: [], pending: true });
    mount(inv());
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /Resolve in chat/ }));
    });
    await waitFor(() =>
      expect((screen.getByPlaceholderText(/Ask a follow-up/) as HTMLTextAreaElement).value).toBe(
        RESOLVE_PROMPT,
      ),
    );
    expect(postChat).not.toHaveBeenCalled();
  });

  it('a starter chip asks on click', async () => {
    mount(inv(), 'drawer');
    openPanel();
    await act(async () => {
      fireEvent.click(await screen.findByRole('button', { name: 'What should I check next?' }));
    });
    await waitFor(() => expect(postChat).toHaveBeenCalledWith('INV-1', 'What should I check next?'));
  });

  it('gives an example that argues against the verdict on screen', () => {
    mount(inv({ verdict: 'false_positive' }), 'drawer');
    openPanel();
    expect(screen.getByPlaceholderText('Ask a follow-up. Example: why not a true positive?')).toBeTruthy();
  });

  it('offers no Apply for the verdict the page already has', async () => {
    vi.mocked(getChatThread).mockResolvedValue({ messages: [proposal('false_positive')], pending: false });
    mount(inv({ verdict: 'false_positive', seedChat: [proposal('false_positive')] }), 'drawer');
    openPanel();
    expect(await screen.findByTestId('proposal-current')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Apply verdict' })).toBeNull();
  });

  it('a proposal in the answer shows Apply and Escalate inline, and Escalate opens the page confirm', async () => {
    vi.mocked(getChatThread).mockResolvedValue({ messages: [proposal('true_positive')], pending: false });
    mount(
      inv({
        seedChat: [proposal('true_positive')],
        actions: [{ id: 'a0', title: 'Escalate to case', tag: 'escalate', rationale: 'r' }],
      }),
      'drawer',
    );
    openPanel();
    expect(await screen.findByRole('button', { name: 'Apply verdict' })).toBeTruthy();
    fireEvent.click(screen.getByTestId('chat-escalate'));
    // The inline control opens the confirm of the escalate card. It writes nothing.
    expect(await screen.findByTestId('action-confirm')).toBeTruthy();
  });

  it('Apply verdict applies the proposal and tells the page', async () => {
    vi.mocked(getChatThread).mockResolvedValue({ messages: [proposal('true_positive')], pending: false });
    const applied = vi.fn();
    mount(inv({ seedChat: [proposal('true_positive')] }), 'page', applied);
    openPanel();
    await act(async () => {
      fireEvent.click(await screen.findByRole('button', { name: 'Apply verdict' }));
    });
    expect(resolveInvestigation).toHaveBeenCalledWith('INV-1', 7, 't');
    await waitFor(() => expect(applied).toHaveBeenCalled());
  });

  it('control: an answer with no proposal carries no Apply and no Escalate', async () => {
    vi.mocked(getChatThread).mockResolvedValue({
      messages: [{ role: 'assistant', text: 'The PCAP shows a TLS session only.' }],
      pending: false,
    });
    mount(
      inv({ actions: [{ id: 'a0', title: 'Escalate to case', tag: 'escalate', rationale: 'r' }] }),
      'drawer',
    );
    openPanel();
    expect(await screen.findByText('The PCAP shows a TLS session only.')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Apply verdict' })).toBeNull();
    expect(screen.queryByTestId('chat-escalate')).toBeNull();
  });
});
