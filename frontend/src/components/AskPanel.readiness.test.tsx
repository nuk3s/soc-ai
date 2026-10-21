// The chat panel and the Dashboard Ask card with a dead model gateway
// (dogfood 2026-10-19, H1-D13): the starters and the Send looked ready, and
// the send failed after the turn started.
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Health } from '../lib/api';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getHealth: vi.fn(),
  getGeneralChat: vi.fn(),
  postGeneralChat: vi.fn(),
}));

import { getGeneralChat, getHealth, postGeneralChat } from '../lib/api';
import { resetSharedHealth } from '../lib/chatReadiness';
import { WithChat } from '../test/chatHarness';
import { AskSocAiCard } from './AskPanel';

const up = { ok: true, detail: 'ok' };
const down = { ok: false, detail: 'Connection refused' };

beforeEach(() => {
  sessionStorage.clear();
  vi.clearAllMocks();
  resetSharedHealth();
  vi.mocked(getGeneralChat).mockResolvedValue({ messages: [], pending: false });
  vi.mocked(postGeneralChat).mockResolvedValue({ messages: [], pending: true });
});

const mount = () =>
  render(
    <MemoryRouter initialEntries={['/dashboard']}>
      <WithChat>
        <AskSocAiCard />
      </WithChat>
    </MemoryRouter>,
  );

describe('a dead model gateway', () => {
  beforeEach(() => {
    vi.mocked(getHealth).mockResolvedValue({ es: down, llm: down, so: up } as Health);
  });

  it('the Ask card says why and turns its starters off', async () => {
    mount();
    const state = await screen.findByTestId('ask-card-state');
    expect(state).toHaveTextContent('The model gateway does not answer.');
    expect(state).toHaveTextContent('The grid does not answer.');
    const card = screen.getByTestId('ask-card');
    for (const chip of card.querySelectorAll('button[title]')) expect(chip).toBeDisabled();
  });

  it('the panel turns the send off and sends nothing', async () => {
    mount();
    fireEvent.click(screen.getByRole('button', { name: 'Ask soc-ai' }));
    const send = await screen.findByLabelText('Send');
    await waitFor(() => expect(send).toBeDisabled());
    fireEvent.change(screen.getByPlaceholderText(/ask/i), { target: { value: 'What changed?' } });
    fireEvent.click(send);
    expect(postGeneralChat).not.toHaveBeenCalled();
  });
});

describe('a working model gateway', () => {
  it('shows no state and sends', async () => {
    vi.mocked(getHealth).mockResolvedValue({ es: up, llm: up, so: up } as Health);
    mount();
    fireEvent.click(screen.getByRole('button', { name: 'Ask soc-ai' }));
    await waitFor(() => expect(getHealth).toHaveBeenCalled());
    expect(screen.queryByTestId('ask-card-state')).toBeNull();
    fireEvent.change(screen.getByPlaceholderText(/ask/i), { target: { value: 'What changed?' } });
    fireEvent.click(screen.getByLabelText('Send'));
    await waitFor(() => expect(postGeneralChat).toHaveBeenCalledWith('What changed?'));
  });
});
