// The one chat (owner, 2026-10-07: "We need to uniform how the AI chat feature
// works. Sometimes it is a collapsible bubble, sometimes it is a panel.").
//
// What these pin about the Ask soc-ai panel, scope by scope:
//   * one button opens it, and its label names the object the page shows;
//   * each scope keeps its own thread, and its draft survives a close;
//   * the general scope is one thread on every page;
//   * focus moves into the input on open and back to the opener on close,
//     and Escape closes the panel, never a drawer under it;
//   * the shortcut opens it, but not while the analyst types.
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { useState } from 'react';
import { Link, MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { ChatThread } from '../lib/api';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getGeneralChat: vi.fn(),
  postGeneralChat: vi.fn(),
  clearGeneralChat: vi.fn(),
  getHostChat: vi.fn(),
  postHostChat: vi.fn(),
  getChatThread: vi.fn(),
  postChat: vi.fn(),
}));

import { getGeneralChat, getHostChat, postGeneralChat, postHostChat } from '../lib/api';
import { ScopedPage, WithChat } from '../test/chatHarness';
import { Drawer } from './Drawer';

// TEST-NET-1 (RFC 5737). The leak gate reads tests too.
const HOST_A = '192.0.2.10';
const HOST_B = '192.0.2.11';

const thread = (messages: ChatThread['messages'], over: Partial<ChatThread> = {}): ChatThread => ({
  messages,
  pending: false,
  ...over,
});
const said = (text: string): ChatThread['messages'][number] => ({ role: 'assistant', text });

/** Two plain pages, two host pages, and links between them. */
function App({ generalEnabled = true, at = '/alerts' }: { generalEnabled?: boolean; at?: string }) {
  return (
    <MemoryRouter initialEntries={[at]}>
      <WithChat generalEnabled={generalEnabled}>
        <nav>
          <Link to="/alerts">Alerts page</Link>
          <Link to="/hunts">Hunts page</Link>
          <Link to={`/hosts/${HOST_A}`}>Host A page</Link>
          <Link to={`/hosts/${HOST_B}`}>Host B page</Link>
        </nav>
        <input aria-label="Filter" />
        <Routes>
          <Route path="/alerts" element={<div data-testid="page-alerts" />} />
          <Route path="/hunts" element={<div data-testid="page-hunts" />} />
          <Route
            path={`/hosts/${HOST_A}`}
            element={<ScopedPage key="a" scope={{ kind: 'host', id: HOST_A, name: 'web-01' }} />}
          />
          <Route
            path={`/hosts/${HOST_B}`}
            element={<ScopedPage key="b" scope={{ kind: 'host', id: HOST_B, name: 'db-01' }} />}
          />
        </Routes>
      </WithChat>
    </MemoryRouter>
  );
}

const panel = () => screen.queryByRole('dialog', { name: 'Ask soc-ai' });
const input = () => screen.getByPlaceholderText(/^Ask /) as HTMLTextAreaElement;
const go = (name: string) => fireEvent.click(screen.getByRole('link', { name }));

beforeEach(() => {
  sessionStorage.clear();
  vi.clearAllMocks();
  vi.mocked(getGeneralChat).mockResolvedValue(thread([]));
  vi.mocked(postGeneralChat).mockResolvedValue(thread([], { pending: true }));
  vi.mocked(getHostChat).mockImplementation(async (ip) =>
    thread([said(ip === HOST_A ? 'Host A is a web server.' : 'Host B is a database.')]),
  );
  vi.mocked(postHostChat).mockResolvedValue(thread([], { pending: true }));
});

describe('the button', () => {
  it('names the object of the page, and reads plain on a page with none', () => {
    render(<App />);
    expect(screen.getByRole('button', { name: 'Ask soc-ai' })).toBeTruthy();
    go('Host A page');
    expect(screen.getByRole('button', { name: 'Ask soc-ai about this host' })).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Ask soc-ai' })).toBeNull();
  });

  it('is absent on a page with no object when the general chat is off', () => {
    render(<App generalEnabled={false} />);
    expect(screen.queryByRole('button', { name: /^Ask soc-ai/ })).toBeNull();
    // Control: an object scope has no switch, so the host page still offers it.
    go('Host A page');
    fireEvent.click(screen.getByRole('button', { name: 'Ask soc-ai about this host' }));
    expect(panel()).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Switch to general' })).toBeNull();
  });
});

describe('focus and Escape', () => {
  it('moves the focus into the input on open, and Escape returns it to the button', async () => {
    render(<App />);
    const button = screen.getByRole('button', { name: 'Ask soc-ai' });
    button.focus();
    fireEvent.click(button);
    expect(panel()).toBeTruthy();
    expect(document.activeElement).toBe(input());

    fireEvent.keyDown(document.activeElement!, { key: 'Escape' });
    expect(panel()).toBeNull();
    expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Ask soc-ai' }));
  });

  it('the close control returns the focus too', () => {
    render(<App />);
    const button = screen.getByRole('button', { name: 'Ask soc-ai' });
    button.focus();
    fireEvent.click(button);
    fireEvent.click(screen.getByRole('button', { name: 'Close Ask soc-ai' }));
    expect(panel()).toBeNull();
    expect(document.activeElement).toBe(button);
  });

  it('Escape closes the panel and leaves a drawer under it open', () => {
    function DrawerPage() {
      const [open, setOpen] = useState(true);
      return (
        <Drawer open={open} onClose={() => setOpen(false)} ariaLabel="Alert report">
          <ScopedPage scope={{ kind: 'host', id: HOST_A, name: 'web-01' }} />
          <span>drawer body</span>
        </Drawer>
      );
    }
    render(
      <MemoryRouter>
        <WithChat>
          <DrawerPage />
        </WithChat>
      </MemoryRouter>,
    );
    fireEvent.click(screen.getByRole('button', { name: 'Ask soc-ai about this host' }));
    expect(panel()).toBeTruthy();
    fireEvent.keyDown(input(), { key: 'Escape' });
    expect(panel()).toBeNull();
    // Negative control: the drawer did not take the same key.
    expect(screen.getByRole('dialog', { name: 'Alert report' })).toBeTruthy();
    // A second Escape, with the panel gone, is the drawer's.
    fireEvent.keyDown(document.body, { key: 'Escape' });
    expect(screen.queryByRole('dialog', { name: 'Alert report' })).toBeNull();
  });
});

describe('the shortcut', () => {
  it('opens the panel on the page scope', () => {
    render(<App at={`/hosts/${HOST_A}`} />);
    fireEvent.keyDown(document.body, { key: 'c' });
    expect(panel()).toBeTruthy();
    expect(screen.getByTestId('ask-scope-title').textContent).toBe('This host');
  });

  it('does not fire while the analyst types in a field', () => {
    render(<App />);
    const filter = screen.getByRole('textbox', { name: 'Filter' });
    filter.focus();
    fireEvent.keyDown(filter, { key: 'c' });
    expect(panel()).toBeNull();
  });
});

describe('a thread per scope', () => {
  it('keeps each host thread apart, and reads it again on reopen', async () => {
    render(<App at={`/hosts/${HOST_A}`} />);
    fireEvent.click(screen.getByRole('button', { name: 'Ask soc-ai about this host' }));
    expect(await screen.findByText('Host A is a web server.')).toBeTruthy();

    // The panel follows the page to the next host and shows that host's thread.
    go('Host B page');
    expect(await screen.findByText('Host B is a database.')).toBeTruthy();
    expect(screen.queryByText('Host A is a web server.')).toBeNull();
    expect(screen.getByTestId('ask-scope-name').textContent).toBe('db-01');

    // Close and reopen: the same thread comes back from the server.
    fireEvent.click(screen.getByRole('button', { name: 'Close Ask soc-ai' }));
    expect(panel()).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Ask soc-ai about this host' }));
    expect(await screen.findByText('Host B is a database.')).toBeTruthy();
    expect(vi.mocked(getHostChat).mock.calls.map((c) => c[0])).toEqual([HOST_A, HOST_B, HOST_B]);
  });

  it('keeps the draft of each scope when the panel closes', () => {
    render(<App at={`/hosts/${HOST_A}`} />);
    fireEvent.click(screen.getByRole('button', { name: 'Ask soc-ai about this host' }));
    fireEvent.change(input(), { target: { value: 'who is on port 22?' } });
    fireEvent.click(screen.getByRole('button', { name: 'Close Ask soc-ai' }));
    fireEvent.click(screen.getByRole('button', { name: 'Ask soc-ai about this host' }));
    expect(input().value).toBe('who is on port 22?');

    // Another scope has its own draft. Negative control: it starts empty.
    fireEvent.click(screen.getByRole('button', { name: 'Switch to general' }));
    expect(input().value).toBe('');
    fireEvent.click(screen.getByRole('button', { name: 'Back to this host' }));
    expect(input().value).toBe('who is on port 22?');
  });

  it('states the scope at the top and switches to the general thread and back', async () => {
    vi.mocked(getGeneralChat).mockResolvedValue(thread([said('You have 3 datasets.')]));
    render(<App at={`/hosts/${HOST_A}`} />);
    fireEvent.click(screen.getByRole('button', { name: 'Ask soc-ai about this host' }));
    expect(screen.getByTestId('ask-scope-title').textContent).toBe('This host');

    fireEvent.click(screen.getByRole('button', { name: 'Switch to general' }));
    expect(screen.getByTestId('ask-scope-title').textContent).toBe('General');
    expect(await screen.findByText('You have 3 datasets.')).toBeTruthy();
    expect(screen.queryByText('Host A is a web server.')).toBeNull();
    // The switch moves the focus into the new thread's input.
    expect(document.activeElement).toBe(input());

    fireEvent.click(screen.getByRole('button', { name: 'Back to this host' }));
    expect(await screen.findByText('Host A is a web server.')).toBeTruthy();
  });
});

describe('the general scope is one thread', () => {
  it('shows the same thread on every page with no object, and on a host page after the switch', async () => {
    vi.mocked(getGeneralChat).mockResolvedValue(thread([]));
    vi.mocked(postGeneralChat).mockResolvedValue(
      thread([{ role: 'user', text: 'noisiest rule?' }, said('ET SCAN, 412 events.')]),
    );
    render(<App />);
    fireEvent.click(screen.getByRole('button', { name: 'Ask soc-ai' }));
    fireEvent.change(input(), { target: { value: 'noisiest rule?' } });
    await act(async () => {
      fireEvent.click(screen.getByLabelText('Send'));
    });
    expect(await screen.findByText('ET SCAN, 412 events.')).toBeTruthy();

    // The server now holds the turn. Every read of the general thread returns it.
    vi.mocked(getGeneralChat).mockResolvedValue(
      thread([{ role: 'user', text: 'noisiest rule?' }, said('ET SCAN, 412 events.')]),
    );
    go('Hunts page');
    expect(panel()).toBeTruthy();
    expect(screen.getByText('ET SCAN, 412 events.')).toBeTruthy();

    go('Host A page');
    expect(await screen.findByText('Host A is a web server.')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Switch to general' }));
    expect(await screen.findByText('ET SCAN, 412 events.')).toBeTruthy();
    // One general thread: every read and write took no id.
    for (const call of vi.mocked(getGeneralChat).mock.calls) expect(call).toEqual([]);
    expect(postGeneralChat).toHaveBeenCalledTimes(1);
  });
});

describe('the chips', () => {
  it('send the question on click in every scope', async () => {
    vi.mocked(getHostChat).mockResolvedValue(thread([]));
    render(<App at={`/hosts/${HOST_A}`} />);
    fireEvent.click(screen.getByRole('button', { name: 'Ask soc-ai about this host' }));
    await act(async () => {
      fireEvent.click(await screen.findByRole('button', { name: 'Who has it talked to today?' }));
    });
    await waitFor(() =>
      expect(postHostChat).toHaveBeenCalledWith(HOST_A, 'Who has it talked to today?'),
    );
  });
});
