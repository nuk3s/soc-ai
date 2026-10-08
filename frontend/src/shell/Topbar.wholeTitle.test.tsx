// The bell named a finished hunt by its objective cut at 80 characters on the
// server, in the middle of a word. The server now sends the whole head line.
// The dropdown is narrow. The title wrapped at three lines, and the owner
// banned the clamp on 2026-10-07. The whole title shows and wraps, and it
// stays in a `title` attribute.
import { act, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getWorkspaces: vi.fn(),
  getNotifications: vi.fn(),
  getHealth: vi.fn(),
}));

import { getHealth, getNotifications, getWorkspaces } from '../lib/api';
import { TITLE_180, bareCuts, showsWhole } from '../test/wholeTitle';
import { ShellProvider } from './ShellContext';
import { Topbar } from './Topbar';

const flush = () =>
  act(async () => {
    await vi.advanceTimersByTimeAsync(0);
  });

const mount = () =>
  render(
    <MemoryRouter>
      <ShellProvider>
        <Topbar />
      </ShellProvider>
    </MemoryRouter>,
  );

const open = async () => {
  mount();
  await flush();
  act(() => {
    screen.getByRole('button', { name: /^Notifications/ }).click();
  });
};

beforeEach(() => {
  vi.clearAllMocks();
  vi.useFakeTimers();
  vi.mocked(getWorkspaces).mockResolvedValue([]);
  vi.mocked(getHealth).mockResolvedValue({
    es: { ok: true, detail: 'ok' },
    llm: { ok: true, detail: 'ok' },
    so: { ok: true, detail: 'ok' },
    pcap: null,
  });
});

afterEach(() => {
  vi.useRealTimers();
});

describe('Topbar bell keeps the whole hunt title', () => {
  it('shows a long hunt notice whole and holds it on the hover', async () => {
    const full = `Hunt finished, 1 threat finding: ${TITLE_180}`;
    vi.mocked(getNotifications).mockResolvedValue([
      { id: 'hunt-done:H-1', tone: 'warn', title: full, when: '4m', href: '/hunts/H-1' },
    ]);
    await open();
    const title = screen.getByTestId('bell-title');
    expect(title.textContent).toBe(full);
    expect(title.getAttribute('title')).toBe(full);
    expect(title.className).toContain('break-words');
    expect(title.className).not.toMatch(/\btruncate\b|line-clamp/);
    expect(showsWhole(document.body, TITLE_180)).toBe(true);
    expect(bareCuts(document.body, TITLE_180)).toEqual([]);
  });

  it('renders a short notice unchanged', async () => {
    vi.mocked(getNotifications).mockResolvedValue([
      { id: 'dep:es', tone: 'warn', title: 'Elasticsearch unreachable', when: '3m', href: null },
    ]);
    await open();
    const title = screen.getByTestId('bell-title');
    expect(title.textContent).toBe('Elasticsearch unreachable');
    expect(title.getAttribute('title')).toBe('Elasticsearch unreachable');
  });
});
