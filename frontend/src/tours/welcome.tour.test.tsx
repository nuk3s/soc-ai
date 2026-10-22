// Smoke test of the welcome tour: every anchor it names is on the shell.
// A renamed anchor in the sidebar, the top bar, the chat button or the page
// time filter fails here.
import { act, render } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getMe: vi.fn(() => Promise.resolve({ username: 'admin', role: 'admin', status: '', signed_in: true })),
  getAbout: vi.fn(() =>
    Promise.resolve({ version: '1.6.0', repo_url: '', license: 'Apache-2.0', update_check_enabled: false }),
  ),
  getWorkspaces: vi.fn(() => Promise.resolve([])),
  getNotifications: vi.fn(() => Promise.resolve([])),
  getHealth: vi.fn(() => Promise.resolve({ es: { ok: true, detail: '' }, llm: { ok: true, detail: '' } })),
  getNeedsYouCount: vi.fn(() => Promise.reject(new Error('not needed'))),
}));

import { TimeRangeFilter } from '../components/TimeRangeFilter';
import { ChatProvider } from '../lib/chatScope';
import { ShellProvider } from '../shell/ShellContext';
import { Sidebar } from '../shell/Sidebar';
import { Topbar } from '../shell/Topbar';
import { WELCOME_TOUR } from './content';
import { missingAnchors } from './testing';

describe('welcome tour anchors', () => {
  it('finds every anchor on the shell and a page with the time filter', async () => {
    render(
      <MemoryRouter initialEntries={['/dashboard']}>
        <ShellProvider>
          <ChatProvider generalEnabled>
            <Sidebar />
            <Topbar />
            <TimeRangeFilter value="24h" onChange={() => {}} />
          </ChatProvider>
        </ShellProvider>
      </MemoryRouter>,
    );
    await act(async () => {
      await new Promise((r) => setTimeout(r, 10));
    });
    expect(missingAnchors(WELCOME_TOUR)).toEqual([]);
    // Every step but the time filter lives in the shell.
    expect(WELCOME_TOUR.steps.filter((s) => s.scope === 'page').map((s) => s.anchor)).toEqual(['time-filter']);
  });
});
