// Analyst is the analyst loop (unchanged order); Operator shelves the
// ops/settings surfaces behind a collapsible group, collapsed by default so a
// first-run session reads as an analyst tool, not a cockpit. The groups were
// "Investigate" and "Operate", and "Operate" named both the group and its
// first page (dogfood 2026-10-06). Regression
// coverage for: default-collapsed, click-to-expand-and-persist, force-expand
// when the active route lives inside the group, and that the icon rail never
// hides navigation regardless of group collapse.
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getMe: vi.fn(() => Promise.resolve({ username: 'analyst', role: 'analyst', status: '' })),
  getAbout: vi.fn(() =>
    Promise.resolve({
      version: '1.2.8',
      repo_url: 'https://github.com/nuk3s/soc-ai',
      license: 'Apache-2.0',
      update_check_enabled: false,
    }),
  ),
  getNeedsYouCount: vi.fn(() => Promise.reject(new Error('not in this test'))),
}));

import { ShellProvider } from './ShellContext';
import { Sidebar } from './Sidebar';

const NAV_KEY = 'soc-ai:navCollapsed';
const OPERATE_KEY = 'soc-ai:navOperateCollapsed';

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <ShellProvider>
        <Sidebar />
      </ShellProvider>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  localStorage.clear();
});

describe('Sidebar nav groups', () => {
  it('groups nav into Analyst and Operator with Operator collapsed by default', async () => {
    renderAt('/dashboard');

    expect(await screen.findByText('Analyst')).toBeInTheDocument();
    expect(screen.getByText('Operator')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Dashboard' })).toBeInTheDocument();
    // Operate's items stay folded until the group is opened.
    expect(screen.queryByRole('link', { name: 'Settings' })).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Runbooks' })).not.toBeInTheDocument();
  });

  it('expands Operator on heading click and persists', async () => {
    renderAt('/dashboard');

    const heading = await screen.findByRole('button', { name: /operator/i });
    expect(screen.queryByRole('link', { name: 'Settings' })).not.toBeInTheDocument();

    fireEvent.click(heading);

    expect(await screen.findByRole('link', { name: 'Settings' })).toBeInTheDocument();
    expect(localStorage.getItem(OPERATE_KEY)).toBe('0');
  });

  it('renders Operator expanded when the active route lives inside it', async () => {
    renderAt('/config');

    // No click needed — the current location is inside the Operate group.
    expect(await screen.findByRole('link', { name: 'Settings' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Runbooks' })).toBeInTheDocument();
  });

  describe('icon rail', () => {
    beforeEach(() => {
      localStorage.setItem(NAV_KEY, '1');
    });

    it('shows all items regardless of group collapse', async () => {
      renderAt('/dashboard');

      // Sanity: the rail really did collapse (labels/headings hidden) —
      // mirrors AccountMenu.test.tsx's collapsed-rail sanity check.
      await waitFor(() => expect(screen.queryByText('Operator')).not.toBeInTheDocument());

      // Operate's own group-collapse state is still default-collapsed here,
      // yet every item — including the ones the group would otherwise fold —
      // renders as an icon-only link in the 64px rail.
      expect(screen.getByTitle('Settings')).toBeInTheDocument();
      expect(screen.getByTitle('Runbooks')).toBeInTheDocument();
      expect(screen.getByTitle('Backtest')).toBeInTheDocument();
      expect(screen.getByTitle('Status')).toBeInTheDocument();
    });
  });
});

describe('Sidebar entries', () => {
  // The bell opens the same list, and its "View all notifications" link keeps
  // the page reachable.
  it('has no Notifications entry', async () => {
    renderAt('/dashboard');
    await screen.findByRole('link', { name: 'Dashboard' });
    expect(screen.queryByRole('link', { name: 'Notifications' })).toBeNull();
  });

  // A lead lives on the Hunts page.
  it('marks Hunts active on a lead page', async () => {
    renderAt('/leads/18');
    const hunts = await screen.findByRole('link', { name: /^Hunts/ });
    expect(hunts.querySelector('span')?.getAttribute('style')).toContain('#4b8bf5');
    // NEGATIVE CONTROL. Alerts is not lit on a lead page.
    const alerts = screen.getByRole('link', { name: /^Alerts/ });
    expect(alerts.querySelector('span')?.getAttribute('style')).not.toContain('#4b8bf5');
  });

  it('reads the wordmark as soc-ai', async () => {
    renderAt('/dashboard');
    await screen.findByRole('link', { name: 'Dashboard' });
    expect(screen.getByText((_, el) => el?.textContent === 'soc-ai' && el.className.includes('font-mono'))).toBeTruthy();
  });
});
