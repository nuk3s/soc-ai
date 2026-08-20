// Investigate is the analyst loop (unchanged order); Operate shelves the
// ops/config surfaces behind a collapsible group, collapsed by default so a
// first-run session reads as an analyst tool, not a cockpit. Regression
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
  it('groups nav into Investigate and Operate with Operate collapsed by default', async () => {
    renderAt('/dashboard');

    expect(await screen.findByText('Investigate')).toBeInTheDocument();
    expect(screen.getByText('Operate')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Dashboard' })).toBeInTheDocument();
    // Operate's items stay folded until the group is opened.
    expect(screen.queryByRole('link', { name: 'Config' })).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Runbooks' })).not.toBeInTheDocument();
  });

  it('expands Operate on heading click and persists', async () => {
    renderAt('/dashboard');

    const heading = await screen.findByRole('button', { name: /operate/i });
    expect(screen.queryByRole('link', { name: 'Config' })).not.toBeInTheDocument();

    fireEvent.click(heading);

    expect(await screen.findByRole('link', { name: 'Config' })).toBeInTheDocument();
    expect(localStorage.getItem(OPERATE_KEY)).toBe('0');
  });

  it('renders Operate expanded when the active route lives inside it', async () => {
    renderAt('/config');

    // No click needed — the current location is inside the Operate group.
    expect(await screen.findByRole('link', { name: 'Config' })).toBeInTheDocument();
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
      await waitFor(() => expect(screen.queryByText('Operate')).not.toBeInTheDocument());

      // Operate's own group-collapse state is still default-collapsed here,
      // yet every item — including the ones the group would otherwise fold —
      // renders as an icon-only link in the 64px rail.
      expect(screen.getByTitle('Config')).toBeInTheDocument();
      expect(screen.getByTitle('Runbooks')).toBeInTheDocument();
      expect(screen.getByTitle('Backtest')).toBeInTheDocument();
      expect(screen.getByTitle('Operate')).toBeInTheDocument();
    });
  });
});
