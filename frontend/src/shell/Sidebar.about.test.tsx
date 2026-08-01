// The sidebar footer carries the running version as a quiet, always-visible
// affordance that deep-links to the About panel — the one place a version was
// missing before.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getMe: vi.fn(() => Promise.resolve({ username: 'analyst', role: 'analyst', status: '' })),
  getAbout: vi.fn(() =>
    Promise.resolve({
      version: '1.2.5',
      repo_url: 'https://github.com/nuk3s/soc-ai',
      license: 'Apache-2.0',
      update_check_enabled: false,
    }),
  ),
}));

import { ShellProvider } from './ShellContext';
import { Sidebar } from './Sidebar';

describe('Sidebar version line', () => {
  it('shows the running version linking to the About panel', async () => {
    render(
      <MemoryRouter>
        <ShellProvider>
          <Sidebar />
        </ShellProvider>
      </MemoryRouter>,
    );
    const label = await screen.findByText(/v1\.2\.5/);
    const link = label.closest('a') as HTMLAnchorElement;
    expect(link).toBeTruthy();
    expect(link.getAttribute('href')).toContain('/config#about');
  });
});
