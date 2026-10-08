// Not-found pages (dogfood 2026-10-06). The investigation page offered "Back
// to Alerts" for a run that does not exist, and the page title and the top
// bar read the raw id over a card that said the id holds nothing.
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getInvestigation: vi.fn(),
  getMe: vi.fn(),
}));

vi.mock('./Investigation', () => ({
  Investigation: () => <div data-testid="investigation-report" />,
}));

import { NotFoundState } from '../components/States';
import { ApiError, getInvestigation, getMe } from '../lib/api';
import { ShellProvider, useShell } from '../shell/ShellContext';
import { InvestigationPage } from './InvestigationPage';

/** Prints the name the top bar would show for the route key. */
function CrumbProbe() {
  const { crumbName } = useShell();
  return <div data-testid="crumb">{crumbName ? `${crumbName.key}=${crumbName.name}` : ''}</div>;
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(getMe).mockResolvedValue({ username: 'ana', role: 'analyst', status: '' });
});

describe('the investigation not-found page', () => {
  it('names the absence in the page title and goes back to Investigations', async () => {
    vi.mocked(getInvestigation).mockRejectedValue(new ApiError('404 Not Found', 404));
    render(
      <ShellProvider>
        <MemoryRouter initialEntries={['/investigation/INV-nope']}>
          <Routes>
            <Route path="/investigation/:id" element={<InvestigationPage />} />
          </Routes>
        </MemoryRouter>
        <CrumbProbe />
      </ShellProvider>,
    );
    expect((await screen.findByTestId('investigation-page-title')).textContent).toBe(
      'No such investigation',
    );
    const backs = screen.getAllByRole('link', { name: /Investigations/ });
    expect(backs.length).toBe(2);
    for (const b of backs) expect(b.getAttribute('href')).toBe('/investigations');
    expect(screen.queryByText(/Alerts/)).toBeNull();
    // The crumb lands one effect after the title, so wait for it.
    await waitFor(() =>
      expect(screen.getByTestId('crumb').textContent).toBe('INV-nope=No such investigation'),
    );
  });

  it('NEGATIVE CONTROL: a run that loads keeps its title and its origin', async () => {
    vi.mocked(getInvestigation).mockResolvedValue({ id: 'INV-1', status: 'complete' } as never);
    render(
      <ShellProvider>
        <MemoryRouter
          initialEntries={[{ pathname: '/investigation/INV-1', state: { from: '/hunts/01HUNT' } }]}
        >
          <Routes>
            <Route path="/investigation/:id" element={<InvestigationPage />} />
          </Routes>
        </MemoryRouter>
        <CrumbProbe />
      </ShellProvider>,
    );
    await screen.findByTestId('investigation-report');
    expect(screen.getByTestId('investigation-page-title').textContent).toBe('Investigation');
    // The origin the run was opened from wins over the list of investigations.
    expect(screen.getByRole('link', { name: 'Back to Hunt' }).getAttribute('href')).toBe('/hunts/01HUNT');
    expect(screen.getByTestId('crumb').textContent).toBe('');
  });
});

describe('the lead not-found page', () => {
  it('sets the top bar title for the lead id and clears it on leave', () => {
    const { unmount } = render(
      <ShellProvider>
        <MemoryRouter>
          <NotFoundState what="lead" id="18" backTo="/hunts#leads" backLabel="Back to leads" />
        </MemoryRouter>
        <CrumbProbe />
      </ShellProvider>,
    );
    expect(screen.getByTestId('crumb').textContent).toBe('18=No such lead');
    expect(screen.getByText('No such lead')).toBeTruthy();
    unmount();
  });

  it('works outside the shell, where there is no top bar', () => {
    render(
      <MemoryRouter>
        <NotFoundState what="lead" id="18" backTo="/hunts#leads" backLabel="Back to leads" />
      </MemoryRouter>,
    );
    expect(screen.getByText('No such lead')).toBeTruthy();
  });
});
