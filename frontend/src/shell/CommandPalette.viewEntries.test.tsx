// "My queue" must land on the Alerts screen's Mine preset. That screen's view
// chips are 'mine' | 'inreview' | 'critical' | 'decision' | 'all' and a ?view=
// outside that set is dropped, so a palette entry that sends anything else
// opens the whole list under a label that promised the analyst their own.
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { CommandPalette } from './CommandPalette';
import { ShellProvider } from './ShellContext';

// Stub useNavigate so the target the entry navigates to is assertable.
const navigateMock = vi.fn();
vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>();
  return { ...actual, useNavigate: () => navigateMock };
});

vi.mock('../lib/api', () => ({
  getAlerts: vi.fn(() => Promise.resolve({ groups: [], truncated: false, other_docs: 0 })),
  getInvestigations: vi.fn(() => Promise.resolve([])),
  getConfig: vi.fn(() => Promise.resolve({ groups: [], tokens: [], users: [], dangerHost: '' })),
  listDossiers: vi.fn(() => Promise.resolve({ rows: [], total: 0, limit: 8, offset: 0 })),
  signOut: vi.fn(),
}));

async function openPalette() {
  render(
    <MemoryRouter>
      <ShellProvider>
        <CommandPalette />
      </ShellProvider>
    </MemoryRouter>,
  );
  // The global ⌘K/Ctrl-K listener is armed even while the palette is closed.
  fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
  await screen.findByRole('combobox');
}

describe('CommandPalette view entries', () => {
  beforeEach(() => navigateMock.mockClear());

  it('"My queue" opens the Alerts screen on its Mine preset', async () => {
    await openPalette();
    fireEvent.click(screen.getByRole('option', { name: /My queue\s+View/ }));
    expect(navigateMock).toHaveBeenCalledWith('/alerts?view=mine');
  });
});
