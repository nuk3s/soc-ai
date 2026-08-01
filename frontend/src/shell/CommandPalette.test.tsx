// Pins two palette contracts: (1) the "Go to" group covers every primary
// sidebar route — including Dashboard, Notifications and Backtest, which were
// previously missing — and (2) the results expose combobox/listbox/option
// semantics so the arrow-key highlight is announced via aria-activedescendant.
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { CommandPalette } from './CommandPalette';
import { ShellProvider } from './ShellContext';

vi.mock('../lib/api', () => ({
  getAlerts: vi.fn(() => Promise.resolve([])),
  getInvestigations: vi.fn(() => Promise.resolve([])),
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

describe('CommandPalette', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('offers Go-to entries for every primary route, incl. Dashboard/Notifications/Backtest', async () => {
    await openPalette();
    for (const label of ['Dashboard', 'Notifications', 'Backtest', 'Alerts', 'Investigations', 'Hunts', 'Runbooks', 'Config']) {
      expect(screen.getByRole('option', { name: new RegExp(`${label}\\s+Go to`) })).toBeInTheDocument();
    }
  });

  it('exposes combobox/listbox semantics with aria-activedescendant tracking the highlight', async () => {
    await openPalette();
    const input = screen.getByRole('combobox');
    const listbox = screen.getByRole('listbox');
    expect(input).toHaveAttribute('aria-controls', listbox.id);
    expect(input).toHaveAttribute('aria-expanded', 'true');

    const options = screen.getAllByRole('option');
    expect(options[0]).toHaveAttribute('aria-selected', 'true');
    expect(input).toHaveAttribute('aria-activedescendant', options[0].id);

    fireEvent.keyDown(window, { key: 'ArrowDown' });
    expect(options[1]).toHaveAttribute('aria-selected', 'true');
    expect(options[0]).toHaveAttribute('aria-selected', 'false');
    expect(input).toHaveAttribute('aria-activedescendant', options[1].id);
  });
});
