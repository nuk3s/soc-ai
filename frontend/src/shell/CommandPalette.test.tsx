// Pins three palette contracts: (1) the "Go to" group covers every primary
// sidebar route — including Dashboard, Notifications and Backtest, which were
// previously missing — (2) the results expose combobox/listbox/option semantics
// so the arrow-key highlight is announced via aria-activedescendant, and (3) the
// "Settings" group makes the Config page's settings searchable (dogfood: typing
// a settings concept like "inherit" or "egress" returned "No matches", because
// ~275 settings across 31 sections had no search path at all).
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Config, Setting } from '../lib/types';
import { CommandPalette } from './CommandPalette';
import { ShellProvider } from './ShellContext';

// Stub useNavigate so the Settings entries' navigate(to, { state }) contract —
// the exact shape the Config page reads to flash the matched row — is assertable.
const navigateMock = vi.fn();
vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>();
  return { ...actual, useNavigate: () => navigateMock };
});

// Small fictional settings corpus: two server-driven groups under two different
// top-level parents. Section ids are NOT hardcoded here — they come out of
// buildConfigLayout ('Triage' → #triage, 'Egress' → #egress), same as the
// Config page renders them.
const setting = (key: string, label: string, help: string): Setting => ({
  key,
  label,
  help,
  source: 'db',
  apply: 'hot-apply',
  type: 'text',
  value: '',
  // None of this fixture's keys are in the real day1 curation — this file
  // tests the palette's own search/navigate contract, not the tier split.
  day1: false,
});

const CONFIG_FIXTURE: Config = {
  groups: [
    {
      title: 'Triage',
      parent: 'Triage & Workflow',
      items: [
        setting('webui_inherit_window_days', 'Verdict inheritance window', 'Days a prior verdict carries forward.'),
        setting('webui_queue_floor', 'Queue severity floor', 'Lowest severity the queue shows.'),
      ],
    },
    {
      title: 'Egress',
      parent: 'Privacy & Egress',
      items: [setting('webui_egress_allowlist', 'Outbound allowlist', 'Hosts the agent may reach.')],
    },
  ],
  tokens: [],
  users: [],
  dangerHost: '',
};

const getConfigMock = vi.fn();

vi.mock('../lib/api', () => ({
  getAlerts: vi.fn(() => Promise.resolve([])),
  getInvestigations: vi.fn(() => Promise.resolve([])),
  getConfig: () => getConfigMock(),
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

function type(text: string) {
  fireEvent.change(screen.getByRole('combobox'), { target: { value: text } });
}

describe('CommandPalette', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getConfigMock.mockResolvedValue(CONFIG_FIXTURE);
  });

  it('offers Go-to entries for every primary route, incl. Dashboard/Notifications/Backtest/Operate', async () => {
    await openPalette();
    for (const label of ['Dashboard', 'Notifications', 'Backtest', 'Alerts', 'Investigations', 'Hunts', 'Operate', 'Runbooks', 'Config']) {
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

  it('surfaces a Settings entry for a setting concept, labelled with its section', async () => {
    await openPalette();
    type('inherit');
    const hit = await screen.findByRole('option', { name: /Verdict inheritance window · Triage\s+Settings/ });
    expect(hit).toBeInTheDocument();
  });

  it('runs a setting entry as /config#<section> with state.highlightKey', async () => {
    await openPalette();
    type('inherit');
    await screen.findByRole('option', { name: /Verdict inheritance window · Triage/ });

    // Label matches rank first, so the matched setting is the highlighted row.
    fireEvent.keyDown(window, { key: 'Enter' });
    expect(navigateMock).toHaveBeenCalledWith('/config#triage', {
      state: { highlightKey: 'webui_inherit_window_days' },
    });
  });

  it('runs a section entry as a bare /config#<section> with no highlight state', async () => {
    await openPalette();
    type('egress');
    const section = await screen.findByRole('option', { name: /Egress policy · section/ });

    // Sections rank above key-only setting matches.
    const labels = screen.getAllByRole('option').map((o) => o.textContent ?? '');
    expect(labels.findIndex((l) => l.includes('· section'))).toBeLessThan(
      labels.findIndex((l) => l.includes('Outbound allowlist')),
    );

    fireEvent.click(section);
    expect(navigateMock).toHaveBeenCalledWith('/config#egress-policy');
  });

  it('degrades silently when getConfig is rejected (non-admin) and never retries', async () => {
    getConfigMock.mockRejectedValue(new Error('403'));
    await openPalette();
    type('inherit');
    expect(await screen.findByText('No matches')).toBeInTheDocument();
    expect(screen.queryAllByText('Settings')).toHaveLength(0);

    // Reopening must not restart the failed fetch (no retry storm).
    fireEvent.keyDown(window, { key: 'Escape' });
    fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
    await screen.findByRole('combobox');
    await waitFor(() => expect(getConfigMock).toHaveBeenCalledTimes(1));
  });

  it('keeps Settings entries out of the empty and 1-char result lists', async () => {
    await openPalette();
    type('inherit');
    await screen.findByRole('option', { name: /Verdict inheritance window · Triage/ });

    type('i');
    expect(screen.queryAllByText('Settings')).toHaveLength(0);

    type('');
    expect(screen.queryAllByText('Settings')).toHaveLength(0);
  });
});
