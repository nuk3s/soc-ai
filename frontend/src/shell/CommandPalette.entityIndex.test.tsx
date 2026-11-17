// The palette's server half (dogfood 2026-10-06, operator 7.2 to 7.5):
//   * a user named in a live lead, a domain and a hunt id were "No matches";
//   * two results read the same, with nothing to tell them apart;
//   * a result from the previous query stayed above "No matches".
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { getInvestigations, listMachines, searchEntityIndex } from '../lib/api';
import type { InvestigationRow, MachineRow } from '../lib/types';
import { CommandPalette } from './CommandPalette';
import { ShellProvider } from './ShellContext';

const navigateMock = vi.fn();
vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>();
  return { ...actual, useNavigate: () => navigateMock };
});

vi.mock('../lib/api', () => ({
  getAbout: vi.fn(() => Promise.resolve({ version: '1.6.0' })),
  getAlerts: vi.fn(() => Promise.resolve({ groups: [], truncated: false, other_docs: 0 })),
  getInvestigations: vi.fn(() => Promise.resolve([])),
  getConfig: vi.fn(() => Promise.resolve({ groups: [], tokens: [], users: [], dangerHost: '' })),
  listMachines: vi.fn(),
  searchEntityIndex: vi.fn(),
  signOut: vi.fn(),
}));

const EMPTY_PAGE = { rows: [], total: 0, limit: 8, offset: 0, sort: 'last_seen' as const, dir: 'desc' as const };

const MACHINE: MachineRow = {
  key: 'agent:7f3a',
  href: '/hosts/agent%3A7f3a',
  name: 'ws-15',
  name_source: 'agent',
  names: [{ value: 'ws-15', source: 'agent' }],
  primary_ip: '192.0.2.15',
  address_count: 1,
  addresses: ['192.0.2.15'],
  container_count: 0,
  agent: null,
  role: { value: null, label: null, confidence: null, state: 'unknown', guess: null, stale_hours: null },
  events: 4,
  first_seen: null,
  last_seen: null,
  flags: { declared: false, conflict: false, broken: false, new: false, rebound: false },
};

const inv = (id: string, host: string, dst: string): InvestigationRow =>
  ({
    id,
    name: 'ET SCAN Potential SSH Scan',
    kind: 'suricata',
    verdict: 'needs_more_info',
    conf: 0.5,
    host,
    dst,
    status: 'complete',
    when: '4d',
  }) as unknown as InvestigationRow;

async function openPalette() {
  render(
    <MemoryRouter>
      <ShellProvider>
        <CommandPalette />
      </ShellProvider>
    </MemoryRouter>,
  );
  fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
  await screen.findByRole('combobox');
}

function type(text: string) {
  fireEvent.change(screen.getByRole('combobox'), { target: { value: text } });
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(listMachines).mockResolvedValue(EMPTY_PAGE);
  vi.mocked(searchEntityIndex).mockResolvedValue({ q: '', hits: [] });
  vi.mocked(getInvestigations).mockResolvedValue([]);
});

describe('CommandPalette: users, domains, addresses and hunts', () => {
  it('finds a user named in a lead and opens the user page', async () => {
    vi.mocked(searchEntityIndex).mockResolvedValue({
      q: 'svc-adm',
      hits: [
        {
          type: 'user',
          value: 'svc-admin',
          label: 'svc-admin',
          detail: 'User · Account named in lead 11',
          href: '/entity/svc-admin?type=user',
        },
      ],
    });
    await openPalette();
    type('svc-adm');
    const hit = await screen.findByRole('option', { name: /svc-admin\s+User · Account named in lead 11\s+Users/ });
    expect(searchEntityIndex).toHaveBeenLastCalledWith('svc-adm');
    fireEvent.click(hit);
    expect(navigateMock).toHaveBeenCalledWith('/entity/svc-admin?type=user');
  });

  it('finds a hunt by a part of its id', async () => {
    vi.mocked(searchEntityIndex).mockResolvedValue({
      q: '7k2p',
      hits: [
        {
          type: 'hunt',
          value: '01HUNT7K2P',
          label: 'Hunt for backup account abuse',
          detail: 'Hunt 01HUNT7K2P · finished',
          href: '/hunts/01HUNT7K2P',
        },
      ],
    });
    await openPalette();
    type('7k2p');
    const hit = await screen.findByRole('option', { name: /Hunt for backup account abuse.*Hunts/ });
    fireEvent.click(hit);
    expect(navigateMock).toHaveBeenCalledWith('/hunts/01HUNT7K2P');
  });

  it('gives two identical investigation results a second line that tells them apart', async () => {
    vi.mocked(getInvestigations).mockResolvedValue([
      inv('01AAA', '192.0.2.5', '192.0.2.9'),
      inv('01BBB', '192.0.2.6', '192.0.2.9'),
    ]);
    await openPalette();
    type('SSH Scan');
    await waitFor(() => expect(screen.getAllByTestId('palette-detail').length).toBe(2));
    const details = screen.getAllByTestId('palette-detail').map((d) => d.textContent);
    expect(details).toEqual([
      '192.0.2.5 → 192.0.2.9 · Investigation 01AAA',
      '192.0.2.6 → 192.0.2.9 · Investigation 01BBB',
    ]);
    expect(new Set(details).size).toBe(2);
  });

  it('clears the results of the previous query as soon as the query changes', async () => {
    vi.useFakeTimers();
    try {
      vi.mocked(listMachines).mockImplementation((q) =>
        Promise.resolve(q?.q === '192.0.2.15' ? { ...EMPTY_PAGE, rows: [MACHINE], total: 1 } : EMPTY_PAGE),
      );
      render(
        <MemoryRouter>
          <ShellProvider>
            <CommandPalette />
          </ShellProvider>
        </MemoryRouter>,
      );
      fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
      await act(async () => {
        await vi.advanceTimersByTimeAsync(10);
      });
      type('192.0.2.15');
      await act(async () => {
        await vi.advanceTimersByTimeAsync(200);
      });
      expect(screen.getByRole('option', { name: /ws-15/ })).toBeInTheDocument();
      // The next keystroke: the old host hit must go before the new answer lands.
      type('192.0.2.15x');
      expect(screen.queryByRole('option', { name: /ws-15/ })).toBeNull();
      expect(screen.getByText('No matches')).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });

  it('keeps the results while the query is the same', async () => {
    // NEGATIVE CONTROL: a re-render with the same query keeps its answer.
    vi.mocked(listMachines).mockResolvedValue({ ...EMPTY_PAGE, rows: [MACHINE], total: 1 });
    await openPalette();
    type('192.0.2.15');
    expect(await screen.findByRole('option', { name: /ws-15/ })).toBeInTheDocument();
    type('192.0.2.15 ');
    expect(screen.getByRole('option', { name: /ws-15/ })).toBeInTheDocument();
  });
});

// L4 (review 2026-11-12): Ctrl K "php2shell" put a hunt first, and its label
// was a 13-line prompt. Investigations and hosts rank before hunts.
describe('CommandPalette: the order of the results', () => {
  it('ranks the hosts and the investigations before a hunt', async () => {
    vi.mocked(listMachines).mockResolvedValue({ ...EMPTY_PAGE, rows: [{ ...MACHINE, name: 'php2shell-web' }], total: 1 });
    vi.mocked(getInvestigations).mockResolvedValue([
      { ...inv('INV-1', '192.0.2.15', '198.51.100.7'), name: 'ET EXPLOIT php2shell upload' } as InvestigationRow,
    ]);
    vi.mocked(searchEntityIndex).mockResolvedValue({
      q: 'php2shell',
      hits: [
        {
          type: 'hunt',
          value: 'H-49',
          label: 'Lead 49 hunt: 192.0.2.15',
          detail: 'Hunt H-49 · 1 confirmed · 0 not judged · of 1 threat finding',
          href: '/hunts/H-49',
        },
      ],
    });
    await openPalette();
    type('php2shell');
    await screen.findByText('Lead 49 hunt: 192.0.2.15');
    const groups = screen.getAllByRole('option').map((o) => o.textContent ?? '');
    const at = (word: string) => groups.findIndex((g) => g.endsWith(word));
    expect(at('Hosts')).toBeGreaterThanOrEqual(0);
    expect(at('Investigations')).toBeGreaterThan(at('Hosts'));
    expect(at('Hunts')).toBeGreaterThan(at('Investigations'));
  });
});
