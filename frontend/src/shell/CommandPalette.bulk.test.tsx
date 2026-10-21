// Dogfood 2026-10-19 R1-D14 and H1-I4. "Bulk investigate all untriaged"
// started a sweep at once, with no word on the window, the severities or the
// model cost. H1-D19: after Escape the focus fell to BODY.
import { act, fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { getAlerts, getHealth } from '../lib/api';
import type { AlertGroup } from '../lib/types';
import { CommandPalette } from './CommandPalette';
import { PALETTE_TRIGGER_ATTR } from './platform';
import { ShellProvider } from './ShellContext';

const navigateMock = vi.fn();
vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>();
  return { ...actual, useNavigate: () => navigateMock };
});

vi.mock('../lib/api', () => ({
  getAlerts: vi.fn(),
  getHealth: vi.fn(),
  getInvestigations: vi.fn(() => Promise.resolve([])),
  getConfig: vi.fn(() => Promise.reject(new Error('403'))),
  listMachines: vi.fn(() => Promise.resolve({ rows: [] })),
  searchEntityIndex: vi.fn(() => Promise.resolve({ q: '', hits: [] })),
  signOut: vi.fn(),
}));

const group = (id: string, sev: AlertGroup['sev'], verdict: AlertGroup['verdict'], extra: Partial<AlertGroup> = {}): AlertGroup => ({
  id,
  name: `Rule ${id}`,
  kind: 'suricata',
  sev,
  count: 3,
  verdict,
  conf: null,
  latest: '1h',
  inherited: false,
  events: [],
  ...extra,
});

const HEALTHY = {
  es: { ok: true, detail: 'ok' },
  llm: { ok: true, detail: 'ok' },
  so: { ok: true, detail: 'ok' },
  pcap: null,
};

const flush = () => act(async () => { await new Promise((r) => setTimeout(r, 0)); });

async function openAndPick() {
  render(
    <MemoryRouter>
      <ShellProvider>
        <button type="button" {...{ [PALETTE_TRIGGER_ATTR]: '' }}>
          Search or jump to
        </button>
        <CommandPalette />
      </ShellProvider>
    </MemoryRouter>,
  );
  fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
  await screen.findByRole('combobox');
  fireEvent.click(screen.getByRole('option', { name: /Investigate untriaged alerts of the last 24 hours/ }));
  await flush();
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(getHealth).mockResolvedValue(HEALTHY as never);
  vi.mocked(getAlerts).mockResolvedValue({
    groups: [
      group('a', 'critical', 'untriaged'),
      group('b', 'high', 'untriaged'),
      group('c', 'unknown', 'untriaged'),
      // Outside the band, settled, or in flight: not counted.
      group('d', 'medium', 'untriaged'),
      group('e', 'high', 'false_positive'),
      group('f', 'high', 'untriaged', { triaging: true }),
    ],
    truncated: false,
    other_docs: 0,
  } as never);
});

describe('palette bulk investigate', () => {
  it('asks first and states the window, the severities, the count and the model cost', async () => {
    await openAndPick();
    // Nothing started yet.
    expect(navigateMock).not.toHaveBeenCalled();
    const confirm = screen.getByTestId('palette-bulk-confirm');
    expect(confirm.textContent).toContain('last 24 hours');
    expect(confirm.textContent).toContain('critical and high alerts');
    expect(confirm.textContent).toContain('3 alert groups of these severities have no verdict.');
    expect(confirm.textContent).toContain('Each investigation uses the model.');
    expect(vi.mocked(getAlerts)).toHaveBeenCalledWith({ range: '24h' });
  });

  it('starts the sweep on Alerts only after the confirm', async () => {
    await openAndPick();
    fireEvent.click(screen.getByRole('button', { name: 'Investigate' }));
    expect(navigateMock).toHaveBeenCalledWith('/alerts', { state: { autoTriage: true } });
  });

  it('goes back to the list on Cancel and starts nothing', async () => {
    await openAndPick();
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByTestId('palette-bulk-confirm')).toBeNull();
    expect(screen.getByRole('combobox')).toBeTruthy();
    expect(navigateMock).not.toHaveBeenCalled();
  });

  it('ignores Enter on the list while the confirm shows', async () => {
    await openAndPick();
    fireEvent.keyDown(window, { key: 'Enter' });
    expect(navigateMock).not.toHaveBeenCalled();
  });

  it('refuses with the reason while the model gateway is down', async () => {
    vi.mocked(getHealth).mockResolvedValue({
      ...HEALTHY,
      llm: { ok: false, detail: 'Connection refused', kind: 'refused' },
    } as never);
    await openAndPick();
    expect(screen.getByRole('button', { name: 'Investigate' })).toBeDisabled();
    expect(screen.getByTestId('palette-bulk-confirm').textContent).toContain(
      'The model gateway does not answer.',
    );
  });

  // V1-S3: at 0 groups the Investigate button stayed on and took the focus.
  it('turns Investigate off with the reason when no group waits', async () => {
    vi.mocked(getAlerts).mockResolvedValue({
      groups: [group('e', 'high', 'false_positive'), group('d', 'medium', 'untriaged')],
      truncated: false,
      other_docs: 0,
    } as never);
    await openAndPick();
    const investigate = screen.getByRole('button', { name: 'Investigate' });
    expect(investigate).toBeDisabled();
    expect(investigate.getAttribute('title')).toBe(
      'No alert group of these severities waits for a verdict.',
    );
    expect(screen.getByTestId('palette-bulk-confirm').textContent).toContain(
      '0 alert groups of these severities have no verdict.',
    );
    // The focus goes to Cancel, and Enter starts nothing.
    expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Cancel' }));
    fireEvent.click(investigate);
    expect(navigateMock).not.toHaveBeenCalled();
  });

  it('refuses with the reason while the grid is down', async () => {
    vi.mocked(getHealth).mockResolvedValue({
      ...HEALTHY,
      es: { ok: false, detail: 'Connection refused', kind: 'refused' },
    } as never);
    vi.mocked(getAlerts).mockRejectedValue(new Error('503'));
    await openAndPick();
    expect(screen.getByRole('button', { name: 'Investigate' })).toBeDisabled();
    const text = screen.getByTestId('palette-bulk-confirm').textContent ?? '';
    expect(text).toContain('The grid does not answer.');
    expect(text).toContain('soc-ai could not count the alert groups.');
  });

  it('finds the entry by the old word "bulk"', async () => {
    render(
      <MemoryRouter>
        <ShellProvider>
          <CommandPalette />
        </ShellProvider>
      </MemoryRouter>,
    );
    fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
    const input = await screen.findByRole('combobox');
    fireEvent.change(input, { target: { value: 'bulk' } });
    expect(screen.getByRole('option', { name: /Investigate untriaged alerts of the last 24 hours/ })).toBeTruthy();
  });
});

describe('palette focus on close', () => {
  it('gives the focus to the palette trigger after Escape when nothing held it', async () => {
    render(
      <MemoryRouter>
        <ShellProvider>
          <button type="button" {...{ [PALETTE_TRIGGER_ATTR]: '' }}>
            Search or jump to
          </button>
          <CommandPalette />
        </ShellProvider>
      </MemoryRouter>,
    );
    (document.activeElement as HTMLElement | null)?.blur?.();
    fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
    await screen.findByRole('combobox');
    fireEvent.keyDown(window, { key: 'Escape' });
    await flush();
    expect(screen.queryByRole('combobox')).toBeNull();
    expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Search or jump to' }));
  });
});
