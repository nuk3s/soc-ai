// Config restructure (dogfood 2026-08-01): the page was one 32,000px scroll of
// 31 sections with no search. It is now master-detail — the two-level nav is the
// master, the content pane renders ONLY the selected section — with a settings
// search that spans every section, an Apply bar that NAMES its staged edits
// (clickable chips, per-chip discard), and a remembered last section.
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('./AgentToolsPanel', () => ({ AgentToolsPanel: () => null }));
vi.mock('./ApiKeysPanel', () => ({ ApiKeysPanel: () => <div data-testid="panel-api-keys" /> }));
vi.mock('./DataSourcesPanel', () => ({ DataSourcesPanel: () => null }));
vi.mock('./EgressPolicyPanel', () => ({ EgressPolicyPanel: () => null }));
vi.mock('./NotificationsPanel', () => ({ NotificationsPanel: () => null }));
vi.mock('./RedactionPreviewPanel', () => ({ RedactionPreviewPanel: () => null }));
vi.mock('./DetectionTuningPanel', () => ({ DetectionTuningPanel: () => <div data-testid="panel-detection-tuning" /> }));
vi.mock('./MaintenancePanel', () => ({ MaintenancePanel: () => null }));
vi.mock('./RunbooksPanel', () => ({ RunbooksPanel: () => null }));
vi.mock('./AboutPanel', () => ({ AboutPanel: () => null }));

const GROUPS = vi.hoisted(() => [
  {
    title: 'Agent',
    parent: 'Models & Reasoning',
    items: [
      {
        key: 'fast_triage_enabled',
        label: 'Fast verdict',
        help: 'Skip tools when confident.',
        source: 'db',
        apply: 'hot',
        type: 'toggle',
        value: true,
      },
    ],
  },
  {
    title: 'Triage automation',
    parent: 'Triage & Workflow',
    items: [
      {
        key: 'webui_inherit_window_days',
        label: 'Verdict inheritance window',
        help: 'Days a standing verdict may be inherited.',
        source: 'db',
        apply: 'hot',
        type: 'number',
        value: 14,
        bounds: '1 to 90',
      },
    ],
  },
]);

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getConfig: vi.fn(() => Promise.resolve({ groups: GROUPS, tokens: [], users: [], dangerHost: '' })),
  listUsers: vi.fn().mockResolvedValue({ users: [] }),
  listDangerSettings: vi.fn().mockResolvedValue([]),
  getGatewayModels: vi.fn().mockResolvedValue({ ok: true, models: [] }),
  getInternalIdentifiers: vi.fn().mockResolvedValue({
    groups: [],
    last_scan: { running: false, last_scan: null, last_summary: null, note: null },
  }),
}));

import { Config } from './Config';

const renderAt = (entry: string | { pathname: string; hash?: string; state?: unknown }) =>
  render(
    <MemoryRouter initialEntries={[entry as never]}>
      <Config />
    </MemoryRouter>,
  );

beforeEach(() => {
  localStorage.clear();
});

describe('master-detail: only the selected section renders', () => {
  it('shows the first section by default and nothing else', async () => {
    renderAt('/config');
    expect(await screen.findByText('Fast verdict')).toBeTruthy();
    expect(screen.queryByText('Verdict inheritance window')).toBeNull();
    // System-parent management surfaces are not in the DOM either.
    expect(screen.queryByText('+ Mint token')).toBeNull();
  });

  it('deep-link hash selects that section', async () => {
    renderAt({ pathname: '/config', hash: '#triage-automation' });
    expect(await screen.findByText('Verdict inheritance window')).toBeTruthy();
    expect(screen.queryByText('Fast verdict')).toBeNull();
  });

  it('nav click switches the rendered section', async () => {
    renderAt('/config');
    await screen.findByText('Fast verdict');
    const navLink = screen
      .getAllByText('Triage automation')
      .find((el) => el.closest('nav'))!;
    fireEvent.click(navLink);
    expect(await screen.findByText('Verdict inheritance window')).toBeTruthy();
    expect(screen.queryByText('Fast verdict')).toBeNull();
  });

  it('remembers the last selected section across visits', async () => {
    const first = renderAt('/config');
    await screen.findByText('Fast verdict');
    const navLink = screen
      .getAllByText('Triage automation')
      .find((el) => el.closest('nav'))!;
    fireEvent.click(navLink);
    await screen.findByText('Verdict inheritance window');
    first.unmount();

    renderAt('/config');
    expect(await screen.findByText('Verdict inheritance window')).toBeTruthy();
    expect(screen.queryByText('Fast verdict')).toBeNull();
  });
});

describe('settings search spans every section', () => {
  it('finds a setting in an unselected section and jumps to it highlighted', async () => {
    renderAt('/config');
    await screen.findByText('Fast verdict');
    const box = screen.getAllByPlaceholderText(/search settings/i)[0];
    fireEvent.change(box, { target: { value: 'inherit' } });
    // Result row: setting label + owning section.
    const hit = await screen.findByTestId('search-result-webui_inherit_window_days');
    expect(hit.textContent).toContain('Verdict inheritance window');
    expect(hit.textContent).toContain('Triage automation');
    fireEvent.click(hit);
    // Jumped to the owning section with the row highlighted.
    await screen.findByText('Verdict inheritance window');
    const row = document.querySelector('[data-setting-key="webui_inherit_window_days"]')!;
    expect(row.getAttribute('data-highlighted')).toBe('true');
  });

  it('matches section names too', async () => {
    renderAt('/config');
    await screen.findByText('Fast verdict');
    const box = screen.getAllByPlaceholderText(/search settings/i)[0];
    fireEvent.change(box, { target: { value: 'triage auto' } });
    const hit = await screen.findByTestId('search-result-section-triage-automation');
    fireEvent.click(hit);
    expect(await screen.findByText('Verdict inheritance window')).toBeTruthy();
  });
});

describe('the Apply bar names its staged edits', () => {
  it('shows a chip per dirty setting; the chip discards individually', async () => {
    renderAt('/config');
    await screen.findByText('Fast verdict');
    fireEvent.click(screen.getByRole('switch', { name: 'fast_triage_enabled' }));
    const chip = await screen.findByTestId('chip-fast_triage_enabled');
    expect(chip.textContent).toContain('Fast verdict');
    fireEvent.click(screen.getByRole('button', { name: /discard fast verdict/i }));
    await waitFor(() => expect(screen.queryByTestId('chip-fast_triage_enabled')).toBeNull());
  });

  it('a chip click returns to the owning section and highlights the row', async () => {
    renderAt('/config');
    await screen.findByText('Fast verdict');
    fireEvent.click(screen.getByRole('switch', { name: 'fast_triage_enabled' }));
    await screen.findByTestId('chip-fast_triage_enabled');
    // Wander to another section — the staged edit and its chip survive.
    const navLink = screen
      .getAllByText('Triage automation')
      .find((el) => el.closest('nav'))!;
    fireEvent.click(navLink);
    await screen.findByText('Verdict inheritance window');
    fireEvent.click(screen.getByTestId('chip-fast_triage_enabled'));
    await waitFor(() => {
      const row = document.querySelector('[data-setting-key="fast_triage_enabled"]');
      expect(row).not.toBeNull();
      expect(row!.getAttribute('data-highlighted')).toBe('true');
    });
  });
});

describe('palette hand-off', () => {
  it('router state highlightKey flashes the row on arrival', async () => {
    renderAt({ pathname: '/config', hash: '#agent', state: { highlightKey: 'fast_triage_enabled' } });
    await screen.findByText('Fast verdict');
    const row = document.querySelector('[data-setting-key="fast_triage_enabled"]')!;
    expect(row.getAttribute('data-highlighted')).toBe('true');
  });
});
