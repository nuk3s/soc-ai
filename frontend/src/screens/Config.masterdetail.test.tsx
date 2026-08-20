// Config restructure (dogfood 2026-08-01): the page was one 32,000px scroll of
// 31 sections with no search. It is now master-detail — the two-level nav is the
// master, the content pane renders ONLY the selected section — with a settings
// search that spans every section, an Apply bar that NAMES its staged edits
// (clickable chips, per-chip discard), and a remembered last section.
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
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

// Both settings are marked day1 — this suite is about section switching,
// search, deep-links and the apply bar, not the tier split (that lives in
// Config.day1tier.test.tsx). day1: true keeps every group's Advanced fold
// empty (advItems.length === 0 skips the fold entirely), so these rows render
// exactly as they did before the day1 feature existed.
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
        day1: true,
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
        day1: true,
      },
    ],
  },
]);

// A section that only the SECOND (and later) GET /config carries. It is the
// refetch test's landing signal: it renders in the nav, which is on screen
// whichever section the content pane settles on, so waiting for it proves the
// refetch resolved, the layout was rebuilt from it, and the deep-link effect
// re-ran — the exact sequence the A6 defect rides on. Waiting on anything the
// apply alone produces would assert against a screen that hasn't got there yet.
const REFETCHED = vi.hoisted(() => 'Refetched marker');
const CALLS = vi.hoisted(() => ({ config: 0 }));

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  // A fresh array per call, like a real fetch: the layout memo keys on the
  // groups' identity, so a mock handing back one frozen array would hide every
  // defect that only fires when the layout is rebuilt (the refetch test below).
  getConfig: vi.fn(() => {
    CALLS.config += 1;
    const groups = GROUPS.map((g) => ({ ...g }));
    if (CALLS.config > 1) {
      groups.push({
        title: REFETCHED,
        parent: 'Data & Enrichment',
        items: [
          {
            key: 'refetch_marker',
            label: 'Refetched setting',
            help: 'Only the refetched config carries this.',
            source: 'db',
            apply: 'hot',
            type: 'toggle',
            value: false,
            day1: false,
          },
        ],
      });
    }
    return Promise.resolve({ groups, tokens: [], users: [], dangerHost: '' });
  }),
  setSetting: vi.fn(() => Promise.resolve({ ok: true, restart_required: false })),
  listUsers: vi.fn().mockResolvedValue({ users: [] }),
  listDangerSettings: vi.fn().mockResolvedValue([]),
  getGatewayModels: vi.fn().mockResolvedValue({ ok: true, models: [] }),
  getInternalIdentifiers: vi.fn().mockResolvedValue({
    groups: [],
    last_scan: { running: false, last_scan: null, last_summary: null, note: null },
  }),
}));

import { getConfig, setSetting } from '../lib/api';
import { Config } from './Config';

const renderAt = (entry: string | { pathname: string; hash?: string; state?: unknown }) =>
  render(
    <MemoryRouter initialEntries={[entry as never]}>
      <Config />
    </MemoryRouter>,
  );

/** Reads the router's own idea of the URL back out, for the nav-URL tests. */
function Url() {
  const l = useLocation();
  return <span data-testid="url">{`${l.pathname}${l.search}${l.hash}`}</span>;
}

const renderWithUrl = (entry: string) =>
  render(
    <MemoryRouter initialEntries={[entry]}>
      <Config />
      <Url />
    </MemoryRouter>,
  );

beforeEach(() => {
  localStorage.clear();
  CALLS.config = 0;
  // Call history survives the whole file otherwise, so "has it been called
  // twice" would read a running total from the tests above and never come true.
  vi.mocked(getConfig).mockClear();
  vi.mocked(setSetting).mockClear();
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

  it('a fresh mount honours the hash over the remembered section', async () => {
    // A bookmark, the sidebar's own version line (/config#about) and every
    // palette jump land this way. The remembered section is for a plain visit;
    // an explicit hash always wins, on the first populate rather than a tick
    // later (finding A6, 2026-08-11).
    localStorage.setItem('soc-ai:config:section', 'agent');
    renderAt({ pathname: '/config', hash: '#users' });
    expect(await screen.findByText('Create user')).toBeTruthy();
    expect(screen.queryByText('Fast verdict')).toBeNull();
  });

  it('a config refetch does not yank the analyst back to the entry hash', async () => {
    // The real A6 defect: `navigateToSection` moved the URL with a raw
    // history.replaceState, so react-router's `location.hash` stayed pinned to
    // whatever the page was ENTERED with. Applying a setting refetches the
    // config, which rebuilds the layout, which re-ran the deep-link effect —
    // and it re-applied the stale entry hash, throwing the analyst out of the
    // section they were editing while the address bar still read the other one.
    renderAt({ pathname: '/config', hash: '#triage-automation' });
    await screen.findByText('Verdict inheritance window');

    const navLink = screen.getAllByText('Agent').find((el) => el.closest('nav'))!;
    fireEvent.click(navLink);
    await screen.findByText('Fast verdict');

    fireEvent.click(screen.getByRole('switch', { name: 'fast_triage_enabled' }));
    fireEvent.click(await screen.findByRole('button', { name: /apply change/i }));

    await waitFor(() => expect(vi.mocked(setSetting)).toHaveBeenCalled());
    // Wait for the REFETCH, not for the apply. The apply's own effects (the
    // ✓ banner, the cleared chips, the switch re-reading the server value) all
    // land a render BEFORE `setNonce` has fetched anything, so asserting after
    // them fires before the layout rebuild and the effect re-run that carry the
    // defect — a green that proves nothing. The marker section exists only in
    // the second response, and only in the nav, so it is on screen whether the
    // pane held its place or was yanked back.
    await waitFor(() => expect(vi.mocked(getConfig)).toHaveBeenCalledTimes(2));
    expect((await screen.findAllByText('Refetched marker')).length).toBeGreaterThan(0);

    expect(screen.queryByText('Verdict inheritance window')).toBeNull();
    expect(screen.getByRole('switch', { name: 'fast_triage_enabled' })).toBeTruthy();
  });

  it('a nav click moves the hash and keeps the query string', async () => {
    // Going through the router is what fixed A6, but a partial Path defaults
    // `search` to '' — so unless it is carried over, the first nav click
    // silently drops the query the analyst arrived with. Nothing links to
    // /config with one today; the point is that adding a ?tab= or ?highlight=
    // later must not need this file to be right a second time.
    renderWithUrl('/config?highlight=fast_triage_enabled#triage-automation');
    await screen.findByText('Verdict inheritance window');
    expect(screen.getByTestId('url').textContent).toBe(
      '/config?highlight=fast_triage_enabled#triage-automation',
    );

    fireEvent.click(screen.getAllByText('Agent').find((el) => el.closest('nav'))!);
    await screen.findByText('Fast verdict');
    expect(screen.getByTestId('url').textContent).toBe(
      '/config?highlight=fast_triage_enabled#agent',
    );
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
