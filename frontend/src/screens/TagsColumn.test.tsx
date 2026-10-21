// The owner: "The 'Depth' and 'hunt' tags mess up the UI by making the titles
// all jagged. They need their own column to keep formatting." (2026-10-07)
//
// The chips of a row move into one fixed-width tags column at the end of the
// row, in one order, on every list. These tests mount each list with a row
// that carries every chip and a row that carries none, and hold three facts:
// the title cell sits in the same column on both rows, the title cell holds the
// title and no chip, and the tags cell holds the chips in the one order.
// happy-dom has no layout engine, so "the same x" is the same grid column.
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  // Investigations and the Dashboard
  listInvestigations: vi.fn(),
  listSavedViews: vi.fn().mockResolvedValue([]),
  // Alerts
  getAlerts: vi.fn(),
  getMe: vi.fn().mockResolvedValue({ username: 'me', role: 'analyst', status: '' }),
  getAlertGroupEvents: vi.fn().mockResolvedValue([]),
  getInvestigation: vi.fn(() => new Promise(() => {})),
  getInvestigations: vi.fn().mockResolvedValue([]),
  getRepresentative: vi.fn(),
  getAutoTriageStatus: vi.fn().mockResolvedValue({ active: false, hunted: 0, total: 0 }),
  getWorkspaces: vi.fn().mockResolvedValue([]),
  getNotifications: vi.fn().mockResolvedValue([]),
  getHealth: vi.fn().mockResolvedValue(null),
  // Hunts
  getHunts: vi.fn(),
  getHuntStats: vi.fn().mockResolvedValue([]),
  getHuntTemplates: vi.fn().mockResolvedValue([]),
  getHuntSchedules: vi.fn().mockResolvedValue({ schedules: [], masterSwitchEnabled: true }),
  getShadowHits: vi.fn().mockResolvedValue({ hits: [], unread: 0 }),
  getAnalytics: vi.fn().mockResolvedValue({ analytics: [], counts: {} }),
  getAnalyticHits: vi.fn().mockResolvedValue({
    hits: [],
    counts: { all: 0, unread: 0, live: 0, shadow: 0 },
  }),
  getNeedsYou: vi
    .fn()
    .mockResolvedValue({ unread_shadow_hits: 0, leads_needing_decision: 0, total: 0 }),
  getLeads: vi.fn().mockResolvedValue([]),
  getHuntCatalog: vi.fn().mockResolvedValue({
    specs: [],
    sweeps_enabled: true,
    sweep_interval_minutes: 60,
    sweep_window_minutes: 61,
    last_sweep_at: null,
  }),
  // The Dashboard
  getDossierConflicts: vi.fn().mockResolvedValue({ pending: 0, rows: [] }),
  getQualityEvalStatus: vi.fn().mockResolvedValue({ running: false }),
  getDataSources: vi.fn().mockResolvedValue({ sources: [] }),
  getQualityTrend: vi.fn().mockResolvedValue({ points: [] }),
  getPreflight: vi.fn().mockResolvedValue({
    status: 'green',
    failing: 0,
    warned: 0,
    checked_at: '2026-08-19T00:00:00+00:00',
  }),
  getPreflightDetail: vi
    .fn()
    .mockResolvedValue({ rows: [], checked_at: '2026-08-19T00:00:00+00:00' }),
}));
vi.mock('../lib/notifications', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/notifications')>()),
  getDismissed: () => new Set<string>(),
  dismissNotification: vi.fn(),
  dismissMany: vi.fn(),
  formatNotificationTitle: (t: string) => t,
}));

import { RowTags, TAGS_COLUMN, TAGS_HEADER_TITLE } from '../components/RowTags';
import { getAlerts, getHunts, listInvestigations } from '../lib/api';
import { DemoProvider } from '../lib/demo';
import { ToastProvider } from '../lib/toast';
import type { AlertGroup, HuntRow, InvestigationList, InvestigationRow } from '../lib/types';
import { ShellProvider } from '../shell/ShellContext';
import { queueOf } from '../test/alertQueue';
import { Alerts } from './Alerts';
import { Dashboard } from './Dashboard';
import { Hunts } from './Hunts';
import { Investigations } from './Investigations';

const FULL_NAME = 'Beacon to a rare external address on a fixed cadence from a workstation';
const BARE_NAME = 'ET INFO STUN Binding Request';

/** The chips a title cell must never hold. */
const CHIP_TEXT = [
  'Synthetic evaluation data',
  'Backtest replay',
  'Depth:',
  'Dismissed',
  'Superseded',
  'uncounted',
  'scheduled',
  'catalog',
];

/** The column of `cell` in its grid row. */
function columnOf(cell: Element): number {
  return Array.from(cell.parentElement!.children).indexOf(cell);
}

/** The text of each chip in a tags cell, in the order the cell draws them. */
function chipTexts(cell: HTMLElement): string[] {
  return Array.from(cell.children).map((c) => (c.textContent ?? '').trim());
}

function expectNoChip(cell: HTMLElement, name: string) {
  expect(cell.textContent?.trim()).toBe(name);
  for (const text of CHIP_TEXT) expect(cell.textContent).not.toContain(text);
  expect(cell.querySelector('[data-testid^="run-class"]')).toBeNull();
  expect(cell.querySelector('[data-testid^="backtest-replay"]')).toBeNull();
  expect(cell.querySelector('[data-testid^="subject-type"]')).toBeNull();
  expect(cell.querySelector('[data-testid="counts-unknown"]')).toBeNull();
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('the tags cell', () => {
  it('draws every chip in the one order', () => {
    render(
      <MemoryRouter>
        <RowTags
          kind="hunt"
          subjectHunt
          huntKind="scheduled"
          depth={{ runClass: 'deep' }}
          synthetic
          replay
          counts={<span>3 acknowledged</span>}
          dismissed
          superseded="A newer run replaced this run."
          links={<button type="button">2 earlier</button>}
          chatCount={4}
        />
      </MemoryRouter>,
    );
    expect(chipTexts(screen.getByTestId('row-tags'))).toEqual([
      'hunt',
      'hunt',
      'scheduled',
      'Depth: deep',
      'Synthetic evaluation data',
      'Backtest replay',
      '3 acknowledged',
      'Dismissed',
      'Superseded',
      '2 earlier',
      '4',
    ]);
  });

  it('renders an empty cell on a row with no chip, so the column holds its width', () => {
    render(<RowTags />);
    const cell = screen.getByTestId('row-tags');
    expect(cell.children).toHaveLength(0);
  });

  // The widest chip, "Synthetic evaluation data", measures 154px in Chromium.
  it('has one fixed width that fits the widest chip', () => {
    expect(TAGS_COLUMN).toMatch(/^\d+px$/);
    expect(Number.parseInt(TAGS_COLUMN, 10)).toBeGreaterThanOrEqual(156);
  });
});

const invRow = (over: Partial<InvestigationRow>): InvestigationRow => ({
  id: 'INV-1',
  name: BARE_NAME,
  kind: 'suricata',
  verdict: 'false_positive',
  conf: 0.88,
  host: '192.0.2.10',
  dst: '198.51.100.7',
  status: 'complete',
  when: '2h ago',
  ts: '2026-10-04T00:00:00+00:00',
  alertId: 'ev-1',
  isPrimary: true,
  fallback: false,
  ...over,
});

const invList = (rows: InvestigationRow[]): InvestigationList => ({
  rows,
  total: rows.length,
  running: 0,
  truePositives: 0,
  totalAll: rows.length,
  active: false,
  limit: 50,
  offset: 0,
});

describe('the Investigations list', () => {
  const FULL = invRow({
    id: 'INV-FULL',
    name: FULL_NAME,
    kind: 'hunt',
    subjectType: 'hunt',
    isSynthEval: true,
    ranBy: 'backtest',
    runClass: 'deep',
    errorDismissed: true,
    isPrimary: false,
    chatCount: 2,
    alertId: 'ev-full',
  });
  const BARE = invRow({ id: 'INV-BARE', alertId: 'ev-bare' });

  async function mount() {
    vi.mocked(listInvestigations).mockResolvedValue(invList([FULL, BARE]));
    render(
      <MemoryRouter initialEntries={['/investigations']}>
        <Investigations />
      </MemoryRouter>,
    );
    await screen.findByTestId('inv-name-INV-FULL');
  }

  it('puts the name of both rows in the same column, with no chip beside it', async () => {
    await mount();
    const full = screen.getByTestId('inv-title-cell-INV-FULL');
    const bare = screen.getByTestId('inv-title-cell-INV-BARE');
    expect(columnOf(full)).toBe(columnOf(bare));
    expectNoChip(full, FULL_NAME);
    expectNoChip(bare, BARE_NAME);
    // The header over the name column is Detection.
    const header = screen.getByRole('button', { name: 'Sort by Detection' }).parentElement!;
    expect(columnOf(header)).toBe(columnOf(full));
  });

  it('draws the chips in the tags column in the one order', async () => {
    await mount();
    const tags = screen.getByTestId('inv-tags-INV-FULL');
    // One hunt chip: the type chip of a hunt run already names the subject
    // (dogfood 2026-10-19, STE item 30).
    expect(chipTexts(tags)).toEqual([
      'hunt',
      'Depth: deep',
      'Synthetic evaluation data',
      'Backtest replay',
      'Dismissed',
      'Superseded',
      '2',
    ]);
    // Negative control: the bare row has only its type. A row with no
    // recorded depth shows no depth chip (dogfood 2026-10-19, STE item 29).
    expect(chipTexts(screen.getByTestId('inv-tags-INV-BARE'))).toEqual(['suricata']);
    // The tags column sits after When and before the delete gutter.
    const header = screen.getByTestId('tags-header');
    expect(header.textContent).toBe('Tags');
    expect(header.getAttribute('title')).toBe(TAGS_HEADER_TITLE);
    expect(columnOf(header)).toBe(columnOf(tags));
    expect(columnOf(tags)).toBe(tags.parentElement!.children.length - 2);
  });
});

const GROUP: AlertGroup = {
  id: 'es-1',
  name: FULL_NAME,
  kind: 'sigma',
  sev: 'high',
  count: 16,
  verdict: 'untriaged',
  conf: null,
  latest: '1m ago',
  inherited: false,
  events: [],
};

describe('the Alerts list', () => {
  async function mount() {
    vi.mocked(getAlerts).mockResolvedValue(
      queueOf([
        { ...GROUP, ackedCount: 3, escalatedCount: null },
        { ...GROUP, id: 'es-2', name: BARE_NAME, kind: 'suricata', count: 1, ackedCount: 0, escalatedCount: 0 },
      ]),
    );
    render(
      <ToastProvider>
        <MemoryRouter initialEntries={['/alerts']}>
          <ShellProvider>
            <Alerts />
          </ShellProvider>
        </MemoryRouter>
      </ToastProvider>,
    );
    await screen.findByText(FULL_NAME);
  }

  it('puts the name of both rows in the same column, with no chip beside it', async () => {
    await mount();
    const cells = screen.getAllByTestId('alert-title-cell');
    expect(cells).toHaveLength(2);
    const [full, bare] = cells;
    expect(columnOf(full)).toBe(columnOf(bare));
    // The fire count stays with the name. It is a count, not a chip.
    expect(within(full).getByTestId('alert-name').textContent).toBe(FULL_NAME);
    expect(full.textContent).toContain('×16');
    for (const text of CHIP_TEXT) expect(full.textContent).not.toContain(text);
    expect(within(full).queryByTitle('3 acknowledged')).toBeNull();
    expect(within(full).queryByTestId('counts-unknown')).toBeNull();
    expect(within(bare).getByTestId('alert-name').textContent).toBe(BARE_NAME);
  });

  it('draws the type and the handled counts in the tags column', async () => {
    await mount();
    const header = screen.getByTestId('tags-header');
    const full = screen.getByTestId('alert-tags-es-1');
    expect(chipTexts(full)).toEqual(['sigma', '3', 'uncounted']);
    expect(within(full).getByTitle('3 acknowledged')).toBeTruthy();
    // Negative control: a counted group with no handled alert has its type only.
    expect(chipTexts(screen.getByTestId('alert-tags-es-2'))).toEqual(['suricata']);
    expect(columnOf(header)).toBe(columnOf(full));
    expect(columnOf(full)).toBe(full.parentElement!.children.length - 2);
  });
});

const HUNT = {
  id: 'H-FULL',
  objective: FULL_NAME,
  kind: 'scheduled',
  status: 'complete',
  findingCount: 1,
  threatFindingCount: 1,
  outcome: 'threats',
  affectedHosts: 1,
  confidence: 0.8,
  startedBy: 'analyst',
  starter: 'analyst',
  leadId: null,
  when: '4m',
  ts: '2026-10-05T10:00:00+00:00',
  chatCount: 3,
  isSynthEval: true,
} as HuntRow;

describe('the Hunts table', () => {
  async function mount() {
    vi.mocked(getHunts).mockResolvedValue([
      HUNT,
      { ...HUNT, id: 'H-BARE', objective: BARE_NAME, kind: 'chat', chatCount: 0, isSynthEval: false },
    ]);
    render(
      <MemoryRouter initialEntries={['/hunts']}>
        <DemoProvider demo={false}>
          <ShellProvider>
            <Routes>
              <Route path="/hunts" element={<Hunts />} />
            </Routes>
          </ShellProvider>
        </DemoProvider>
      </MemoryRouter>,
    );
    await screen.findByText(FULL_NAME);
  }

  it('puts the objective of both rows in the same column, with no chip beside it', async () => {
    await mount();
    const [full, bare] = screen.getAllByTestId('hunt-title-cell');
    expect(columnOf(full)).toBe(columnOf(bare));
    expectNoChip(full, FULL_NAME);
    expectNoChip(bare, BARE_NAME);
  });

  it('draws the hunt kind, the synthetic mark and the chat count in the tags column', async () => {
    await mount();
    const full = screen.getByTestId('hunt-tags-H-FULL');
    expect(chipTexts(full)).toEqual(['scheduled', 'Synthetic evaluation data', '3']);
    // Negative control: a manual hunt with no mark has an empty tags cell.
    expect(chipTexts(screen.getByTestId('hunt-tags-H-BARE'))).toEqual([]);
    const header = screen.getByTestId('tags-header');
    expect(columnOf(header)).toBe(columnOf(full));
  });
});

describe('the Dashboard recent list', () => {
  it('puts the name first on both rows and the chips in the tags cell at the end', async () => {
    vi.mocked(listInvestigations).mockResolvedValue(
      invList([
        invRow({ id: 'INV-FULL', name: FULL_NAME, kind: 'hunt', isSynthEval: true }),
        invRow({ id: 'INV-BARE' }),
      ]),
    );
    render(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>,
    );
    await screen.findByText(FULL_NAME);
    const rows = screen.getAllByTestId('recent-investigation');
    const [fullRow, bareRow] = rows;
    const full = within(fullRow).getByTestId('recent-title-cell');
    const bare = within(bareRow).getByTestId('recent-title-cell');
    // The title cell is the first cell of both rows.
    expect(columnOf(full)).toBe(0);
    expect(columnOf(bare)).toBe(0);
    for (const text of CHIP_TEXT) expect(full.textContent).not.toContain(text);
    expect(full.querySelector('a')!.textContent).toBe(FULL_NAME);
    // The tags cell is the last cell of the row, and has the one width.
    const tags = within(fullRow).getByTestId('recent-tags-INV-FULL');
    expect(chipTexts(tags)).toEqual(['hunt', 'Synthetic evaluation data']);
    const slot = tags.parentElement!;
    expect(columnOf(slot)).toBe(fullRow.children.length - 1);
    expect(slot.style.width).toBe(TAGS_COLUMN);
    expect(chipTexts(within(bareRow).getByTestId('recent-tags-INV-BARE'))).toEqual(['suricata']);
  });
});
