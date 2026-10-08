// The Dashboard panels sit on a grid an operator can rearrange (owner request
// 2026-10-06: "The dashboard panels need to be user movable, almost like you
// can in kibana"). These tests render the real grid and pin the contract:
// the shipped order, a saved layout from the API, a saved layout that names a
// panel this build does not have, Reset, the edit toggle, and the browser
// store that a deployment with authentication off uses.
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { DashboardLayoutPanel } from '../lib/types';

// happy-dom lays nothing out, so every width reads 0. react-grid-layout needs
// a real width to place cells in edit mode: give it a 1200 px container.
vi.mock('react-grid-layout', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-grid-layout')>();
  return {
    ...actual,
    useContainerWidth: () => ({
      width: 1200,
      mounted: true,
      containerRef: { current: null },
      measureWidth: () => undefined,
    }),
  };
});

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAlerts: vi.fn().mockResolvedValue({ groups: [], truncated: false, other_docs: 0 }),
  listInvestigations: vi.fn().mockResolvedValue({
    rows: [],
    total: 0,
    running: 0,
    truePositives: 0,
    totalAll: 0,
    active: false,
    limit: 100,
    offset: 0,
  }),
  getAutoTriageStatus: vi.fn().mockResolvedValue({ active: false, hunted: 0, total: 0 }),
  getDataSources: vi.fn().mockResolvedValue({ sources: [] }),
  getDetectionTuningSummary: vi.fn().mockResolvedValue({ pending: 0 }),
  getDossierConflicts: vi.fn().mockResolvedValue({ pending: 0, rows: [] }),
  getShadowHits: vi.fn().mockResolvedValue({ hits: [], unread: 0 }),
  getQualityTrend: vi.fn().mockResolvedValue({ points: [] }),
  getQualityEvalStatus: vi.fn().mockResolvedValue({ running: false }),
  getHealth: vi.fn().mockResolvedValue(null),
  getPreflight: vi.fn().mockResolvedValue({
    status: 'green',
    failing: 0,
    warned: 0,
    checked_at: '2026-10-06T00:00:00+00:00',
  }),
  getPreflightDetail: vi.fn().mockResolvedValue({ rows: [], checked_at: '2026-10-06T00:00:00+00:00' }),
  // The assistant is off here, so its panel is absent and no chat GET runs.
  getAbout: vi.fn().mockResolvedValue({
    version: '1.5.2',
    repo_url: 'https://example.invalid/soc-ai',
    license: 'AGPL-3.0',
    update_check_enabled: false,
    general_chat_enabled: false,
  }),
  getMe: vi.fn(),
  getDashboardLayout: vi.fn(),
  putDashboardLayout: vi.fn(),
  deleteDashboardLayout: vi.fn(),
}));

import {
  ApiError,
  deleteDashboardLayout,
  getDashboardLayout,
  getDetectionTuningSummary,
  getMe,
  putDashboardLayout,
} from '../lib/api';
import { LAYOUT_STORAGE_KEY } from '../lib/dashboardLayout';
import { Dashboard } from './Dashboard';

const SIGNED_IN = { username: 'ana', role: 'analyst', status: '', signed_in: true };
const AUTH_OFF = { username: 'admin', role: 'admin', status: '', signed_in: false };

/** The shipped order with the assistant off and no nudge showing. */
const SHIPPED_ORDER = [
  'kpi-awaiting',
  'kpi-alert-events',
  'kpi-true-positives',
  'kpi-running',
  'outcomes',
  'recent',
  'setup-health',
  'auto-investigate',
  'verdict-quality',
  'enrichment',
];

/** A saved layout: recent across the top, setup health and outcomes under it. */
const SAVED: DashboardLayoutPanel[] = [
  { id: 'recent', x: 0, y: 0, w: 12, h: 1 },
  { id: 'setup-health', x: 0, y: 1, w: 4, h: 1 },
  { id: 'outcomes', x: 4, y: 1, w: 8, h: 1 },
];

const mount = () =>
  render(
    <MemoryRouter initialEntries={['/dashboard']}>
      <Dashboard />
    </MemoryRouter>,
  );

const cells = () =>
  Array.from(document.querySelectorAll<HTMLElement>('[data-panel]')).map((el) => el.dataset.panel);

const cell = (id: string) => document.querySelector<HTMLElement>(`[data-panel="${id}"]`)!;

/** The edit toggle. It reads "Edit layout", and "Done" while the editor is on. */
const editToggle = () => screen.getByRole('button', { name: /^(Edit layout|Done)$/ });

/** Wait until the layout read has settled and the toggle can be used. */
const ready = async () => {
  await screen.findByText('Investigation outcomes');
  await waitFor(() => expect(editToggle()).toBeEnabled());
};

beforeEach(() => {
  vi.clearAllMocks();
  localStorage.clear();
  vi.mocked(getMe).mockResolvedValue(SIGNED_IN);
  vi.mocked(getDetectionTuningSummary).mockResolvedValue({ pending: 0 });
  vi.mocked(getDashboardLayout).mockResolvedValue({ panels: null });
  vi.mocked(putDashboardLayout).mockImplementation(async (panels) => ({ panels }));
  vi.mocked(deleteDashboardLayout).mockResolvedValue({ ok: true, removed: true });
});

afterEach(() => {
  localStorage.clear();
});

describe('Dashboard layout: the shipped layout', () => {
  it('renders the panels in the shipped order, in the shipped columns', async () => {
    mount();
    await ready();
    expect(cells()).toEqual(SHIPPED_ORDER);
    // Four tiles of three columns, the Needs-you tile first, then eight
    // columns left and four right: the arrangement the Dashboard had before
    // the grid.
    expect(cell('kpi-awaiting').style.gridColumn).toBe('1 / span 3');
    expect(cell('kpi-alert-events').style.gridColumn).toBe('4 / span 3');
    expect(cell('kpi-running').style.gridColumn).toBe('10 / span 3');
    expect(cell('outcomes').style.gridColumn).toBe('1 / span 8');
    expect(cell('recent').style.gridColumn).toBe('1 / span 8');
    expect(cell('setup-health').style.gridColumn).toBe('9 / span 4');
    expect(cell('enrichment').style.gridColumn).toBe('9 / span 4');
    expect(editToggle()).toHaveAttribute('aria-pressed', 'false');
  });

  it('keeps a conditional panel in its shipped slot when it shows', async () => {
    vi.mocked(getDetectionTuningSummary).mockResolvedValue({ pending: 2 });
    mount();
    await screen.findByText('Detection tuning');
    expect(cells()).toEqual([...SHIPPED_ORDER, 'detection-tuning']);
    expect(cell('detection-tuning').style.gridColumn).toBe('9 / span 4');
  });
});

describe('Dashboard layout: a saved layout', () => {
  it('reorders and resizes the panels from the API', async () => {
    vi.mocked(getDashboardLayout).mockResolvedValue({ panels: SAVED });
    mount();
    await ready();
    await waitFor(() => expect(cells()[0]).toBe('recent'));
    expect(cells().slice(0, 3)).toEqual(['recent', 'setup-health', 'outcomes']);
    expect(cell('recent').style.gridColumn).toBe('1 / span 12');
    expect(cell('setup-health').style.gridColumn).toBe('1 / span 4');
    expect(cell('outcomes').style.gridColumn).toBe('5 / span 8');
    // Every panel the layout does not name is still on the Dashboard.
    expect(new Set(cells())).toEqual(new Set(SHIPPED_ORDER));
    expect(putDashboardLayout).not.toHaveBeenCalled();
  });

  it('drops a panel this build does not have and keeps the rest', async () => {
    vi.mocked(getDashboardLayout).mockResolvedValue({
      panels: [{ id: 'retired-panel', x: 0, y: 0, w: 12, h: 1 }, ...SAVED],
    });
    mount();
    await ready();
    await waitFor(() => expect(cells()[0]).toBe('recent'));
    expect(document.querySelector('[data-panel="retired-panel"]')).toBeNull();
    expect(cells().slice(0, 3)).toEqual(['recent', 'setup-health', 'outcomes']);
    expect(new Set(cells())).toEqual(new Set(SHIPPED_ORDER));
  });

  it('Reset layout calls DELETE and restores the shipped layout', async () => {
    vi.mocked(getDashboardLayout).mockResolvedValue({ panels: SAVED });
    mount();
    await ready();
    await waitFor(() => expect(cells()[0]).toBe('recent'));

    fireEvent.click(editToggle());
    const reset = screen.getByRole('button', { name: 'Reset layout' });
    expect(reset).toBeEnabled();
    fireEvent.click(reset);

    await waitFor(() => expect(deleteDashboardLayout).toHaveBeenCalledTimes(1));
    expect(cells()).toEqual(SHIPPED_ORDER);
    // Nothing left to reset, and no save went out on the way.
    expect(screen.getByRole('button', { name: 'Reset layout' })).toBeDisabled();
    expect(putDashboardLayout).not.toHaveBeenCalled();
  });

  it('says where a signed-in user keeps the layout', async () => {
    mount();
    await ready();
    fireEvent.click(editToggle());
    expect(screen.getByText(/soc-ai keeps this layout for your user account/)).toBeInTheDocument();
  });
});

describe('Dashboard layout: the edit toggle', () => {
  it('gates dragging, resizing and the keyboard', async () => {
    mount();
    await ready();

    // Normal use: no handle, and react-grid-layout has dragging and resizing off.
    expect(screen.queryAllByRole('button', { name: /^Move the / })).toHaveLength(0);
    for (const id of SHIPPED_ORDER) {
      expect(cell(id)).not.toHaveClass('react-draggable');
      expect(cell(id)).toHaveClass('react-resizable-hide');
    }
    // A key press on a panel moves nothing.
    fireEvent.keyDown(cell('outcomes'), { key: 'ArrowDown' });
    expect(cells()).toEqual(SHIPPED_ORDER);

    fireEvent.click(editToggle());
    expect(editToggle()).toHaveAttribute('aria-pressed', 'true');
    const handles = screen.getAllByRole('button', { name: /^Move the / });
    expect(handles).toHaveLength(SHIPPED_ORDER.length);
    for (const id of SHIPPED_ORDER) {
      expect(cell(id)).toHaveClass('react-draggable');
      expect(cell(id)).not.toHaveClass('react-resizable-hide');
      expect(cell(id).querySelector('.react-resizable-handle-se')).not.toBeNull();
    }

    // The keyboard moves the outcomes chart under the recent list.
    const handle = screen.getByRole('button', { name: 'Move the Investigation outcomes panel' });
    expect(handle).toHaveAttribute('aria-describedby', 'dashboard-layout-help');
    handle.focus();
    fireEvent.keyDown(handle, { key: 'ArrowDown' });
    await waitFor(() => expect(cells().indexOf('recent')).toBeLessThan(cells().indexOf('outcomes')));
    expect(screen.getByTestId('layout-announcement')).toHaveTextContent(
      'The Investigation outcomes panel moved down.',
    );
    // The focus stays on the handle that moved.
    expect(document.activeElement).toBe(
      screen.getByRole('button', { name: 'Move the Investigation outcomes panel' }),
    );
    await waitFor(() => expect(putDashboardLayout).toHaveBeenCalledTimes(1));
    const sent = vi.mocked(putDashboardLayout).mock.calls[0][0];
    const byId = new Map(sent.map((p) => [p.id, p]));
    expect(byId.get('recent')!.y).toBeLessThan(byId.get('outcomes')!.y);
    expect(sent).toHaveLength(14);

    // Off again: the handles go, and dragging is off.
    fireEvent.click(editToggle());
    expect(editToggle()).toHaveAttribute('aria-pressed', 'false');
    expect(screen.queryAllByRole('button', { name: /^Move the / })).toHaveLength(0);
    expect(cell('recent')).not.toHaveClass('react-draggable');
  });

  it('resizes a panel with Shift and an arrow key', async () => {
    mount();
    await ready();
    fireEvent.click(editToggle());
    const handle = screen.getByRole('button', { name: 'Move the Setup health panel' });
    fireEvent.keyDown(handle, { key: 'ArrowLeft', shiftKey: true });
    await waitFor(() => expect(putDashboardLayout).toHaveBeenCalledTimes(1));
    const setup = vi.mocked(putDashboardLayout).mock.calls[0][0].find((p) => p.id === 'setup-health')!;
    expect(setup.w).toBe(3);
    expect(screen.getByTestId('layout-announcement')).toHaveTextContent(
      'The Setup health panel is 3 columns wide.',
    );
  });

  it('locks the layout when the saved layout cannot be read', async () => {
    vi.mocked(getDashboardLayout).mockRejectedValue(new ApiError('boom', 500));
    mount();
    await screen.findByText('Investigation outcomes');
    await screen.findByText(/could not read your saved layout/);
    expect(editToggle()).toBeDisabled();
    // A read that failed must not let an edit save over the layout it missed.
    expect(putDashboardLayout).not.toHaveBeenCalled();
    expect(cells()).toEqual(SHIPPED_ORDER);
  });
});

describe('Dashboard layout: authentication off', () => {
  it('reads and writes localStorage and never calls the layout API', async () => {
    vi.mocked(getMe).mockResolvedValue(AUTH_OFF);
    localStorage.setItem(LAYOUT_STORAGE_KEY, JSON.stringify({ version: 1, panels: SAVED }));
    mount();
    await ready();
    await waitFor(() => expect(cells()[0]).toBe('recent'));
    expect(cells().slice(0, 3)).toEqual(['recent', 'setup-health', 'outcomes']);

    fireEvent.click(editToggle());
    expect(screen.getByText(/Authentication is off\. This browser keeps the layout\./)).toBeInTheDocument();

    const before = localStorage.getItem(LAYOUT_STORAGE_KEY);
    fireEvent.keyDown(screen.getByRole('button', { name: 'Move the Recent investigations panel' }), {
      key: 'ArrowDown',
    });
    await waitFor(() => expect(localStorage.getItem(LAYOUT_STORAGE_KEY)).not.toBe(before));
    const kept = JSON.parse(localStorage.getItem(LAYOUT_STORAGE_KEY)!) as {
      panels: DashboardLayoutPanel[];
    };
    expect(kept.panels).toHaveLength(14);
    expect(cells()[0]).not.toBe('recent');

    fireEvent.click(screen.getByRole('button', { name: 'Reset layout' }));
    expect(localStorage.getItem(LAYOUT_STORAGE_KEY)).toBeNull();
    expect(cells()).toEqual(SHIPPED_ORDER);

    // Give a debounced write every chance to fire before the negative control.
    await act(() => new Promise((r) => setTimeout(r, 500)));
    expect(getDashboardLayout).not.toHaveBeenCalled();
    expect(putDashboardLayout).not.toHaveBeenCalled();
    expect(deleteDashboardLayout).not.toHaveBeenCalled();
  });

  it('a signed-in user never touches the browser store', async () => {
    // The negative control for the test above: with a user row, the layout is
    // the server's, and a stale browser copy is ignored.
    localStorage.setItem(LAYOUT_STORAGE_KEY, JSON.stringify({ version: 1, panels: SAVED }));
    mount();
    await ready();
    expect(cells()).toEqual(SHIPPED_ORDER);
    expect(getDashboardLayout).toHaveBeenCalledTimes(1);
    expect(JSON.parse(localStorage.getItem(LAYOUT_STORAGE_KEY)!).panels).toEqual(SAVED);
  });
});

describe('Dashboard layout: a narrow window', () => {
  it('stacks the panels in reading order and offers no edit mode', async () => {
    const matchMedia = vi.spyOn(window, 'matchMedia').mockImplementation(
      (query: string) =>
        ({
          matches: false,
          media: query,
          onchange: null,
          addEventListener: () => undefined,
          removeEventListener: () => undefined,
          addListener: () => undefined,
          removeListener: () => undefined,
          dispatchEvent: () => false,
        }) as MediaQueryList,
    );
    try {
      vi.mocked(getDashboardLayout).mockResolvedValue({ panels: SAVED });
      mount();
      await screen.findByText('Investigation outcomes');
      await waitFor(() => expect(cells()[0]).toBe('recent'));
      expect(screen.queryByRole('button', { name: /^(Edit layout|Done)$/ })).toBeNull();
      // The reason the control is gone.
      expect(screen.getByTestId('layout-narrow').textContent).toBe(
        'Widen the window to move or resize panels.',
      );
      expect(cell('recent').style.gridColumn).toBe('1 / -1');
      expect(cell('kpi-awaiting').style.gridColumn).toBe('span 1');
      expect(within(cell('recent')).getByText('Recent investigations')).toBeInTheDocument();
    } finally {
      matchMedia.mockRestore();
    }
  });
});

// The label read "Edit layout" in both states (dogfood 2026-10-06).
describe('Dashboard layout: the edit toggle label', () => {
  it('reads Done while the editor is on, and Edit layout again after', async () => {
    mount();
    await ready();
    expect(editToggle().textContent).toBe('Edit layout');
    fireEvent.click(editToggle());
    expect(editToggle().textContent).toBe('Done');
    expect(editToggle()).toHaveAttribute('aria-pressed', 'true');
    fireEvent.click(editToggle());
    expect(editToggle().textContent).toBe('Edit layout');
    // NEGATIVE CONTROL. A wide window has no narrow-window line.
    expect(screen.queryByTestId('layout-narrow')).toBeNull();
  });
});
