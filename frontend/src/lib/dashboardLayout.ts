import { cloneLayout, moveElement, verticalCompactor, type Layout, type LayoutItem } from 'react-grid-layout/core';

// ---------------------------------------------------------------------------
// The Dashboard's panel grid: the panel ids, the shipped layout, and the pure
// functions that read, repair and edit a layout.
//
// The grid has 12 columns. A row is ROW_PX high, so a panel's height follows
// its content to within a few pixels. A panel's `h` is a FLOOR, never a cap: a
// panel always grows to hold its content. A cap would let a layout clip the
// failing row of the Setup health card or the pipeline-error line of a tile,
// and a clipped warning is a hidden warning. The shipped layout sets every
// floor to one row, so each panel is exactly as tall as it was before the grid.
//
// `y` is in the same row units. Vertical compaction packs every panel up
// against the one above it, so a stored `y` decides ORDER within a column, and
// the content decides where on the screen that order lands.
//
// The panel ids are a contract with the backend: soc_ai/store/dashboard_layout.py
// holds the same tuple, and tests/test_dashboard_layout.py fails when the two
// lists differ. Add a panel here and there in one change.
// ---------------------------------------------------------------------------

export const GRID_COLS = 12;
/** One grid row, in pixels. */
export const ROW_PX = 4;
/** The space under each panel, in pixels. The cell draws it, so the grid itself
 *  has no vertical margin and a row stays exactly ROW_PX. */
export const GAP_PX = 16;
/** Bounds the backend enforces on a saved layout. */
export const MAX_Y = 10_000;
export const MAX_H = 1_000;
/** Shift and an arrow key change a floor by this many rows (40 px). */
export const KEY_HEIGHT_STEP = 10;

export const PANEL_IDS = [
  'kpi-alert-events',
  'kpi-awaiting',
  'kpi-true-positives',
  'kpi-running',
  'kpi-shadow-hits',
  'outcomes',
  'recent',
  'setup-health',
  'assistant',
  'auto-investigate',
  'verdict-quality',
  'enrichment',
  'detection-tuning',
  'host-dossier',
] as const;

export type PanelId = (typeof PANEL_IDS)[number];

export interface PanelMeta {
  /** The name the drag handle and the announcements use. */
  title: string;
  /** A count tile. Tiles that start on one row share one height, the way the
   *  tile row did when it was a CSS grid. */
  tile: boolean;
  /** The narrowest the panel may get, in columns. */
  minW: number;
}

export const PANEL_META: Record<PanelId, PanelMeta> = {
  'kpi-alert-events': { title: 'Alert events', tile: true, minW: 2 },
  // The slot id predates the tile. A saved layout keeps the place it gave
  // "Awaiting investigation", and the Needs-you tile holds that place now.
  'kpi-awaiting': { title: 'Needs you', tile: true, minW: 2 },
  'kpi-true-positives': { title: 'True positives', tile: true, minW: 2 },
  'kpi-running': { title: 'Investigations running', tile: true, minW: 2 },
  'kpi-shadow-hits': { title: 'Shadow hits', tile: true, minW: 2 },
  outcomes: { title: 'Investigation outcomes', tile: false, minW: 3 },
  recent: { title: 'Recent investigations', tile: false, minW: 3 },
  'setup-health': { title: 'Setup health', tile: false, minW: 3 },
  assistant: { title: 'Ask soc-ai', tile: false, minW: 3 },
  'auto-investigate': { title: 'Auto-Investigate', tile: false, minW: 3 },
  'verdict-quality': { title: 'Verdict quality', tile: false, minW: 3 },
  enrichment: { title: 'Enrichment posture', tile: false, minW: 3 },
  'detection-tuning': { title: 'Detection tuning', tile: false, minW: 3 },
  'host-dossier': { title: 'Host dossier', tile: false, minW: 3 },
};

/** One panel's place in a layout. `x` and `w` are columns, `y` and `h` rows. */
export interface PanelSlot {
  id: PanelId;
  x: number;
  y: number;
  w: number;
  h: number;
}

/**
 * The shipped layout: the arrangement the Dashboard had before the grid.
 *
 * Four tiles of three columns, the Needs-you tile first because it is the
 * total of the work. The shadow-hit tile spans the eight columns of the left
 * column under them, then the outcomes chart and the recent list, and the side
 * column sits in four columns on the right. Every floor is one row, so every
 * panel takes the height of its content.
 *
 * The shadow-hit tile was three columns wide, and it left a hole of five
 * columns beside it that no panel could fill (dogfood 2026-10-19, R1-D25).
 */
export const DEFAULT_LAYOUT: readonly PanelSlot[] = Object.freeze([
  { id: 'kpi-alert-events', x: 3, y: 0, w: 3, h: 1 },
  { id: 'kpi-awaiting', x: 0, y: 0, w: 3, h: 1 },
  { id: 'kpi-true-positives', x: 6, y: 0, w: 3, h: 1 },
  { id: 'kpi-running', x: 9, y: 0, w: 3, h: 1 },
  { id: 'kpi-shadow-hits', x: 0, y: 1, w: 8, h: 1 },
  { id: 'outcomes', x: 0, y: 2, w: 8, h: 1 },
  { id: 'recent', x: 0, y: 3, w: 8, h: 1 },
  { id: 'setup-health', x: 8, y: 2, w: 4, h: 1 },
  { id: 'assistant', x: 8, y: 3, w: 4, h: 1 },
  { id: 'auto-investigate', x: 8, y: 4, w: 4, h: 1 },
  { id: 'verdict-quality', x: 8, y: 5, w: 4, h: 1 },
  { id: 'enrichment', x: 8, y: 6, w: 4, h: 1 },
  { id: 'detection-tuning', x: 8, y: 7, w: 4, h: 1 },
  { id: 'host-dossier', x: 8, y: 8, w: 4, h: 1 },
]);

const KNOWN = new Set<string>(PANEL_IDS);

export function isPanelId(value: unknown): value is PanelId {
  return typeof value === 'string' && KNOWN.has(value);
}

export function defaultLayout(): PanelSlot[] {
  return DEFAULT_LAYOUT.map((s) => ({ ...s }));
}

function isInt(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value);
}

/** One saved entry as a slot, or null when it is not one the grid can place. */
function readSlot(entry: unknown): PanelSlot | null {
  if (typeof entry !== 'object' || entry === null) return null;
  const { id, x, y, w, h } = entry as Record<string, unknown>;
  if (!isPanelId(id) || !isInt(x) || !isInt(y) || !isInt(w) || !isInt(h)) return null;
  if (x < 0 || w < 1 || x + w > GRID_COLS) return null;
  if (y < 0 || y > MAX_Y || h < 1 || h > MAX_H) return null;
  return { id, x, y, w, h };
}

/**
 * A saved layout made safe to place.
 *
 * An entry that names a panel this build does not have is dropped: a panel
 * removed in a later release must not leave a hole or crash the grid. An entry
 * the grid cannot place (a bad number, a second entry for one panel) is dropped
 * the same way. A panel the layout does not name takes its shipped column and
 * width at the bottom of the layout, in shipped order, so a panel added in a
 * later release appears for every operator with a saved layout. Nothing can
 * remove a panel: every known panel is in the result.
 */
export function normalizeLayout(raw: unknown): PanelSlot[] {
  const kept: PanelSlot[] = [];
  const seen = new Set<PanelId>();
  if (Array.isArray(raw)) {
    for (const entry of raw) {
      const slot = readSlot(entry);
      if (!slot || seen.has(slot.id)) continue;
      seen.add(slot.id);
      kept.push(slot);
    }
  }
  if (kept.length === 0) return defaultLayout();
  let bottom = kept.reduce((b, s) => Math.max(b, s.y + s.h), 0);
  for (const slot of DEFAULT_LAYOUT) {
    if (seen.has(slot.id)) continue;
    kept.push({ ...slot, y: Math.min(bottom, MAX_Y) });
    bottom += slot.h;
  }
  return kept;
}

/** The wire shape the backend and the browser store keep. */
export function toWire(layout: readonly PanelSlot[]): PanelSlot[] {
  return layout.map(({ id, x, y, w, h }) => ({ id, x, y, w, h }));
}

/** Rows a measured height needs, the gap under the panel included. */
export function rowsFor(px: number): number {
  return Math.max(1, Math.ceil((px + GAP_PX) / ROW_PX));
}

export function sameLayout(a: readonly PanelSlot[], b: readonly PanelSlot[]): boolean {
  if (a.length !== b.length) return false;
  return a.every((s, n) => {
    const t = b[n];
    return s.id === t.id && s.x === t.x && s.y === t.y && s.w === t.w && s.h === t.h;
  });
}

/**
 * The layout the grid draws: the panels on screen, each at least as tall as
 * its content, packed upward.
 *
 * `natural` is each panel's content height in rows, where it has been
 * measured. Count tiles that start on one row then take the height of the
 * tallest of them.
 */
export function effectiveLayout(
  stored: readonly PanelSlot[],
  present: ReadonlySet<string>,
  natural: Readonly<Partial<Record<PanelId, number>>>,
): LayoutItem[] {
  const items: LayoutItem[] = stored
    .filter((s) => present.has(s.id))
    .map((s) => {
      const content = natural[s.id];
      return {
        i: s.id,
        x: s.x,
        y: s.y,
        w: s.w,
        h: Math.max(s.h, content ?? 1),
        minW: PANEL_META[s.id].minW,
        maxW: GRID_COLS,
        minH: content ?? 1,
        maxH: MAX_H,
      };
    });
  const packed = verticalCompactor.compact(items, GRID_COLS);
  const rowHeight = new Map<number, number>();
  for (const it of packed) {
    if (isPanelId(it.i) && PANEL_META[it.i].tile) {
      rowHeight.set(it.y, Math.max(rowHeight.get(it.y) ?? 0, it.h));
    }
  }
  const evened = packed.map((it) =>
    isPanelId(it.i) && PANEL_META[it.i].tile ? { ...it, h: rowHeight.get(it.y) ?? it.h } : { ...it },
  );
  return cloneLayout(verticalCompactor.compact(evened, GRID_COLS));
}

interface Box {
  x: number;
  y: number;
  w: number;
  h: number;
}

/** Split boxes where a line along `axis` crosses none of them. */
function cut<T extends Box>(items: readonly T[], axis: 'x' | 'y'): T[][] {
  const size = axis === 'x' ? 'w' : 'h';
  const other = axis === 'x' ? 'y' : 'x';
  const sorted = [...items].sort((a, b) => a[axis] - b[axis] || a[other] - b[other]);
  const groups: T[][] = [];
  let end = Number.NEGATIVE_INFINITY;
  for (const it of sorted) {
    if (groups.length === 0 || it[axis] >= end) groups.push([it]);
    else groups[groups.length - 1].push(it);
    end = Math.max(end, it[axis] + it[size]);
  }
  return groups;
}

/**
 * The order a person reads the panels in: a recursive XY cut.
 *
 * Columns that no panel crosses are read left to right, each one top to bottom.
 * Where no such column exists, the top band (the panels above the first line
 * that crosses no panel) is read first, then the rest. Count tiles read the
 * way a row of tiles does: top to bottom, left to right. The shipped layout
 * reads as it always did: the tiles, then the left column (outcomes, recent),
 * then the side column. The grid renders panels in this order, so the tab
 * order and a screen reader follow the screen, and a narrow window stacks the
 * panels in this order.
 */
export function readingOrder<T extends Box & { i: string }>(items: readonly T[]): T[] {
  const rowMajor = () => [...items].sort((a, b) => a.y - b.y || a.x - b.x);
  if (items.length <= 1) return [...items];
  if (items.every((it) => isPanelId(it.i) && PANEL_META[it.i].tile)) return rowMajor();
  const columns = cut(items, 'x');
  if (columns.length > 1) return columns.flatMap((column) => readingOrder(column));
  const bands = cut(items, 'y');
  if (bands.length > 1) return [...readingOrder(bands[0]), ...readingOrder(bands.slice(1).flat())];
  return rowMajor();
}

/**
 * Fold the grid's result back into the stored layout.
 *
 * The grid reports `x`, `y` and `w` for the panels on screen. Their floors stay
 * as they were: the grid's `h` is the content height, and storing that would
 * pin every panel at today's content. A panel that is not on screen (a nudge
 * with nothing to review, a tile that is not showing) keeps its column, and
 * takes a `y` just inside the bottom of the panel that was above it, so it
 * comes back in the same place in its column.
 */
export function mergeGridLayout(
  stored: readonly PanelSlot[],
  grid: Layout,
  resized?: { id: PanelId; h: number },
): PanelSlot[] {
  const placed = new Map(grid.map((it) => [it.i, it]));
  return stored.map((slot) => {
    const it = placed.get(slot.id);
    if (it) {
      const h = resized && resized.id === slot.id ? resized.h : slot.h;
      return { id: slot.id, x: it.x, y: Math.min(it.y, MAX_Y), w: it.w, h };
    }
    let anchor: PanelSlot | null = null;
    for (const other of stored) {
      if (!placed.has(other.id) || other.y >= slot.y) continue;
      if (other.x >= slot.x + slot.w || slot.x >= other.x + other.w) continue;
      if (!anchor || other.y > anchor.y) anchor = other;
    }
    if (!anchor) return { ...slot, y: 0 };
    const a = placed.get(anchor.id)!;
    return { ...slot, y: Math.min(a.y + Math.max(0, a.h - 1), MAX_Y) };
  });
}

export type KeyDirection = 'left' | 'right' | 'up' | 'down';

/** True when two items share at least one column. */
function sharesColumns(a: Box, b: Box): boolean {
  return a.x < b.x + b.w && b.x < a.x + a.w;
}

/**
 * Move one panel a step with the keyboard, the way a drag would.
 *
 * Left and right move one column. Up and down move past the nearest panel above
 * or below in the same columns, so one key press is one visible step. Returns
 * null when the panel cannot move that way.
 */
export function moveByKey(layout: Layout, id: string, dir: KeyDirection): LayoutItem[] | null {
  const work = cloneLayout(layout);
  const item = work.find((it) => it.i === id);
  if (!item) return null;
  let x = item.x;
  let y = item.y;
  if (dir === 'left' || dir === 'right') {
    x = dir === 'left' ? item.x - 1 : item.x + 1;
    if (x < 0 || x + item.w > GRID_COLS) return null;
  } else {
    const others = work.filter((it) => it.i !== id && sharesColumns(it, item));
    if (dir === 'up') {
      const above = others.filter((it) => it.y + it.h <= item.y);
      if (!above.length) return null;
      const nearest = above.reduce((n, it) => (it.y + it.h > n.y + n.h ? it : n));
      y = nearest.y;
    } else {
      const below = others.filter((it) => it.y >= item.y + item.h);
      if (!below.length) return null;
      const nearest = below.reduce((n, it) => (it.y < n.y ? it : n));
      y = nearest.y + nearest.h;
    }
  }
  const before = { x: item.x, y: item.y };
  const moved = moveElement(work, item, x, y, true, false, 'vertical', GRID_COLS, false);
  const packed = cloneLayout(verticalCompactor.compact(moved, GRID_COLS));
  const after = packed.find((it) => it.i === id);
  if (!after || (after.x === before.x && after.y === before.y)) return null;
  return packed;
}

/**
 * Change one panel's width or floor with the keyboard.
 *
 * Width moves one column, inside the panel's minimum and the right edge.
 * Height moves KEY_HEIGHT_STEP rows and never goes under the content: at the
 * content height the floor returns to one row, which means "fit the content".
 * Returns the new grid layout and the floor to store (null when the floor
 * stays), or null when nothing changes.
 */
export function resizeByKey(
  layout: Layout,
  id: string,
  dir: KeyDirection,
  contentRows: number,
): { grid: LayoutItem[]; h: number | null } | null {
  const work = cloneLayout(layout);
  const item = work.find((it) => it.i === id);
  if (!item || !isPanelId(item.i)) return null;
  const minW = PANEL_META[item.i].minW;
  if (dir === 'left' || dir === 'right') {
    const w = dir === 'left' ? item.w - 1 : item.w + 1;
    if (w < minW || item.x + w > GRID_COLS) return null;
    item.w = w;
    return { grid: cloneLayout(verticalCompactor.compact(work, GRID_COLS)), h: null };
  }
  const target = dir === 'up' ? item.h - KEY_HEIGHT_STEP : item.h + KEY_HEIGHT_STEP;
  const h = Math.min(MAX_H, Math.max(contentRows, target));
  if (h === item.h) return null;
  item.h = h;
  return {
    grid: cloneLayout(verticalCompactor.compact(work, GRID_COLS)),
    h: h <= contentRows ? 1 : h,
  };
}

/** The key the layout lives under when the browser keeps it. */
export const LAYOUT_STORAGE_KEY = 'soc-ai.dashboard.layout';
