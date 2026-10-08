// The pure half of the Dashboard grid: reading, repairing and editing a layout.
import type { LayoutItem } from 'react-grid-layout/core';
import { describe, expect, it } from 'vitest';
import {
  DEFAULT_LAYOUT,
  GRID_COLS,
  MAX_H,
  PANEL_IDS,
  type PanelId,
  type PanelSlot,
  defaultLayout,
  effectiveLayout,
  mergeGridLayout,
  moveByKey,
  normalizeLayout,
  readingOrder,
  resizeByKey,
  rowsFor,
} from './dashboardLayout';

const ALL = new Set<string>(PANEL_IDS);
const ids = (items: { i: string }[]) => items.map((it) => it.i);
const find = (items: LayoutItem[], id: string) => items.find((it) => it.i === id)!;

/** Content heights in rows that differ per panel, the way a real screen does. */
const NATURAL: Partial<Record<PanelId, number>> = {
  'kpi-alert-events': 24,
  'kpi-awaiting': 26,
  'kpi-true-positives': 30,
  'kpi-running': 24,
  'kpi-shadow-hits': 24,
  outcomes: 70,
  recent: 95,
  'setup-health': 15,
  assistant: 60,
  'auto-investigate': 20,
  'verdict-quality': 45,
  enrichment: 30,
  'detection-tuning': 18,
  'host-dossier': 18,
};

describe('the shipped layout', () => {
  it('places every panel exactly once, inside the grid', () => {
    expect(DEFAULT_LAYOUT.map((s) => s.id)).toEqual([...PANEL_IDS]);
    for (const s of DEFAULT_LAYOUT) {
      expect(s.x + s.w).toBeLessThanOrEqual(GRID_COLS);
      expect(s.h).toBe(1);
    }
  });

  it('reads the tiles, then the left column, then the side column', () => {
    for (const natural of [NATURAL, {}]) {
      const present = new Set<string>(PANEL_IDS);
      present.delete('kpi-shadow-hits');
      const order = ids(readingOrder(effectiveLayout(defaultLayout(), present, natural)));
      expect(order).toEqual([
        'kpi-awaiting',
        'kpi-alert-events',
        'kpi-true-positives',
        'kpi-running',
        'outcomes',
        'recent',
        'setup-health',
        'assistant',
        'auto-investigate',
        'verdict-quality',
        'enrichment',
        'detection-tuning',
        'host-dossier',
      ]);
    }
  });

  it('reads the shadow-hit tile after the tile row, before the outcomes chart', () => {
    const order = ids(readingOrder(effectiveLayout(defaultLayout(), ALL, NATURAL)));
    expect(order.slice(0, 6)).toEqual([
      'kpi-awaiting',
      'kpi-alert-events',
      'kpi-true-positives',
      'kpi-running',
      'kpi-shadow-hits',
      'outcomes',
    ]);
  });
});

describe('effectiveLayout', () => {
  it('makes each panel as tall as its content and evens the tile row', () => {
    const grid = effectiveLayout(defaultLayout(), ALL, NATURAL);
    expect(find(grid, 'outcomes').h).toBe(70);
    expect(find(grid, 'recent').y).toBe(find(grid, 'outcomes').y + 70);
    // The four tiles in the first row take the tallest tile's height.
    for (const id of ['kpi-alert-events', 'kpi-awaiting', 'kpi-true-positives', 'kpi-running']) {
      expect(find(grid, id).h).toBe(30);
      expect(find(grid, id).y).toBe(0);
    }
    // Panels are not tiles: the chart and the side column keep their own heights.
    expect(find(grid, 'setup-health').h).toBe(15);
  });

  it('keeps a raised floor and never goes under the content', () => {
    const layout = defaultLayout().map((s) => (s.id === 'setup-health' ? { ...s, h: 40 } : s));
    const grid = effectiveLayout(layout, ALL, NATURAL);
    expect(find(grid, 'setup-health').h).toBe(40);
    expect(find(grid, 'setup-health').minH).toBe(15);
  });

  it('leaves out a panel that is not on screen', () => {
    const present = new Set(['outcomes', 'recent']);
    expect(ids(effectiveLayout(defaultLayout(), present, NATURAL)).sort()).toEqual([
      'outcomes',
      'recent',
    ]);
  });
});

describe('normalizeLayout', () => {
  it('returns the shipped layout for nothing usable', () => {
    for (const raw of [null, undefined, 'x', {}, [], [{ id: 'retired-panel', x: 0, y: 0, w: 1, h: 1 }]]) {
      expect(normalizeLayout(raw)).toEqual(defaultLayout());
    }
  });

  it('drops an unknown panel and a slot it cannot place, and keeps the rest', () => {
    const out = normalizeLayout([
      { id: 'retired-panel', x: 0, y: 0, w: 12, h: 1 },
      { id: 'recent', x: 0, y: 0, w: 12, h: 1 },
      { id: 'recent', x: 0, y: 50, w: 12, h: 1 },
      { id: 'outcomes', x: 10, y: 1, w: 3, h: 1 },
      { id: 'enrichment', x: 0.5, y: 1, w: 3, h: 1 },
      { id: 'setup-health', x: 0, y: 1, w: 4, h: 0 },
    ]);
    expect(out.find((s) => s.id === 'recent')).toEqual({ id: 'recent', x: 0, y: 0, w: 12, h: 1 });
    expect(out.map((s) => s.id).sort()).toEqual([...PANEL_IDS].sort());
    expect(out.some((s) => (s.id as string) === 'retired-panel')).toBe(false);
  });

  it('puts a panel the layout does not name in its shipped column, at the bottom, in shipped order', () => {
    const saved: PanelSlot[] = [
      { id: 'recent', x: 0, y: 0, w: 12, h: 1 },
      { id: 'outcomes', x: 0, y: 200, w: 12, h: 1 },
    ];
    const out = normalizeLayout(saved);
    expect(out.slice(0, 2)).toEqual(saved);
    const rest = out.slice(2);
    expect(rest.map((s) => s.id)).toEqual(
      DEFAULT_LAYOUT.map((s) => s.id).filter((id) => id !== 'recent' && id !== 'outcomes'),
    );
    for (const s of rest) {
      const shipped = DEFAULT_LAYOUT.find((d) => d.id === s.id)!;
      expect(s.x).toBe(shipped.x);
      expect(s.w).toBe(shipped.w);
      expect(s.y).toBeGreaterThanOrEqual(201);
    }
  });

  it('passes a complete, valid layout through unchanged', () => {
    const full = defaultLayout().map((s, n) => ({ ...s, y: n * 10 }));
    expect(normalizeLayout(full)).toEqual(full);
  });
});

describe('mergeGridLayout', () => {
  it('takes x, y and w from the grid and keeps every floor', () => {
    const stored = defaultLayout();
    const grid = effectiveLayout(stored, ALL, NATURAL);
    const merged = mergeGridLayout(stored, grid);
    for (const s of merged) expect(s.h).toBe(1);
    expect(merged.find((s) => s.id === 'recent')!.y).toBe(find(grid, 'recent').y);
  });

  it('stores the floor of the panel that was resized', () => {
    const stored = defaultLayout();
    const grid = effectiveLayout(stored, ALL, NATURAL);
    const merged = mergeGridLayout(stored, grid, { id: 'recent', h: 120 });
    expect(merged.find((s) => s.id === 'recent')!.h).toBe(120);
  });

  it('brings an absent panel back under the panel that was above it', () => {
    const present = new Set<string>(PANEL_IDS);
    present.delete('detection-tuning');
    present.delete('host-dossier');
    const stored = defaultLayout();
    const grid = effectiveLayout(stored, present, NATURAL);
    const merged = mergeGridLayout(stored, grid);
    // Later the tuning nudge shows again. It must come back after enrichment,
    // the panel above it, and not jump to the top of the side column.
    const order = ids(readingOrder(effectiveLayout(merged, ALL, NATURAL)));
    expect(order.slice(-3)).toEqual(['enrichment', 'detection-tuning', 'host-dossier']);
  });
});

describe('keyboard moves', () => {
  const grid = () => {
    const present = new Set<string>(PANEL_IDS);
    present.delete('kpi-shadow-hits');
    return effectiveLayout(defaultLayout(), present, NATURAL);
  };

  it('moves a panel past its neighbour below and above', () => {
    const down = moveByKey(grid(), 'outcomes', 'down')!;
    expect(find(down, 'recent').y).toBeLessThan(find(down, 'outcomes').y);
    const up = moveByKey(down, 'outcomes', 'up')!;
    expect(find(up, 'outcomes').y).toBeLessThan(find(up, 'recent').y);
  });

  it('moves one column at a time and stops at the edge', () => {
    // The Needs-you tile leads the row, so it is the one at the left edge.
    expect(moveByKey(grid(), 'kpi-awaiting', 'left')).toBeNull();
    expect(moveByKey(grid(), 'kpi-running', 'right')).toBeNull();
    const left = moveByKey(grid(), 'setup-health', 'left')!;
    expect(find(left, 'setup-health').x).toBe(7);
  });

  it('says no when there is nothing to move past', () => {
    expect(moveByKey(grid(), 'kpi-awaiting', 'up')).toBeNull();
    expect(moveByKey(grid(), 'host-dossier', 'down')).toBeNull();
  });

  it('resizes the width inside the minimum and the edge', () => {
    const narrower = resizeByKey(grid(), 'setup-health', 'left', 15)!;
    expect(find(narrower.grid, 'setup-health').w).toBe(3);
    expect(narrower.h).toBeNull();
    expect(resizeByKey(narrower.grid, 'setup-health', 'left', 15)).toBeNull();
    expect(resizeByKey(grid(), 'setup-health', 'right', 15)).toBeNull();
  });

  it('never makes a panel shorter than its content', () => {
    const taller = resizeByKey(grid(), 'setup-health', 'down', 15)!;
    expect(find(taller.grid, 'setup-health').h).toBe(25);
    expect(taller.h).toBe(25);
    const back = resizeByKey(taller.grid, 'setup-health', 'up', 15)!;
    // At the content height the floor returns to one row: fit the content.
    expect(find(back.grid, 'setup-health').h).toBe(15);
    expect(back.h).toBe(1);
    expect(resizeByKey(back.grid, 'setup-health', 'up', 15)).toBeNull();
  });

  it('stops at the largest floor the backend accepts', () => {
    const tall = grid().map((it) => (it.i === 'recent' ? { ...it, h: MAX_H - 5 } : it));
    const out = resizeByKey(tall, 'recent', 'down', 95)!;
    expect(find(out.grid, 'recent').h).toBe(MAX_H);
  });
});

describe('rowsFor', () => {
  it('rounds a height up to whole rows, with the gap under the panel', () => {
    expect(rowsFor(0)).toBe(4);
    expect(rowsFor(100)).toBe(29);
    expect(rowsFor(101)).toBe(30);
  });
});
