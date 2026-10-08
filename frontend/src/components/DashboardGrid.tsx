import { Check, GripHorizontal, LayoutGrid, RotateCcw } from 'lucide-react';
import {
  Children,
  type CSSProperties,
  Fragment,
  isValidElement,
  type KeyboardEvent,
  type ReactElement,
  type ReactNode,
  type RefObject,
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import { flushSync } from 'react-dom';
import ReactGridLayout, { useContainerWidth } from 'react-grid-layout';
import {
  type EventCallback,
  type PositionStrategy,
  transformStrategy,
} from 'react-grid-layout/core';
import 'react-grid-layout/css/styles.css';
import { cn } from '../lib/cn';
import {
  GAP_PX,
  GRID_COLS,
  type KeyDirection,
  PANEL_META,
  type PanelId,
  type PanelSlot,
  ROW_PX,
  effectiveLayout,
  isPanelId,
  mergeGridLayout,
  moveByKey,
  readingOrder,
  resizeByKey,
  rowsFor,
  sameLayout,
} from '../lib/dashboardLayout';

const ARROWS: Record<string, KeyDirection> = {
  ArrowLeft: 'left',
  ArrowRight: 'right',
  ArrowUp: 'up',
  ArrowDown: 'down',
};

/** The id of the help text the drag handles point at. Dashboard renders it. */
export const LAYOUT_HELP_ID = 'dashboard-layout-help';

// ---------------------------------------------------------------------------
// The Dashboard's movable panels, on react-grid-layout.
//
// Two ways to draw one tree. Outside edit mode the grid is a CSS grid: every
// cell sits on its rows and columns as soon as React renders, so a panel that
// grows as its data lands moves the panels under it in the same frame. In
// edit mode react-grid-layout positions the cells itself, which is what makes
// them draggable and resizable. The tree is the same in both modes, so turning
// edit mode on or off does not remount a panel: the chat panel keeps its draft
// and nothing fetches again.
// ---------------------------------------------------------------------------

/** Lay the cells out with CSS grid placement. react-grid-layout adds nothing. */
const STATIC_STRATEGY: PositionStrategy = {
  type: 'absolute',
  scale: 1,
  calcStyle: () => ({}),
};

const GRID_CONFIG = {
  cols: GRID_COLS,
  rowHeight: ROW_PX,
  margin: [GAP_PX, 0] as [number, number],
  containerPadding: [0, 0] as [number, number],
};
const DRAG_ON = { enabled: true, handle: '.dash-drag-handle', threshold: 3 };
const DRAG_OFF = { enabled: false };
const RESIZE_ON = { enabled: true, handles: ['se' as const] };
const RESIZE_OFF = { enabled: false };

const WIDE_STYLE: CSSProperties = {
  display: 'grid',
  gridTemplateColumns: `repeat(${GRID_COLS}, minmax(0, 1fr))`,
  columnGap: GAP_PX,
  gridAutoRows: ROW_PX,
  height: 'auto',
};
// Below the `lg` width the grid stacks: the tiles two to a row, every other
// panel full width, in reading order. That is the narrow Dashboard as it was.
const NARROW_STYLE: CSSProperties = {
  display: 'grid',
  gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
  columnGap: 12,
  height: 'auto',
};
const NARROW_TILE_GAP = 12;

/** Every keyed child, with fragments opened. The key is the panel id. */
function collectPanels(children: ReactNode, out = new Map<PanelId, ReactElement>()) {
  Children.forEach(children, (child) => {
    if (!isValidElement(child)) return;
    if (child.type === Fragment) {
      collectPanels((child.props as { children?: ReactNode }).children, out);
      return;
    }
    if (isPanelId(child.key)) out.set(child.key, child);
  });
  return out;
}

type Natural = Partial<Record<PanelId, number>>;

export interface DashboardGridProps {
  /** The panels. Each one carries its panel id as its `key`. Fragments are opened. */
  children: ReactNode;
  layout: PanelSlot[];
  /** Drag, resize and keyboard moves are on only while this is true. */
  editing: boolean;
  /** At the `lg` width and wider. A narrow window stacks the panels. */
  wide: boolean;
  onCommit: (next: PanelSlot[]) => void;
}

export function DashboardGrid({ children, layout, editing, wide, onCommit }: DashboardGridProps) {
  const panels = collectPanels(children);
  const presentKey = [...panels.keys()].sort().join(',');
  const present = useMemo(() => new Set(presentKey.split(',')), [presentKey]);

  // Each panel's content height in rows, where it has been measured at the
  // wide width. The narrow stack has other heights, so it records none.
  const [natural, setNatural] = useState<Natural>({});
  const grid = useMemo(() => effectiveLayout(layout, present, natural), [layout, present, natural]);
  const order = useMemo(
    () => readingOrder(grid).map((it) => it.i).filter(isPanelId),
    [grid],
  );
  const placed = useMemo(() => new Map(grid.map((it) => [it.i, it])), [grid]);

  const layoutRef = useRef(layout);
  layoutRef.current = layout;
  const naturalRef = useRef(natural);
  naturalRef.current = natural;
  const wideRef = useRef(wide);
  wideRef.current = wide;

  const record = useCallback((updates: Natural) => {
    setNatural((prev) => {
      let changed = false;
      const next: Natural = { ...prev };
      for (const [id, rows] of Object.entries(updates) as [PanelId, number][]) {
        if (next[id] !== rows) {
          next[id] = rows;
          changed = true;
        }
      }
      return changed ? next : prev;
    });
  }, []);

  // The content height of one tile wrapper, or undefined while the wrapper is
  // stretched to a floor taller than its content (the content is then hidden
  // inside the floor, and the floor is the height that matters).
  const measure = useCallback((el: HTMLElement): number | undefined => {
    if (!wideRef.current) return undefined;
    const px = el.getBoundingClientRect().height;
    const floor = parseFloat(el.style.minHeight) || 0;
    if (floor > 0 && px <= floor + 0.5) return undefined;
    return rowsFor(px);
  }, []);

  const els = useRef(new Map<PanelId, HTMLElement>());
  const ids = useRef(new Map<Element, PanelId>());
  const observer = useRef<ResizeObserver | null>(null);
  useEffect(() => {
    if (typeof ResizeObserver === 'undefined') return undefined;
    const ro = new ResizeObserver((entries) => {
      const updates: Natural = {};
      for (const entry of entries) {
        const id = ids.current.get(entry.target);
        const rows = id ? measure(entry.target as HTMLElement) : undefined;
        if (id && rows !== undefined) updates[id] = rows;
      }
      // Synchronous, so the cells below a growing panel move in the frame the
      // panel grew in. A deferred update draws one frame of overlap.
      if (Object.keys(updates).length) flushSync(() => record(updates));
    });
    observer.current = ro;
    els.current.forEach((el) => ro.observe(el));
    return () => {
      ro.disconnect();
      observer.current = null;
    };
  }, [measure, record]);

  const refFns = useRef(new Map<PanelId, (el: HTMLDivElement | null) => void>());
  const tileRef = (id: PanelId) => {
    let fn = refFns.current.get(id);
    if (!fn) {
      fn = (el: HTMLDivElement | null) => {
        const prev = els.current.get(id);
        if (prev && prev !== el) {
          observer.current?.unobserve(prev);
          ids.current.delete(prev);
          els.current.delete(id);
        }
        if (el) {
          els.current.set(id, el);
          ids.current.set(el, id);
          observer.current?.observe(el);
        }
      };
      refFns.current.set(id, fn);
    }
    return fn;
  };

  // Measure before the first paint, so the first frame already has every cell
  // at its content height.
  useLayoutEffect(() => {
    const updates: Natural = {};
    els.current.forEach((el, id) => {
      const rows = measure(el);
      if (rows !== undefined) updates[id] = rows;
    });
    record(updates);
  }, [presentKey, wide, measure, record]);

  // react-grid-layout types the ref as holding null, which a div's ref prop
  // does not accept under React 18's types. It is the same object.
  const { width, containerRef } = useContainerWidth();
  const gridRef = containerRef as RefObject<HTMLDivElement>;

  const onDragStop: EventCallback = (finalLayout) => {
    const next = mergeGridLayout(layoutRef.current, finalLayout);
    if (!sameLayout(next, layoutRef.current)) onCommit(next);
  };

  // A floor taller than the content hides the content height. Read it once,
  // with the floor lifted, so the resize stops at the content and no lower.
  const onResizeStart: EventCallback = (_layout, oldItem) => {
    if (!oldItem || !isPanelId(oldItem.i)) return;
    const el = els.current.get(oldItem.i);
    if (!el) return;
    const floor = el.style.minHeight;
    el.style.minHeight = '';
    const px = el.getBoundingClientRect().height;
    el.style.minHeight = floor;
    record({ [oldItem.i]: rowsFor(px) });
  };

  const onResizeStop: EventCallback = (finalLayout, oldItem, newItem) => {
    if (!oldItem || !newItem || !isPanelId(newItem.i)) return;
    const id = newItem.i;
    const slot = layoutRef.current.find((s) => s.id === id);
    if (!slot) return;
    const content = naturalRef.current[id] ?? 1;
    // A resize that left the height alone keeps the floor. A floor at or under
    // the content returns to one row: "fit the content".
    let h = slot.h;
    if (newItem.h !== oldItem.h) h = newItem.h <= content ? 1 : newItem.h;
    const next = mergeGridLayout(layoutRef.current, finalLayout, { id, h });
    if (!sameLayout(next, layoutRef.current)) onCommit(next);
  };

  // The keyboard path. react-grid-layout has none: a drag needs a pointer. With
  // a handle in focus, an arrow key moves the panel one step and Shift with an
  // arrow key resizes it. Each step goes through the same layout functions a
  // drag does, and a polite live region says what happened.
  const [announcement, setAnnouncement] = useState('');
  const handles = useRef(new Map<PanelId, HTMLButtonElement>());
  const refocus = useRef<PanelId | null>(null);
  // A move can change the reading order, and React then moves the cell in the
  // DOM. A moved node loses focus, so give it back to the same handle.
  useLayoutEffect(() => {
    const id = refocus.current;
    if (!id) return;
    refocus.current = null;
    const el = handles.current.get(id);
    if (el && document.activeElement !== el) el.focus();
  });

  const onHandleKey = (id: PanelId) => (e: KeyboardEvent<HTMLButtonElement>) => {
    const dir = ARROWS[e.key];
    if (!dir || e.altKey || e.ctrlKey || e.metaKey) return;
    e.preventDefault();
    const title = PANEL_META[id].title;
    const stored = layoutRef.current;
    if (e.shiftKey) {
      const resized = resizeByKey(grid, id, dir, naturalRef.current[id] ?? 1);
      if (!resized) {
        setAnnouncement(`The ${title} panel cannot change size in that direction.`);
        return;
      }
      const floor = resized.h ?? stored.find((s) => s.id === id)?.h ?? 1;
      refocus.current = id;
      onCommit(mergeGridLayout(stored, resized.grid, { id, h: floor }));
      const it = resized.grid.find((g) => g.i === id);
      setAnnouncement(
        dir === 'left' || dir === 'right'
          ? `The ${title} panel is ${it?.w ?? 0} columns wide.`
          : `The ${title} panel is ${dir === 'up' ? 'shorter' : 'taller'}.`,
      );
      return;
    }
    const moved = moveByKey(grid, id, dir);
    if (!moved) {
      setAnnouncement(`The ${title} panel cannot move ${dir}.`);
      return;
    }
    refocus.current = id;
    onCommit(mergeGridLayout(stored, moved));
    const it = moved.find((g) => g.i === id);
    setAnnouncement(`The ${title} panel moved ${dir}. It starts at column ${(it?.x ?? 0) + 1}.`);
  };

  const handleRefFns = useRef(new Map<PanelId, (el: HTMLButtonElement | null) => void>());
  const handleRef = (id: PanelId) => {
    let fn = handleRefFns.current.get(id);
    if (!fn) {
      fn = (el: HTMLButtonElement | null) => {
        if (el) handles.current.set(id, el);
        else handles.current.delete(id);
      };
      handleRefFns.current.set(id, fn);
    }
    return fn;
  };

  const cellStyle =(id: PanelId, index: number): CSSProperties | undefined => {
    if (editing) return undefined;
    if (!wide) {
      // A flex column, so a tile stretches to the tallest tile in its row the
      // way the old tile grid did.
      if (PANEL_META[id].tile) {
        return {
          gridColumn: 'span 1',
          paddingBottom: NARROW_TILE_GAP,
          display: 'flex',
          flexDirection: 'column',
        };
      }
      const prev = order[index - 1];
      const afterTile = prev !== undefined && PANEL_META[prev].tile;
      return { gridColumn: '1 / -1', paddingTop: afterTile ? GAP_PX - NARROW_TILE_GAP : 0 };
    }
    const it = placed.get(id);
    if (!it) return undefined;
    return { gridColumn: `${it.x + 1} / span ${it.w}`, gridRow: `${it.y + 1} / span ${it.h}` };
  };

  // Stretch the tile to the cell when the cell is taller than the content: a
  // raised floor, or a tile row evened to its tallest tile.
  const tileStyle = (id: PanelId): CSSProperties | undefined => {
    if (!wide) return PANEL_META[id].tile ? { flex: '1 0 auto' } : undefined;
    const it = placed.get(id);
    const content = natural[id];
    if (!it || content === undefined || it.h <= content) return undefined;
    return { minHeight: it.h * ROW_PX - GAP_PX };
  };

  return (
    <div
      ref={gridRef}
      className={cn('dash-grid', editing && 'dash-grid--editing')}
      data-editing={editing ? 'true' : 'false'}
    >
      <ReactGridLayout
        width={width}
        layout={grid}
        gridConfig={GRID_CONFIG}
        dragConfig={editing ? DRAG_ON : DRAG_OFF}
        resizeConfig={editing ? RESIZE_ON : RESIZE_OFF}
        positionStrategy={editing ? transformStrategy : STATIC_STRATEGY}
        autoSize={editing}
        style={editing ? undefined : wide ? WIDE_STYLE : NARROW_STYLE}
        onDragStop={onDragStop}
        onResizeStart={onResizeStart}
        onResizeStop={onResizeStop}
      >
        {order.map((id, index) => (
          <div key={id} data-panel={id} className="dash-cell" style={cellStyle(id, index)}>
            {editing && (
              <>
                <div
                  aria-hidden="true"
                  className="pointer-events-none absolute inset-x-0 top-0 rounded-panel border border-dashed border-accent/60"
                  style={{ bottom: GAP_PX }}
                />
                <button
                  ref={handleRef(id)}
                  type="button"
                  data-panel-handle={id}
                  className="dash-drag-handle absolute left-1/2 top-0 z-[5] flex h-5 w-10 -translate-x-1/2 -translate-y-1/2 cursor-grab items-center justify-center rounded-pill border border-accent/60 bg-surface-3 text-accent hover:bg-accent/20 active:cursor-grabbing"
                  aria-label={`Move the ${PANEL_META[id].title} panel`}
                  aria-describedby={LAYOUT_HELP_ID}
                  aria-keyshortcuts="ArrowLeft ArrowRight ArrowUp ArrowDown Shift+ArrowLeft Shift+ArrowRight Shift+ArrowUp Shift+ArrowDown"
                  title="Drag to move the panel. With the handle in focus, the arrow keys move it."
                  onKeyDown={onHandleKey(id)}
                >
                  <GripHorizontal size={14} aria-hidden="true" />
                </button>
              </>
            )}
            <div ref={tileRef(id)} className="dash-tile" style={tileStyle(id)}>
              {panels.get(id)}
            </div>
          </div>
        ))}
      </ReactGridLayout>
      <div className="sr-only" aria-live="polite" data-testid="layout-announcement">
        {editing ? announcement : ''}
      </div>
    </div>
  );
}

export interface LayoutControlsProps {
  editing: boolean;
  onToggle: () => void;
  onReset: () => void;
  /** A saved layout is in force. */
  saved: boolean;
  /** The layout may change. */
  editable: boolean;
  /** Why the layout may not change, when it may not. */
  lockedReason?: string | null;
  error: string | null;
}

/** "Edit layout" and, while it is on, "Reset layout". */
export function LayoutControls({
  editing,
  onToggle,
  onReset,
  saved,
  editable,
  lockedReason,
  error,
}: LayoutControlsProps) {
  const button =
    'flex items-center gap-1.5 rounded-control border px-[11px] py-1.5 text-[12px] font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-60';
  return (
    <div className="ml-auto flex flex-wrap items-center gap-2">
      {error && (
        <span role="status" className="text-[11.5px] text-warn">
          {error}
        </span>
      )}
      {editing && (
        <button
          type="button"
          onClick={onReset}
          disabled={!saved}
          title={
            saved
              ? 'Put every panel back in its shipped place and size.'
              : 'The Dashboard shows the shipped layout.'
          }
          className={cn(button, 'border-border-2 bg-surface-1 text-text-2 hover:border-border-strong')}
        >
          <RotateCcw size={12} aria-hidden="true" />
          Reset layout
        </button>
      )}
      <button
        type="button"
        aria-pressed={editing}
        onClick={onToggle}
        disabled={!editable}
        title={
          !editable
            ? (lockedReason ?? undefined)
            : editing
              ? 'Stop editing the layout. The console keeps each change when you make it.'
              : 'Move and resize the Dashboard panels.'
        }
        className={cn(
          button,
          editing
            ? 'border-accent/50 bg-accent/10 text-[#cfe0ff]'
            : 'border-border-2 bg-surface-1 text-dim hover:border-border-strong hover:text-text-2',
        )}
      >
        {/* "Done" while the editor is on. The label read "Edit layout" in
            both states, so the button gave no word for how to leave the
            editor (dogfood 2026-10-06). */}
        {editing ? <Check size={12} aria-hidden="true" /> : <LayoutGrid size={12} aria-hidden="true" />}
        {editing ? 'Done' : 'Edit layout'}
      </button>
    </div>
  );
}
