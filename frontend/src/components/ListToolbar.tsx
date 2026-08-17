import { Bookmark, EyeOff, Plus, Search, X } from 'lucide-react';
import { useState, type ReactNode } from 'react';
import { cn } from '../lib/cn';

/**
 * The list layer's one toolbar.
 *
 * Alerts, Investigations, Hunts and Hosts each invented their own filter bar,
 * their own selection strip and their own empty state, so four screens of the
 * same product read as four products (dogfood B1, 2026-08-11). This component
 * owns what is genuinely common — the chip row of preset and saved views, the
 * opt-in search box, the selection count and the bulk-action slot — and takes
 * each screen's own facet controls as children, because a verdict multi-select
 * and a host role filter have nothing to share but their placement.
 *
 * Layout, top to bottom:
 *
 *   [ Views · preset chips · saved-view chips · + Save view ]   (omitted when a
 *                                                                screen has none)
 *   [ search | facets …                            | trailing ]  ← always
 *   [ N selected · M not on this page · bulk actions · Clear ]   ← when selecting
 *
 * The selection strip is APPENDED, never a swap for the facet row. Alerts used
 * to replace its filter row during selection and could afford to — its preset
 * tabs sat above, so something filter-shaped survived. Generalised to the other
 * three that rule deleted the only filter Hunts has, blanked a typed search
 * term that was still applied server-side, and made "Clear" (which discards the
 * selection) the only way back to the controls.
 */

export interface ToolbarPreset {
  id: string;
  label: string;
  count?: number;
  active: boolean;
}

/** A saved view as the chip row needs it — the full row lives in lib/types. */
export interface ToolbarView {
  id: number;
  name: string;
}

export interface ListToolbarSearch {
  value: string;
  onChange: (next: string) => void;
  placeholder?: string;
  /** Accessible name; defaults to the placeholder. */
  label?: string;
}

export interface ListToolbarSelection {
  count: number;
  onClear: () => void;
  /** "3 selected" by default; Hosts says "3 hosts selected". */
  noun?: string;
  /** Replaces the count line entirely. Alerts selects two different things at
   *  once — detection groups AND individual events — and one number cannot say
   *  that honestly. */
  summary?: ReactNode;
  /** How many of the selected ids this page does not show. Rendered as its own
   *  marker whenever non-zero: a selection that outlives a filter change is
   *  correct, but only if the operator can tell it happened. */
  offPageCount?: number;
  /** Drop just the off-page ids. Without it the marker is read-only. */
  onClearOffPage?: () => void;
  actions?: ReactNode;
}

export interface ListToolbarProps {
  presets?: ToolbarPreset[];
  onPreset?: (id: string) => void;
  views?: ToolbarView[];
  /** The saved view currently applied, if the screen tracks one. */
  activeViewId?: number | null;
  onApplyView?: (view: ToolbarView) => void;
  onDeleteView?: (view: ToolbarView) => void;
  /** Capture the screen's current filter state under a name. Absent → no
   *  control. A rejected promise KEEPS the composer open with the typed name,
   *  so a refused save is recoverable rather than a vanished one. */
  onSaveView?: (name: string) => void | Promise<void>;
  /** The last saved-view write's error, shown beside the composer. */
  viewError?: string | null;
  search?: ListToolbarSearch;
  /** The screen's own facet controls. */
  children?: ReactNode;
  /** Right-aligned extras that stay put through a selection (density, Rebuild now). */
  trailing?: ReactNode;
  selection?: ListToolbarSelection;
  /** A transient status line — "Deleted 2 investigations", a sweep note. */
  note?: ReactNode;
}

const CHIP_BASE =
  'flex items-center gap-1.5 rounded-chip border px-[10px] py-[5px] text-[12px] font-semibold transition-colors';

function Chip({
  label,
  count,
  active,
  onClick,
  icon,
  title,
  onDelete,
  deleteLabel,
}: {
  label: string;
  count?: number;
  active: boolean;
  onClick: () => void;
  icon?: ReactNode;
  title?: string;
  onDelete?: () => void;
  deleteLabel?: string;
}) {
  return (
    <span className="group/chip relative flex items-center">
      <button
        type="button"
        aria-pressed={active}
        title={title}
        onClick={onClick}
        className={cn(
          CHIP_BASE,
          active
            ? 'border-accent/50 bg-accent/10 text-[#cfe0ff]'
            : 'border-border-2 bg-surface-1 text-dim hover:border-border-strong hover:text-text-2',
          onDelete ? 'pr-[26px]' : '',
        )}
      >
        {icon}
        <span className="max-w-[220px] truncate">{label}</span>
        {count != null && (
          <span className="rounded-chip bg-surface-3 px-1.5 py-px font-mono text-[10.5px] text-dim">
            {count}
          </span>
        )}
      </button>
      {onDelete && (
        <button
          type="button"
          aria-label={deleteLabel}
          title={deleteLabel}
          onClick={onDelete}
          className="absolute right-[7px] flex text-faint opacity-0 transition-opacity hover:text-danger focus:opacity-100 group-hover/chip:opacity-100"
        >
          <X size={11} />
        </button>
      )}
    </span>
  );
}

/**
 * The armed half of a saved view's delete, in the chip's own place.
 *
 * The × deleted on the first click — no confirm, no undo, and the row gone
 * server-side — from a target sitting a few pixels inside the chip the operator
 * clicks to APPLY the view. This is the app's standing destructive pattern
 * (a runbook row, a hunt, an investigation): arm, then confirm, with the way
 * out as prominent as the way through.
 */
function DeleteConfirm({
  name,
  onConfirm,
  onCancel,
}: {
  name: string;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  return (
    <span
      className={cn(CHIP_BASE, 'border-danger/50 bg-danger/10 text-danger')}
      role="group"
      aria-label={`Delete the saved view "${name}"?`}
    >
      <span className="max-w-[160px] truncate">Delete "{name}"?</span>
      <button
        type="button"
        autoFocus
        onClick={onConfirm}
        aria-label={`Confirm delete of the saved view "${name}"`}
        className="rounded-control border border-danger px-1.5 py-px text-[11.5px] font-semibold text-danger hover:bg-danger/15"
      >
        Delete
      </button>
      <button
        type="button"
        onClick={onCancel}
        className="rounded-control border border-border-strong px-1.5 py-px text-[11.5px] font-semibold text-dim hover:text-text"
      >
        Cancel
      </button>
    </span>
  );
}

export function ListToolbar({
  presets,
  onPreset,
  views,
  activeViewId,
  onApplyView,
  onDeleteView,
  onSaveView,
  search,
  children,
  trailing,
  selection,
  note,
  viewError,
}: ListToolbarProps) {
  const [naming, setNaming] = useState(false);
  const [draft, setDraft] = useState('');
  const [saving, setSaving] = useState(false);
  /** The one view whose delete is armed. Null = none; arming a second disarms
   *  the first, so there is never more than one live destructive control. */
  const [pendingDelete, setPendingDelete] = useState<number | null>(null);

  const hasChips = !!presets?.length || !!views?.length || !!onSaveView;
  const selecting = (selection?.count ?? 0) > 0;

  const commitName = () => {
    const name = draft.trim();
    if (!name || saving) return;
    const out = onSaveView?.(name);
    // Close ONLY once the write has actually landed. Closing first threw the
    // typed name away on every refusal, so a real `too_many_views` produced no
    // chip, no name and no message.
    if (!out || typeof (out as Promise<void>).then !== 'function') {
      setDraft('');
      setNaming(false);
      return;
    }
    setSaving(true);
    void (out as Promise<void>)
      .then(() => {
        setDraft('');
        setNaming(false);
      })
      .catch(() => {
        /* stay open with the name; `viewError` says why */
      })
      .finally(() => setSaving(false));
  };

  return (
    <div>
      {hasChips && (
        <div
          data-testid="list-toolbar-views"
          className="mb-2.5 flex flex-wrap items-center gap-1.5"
        >
          <span className="mr-0.5 text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint">
            Views
          </span>
          {presets?.map((p) => (
            <Chip
              key={p.id}
              label={p.label}
              count={p.count}
              active={p.active}
              onClick={() => onPreset?.(p.id)}
            />
          ))}
          {views?.map((v) =>
            pendingDelete === v.id ? (
              <DeleteConfirm
                key={v.id}
                name={v.name}
                onConfirm={() => {
                  setPendingDelete(null);
                  onDeleteView?.(v);
                }}
                onCancel={() => setPendingDelete(null)}
              />
            ) : (
              <Chip
                key={v.id}
                label={v.name}
                active={activeViewId === v.id}
                icon={<Bookmark size={11} className="flex-none" />}
                // The title says what THIS press does. It read "Apply the
                // saved view …" in both states, on a control rendering
                // aria-pressed — so the one affordance that could have
                // explained the toggle instead denied there was one.
                title={
                  activeViewId === v.id
                    ? `Clear the saved view "${v.name}" and show everything`
                    : `Apply the saved view "${v.name}"`
                }
                onClick={() => onApplyView?.(v)}
                onDelete={onDeleteView ? () => setPendingDelete(v.id) : undefined}
                deleteLabel={`Delete the saved view "${v.name}"`}
              />
            ),
          )}
          {onSaveView &&
            (naming ? (
              <span className="flex items-center gap-1.5">
                <input
                  autoFocus
                  value={draft}
                  onChange={(e) => setDraft(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') commitName();
                    if (e.key === 'Escape') {
                      setDraft('');
                      setNaming(false);
                    }
                  }}
                  placeholder="Name this view…"
                  aria-label="Name this view"
                  className="w-[190px] rounded-control border border-border-input bg-bg px-2.5 py-[5px] text-[12px] text-text outline-none focus:border-accent"
                />
                <button
                  type="button"
                  onClick={commitName}
                  disabled={saving}
                  className="rounded-control border border-accent/50 bg-accent/10 px-2.5 py-[5px] text-[12px] font-semibold text-[#cfe0ff] disabled:opacity-60"
                >
                  {saving ? 'Saving…' : 'Save'}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setDraft('');
                    setNaming(false);
                  }}
                  className="rounded-control border border-border-strong px-2.5 py-[5px] text-[12px] font-semibold text-dim hover:text-text"
                >
                  Cancel
                </button>
              </span>
            ) : (
              <button
                type="button"
                onClick={() => setNaming(true)}
                title="Save the filters currently applied as a named view. Views follow you between workstations."
                className={cn(
                  CHIP_BASE,
                  'border-dashed border-border-strong bg-transparent text-faint hover:text-text-2',
                )}
              >
                <Plus size={11} className="flex-none" />
                Save view
              </button>
            ))}
          {viewError && (
            <span role="alert" className="text-[11.5px] text-danger">
              {viewError}
            </span>
          )}
        </div>
      )}

      {/* The facet row. ALWAYS rendered — the controls that produced the list
          have to stay visible and usable while a selection is being assembled.
          An earlier cut swapped this row out for the selection strip, which on
          Hunts removed the screen's only filter, wiped the typed search term
          out of the box while it was still applied server-side, and left
          "Clear" (which discards the selection) as the only way back. */}
      <div className="mb-2.5 flex min-h-[37px] flex-wrap items-center gap-2">
        {search && (
          <span className="relative flex items-center">
            <Search size={13} className="pointer-events-none absolute left-[9px] text-faint" />
            <input
              type="search"
              value={search.value}
              onChange={(e) => search.onChange(e.target.value)}
              placeholder={search.placeholder ?? 'Search…'}
              aria-label={search.label ?? search.placeholder ?? 'Search'}
              className="w-[240px] rounded-control border border-border-input bg-bg py-[7px] pl-[28px] pr-3 text-[12.5px] text-text outline-none focus:border-accent"
            />
          </span>
        )}
        {children}
        {trailing && (
          <>
            <div className="flex-1" />
            {trailing}
          </>
        )}
      </div>

      {/* Its own row: a bulk-action result names the hosts it did and did not
          reach, which is long enough to shove a right-aligned control onto a
          second line if it shares the facet row. */}
      {note && <div className="mb-2.5 text-[12.5px] text-text-2">{note}</div>}

      {/* The selection strip, APPENDED under the facets rather than replacing
          them. Compact and accented so it reads as a mode without costing the
          filters their place. */}
      {selecting && (
        <div
          data-testid="list-toolbar-selection"
          className="mb-3.5 flex flex-wrap items-center gap-2 rounded-card border border-accent-deep bg-[#0d1726] px-[11px] py-[7px]"
        >
          <span className="text-[12.5px] text-dim">
            {selection?.summary ?? (
              <>
                <span className="font-mono text-accent">{selection?.count}</span>{' '}
                {selection?.noun ?? 'selected'}
              </>
            )}
          </span>
          {/* Selection outlives a filter change on purpose — but silently, it is
              a trap: the operator submits ids nothing on screen shows. Say so,
              and offer the narrower exit than "Clear". */}
          {!!selection?.offPageCount && (
            <button
              type="button"
              onClick={selection.onClearOffPage}
              disabled={!selection.onClearOffPage}
              title="These were selected under a different filter or on another page. They are still included in a bulk action."
              className="flex items-center gap-1.5 rounded-badge border border-warn/40 bg-warn/10 px-[7px] py-[2px] text-[11.5px] font-semibold text-warn enabled:hover:border-warn"
            >
              <EyeOff size={11} className="flex-none" />
              {selection.offPageCount} not on this page
              {selection.onClearOffPage && <X size={11} className="flex-none" />}
            </button>
          )}
          {selection?.actions}
          <button
            type="button"
            onClick={selection?.onClear}
            className="rounded-[7px] border border-border-strong bg-transparent px-[11px] py-1.5 text-[12.5px] font-semibold text-dim hover:border-danger hover:text-danger"
          >
            Clear
          </button>
        </div>
      )}
    </div>
  );
}
