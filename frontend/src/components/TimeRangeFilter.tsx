import { Calendar, ChevronDown } from 'lucide-react';
import { useState } from 'react';
import { absoluteTime } from '../lib/timeRange';

// Must match the backend's TIME_RANGES (alerts_query.py) so every preset resolves.
const DEFAULT_PRESETS = ['15m', '1h', '4h', '24h', '3d', '7d', '30d'];

export interface CustomRange {
  from: string; // datetime-local value
  to: string;
}

const UNIT_MS: Record<string, number> = { m: 60_000, h: 3_600_000, d: 86_400_000 };

/**
 * One bound of a custom window as the chip states it: "Aug 25 00:00 UTC".
 *
 * The chip printed the stored value with its seconds, its milliseconds and a
 * bare "Z" (dogfood 2026-10-19, R2-D17). The picker writes a wall time in the
 * browser zone, and a link can write an ISO time in UTC. Both read here as
 * the same instant, stated in the browser zone with the zone named, the zone
 * every other absolute time of the console uses. An unreadable value reads
 * as itself. `timeZone` is for tests.
 */
export function customBoundText(value: string, opts: { timeZone?: string } = {}): string {
  if (!value) return '';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  const parts = new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
    timeZoneName: 'short',
    ...(opts.timeZone ? { timeZone: opts.timeZone } : {}),
  }).formatToParts(d);
  const get = (type: Intl.DateTimeFormatPartTypes): string =>
    parts.find((p) => p.type === type)?.value ?? '';
  return `${get('month')} ${get('day')} ${get('hour')}:${get('minute')} ${get('timeZoneName')}`.trim();
}

/**
 * A time as a datetime-local value, "2026-08-25T00:00", in the browser zone.
 *
 * The input refuses any other form and shows an empty field, so an ISO bound
 * from a link opened the picker empty (dogfood 2026-10-19, R2-I7). An
 * unreadable value reads as an empty string.
 */
export function pickerValue(value: string | number): string {
  if (value === '') return '';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return '';
  const pad = (n: number) => String(n).padStart(2, '0');
  return (
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}` +
    `T${pad(d.getHours())}:${pad(d.getMinutes())}`
  );
}

/** The active window as picker values, or null when it has no lower edge. */
function activeWindow(
  value: string,
  custom: CustomRange | null | undefined,
  now = Date.now(),
): CustomRange | null {
  if (value === 'custom') {
    return custom?.from && custom?.to
      ? { from: pickerValue(custom.from), to: pickerValue(custom.to) }
      : null;
  }
  const m = /^(\d+)([mhd])$/.exec(value);
  if (!m) return null;
  const span = Number(m[1]) * UNIT_MS[m[2]];
  return { from: pickerValue(now - span), to: pickerValue(now) };
}

interface Props {
  value: string; // a preset string, or 'custom'
  custom?: CustomRange | null;
  onChange: (value: string, range?: CustomRange) => void;
  presets?: string[];
}

/**
 * Time-range filter: preset segments + a "Custom" range picker (from/to).
 * Reusable across any page with a date/time filter.
 */
export function TimeRangeFilter({ value, custom, onChange, presets = DEFAULT_PRESETS }: Props) {
  const [open, setOpen] = useState(false);
  const [from, setFrom] = useState(() => (custom?.from ? pickerValue(custom.from) : ''));
  const [to, setTo] = useState(() => (custom?.to ? pickerValue(custom.to) : ''));
  const isCustom = value === 'custom';

  // The picker opens on the window in force: the custom window, or the span
  // of the active preset up to now. It opened empty while a custom window was
  // active, and the analyst typed the whole window again to move one edge.
  const toggle = () => {
    if (!open) {
      const active = activeWindow(value, custom);
      if (active) {
        setFrom(active.from);
        setTo(active.to);
      }
    }
    setOpen((o) => !o);
  };

  const apply = () => {
    if (!from || !to) return;
    onChange('custom', { from, to });
    setOpen(false);
  };

  return (
    <div data-tour="time-filter" className="relative flex items-center">
      <div className="flex items-center overflow-hidden rounded-control border border-border-2 bg-surface-1">
        {presets.map((t) => (
          <button
            key={t}
            onClick={() => onChange(t)}
            className="border-r border-border px-[11px] py-1.5 font-mono text-[12px] font-medium"
            style={{ color: value === t ? '#e6e9ef' : '#8b94a3', background: value === t ? '#161e29' : 'transparent' }}
          >
            {t}
          </button>
        ))}
        <button
          onClick={toggle}
          aria-label="Custom date range"
          title={
            isCustom && custom
              ? `The window starts ${absoluteTime(custom.from)} and ends ${absoluteTime(custom.to)}.`
              : undefined
          }
          className="flex items-center gap-1.5 px-[11px] py-1.5 text-[12px] font-medium"
          style={{
            color: isCustom || open ? '#e6e9ef' : '#8b94a3',
            background: isCustom || open ? '#161e29' : 'transparent',
          }}
        >
          <Calendar size={12.5} />
          {isCustom && custom ? (
            <span className="font-mono text-[11.5px]">
              {customBoundText(custom.from)} <span className="text-faint">to</span>{' '}
              {customBoundText(custom.to)}
            </span>
          ) : (
            <>
              Custom <ChevronDown size={11} className="text-faint" />
            </>
          )}
        </button>
      </div>

      {open && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} />
          <div className="absolute left-0 top-[calc(100%+6px)] z-50 w-[300px] animate-fadeUp rounded-panel border border-border-2 bg-surface-1 p-3.5 shadow-[0_20px_54px_rgba(0,0,0,.55)]">
            <div className="mb-2.5 text-[11px] font-semibold uppercase tracking-[.05em] text-faint">Custom range</div>
            <label className="mb-1 block text-[11.5px] text-dim">From</label>
            <input
              type="datetime-local"
              value={from}
              onChange={(e) => setFrom(e.target.value)}
              className="mb-2.5 w-full rounded-control border border-border-input bg-bg px-2.5 py-2 font-mono text-[12.5px] text-text outline-none focus:border-accent"
              style={{ colorScheme: 'dark' }}
            />
            <label className="mb-1 block text-[11.5px] text-dim">To</label>
            <input
              type="datetime-local"
              value={to}
              onChange={(e) => setTo(e.target.value)}
              className="mb-3 w-full rounded-control border border-border-input bg-bg px-2.5 py-2 font-mono text-[12.5px] text-text outline-none focus:border-accent"
              style={{ colorScheme: 'dark' }}
            />
            <div className="flex items-center justify-end gap-2">
              <button onClick={() => setOpen(false)} className="rounded-control px-2.5 py-1.5 text-[12px] text-dim hover:text-text">
                Cancel
              </button>
              <button
                onClick={apply}
                disabled={!from || !to}
                className="rounded-control bg-accent px-3 py-1.5 text-[12px] font-semibold text-white hover:bg-accent-deep disabled:cursor-not-allowed disabled:opacity-40"
              >
                Apply
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
