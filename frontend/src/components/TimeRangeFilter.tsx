import { Calendar, ChevronDown } from 'lucide-react';
import { useState } from 'react';

// Must match the backend's TIME_RANGES (alerts_query.py) so every preset resolves.
const DEFAULT_PRESETS = ['15m', '1h', '4h', '24h', '3d', '7d', '30d'];
const MON = ['', 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

export interface CustomRange {
  from: string; // datetime-local value
  to: string;
}

function fmtLocal(s: string): string {
  if (!s) return '';
  const [d, t] = s.split('T');
  const [, mo, day] = d.split('-');
  return `${MON[+mo]} ${+day} ${t ?? ''}`;
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
  const [from, setFrom] = useState(custom?.from ?? '');
  const [to, setTo] = useState(custom?.to ?? '');
  const isCustom = value === 'custom';

  const apply = () => {
    if (!from || !to) return;
    onChange('custom', { from, to });
    setOpen(false);
  };

  return (
    <div className="relative flex items-center">
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
          onClick={() => setOpen((o) => !o)}
          aria-label="Custom date range"
          className="flex items-center gap-1.5 px-[11px] py-1.5 text-[12px] font-medium"
          style={{
            color: isCustom || open ? '#e6e9ef' : '#8b94a3',
            background: isCustom || open ? '#161e29' : 'transparent',
          }}
        >
          <Calendar size={12.5} />
          {isCustom && custom ? (
            <span className="font-mono text-[11.5px]">
              {fmtLocal(custom.from)} <span className="text-faint">→</span> {fmtLocal(custom.to)}
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
