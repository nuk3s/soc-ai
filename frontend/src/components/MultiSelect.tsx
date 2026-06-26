import { ChevronDown } from 'lucide-react';
import { useState } from 'react';

interface MultiSelectProps {
  label: string;
  icon?: React.ReactNode;
  options: Array<{ value: string; label: string }>;
  value: string[];
  onChange: (v: string[]) => void;
}

export function MultiSelect({ label, icon, options, value, onChange }: MultiSelectProps) {
  const [open, setOpen] = useState(false);

  const toggle = (optValue: string) => {
    if (value.includes(optValue)) {
      onChange(value.filter((v) => v !== optValue));
    } else {
      onChange([...value, optValue]);
    }
  };

  const count = value.length;
  const active = count > 0;

  const triggerStyle = active
    ? { borderColor: 'rgba(75,139,245,.5)', background: 'rgba(75,139,245,.08)', color: '#cfe0ff' }
    : { borderColor: 'var(--color-border-2, #23314a)', background: 'var(--color-surface-1, #111827)', color: 'var(--color-dim, #8b94a3)' };

  return (
    <div className="relative" onKeyDown={(e) => { if (e.key === 'Escape') setOpen(false); }}>
      {/* trigger */}
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="relative flex items-center gap-1.5 rounded-control border pl-[11px] pr-7 text-[12.5px] font-semibold"
        style={{ ...triggerStyle, paddingTop: '7px', paddingBottom: '7px' }}
      >
        {icon}
        <span>{active ? `${label} · ${count}` : label}</span>
        <span className="pointer-events-none absolute right-2">
          <ChevronDown size={12} />
        </span>
      </button>

      {open && (
        <>
          {/* backdrop to close on outside click */}
          <div
            className="fixed inset-0 z-[39]"
            onClick={() => setOpen(false)}
          />
          {/* popover */}
          <div className="absolute left-0 top-[calc(100%+6px)] z-40 min-w-[160px] animate-fadeUp rounded-panel border border-border-2 bg-surface-1 p-1.5 shadow-[0_12px_40px_rgba(0,0,0,.5)]">
            {options.map((opt) => {
              const checked = value.includes(opt.value);
              return (
                <label
                  key={opt.value}
                  className="flex cursor-pointer items-center gap-2 rounded-[5px] px-2.5 py-[6px] text-[12.5px] hover:bg-surface-hover"
                >
                  <input
                    type="checkbox"
                    className="accent-accent"
                    checked={checked}
                    onChange={() => toggle(opt.value)}
                  />
                  <span className={checked ? 'text-text' : 'text-dim'}>{opt.label}</span>
                </label>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
}
