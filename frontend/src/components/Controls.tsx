import { ChevronDown } from 'lucide-react';
import type { InputHTMLAttributes } from 'react';
import { cn } from '../lib/cn';

// ---- Toggle (interactive pill) ---------------------------------------------
interface ToggleProps {
  on: boolean;
  onChange: (next: boolean) => void;
  label?: string;
  disabled?: boolean;
}
export function Toggle({ on, onChange, label, disabled }: ToggleProps) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={on}
      aria-label={label}
      disabled={disabled}
      onClick={() => { if (!disabled) onChange(!on); }}
      className="relative h-[22px] w-[38px] flex-none rounded-[11px] border transition-colors disabled:cursor-not-allowed disabled:opacity-60"
      style={{
        background: on ? '#1d6b3f' : '#1a212b',
        borderColor: on ? '#2a8a52' : '#2a3645',
      }}
    >
      <span
        className="absolute top-[2px] h-4 w-4 rounded-full bg-white transition-[left]"
        style={{ left: on ? 18 : 2 }}
      />
    </button>
  );
}

// ---- Number field ----------------------------------------------------------
interface NumberFieldProps {
  value: number;
  bounds?: string;
  onChange?: (v: number) => void;
}
export function NumberField({ value, bounds, onChange }: NumberFieldProps) {
  return (
    <div className="flex items-center gap-2">
      <input
        type="number"
        defaultValue={value}
        onChange={(e) => onChange?.(Number(e.target.value))}
        className="w-[62px] rounded-control border border-border-input bg-bg px-2.5 py-[7px] text-right font-mono text-[12.5px] text-text outline-none focus:border-accent"
      />
      {bounds && <span className="font-mono text-[11px] text-faint">{bounds}</span>}
    </div>
  );
}

// ---- Select (styled box) ---------------------------------------------------
// Plain strings are the common case; an object option carries a display label
// distinct from its value (e.g. '' rendered as "(off)").
export type SelectOption = string | { value: string; label: string };
interface SelectProps {
  value: string;
  options?: SelectOption[];
  onChange?: (v: string) => void;
}
export function Select({ value, options, onChange }: SelectProps) {
  const opts = (options ?? []).map((o) => (typeof o === 'string' ? { value: o, label: o } : o));
  if (opts.length <= 1) {
    return (
      <div className="flex cursor-default items-center gap-[9px] rounded-control border border-border-input bg-bg px-[11px] py-[7px]">
        <span className="font-mono text-[12.5px] text-text">{value}</span>
        <span className="text-faint">
          <ChevronDown size={12} />
        </span>
      </div>
    );
  }
  return (
    <div className="relative flex items-center rounded-control border border-border-input bg-bg pr-2">
      <select
        value={value}
        onChange={(e) => onChange?.(e.target.value)}
        className="cursor-pointer appearance-none bg-transparent py-[7px] pl-[11px] pr-5 font-mono text-[12.5px] text-text outline-none"
      >
        {opts.map((o) => (
          <option key={o.value} value={o.value} className="bg-surface-1 text-text">
            {o.label}
          </option>
        ))}
      </select>
      <span className="pointer-events-none absolute right-2 text-faint">
        <ChevronDown size={12} />
      </span>
    </div>
  );
}

// ---- Text input ------------------------------------------------------------
export function TextInput({ className, ...rest }: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={cn(
        'w-full rounded-control border border-border-input bg-bg px-3 py-2.5 text-[13.5px] text-text outline-none focus:border-accent',
        className
      )}
      {...rest}
    />
  );
}

// ---- Checkbox (16px, accent fill when checked) -----------------------------
interface CheckboxProps {
  checked: boolean;
  onClick?: (e: React.MouseEvent) => void;
  onChange?: (checked: boolean) => void;
  title?: string;
  indeterminate?: boolean;
}
export function Checkbox({ checked, onClick, onChange, title, indeterminate }: CheckboxProps) {
  const active = checked || !!indeterminate;
  const handleClick = (e: React.MouseEvent) => {
    onClick?.(e);
    if (onChange) onChange(!checked);
  };
  return (
    <div
      role="checkbox"
      aria-checked={indeterminate ? 'mixed' : checked}
      title={title}
      onClick={handleClick}
      className="flex h-4 w-4 cursor-pointer items-center justify-center rounded-[4px] border-[1.5px]"
      style={{
        borderColor: active ? '#4b8bf5' : '#2a3645',
        background: active ? '#4b8bf5' : 'transparent',
      }}
    >
      {indeterminate && !checked ? (
        <svg width={11} height={11} viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth={3} strokeLinecap="round">
          <path d="M5 12h14" />
        </svg>
      ) : checked ? (
        <svg width={11} height={11} viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth={3} strokeLinecap="round" strokeLinejoin="round">
          <path d="M20 6L9 17l-5-5" />
        </svg>
      ) : null}
    </div>
  );
}
