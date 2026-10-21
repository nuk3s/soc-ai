import { ChevronDown } from 'lucide-react';
import { useState } from 'react';
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

/** "1 to 365" / "0.0 to 1.0" / "∞ to 100" (GET /config `bounds`) as numbers. */
export function parseBounds(bounds?: string | null): { min?: number; max?: number } {
  if (!bounds) return {};
  const m = /^\s*(\S+)\s+to\s+(\S+)\s*$/.exec(bounds);
  if (!m) return {};
  const num = (t: string) => {
    const n = Number(t);
    return Number.isFinite(n) ? n : undefined;
  };
  return { min: num(m[1]), max: num(m[2]) };
}

/** The pixels a number field adds to its characters: 10 px of padding on each
 *  side, a 1 px border on each side and the spinner of about 15 px. The field
 *  added 34 px, and Chromium clipped every value by 3 px: 0.15 read "0.1" and
 *  half a 5 (dogfood round 2, R5-D1). 40 px is the least that fits. */
export const NUMBER_FIELD_PAD_PX = 44;

/** The characters of the smallest step a decimal field can hold: "0.01". */
function stepChars(step: number | undefined, numbers: readonly number[], texts: readonly string[]): number {
  if (step !== undefined && Number.isFinite(step) && step > 0) return String(step).length;
  const decimals = [...numbers.map(String), ...texts]
    .map((t) => (/\.(\d+)$/.exec(t.trim())?.[1].length ?? 0))
    .reduce((most, n) => Math.max(most, n), 0);
  return decimals > 0 ? decimals + 2 : 0;
}

/** The width of a number field in characters: room for the longest of the
 *  value, the bounds and the step. A fixed 62 px cut 32000 to "320" and 0.02
 *  to "0.0" (dogfood 2026-10-19, R5-D1). The bound texts count as typed, so
 *  "1.00" counts four characters. */
export function numberFieldChars(
  value: number,
  min?: number,
  max?: number,
  { texts = [], step }: { texts?: readonly string[]; step?: number } = {},
): number {
  const numbers = [value, min, max].filter(
    (n): n is number => typeof n === 'number' && Number.isFinite(n),
  );
  const lengths = [
    ...numbers.map((n) => String(n).length),
    ...texts.map((t) => t.trim().length),
    stepChars(step, numbers, texts),
  ];
  return Math.min(16, Math.max(4, ...lengths));
}

interface NumberFieldProps {
  value: number;
  bounds?: string;
  onChange?: (v: number) => void;
  /** Accessible name: the setting label. The field had none (R5-D23). */
  label?: string;
}
export function NumberField({ value, bounds, onChange, label }: NumberFieldProps) {
  const { min, max } = parseBounds(bounds);
  const [error, setError] = useState('');
  const [lo, hi] = bounds ? bounds.split(/\s+to\s+/) : [];
  // An open bound reads "∞". It is no number a reader types.
  const texts = [lo, hi].filter((t): t is string => !!t && Number.isFinite(Number(t)));
  const least = numberFieldChars(value, min, max, { texts });
  const [chars, setChars] = useState(least);
  const name = label || 'The value';
  const check = (raw: string) => {
    // The field grows with a long typed value, up to the cap.
    setChars(Math.min(16, Math.max(least, raw.length)));
    if (raw.trim() === '') {
      setError('Enter a number.');
      return;
    }
    const n = Number(raw);
    if (!Number.isFinite(n)) {
      setError(`${name} must be a number.`);
      return;
    }
    // Checked here before Apply. The server refused 999 with the raw key
    // and no word beside the field until Apply (H1-D23, R5-I7).
    if ((min !== undefined && n < min) || (max !== undefined && n > max)) {
      const span =
        min !== undefined && max !== undefined
          ? `from ${lo} to ${hi}`
          : min !== undefined
            ? `${lo} or more`
            : `${hi} or less`;
      setError(`${name} must be ${span}.`);
      return;
    }
    setError('');
    onChange?.(n);
  };
  return (
    <div className="flex flex-col items-end gap-1">
      <div className="flex items-center gap-2">
        <input
          type="number"
          defaultValue={value}
          min={min}
          max={max}
          step="any"
          aria-label={label}
          aria-invalid={error ? true : undefined}
          onChange={(e) => check(e.target.value)}
          className="rounded-control border border-border-input bg-bg px-2.5 py-[7px] text-right font-mono text-[12.5px] text-text outline-none focus:border-accent"
          style={{
            width: `calc(${chars}ch + ${NUMBER_FIELD_PAD_PX}px)`,
            ...(error ? { borderColor: '#f04438' } : {}),
          }}
        />
        {bounds && <span className="font-mono text-[11px] text-faint">{bounds}</span>}
      </div>
      {error && (
        <span role="alert" className="max-w-[240px] text-right text-[11px] text-danger">
          {error}
        </span>
      )}
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
  /** Accessible name, for a select with no visible `<label>` beside it — the
   *  compact controls in a selection strip, where a caption costs more room
   *  than it earns. */
  label?: string;
}
export function Select({ value, options, onChange, label }: SelectProps) {
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
        aria-label={label}
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
  /** Renders inert (dimmed, no click) — a row that bulk actions can't reach. */
  disabled?: boolean;
  'aria-label'?: string;
}
export function Checkbox({ checked, onClick, onChange, title, indeterminate, disabled, 'aria-label': ariaLabel }: CheckboxProps) {
  const active = checked || !!indeterminate;
  const handleClick = (e: React.MouseEvent) => {
    if (disabled) return;
    onClick?.(e);
    if (onChange) onChange(!checked);
  };
  return (
    <button
      type="button"
      role="checkbox"
      aria-checked={indeterminate ? 'mixed' : checked}
      aria-disabled={disabled || undefined}
      disabled={disabled}
      aria-label={ariaLabel}
      title={title}
      onClick={handleClick}
      className={`flex h-4 w-4 flex-none items-center justify-center rounded-[4px] border-[1.5px] p-0 ${disabled ? 'cursor-not-allowed opacity-40' : 'cursor-pointer'}`}
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
    </button>
  );
}
