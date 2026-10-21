// The one role control for a declaration.
//
// The host page offered a free-text box with a datalist, and the Hosts bulk
// bar offered a closed list. The two read as two different rules for one
// field (dogfood 2026-10-19, R4-D20). Both now render this control: the
// vocabulary roles in reading form, and "Other" with a text box where the
// caller allows a novel role.
//
// The single-host declare allows Other. One operator who knows a machine is a
// jump host states a fact about one machine. The bulk bar does not: the
// server refuses a role outside the vocabulary on a bulk declare
// (routes_dossier.py, reason `unknown_role`), because one typo there becomes a
// role on every selected machine.

import { ChevronDown } from 'lucide-react';
import { useMemo, useRef, useState } from 'react';
import { cn } from '../lib/cn';
import { roleLabel, roleVocabulary } from '../lib/hostDossier';

/** The list value of the Other choice. No role slug starts with "__". */
export const OTHER_ROLE = '__other__';

export interface RoleChoiceProps {
  /** The role to declare: a vocabulary slug, the operator's own text, or ''. */
  value: string;
  onChange: (value: string) => void;
  /** The role vocabulary from the wire. Null or empty falls back to the
   *  frontend list (lib/hostDossier `roleVocabulary`). */
  vocabulary?: readonly string[] | null;
  /** Offer "Other" and a text box for a role outside the vocabulary. */
  allowOther?: boolean;
  /** The accessible name of the list. */
  label: string;
  /** The id of the list, for a form label. */
  id?: string;
  /** "bar" fits a toolbar row. "form" fills the width of a form. */
  variant?: 'bar' | 'form';
  title?: string;
}

export function RoleChoice({
  value,
  onChange,
  vocabulary,
  allowOther = true,
  label,
  id,
  variant = 'bar',
  title,
}: RoleChoiceProps) {
  const roles = useMemo(() => [...roleVocabulary(vocabulary)].sort(), [vocabulary]);
  const listed = roles.includes(value);
  // Other with an empty box has no value to show it by, so the choice is
  // state. A value outside the list opens on Other too.
  const [otherChosen, setOtherChosen] = useState(false);
  const other = allowOther && (otherChosen || (value !== '' && !listed));
  const selected = other ? OTHER_ROLE : listed ? value : '';
  // Focus the box when the operator picks Other, and not when the form
  // opens on it.
  const focusBox = useRef(false);

  const pick = (next: string) => {
    if (next === OTHER_ROLE) {
      focusBox.current = true;
      setOtherChosen(true);
      onChange('');
      return;
    }
    setOtherChosen(false);
    onChange(next);
  };

  const form = variant === 'form';
  return (
    <div className={cn('flex', form ? 'flex-col gap-2' : 'items-center gap-2')} title={title}>
      <div
        className={cn(
          'relative flex items-center rounded-control border border-border-input bg-bg pr-2',
          form && 'w-full',
        )}
      >
        <select
          id={id}
          value={selected}
          aria-label={label}
          onChange={(e) => pick(e.target.value)}
          className={cn(
            'cursor-pointer appearance-none bg-transparent pr-5 text-text outline-none',
            form ? 'w-full px-3 py-2 text-[13px]' : 'py-[7px] pl-[11px] font-mono text-[12.5px]',
          )}
        >
          <option value="" className="bg-surface-1 text-text">
            choose
          </option>
          {roles.map((r) => (
            <option key={r} value={r} className="bg-surface-1 text-text">
              {roleLabel(r)}
            </option>
          ))}
          {allowOther && (
            <option value={OTHER_ROLE} className="bg-surface-1 text-text">
              Other
            </option>
          )}
        </select>
        <span className="pointer-events-none absolute right-2 text-faint">
          <ChevronDown size={12} />
        </span>
      </div>
      {other && (
        <input
          ref={(el) => {
            if (el && focusBox.current) {
              focusBox.current = false;
              el.focus();
            }
          }}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          aria-label="Type the role"
          placeholder="Type the role"
          className={cn(
            'rounded-control border border-border-input bg-bg text-text outline-none focus:border-accent',
            form ? 'w-full px-3 py-2 text-[13px]' : 'w-[180px] px-2.5 py-[6px] text-[12.5px]',
          )}
        />
      )}
    </div>
  );
}
