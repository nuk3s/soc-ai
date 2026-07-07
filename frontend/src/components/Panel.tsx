import { ChevronRight } from 'lucide-react';
import type { ReactNode } from 'react';
import { cn } from '../lib/cn';

/**
 * Collapse chevron toggle — the shared fold/unfold affordance for a section
 * header. Rotates 90° when expanded (mirrors the settings-group headers on the
 * Config page). Renders as a button so it's independently clickable when it sits
 * inside a panel header that isn't itself a toggle.
 */
export function CollapseChevron({
  collapsed,
  onToggle,
  label,
}: {
  collapsed: boolean;
  onToggle: () => void;
  label?: string;
}) {
  return (
    <button
      type="button"
      onClick={onToggle}
      aria-expanded={!collapsed}
      aria-label={label ?? (collapsed ? 'Expand section' : 'Collapse section')}
      className="group flex-none text-faint hover:text-text-2"
    >
      <ChevronRight
        size={15}
        className="transition-transform"
        style={{ transform: collapsed ? 'none' : 'rotate(90deg)' }}
      />
    </button>
  );
}

interface PanelProps {
  children: ReactNode;
  className?: string;
}

/** Bordered card/panel surface used across screens. */
export function Panel({ children, className }: PanelProps) {
  return (
    <div className={cn('overflow-hidden rounded-panel border border-border bg-surface-1', className)}>
      {children}
    </div>
  );
}

interface PanelHeaderProps {
  icon?: ReactNode;
  title: ReactNode;
  right?: ReactNode;
  className?: string;
}

export function PanelHeader({ icon, title, right, className }: PanelHeaderProps) {
  return (
    <div className={cn('flex items-center gap-[9px] border-b border-border px-[15px] py-3', className)}>
      {icon && <span className="flex text-accent">{icon}</span>}
      <div className="text-[13px] font-semibold">{title}</div>
      {right != null && (
        <>
          <div className="flex-1" />
          {right}
        </>
      )}
    </div>
  );
}

/** Uppercase section title row with a hairline rule and optional right slot. */
export function SectionTitle({
  children,
  right,
}: {
  children: ReactNode;
  right?: ReactNode;
}) {
  return (
    <div className="mb-[11px] flex items-center gap-[9px]">
      <div className="text-[14px] font-semibold">{children}</div>
      <div className="h-px flex-1 bg-border" />
      {right}
    </div>
  );
}
