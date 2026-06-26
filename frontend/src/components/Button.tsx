import type { ButtonHTMLAttributes, ReactNode } from 'react';
import { cn } from '../lib/cn';

type Variant = 'primary' | 'secondary' | 'ghost' | 'approve' | 'reject';
type Size = 'sm' | 'md';

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  icon?: ReactNode;
  children?: ReactNode;
}

const base =
  'inline-flex items-center justify-center gap-1.5 font-semibold rounded-control cursor-pointer font-sans transition-colors disabled:cursor-not-allowed';

const sizes: Record<Size, string> = {
  sm: 'text-[12.5px] px-3 py-1.5',
  md: 'text-[13px] px-[13px] py-2',
};

const variants: Record<Variant, string> = {
  primary: 'bg-accent border border-accent text-white hover:bg-accent-deep',
  secondary:
    'bg-surface-3 border border-border-strong text-text hover:border-accent hover:bg-[#141b25]',
  ghost: 'bg-transparent border border-border-strong text-dim hover:text-text hover:border-accent',
  approve:
    'bg-success-btn border border-success-btn-border text-[#eafff2] hover:bg-[#22824c]',
  reject:
    'bg-surface-3 border border-border-strong text-text-2 hover:border-danger hover:text-danger',
};

export function Button({
  variant = 'secondary',
  size = 'md',
  icon,
  children,
  className,
  ...rest
}: ButtonProps) {
  return (
    <button className={cn(base, sizes[size], variants[variant], className)} {...rest}>
      {icon && <span className="flex">{icon}</span>}
      {children}
    </button>
  );
}
