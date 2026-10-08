// Source → destination IP pair, rendered the Security Onion way: both ends always
// shown with a direction arrow. Used everywhere an alert/investigation flow is
// displayed so a single surface never hides one of the two hosts.

export function FlowBadge({
  src,
  dst,
  className = '',
}: {
  src?: string | null;
  dst?: string | null;
  className?: string;
}) {
  if (!src && !dst) return <span className="text-faint">—</span>;
  return (
    <span
      className={`inline-flex min-w-0 flex-wrap items-center gap-x-1 font-mono text-[12px] ${className}`}
      title={`${src ?? '—'} → ${dst ?? '—'}`}
    >
      <span className="min-w-0 break-all text-mono-amber">{src ?? '—'}</span>
      <span className="flex-none text-faint">→</span>
      <span className="min-w-0 break-all text-mono-green">{dst ?? '—'}</span>
    </span>
  );
}
