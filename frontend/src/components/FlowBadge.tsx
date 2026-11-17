// Source → destination IP pair, rendered the Security Onion way: both ends always
// shown with a direction arrow. Used everywhere an alert/investigation flow is
// displayed so a single surface never hides one of the two hosts.
//
// Each end names its machine when the Hosts data has a name or a role:
// "ws-01 (workstation) 10.20.30.5". An address with neither prints alone
// (prod review 2026-11-12, ui-core 9). The source is amber and the destination
// green on every surface: the group row and the event rows of Alerts used the
// two colours the other way round (ui-core 11).
import { hostLabelText, hostOf, useHostNames } from '../lib/hostNames';

/** The colour of each end. One place, so no surface can swap them. */
const FLOW_SRC_TONE = 'text-mono-amber';
const FLOW_DST_TONE = 'text-mono-green';

/** The name and the role of the machine behind an address, or nothing. Put
 *  it before an address that a surface prints by hand. */
export function HostLabel({ value, className = '' }: { value?: string | null; className?: string }) {
  useHostNames([value]);
  const text = hostLabelText(hostOf(value));
  if (!text) return null;
  return (
    <span data-testid="host-label" className={`break-words font-sans text-text-2 ${className}`}>
      {text}{' '}
    </span>
  );
}

function End({
  value,
  tone,
  testId,
  onPivot,
}: {
  value?: string | null;
  tone: string;
  testId: string;
  onPivot?: () => void;
}) {
  const label = hostLabelText(hostOf(value));
  const shown = value ?? '—';
  return (
    <span data-testid={testId} className="inline-flex min-w-0 flex-wrap items-baseline gap-x-1">
      {label && (
        <span data-testid="host-label" className="min-w-0 break-words font-sans text-text-2">
          {label}
        </span>
      )}
      {onPivot ? (
        <span
          className={`min-w-0 cursor-pointer break-words hover:underline ${tone}`}
          onClick={(e) => {
            e.stopPropagation();
            onPivot();
          }}
          title={`Pivot to ${shown}`}
        >
          {shown}
        </span>
      ) : (
        <span className={`min-w-0 break-words ${tone}`}>{shown}</span>
      )}
    </span>
  );
}

export function FlowBadge({
  src,
  dst,
  port,
  className = '',
  onPivotSrc,
  onPivotDst,
}: {
  src?: string | null;
  dst?: string | null;
  /** The destination port, printed once against the destination. */
  port?: number | string | null;
  className?: string;
  /** Make an end a link to its entity page. */
  onPivotSrc?: () => void;
  onPivotDst?: () => void;
}) {
  useHostNames([src, dst]);
  if (!src && !dst) return <span className="text-faint">—</span>;
  const words = (v?: string | null) => {
    const label = hostLabelText(hostOf(v));
    return label ? `${label} ${v}` : v ?? '—';
  };
  return (
    <span
      data-testid="flow-badge"
      className={`inline-flex min-w-0 flex-wrap items-center gap-x-1 font-mono text-[12px] ${className}`}
      title={`${words(src)} → ${words(dst)}`}
    >
      <End value={src} tone={FLOW_SRC_TONE} testId="flow-src" onPivot={onPivotSrc} />
      <span className="flex-none text-faint">→</span>
      <span className="inline-flex min-w-0 flex-wrap items-baseline">
        <End value={dst} tone={FLOW_DST_TONE} testId="flow-dst" onPivot={onPivotDst} />
        {port != null && port !== '' && <span className="text-faint">:{port}</span>}
      </span>
    </span>
  );
}
