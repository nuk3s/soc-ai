// Why the reader should care — directly under the identity sentence.
//
// The two fields that ARE pure why-care (criticality and the operator note)
// used to render 11th and 12th of 12, ~3,800px down; the policy note written
// specifically to prevent the 2026-08-05 pivot incident sat below a raw JSON
// histogram. This strip puts them first, verbatim, with their author — and
// carries the other two things that change how an analyst reads the page: the
// coverage caveat in words, and any open disagreement with BOTH claims and
// BOTH resolutions inline (the old page scattered that decision across an
// amber box, a grey box above it and a collapsed drawer below).

import { AlertTriangle, Check, EyeOff, Undo2 } from 'lucide-react';
import { useState } from 'react';
import { clearDossierOverride, snoozeDossierConflict } from '../lib/api';
import { cn } from '../lib/cn';
import { fieldLabel, isResolved, relativeAge } from '../lib/hostDossier';
import { absTime } from '../lib/timeRange';
import type { Dossier, DossierField } from '../lib/types';
import { useDossierWrite } from '../lib/useDossierWrite';
import { Spinner } from './States';
import { FactRow } from './HostFacts';

/** What kind-specific words an open disagreement opens with. */
function conflictLead(kind: string | null, label: string): string {
  if (kind === 'retracted')
    return `The evidence behind your ${label} declaration has gone away — the sweep no longer sees anything here.`;
  if (kind === 'rebound')
    return `A different machine may hold this address now — your ${label} declaration may describe a host that has moved on.`;
  return `The sweep keeps disagreeing with your ${label}.`;
}

/**
 * One open disagreement: both claims, the sweep's evidence, and the only two
 * buttons that resolve it — each labelled with the value it leaves standing,
 * because "Accept inference" never said what would be accepted (F11).
 */
function ConflictCard({
  ip,
  f,
  canDeclare,
  onApplied,
}: {
  ip: string;
  f: DossierField;
  canDeclare: boolean;
  onApplied: (next: Dossier) => void;
}) {
  const { busy, err, run } = useDossierWrite(onApplied);
  // Discarding an operator's declaration is destructive, so it arms first —
  // the same two-step every other delete in the app uses.
  const [confirming, setConfirming] = useState(false);

  const conflict = f.conflict!;
  const label = fieldLabel(f.field).toLowerCase();
  const yours = f.value ?? (f.value_json != null ? JSON.stringify(f.value_json) : '—');
  const sweeps =
    f.inferred_value ??
    (f.inferred_value_json != null ? JSON.stringify(f.inferred_value_json) : null);
  // The sweep's argument, from the lane that disagrees — the decision point
  // finally shows the evidence it is asking the operator to weigh.
  const rungEntry = f.inferred_source ? f.evidence?.[f.inferred_source] : null;
  const evidenceLine =
    rungEntry && typeof rungEntry === 'object' && Array.isArray((rungEntry as Record<string, unknown>).strings)
      ? String(((rungEntry as Record<string, unknown>).strings as unknown[])[0] ?? '')
      : '';

  return (
    <div
      data-testid={`conflict-${f.field}`}
      className="rounded-card border border-warn/35 bg-warn/[0.06] px-3.5 py-2.5"
    >
      <div className="flex items-start gap-2 text-[12.5px] leading-[1.5] text-warn">
        <AlertTriangle size={13} className="mt-0.5 flex-none" />
        <span>{conflictLead(conflict.kind, label)}</span>
      </div>
      <div className="mt-1.5 text-[12.5px] leading-[1.6] text-text-2">
        Yours: <span className="font-semibold text-text">{yours}</span>
        {sweeps != null && (
          <>
            {' '}
            · the sweep sees <span className="font-semibold text-text">{sweeps}</span>
          </>
        )}
        <span className="text-faint">
          {' '}
          — seen {conflict.observations} time{conflict.observations === 1 ? '' : 's'}
          {conflict.first_seen_at ? ` since ${relativeAge(conflict.first_seen_at)}` : ''}
        </span>
      </div>
      {evidenceLine && (
        <div className="mt-1 text-[12px] leading-[1.5] text-dim">"{evidenceLine}"</div>
      )}
      {conflict.snoozed_until && (
        <div className="mt-1 text-[11.5px] text-faint">
          Kept yours — asking again after {absTime(conflict.snoozed_until)}
        </div>
      )}
      {canDeclare && (
        <div className="mt-2 flex flex-wrap items-center gap-2">
          {confirming ? (
            <>
              <button
                disabled={busy}
                onClick={() => run(() => clearDossierOverride(ip, f.field), () => setConfirming(false))}
                className="flex items-center gap-1.5 rounded-control border border-danger bg-danger/10 px-3 py-1.5 text-[12px] font-semibold text-danger hover:bg-danger/20 disabled:opacity-60"
              >
                {busy ? <Spinner size={12} color="#f04438" /> : <Undo2 size={12} />}
                Replace my declaration
              </button>
              <button
                onClick={() => setConfirming(false)}
                className="rounded-control border border-border-strong bg-surface-3 px-3 py-1.5 text-[12px] text-text-2 hover:text-text"
              >
                Cancel
              </button>
            </>
          ) : (
            <>
              <button
                onClick={() => setConfirming(true)}
                className="rounded-control border border-border-strong bg-surface-3 px-3 py-1.5 text-[12px] font-semibold text-text-2 hover:border-accent hover:text-text"
              >
                {sweeps != null ? `Use the sweep's answer: ${sweeps}` : 'Withdraw my declaration'}
              </button>
              <button
                disabled={busy}
                onClick={() => run(() => snoozeDossierConflict(ip, f.field))}
                title="Keep your declaration; the sweep asks again later (the interval doubles, capped at 90 days)"
                className="flex items-center gap-1.5 rounded-control border border-border-strong bg-surface-3 px-3 py-1.5 text-[12px] font-semibold text-text-2 hover:border-accent hover:text-text disabled:opacity-60"
              >
                {busy ? <Spinner size={12} /> : <Check size={12} />}
                Keep mine: {yours}
              </button>
            </>
          )}
        </div>
      )}
      {err && (
        <div className="mt-2 rounded-control border border-danger/35 bg-danger/[0.07] px-3 py-2 text-[12px] text-danger">
          {err}
        </div>
      )}
    </div>
  );
}

export interface HostBriefingProps {
  dossier: Dossier;
  canDeclare: boolean;
  onApplied: (next: Dossier) => void;
  focusField: string | null;
}

export function HostBriefing({ dossier, canDeclare, onApplied, focusField }: HostBriefingProps) {
  const conflicts = dossier.fields.filter((f) => f.conflict != null);
  const criticality = dossier.fields.find((f) => f.field === 'criticality' && isResolved(f));
  const policy = dossier.fields.find((f) => f.field === 'policy_notes' && isResolved(f));
  // "No agent data" was a grey pill nobody was told the meaning of. The caveat
  // belongs here, in words, because it changes how every number below reads.
  // `reporting` is the wire's answer, computed under overrides and the
  // staleness gates the client does not hold.
  const noAgent = !dossier.reporting;

  if (conflicts.length === 0 && !criticality && !policy && !noAgent) return null;

  return (
    <section data-testid="host-briefing" className="mb-3 flex flex-col gap-2">
      {(criticality || policy) && (
        <div
          className={cn(
            'overflow-hidden rounded-card border border-border bg-surface-1',
            criticality && 'border-l-2 border-l-danger/60',
          )}
        >
          {criticality && (
            <FactRow
              ip={dossier.ip}
              f={criticality}
              canDeclare={canDeclare}
              highlight={focusField === 'criticality'}
              onApplied={onApplied}
              variant="strip"
            />
          )}
          {policy && (
            <FactRow
              ip={dossier.ip}
              f={policy}
              canDeclare={canDeclare}
              highlight={focusField === 'policy_notes'}
              onApplied={onApplied}
              variant="strip"
            />
          )}
        </div>
      )}

      {conflicts.map((f) => (
        <ConflictCard key={f.field} ip={dossier.ip} f={f} canDeclare={canDeclare} onApplied={onApplied} />
      ))}

      {noAgent && (
        <div className="flex items-start gap-2 rounded-card border border-border bg-surface-1 px-3.5 py-2.5 text-[12.5px] leading-[1.5] text-dim">
          <EyeOff size={13} className="mt-0.5 flex-none text-faint" />
          <span>
            No agent reports from this machine — its processes, users and local logs are invisible
            here. Everything on this page was learned from network traffic.
          </span>
        </div>
      )}
    </section>
  );
}
