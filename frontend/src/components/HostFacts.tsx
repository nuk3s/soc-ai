// What we KNOW about a host — and one honest line about what we don't.
//
// The old page gave all twelve schema fields a card each, empty or not, so the
// common case (one fact) was sixteen boxes of absence. This file renders only
// resolved facts as rows — value, provenance in words, relative freshness —
// and collapses every unknown into a single line that says why each gap is a
// gap. The machinery (rung names, confidence floats, wall-clock stamps, the
// suppressed lane under an override) lives behind each row's "Why?" drawer:
// available to whoever asks "says who?", ambient for nobody.

import { Check, ListChecks, Pencil } from 'lucide-react';
import { useEffect, useState, type ReactNode } from 'react';
import {
  clearDossierOverride,
  setDossierOverride,
  type DossierOverrideInput,
} from '../lib/api';
import { cn } from '../lib/cn';
import { criticalityAccent } from '../lib/hostColors';
import {
  activityProfileView,
  fieldLabel,
  isJsonField,
  partitionFields,
  portString,
  portsView,
  provenancePhrase,
  relativeAge,
  ROLE_VOCABULARY,
  unresolvedPhrase,
} from '../lib/hostDossier';
import { absTime } from '../lib/timeRange';
import type { Dossier, DossierField, DossierFieldName } from '../lib/types';
import { useDossierWrite } from '../lib/useDossierWrite';
import { Panel, PanelHeader } from './Panel';
import { Spinner } from './States';

/** The two why-care fields the briefing strip carries. They lead the page up
 *  there; a second row down here would state the same fact twice on one
 *  screen — the duplication the dogfood pass counted six deep on conflicts. */
export const BRIEFING_FIELDS: ReadonlySet<DossierFieldName> = new Set([
  'criticality',
  'policy_notes',
]);

/** Small mono chip, the vocabulary the alert rows already use. */
function Chip({ children, title }: { children: ReactNode; title?: string }) {
  return (
    <span
      title={title}
      className="rounded-chip border border-border-input bg-surface-3 px-1.5 py-px font-mono text-[11px] text-text-2"
    >
      {children}
    </span>
  );
}

// ---- the declare / edit form ------------------------------------------------

export interface DeclareEditorProps {
  f: DossierField;
  busy: boolean;
  onSave: (body: DossierOverrideInput) => void;
  onCancel: () => void;
  /** Validation problems are the parent's error line, beside the control. */
  onInvalid: (msg: string) => void;
  /** The role datalist suggestions, from the summary wire (see
   *  lib/hostDossier `roleVocabulary`). Omitted, it falls back to the frontend's
   *  ROLE_VOCABULARY — so the declare form and the host filter offer the same
   *  vocabulary instead of drifting apart (the F10 finding). */
  roleVocabulary?: readonly string[];
}

/**
 * The one form that writes a declaration, shared by fact rows, the why-care
 * strip and the unknown line so the three cannot drift. Role declarations get
 * the classifier's own vocabulary as suggestions (still free text — an
 * operator may know a role the classifier does not), because a typed
 * "Hypervisor" would be disputed against the canonical `hypervisor` forever.
 *
 * Free text HERE and a closed `<select>` in the Hosts BULK strip is the
 * deliberate asymmetry: this declares one host the operator has looked at, and
 * a novel role costs exactly one row. Bulk writes the same keystroke to every
 * selected host, where a typo becomes a first-class bucket in the ROLES
 * distribution and an entry in the role facet for every user.
 */
export function DeclareEditor({
  f,
  busy,
  onSave,
  onCancel,
  onInvalid,
  roleVocabulary,
}: DeclareEditorProps) {
  const jsonField = isJsonField(f.field);
  const label = fieldLabel(f.field);
  const [draft, setDraft] = useState(() =>
    jsonField
      ? JSON.stringify(f.value_json ?? f.inferred_value_json ?? null, null, 2)
      : (f.value ?? f.inferred_value ?? ''),
  );
  const [note, setNote] = useState(f.operator_note ?? '');

  const save = () => {
    const trimmedNote = note.trim();
    const base = { field: f.field, ...(trimmedNote ? { note: trimmedNote } : {}) };
    if (jsonField) {
      const raw = draft.trim();
      if (!raw) return onInvalid('A declaration needs a value.');
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch {
        return onInvalid(`That is not valid JSON — ${label} is stored as a structured value.`);
      }
      // `null` parses fine and would post a declaration that resolves to
      // nothing — the same thing the server's empty_override rule refuses.
      if (parsed == null) return onInvalid('A declaration needs a value.');
      onSave({ ...base, value_json: parsed });
    } else {
      const value = draft.trim();
      if (!value) return onInvalid('A declaration needs a value.');
      onSave({ ...base, value });
    }
  };

  const roleList = f.field === 'role' ? `role-options-${f.field}` : undefined;

  return (
    <div className="mt-2 flex flex-col gap-2 rounded-card border border-border-input bg-surface-2 px-3 py-2.5">
      <label className="text-[11.5px] font-semibold text-dim" htmlFor={`declare-${f.field}`}>
        Value{jsonField ? ' (JSON)' : ''}
      </label>
      {jsonField ? (
        <textarea
          id={`declare-${f.field}`}
          aria-label={`Value for ${label}`}
          value={draft}
          rows={6}
          onChange={(e) => setDraft(e.target.value)}
          className="w-full rounded-control border border-border-input bg-bg px-3 py-2 font-mono text-[12px] text-text outline-none focus:border-accent"
        />
      ) : (
        <>
          <input
            id={`declare-${f.field}`}
            aria-label={`Value for ${label}`}
            value={draft}
            list={roleList}
            onChange={(e) => setDraft(e.target.value)}
            className="w-full rounded-control border border-border-input bg-bg px-3 py-2 text-[13px] text-text outline-none focus:border-accent"
          />
          {roleList && (
            <datalist id={roleList}>
              {(roleVocabulary ?? ROLE_VOCABULARY).map((r) => (
                <option key={r} value={r} />
              ))}
            </datalist>
          )}
        </>
      )}
      <label className="text-[11.5px] font-semibold text-dim" htmlFor={`declare-note-${f.field}`}>
        Note <span className="font-normal text-faint">(optional — recorded with your name)</span>
      </label>
      <input
        id={`declare-note-${f.field}`}
        aria-label={`Note for ${label}`}
        value={note}
        onChange={(e) => setNote(e.target.value)}
        placeholder="Optional — how you know this"
        className="w-full rounded-control border border-border-input bg-bg px-3 py-2 text-[13px] text-text outline-none focus:border-accent"
      />
      <div className="flex items-center gap-2">
        <button
          disabled={busy}
          onClick={save}
          className="flex items-center gap-1.5 rounded-control border border-accent bg-accent/10 px-3 py-1.5 text-[12px] font-semibold text-accent hover:bg-accent/20 disabled:opacity-60"
        >
          {busy ? <Spinner size={12} /> : <Check size={12} />}
          Save
        </button>
        <button
          onClick={onCancel}
          className="rounded-control border border-border-strong bg-surface-3 px-3 py-1.5 text-[12px] text-text-2 hover:text-text"
        >
          Cancel
        </button>
      </div>
    </div>
  );
}

// ---- value rendering --------------------------------------------------------

/** The hour-of-day histogram as 24 bars. The one field that wants a chart was
 *  the one field shipped as `{"0":120,...}` — F8. */
function HourBars({ hours }: { hours: number[] }) {
  const peak = hours.reduce((max, v) => Math.max(max, v), 0) || 1;
  return (
    <svg
      viewBox="0 0 240 36"
      className="mt-1.5 h-9 w-[240px] max-w-full text-mono-green"
      role="img"
      aria-label="events by hour of day (UTC)"
    >
      {hours.map((v, h) => {
        const barHeight = v > 0 ? Math.max(2, (v / peak) * 32) : 1;
        return (
          <rect
            key={h}
            x={h * 10}
            y={36 - barHeight}
            width={7}
            height={barHeight}
            fill="currentColor"
            opacity={v > 0 ? 0.9 : 0.25}
          />
        );
      })}
    </svg>
  );
}

/** A port payload as chips — one chip per port, never a comma-string split
 *  apart, with the connection count in the hover. */
function PortChips({ payload }: { payload: unknown[] }) {
  if (payload.length === 0) return <span className="text-[12.5px] text-faint">none seen</span>;
  return (
    <span className="flex flex-wrap gap-1.5">
      {payload.map((entry, i) => {
        const rec = entry && typeof entry === 'object' ? (entry as Record<string, unknown>) : null;
        const count = rec && typeof rec.count === 'number' ? rec.count : null;
        const svc = rec && typeof rec.service === 'string' ? rec.service : null;
        return (
          <Chip key={i} title={count != null ? `${count.toLocaleString()} connections` : undefined}>
            {portString(entry)}
            {svc ? ` · ${svc}` : ''}
          </Chip>
        );
      })}
    </span>
  );
}

/** One fact's value, rendered per field so the reader gets the fact and not
 *  the payload's shape. Falls back to the scalar (the exact string the
 *  investigation prompt prints) for anything unrecognised. */
function FactValue({ f }: { f: DossierField }) {
  if (f.field === 'activity_profile') {
    const view = activityProfileView(f.value_json);
    return (
      <div className="min-w-0">
        {f.value && <div className="text-[13px] text-text">{f.value}</div>}
        {view && (
          <>
            <HourBars hours={view.hours} />
            {view.lines.length > 0 && (
              <div className="mt-1 text-[11.5px] leading-[1.5] text-dim">
                {view.lines.join(' · ')}
              </div>
            )}
          </>
        )}
        {!view && f.value_json != null && (
          <div className="break-words font-mono text-[11.5px] text-dim">
            {JSON.stringify(f.value_json)}
          </div>
        )}
      </div>
    );
  }
  if (f.field === 'management_plane') {
    // The wire's own yes/no first: {"answers": false, ...} rendered as raw
    // JSON reads like an exposure to a skimming eye (the 2026-08-09 dogfood
    // caught the true case dumped verbatim on the flagship host).
    const view = portsView(f.value_json);
    if (view) {
      const denied = view.answers === false || (f.value ?? '').trim().toLowerCase() === 'no';
      if (denied || view.ports.length === 0) {
        return <span className="text-[12.5px] text-dim">no admin interface answering</span>;
      }
      return (
        <span className="flex flex-wrap items-center gap-1.5">
          <span className="text-[12.5px] text-text">answers on</span>
          <PortChips payload={view.ports} />
        </span>
      );
    }
  }
  if (f.field === 'services_offered') {
    // The builder's rich entry list keeps its per-port counts; the dict
    // family ({ports: [...]}) flattens to plain port chips.
    if (Array.isArray(f.value_json)) return <PortChips payload={f.value_json} />;
    const view = portsView(f.value_json);
    if (view) return <PortChips payload={view.ports} />;
  }
  if (f.field === 'is_static_addressed') {
    const v = (f.value ?? '').trim().toLowerCase();
    if (v === 'yes') return <span className="text-[13px] text-text">static</span>;
    if (v === 'no') return <span className="text-[13px] text-text">DHCP</span>;
  }
  if (f.field === 'criticality' && f.value) {
    // The one value on the page whose whole job is to be seen first.
    return (
      <span
        title="How much this machine matters"
        className={cn(
          'inline-flex rounded-pill border px-2.5 py-[3px] font-mono text-[11.5px] font-semibold',
          criticalityAccent(f.value),
        )}
      >
        {f.value}
      </span>
    );
  }
  if (f.value != null && f.value.trim() !== '') {
    return <span className="break-words text-[13px] text-text">{f.value}</span>;
  }
  if (f.value_json != null) {
    return (
      <span className="break-words font-mono text-[12px] text-text-2">
        {JSON.stringify(f.value_json)}
      </span>
    );
  }
  return <span className="text-faint">—</span>;
}

// ---- the evidence drawer ----------------------------------------------------

/** Everything a reader gets when they ask "says who?": the evidence strings
 *  with their "(from …)" attribution, the rung, the stored confidence and
 *  strength, wall-clock stamps — and, under a declaration, the sweep's own
 *  suppressed reading plus the way out of the declaration. This is the ONE
 *  place the machinery vocabulary is allowed on this page. */
function WhyDrawer({
  f,
  canDeclare,
  busy,
  onRemove,
}: {
  f: DossierField;
  canDeclare: boolean;
  busy: boolean;
  onRemove: () => void;
}) {
  const sources = Object.entries(f.evidence ?? {});
  if (sources.length === 0 && !f.overridden) return null;

  const sweeps =
    f.inferred_value ??
    (f.inferred_value_json != null ? JSON.stringify(f.inferred_value_json) : null);

  return (
    <details className="mt-1.5">
      <summary className="cursor-pointer select-none text-[11.5px] text-faint hover:text-dim">
        Why?{sources.length > 0 ? ` · ${sources.length} source${sources.length === 1 ? '' : 's'}` : ''}
      </summary>
      <div className="mt-2 flex flex-col gap-2.5 rounded-card border border-border bg-surface-2 px-3 py-2.5">
        {f.overridden && (
          <div className="flex flex-col gap-1 text-[12px] text-dim">
            <div>
              Declared by{' '}
              <span className="font-semibold text-text-2">{f.operator_actor ?? 'an operator'}</span>
              {f.operator_set_at ? (
                <span className="text-faint"> · {absTime(f.operator_set_at)}</span>
              ) : null}
            </div>
            <div>
              The sweep's own reading:{' '}
              {sweeps != null ? (
                <>
                  <span className="text-text-2">{sweeps}</span>
                  <span className="text-faint">
                    {f.inferred_confidence != null ? ` · ${f.inferred_confidence.toFixed(2)}` : ''}
                    {f.inferred_source ? ` · ${f.inferred_source}` : ''}
                  </span>
                </>
              ) : (
                <span className="text-faint">nothing — it does not work this field out</span>
              )}
            </div>
          </div>
        )}

        {sources.map(([source, raw]) => {
          const entry =
            raw && typeof raw === 'object'
              ? (raw as Record<string, unknown>)
              : ({} as Record<string, unknown>);
          const strings = Array.isArray(entry.strings) ? (entry.strings as unknown[]) : [];
          const conf = typeof entry.confidence === 'number' ? entry.confidence.toFixed(2) : null;
          return (
            <div key={source}>
              <div className="mb-1 flex flex-wrap items-center gap-2">
                <Chip>{source}</Chip>
                {entry.value != null && (
                  <span className="text-[12px] text-text-2">{String(entry.value)}</span>
                )}
                {typeof entry.strength === 'string' && (
                  <span className="text-[11px] text-faint">{entry.strength}</span>
                )}
                {conf && <span className="font-mono text-[11px] text-faint">{conf}</span>}
                {typeof entry.last_seen === 'string' && (
                  <span className="font-mono text-[11px] text-faint">{absTime(entry.last_seen)}</span>
                )}
              </div>
              {strings.length > 0 && (
                <ul className="ml-1 flex flex-col gap-0.5">
                  {strings.map((line, i) => (
                    <li key={i} className="text-[12px] leading-[1.5] text-dim">
                      · {String(line)}
                    </li>
                  ))}
                </ul>
              )}
              {typeof entry.conflict === 'string' && (
                <div className="mt-1 text-[12px] text-warn">sources disagree: {entry.conflict}</div>
              )}
            </div>
          );
        })}

        {(f.observed_at || f.last_run_at) && (
          <div className="flex flex-wrap gap-x-4 gap-y-0.5 font-mono text-[11px] text-faint">
            {f.observed_at && <span>evidence {absTime(f.observed_at)}</span>}
            {f.last_run_at && <span>checked {absTime(f.last_run_at)}</span>}
          </div>
        )}

        {/* Raw payload for the structured fields — source code belongs behind
            the disclosure, not on the page (F8). */}
        {isJsonField(f.field) && f.value_json != null && (
          <pre className="max-w-full overflow-x-auto whitespace-pre-wrap break-all font-mono text-[10.5px] leading-[1.5] text-faint">
            {JSON.stringify(f.value_json)}
          </pre>
        )}

        {/* The way OUT of a declaration, labelled with its consequence. The old
            "Hand back to the builder" offered, on fields the sweep never works
            out, to trade a value for nothing — without saying so (F5). An open
            disagreement moves this decision to the why-care strip instead. */}
        {canDeclare && f.overridden && !f.conflict && (
          <div>
            <button
              disabled={busy}
              onClick={onRemove}
              className="rounded-control border border-border-strong bg-surface-3 px-2.5 py-1 text-[11.5px] text-dim hover:text-text disabled:opacity-60"
            >
              {sweeps != null
                ? `Remove my declaration — the sweep's answer (${sweeps}) will stand`
                : 'Remove my declaration — this goes back to unknown'}
            </button>
          </div>
        )}
      </div>
    </details>
  );
}

// ---- one fact row -----------------------------------------------------------

export interface FactRowProps {
  ip: string;
  f: DossierField;
  canDeclare: boolean;
  highlight: boolean;
  onApplied: (next: Dossier) => void;
  /** 'strip' renders the value with why-care weight (the briefing card);
   *  'row' is the compact what-we-know line. Same machinery either way. */
  variant?: 'row' | 'strip';
  /** Passed to the declare editor's role datalist; see DeclareEditorProps. */
  roleVocabulary?: readonly string[];
}

export function FactRow({
  ip,
  f,
  canDeclare,
  highlight,
  onApplied,
  variant = 'row',
  roleVocabulary,
}: FactRowProps) {
  const { busy, err, setErr, run } = useDossierWrite(onApplied);
  const [editing, setEditing] = useState(false);
  const label = fieldLabel(f.field);
  const phrase = provenancePhrase(f);
  // Freshness: when it was last confirmed for an inferred fact, when it was
  // said for a declared one. Relative either way; the wall clock rides in the
  // hover and the drawer.
  const freshness = f.overridden
    ? f.operator_set_at
      ? relativeAge(f.operator_set_at)
      : null
    : f.observed_at
      ? `confirmed ${relativeAge(f.observed_at)}`
      : null;

  const meta = [phrase, freshness].filter(Boolean).join(' · ');

  return (
    <div
      data-testid={`field-${f.field}`}
      data-field={f.field}
      data-highlight={highlight ? 'true' : 'false'}
      id={`field-${f.field}`}
      className={cn(
        variant === 'row' && 'border-b border-border-faint px-4 py-2.5 last:border-0',
        variant === 'strip' && 'px-4 py-2.5',
        highlight && 'border-l-2 border-l-accent bg-accent/[0.04]',
      )}
    >
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <span className="w-[130px] flex-none text-[10.5px] font-semibold uppercase tracking-[.05em] text-faint">
          {label}
        </span>
        <div className={cn('min-w-0', variant === 'strip' ? 'flex-1 basis-[280px]' : 'flex-1')}>
          <FactValue f={f} />
        </div>
        {meta && (
          <span className="flex-none text-[11.5px] text-faint" title={f.observed_at ? absTime(f.observed_at) : undefined}>
            {meta}
          </span>
        )}
        {canDeclare && !editing && (
          <button
            onClick={() => {
              setErr(null);
              setEditing(true);
            }}
            aria-label={`Edit ${label}`}
            className="flex flex-none items-center gap-1 rounded-control border border-border-strong bg-surface-3 px-2 py-0.5 text-[11px] font-semibold text-dim hover:border-accent hover:text-text"
          >
            <Pencil size={10} />
            Edit
          </button>
        )}
      </div>

      {/* The note travels with the fact, verbatim — it is usually the whole
          reason the declaration exists. */}
      {f.overridden && f.operator_note && f.field !== 'policy_notes' && (
        <div className="mt-1 text-[12px] italic leading-[1.5] text-dim">"{f.operator_note}"</div>
      )}

      <WhyDrawer
        f={f}
        canDeclare={canDeclare}
        busy={busy}
        onRemove={() => run(() => clearDossierOverride(ip, f.field))}
      />

      {editing && (
        <DeclareEditor
          f={f}
          busy={busy}
          roleVocabulary={roleVocabulary}
          onInvalid={setErr}
          onCancel={() => {
            setEditing(false);
            setErr(null);
          }}
          onSave={(body) => run(() => setDossierOverride(ip, body), () => setEditing(false))}
        />
      )}

      {err && (
        <div className="mt-2 rounded-control border border-danger/35 bg-danger/[0.07] px-3 py-2 text-[12px] text-danger">
          {err}
        </div>
      )}
    </div>
  );
}

// ---- the known panel --------------------------------------------------------

export interface HostFactsProps {
  dossier: Dossier;
  canDeclare: boolean;
  onApplied: (next: Dossier) => void;
  focusField: string | null;
  /** The classifier's role vocabulary from the summary wire, threaded down to
   *  the declare editor's datalist. Omitted, the editor falls back to the
   *  frontend's ROLE_VOCABULARY. */
  roleVocabulary?: readonly string[];
}

export function HostFacts({
  dossier,
  canDeclare,
  onApplied,
  focusField,
  roleVocabulary,
}: HostFactsProps) {
  const { known } = partitionFields(dossier.fields);
  const rows = known.filter((f) => !BRIEFING_FIELDS.has(f.field));
  return (
    <div data-testid="host-facts" className="mb-3">
      <Panel>
        <PanelHeader
          icon={<ListChecks size={15} />}
          title="What we know"
          right={
            <span className="font-mono text-[11px] text-faint">
              {known.length} of {dossier.fields.length} facts
            </span>
          }
        />
        {rows.length === 0 ? (
          <div className="px-4 py-4 text-[12.5px] text-faint">
            Nothing confirmed about this machine yet.
          </div>
        ) : (
          rows.map((f) => (
            <FactRow
              key={f.field}
              ip={dossier.ip}
              f={f}
              canDeclare={canDeclare}
              highlight={focusField === f.field}
              onApplied={onApplied}
              roleVocabulary={roleVocabulary}
            />
          ))
        )}
      </Panel>
    </div>
  );
}

// ---- the unknown line -------------------------------------------------------

/** One unknown field: what it would be called, why there is no answer, and a
 *  declare control for the operator who knows. */
function UnknownEntry({
  ip,
  f,
  canDeclare,
  highlight,
  onApplied,
  roleVocabulary,
}: {
  ip: string;
  f: DossierField;
  canDeclare: boolean;
  highlight: boolean;
  onApplied: (next: Dossier) => void;
  roleVocabulary?: readonly string[];
}) {
  const { busy, err, setErr, run } = useDossierWrite(onApplied);
  const [editing, setEditing] = useState(false);
  return (
    <div
      data-testid={`field-${f.field}`}
      data-field={f.field}
      data-highlight={highlight ? 'true' : 'false'}
      id={`field-${f.field}`}
      className={cn(
        'border-b border-border-faint px-4 py-2 last:border-0',
        highlight && 'border-l-2 border-l-accent bg-accent/[0.04]',
      )}
    >
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <span className="w-[130px] flex-none text-[10.5px] font-semibold uppercase tracking-[.05em] text-faint">
          {fieldLabel(f.field)}
        </span>
        <span className="min-w-0 flex-1 text-[12px] text-dim">{unresolvedPhrase(f)}</span>
        {canDeclare && !editing && (
          <button
            onClick={() => {
              setErr(null);
              setEditing(true);
            }}
            className="flex flex-none items-center gap-1 rounded-control border border-border-strong bg-surface-3 px-2 py-0.5 text-[11px] font-semibold text-dim hover:border-accent hover:text-text"
          >
            <Pencil size={10} />
            Declare a value
          </button>
        )}
      </div>
      {editing && (
        <DeclareEditor
          f={f}
          busy={busy}
          roleVocabulary={roleVocabulary}
          onInvalid={setErr}
          onCancel={() => {
            setEditing(false);
            setErr(null);
          }}
          onSave={(body) => run(() => setDossierOverride(ip, body), () => setEditing(false))}
        />
      )}
      {err && (
        <div className="mt-2 rounded-control border border-danger/35 bg-danger/[0.07] px-3 py-2 text-[12px] text-danger">
          {err}
        </div>
      )}
    </div>
  );
}

export function HostUnknowns({
  dossier,
  canDeclare,
  onApplied,
  focusField,
  roleVocabulary,
}: HostFactsProps) {
  const { unknown } = partitionFields(dossier.fields);
  const names = unknown.map((f) => f.field).join(',');

  // Collapsed by default: these are the gaps, not the content. A deep link
  // (?field=) that targets a gap opens the line so the link lands somewhere.
  const [open, setOpen] = useState(false);
  useEffect(() => {
    if (focusField && names.split(',').indexOf(focusField) >= 0) setOpen(true);
  }, [focusField, names]);

  if (unknown.length === 0) return null;

  const labels = unknown.map((f) => fieldLabel(f.field));
  const shown = labels.slice(0, 3).join(', ');
  const rest = labels.length - 3;

  return (
    <div data-testid="host-unknowns" className="mb-3">
      <details open={open} className="rounded-panel border border-border bg-surface-1">
        {/* Explicit toggle: jsdom does not run the native summary behaviour,
            and the entries below only render when open — so the state, not the
            platform, is the source of truth. */}
        <summary
          onClick={(e) => {
            e.preventDefault();
            setOpen((v) => !v);
          }}
          className="cursor-pointer select-none px-4 py-2.5 text-[12.5px] text-dim hover:text-text"
        >
          Unknown: {shown}
          {rest > 0 ? `, +${rest} more` : ''}
        </summary>
        {open && (
          <div className="border-t border-border">
            {unknown.map((f) => (
              <UnknownEntry
                key={f.field}
                ip={dossier.ip}
                f={f}
                canDeclare={canDeclare}
                highlight={focusField === f.field}
                onApplied={onApplied}
                roleVocabulary={roleVocabulary}
              />
            ))}
          </div>
        )}
      </details>
    </div>
  );
}
