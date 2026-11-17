import { useEffect, useId, useState } from 'react';
import { AlertTriangle, Check, Crosshair, Server, ShieldCheck, X } from 'lucide-react';
import {
  ApiError,
  authorizeCampaign,
  getCampaignAuthorizeDraft,
  type CampaignAuthorizeDraft,
  type CampaignAuthorizeParty,
  type CampaignDetail,
} from '../../lib/api';
import {
  AUTHORIZE_ADMIN_ONLY,
  AUTHORIZE_DRAFT_FAILED,
  AUTHORIZE_FAILED,
  AUTHORIZE_LABEL_REQUIRED,
  AUTHORIZE_LATER,
  AUTHORIZE_LISTED,
  AUTHORIZE_LOUD_TAIL,
  AUTHORIZE_NEEDS_BOTH,
  AUTHORIZE_NOT_LISTED,
  AUTHORIZE_QUIET_TAIL,
  AUTHORIZE_READING,
  AUTHORIZE_TITLE,
  AUTHORIZE_WRITES,
  COUNTS_ALL_LISTED,
  NOTE_OPTIONAL,
  authorizationPeriodSentence,
  earlierRecordSentence,
  expiryLimitSentence,
  insideSentence,
  outsideSentence,
  partyName,
  unlistedSentence,
} from '../../lib/campaignWords';
import { demoBlocked, useDemo } from '../../lib/demo';
import { Spinner } from '../States';
import { MachinesPicture } from './MachinesPicture';

const LABEL = 'mb-1.5 block text-[12px] font-semibold text-dim';
const FIELD =
  'w-full rounded-control border border-border-input bg-bg px-3 py-2 text-[13px] text-text outline-none focus:border-accent';
const LISTED_INK = 'rgb(var(--text-2))';
const LOUD_INK = 'rgb(var(--danger))';

/** The UTC day of an ISO time, as the date field holds it. */
function dayOf(iso: string): string {
  const t = new Date(iso);
  return Number.isNaN(t.getTime()) ? '' : t.toISOString().slice(0, 10);
}

/** The time of day of an ISO time in UTC, with the seconds. */
function timeOf(iso: string): string {
  const t = new Date(iso);
  return Number.isNaN(t.getTime()) ? '00:00:00' : t.toISOString().slice(11, 19);
}

/** The expiry that the press sends: the picked day at the time of day of the
 *  default, never later than the maximum. Null for no valid day. */
export function expiryFor(day: string, draft: Pick<CampaignAuthorizeDraft, 'expiresAt' | 'maxExpiresAt'>): string | null {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) return null;
  const t = Date.parse(`${day}T${timeOf(draft.expiresAt)}Z`);
  if (Number.isNaN(t)) return null;
  const max = Date.parse(draft.maxExpiresAt);
  return new Date(Number.isNaN(max) ? t : Math.min(t, max)).toISOString();
}

function errorText(err: unknown): string {
  if (err instanceof ApiError && (err.reason === 'admin_required' || err.status === 403)) return AUTHORIZE_ADMIN_ONLY;
  return err instanceof Error && err.message ? err.message : AUTHORIZE_FAILED;
}

/**
 * The dialog "Record authorized activity" of a campaign. The admin sees the
 * whole activity and decides once. The dialog leads with the machines as a
 * small picture: the actors on the left, the targets on the right, a line for
 * each attack between them. Each machine is a check box, listed by default.
 * A line between two listed machines is inside. A line with an unlisted end
 * is dashed in the danger tone: it stays loud.
 *
 * Then the numbers: the investigations inside, those of them that wait today,
 * and those outside, side by side in two boxes of one size. The server counts
 * the scope with every machine listed. When the admin unlists a machine, the
 * dialog says so and counts the investigations with an unlisted end.
 *
 * Then the form: the label, the note and the expiry, and what the press writes.
 */
export function AuthorizeCampaignDialog({
  campaign,
  open,
  onClose,
  onAuthorized,
}: {
  campaign: Pick<CampaignDetail, 'id' | 'title' | 'members' | 'graph' | 'parties'>;
  open: boolean;
  onClose: () => void;
  onAuthorized: (next: CampaignDetail) => void;
}) {
  const demo = useDemo();
  const titleId = useId();
  const labelId = useId();
  const noteId = useId();
  const expiryId = useId();
  const [draft, setDraft] = useState<CampaignAuthorizeDraft | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [listed, setListed] = useState<Set<string>>(new Set());
  const [label, setLabel] = useState('');
  const [note, setNote] = useState('');
  const [day, setDay] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // A fresh dialog and a fresh draft for each open.
  useEffect(() => {
    if (!open) return;
    let alive = true;
    setDraft(null);
    setLoadError(null);
    setError(null);
    setNote('');
    getCampaignAuthorizeDraft(campaign.id)
      .then((answer) => {
        if (!alive) return;
        setDraft(answer);
        setListed(new Set(answer.parties.filter((p) => p.listed).map((p) => p.machineKey)));
        setLabel(answer.label ?? '');
        setDay(dayOf(answer.expiresAt));
      })
      .catch((err: unknown) => {
        if (!alive) return;
        setLoadError(err instanceof ApiError && err.status === 403 ? AUTHORIZE_ADMIN_ONLY : AUTHORIZE_DRAFT_FAILED);
      });
    return () => {
      alive = false;
    };
  }, [open, campaign.id]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;

  const parties = draft?.parties ?? [];
  const actors = parties.filter((p) => p.role === 'actor');
  const targets = parties.filter((p) => p.role !== 'actor');
  // The targets that only a target acted on take a third column, as on the attack graph.
  const furtherKeys = new Set((campaign.parties ?? []).filter((p) => p.role === 'target' && p.beyond).map((p) => p.machineKey));
  const unlisted = new Set(parties.filter((p) => !listed.has(p.machineKey)).map((p) => p.machineKey));
  const hasBoth = actors.some((p) => listed.has(p.machineKey)) && targets.some((p) => listed.has(p.machineKey));
  const expiresAt = draft ? expiryFor(day, draft) : null;
  const expiryInFuture = expiresAt !== null && Date.parse(expiresAt) > Date.now();
  const canSave = !!draft && hasBoth && label.trim().length > 0 && expiryInFuture && !saving;
  // The investigations of the campaign that an unlisted machine is an end of.
  const touched = campaign.members.filter(
    (m) => !m.verdictDiffers && ((m.sourceKey && unlisted.has(m.sourceKey)) || (m.targetKey && unlisted.has(m.targetKey))),
  ).length;

  const toggle = (key: string) =>
    setListed((have) => {
      const next = new Set(have);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  const save = () => {
    if (!draft || !expiresAt) return;
    if (!label.trim()) {
      setError(AUTHORIZE_LABEL_REQUIRED);
      return;
    }
    const blocked = demoBlocked(demo);
    if (blocked) {
      setError(blocked);
      return;
    }
    setSaving(true);
    setError(null);
    authorizeCampaign(campaign.id, {
      label: label.trim(),
      note: note.trim(),
      expiresAt,
      machineKeys: parties.filter((p) => listed.has(p.machineKey)).map((p) => p.machineKey),
    })
      .then((next) => {
        onAuthorized(next);
        onClose();
      })
      .catch((err: unknown) => setError(errorText(err)))
      .finally(() => setSaving(false));
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center"
      style={{ background: 'rgba(0,0,0,.65)' }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        data-testid="authorize-campaign-dialog"
        className="relative max-h-[calc(100vh-48px)] w-[760px] max-w-[calc(100vw-32px)] overflow-y-auto rounded-panel-lg border p-6"
        style={{ background: '#0e1117', borderColor: '#1c232e' }}
      >
        <button onClick={onClose} className="absolute right-4 top-4 text-ghost hover:text-text" aria-label="Close">
          <X size={16} />
        </button>
        <div id={titleId} className="mb-1 pr-6 text-[14px] font-semibold">
          {AUTHORIZE_TITLE}
        </div>
        <p className="mb-4 break-words pr-6 text-[12.5px] leading-[1.5] text-dim">{campaign.title}</p>

        {loadError && (
          <div role="alert" className="mb-3 break-words text-[12.5px] text-danger">
            {loadError}
          </div>
        )}
        {!draft && !loadError && (
          <div className="mb-4 flex items-center gap-2 text-[12.5px] text-dim">
            <Spinner size={13} /> {AUTHORIZE_READING}
          </div>
        )}

        {draft && (
          <>
            <ScopePicture
              actors={actors}
              targets={targets.filter((p) => !furtherKeys.has(p.machineKey))}
              further={targets.filter((p) => furtherKeys.has(p.machineKey))}
              listed={listed}
              edges={campaign.graph?.edges ?? []}
              onToggle={toggle}
            />
            {!hasBoth && (
              <div data-testid="authorize-needs-both" role="note" className="mb-3 text-[12.5px] text-warn">
                {AUTHORIZE_NEEDS_BOTH}
              </div>
            )}

            <p data-testid="authorize-period" className="mb-3 break-words text-[12.5px] leading-[1.5] text-text-2">
              {authorizationPeriodSentence(draft.startsAt, expiresAt ?? draft.expiresAt)}
            </p>

            {unlisted.size > 0 && (
              <p data-testid="authorize-counts-scope" className="mb-1.5 text-[12px] text-dim">
                {COUNTS_ALL_LISTED}
              </p>
            )}
            <div className="mb-3 grid grid-cols-1 gap-2.5 sm:grid-cols-2">
              <div
                data-testid="authorize-inside"
                className="rounded-[7px] border border-border-strong bg-surface-2 px-3 py-2.5 text-[12.5px] leading-[1.5]"
              >
                <div className="flex items-start gap-2">
                  <ShieldCheck size={14} aria-hidden className="mt-[2px] flex-none text-text-2" />
                  <div className="min-w-0 break-words">
                    <div className="text-[13px] font-semibold text-text">{insideSentence(draft.inside, draft.waiting)}</div>
                    <div className="mt-0.5 text-dim">{AUTHORIZE_QUIET_TAIL}</div>
                  </div>
                </div>
              </div>
              <div
                data-testid="authorize-outside"
                className="rounded-[7px] border border-danger/45 bg-danger/[.07] px-3 py-2.5 text-[12.5px] leading-[1.5]"
              >
                <div className="flex items-start gap-2">
                  <AlertTriangle size={14} aria-hidden className="mt-[2px] flex-none text-danger" />
                  <div className="min-w-0 break-words">
                    <div className="text-[13px] font-semibold text-text">{outsideSentence(draft.outside)}</div>
                    <div className="mt-0.5 text-dim">{AUTHORIZE_LOUD_TAIL}</div>
                  </div>
                </div>
              </div>
            </div>
            {unlisted.size > 0 && (
              <p data-testid="authorize-unlisted" className="mb-3 break-words text-[12.5px] font-semibold text-danger">
                {unlistedSentence(touched)}
              </p>
            )}
            <p className="mb-4 break-words text-[12px] leading-[1.5] text-dim">{AUTHORIZE_LATER}</p>

            {draft.earlier && (
              <p
                data-testid="authorize-earlier"
                className="mb-4 break-words rounded-[7px] border border-border px-3 py-2 text-[12.5px] leading-[1.5] text-text-2"
              >
                {earlierRecordSentence(draft.earlier)}
              </p>
            )}

            <div className="mb-3">
              <label htmlFor={labelId} className={LABEL}>
                Label
              </label>
              <input
                id={labelId}
                value={label}
                maxLength={120}
                onChange={(e) => setLabel(e.target.value)}
                placeholder="Example: red team test"
                className={FIELD}
              />
            </div>
            <div className="mb-3">
              <label htmlFor={noteId} className={LABEL}>
                Note
              </label>
              <textarea
                id={noteId}
                value={note}
                maxLength={2000}
                rows={2}
                onChange={(e) => setNote(e.target.value)}
                className={FIELD}
              />
              <div className="mt-1 text-[11.5px] text-faint">{NOTE_OPTIONAL}</div>
            </div>
            <div className="mb-4">
              <label htmlFor={expiryId} className={LABEL}>
                Expiry
              </label>
              <input
                id={expiryId}
                type="date"
                value={day}
                min={dayOf(new Date().toISOString())}
                max={dayOf(draft.maxExpiresAt)}
                onChange={(e) => setDay(e.target.value)}
                className={`${FIELD} max-w-[13rem]`}
              />
              <div data-testid="authorize-expiry-limit" className="mt-1 text-[11.5px] text-faint">
                {expiryLimitSentence(draft.maxExpiresAt)}
              </div>
            </div>

            <div className="mb-4 rounded-[7px] border border-warn/35 bg-warn/[.07] px-3 py-2.5 text-[12.5px] leading-[1.5] text-text-2">
              <div className="flex items-start gap-2">
                <AlertTriangle size={13} aria-hidden className="mt-[3px] flex-none text-warn" />
                <div data-testid="authorize-writes" className="min-w-0 break-words">
                  {AUTHORIZE_WRITES.map((line) => (
                    <div key={line}>{line}</div>
                  ))}
                </div>
              </div>
            </div>
          </>
        )}

        {error && (
          <div role="alert" className="mb-3 break-words text-[12.5px] text-danger">
            {error}
          </div>
        )}

        <div className="flex flex-wrap justify-end gap-2">
          <button
            onClick={onClose}
            className="rounded-control border border-border-strong bg-surface-3 px-4 py-2 text-[13px] font-semibold text-text-2 hover:text-text"
          >
            Cancel
          </button>
          {draft && (
            <button
              disabled={!canSave}
              onClick={save}
              className="flex items-center gap-1.5 rounded-control border border-accent bg-[rgba(75,139,245,.14)] px-4 py-2 text-[13px] font-semibold text-accent hover:bg-[rgba(75,139,245,.22)] disabled:opacity-60"
            >
              {saving ? <Spinner size={13} /> : <Check size={13} />}
              {AUTHORIZE_TITLE}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

/** The machines of the draft as the attack graph draws them, each one a
 *  check box. A line between two listed machines is inside. A line with an
 *  unlisted end is dashed in the danger tone: it stays loud. */
function ScopePicture({
  actors,
  targets,
  further,
  listed,
  edges,
  onToggle,
}: {
  actors: CampaignAuthorizeParty[];
  targets: CampaignAuthorizeParty[];
  further: CampaignAuthorizeParty[];
  listed: Set<string>;
  edges: readonly { source: string; target: string }[];
  onToggle: (key: string) => void;
}) {
  const row = (p: CampaignAuthorizeParty) => {
    const on = listed.has(p.machineKey);
    const Icon = p.role === 'actor' ? Crosshair : Server;
    const name = partyName(p);
    return (
      <label
        data-testid="authorize-party"
        data-listed={on}
        className={`flex min-h-[46px] cursor-pointer items-start gap-2 rounded-card border px-2.5 py-2 ${
          on ? 'border-border-strong bg-surface-2' : 'border-dashed border-danger/45 bg-transparent'
        }`}
      >
        <input type="checkbox" className="mt-[3px] flex-none" checked={on} onChange={() => onToggle(p.machineKey)} />
        <Icon size={14} aria-hidden className={`mt-[2px] flex-none ${on ? 'text-text-2' : 'text-dim'}`} />
        <span className="min-w-0 flex-1">
          <span className={`block break-words text-[12.5px] font-semibold leading-tight ${on ? 'text-text' : 'text-dim'}`}>
            {name}
          </span>
          {p.address && p.address !== name && (
            <span className="mt-0.5 block break-words font-mono text-[10.5px] leading-tight text-faint">{p.address}</span>
          )}
          <span className={`mt-0.5 block break-words text-[11px] leading-tight ${on ? 'text-dim' : 'text-danger'}`}>
            {on ? AUTHORIZE_LISTED : AUTHORIZE_NOT_LISTED}
          </span>
        </span>
        {on && <ShieldCheck size={14} aria-hidden className="mt-[2px] flex-none text-text-2" />}
      </label>
    );
  };

  return (
    <MachinesPicture
      testId="authorize"
      actors={actors}
      targets={targets}
      further={further}
      lines={edges}
      row={row}
      inside={(e) => listed.has(e.source) && listed.has(e.target)}
      legend={
        <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-dim">
          <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
            <span aria-hidden className="h-0 w-4 border-t-2" style={{ borderColor: LISTED_INK }} />
            Both machines listed: inside
          </span>
          <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
            <span aria-hidden className="h-0 w-4 border-t-2 border-dashed" style={{ borderColor: LOUD_INK }} />
            A machine not listed: outside, stays loud
          </span>
        </div>
      }
    />
  );
}
