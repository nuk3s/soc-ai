import { useEffect, useId, useState } from 'react';
import { AlertTriangle, Briefcase, Crosshair, ExternalLink, Server, X } from 'lucide-react';
import {
  getCampaign,
  getCampaignCaseScope,
  openCampaignCase,
  type CampaignCaseScope,
  type CampaignDetail,
  type CampaignParty,
} from '../../lib/api';
import {
  CASE_ALERTS_RULE,
  CASE_HELD_HEADING,
  CASE_INTRO,
  CASE_LINK,
  CASE_NOTE_TAIL,
  CASE_OPEN_FAILED,
  CASE_READING,
  CASE_SKIPPED_HEADING,
  CASE_SUBMIT_EXISTING,
  CASE_TITLE,
  lastActivityOf,
  caseAlertsSentence,
  caseCappedSentence,
  caseExistingSentence,
  caseSkippedLines,
  caseTitleWords,
  caseWritesLines,
  partyName,
  stageMeterWords,
} from '../../lib/campaignWords';
import { stageColor } from '../../lib/campaignViz';
import { demoBlocked, useDemo } from '../../lib/demo';

import { Spinner } from '../States';
import { MachinesPicture } from './MachinesPicture';
import { StageMeter } from './StageMeter';
import { UtcTime } from '../UtcTime';

const LABEL = 'mb-1 block text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint';
const BOX = 'rounded-[7px] border px-3 py-2.5 text-[12.5px] leading-[1.5]';

/** The scope of a failed read: an unknown count, never a zero. */
function unread(title: string): CampaignCaseScope {
  return {
    title: caseTitleWords(title),
    alerts: null,
    capped: false,
    skipped: { acknowledged: 0, escalated: 0, noAlert: 0 },
    existing: null,
  };
}

/**
 * The dialog "Open one case" of a campaign. The analyst sees the case as
 * Security Onion holds it before the press, in one box: the title, the bottom
 * line and the period, then the picture of the stage meter and the machines,
 * then the numbers of the alerts that go on the case and of the alerts that
 * it skips, then the note. Under the box, in the warning tone, the dialog
 * states that the press writes to Security Onion and what it writes.
 *
 * The server counts the alerts before the press. A count that soc-ai cannot
 * read is no zero. A campaign that holds a case already names that case, and
 * the press opens no second one. A refusal of Security Onion keeps the
 * dialog open with the reason, and the page reads the campaign again.
 */
export function OpenCaseDialog({
  campaign,
  open,
  onClose,
  onOpened,
}: {
  campaign: Pick<CampaignDetail, 'id' | 'title' | 'bottomLine' | 'stage' | 'parties' | 'graph' | 'firstEvent' | 'lastEvent' | 'lastActivity'>;
  open: boolean;
  onClose: () => void;
  onOpened: (next: CampaignDetail) => void;
}) {
  const demo = useDemo();
  const titleId = useId();
  const noteId = useId();
  const [scope, setScope] = useState<CampaignCaseScope | null>(null);
  const [failedRead, setFailedRead] = useState(false);
  const [note, setNote] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // A fresh dialog and a fresh count for each open.
  useEffect(() => {
    if (!open) return;
    let alive = true;
    setScope(null);
    setFailedRead(false);
    setNote('');
    setError(null);
    getCampaignCaseScope(campaign.id)
      .then((answer) => {
        if (alive) setScope(answer);
      })
      .catch(() => {
        if (!alive) return;
        setScope(unread(campaign.title));
        setFailedRead(true);
      });
    return () => {
      alive = false;
    };
  }, [open, campaign.id, campaign.title]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;

  const existing = scope?.existing ?? null;
  const canSave = scope !== null && !saving;
  const parties = campaign.parties ?? [];
  const actors = parties.filter((p) => p.role === 'actor');
  const targets = parties.filter((p) => p.role !== 'actor' && !p.beyond);
  const further = parties.filter((p) => p.role !== 'actor' && p.beyond);
  const skipped = scope && !failedRead ? caseSkippedLines(scope.skipped) : [];

  const save = () => {
    if (!scope) return;
    const blocked = demoBlocked(demo);
    if (blocked) {
      setError(blocked);
      return;
    }
    setSaving(true);
    setError(null);
    openCampaignCase(campaign.id, { note: note.trim() })
      .then((next) => {
        onOpened(next);
        onClose();
      })
      .catch((err: unknown) => {
        setError(err instanceof Error && err.message ? err.message : CASE_OPEN_FAILED);
        // A refusal leaves a change on the campaign, and an unreadable
        // answer leaves an open request. The page reads the campaign again.
        getCampaign(campaign.id)
          .then(onOpened)
          .catch(() => {});
      })
      .finally(() => setSaving(false));
  };

  const row = (p: CampaignParty) => {
    const Icon = p.role === 'actor' ? Crosshair : Server;
    const name = partyName(p);
    const address = p.addresses[0] ?? null;
    return (
      <div
        data-testid="case-party"
        data-machine={p.machineKey}
        className="flex min-h-[40px] items-start gap-2 rounded-card border border-border-strong bg-surface-3 px-2.5 py-1.5"
      >
        <Icon size={14} aria-hidden className="mt-[2px] flex-none text-text-2" />
        <span className="min-w-0 flex-1">
          <span className="block break-words text-[12.5px] font-semibold leading-tight text-text">{name}</span>
          {address && address !== name && (
            <span className="mt-0.5 block break-words font-mono text-[10.5px] leading-tight text-faint">{address}</span>
          )}
        </span>
      </div>
    );
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
        data-testid="open-case-dialog"
        className="relative max-h-[calc(100vh-48px)] w-[720px] max-w-[calc(100vw-32px)] overflow-y-auto rounded-panel-lg border p-6"
        style={{ background: '#0e1117', borderColor: '#1c232e' }}
      >
        <button onClick={onClose} className="absolute right-4 top-4 text-ghost hover:text-text" aria-label="Close">
          <X size={16} />
        </button>
        <div id={titleId} className="mb-1 pr-6 text-[14px] font-semibold">
          {CASE_TITLE}
        </div>
        <p className="mb-4 break-words pr-6 text-[12.5px] leading-[1.5] text-dim">{CASE_INTRO}</p>

        <section
          data-testid="case-preview"
          aria-label={CASE_HELD_HEADING}
          className="mb-4 rounded-[9px] border border-border-strong bg-surface-2 px-4 py-3.5"
        >
          <div className="mb-2.5 flex items-center gap-1.5 text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint">
            <Briefcase size={12} aria-hidden className="flex-none" />
            {CASE_HELD_HEADING}
          </div>
          <div data-testid="case-title" className="break-words text-[14px] font-semibold leading-snug text-text">
            {scope?.title || caseTitleWords(campaign.title)}
          </div>
          {campaign.bottomLine && (
            <p data-testid="case-bottom-line" className="mt-1 break-words text-[13px] leading-[1.5] text-text-2">
              {campaign.bottomLine}
            </p>
          )}
          <div data-testid="case-period" className="mt-1 font-mono text-[11.5px] text-dim">
            <UtcTime iso={campaign.firstEvent} to={lastActivityOf(campaign)} seconds={false} />
          </div>

          <div
            data-testid="case-stage"
            className="mb-3 mt-3 flex flex-wrap items-center gap-x-2.5 gap-y-1 border-t border-border pt-3 text-[12.5px] text-text-2"
          >
            <StageMeter stage={campaign.stage} size="md" testId="case-stage-meter" />
            <span className="min-w-0 break-words">{stageMeterWords(campaign.stage)}</span>
          </div>
          {parties.length > 0 && (
            <MachinesPicture
              testId="case"
              actors={actors}
              targets={targets}
              further={further}
              lines={campaign.graph?.edges ?? []}
              row={row}
              color={(e) => stageColor(e.stage)}
            />
          )}

          {scope === null ? (
            <div className="mb-3 flex items-center gap-2 text-[12.5px] text-dim">
              <Spinner size={13} /> {CASE_READING}
            </div>
          ) : existing ? (
            <div data-testid="case-existing" className={`mb-3 border-border-strong bg-surface-3 ${BOX}`}>
              <span className="break-words font-semibold text-text">{caseExistingSentence(existing.id)}</span>
              {existing.url && (
                <a
                  href={existing.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="ml-2 inline-flex items-center gap-1 whitespace-nowrap font-semibold text-accent hover:underline"
                >
                  {CASE_LINK}
                  <ExternalLink size={12} aria-hidden />
                </a>
              )}
            </div>
          ) : (
            <div className={`mb-3 grid grid-cols-1 gap-2.5 ${skipped.length > 0 ? 'sm:grid-cols-2' : ''}`}>
              <div className={`border-border-strong bg-surface-3 ${BOX}`}>
                <div data-testid="case-alerts" className="break-words text-[13px] font-semibold text-text">
                  {caseAlertsSentence(scope.alerts)}
                </div>
                {scope.capped && typeof scope.alerts === 'number' && (
                  <div data-testid="case-capped" className="mt-0.5 break-words text-text-2">
                    {caseCappedSentence(scope.alerts)}
                  </div>
                )}
                <div className="mt-0.5 break-words text-dim">{CASE_ALERTS_RULE}</div>
              </div>
              {skipped.length > 0 && (
                <div data-testid="case-skipped" className={`border-border bg-transparent ${BOX}`}>
                  <div className={LABEL}>{CASE_SKIPPED_HEADING}</div>
                  {skipped.map((line) => (
                    <div key={line} className="break-words text-text-2">
                      {line}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          <div data-testid="case-note">
            <label htmlFor={noteId} className="mb-1.5 block text-[12px] font-semibold text-dim">
              Note
            </label>
            <textarea
              id={noteId}
              value={note}
              maxLength={2000}
              rows={2}
              onChange={(e) => setNote(e.target.value)}
              className="w-full rounded-control border border-border-input bg-bg px-3 py-2 text-[13px] text-text outline-none focus:border-accent"
            />
            <div className="mt-1 text-[11.5px] text-faint">{CASE_NOTE_TAIL}</div>
          </div>
        </section>

        <div className="mb-4 rounded-[7px] border border-warn/35 bg-warn/[.07] px-3 py-2.5 text-[12.5px] leading-[1.5] text-text-2">
          <div className="flex items-start gap-2">
            <AlertTriangle size={13} aria-hidden className="mt-[3px] flex-none text-warn" />
            <div data-testid="case-writes" className="min-w-0 break-words">
              {caseWritesLines(scope?.alerts ?? null, !!existing).map((line, i) => (
                <div key={line} className={i === 0 ? 'font-semibold text-text' : undefined}>
                  {line}
                </div>
              ))}
            </div>
          </div>
        </div>

        {error && (
          <div role="alert" className="mb-3 break-words text-[12.5px] text-danger">
            {error}
          </div>
        )}

        <div data-testid="case-actions" className="flex flex-wrap justify-end gap-2">
          <button
            onClick={onClose}
            className="rounded-control border border-border-strong bg-surface-3 px-4 py-2 text-[13px] font-semibold text-text-2 hover:text-text"
          >
            Cancel
          </button>
          <button
            disabled={!canSave}
            onClick={save}
            className="flex items-center gap-1.5 rounded-control border border-accent bg-[rgba(75,139,245,.14)] px-4 py-2 text-[13px] font-semibold text-accent hover:bg-[rgba(75,139,245,.22)] disabled:opacity-60"
          >
            {saving ? <Spinner size={13} /> : <Briefcase size={13} aria-hidden />}
            {existing ? CASE_SUBMIT_EXISTING : CASE_TITLE}
          </button>
        </div>
      </div>
    </div>
  );
}
