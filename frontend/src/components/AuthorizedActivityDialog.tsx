import { useEffect, useRef, useState } from 'react';
import { ArrowUpRight, Check, X } from 'lucide-react';
import { Link } from 'react-router-dom';

import {
  ApiError,
  createAuthorizedActivity,
  getAuthorizedDraft,
  type AuthorizedActivity,
  type AuthorizedDraft,
  type InvestigationCampaign,
} from '../lib/api';
import { isActiveCampaign } from '../lib/campaignDecision';
import { ON_CAMPAIGN_ACTION, onCampaignWords } from '../lib/campaignWords';
import {
  SOURCE_ADDRESS_NOTE,
  machineWords,
  ruleClassWords,
  targetWords,
} from '../lib/authorizedActivity';
import { demoBlocked, useDemo } from '../lib/demo';
import { plural } from '../lib/plural';
import { DEFINE_AUTHORIZED_ACTIVITY } from '../lib/tooltips';
import { useSession } from '../shell/Session';
import { Spinner } from './States';

// ---------------------------------------------------------------------------
// The dialog that records authorized activity from one true positive run.
//
// The server decides what the run allows: the target address, and the source
// addresses and the rule names the dialog may offer. The dialog can only
// select among them. What it lists is exactly what can match: a scope holds
// exact addresses and exact rule names, and no prefix or pattern.
//
// The dialog says why the server left a source address out, that a target
// with no agent follows its address, and how many earlier runs the chosen
// scope matches. The earlier runs stay off until the analyst selects them.
//
// An investigation of a campaign records no authorization here. The dialog
// sends the admin to the campaign, where one authorization lists the machines
// and covers the alert and the finding investigations of the whole activity.
// ---------------------------------------------------------------------------

interface Props {
  invId: string;
  open: boolean;
  onClose: () => void;
  onSaved: (record: AuthorizedActivity) => void;
  /** The campaign of the investigation, or null. An earlier server sends none. */
  campaign?: InvestigationCampaign | null;
}

const FIELD =
  'w-full rounded-control border border-border-input bg-bg px-3 py-2 text-[13px] text-text outline-none focus:border-accent';
const LABEL = 'mb-1.5 block text-[12px] font-semibold text-dim';

function errorText(err: unknown, fallback: string): string {
  return err instanceof Error && err.message ? err.message : fallback;
}

function toggled(have: string[], value: string): string[] {
  return have.includes(value) ? have.filter((v) => v !== value) : [...have, value];
}

export function AuthorizedActivityDialog({ invId, open, onClose, onSaved, campaign = null }: Props) {
  // An investigation of an active campaign, with the verdict of the campaign.
  const onCampaign = !!campaign && isActiveCampaign(campaign.status) && !campaign.differs;
  const demo = useDemo();
  const { me } = useSession();
  const [draft, setDraft] = useState<AuthorizedDraft | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [label, setLabel] = useState('');
  const [note, setNote] = useState('');
  // The offered sources and rules the analyst added. The source and the rule
  // of the run are always in the scope, so they are not in these lists.
  const [addedSources, setAddedSources] = useState<string[]>([]);
  const [addedRules, setAddedRules] = useState<string[]>([]);
  const [days, setDays] = useState<number | null>(null);
  const [applyEarlier, setApplyEarlier] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const labelRef = useRef<HTMLInputElement | null>(null);

  // A fresh dialog for each open.
  useEffect(() => {
    if (!open) return;
    setDraft(null);
    setLoadError(null);
    setLabel('');
    setNote('');
    setAddedSources([]);
    setAddedRules([]);
    setDays(null);
    setApplyEarlier(false);
    setSaveError(null);
  }, [open, invId]);

  // The draft, read again when the chosen rules or sources change. The answer
  // counts the earlier runs of that scope.
  const sourceKey = addedSources.join('\n');
  const ruleKey = addedRules.join('\n');
  useEffect(() => {
    if (!open || onCampaign) return;
    let alive = true;
    getAuthorizedDraft(invId, {
      rules: ruleKey ? ruleKey.split('\n') : [],
      sources: sourceKey ? sourceKey.split('\n') : [],
    })
      .then((answer) => {
        if (!alive) return;
        setDraft(answer);
        setLoadError(null);
        setDays((value) => value ?? answer.default_days);
      })
      .catch((err: unknown) => {
        if (alive) setLoadError(errorText(err, 'soc-ai could not read what this investigation allows.'));
      });
    return () => {
      alive = false;
    };
  }, [open, invId, ruleKey, sourceKey, onCampaign]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  // Focus the label once, when the form first shows.
  const formShown = open && !!draft?.allowed;
  useEffect(() => {
    if (formShown) labelRef.current?.focus();
  }, [formShown]);

  if (!open) return null;

  const notAdmin = me != null && me.role !== 'admin';
  const earlier = draft?.earlier_runs ?? 0;
  const canSave = !!draft?.allowed && label.trim().length > 0 && !saving && days != null;

  const save = () => {
    if (!draft || days == null) return;
    const blocked = demoBlocked(demo);
    if (blocked) {
      setSaveError(blocked);
      return;
    }
    setSaving(true);
    setSaveError(null);
    createAuthorizedActivity({
      investigation_id: invId,
      label: label.trim(),
      note: note.trim() || null,
      sources: [
        ...draft.sources.filter((s) => s.of_this_run).map((s) => s.address),
        ...addedSources,
      ],
      rule_names: [...draft.rules.filter((r) => r.of_this_run).map((r) => r.name), ...addedRules],
      expires_in_days: days,
      apply_to_earlier: applyEarlier && earlier > 0,
    })
      .then((record) => {
        onSaved(record);
        onClose();
      })
      .catch((err: unknown) => {
        setSaveError(
          err instanceof ApiError && err.reason === 'admin_required'
            ? 'Only an admin can record authorized activity.'
            : errorText(err, 'soc-ai could not save the record. Try again.'),
        );
      })
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
        aria-labelledby="authorized-activity-title"
        data-testid="authorized-activity-dialog"
        className="relative max-h-[calc(100vh-48px)] w-[560px] max-w-[calc(100vw-32px)] overflow-y-auto rounded-panel-lg border p-6"
        style={{ background: '#0e1117', borderColor: '#1c232e' }}
      >
        <button
          onClick={onClose}
          className="absolute right-4 top-4 text-ghost hover:text-text"
          aria-label="Close"
        >
          <X size={16} />
        </button>
        <div id="authorized-activity-title" className="mb-2 text-[14px] font-semibold">
          Record authorized activity
        </div>
        <p className="mb-4 text-[12.5px] leading-[1.5] text-dim">{DEFINE_AUTHORIZED_ACTIVITY}</p>

        {onCampaign && campaign && (
          <div data-testid="authorized-on-campaign" className="mb-4 text-[13px] leading-[1.5] text-text-2">
            <p className="break-words">{onCampaignWords(campaign.title)}</p>
            <Link
              to={`/campaigns/${campaign.id}`}
              onClick={onClose}
              className="mt-3 inline-flex items-center gap-1.5 rounded-control border border-accent bg-[rgba(75,139,245,.14)] px-4 py-2 text-[13px] font-semibold text-accent hover:bg-[rgba(75,139,245,.22)]"
            >
              {ON_CAMPAIGN_ACTION}
              <ArrowUpRight size={13} aria-hidden />
            </Link>
          </div>
        )}

        {!onCampaign && loadError && (
          <div role="alert" className="mb-3 text-[12.5px] text-danger">
            {loadError}
          </div>
        )}
        {!onCampaign && !draft && !loadError && (
          <div className="flex items-center gap-2 text-[12.5px] text-dim">
            <Spinner size={13} /> Reading what this investigation allows
          </div>
        )}
        {draft && !draft.allowed && (
          <div data-testid="authorized-refusal" role="note" className="text-[13px] text-text-2">
            {draft.hint}
          </div>
        )}

        {draft?.allowed && draft.target && (
          <>
            <div className="mb-3">
              <label htmlFor="authorized-label" className={LABEL}>
                Label
              </label>
              <input
                id="authorized-label"
                ref={labelRef}
                value={label}
                maxLength={120}
                onChange={(e) => setLabel(e.target.value)}
                placeholder="Example: php2shell exploit test"
                className={FIELD}
              />
            </div>

            <fieldset data-testid="authorized-sources" className="mb-3">
              <legend className={LABEL}>Source addresses</legend>
              <p className="mb-1.5 text-[12px] text-dim">
                A match needs one of these exact addresses, on the same machine as now.{' '}
                {SOURCE_ADDRESS_NOTE}
              </p>
              <div className="flex flex-col gap-1.5">
                {draft.sources.map((source) => (
                  <label
                    key={source.address}
                    className="flex items-start gap-2 text-[12.5px] text-text-2"
                  >
                    <input
                      type="checkbox"
                      className="mt-[3px]"
                      checked={source.of_this_run || addedSources.includes(source.address)}
                      disabled={source.of_this_run}
                      onChange={() => setAddedSources((have) => toggled(have, source.address))}
                    />
                    <span>
                      <span className="font-mono text-text">{machineWords(source)}</span>
                      {source.of_this_run ? ' is the source of this investigation. ' : '. '}
                      {plural(source.runs, 'true positive investigation')} on the target in the last{' '}
                      {draft.earlier_days_max} days.
                    </span>
                  </label>
                ))}
              </div>
              {draft.excluded_sources.length > 0 && (
                <ul
                  data-testid="excluded-sources"
                  className="mt-1.5 list-disc pl-5 text-[12px] text-dim"
                >
                  {draft.excluded_sources.map((left) => (
                    <li key={left.address}>{left.hint} It cannot be in a scope.</li>
                  ))}
                </ul>
              )}
            </fieldset>

            <div data-testid="authorized-target" className="mb-3 text-[12.5px] leading-[1.5] text-text-2">
              <div className={LABEL}>Target address</div>
              <span className="font-mono text-text">{machineWords(draft.target)}</span>.{' '}
              {targetWords(draft.target_has_agent)}
            </div>

            <fieldset data-testid="authorized-rules" className="mb-3">
              <legend className={LABEL}>Rules</legend>
              <p className="mb-1.5 text-[12px] text-dim">
                A match needs one of these exact rule names, with the class{' '}
                {ruleClassWords(draft.rule_class)}. A rule that is not selected is outside the
                scope. The list holds the rules of the true positive investigations from these
                sources to the target.
              </p>
              <div className="flex flex-col gap-1.5">
                {draft.rules.map((rule) => (
                  <label
                    key={rule.name}
                    className="flex items-start gap-2 text-[12.5px] text-text-2"
                  >
                    <input
                      type="checkbox"
                      className="mt-[3px]"
                      checked={rule.of_this_run || addedRules.includes(rule.name)}
                      disabled={rule.of_this_run}
                      onChange={() => setAddedRules((have) => toggled(have, rule.name))}
                    />
                    <span>
                      <span className="font-mono text-[11.5px] text-text">{rule.name}</span>
                      {rule.of_this_run ? ' is the rule of this investigation. ' : '. '}
                      {plural(rule.runs, 'investigation')}.
                    </span>
                  </label>
                ))}
              </div>
            </fieldset>

            <div className="mb-3">
              <label htmlFor="authorized-expiry" className={LABEL}>
                Expiry
              </label>
              <select
                id="authorized-expiry"
                value={days ?? draft.default_days}
                onChange={(e) => setDays(Number(e.target.value))}
                className={FIELD}
              >
                {draft.expiry_choices.map((choice) => (
                  <option key={choice} value={choice}>
                    {plural(choice, 'day')}
                  </option>
                ))}
              </select>
              <p className="mt-1 text-[12px] text-dim">
                The record ends at the expiry. The longest expiry is {draft.max_days} days.
              </p>
            </div>

            {draft.this_run_outside && (
              <div
                data-testid="this-run-outside"
                role="note"
                className="mb-3 rounded-[7px] border px-3 py-2 text-[12.5px] text-warn"
                style={{ borderColor: 'rgba(245,166,35,.35)', background: 'rgba(245,166,35,.06)' }}
              >
                This investigation keeps normal handling under the record. {draft.this_run_outside}
              </div>
            )}

            <label className="mb-3 flex items-start gap-2 text-[12.5px] text-text-2">
              <input
                type="checkbox"
                className="mt-[3px]"
                data-testid="apply-earlier"
                checked={applyEarlier && earlier > 0}
                disabled={earlier === 0}
                onChange={(e) => setApplyEarlier(e.target.checked)}
              />
              <span>
                {earlier > 0
                  ? `Apply the record to the ${plural(earlier, 'earlier investigation')} that this scope matches in the last ${draft.earlier_days_max} days.`
                  : `No earlier investigation of the last ${draft.earlier_days_max} days matches this scope.`}
              </span>
            </label>

            <div className="mb-4">
              <label htmlFor="authorized-note" className={LABEL}>
                Note <span className="font-normal text-faint">optional</span>
              </label>
              <textarea
                id="authorized-note"
                value={note}
                rows={2}
                onChange={(e) => setNote(e.target.value)}
                className={FIELD}
              />
            </div>

            {notAdmin && (
              <div role="note" className="mb-3 text-[12.5px] text-warn">
                Only an admin can record authorized activity.
              </div>
            )}
            {saveError && (
              <div
                role="alert"
                className="mb-3 rounded-[7px] border px-3 py-2 text-[12px] text-danger"
                style={{ borderColor: 'rgba(240,68,56,.35)', background: 'rgba(240,68,56,.07)' }}
              >
                {saveError}
              </div>
            )}
          </>
        )}

        <div className="flex justify-end gap-2.5">
          <button
            onClick={onClose}
            className="rounded-control border border-border-strong bg-surface-3 px-4 py-2 text-[13px] font-semibold text-text-2 hover:text-text"
          >
            {draft?.allowed ? 'Cancel' : 'Close'}
          </button>
          {draft?.allowed && (
            <button
              disabled={!canSave}
              onClick={save}
              className="flex items-center gap-1.5 rounded-control border border-accent bg-[rgba(75,139,245,.14)] px-4 py-2 text-[13px] font-semibold text-accent hover:bg-[rgba(75,139,245,.22)] disabled:opacity-60"
            >
              {saving ? <Spinner size={13} /> : <Check size={13} />}
              {saving ? 'Saving' : 'Record authorized activity'}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
