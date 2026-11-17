// ---------------------------------------------------------------------------
// The words of authorized activity.
//
// An analyst records that some activity is authorized: a label, a scope and
// an expiry. A run inside the scope keeps its true positive verdict. It
// carries the mark, requests no case and raises no notification of its own.
// The run page, the list rows, the cards and the dialog all say it with the
// sentences below, so the one term reads the same on every surface.
// ---------------------------------------------------------------------------
import { plural } from './plural';
import { utcStamp } from './timeRange';
import type { AuthorizationRef } from './types';
import type { AuthorizedActivity, AuthorizedMachine } from './api';

/** The mark on a run and on a row. */
export const AUTHORIZED_MARK = 'Authorized activity';

/** The state word of a record. */
export const AUTHORIZED_STATE: Record<AuthorizedActivity['state'], string> = {
  active: 'Active',
  expired: 'Expired',
  revoked: 'Revoked',
};

/** True while the mark of a run holds. A revoke ends it. An expiry does not. */
export function markHolds(ref: AuthorizationRef | null | undefined): ref is AuthorizationRef {
  return !!ref && ref.state !== 'revoked';
}

/** The sentences of the run page for a run that matched an authorization. */
export function authorizedSentence(ref: AuthorizationRef): string {
  if (ref.state === 'revoked') {
    return `An analyst revoked the authorized activity "${ref.label}". This investigation gets normal handling.`;
  }
  const expiry =
    ref.state === 'expired'
      ? `It expired on ${utcStamp(ref.expiresAt)}. This investigation keeps the mark.`
      : `It expires on ${utcStamp(ref.expiresAt)}.`;
  return `${ref.label}. ${ref.by} recorded it. ${expiry} This investigation requests no case.`;
}

/** A machine in a sentence: its name and its address, or the address alone. */
export function machineWords(machine: AuthorizedMachine): string {
  return machine.name ? `${machine.name} at ${machine.address}` : machine.address;
}

/** What the record does with a source address, for the dialog. */
export const SOURCE_ADDRESS_NOTE =
  'The agent of this machine reports the address. The record holds this address only.';

/** What the record does with the target address, for the dialog. */
export function targetWords(hasAgent: boolean): string {
  return hasAgent
    ? 'The agent of this machine reports the address. The record holds this address only.'
    : 'The target has no agent. The record follows the address, so another device on ' +
        'this address is inside the scope until the expiry.';
}

/** The alert class of the rules of a scope in plain words. */
export function ruleClassWords(ruleClass: string | null | undefined): string {
  const words: Record<string, string> = {
    exploit_attempt: 'exploit attempt',
    post_compromise: 'post compromise',
    recon: 'recon',
    informational_visibility: 'informational',
    unknown: 'no class',
  };
  return words[ruleClass ?? ''] ?? (ruleClass ?? '').replace(/_/g, ' ');
}

/** "in 6 days", "in 5 hours", "in 12 minutes", for a time that lies ahead. */
function ahead(ms: number): string {
  const minutes = Math.max(1, Math.round(ms / 60000));
  if (minutes < 60) return `in ${plural(minutes, 'minute')}`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `in ${plural(hours, 'hour')}`;
  return `in ${plural(Math.round(hours / 24), 'day')}`;
}

/** The time sentence of a card. */
export function recordTimeSentence(record: AuthorizedActivity, now = Date.now()): string {
  const recorded = `${record.created_by} recorded it on ${utcStamp(record.created_at)}.`;
  if (record.state === 'revoked') {
    const reason = record.revoke_reason ? ` Reason: ${record.revoke_reason}` : '';
    return (
      `${recorded} ${record.revoked_by ?? 'An analyst'} revoked it on ` +
      `${utcStamp(record.revoked_at)}.${reason}`
    );
  }
  if (record.state === 'expired') {
    return `${recorded} It expired on ${utcStamp(record.expires_at)}. New investigations get normal handling.`;
  }
  const left = new Date(record.expires_at).getTime() - now;
  return `${recorded} It expires ${ahead(left)}, on ${utcStamp(record.expires_at)}.`;
}

/** The scope of a card on one line: the sources by name, and the target. A
 *  machine with no name reads as its address. */
export function scopeWords(record: AuthorizedActivity): string {
  const name = (machine: AuthorizedMachine) => machine.name?.trim() || machine.address;
  return `${record.sources.map(name).join(', ')} to ${name(record.target)}`;
}

/** The expiry of a card in a few words, for its one row. */
export function expiryWords(record: AuthorizedActivity, now = Date.now()): string {
  if (record.state === 'revoked') {
    return `Revoked by ${record.revoked_by ?? 'an analyst'} on ${utcStamp(record.revoked_at)}`;
  }
  if (record.state === 'expired') return `Expired on ${utcStamp(record.expires_at)}`;
  return `Expires ${ahead(new Date(record.expires_at).getTime() - now)}`;
}

/** The count line of a card: the runs since the decision, and the earlier runs. */
export function runCountWords(record: AuthorizedActivity): string {
  const since = `${plural(record.runs_since_decision, 'matching investigation')} since the decision`;
  return record.earlier_runs > 0
    ? `${since}, and ${plural(record.earlier_runs, 'earlier investigation')}`
    : since;
}

/** The rules of a card: the count, for the line above the list of names. */
export function ruleCountWords(record: AuthorizedActivity): string {
  return `${plural(record.rule_names.length, 'rule')}, class ${ruleClassWords(record.rule_class)}`;
}
