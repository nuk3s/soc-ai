import { render, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { CampaignChange } from '../../lib/api';
import { forbiddenWords } from '../../test/analystWords';
import { CAMPAIGN_AUTHORIZED, CASE_CHANGES, CLOSED_CHANGES } from '../../test/campaign';
import { CampaignChanges } from './CampaignChanges';

describe('CampaignChanges', () => {
  it('lists every change in words with its time, newest first', () => {
    render(<CampaignChanges changes={CLOSED_CHANGES} />);
    const rows = screen.getAllByTestId('campaign-change');
    expect(rows.map((r) => r.getAttribute('data-type'))).toEqual([
      'acknowledged',
      'decided',
      'reopened',
      'acknowledged',
      'decided',
      'stage',
      'party',
      'formed',
    ]);
    const words = rows.map((r) => within(r).getByTestId('campaign-change-words').textContent);
    expect(words).toEqual([
      'soc-ai acknowledged 1,083 alerts in Security Onion. soc-ai could not acknowledge 2 alerts.',
      'admin closed the campaign. Reason: Test that is over.',
      'A later event opened the campaign again.',
      'soc-ai acknowledged 40 alerts in Security Onion.',
      'analyst-2 closed the campaign. Reason: Accepted risk.',
      'The stage went from Attempt to Action on the target.',
      '2 new machines joined the campaign: db-1, mail-1.',
      'soc-ai formed the campaign.',
    ]);
    expect(within(rows[1]).getByTestId('campaign-change-at')).toHaveTextContent('2026-11-14 21:00 UTC');
    const list = screen.getByTestId('campaign-changes');
    expect(forbiddenWords(list)).toEqual([]);
    expect(list.textContent).not.toMatch(/\bkinds?\b/i);
  });

  it('states each cause of a reopen and a change type from a newer server', () => {
    const changes: CampaignChange[] = [
      { id: 1, type: 'reopened', at: '2026-11-01T00:00:00Z', detail: { cause: 'stage' } },
      { id: 2, type: 'reopened', at: '2026-11-02T00:00:00Z', detail: { cause: 'party' } },
      { id: 3, type: 'reopened', at: '2026-11-03T00:00:00Z', detail: { cause: 'analyst', by: 'admin' } },
      { id: 4, type: 'party', at: '2026-11-04T00:00:00Z', detail: { names: ['db-1'] } },
      { id: 5, type: 'stage', at: '2026-11-05T00:00:00Z', detail: { to: 'access' } },
      { id: 6, type: 'case_opened' as CampaignChange['type'], at: '2026-11-06T00:00:00Z', detail: {} },
    ];
    render(<CampaignChanges changes={changes} />);
    expect(screen.getAllByTestId('campaign-change-words').map((w) => w.textContent)).toEqual([
      'A higher stage opened the campaign again.',
      'A new machine opened the campaign again.',
      'admin opened the campaign again.',
      'A new machine joined the campaign: db-1.',
      'The campaign reached the stage Access.',
      'case_opened',
    ]);
  });
  it('states the changes of an authorization by the label of each investigation', () => {
    const changes: CampaignChange[] = [
      { id: 31, type: 'included', at: '2026-11-15T10:00:00Z', detail: { runId: 'run-nmi', by: 'analyst-2' } },
      { id: 30, type: 'reopened', at: '2026-11-15T09:00:00Z', detail: { cause: 'revoked', by: 'admin' } },
      ...(CAMPAIGN_AUTHORIZED.changes ?? []).slice(0, 3),
    ];
    const labels = { 'run-nmi': 'ET POLICY SSH session', 'run-beyond': 'ET EXPLOIT SMB probe', 'run-excluded': 'ET INFO curl download' };
    render(<CampaignChanges changes={changes} labels={labels} />);
    const rows = screen.getAllByTestId('campaign-change');
    expect(rows.map((r) => within(r).getByTestId('campaign-change-words').textContent)).toEqual([
      'analyst-2 included the investigation "ET POLICY SSH session" in the campaign.',
      'admin revoked the authorization. The campaign waits on a decision again.',
      'analyst-2 excluded the investigation "ET INFO curl download" from the campaign.',
      'The investigation "ET EXPLOIT SMB probe" is beyond the authorization. The target is not a listed machine.',
      'admin authorized the campaign.',
    ]);
    // The investigation beyond the authorization wears the danger tone.
    expect((within(rows[3]).getByTestId('campaign-change-dot') as HTMLElement).getAttribute('style')).toContain('--danger');
    expect(forbiddenWords(screen.getByTestId('campaign-changes'))).toEqual([]);
  });

  it('names no id when the label of the investigation is unknown', () => {
    // NEGATIVE CONTROL: an id tells the analyst nothing.
    render(<CampaignChanges changes={[{ id: 1, type: 'excluded', at: '2026-11-15T10:00:00Z', detail: { runId: 'run-x' } }]} />);
    expect(screen.getByTestId('campaign-change-words').textContent).toBe('An analyst excluded an investigation from the campaign.');
  });

  it('states the request, the case, the refusal and each comment of soc-ai in words', () => {
    render(<CampaignChanges changes={CASE_CHANGES.slice(0, 5)} />);
    const rows = screen.getAllByTestId('campaign-change');
    expect(rows.map((r) => r.getAttribute('data-type'))).toEqual([
      'case_comment',
      'case_comment',
      'case',
      'case_intent',
      'case_failed',
    ]);
    expect(rows.map((r) => within(r).getByTestId('campaign-change-words').textContent)).toEqual([
      'soc-ai added a comment to the case case-0c41 for a new machine.',
      'soc-ai added a comment to the case case-0c41 for a higher stage.',
      'analyst-2 opened the case case-0c41 in Security Onion with 21 alerts.',
      'analyst-2 asked Security Onion for one case.',
      'Security Onion refused the case. Reason: Security Onion answered 503.',
    ]);
    const dots = rows.map((r) => (within(r).getByTestId('campaign-change-dot') as HTMLElement).style.background);
    expect(dots[2]).toBe('rgb(var(--accent))');
    expect(dots[4]).toBe('rgb(var(--warn))');
    expect(forbiddenWords(screen.getByTestId('campaign-changes'))).toEqual([]);
  });

  it('states a case change with fields missing in whole sentences', () => {
    const sparse: CampaignChange[] = [
      { id: 5, type: 'case_comment', at: '2026-11-16T07:30:00Z', detail: {} },
      { id: 4, type: 'case', at: '2026-11-15T09:00:00Z', detail: { alerts: 0 } },
      { id: 3, type: 'case', at: '2026-11-15T09:00:00Z', detail: { caseId: 'c-1', alerts: 1, by: 'admin' } },
      { id: 2, type: 'case_intent', at: '2026-11-15T08:59:00Z', detail: {} },
      { id: 1, type: 'case_failed', at: '2026-11-15T08:40:00Z', detail: {} },
    ];
    render(<CampaignChanges changes={sparse} />);
    expect(screen.getAllByTestId('campaign-change-words').map((w) => w.textContent)).toEqual([
      'soc-ai added a comment to the case.',
      'An analyst opened a case in Security Onion with no alert.',
      'admin opened the case c-1 in Security Onion with 1 alert.',
      'soc-ai asked Security Onion for one case.',
      'Security Onion refused the case.',
    ]);
  });
});
