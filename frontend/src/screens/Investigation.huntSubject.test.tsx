// An investigation of a hunt has the hunt as its subject (design, 2026-09-22).
//
// An alert investigation has one rule and one event, and the right rail names
// both. A hunt investigation has an objective, a set of findings and every
// document those findings cite. There is no rule to name and no single event
// to show, and the rail that insisted on naming them described the wrong run.
//
// The verdict block, the evidence and the citations are unchanged: what the
// investigation concluded reads the same whatever it investigated.
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { Investigation as Inv, InvestigationSubject } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getChatThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getMe: vi.fn().mockResolvedValue({ username: 'analyst' }),
}));

import { Investigation } from './Investigation';
import {
  CHIP_SUBJECT_HUNT,
  SUBJECT_DOCUMENTS,
  SUBJECT_FINDINGS,
  SUBJECT_LEAD,
  SUBJECT_OBJECTIVE,
} from '../lib/tooltips';

const LONG_OBJECTIVE =
  'Sweep for directory replication by a non-machine account. Say whether the two leads are ' +
  'one campaign.';

const SUBJECT: InvestigationSubject = {
  type: 'hunt',
  hunt_id: '01HUNTABC000000000000000000',
  objective: 'Sweep for directory replication by a non-machine account',
  finding_ordinals: [1, 3],
  finding_titles: ['Replication rights granted to a user account', 'Off-hours replication pull'],
  lead_id: 12,
  document_ids: ['doc-a', 'doc-b', 'doc-c'],
  observation_ids: [41, 42],
};

const baseInv = (over: Partial<Inv>): Inv =>
  ({
    id: 'INV-1',
    groupId: 'ev-1',
    name: 'Sweep for directory replication by a non-machine account',
    kind: 'hunt',
    host: '10.1.2.3',
    ip: '10.1.2.3',
    verdict: 'true_positive',
    conf: 0.8,
    rationale: 'The hunt found replication rights on a user account.',
    summary: [{ t: 'text', v: 'evidence' }],
    status: 'complete',
    elapsedLabel: '4m 5s',
    actions: [],
    timeline: [],
    nodes: [],
    edges: [],
    seedChat: [],
    ...over,
  }) as Inv;

const mount = (over: Partial<Inv>) =>
  render(
    <MemoryRouter>
      <Investigation inv={baseInv(over)} layout="page" />
    </MemoryRouter>,
  );

describe('the subject panel of a hunt investigation', () => {
  it('names the hunt as the subject and the objective in place of the rule', () => {
    mount({ subject: SUBJECT });
    // The panel header is the subject line, and it stays on screen when the
    // panel is folded. It carries the sentence the list chip carries.
    expect(screen.getByText('Subject: hunt').getAttribute('title')).toBe(CHIP_SUBJECT_HUNT);
    const panel = screen.getByTestId('investigation-subject');
    const objective = within(panel).getByText(
      'Sweep for directory replication by a non-machine account',
    );
    expect(objective.getAttribute('title')).toBe(SUBJECT_OBJECTIVE);
  });

  // The ordinal is an identifier and it counts from zero. A person counts
  // from one, and the panel read "Finding 0 · …" over the first finding of the
  // hunt. The stored ordinal does not move: the word on screen does.
  it('lists the findings the investigation read, counting from one', () => {
    mount({ subject: SUBJECT });
    const list = screen.getByTestId('subject-findings');
    expect(list.getAttribute('title')).toBe(SUBJECT_FINDINGS);
    const items = within(list).getAllByRole('listitem');
    expect(items.map((li) => li.textContent)).toEqual([
      'Finding 2 · Replication rights granted to a user account',
      'Finding 4 · Off-hours replication pull',
    ]);
  });

  it('reads the first finding of the hunt as Finding 1', () => {
    mount({
      subject: { ...SUBJECT, finding_ordinals: [0], finding_titles: ['Root id to a Tor exit'] },
    });
    const items = within(screen.getByTestId('subject-findings')).getAllByRole('listitem');
    expect(items.map((li) => li.textContent)).toEqual(['Finding 1 · Root id to a Tor exit']);
  });

  // A backend that sends the ordinals alone still says which findings were
  // read. A made-up title would be worse than the number.
  it('names the findings by number when the titles are absent', () => {
    mount({ subject: { ...SUBJECT, finding_titles: undefined } });
    const items = within(screen.getByTestId('subject-findings')).getAllByRole('listitem');
    expect(items.map((li) => li.textContent)).toEqual(['Finding 2', 'Finding 4']);
  });

  it('links the hunt and the lead, and counts the documents', () => {
    mount({ subject: SUBJECT });
    const panel = screen.getByTestId('investigation-subject');
    expect(within(panel).getByRole('link', { name: '01HUNTABC000000000000000000' })).toHaveAttribute(
      'href',
      '/hunts/01HUNTABC000000000000000000',
    );
    const lead = within(panel).getByRole('link', { name: 'Lead 12' });
    expect(lead).toHaveAttribute('href', '/leads/12');
    expect(lead.getAttribute('title')).toBe(SUBJECT_LEAD);
    const docs = within(panel).getByTestId('subject-documents');
    expect(docs.textContent).toBe('3 documents');
    expect(docs.getAttribute('title')).toBe(SUBJECT_DOCUMENTS);
  });

  it('names no lead when an analyst started the hunt', () => {
    mount({ subject: { ...SUBJECT, lead_id: null } });
    const panel = screen.getByTestId('investigation-subject');
    expect(within(panel).queryByRole('link', { name: /^Lead / })).toBeNull();
  });

  // The header carried the severity of the first cited document and that
  // document's two endpoints. Neither is the subject: the run read the whole
  // hunt, and the first document is one of many.
  it('reads the subject line and the lead in place of the document pills', () => {
    mount({ subject: { ...SUBJECT, objective: LONG_OBJECTIVE }, sev: 'medium' });
    const line = screen.getByTestId('verdict-subject');
    expect(line.textContent).toBe('Sweep for directory replication by a non-machine account.');
    expect(line.getAttribute('title')).toBe(SUBJECT_OBJECTIVE);
    const lead = screen.getByTestId('verdict-lead');
    expect(lead).toHaveAttribute('href', '/leads/12');
    expect(screen.queryByTestId('verdict-endpoints')).toBeNull();
  });

  it('names no lead on a hunt an analyst started', () => {
    mount({ subject: { ...SUBJECT, lead_id: null } });
    expect(screen.getByTestId('verdict-subject')).toBeTruthy();
    expect(screen.queryByTestId('verdict-lead')).toBeNull();
  });

  // The rail names the rule and the event on an alert run, and that is every
  // run this release inherited.
  it('keeps the alert details on an investigation with no hunt subject', () => {
    mount({
      kind: 'suricata',
      alert: {
        rule: 'ET MALWARE beaconing',
        src: '10.1.2.3',
        dst: '198.51.100.7',
        proto: 'tcp',
        action: 'allowed',
        count: 4,
      },
    });
    expect(screen.queryByTestId('investigation-subject')).toBeNull();
    expect(screen.getByText('Alert details')).toBeTruthy();
    // The endpoints of the alert are the subject of an alert run.
    expect(screen.getByTestId('verdict-endpoints')).toBeTruthy();
    expect(screen.queryByTestId('verdict-subject')).toBeNull();
  });
});
