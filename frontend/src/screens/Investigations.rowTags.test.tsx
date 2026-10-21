// The tags and the group header of an Investigations row (dogfood 2026-10-19,
// STE items 29 and 30, R2-D21).
//
// - "Depth: not recorded" stood on every run from before depths existed. The
//   tag said nothing the analyst can act on. A row with no recorded depth now
//   shows no depth tag.
// - A promoted finding showed "HUNT" and "hunt" side by side. The type tag of
//   a hunt run already says that the subject is the hunt, so the row shows one
//   tag.
// - Group by detection showed "1" over a group of 3 runs. The count read the
//   rows of the group and left out the earlier runs under each row.
import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { InvestigationList, InvestigationRow } from '../lib/types';

const row = (over: Partial<InvestigationRow>): InvestigationRow => ({
  id: 'INV-X',
  name: 'ET INFO NTLMv1 Session Setup Response',
  kind: 'suricata',
  verdict: 'false_positive',
  conf: 0.8,
  host: '192.0.2.20',
  dst: '192.0.2.40',
  status: 'complete',
  when: '2h',
  ts: new Date(Date.now() - 2 * 3_600_000).toISOString(),
  alertId: 'ev-x',
  isPrimary: true,
  fallback: false,
  ...over,
});

const list = (rows: InvestigationRow[], over: Partial<InvestigationList> = {}): InvestigationList => ({
  rows,
  total: rows.length,
  running: 0,
  truePositives: 0,
  totalAll: rows.length,
  active: false,
  limit: 50,
  offset: 0,
  ...over,
});

const listInvestigations = vi.hoisted(() => vi.fn());
const listSavedViews = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  listInvestigations,
  listSavedViews,
}));

import { Investigations } from './Investigations';

const mount = (url = '/investigations') =>
  render(
    <MemoryRouter initialEntries={[url]}>
      <Investigations />
    </MemoryRouter>,
  );

beforeEach(() => {
  listInvestigations.mockReset();
  listSavedViews.mockReset().mockResolvedValue([]);
});

describe('the depth tag', () => {
  it('shows no tag on a row with no recorded depth', async () => {
    listInvestigations.mockResolvedValue(
      list([
        row({ id: 'A', alertId: 'ev-a', runClass: 'standard' }),
        row({ id: 'B', alertId: 'ev-b', runClass: null }),
      ]),
    );
    mount();
    expect(await screen.findByTestId('run-class-A')).toHaveTextContent('Depth: standard');
    expect(screen.queryByTestId('run-class-B')).toBeNull();
    expect(screen.getByTestId('inv-tags-B').textContent).not.toContain('not recorded');
  });

  it('keeps the pending tag on a run in progress', async () => {
    listInvestigations.mockResolvedValue(
      list([
        row({ id: 'A', alertId: 'ev-a', runClass: 'deep' }),
        row({ id: 'C', alertId: 'ev-c', runClass: null, status: 'running', verdict: 'untriaged' }),
      ]),
    );
    mount();
    expect(await screen.findByTestId('run-class-C')).toHaveTextContent('Depth: pending');
  });

  it('shows no tag on an earlier run with no recorded depth', async () => {
    listInvestigations.mockResolvedValue(
      list([
        row({ id: 'NEW', alertId: 'ev-a', runClass: 'standard' }),
        row({ id: 'OLD', alertId: 'ev-a', runClass: null, isPrimary: false }),
      ]),
    );
    mount();
    fireEvent.click(await screen.findByText('1 earlier'));
    await screen.findByTestId('inv-tags-OLD');
    expect(screen.queryByTestId('run-class-OLD')).toBeNull();
  });
});

describe('the hunt tags', () => {
  it('shows one hunt tag on a promoted finding', async () => {
    listInvestigations.mockResolvedValue(
      list([row({ id: 'H', kind: 'hunt', subjectType: 'hunt', dst: null })]),
    );
    mount();
    const tags = await screen.findByTestId('inv-tags-H');
    const texts = Array.from(tags.children).map((c) => (c.textContent ?? '').trim().toLowerCase());
    expect(texts.filter((t) => t === 'hunt')).toHaveLength(1);
    expect(screen.queryByTestId('subject-type-H')).toBeNull();
  });

  it('keeps the subject tag beside a lead type tag', async () => {
    // A lead run on a hunt: two tags with two different words.
    listInvestigations.mockResolvedValue(
      list([row({ id: 'L', kind: 'lead' as never, subjectType: 'hunt' })]),
    );
    mount();
    expect((await screen.findByTestId('subject-type-L')).textContent).toBe('hunt');
    expect(within(screen.getByTestId('inv-tags-L')).getByText('lead')).toBeTruthy();
  });
});

describe('the group header count', () => {
  it('counts the earlier runs under a row', async () => {
    // One alert, three runs: the standing run and two earlier runs.
    listInvestigations.mockResolvedValue(
      list([
        row({ id: 'R3', alertId: 'ev-ntlm' }),
        row({ id: 'R2', alertId: 'ev-ntlm', isPrimary: false }),
        row({ id: 'R1', alertId: 'ev-ntlm', isPrimary: false }),
        row({ id: 'S1', alertId: 'ev-scan', name: 'ET SCAN Potential SSH Scan' }),
      ]),
    );
    mount('/investigations?group=detection');
    const header = await screen.findByTestId('group-count-ET INFO NTLMv1 Session Setup Response');
    expect(header.textContent).toBe('3 investigations');
    expect(header.getAttribute('title')).toBe(
      'This detection has 3 investigations in the list. The count includes the earlier runs under each row.',
    );
    expect(screen.getByTestId('group-count-ET SCAN Potential SSH Scan').textContent).toBe(
      '1 investigation',
    );
  });

  it('says the count covers the page when the list has more pages', async () => {
    listInvestigations.mockResolvedValue(
      list(
        [
          row({ id: 'R2', alertId: 'ev-ntlm' }),
          row({ id: 'R1', alertId: 'ev-ntlm', isPrimary: false }),
        ],
        { total: 120, totalAll: 120 },
      ),
    );
    mount('/investigations?group=detection');
    const header = await screen.findByTestId('group-count-ET INFO NTLMv1 Session Setup Response');
    expect(header.textContent).toBe('2 investigations on this page');
    expect(header.getAttribute('title')).toBe(
      'This detection has 2 investigations on this page. The count includes the earlier runs under each row.',
    );
  });
});
