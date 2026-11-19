// Round "decide once" (DC3). The Dashboard tile read "12 true positives on 0
// hosts", and its link opened 14 rows: 12 in a closed campaign and 2
// superseded. The tile links with `?waits=true`, the list asks the server for
// the true positives that wait, and the true positives view states its parts.
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { InvestigationList, InvestigationRow, TruePositiveParts } from '../lib/types';

const row = (over: Partial<InvestigationRow> = {}): InvestigationRow =>
  ({
    id: 'INV-1',
    name: 'ET EXPLOIT Example Upload Request',
    kind: 'suricata',
    verdict: 'true_positive',
    conf: 0.85,
    host: '192.0.2.10',
    dst: '192.0.2.20',
    status: 'complete',
    when: '1h',
    ts: new Date().toISOString(),
    alertId: 'alert-1',
    isPrimary: true,
    ...over,
  }) as InvestigationRow;

const PARTS: TruePositiveParts = {
  total: 14,
  waiting: 0,
  decided: 12,
  authorized: 0,
  superseded: 2,
  other: 0,
  campaigns: [{ id: 2, title: 'actor-a against web-1', state: 'closed', investigations: 12 }],
};

const list = (rows: InvestigationRow[], parts: TruePositiveParts | null = null): InvestigationList => ({
  rows,
  total: rows.length,
  running: 0,
  truePositives: rows.length,
  totalAll: rows.length,
  active: false,
  limit: 50,
  offset: 0,
  truePositiveParts: parts,
});

const listInvestigations = vi.hoisted(() => vi.fn());
const listSavedViews = vi.hoisted(() => vi.fn());
const getAuthorizedActivity = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  listInvestigations,
  listSavedViews,
  getAuthorizedActivity,
}));

import { partsSentence } from '../lib/truePositiveParts';
import { Investigations, waitsFromSearch } from './Investigations';

const mount = (path: string) =>
  render(
    <MemoryRouter initialEntries={[path]}>
      <Investigations />
    </MemoryRouter>,
  );

const lastQuery = () => listInvestigations.mock.calls[listInvestigations.mock.calls.length - 1][0];

beforeEach(() => {
  listInvestigations.mockReset().mockResolvedValue(list([row()], PARTS));
  listSavedViews.mockReset().mockResolvedValue([]);
  getAuthorizedActivity.mockReset().mockResolvedValue({ rows: [], active: 0 });
});

describe('Investigations: the true positives that wait', () => {
  it('reads the filter from the link of the Dashboard tile and names it on a chip', async () => {
    mount('/investigations?range=7d&verdict=true_positive&waits=true');
    await waitFor(() => expect(listInvestigations).toHaveBeenCalled());
    expect(lastQuery().waits).toBe(true);
    expect(lastQuery().verdict).toEqual(['true_positive']);
    expect((await screen.findByTestId('inv-waits-filter')).textContent).toContain('True positives that wait');
  });

  it('drops the filter with the chip, and a plain link carries none', async () => {
    // NEGATIVE CONTROL: a link with no `waits` keeps every true positive.
    expect(waitsFromSearch('?verdict=true_positive')).toBe(false);
    expect(waitsFromSearch('?waits=true')).toBe(true);
    mount('/investigations?range=7d&verdict=true_positive&waits=true');
    const chip = await screen.findByTestId('inv-waits-filter');
    fireEvent.click(chip.querySelector('button')!);
    await waitFor(() => expect(lastQuery().waits).toBeUndefined());
    expect(screen.queryByTestId('inv-waits-filter')).toBeNull();
  });

  it('states the parts of the true positives in the header of the view', async () => {
    mount('/investigations?range=7d&verdict=true_positive');
    await waitFor(() => expect(lastQuery().tpParts).toBe(true));
    const line = await screen.findByTestId('inv-tp-parts');
    expect(line.textContent).toBe('14 true positives. 0 wait. 12 are in a decided campaign. 2 are superseded.');
    expect(line.textContent).toBe(partsSentence(PARTS));
    // Nothing waits, so no part wears the danger color.
    expect(line.querySelector('.text-danger')).toBeNull();
  });

  it('states the part that waits in the danger color', async () => {
    listInvestigations.mockResolvedValue(list([row()], { ...PARTS, waiting: 1, total: 15 }));
    mount('/investigations?range=7d&verdict=true_positive');
    const line = await screen.findByTestId('inv-tp-parts');
    await waitFor(() => expect(line.querySelector('[data-part="waiting"]')?.className).toContain('text-danger'));
    expect(line.querySelector('[data-part="waiting"]')?.textContent).toBe('1 waits.');
  });

  it('asks for no parts outside the true positives view', async () => {
    // NEGATIVE CONTROL: the parts belong to the true positives view.
    mount('/investigations?range=7d&verdict=false_positive');
    await waitFor(() => expect(listInvestigations).toHaveBeenCalled());
    expect(lastQuery().tpParts).toBeUndefined();
    expect(screen.queryByTestId('inv-tp-parts')).toBeNull();
  });
});
