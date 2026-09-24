// The Investigations list carries a type chip for a run whose subject is a
// whole hunt (design, 2026-09-22).
//
// The row already names the detector that raised the alert. A hunt
// investigation has no detector: the subject is the hunt's findings, and the
// row read as an ordinary alert run beside every other one.
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { InvestigationList, InvestigationRow } from '../lib/types';

const row = (over: Partial<InvestigationRow>): InvestigationRow => ({
  id: 'INV-X',
  name: 'Sweep for directory replication by a non-machine account',
  kind: 'hunt',
  verdict: 'true_positive',
  conf: 0.85,
  host: '10.1.2.3',
  dst: null,
  status: 'complete',
  when: '2h ago',
  ts: '2026-09-21T01:00:00+00:00',
  alertId: 'ev-1',
  isPrimary: true,
  fallback: false,
  ...over,
});

const list = (rows: InvestigationRow[]): InvestigationList => ({
  rows,
  total: rows.length,
  running: 0,
  truePositives: 0,
  totalAll: rows.length,
  active: false,
  limit: 50,
  offset: 0,
});

const listInvestigations = vi.hoisted(() => vi.fn());
const listSavedViews = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  listInvestigations,
  listSavedViews,
}));

import { Investigations } from './Investigations';
import { CHIP_SUBJECT_HUNT, detectionKindTitle } from '../lib/tooltips';

const mount = () =>
  render(
    <MemoryRouter initialEntries={['/investigations']}>
      <Investigations />
    </MemoryRouter>,
  );

beforeEach(() => {
  listInvestigations.mockReset().mockResolvedValue(list([]));
  listSavedViews.mockReset().mockResolvedValue([]);
});

describe('the subject type chip', () => {
  it('names a hunt subject beside the detection type, with its sentence', async () => {
    listInvestigations.mockResolvedValue(list([row({ subjectType: 'hunt' })]));
    mount();
    const chip = await screen.findByTestId('subject-type-INV-X');
    expect(chip.textContent).toBe('hunt');
    expect(chip.getAttribute('title')).toBe(CHIP_SUBJECT_HUNT);
  });

  it('carries no chip on a run whose subject is one alert', async () => {
    listInvestigations.mockResolvedValue(
      list([row({ kind: 'suricata', subjectType: 'alert' })]),
    );
    mount();
    await screen.findByText(/directory replication/);
    expect(screen.queryByTestId('subject-type-INV-X')).toBeNull();
  });

  // Every row this release inherited has an alert subject and no field to say
  // so. A chip on all of them would name a change that did not happen.
  it('carries no chip on a row from a backend that sends no subject type', async () => {
    listInvestigations.mockResolvedValue(list([row({ kind: 'suricata' })]));
    mount();
    await screen.findByText(/directory replication/);
    expect(screen.queryByTestId('subject-type-INV-X')).toBeNull();
  });

  // The LEAD chip read "The detector that raised this alert, as the grid
  // names it." No detector raised it: a lead did, and the subject is the
  // lead's hunt.
  it('states what a lead run is on the type chip', async () => {
    listInvestigations.mockResolvedValue(
      list([row({ kind: 'lead' as never, subjectType: 'hunt' })]),
    );
    mount();
    await screen.findByTestId('subject-type-INV-X');
    expect(screen.getByText('lead').getAttribute('title')).toBe(
      "An investigation that started from a lead. Its subject is the lead's hunt.",
    );
    expect(screen.getByText('lead').getAttribute('title')).toBe(detectionKindTitle('lead'));
  });

  // The two chips answer two questions: what raised it, and what it read. The
  // subject chip stands beside the detection chip, it does not replace it.
  it('keeps the detection type chip beside it', async () => {
    listInvestigations.mockResolvedValue(list([row({ subjectType: 'hunt' })]));
    mount();
    const chip = await screen.findByTestId('subject-type-INV-X');
    const rowEl = chip.parentElement as HTMLElement;
    const chips = within(rowEl).getAllByTitle(/hunt/i);
    expect(chips.length).toBe(2);
  });
});
