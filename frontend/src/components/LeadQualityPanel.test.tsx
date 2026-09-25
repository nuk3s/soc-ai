// The lead rule is instrumented, not moved (design, 2026-09-22).
//
// The rule that forms a lead is a set of thresholds, and a threshold nobody
// measures is a guess that hardened into a constant. The block states the rule
// in the server's own words, then counts what it produced: per week, and per
// set of observation types.
//
// The noise floor rule from the eval work holds here too, and the server sends
// it as a sentence: a threshold moves on a week of data, never on a day.
import { render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getLeadQuality: vi.fn(),
}));

import { getLeadQuality, type LeadQuality } from '../lib/api';
import {
  LEAD_QUALITY,
  QUALITY_DISMISSED,
  QUALITY_FORMED,
  QUALITY_HUNTED,
  QUALITY_PROMOTED,
  QUALITY_CLOSED_BY_HUNT,
  QUALITY_THREAT,
  QUALITY_TYPES,
  QUALITY_TYPES_DISMISSED,
  QUALITY_TYPES_CLOSED_BY_HUNT,
  QUALITY_TYPES_FORMED,
  QUALITY_TYPES_THREAT,
  QUALITY_WEEK,
} from '../lib/tooltips';
import { LeadQualityPanel } from './LeadQualityPanel';

const QUALITY: LeadQuality = {
  weeks: [
    {
      week: '2026-W38',
      formed: 11,
      hunted: 9,
      threat: 2,
      promoted: 1,
      closed_by_hunt: 3,
      dismissed: { benign_repeat: 4, expected_for_role: 1 },
    },
    {
      week: '2026-W37',
      formed: 6,
      hunted: 6,
      threat: 0,
      promoted: 0,
      closed_by_hunt: 1,
      dismissed: { bad_baseline: 2 },
    },
  ],
  by_types: [
    { types: 'catalog_match + off_hours', formed: 7, dismissed: 3, threat: 2, closed_by_hunt: 2 },
    { types: 'novel_destination + off_hours', formed: 4, dismissed: 2, threat: 0, closed_by_hunt: 1 },
  ],
  rule: 'A lead forms at 0.85 over two or more types, at a finding with no benign baseline, or at one type repeated to 1.5.',
  note: 'A threshold moves on a week of data, never on a day.',
};

const mount = () =>
  render(
    <MemoryRouter>
      <LeadQualityPanel />
    </MemoryRouter>,
  );

beforeEach(() => {
  vi.mocked(getLeadQuality).mockReset().mockResolvedValue(QUALITY);
});

describe('the lead quality block', () => {
  it('states the rule and the noise floor in the server words', async () => {
    mount();
    expect((await screen.findByTestId('lead-quality-rule')).textContent).toBe(QUALITY.rule);
    expect(screen.getByTestId('lead-quality-note').textContent).toBe(QUALITY.note);
    expect(screen.getByText('Lead quality').getAttribute('title')).toBe(LEAD_QUALITY);
  });

  it('counts each week and expands the reasons the data carries', async () => {
    mount();
    const table = await screen.findByTestId('lead-quality-weeks');
    const heads = within(table).getAllByRole('columnheader').map((th) => th.textContent);
    expect(heads).toEqual([
      'Week',
      'Formed',
      'Hunted',
      'Threat',
      'Promoted',
      'Closed by hunt',
      'The baseline is wrong',
      'A benign repeat',
      'Expected for this role',
    ]);
    const first = within(table).getByTestId('quality-week-2026-W38');
    expect(within(first).getAllByRole('cell').map((td) => td.textContent)).toEqual([
      '2026-W38',
      '11',
      '9',
      '2',
      '1',
      '3',
      '0',
      '4',
      '1',
    ]);
  });

  it('carries a sentence on every week column header', async () => {
    mount();
    const table = await screen.findByTestId('lead-quality-weeks');
    const titles = within(table)
      .getAllByRole('columnheader')
      .map((th) => th.getAttribute('title'));
    expect(titles).toEqual([
      QUALITY_WEEK,
      QUALITY_FORMED,
      QUALITY_HUNTED,
      QUALITY_THREAT,
      QUALITY_PROMOTED,
      QUALITY_CLOSED_BY_HUNT,
      QUALITY_DISMISSED,
      QUALITY_DISMISSED,
      QUALITY_DISMISSED,
    ]);
  });

  it('counts the leads each set of types formed', async () => {
    mount();
    const table = await screen.findByTestId('lead-quality-types');
    const heads = within(table).getAllByRole('columnheader');
    expect(heads.map((th) => th.textContent)).toEqual([
      'Types',
      'Formed',
      'Dismissed',
      'Closed by hunt',
      'Threat',
    ]);
    expect(heads.map((th) => th.getAttribute('title'))).toEqual([
      QUALITY_TYPES,
      QUALITY_TYPES_FORMED,
      QUALITY_TYPES_DISMISSED,
      QUALITY_TYPES_CLOSED_BY_HUNT,
      QUALITY_TYPES_THREAT,
    ]);
    const row = within(table).getByTestId('quality-types-0');
    // The stored names read as the analyst's words, as they do on every chip.
    expect(within(row).getAllByRole('cell').map((td) => td.textContent)).toEqual([
      'analytic match + off hours',
      '7',
      '3',
      '2',
      '2',
    ]);
  });

  // A week with no dismissal is a real answer, and a row of reason columns
  // nobody used is noise. The columns come from the data.
  it('drops the reason columns when no week holds a dismissal', async () => {
    vi.mocked(getLeadQuality).mockResolvedValue({
      ...QUALITY,
      weeks: [
        {
          week: '2026-W38',
          formed: 3,
          hunted: 3,
          threat: 1,
          promoted: 1,
          closed_by_hunt: 0,
          dismissed: {},
        },
      ],
    });
    mount();
    const table = await screen.findByTestId('lead-quality-weeks');
    expect(within(table).getAllByRole('columnheader')).toHaveLength(6);
  });

  it('states the absence of any lead rather than showing an empty table', async () => {
    vi.mocked(getLeadQuality).mockResolvedValue({ ...QUALITY, weeks: [], by_types: [] });
    mount();
    expect(
      await screen.findByText('No lead formed in the window. The rule has produced nothing to read.'),
    ).toBeTruthy();
  });

  // A block that reads "no leads" over a dead endpoint is the false all-clear
  // the whole surface exists to prevent.
  it('states a failed read as a failure', async () => {
    vi.mocked(getLeadQuality).mockRejectedValue(new Error('down'));
    mount();
    await waitFor(() =>
      expect(screen.getByText('Could not read the lead quality.')).toBeTruthy(),
    );
    expect(screen.queryByTestId('lead-quality-weeks')).toBeNull();
  });
});
