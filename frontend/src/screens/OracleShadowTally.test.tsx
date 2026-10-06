// The Oracle rule shadow tally (oracle_rule_mode=shadow). One small table:
// what the uncertainty rule would send, what the classic rule sent, and the
// overlap, by reason. A failed load must never read as "the rules agree".
import { render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { OracleShadowTally as Tally } from '../lib/api';

const getOracleShadowTallyMock = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getOracleShadowTally: getOracleShadowTallyMock,
}));

import { OracleShadowTally } from './OracleShadowTally';

const WEEK: Tally = {
  mode: 'shadow',
  days: 7,
  recorded: 5,
  would_escalate: 3,
  classic: 3,
  both: 1,
  by_reason: [
    { rule: 'uncertainty', reason: 'confidence_in_band', count: 2, overlap: 1 },
    { rule: 'uncertainty', reason: 'template_split', count: 1, overlap: 0 },
    { rule: 'classic', reason: 'malware_non_tp', count: 2, overlap: 0 },
    { rule: 'classic', reason: 'below_confidence', count: 1, overlap: 1 },
  ],
};

describe('OracleShadowTally', () => {
  afterEach(() => {
    getOracleShadowTallyMock.mockReset();
  });

  it('shows the counts, the overlap and one row per reason', async () => {
    getOracleShadowTallyMock.mockResolvedValue(WEEK);
    render(<OracleShadowTally />);
    const summary = await screen.findByTestId('oracle-shadow-summary');
    expect(summary.textContent).toContain('The uncertainty rule would send 3.');
    expect(summary.textContent).toContain('The classic rule sent 3.');
    expect(summary.textContent).toContain('Both rules send 1.');
    const table = screen.getByTestId('oracle-shadow-tally');
    const band = within(table).getByText('confidence_in_band').parentElement as HTMLElement;
    expect(within(band).getByText('Uncertainty')).toBeTruthy();
    expect(within(band).getByText('2')).toBeTruthy();
    expect(within(band).getByText('1')).toBeTruthy();
    expect(within(table).getByText('malware_non_tp')).toBeTruthy();
    expect(getOracleShadowTallyMock).toHaveBeenCalledWith(7);
  });

  it('says it could not load, and shows no count, when the call fails', async () => {
    getOracleShadowTallyMock.mockRejectedValue(new Error('boom'));
    render(<OracleShadowTally />);
    expect(
      await screen.findByText(/could not load the shadow tally\. This is not a claim that the rules agree/),
    ).toBeTruthy();
    expect(screen.queryByTestId('oracle-shadow-summary')).toBeNull();
  });

  it('names the mode when no shadow row can exist', async () => {
    getOracleShadowTallyMock.mockResolvedValue({
      ...WEEK,
      mode: 'classic',
      recorded: 0,
      would_escalate: 0,
      classic: 0,
      both: 0,
      by_reason: [],
    });
    render(<OracleShadowTally />);
    expect(
      await screen.findByText('The Oracle rule mode is classic. No shadow row is recorded in this mode.'),
    ).toBeTruthy();
  });
});
