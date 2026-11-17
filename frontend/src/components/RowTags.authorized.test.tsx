// The authorized activity chip of a list row. The run stays in every list,
// and the chip says why it requests no case. A revoked authorization shows
// no chip: the run gets normal handling.
import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';

import { RowTags } from './RowTags';

const ref = {
  id: 3,
  label: 'php2shell test',
  state: 'active' as const,
  expiresAt: '2026-11-20T10:00:00+00:00',
  by: 'casey',
};

afterEach(cleanup);

describe('the authorized activity chip', () => {
  it('marks a run inside an authorized scope and names the label on hover', () => {
    render(<RowTags authorized={ref} />);
    const chip = screen.getByTestId('authorized-chip');
    expect(chip.textContent).toBe('Authorized activity');
    expect(chip.getAttribute('title')).toContain('It keeps its verdict and requests no case.');
    expect(chip.getAttribute('title')).toContain('The label is "php2shell test".');
  });

  it('keeps the chip after the expiry', () => {
    render(<RowTags authorized={{ ...ref, state: 'expired' }} />);
    expect(screen.getByTestId('authorized-chip')).toBeTruthy();
  });

  it('shows no chip after a revoke and on a run with no authorization', () => {
    render(<RowTags authorized={{ ...ref, state: 'revoked' }} />);
    expect(screen.queryByTestId('authorized-chip')).toBeNull();
    cleanup();
    render(<RowTags authorized={null} />);
    expect(screen.queryByTestId('authorized-chip')).toBeNull();
  });
});
