// A run whose name came from a hunt is a promoted finding or a run whose
// subject is a hunt. The list cut its name at 72 characters in the middle,
// and later at two lines. An alert row kept the middle cut. The owner banned
// the ellipsis on 2026-10-07: every name now shows whole and wraps in its
// cell, and the `title` attribute still holds it.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { InvestigationList, InvestigationRow } from '../lib/types';

const row = (over: Partial<InvestigationRow>): InvestigationRow => ({
  id: 'INV-X',
  name: 'Beaconing to rare external IP',
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

import { TITLE_180, bareCuts, showsWhole } from '../test/wholeTitle';
import { Investigations } from './Investigations';

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

describe('Investigations list keeps a hunt-sourced name whole', () => {
  it('wraps a 180 character promoted finding title whole in its cell', async () => {
    listInvestigations.mockResolvedValue(list([row({ name: TITLE_180 })]));
    mount();
    const name = await screen.findByTestId('inv-name-INV-X');
    expect(name.textContent).toBe(TITLE_180);
    expect(name.getAttribute('title')).toBe(TITLE_180);
    expect(name.className).toContain('break-words');
    expect(name.className).not.toMatch(/\btruncate\b|line-clamp/);
    expect(showsWhole(document.body, TITLE_180)).toBe(true);
    expect(bareCuts(document.body, TITLE_180)).toEqual([]);
  });

  it('keeps the whole name of a run whose subject is a hunt', async () => {
    listInvestigations.mockResolvedValue(
      list([row({ kind: 'suricata', subjectType: 'hunt', name: TITLE_180 })]),
    );
    mount();
    const name = await screen.findByTestId('inv-name-INV-X');
    expect(name.textContent).toBe(TITLE_180);
    expect(name.getAttribute('title')).toBe(TITLE_180);
  });

  it('renders a short hunt-sourced name unchanged', async () => {
    listInvestigations.mockResolvedValue(list([row({})]));
    mount();
    const name = await screen.findByTestId('inv-name-INV-X');
    expect(name.textContent).toBe('Beaconing to rare external IP');
  });

  // An alert row kept a middle cut. The tail of a rule name tells two rules
  // apart, and the head does too, so the whole name shows.
  it('shows a long alert rule name whole, with no middle cut', async () => {
    listInvestigations.mockResolvedValue(
      list([row({ kind: 'suricata', subjectType: 'alert', name: TITLE_180 })]),
    );
    mount();
    const name = await screen.findByTestId('inv-name-INV-X');
    expect(name.textContent).toBe(TITLE_180);
    expect(name.textContent).not.toMatch(/…|\.\.\./);
    expect(name.getAttribute('title')).toBe(TITLE_180);
    expect(name.className).not.toMatch(/\btruncate\b|line-clamp/);
    expect(bareCuts(document.body, TITLE_180)).toEqual([]);
  });
});
