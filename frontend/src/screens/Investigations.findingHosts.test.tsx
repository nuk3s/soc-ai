// A finding investigation with no source read "— → 203.0.113.10" in the
// Investigations list: an arrow from nothing (dogfood 2026-11-17, N5). The row
// names the hosts of the finding with no arrow, as the investigation page does.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { InvestigationList, InvestigationRow } from '../lib/types';

const row = (over: Partial<InvestigationRow>): InvestigationRow => ({
  id: 'INV-F',
  name: 'Successful LFI read-back',
  kind: 'hunt',
  subjectType: 'alert',
  verdict: 'true_positive',
  conf: 0.85,
  host: '—',
  dst: '203.0.113.10',
  status: 'complete',
  when: '2h ago',
  ts: '2026-11-16T01:00:00+00:00',
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

import { FINDING_HOSTS_TITLE, Investigations } from './Investigations';

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

describe('the hosts of a finding investigation with no pair', () => {
  it('lists the hosts of the finding with no arrow', async () => {
    listInvestigations.mockResolvedValue(list([row({ findingHosts: ['203.0.113.10', '198.51.100.7'] })]));
    mount();
    const cell = await screen.findByTestId('finding-hosts-INV-F');
    expect(cell).toHaveTextContent('hosts203.0.113.10198.51.100.7');
    expect(cell.textContent).not.toContain('→');
    expect(cell.getAttribute('title')).toBe(FINDING_HOSTS_TITLE);
    expect(screen.queryByTestId('flow-badge')).toBeNull();
  });

  it('keeps the flow of a row with a source', async () => {
    // Negative control: a row with a pair keeps its arrow.
    listInvestigations.mockResolvedValue(list([row({ host: '198.51.100.7', findingHosts: null })]));
    mount();
    const badge = await screen.findByTestId('flow-badge');
    expect(badge.textContent).toContain('→');
    expect(screen.queryByTestId('finding-hosts-INV-F')).toBeNull();
  });
});
