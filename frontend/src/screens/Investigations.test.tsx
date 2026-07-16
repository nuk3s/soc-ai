// The Dashboard's pipeline-error KPI deep-links to ?verdict=pipeline_error.
// A fallback run that was superseded by a successful re-run is NON-primary and
// used to be tucked under its (filtered-out) primary — the filter found it but
// displayed nothing (dogfood 2026-07-15). The filter must surface matching
// non-primary rows, and a filter that matches nothing must say so instead of
// rendering a blank table.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';

const ROWS = vi.hoisted(() => [
  {
    id: 'INV-PRIMARY',
    name: 'GPL ICMP Large ICMP Packet',
    kind: 'suricata',
    verdict: 'false_positive',
    conf: 0.95,
    host: '192.0.2.10',
    dst: '198.51.100.7',
    status: 'complete',
    when: '9h ago',
    ts: '2026-07-15T01:00:00+00:00',
    alertId: 'ev-icmp',
    isPrimary: true,
    fallback: false,
  },
  {
    id: 'INV-SUPERSEDED-FB',
    name: 'GPL ICMP Large ICMP Packet',
    kind: 'suricata',
    verdict: 'needs_more_info',
    conf: 0.3,
    host: '192.0.2.10',
    dst: '198.51.100.7',
    status: 'complete',
    when: '1d ago',
    ts: '2026-07-14T01:00:00+00:00',
    alertId: 'ev-icmp',
    isPrimary: false,
    fallback: true,
  },
]);

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getInvestigations: vi.fn().mockResolvedValue(ROWS),
}));

import { Investigations } from './Investigations';

const mount = (url: string) =>
  render(
    <MemoryRouter initialEntries={[url]}>
      <Investigations />
    </MemoryRouter>,
  );

describe('Investigations pipeline_error deep link', () => {
  it('surfaces a superseded (non-primary) fallback run as a visible row', async () => {
    mount('/investigations?verdict=pipeline_error');
    const chip = await screen.findByText('Pipeline error');
    expect(chip).toBeTruthy();
    // the row shown is the fallback run itself, not just its primary
    expect(screen.getAllByText('GPL ICMP Large ICMP Packet')).toHaveLength(1);
  });

  it('says so when the active filter matches nothing', async () => {
    mount('/investigations?verdict=inconclusive');
    expect(await screen.findByText(/No investigations match the selected filters/i)).toBeTruthy();
  });
});
