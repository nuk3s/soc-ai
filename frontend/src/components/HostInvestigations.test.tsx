// The host page of a domain controller with 7 investigations, 6 of them true
// positives, showed no investigation count, list or link. A search for the
// host name found 1 of the 7 (dogfood 2026-10-19, R4-D3 and R4-I1).
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  listInvestigations: vi.fn(),
}));

import { listInvestigations } from '../lib/api';
import type { InvestigationList, InvestigationRow } from '../lib/types';
import { HostInvestigations, investigationsHref, useHostInvestigations } from './HostInvestigations';

const row = (id: string, verdict: InvestigationRow['verdict'], name: string): InvestigationRow => ({
  id,
  name,
  kind: 'suricata',
  verdict,
  conf: 0.9,
  host: '192.0.2.10',
  status: 'complete',
  when: '2d ago',
  ts: new Date(Date.now() - 2 * 86_400_000).toISOString(),
});

const LIST: InvestigationList = {
  rows: [
    row('01A', 'true_positive', 'DCSync from a workstation'),
    row('01B', 'true_positive', 'Kerberoast of a service account'),
    row('01C', 'false_positive', 'SMB scan'),
  ],
  total: 7,
  running: 0,
  truePositives: 6,
  totalAll: 40,
  active: false,
  limit: 3,
  offset: 0,
  entityKeys: ['agent:ea2d', '192.0.2.10', 'dc01'],
};

function Mounted() {
  const read = useHostInvestigations('agent:ea2d');
  return <HostInvestigations entityKey="agent:ea2d" label="dc01" read={read} />;
}

const mount = () =>
  render(
    <MemoryRouter>
      <Mounted />
    </MemoryRouter>,
  );

beforeEach(() => {
  vi.mocked(listInvestigations).mockReset().mockResolvedValue(LIST);
});

describe('HostInvestigations', () => {
  it('counts every investigation of the machine and lists the newest', async () => {
    mount();
    expect((await screen.findByTestId('host-investigations-count')).textContent).toBe(
      '7 investigations name this host. 6 reached a true-positive verdict.',
    );
    expect(listInvestigations).toHaveBeenCalledWith({ entity: 'agent:ea2d', limit: 3 });
    const rows = screen.getAllByTestId('host-investigation-row');
    expect(rows).toHaveLength(3);
    expect(rows[0].getAttribute('href')).toBe('/investigation/01A');
    const all = screen.getByTestId('host-investigations-all');
    expect(all.getAttribute('href')).toBe(investigationsHref('agent:ea2d', 'dc01'));
    expect(all.textContent).toBe('Open the 7 investigations');
  });

  it('links the list filtered on the machine over all time', () => {
    expect(investigationsHref('agent:ea2d', 'dc01')).toBe(
      '/investigations?entity=agent%3Aea2d&entity_label=dc01&range=all',
    );
  });

  it('says that no investigation names the host when none does', async () => {
    // NEGATIVE CONTROL: no rows, no list link.
    vi.mocked(listInvestigations).mockResolvedValue({ ...LIST, rows: [], total: 0, truePositives: 0 });
    mount();
    expect((await screen.findByTestId('host-investigations-count')).textContent).toBe(
      'No investigation names this host.',
    );
    expect(screen.queryByTestId('host-investigations-all')).toBeNull();
  });

  it('says that the read failed', async () => {
    vi.mocked(listInvestigations).mockRejectedValue(new Error('offline'));
    mount();
    expect((await screen.findByTestId('host-investigations-error')).textContent).toContain(
      'This page could not read the investigations of this host.',
    );
  });
});
