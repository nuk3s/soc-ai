// The host page of a domain controller with 7 investigations, 6 of them true
// positives, showed no investigation count, list or link. A search for the
// host name found 1 of the 7 (dogfood 2026-10-19, R4-D3 and R4-I1).
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  listInvestigations: vi.fn(),
}));

import { listInvestigations } from '../lib/api';
import type { InvestigationList, InvestigationRow } from '../lib/types';
import { absTime, localTitle, utcStamp } from '../lib/timeRange';
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
    expect(listInvestigations).toHaveBeenCalledWith({ entity: 'agent:ea2d', limit: 3, tpParts: true });
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

  // Review 2026-11-12 (ui-hunt 7): an attacked host with 42 true positives
  // listed its three newest runs, three false positives.
  it('lists the true positives first when the newest runs are false positives', async () => {
    const fps = [
      row('F1', 'false_positive', 'ET INFO ZIP file download'),
      row('F2', 'false_positive', 'ET INFO APT User-Agent'),
      row('F3', 'needs_more_info', 'ET INFO APT User-Agent'),
    ];
    const tps = [row('T1', 'true_positive', 'ET EXPLOIT Example RCE'), row('T2', 'true_positive', 'ET EXPLOIT Example RCE')];
    vi.mocked(listInvestigations).mockImplementation(async (q = {}) =>
      q.verdict?.length
        ? { ...LIST, rows: tps, total: 42 }
        : { ...LIST, rows: fps, total: 115, truePositives: 42 },
    );
    mount();
    await waitFor(() =>
      expect(screen.getAllByTestId('host-investigation-row').map((r) => r.getAttribute('href'))).toEqual([
        '/investigation/T1',
        '/investigation/T2',
        '/investigation/F3',
      ]),
    );
    expect(listInvestigations).toHaveBeenCalledWith({ entity: 'agent:ea2d', verdict: ['true_positive'], limit: 3 });
    // The count line keeps the counts of the whole host.
    expect(screen.getByTestId('host-investigations-count').textContent).toBe(
      '115 investigations name this host. 42 reached a true-positive verdict.',
    );
  });

  it('keeps the newest order and makes no second read when the host has no true positive', async () => {
    // NEGATIVE CONTROL: no true positive, so nothing moves and nothing more is read.
    const rows = [row('A', 'false_positive', 'one'), row('B', 'inconclusive', 'two'), row('C', 'false_positive', 'three')];
    vi.mocked(listInvestigations).mockResolvedValue({ ...LIST, rows, total: 3, truePositives: 0 });
    mount();
    await waitFor(() => expect(screen.getAllByTestId('host-investigation-row')).toHaveLength(3));
    expect(screen.getAllByTestId('host-investigation-row').map((r) => r.getAttribute('href'))).toEqual([
      '/investigation/B',
      '/investigation/A',
      '/investigation/C',
    ]);
    expect(listInvestigations).toHaveBeenCalledTimes(1);
  });

  it('says that the read failed', async () => {
    vi.mocked(listInvestigations).mockRejectedValue(new Error('offline'));
    mount();
    expect((await screen.findByTestId('host-investigations-error')).textContent).toContain(
      'This page could not read the investigations of this host.',
    );
  });
});

// Round "decide once" (DC5). The host page read "51 reached a true-positive
// verdict" in red, and each of the 51 was in a campaign that the analyst had
// closed.
describe('HostInvestigations: the true positives split', () => {
  const PARTS = {
    total: 6,
    waiting: 1,
    decided: 4,
    authorized: 0,
    superseded: 1,
    other: 0,
    campaigns: [{ id: 2, title: 'actor-a against web-1', state: 'closed', investigations: 4 }],
  };

  it('states the count that waits in the danger color and the decided count with a link', async () => {
    vi.mocked(listInvestigations).mockResolvedValue({ ...LIST, truePositiveParts: PARTS });
    mount();
    const line = await screen.findByTestId('host-tp-split');
    expect(line.textContent).toBe(
      '7 investigations name this host. 6 reached a true-positive verdict. 1 waits. ' +
        '4 are in a decided campaign: actor-a against web-1. 1 is superseded.',
    );
    expect(line.querySelector('[data-part="waiting"]')!.className).toContain('text-danger');
    const decided = line.querySelector('[data-part="decided"]')!;
    expect(decided.className).not.toMatch(/danger|warn/);
    expect(screen.getByTestId('host-tp-decided-campaign')).toHaveAttribute('href', '/campaigns/2');
    // The line itself reads neutral: only the count that waits is red.
    expect(screen.getByTestId('host-investigations-count').className).not.toContain('text-danger');
  });

  it('wears no danger color when nothing waits', async () => {
    // NEGATIVE CONTROL: the decided true positives are no alarm.
    vi.mocked(listInvestigations).mockResolvedValue({
      ...LIST,
      truePositiveParts: { ...PARTS, waiting: 0, decided: 5, superseded: 1 },
    });
    mount();
    const line = await screen.findByTestId('host-tp-split');
    expect(line.textContent).toContain('0 wait.');
    expect(line.querySelector('.text-danger')).toBeNull();
  });

  it('keeps the red line of an older server that sends no parts', async () => {
    // NEGATIVE CONTROL: with no parts, every true positive still reads as an alarm.
    mount();
    const count = await screen.findByTestId('host-investigations-count');
    await waitFor(() => expect(count.textContent).toBe('7 investigations name this host. 6 reached a true-positive verdict.'));
    expect(count.className).toContain('text-danger');
  });
});

// Dogfood 2026-11-17, AB2: the host page dated a row by the time soc-ai
// investigated it, and the Investigations list dated the same row by its
// event. A run of today on an event of 17 days ago read "today" here.
describe('HostInvestigations: the time of the event', () => {
  it('dates a row by its event and names both times in the hover', async () => {
    const event = new Date(Date.now() - 17 * 86_400_000).toISOString();
    const investigated = new Date(Date.now() - 3_600_000).toISOString();
    vi.mocked(listInvestigations).mockResolvedValue({
      ...LIST,
      rows: [{ ...row('01A', 'true_positive', 'DCSync from a workstation'), ts: investigated, eventAt: event }],
    });
    mount();
    const when = await screen.findByTestId('host-investigation-when');
    expect(when.textContent).toBe(absTime(event));
    expect(when.getAttribute('title')).toBe(
      `Event ${utcStamp(event)}. ${localTitle(event)}. Investigated ${utcStamp(investigated)}.`,
    );
    // Round 3, T3: the row shows UTC with the label, and the hover states the
    // local time with its zone.
    expect(when.textContent!.endsWith(' UTC')).toBe(true);
  });

  it('falls back to the time of the investigation for a row with no event time', async () => {
    // NEGATIVE CONTROL: an older server sends no event time.
    mount();
    const [when] = await screen.findAllByTestId('host-investigation-when');
    expect(when.textContent).toBe(absTime(LIST.rows[0].ts ?? ''));
  });
});
