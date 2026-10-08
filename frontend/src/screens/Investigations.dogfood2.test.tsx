// Dogfood 2026-10-06 on the Investigations list.
//
// - A search for a run older than the window read "No investigation matches"
//   and offered no way out. The window was the cause.
// - A store whose newest run was older than 30 days opened on an empty list.
// - A host-log alert read "<address> → " and a dash, as if a destination was
//   lost.
// - A row with no verdict showed a bare dash. A failed run and a running one
//   looked the same.
// - Three status words named one fact: the run stopped. The row says "Failed"
//   and the title names the cause.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { InvestigationList, InvestigationRow } from '../lib/types';

const row = (over: Partial<InvestigationRow> & Record<string, unknown>): InvestigationRow =>
  ({
    id: 'INV-X',
    name: 'GPL ICMP Large ICMP Packet',
    kind: 'suricata',
    verdict: 'false_positive',
    conf: 0.7,
    host: '192.0.2.10',
    dst: '198.51.100.7',
    status: 'complete',
    when: '9h',
    ts: new Date(Date.now() - 9 * 3_600_000).toISOString(),
    alertId: 'ev-x',
    isPrimary: true,
    fallback: false,
    ...over,
  }) as InvestigationRow;

const list = (rows: InvestigationRow[], over: Partial<InvestigationList> = {}): InvestigationList => ({
  rows,
  total: rows.length,
  running: 0,
  truePositives: 0,
  totalAll: rows.length,
  active: false,
  limit: 50,
  offset: 0,
  ...over,
});

const listInvestigations = vi.hoisted(() => vi.fn());
const listSavedViews = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  listInvestigations,
  listSavedViews,
}));

import { Investigations, countLine, hostLogMachine, landingWindow, noVerdictText } from './Investigations';

const mount = (url = '/investigations') =>
  render(
    <MemoryRouter initialEntries={[url]}>
      <Investigations />
    </MemoryRouter>,
  );

const lastQuery = () => listInvestigations.mock.calls[listInvestigations.mock.calls.length - 1][0];

beforeEach(() => {
  listInvestigations.mockReset();
  listInvestigations.mockResolvedValue(list([]));
  listSavedViews.mockReset();
  listSavedViews.mockResolvedValue([]);
});

describe('the window', () => {
  it('opens on all time when the newest run is older than every preset', () => {
    const now = Date.UTC(2026, 9, 6);
    expect(landingWindow(new Date(now - 45 * 86_400_000).toISOString(), now)).toBe('all');
    // Negative control: a run inside 30 days keeps the narrowest preset.
    expect(landingWindow(new Date(now - 9 * 86_400_000).toISOString(), now)).toBe('30d');
    expect(landingWindow(new Date(now - 3 * 3_600_000).toISOString(), now)).toBe('24h');
  });

  it('names all time as a total in the count line', () => {
    const base = { running: 0, truePositives: 0, replays: 0, includesReplays: false };
    expect(countLine({ ...base, total: 12, range: 'all' })).toBe(
      '12 investigations in total · 0 in progress · 0 true positives',
    );
    expect(countLine({ ...base, total: 1, range: '7d' })).toBe(
      '1 investigation in the last 7 days · 0 in progress · 0 true positives',
    );
  });

  it('widens to the newest run, sends no lower edge and says why', async () => {
    const old = new Date(Date.now() - 45 * 86_400_000).toISOString();
    listInvestigations
      .mockResolvedValueOnce(list([], { total: 0, totalAll: 4 }))
      .mockResolvedValueOnce(list([row({ ts: old })], { total: 1, totalAll: 4 }))
      .mockResolvedValue(list([row({ ts: old })], { total: 1, totalAll: 4 }));
    const { container } = mount();
    expect(await screen.findByText(/1 investigation in total/)).toBeTruthy();
    expect(lastQuery().since).toBeUndefined();
    expect(screen.getByTestId('window-widened').textContent).toMatch(
      /No run started in the last 24 hours\. The newest run started 45d ago, so the list shows all time\./,
    );
    expect(container.textContent).not.toContain('in the last 30 days');
  });

  it('says nothing about widening when the default window holds runs', async () => {
    listInvestigations.mockResolvedValue(list([row({})], { total: 1, totalAll: 4 }));
    mount();
    await screen.findByText(/1 investigation in the last 24 hours/);
    expect(screen.queryByTestId('window-widened')).toBeNull();
  });
});

describe('a search with no match in the window', () => {
  it('names the window and offers to search all time', async () => {
    listInvestigations.mockResolvedValue(list([], { total: 0, totalAll: 42 }));
    mount('/investigations?q=NTLM');
    expect(
      await screen.findByText('No investigation matches the search in the last 24 hours.'),
    ).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Search all time' }));
    await waitFor(() => {
      expect(lastQuery().q).toBe('NTLM');
      expect(lastQuery().since).toBeUndefined();
    });
  });

  it('offers no wider window once the search covers all time', async () => {
    listInvestigations.mockResolvedValue(list([], { total: 0, totalAll: 42 }));
    mount('/investigations?q=NTLM&range=all');
    expect(await screen.findByText('No investigation matches the search.')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Search all time' })).toBeNull();
  });
});

describe('the flow cell of a host-log alert', () => {
  it('names the machine and says host log', async () => {
    listInvestigations.mockResolvedValue(
      list([
        row({ id: 'SIG', kind: 'sigma', host: '192.0.2.44', dst: null, hostName: 'ws-07.example.test' }),
        row({ id: 'NET', alertId: 'ev-net' }),
      ]),
    );
    mount();
    const cell = await screen.findByTestId('host-log-SIG');
    expect(cell.textContent).toBe('on ws-07.example.test · host log');
    // Negative control: a network alert keeps its source and destination.
    expect(screen.queryByTestId('host-log-NET')).toBeNull();
    expect(screen.getByTitle('192.0.2.10 → 198.51.100.7')).toBeTruthy();
  });

  it('falls back to the address on a Sigma row with no machine name', () => {
    expect(hostLogMachine(row({ kind: 'sigma', dst: null, host: '192.0.2.44' }))).toBe('192.0.2.44');
    // A hunt subject has no flow and no machine of its own.
    expect(hostLogMachine(row({ kind: 'hunt', dst: null, hostName: 'x' }))).toBeNull();
    // A Suricata row with no destination stays a flow: it read network traffic.
    expect(hostLogMachine(row({ kind: 'suricata', dst: null }))).toBeNull();
  });
});

describe('a row with no verdict', () => {
  it('says Running on a run in progress', () => {
    expect(noVerdictText(row({ verdict: 'untriaged', status: 'running' }))).toBe('Running');
  });

  it('says a later run replaced a failed run that is not the newest', () => {
    expect(
      noVerdictText(
        row({ id: 'OLD', verdict: 'untriaged', status: 'error', isPrimary: false, latestRunId: 'NEW' }),
      ),
    ).toBe('Failed. A later run replaced it.');
  });

  it('says an earlier run holds the verdict when the failed run is the newest', () => {
    expect(
      noVerdictText(
        row({ id: 'NEW', verdict: 'untriaged', status: 'error', isPrimary: false, latestRunId: 'NEW' }),
      ),
    ).toBe('Failed. An earlier run holds the verdict.');
    expect(noVerdictText(row({ verdict: 'untriaged', status: 'interrupted' }))).toBe(
      'Failed. No run reached a verdict.',
    );
  });

  it('renders the sentence and the Failed status, with the cause in the title', async () => {
    listInvestigations.mockResolvedValue(
      list([
        row({ id: 'RUN', verdict: 'untriaged', conf: null, status: 'running', alertId: 'ev-run' }),
        row({ id: 'CUT', verdict: 'untriaged', conf: null, status: 'interrupted', alertId: 'ev-cut' }),
        row({ id: 'OK', alertId: 'ev-ok' }),
      ]),
    );
    mount();
    expect((await screen.findByTestId('no-verdict-RUN')).textContent).toBe('Running');
    expect(screen.getByTestId('no-verdict-CUT').textContent).toBe('Failed. No run reached a verdict.');
    const statuses = screen.getAllByTestId('status-cell');
    const failed = statuses.find((s) => s.textContent === 'Failed')!;
    expect(failed.getAttribute('title')).toMatch(/service restart/);
    // Negative control: a row with a verdict shows its pill and no sentence.
    expect(screen.queryByTestId('no-verdict-OK')).toBeNull();
    expect(within(screen.getByTestId('when-OK')).getByText('9h ago')).toBeTruthy();
  });
});

describe('the When and confidence cells', () => {
  it('print the shared relative time and two decimals', async () => {
    const fourDays = new Date(Date.now() - 4 * 86_400_000 - 3_600_000).toISOString();
    listInvestigations.mockResolvedValue(list([row({ id: 'A', ts: fourDays, conf: 0.7 })]));
    mount('/investigations?range=7d');
    const when = await screen.findByTestId('when-A');
    expect(when.textContent).toBe('4d ago');
    expect(when.getAttribute('title')).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2} \S+$/);
    expect(screen.getByText('0.70')).toBeTruthy();
  });
});
